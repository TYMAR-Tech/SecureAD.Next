using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;

namespace SecureAD.Judgement;

internal static class LapsReadFindingStorage
{
    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, Finding finding, LapsPasswordReaderEvidence evidence)
    {
        var exposures = evidence.SupportingExposures
            ?? throw new InvalidDataException("Calculated LAPS supporting exposures were not supplied.");
        ValidateSummary(evidence.Assessment);
        if (finding.RuleId != "SEC-090" || finding.RuleVersion != LapsPasswordReadAccess.RuleVersion
            || exposures.Count != evidence.Assessment.ExposureCount
            || exposures.Count(value => value.State == LapsReadState.Established) != evidence.Assessment.EstablishedExposureCount
            || evidence.Assessment.MembershipIsComplete && exposures.Any(value => !value.MembershipIsComplete)
            || exposures.Select(value => (value.TrusteeSid, value.TrusteeScope, value.Attribute)).Distinct().Count() != exposures.Count)
            throw Invalid();
        foreach (var exposure in exposures)
            ValidateExposure(exposure, finding.DistinguishedName, finding.ObjectGuid, evidence.BroadPrincipalSid);
        if (!exposures.Any(value => value.TrusteeSid == evidence.TrusteeSid && value.Attribute == evidence.Attribute
            && value.MembershipIsComplete == evidence.ExpansionWasComplete
            && value.MembershipPath.SequenceEqual(evidence.MembershipPath))) throw Invalid();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO finding_laps_password_reader
                (finding_id,trustee_sid,trustee_name,broad_principal_sid,broad_principal_name,attribute,rights,reach,
                 inherited_class_guid,is_inherited,expansion_was_complete,route_length,assessment_complete,
                 exposure_count,established_count,assessment_json)
                VALUES ($id,$trustee,$name,$broad,$broadName,$attribute,$rights,$reach,$class,$inherited,
                 $membership,$length,$complete,$count,$established,$assessment)
                """;
            command.Parameters.AddWithValue("$id", findingId);
            command.Parameters.AddWithValue("$trustee", evidence.TrusteeSid);
            command.Parameters.AddWithValue("$name", (object?)evidence.TrusteeName ?? DBNull.Value);
            command.Parameters.AddWithValue("$broad", evidence.BroadPrincipalSid);
            command.Parameters.AddWithValue("$broadName", (object?)evidence.BroadPrincipalName ?? DBNull.Value);
            command.Parameters.AddWithValue("$attribute", evidence.Attribute);
            command.Parameters.AddWithValue("$rights", evidence.Rights.ToString());
            command.Parameters.AddWithValue("$reach", evidence.Reach.ToString());
            command.Parameters.AddWithValue("$class", (object?)evidence.InheritedClassGuid ?? DBNull.Value);
            command.Parameters.AddWithValue("$inherited", evidence.IsInherited ? 1 : 0);
            command.Parameters.AddWithValue("$membership", evidence.ExpansionWasComplete ? 1 : 0);
            command.Parameters.AddWithValue("$length", evidence.MembershipPath.Count);
            command.Parameters.AddWithValue("$complete", evidence.IsComplete ? 1 : 0);
            command.Parameters.AddWithValue("$count", evidence.Assessment.ExposureCount);
            command.Parameters.AddWithValue("$established", evidence.Assessment.EstablishedExposureCount);
            command.Parameters.AddWithValue("$assessment", JsonSerializer.Serialize(evidence.Assessment, ProofSerialization.Options));
            command.ExecuteNonQuery();
        }
        for (var ordinal = 0; ordinal < evidence.MembershipPath.Count; ordinal++)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO finding_laps_password_reader_path VALUES ($id,$ordinal,$sid,$name)";
            command.Parameters.AddWithValue("$id", findingId);
            command.Parameters.AddWithValue("$ordinal", ordinal);
            command.Parameters.AddWithValue("$sid", evidence.MembershipPath[ordinal].Sid);
            command.Parameters.AddWithValue("$name", (object?)evidence.MembershipPath[ordinal].Name ?? DBNull.Value);
            command.ExecuteNonQuery();
        }
        var originals = new Dictionary<(string Attribute, int Ordinal), string>();
        for (var ordinal = 0; ordinal < exposures.Count; ordinal++)
        {
            var exposure = exposures[ordinal];
            foreach (var entry in exposure.Entries ?? throw Invalid())
            {
                var key = (exposure.Attribute, entry.Entry.Ordinal);
                var payload = JsonSerializer.Serialize(entry, ProofSerialization.Options);
                if (originals.TryGetValue(key, out var saved))
                {
                    if (payload != saved) throw Invalid();
                    continue;
                }
                originals.Add(key, payload);
                using var original = connection.CreateCommand();
                original.Transaction = transaction;
                original.CommandText = """
                    INSERT INTO finding_laps_password_reader_entry (finding_id,attribute,ordinal,payload)
                    VALUES ($id,$attribute,$ordinal,$payload)
                    """;
                original.Parameters.AddWithValue("$id", findingId);
                original.Parameters.AddWithValue("$attribute", exposure.Attribute);
                original.Parameters.AddWithValue("$ordinal", entry.Entry.Ordinal);
                original.Parameters.AddWithValue("$payload", payload);
                original.ExecuteNonQuery();
            }
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO finding_laps_password_reader_support
                (finding_id,ordinal,generation_id,trustee_sid,attribute,state,payload)
                VALUES ($id,$ordinal,$generation,$trustee,$attribute,$state,$payload)
                """;
            command.Parameters.AddWithValue("$id", findingId);
            command.Parameters.AddWithValue("$ordinal", ordinal);
            command.Parameters.AddWithValue("$generation", generation.ToString("D"));
            command.Parameters.AddWithValue("$trustee", exposure.TrusteeSid);
            command.Parameters.AddWithValue("$attribute", exposure.Attribute);
            command.Parameters.AddWithValue("$state", exposure.State.ToString());
            command.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(exposure with { Entries = null }, ProofSerialization.Options));
            command.ExecuteNonQuery();
        }
    }

    internal static LapsReadSummary ReadSummary(string json, long count, long established, long complete)
    {
        var value = JsonSerializer.Deserialize<LapsReadSummary>(json, ProofSerialization.Options) ?? throw Invalid();
        ValidateSummary(value);
        if (complete is not (0 or 1) || value.ExposureCount != count
            || value.EstablishedExposureCount != established || value.IsComplete != (complete == 1)) throw Invalid();
        return value;
    }

    internal static void ValidateSummary(LapsReadSummary value)
    {
        if (value is null || value.ExposureCount <= 0 || value.EstablishedExposureCount < 0
            || value.EstablishedExposureCount > value.ExposureCount || value.Limitations is null
            || value.ReadChecksAreComplete && value.UnresolvedExposureCount != 0) throw Invalid();
    }

    internal static void ValidateExposure(LapsReadExposure value, string target, Guid targetGuid, string broad)
    {
        if (value is null || value.Target != target || value.TargetGuid != targetGuid || targetGuid == Guid.Empty
            || string.IsNullOrWhiteSpace(value.TrusteeSid) || !LapsPasswordAttributeCatalogue.All.Contains(value.Attribute)
            || !Guid.TryParse(value.AttributeGuid, out _) || !Enum.IsDefined(value.State)
            || value.State == LapsReadState.NotEstablished || !Enum.IsDefined(value.Confidentiality)
            || !Enum.IsDefined(value.Rights) || !Enum.IsDefined(value.Reach)
            || value.MembershipPath is null || value.MembershipPath.Count == 0
            || value.MembershipPath[0].Sid != value.TrusteeSid || value.MembershipPath[^1].Sid != broad
            || value.InheritedClassGuids is null || value.Entries is null || value.EntryOrdinals is null
            || value.ReadProperty is null || value.ControlAccess is null
            || value.ReadProperty.Mask != 0x10 || value.ControlAccess.Mask != 0x100
            || value.Entries.Any(item => item is null || item.Entry is null || item.Entry.Trustee is null
                || item.Entry.ApplicationData is null || !Enum.IsDefined(item.Scope)
                || item.ScopeReason is null || item.Definitions is null)
            || !value.EntryOrdinals.SequenceEqual(value.Entries.Select(item => item.Entry.Ordinal))
            || !value.EntryOrdinals.SequenceEqual(value.EntryOrdinals.Order())
            || value.Entries.Select(item => item.Entry.Ordinal).Distinct().Count() != value.Entries.Count)
            throw Invalid();
        var expected = value.Confidentiality switch
        {
            LapsConfidentiality.NotConfidential => value.ReadProperty.State,
            LapsConfidentiality.Confidential when value.ReadProperty.State == LapsReadState.NotEstablished
                || value.ControlAccess.State == LapsReadState.NotEstablished => LapsReadState.NotEstablished,
            _ when value.ReadProperty.State == LapsReadState.NotEstablished => LapsReadState.NotEstablished,
            _ when value.ReadProperty.State == LapsReadState.Established && value.ControlAccess.State == LapsReadState.Established
                => LapsReadState.Established,
            _ => LapsReadState.Unresolved,
        };
        if (expected != value.State) throw Invalid();
        if (value.Confidentiality != LapsAttributeReadQuestion.Requirement(value.SearchFlags, value.SystemFlags))
            throw Invalid();
        foreach (var right in new[] { value.ReadProperty, value.ControlAccess })
        {
            if (!Enum.IsDefined(right.State) || right.GrantOrdinals is null || right.BlockingOrdinals is null
                || right.Limitations is null || right.GrantOrdinals.Concat(right.BlockingOrdinals)
                    .Any(ordinal => !value.Entries.Any(item => item.Entry.Ordinal == ordinal))
                || right.State == LapsReadState.Established && right.GrantOrdinals.Count == 0) throw Invalid();
            foreach (var ordinal in right.GrantOrdinals)
            {
                var granted = value.Entries.Single(item => item.Entry.Ordinal == ordinal);
                if (granted.Scope != LapsReadState.Established || (granted.Entry.AccessMask & right.Mask) == 0
                    || granted.Entry.AceType is not ("AccessAllowed" or "AccessAllowedObject")
                    || granted.Entry.Trustee.Sid != value.TrusteeSid && granted.Entry.Trustee.Sid != "S-1-5-10")
                    throw Invalid();
            }
        }
        var rights = (value.ReadProperty.State == LapsReadState.Established, value.ControlAccess.State == LapsReadState.Established) switch
        {
            (true, true) => LapsReadRights.Both,
            (true, false) => LapsReadRights.ReadPropertyOnly,
            (false, true) => LapsReadRights.ControlAccessOnly,
            _ => LapsReadRights.Neither,
        };
        if (value.Rights != rights) throw Invalid();
        foreach (var item in value.Entries)
            if (item.Entry is null || item.Entry.Trustee is null || item.Entry.ApplicationData is null
                || !Enum.IsDefined(item.Scope) || item.ScopeReason is null || item.Definitions is null) throw Invalid();
    }

    internal static InvalidDataException Invalid() =>
        new("The saved LAPS read-permission assessment is missing, invalid or inconsistent.");

    internal static bool Bit(long value) => value switch { 0 => false, 1 => true, _ => throw Invalid() };
}
