using System.Collections.Immutable;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

public sealed partial class BundleReader
{
    internal Result<CapturedGpoProtocolInputs> ReadGpoProtocolInputs(CapturedObjectIdentity policy, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var values = ReadObjectAttributesAt(policy,
            ["objectClass", "gPCFileSysPath", "gPCFunctionalityVersion", "versionNumber", "flags", "gPCMachineExtensionNames"]).Snapshot();
        policy = policy with
        {
            DistinguishedName = values.DistinguishedName, ObjectGuid = values.ObjectGuid,
            ObjectClass = AttributeReading.LastText(values, "objectClass"), DomainFqdn = values.DomainFqdn, PrincipalSid = null,
        };
        if (policy.ObjectGuid is not { } guid || guid == Guid.Empty
            || !string.Equals(policy.ObjectClass, "groupPolicyContainer", StringComparison.OrdinalIgnoreCase))
            return Result<CapturedGpoProtocolInputs>.Failure(Error("GpoProtocolPolicyUnqualified",
                "The selected captured row is not an identifiable policy."));
        using (var unique = Connection.CreateCommand())
        {
            unique.CommandText = "SELECT object_id FROM captured_object WHERE object_guid=$guid LIMIT 2";
            unique.Parameters.AddWithValue("$guid", guid.ToString("D"));
            using var rows = unique.ExecuteReader();
            if (!rows.Read() || rows.GetInt64(0) != policy.ObjectId || rows.Read())
                return Result<CapturedGpoProtocolInputs>.Failure(Error("GpoProtocolPolicyAmbiguous",
                    "The captured policy GUID does not bind one exact source row."));
        }
        token.ThrowIfCancellationRequested();
        var sourcePath = SingleText(values.Find("gPCFileSysPath"))?.Trim();
        using var command = Connection.CreateCommand();
        command.CommandText = """
            SELECT file_sys_path,outcome,original_bytes,original_version,version,reason
            FROM gpo_template_version WHERE gpo_guid=$gpo
            """;
        command.Parameters.AddWithValue("$gpo", guid.ToString("D"));
        using var read = command.ExecuteReader();
        if (!read.Read())
        {
            var coverage = SysvolCoverageOf(guid.ToString("D"));
            var unavailable = coverage.Outcome == GpoSettingsOutcome.Unreadable;
            var missingReason = unavailable ? coverage.Reason!
                : "This capture has no GPT.ini acquisition/version observation for this policy.";
            return Reading(new(unavailable ? GpoTemplateVersionOutcome.Unavailable : GpoTemplateVersionOutcome.NotCaptured,
                sourcePath, null, null, null, missingReason,
                Error(unavailable ? "GpoTemplateVersionUnavailable" : "GpoTemplateVersionNotCaptured", missingReason)));
        }
        var path = read.GetString(0);
        if (string.IsNullOrWhiteSpace(sourcePath) || !string.Equals(sourcePath, path, StringComparison.OrdinalIgnoreCase))
            return Result<CapturedGpoProtocolInputs>.Failure(Error("GpoTemplateVersionResourceMismatch",
                "The saved template observation is not bound to the policy's captured file-system path."));
        if (!Enum.TryParse<GpoTemplateVersionOutcome>(read.GetString(1), out var outcome))
            throw new InvalidDataException("The saved template-version outcome is invalid.");
        var bytes = read.IsDBNull(2) ? null : (byte[])read[2];
        var original = read.IsDBNull(3) ? null : read.GetString(3);
        uint? version = read.IsDBNull(4) ? null : checked((uint)read.GetInt64(4));
        var reason = read.IsDBNull(5) ? null : read.GetString(5);
        if (!new GpoTemplateVersionObservation(outcome, bytes, original, version, reason).IsConsistent)
            throw new InvalidDataException("The saved template-version observation is inconsistent.");
        return Reading(new(outcome, path, bytes?.ToImmutableArray(), original, version, reason,
            outcome == GpoTemplateVersionOutcome.Read ? null : Error("GpoTemplateVersion" + outcome, reason!)));

        Result<CapturedGpoProtocolInputs> Reading(CapturedGpoTemplateVersion template)
        {
            token.ThrowIfCancellationRequested();
            return new CapturedGpoProtocolInputs(Description.CaptureGenerationId, policy, values, template);
        }
        AuditError Error(string code, string description) =>
            AuditError.Create(ErrorCategory.Evidence, code, ErrorSeverity.Degraded, description, policy.DistinguishedName);
    }
}
