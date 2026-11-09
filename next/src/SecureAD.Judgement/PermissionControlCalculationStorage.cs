using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class PermissionControlCalculationStorage
{
    internal static void Validate(Finding finding, Guid generation, string evidenceSeal, Guid? derivation)
    {
        if (finding.Evidence is not ObjectTakeoverEvidence evidence || evidence.Calculation is not { } value)
            throw Invalid();
        Validate(value, generation, evidenceSeal, derivation, finding.ObjectGuid, finding.DistinguishedName,
            finding.DomainFqdn, evidence.TrusteeSid, evidence.BroadPrincipalSid, evidence.Right);
        if (finding.RuleId != "SEC-060" || finding.RuleVersion != BroadPrincipalCanTakeOverObject.RuleVersion
            || finding.Severity != Severity.High || finding.Subject.Kind != FindingSubjectKind.Account
            || finding.Subject.Key != BroadPrincipalCanTakeOverObject.SubjectKeyFor(value.BroadSid)
            || evidence.InheritedFrom is not null || evidence.MembershipPath.Count == 0
            || evidence.MembershipPath[0].Sid != value.HolderSid || evidence.MembershipPath[^1].Sid != value.BroadSid)
            throw Invalid();
    }

    internal static void Validate(PermissionControlCalculation value, Guid generation, string evidenceSeal,
        Guid? derivation, Guid objectGuid, string target, string domain, string holder, string broad, ObjectTakeoverRight right)
    {
        ValidateShape(value);
        if (value.GenerationId != generation || value.EvidenceSeal != evidenceSeal
            || value.DerivationGenerationId != derivation || value.ObjectGuid != objectGuid || value.Target != target
            || (value.ResourceDomain ?? "") != domain || value.HolderSid != holder || value.BroadSid != broad
            || Strongest(value) != right) throw Invalid();
    }

    internal static PermissionControlCalculation Read(SqliteConnection connection, long findingId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT payload,calculation_complete FROM finding_object_takeover_calculation WHERE finding_id=$id";
        command.Parameters.AddWithValue("$id", findingId);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string payload || row.GetValue(1) is not long complete
            || complete is not (0 or 1)) throw Invalid();
        PermissionControlCalculation? value;
        try { value = JsonSerializer.Deserialize<PermissionControlCalculation>(payload, ProofSerialization.Options); }
        catch (JsonException error) { throw new InvalidDataException(Invalid().Message, error); }
        if (value is null) throw Invalid();
        ValidateShape(value);
        if (value.IsComplete != (complete == 1)) throw Invalid();
        return value;
    }

    private static void ValidateShape(PermissionControlCalculation value)
    {
        if (value.GenerationId == Guid.Empty || !new Tier0InputBinding(value.EvidenceSeal, value.DerivationGenerationId,
                value.DerivationSeal, PrincipalClassificationRegistry.Version, 2, 2, null, null).IsSupported
            || value.ObjectGuid == Guid.Empty || string.IsNullOrWhiteSpace(value.Target)
            || Sid.ToBytes(value.HolderSid) is null || !BroadPrincipalCatalogue.IsBroad(value.BroadSid)
            || value.HolderScope != (Sid.IsBuiltinDomain(value.HolderSid) ? value.ResourceDomain : null)
            || Sid.IsBuiltinDomain(value.HolderSid) && string.IsNullOrWhiteSpace(value.HolderScope)
            || !Enum.IsDefined(value.DescriptorState) || value.DescriptorState == DaclState.Unreadable
            || !Enum.IsDefined(value.DescriptorCompleteness) || !Enum.IsDefined(value.OwnerRightsCondition)
            || !Enum.IsDefined(value.OwnerTransition) || value.OwnerTransition == PermissionControlState.Established
            || value.OwnerConditions is null || value.Limitations is null
            || value.Limitations.Any(string.IsNullOrWhiteSpace)
            || value.OwnerConditions.Any(condition => condition is null || string.IsNullOrWhiteSpace(condition.Name)
                || string.IsNullOrWhiteSpace(condition.Basis) || !Enum.IsDefined(condition.State))) throw Invalid();
        ValidateRight(value.ModifyPermissions);
        ValidateRight(value.ChangeOwner);
        ValidateRight(value.FullControl);
        if (value.DescriptorState != DaclState.Null
            && new[] { value.ModifyPermissions, value.ChangeOwner, value.FullControl }
                .Any(right => right.State == PermissionControlState.Established && right.GrantOrdinals.Count == 0))
            throw Invalid();
        if (value.ChangeOwner.State != PermissionControlState.NotEstablished
            && (value.OwnerTransition != PermissionControlState.Unknown
                || !value.OwnerConditions.Any(condition => condition.Name == "ControlledOwnerSidTransition"
                    && condition.State == PermissionControlState.Unknown && condition.Basis == "OwnerTransitionLabRequired")))
            throw Invalid();
        if (value.ChangeOwner.State == PermissionControlState.NotEstablished
            ? value.OwnerConditions.Count != 0 || value.OwnerRightsCondition != PermissionControlState.NotEstablished
                || value.OwnerTransition != PermissionControlState.NotEstablished
            : value.OwnerConditions.Count(condition => condition.Name == "OwnerWouldReceiveWriteDacl"
                && condition.State == value.OwnerRightsCondition) != 1)
            throw Invalid();
    }

    private static void ValidateRight(PermissionControlRightAssessment right)
    {
        if (right is null || !Enum.IsDefined(right.State) || right.GrantOrdinals is null || right.BlockingOrdinals is null
            || right.Limitations is null || right.GrantOrdinals.Any(ordinal => ordinal < 0)
            || right.BlockingOrdinals.Any(ordinal => ordinal < 0)
            || !right.GrantOrdinals.SequenceEqual(right.GrantOrdinals.Distinct().Order())
            || !right.BlockingOrdinals.SequenceEqual(right.BlockingOrdinals.Distinct().Order())
            || right.Limitations.Any(string.IsNullOrWhiteSpace)
            || right.State == PermissionControlState.Established && right.Limitations.Count != 0) throw Invalid();
    }

    private static ObjectTakeoverRight? Strongest(PermissionControlCalculation value) =>
        value.FullControl.State == PermissionControlState.Established ? ObjectTakeoverRight.GenericAll
            : value.ModifyPermissions.State == PermissionControlState.Established ? ObjectTakeoverRight.WriteDacl
            : value.ChangeOwner.State == PermissionControlState.Established ? ObjectTakeoverRight.WriteOwner : null;

    internal static InvalidDataException Invalid() =>
        new("The saved SEC-060 calculation is missing, invalid or belongs to another source or target.");
}
