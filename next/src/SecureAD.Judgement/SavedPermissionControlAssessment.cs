using System.Text.Json.Serialization;
using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Compact version-3 display values; original permission references remain in the calculation product.</summary>
public sealed record SavedPermissionControlAssessment(Guid GenerationId, string EvidenceSeal,
    Guid DerivationGenerationId, string DerivationSeal, Guid ObjectGuid, string Target, string? ResourceDomain,
    string HolderSid, string? HolderScope, string BroadSid, DaclState DescriptorState,
    DaclCompleteness DescriptorCompleteness, PermissionControlState ModifyPermissions, PermissionControlState ChangeOwner,
    PermissionControlState FullControl, PermissionControlState OwnerTransition, bool HasLimitations,
    bool SupportingEntryIsInherited, long ChainCount)
{
    [JsonIgnore]
    public bool IsComplete => ModifyPermissions != PermissionControlState.Unknown
        && ChangeOwner != PermissionControlState.Unknown && FullControl != PermissionControlState.Unknown && !HasLimitations;

    internal static SavedPermissionControlAssessment From(PermissionControlCalculation value, long chainCount) =>
        new(value.GenerationId, value.EvidenceSeal, value.DerivationGenerationId, value.DerivationSeal, value.ObjectGuid,
            value.Target, value.ResourceDomain, value.HolderSid, value.HolderScope, value.BroadSid, value.DescriptorState,
            value.DescriptorCompleteness, value.ModifyPermissions.State, value.ChangeOwner.State, value.FullControl.State,
            value.OwnerTransition, value.Limitations.Count != 0, value.SupportingEntryIsInherited, chainCount);

    internal bool HasExpectedShape => GenerationId != Guid.Empty && ObjectGuid != Guid.Empty
        && new Tier0InputBinding(EvidenceSeal, DerivationGenerationId, DerivationSeal,
            PrincipalClassificationRegistry.Version, 2, 2, null, null).IsSupported
        && !string.IsNullOrWhiteSpace(Target) && Sid.ToBytes(HolderSid) is not null
        && BroadPrincipalCatalogue.IsBroad(BroadSid)
        && HolderScope == (Sid.IsBuiltinDomain(HolderSid) ? ResourceDomain : null)
        && (!Sid.IsBuiltinDomain(HolderSid) || !string.IsNullOrWhiteSpace(HolderScope))
        && Enum.IsDefined(DescriptorState) && DescriptorState != DaclState.Unreadable
        && Enum.IsDefined(DescriptorCompleteness) && Enum.IsDefined(ModifyPermissions)
        && Enum.IsDefined(ChangeOwner) && Enum.IsDefined(FullControl) && Enum.IsDefined(OwnerTransition)
        && OwnerTransition == (ChangeOwner == PermissionControlState.NotEstablished
            ? PermissionControlState.NotEstablished : PermissionControlState.Unknown)
        && (DescriptorState != DaclState.Null || !SupportingEntryIsInherited) && ChainCount > 0;

    internal ObjectTakeoverRight? ReportedRight => FullControl == PermissionControlState.Established ? ObjectTakeoverRight.GenericAll
        : ModifyPermissions == PermissionControlState.Established ? ObjectTakeoverRight.WriteDacl
        : ChangeOwner == PermissionControlState.Established ? ObjectTakeoverRight.WriteOwner : null;

    internal bool Matches(SavedPermissionControl value) => HasExpectedShape && GenerationId == value.Reference.GenerationId
        && ObjectGuid == value.Object.ObjectGuid && Target == value.Object.DistinguishedName
        && (ResourceDomain ?? "") == value.Object.DomainFqdn && HolderSid == value.HolderSid && BroadSid == value.BroadSid
        && SupportingEntryIsInherited == value.InheritedContext && ReportedRight == value.ReportedRight && ChainCount == value.ChainCount;
}
