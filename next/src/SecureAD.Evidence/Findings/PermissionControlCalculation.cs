using SecureAD.Kernel.Security;

namespace SecureAD.Evidence.Findings;

public enum PermissionControlState
{
    Established,
    NotEstablished,
    Unknown,
}

public sealed record PermissionControlRightAssessment(PermissionControlState State,
    IReadOnlyList<int> GrantOrdinals, IReadOnlyList<int> BlockingOrdinals, IReadOnlyList<string> Limitations);

public sealed record PermissionControlCondition(string Name, PermissionControlState State, string Basis);

/// <summary>Saved named-holder permission conclusions, not an individual token or completed owner transition.</summary>
public sealed record PermissionControlCalculation(Guid GenerationId, string EvidenceSeal,
    Guid DerivationGenerationId, string DerivationSeal, Guid ObjectGuid, string Target, string? ResourceDomain,
    string HolderSid, string? HolderScope, string BroadSid, DaclState DescriptorState,
    DaclCompleteness DescriptorCompleteness, bool DaclWasCanonical, PermissionControlRightAssessment ModifyPermissions,
    PermissionControlRightAssessment ChangeOwner, PermissionControlRightAssessment FullControl,
    PermissionControlState OwnerRightsCondition, PermissionControlState OwnerTransition,
    IReadOnlyList<PermissionControlCondition> OwnerConditions, IReadOnlyList<string> Limitations,
    bool SupportingEntryIsInherited)
{
    public bool IsComplete => ModifyPermissions.State != PermissionControlState.Unknown
        && ChangeOwner.State != PermissionControlState.Unknown && FullControl.State != PermissionControlState.Unknown
        && Limitations.Count == 0;
}
