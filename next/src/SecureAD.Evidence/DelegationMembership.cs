namespace SecureAD.Evidence;

/// <summary>A scoped identity participating in the selected principal's saved membership relationships.</summary>
public sealed record DelegationMemberNode(int Id, string Sid, string Scope, Guid? ObjectGuid,
    bool? IsGroup, bool? IsSecurityEnabled)
{
    /// <summary>The identity independently resolved against the same protected evidence.</summary>
    public DelegationPrincipal? Principal { get; init; }
}

/// <summary>One saved relationship; primary-group membership remains distinct from an ordinary link.</summary>
public sealed record DelegationMemberLink(int MemberId, int GroupId, bool IsPrimaryGroup);

/// <summary>A finite supporting graph, never an enumeration of exponentially many route combinations.</summary>
public sealed record DelegationMembership(Guid GenerationId, string EvidenceFingerprint, int RootId,
    IReadOnlyList<DelegationMemberNode> Nodes, IReadOnlyList<DelegationMemberLink> Links, IReadOnlyList<string> Warnings);
