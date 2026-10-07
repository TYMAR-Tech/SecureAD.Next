namespace SecureAD.Evidence.Findings;

/// <summary>A captured group identity; repeated BUILTIN SIDs remain scoped to their domain.</summary>
public sealed record CircularMembershipGroup(Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    string Sid, string? SidScope);

/// <summary>An original member or memberOf value supporting a direct relationship.</summary>
public sealed record CircularMembershipWitness(Guid SourceObjectGuid, string Attribute, int Ordinal, string Value);

/// <summary>A direct captured relationship, not an ordered cycle path or a permission grant.</summary>
public sealed record CircularMembershipLink(Guid GroupGuid, Guid MemberGuid, IReadOnlyList<CircularMembershipWitness> Witnesses)
{
    /// <summary>Whether this relationship has a recorded source value, not whether a group's entire membership is visible.</summary>
    public bool IsComplete => Witnesses.Count != 0;
}

/// <summary>A recorded strongly connected group set with explicit inventory completeness.</summary>
public sealed record CircularMembershipEvidence(string EvidenceSeal, Guid DerivationGenerationId,
    string ComponentKey, IReadOnlyList<CircularMembershipGroup> Groups, IReadOnlyList<CircularMembershipLink> Links,
    bool InventoryComplete) : FindingEvidence
{
    /// <summary>The cycle inventory's coverage, independent of the positive membership witnesses.</summary>
    public bool IsComplete => InventoryComplete;
}
