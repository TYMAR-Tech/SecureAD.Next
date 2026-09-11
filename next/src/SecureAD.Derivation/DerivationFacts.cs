using SecureAD.Evidence.Run;

namespace SecureAD.Derivation;

/// <summary>
/// One SID and the principal it identifies.
/// </summary>
/// <param name="SidId">The SID.</param>
/// <param name="PrincipalSidId">The current SID of the principal it identifies.</param>
/// <param name="Kind">Whether this is that principal's own SID or one it carries from a migration.</param>
internal readonly record struct SidIdentityRow(int SidId, int PrincipalSidId, SidIdentityKind Kind);

/// <summary>
/// One domain, the SID its principals share, and what the run made of reading it.
/// </summary>
/// <remarks>
/// <b>This is what lets an unresolvable identifier be attributed to a domain.</b> An
/// <c>S-1-5-21-a-b-c-RID</c> identifier names its domain in its own text, so a row here turns that
/// prefix into a statement about whether the run saw the whole of the domain it came from - and so
/// into whether "nothing carries this identifier" is evidence of absence or of a gap.
/// </remarks>
/// <param name="DomainSid">The domain's SID, the prefix its principals' identifiers share.</param>
/// <param name="DomainFqdn">The domain, for a reader diagnosing a run.</param>
/// <param name="Outcome">What the run made of reading it.</param>
internal readonly record struct DomainReadCoverageRow(
    string DomainSid,
    string DomainFqdn,
    DomainReadOutcome Outcome);


/// <summary>
/// Everything about one principal that a membership question needs, other than its edges.
/// </summary>
/// <remarks>
/// <b><paramref name="GroupType"/> is null for two different reasons and the difference matters.</b>
/// A principal that is not a group has no group type; a group whose <c>groupType</c> the capture
/// did not record has one nobody knows. <paramref name="IsGroup"/> is what tells them apart, which
/// is why it is carried separately rather than inferred from this being null.
/// </remarks>
/// <param name="SidId">The principal's current SID.</param>
/// <param name="ObjectGuid">The object's GUID, so a derived fact can name something durable.</param>
/// <param name="IsGroup">Whether <c>objectClass</c> called it a group.</param>
/// <param name="GroupType">The raw <c>groupType</c> flags word, when one was captured.</param>
/// <param name="PrimaryGroupSidId">
/// The group named by <c>primaryGroupID</c>, when the principal is an account that had one. Held
/// here rather than as an edge: it is real membership, but it is also the most uniform fact in the
/// directory, and materialising it would add one row per account all pointing at Domain Users.
/// </param>
internal readonly record struct PrincipalRow(
    int SidId,
    Guid ObjectGuid,
    bool IsGroup,
    int? GroupType,
    int? PrimaryGroupSidId)
{
    public string? DistinguishedName { get; init; }
}

/// <summary>
/// One directory nesting relationship: <paramref name="MemberSidId"/> is directly in
/// <paramref name="GroupSidId"/>.
/// </summary>
/// <remarks>
/// <b>A struct because there are more of these than of anything else.</b> A forest's nesting is
/// millions of these, and as a class each one would be a separate heap allocation for the garbage
/// collector to trace. Two integers in a struct is the whole edge.
/// </remarks>
/// <param name="GroupSidId">The containing group.</param>
/// <param name="MemberSidId">The principal directly inside it.</param>
internal readonly record struct NestingEdge(int GroupSidId, int MemberSidId);

/// <summary>Which side of a membership link the name nobody could resolve sat on.</summary>
/// <remarks>
/// <b>The two thin opposite answers, which is why they are not one value.</b> A group naming a
/// member nobody captured leaves that group's contents short; a principal naming a containing
/// group nobody captured leaves what encloses that principal short. Recording them
/// undirected would let a walk asking one question spend the other question's evidence.
/// </remarks>
internal enum NestingLinkDirection
{
    /// <summary>A group named something inside it that no captured object answers to.</summary>
    Member,

    /// <summary>A principal named a group containing it that no captured object answers to.</summary>
    ContainingGroup,
}

/// <summary>
/// A membership link that named something no captured object answers to, kept against the end of
/// it that did resolve.
/// </summary>
/// <remarks>
/// <b>Dropping one of these is how an unreadable group came to look empty.</b> The link cannot
/// become a <see cref="NestingEdge"/> because one end names no principal, and discarding it left
/// the other end indistinguishable from a principal that genuinely had no such relationship.
/// P-164.
/// </remarks>
/// <param name="SidId">The end of the link that resolved.</param>
/// <param name="Direction">Which side the unresolvable name sat on.</param>
/// <param name="DistinguishedName">The name nothing answered to.</param>
internal readonly record struct UnresolvedNestingLink(
    int SidId,
    NestingLinkDirection Direction,
    string DistinguishedName);
