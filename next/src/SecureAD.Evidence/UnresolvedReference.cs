namespace SecureAD.Evidence;

/// <summary>
/// What one object was pointing at when it named something the run never saw.
/// </summary>
/// <remarks>
/// The four kinds named by <c>docs/decisions/0022</c>. Each is a way one object refers to another,
/// and each produces a hole of a different shape: a missing group member understates who holds a
/// privilege, a missing permission trustee leaves an entry nobody can attribute, a missing parent
/// container breaks the containment chain that inherited permissions travel down, and a missing
/// primary group hides a membership that is stored as a number rather than as a link.
/// </remarks>
public enum UnresolvedReferenceKind
{
    /// <summary>A member of a group, named in <c>member</c>.</summary>
    GroupMember,

    /// <summary>A trustee named by an access control entry.</summary>
    PermissionTrustee,

    /// <summary>The container this object sits in.</summary>
    ParentContainer,

    /// <summary>The group named by this object's <c>primaryGroupID</c>.</summary>
    PrimaryGroup,
}

/// <summary>
/// Why something one object pointed at was never seen.
/// </summary>
/// <remarks>
/// <para>
/// The closed four from <c>docs/decisions/0022</c>, with no free text beside them. The predecessor
/// carried a typed category and a prose reason together, and the prose was not the defect - reading
/// behaviour off its wording was, which turned a display string into a contract and made rewording
/// a message change a metric. What the prose also carried was <i>which</i> thing was missing, and
/// that is data rather than explanation, so it is stored as the reference itself.
/// </para>
/// <para>
/// <b>There is deliberately no <c>Undetermined</c>.</b> The predecessor had one and it was
/// well-reasoned: a re-analysis of a saved capture does not know the forest's domain list, so it
/// could not honestly say whether a member was in the forest or outside it. Its defect was that the
/// member was reachable by omission - it was the default of the C# parameter <i>and</i> of the
/// column - so anything that forgot to classify silently claimed to have no opinion. Here the state
/// does not exist at all, because <c>docs/next/S-15</c> removed re-analysis: every bundle is now
/// written by the run that read the forest, so the domain list is always known.
/// </para>
/// </remarks>
public enum UnresolvedReferenceReason
{
    /// <summary>
    /// It belongs to a domain in this forest that the run did not capture. The privilege graph is
    /// incomplete here, and this is the reason that counts against coverage.
    /// </summary>
    DomainNotCaptured,

    /// <summary>
    /// It belongs to a forest this run is not auditing, reached across a trust. Legitimately out of
    /// scope rather than missing.
    /// </summary>
    AnotherForest,

    /// <summary>
    /// It names something that does not exist: a deleted object, or an identifier left behind by
    /// one. Says nothing about coverage.
    /// </summary>
    OrphanedIdentifier,

    /// <summary>
    /// It is in a captured partition and could not be read - the reference resolves to somewhere
    /// this run should have been able to see and was not.
    /// </summary>
    Unreadable,
}
