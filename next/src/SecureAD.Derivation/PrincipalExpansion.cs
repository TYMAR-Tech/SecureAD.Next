namespace SecureAD.Derivation;

/// <summary>
/// What became of an attempt to expand one principal to everything inside it.
/// </summary>
/// <remarks>
/// <b>Three of these are not failures and one is.</b> A principal that is not a group has nothing
/// inside it, which is an answer; a principal nobody captured is a question this bundle cannot
/// settle, which is a different answer; and an expansion that ran out of budget produced true
/// members and an untrue silence about the rest.
/// </remarks>
public enum PrincipalExpansionOutcome
{
    /// <summary>Everything inside the principal was reached.</summary>
    Expanded,

    /// <summary>
    /// The walk stopped at a budget. Every member listed is really inside the principal, and the
    /// absence of any other is not a fact.
    /// </summary>
    StoppedAtBudget,

    /// <summary>
    /// The principal is not in this derivation at all, so nothing can be said about what is inside
    /// it. Distinct from finding it and finding it empty.
    /// </summary>
    PrincipalNotFound,

    /// <summary>
    /// No expansion could be attempted, because the derivation carries no nesting to walk.
    /// </summary>
    NoNestingDerived,
}

/// <summary>
/// One principal found inside another, and how it got there.
/// </summary>
/// <remarks>
/// <para>
/// <b>The path is the point.</b> Telling an operator that <i>Authenticated Users</i> can read a LAPS
/// password is unusable when the route runs through six groups; telling them
/// <c>LAPS-Readers to IT-All to Site-Staff to Domain Users</c> says which link to cut. Microsoft's
/// own least-privilege guidance describes finding <i>dozens of nested groups that, when expanded,
/// reveal hundreds, even thousands, of accounts</i>, and the reason nobody acts on that is that the
/// expansion is never shown.
/// </para>
/// <para>
/// <b>One path is recorded, not all of them.</b> A principal can sit inside another by several
/// routes and enumerating every one is exponential. The first route found is the shortest, because
/// the walk goes breadth first, and a shortest route is the one an operator would cut.
/// </para>
/// </remarks>
/// <param name="Sid">The principal's SID.</param>
/// <param name="Scope">The scope the SID is unique within, empty for a forest-wide principal.</param>
/// <param name="PathFromRoot">
/// The SIDs from the principal being expanded down to this one, this one included.
/// </param>
/// <param name="IsComplete">
/// Whether everything nested below this principal was also reached. False marks the edge of a walk
/// that stopped, so a reader can see where the answer thins out rather than inferring it.
/// </param>
public sealed record ExpandedPrincipal(
    string Sid,
    string Scope,
    IReadOnlyList<string> PathFromRoot,
    bool IsComplete);

/// <summary>
/// Everything inside one principal, with what the walk could not reach.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the shared foundation SEC-090, SEC-093, the membership cycle rule and the groups
/// screen all rest on</b>, recorded as <c>P-124</c>. They differ only in which principal they start
/// from - an entry in a security descriptor, a value read out of Group Policy, or one an operator
/// typed - and building the walk once is what stops two of them disagreeing about the same nesting.
/// </para>
/// <para>
/// <b>It does not say whether anything here should be here.</b> The product cannot know which
/// principals an organisation intended, which is the owner's decision recorded as <c>P-123</c>. This
/// hands over the expansion; judging it is a rule's job, and the only judgement any rule may make
/// without local knowledge is that a member is broad in every organisation.
/// </para>
/// <para>
/// <b><see cref="Members"/> is null unless the walk reached an answer</b>, rather than empty, so
/// that <i>nobody looked</i> cannot be read as <i>nothing is inside it</i>.
/// </para>
/// </remarks>
/// <param name="RootSid">The principal that was expanded.</param>
/// <param name="Outcome">What became of the walk.</param>
/// <param name="Members">
/// Everything inside the principal, or null where no answer was reached. A group with nothing in it
/// yields an empty list, which is a different statement.
/// </param>
public sealed record PrincipalExpansion(
    string RootSid,
    PrincipalExpansionOutcome Outcome,
    IReadOnlyList<ExpandedPrincipal>? Members)
{
    /// <summary>
    /// Whether everything inside the principal was reached.
    /// </summary>
    /// <remarks>
    /// False covers a walk that stopped at a budget, a principal nobody captured, and a derivation
    /// with no nesting in it. A caller may report what is here in every case; what it may not do is
    /// say that nothing else is inside.
    /// </remarks>
    public bool IsComplete => Outcome is PrincipalExpansionOutcome.Expanded;

    /// <summary>
    /// The members that are broad in any organisation, with the path that reached each.
    /// </summary>
    /// <remarks>
    /// <b>Empty is not the same as safe unless <see cref="IsComplete"/> is true.</b> A walk that
    /// stopped early can find no broad principal and one may still be inside, which is why the two
    /// are read together and why the rules built on this must refuse rather than report silence.
    /// </remarks>
    public IReadOnlyList<ExpandedPrincipal> BroadMembers =>
        Members is null
            ? []
            : [.. Members.Where(m => BroadPrincipalCatalogue.IsBroad(m.Sid))];
}
