namespace SecureAD.Derivation;

/// <summary>
/// What became of an attempt to expand one principal to everything inside it.
/// </summary>
/// <remarks>
/// <b>Three of these are not failures and one is.</b> A principal that is not a group has nothing
/// inside it, which is an answer; a principal nobody captured is a question this bundle cannot
/// settle, which is a different answer; and an expansion that ran out of budget produced true
/// members and an untrue silence about the rest.
/// <para>
/// <b><see cref="PrincipalNotFound"/> and <see cref="PrincipalDoesNotExist"/> look alike and are
/// opposites.</b> The first is ignorance and the second is knowledge. Reading one as the other in
/// either direction is a defect: treating ignorance as knowledge reports an unknown delegation as
/// harmless, and treating knowledge as ignorance refuses to judge an entry that grants nobody
/// anything.
/// </para>
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
    /// No principal carries this identifier, and the derivation is in a position to say so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An orphaned identifier, and it is a fact rather than a refusal.</b> The identifier is
    /// domain-relative - <c>S-1-5-21-a-b-c-RID</c> - so it names the domain it belongs to; that
    /// domain was read in full; and no object in it carries the identifier. There is therefore no
    /// such principal. An access control entry naming it grants nobody anything and there is
    /// nothing inside it to fear, so a rule should judge rather than decline to answer. In
    /// practice this is most often an account that was deleted while entries naming it were left
    /// behind.
    /// </para>
    /// <para>
    /// <b>Every part of that is load-bearing, and dropping any one of them manufactures a false
    /// negative.</b> Without the domain-relative form there is no domain to check, and a built-in
    /// or well-known identifier that is merely absent would be read as non-existent. Without the
    /// domain having been read <i>in full</i>, "no object carries it" means only "no object we
    /// managed to read carries it" - which is exactly the trusted-external-forest and
    /// unreachable-domain case that must keep refusing. A partially read domain is a hole of
    /// unknown shape and is not evidence of absence.
    /// </para>
    /// <para>
    /// Answered by <see cref="PrincipalNotFound"/> wherever the derivation cannot prove all three,
    /// because the failure that matters here is the one that reports a broad delegation as inert.
    /// </para>
    /// </remarks>
    PrincipalDoesNotExist,

    /// <summary>
    /// No expansion could be attempted, because the derivation carries no nesting to walk.
    /// </summary>
    NoNestingDerived,

    /// <summary>
    /// The walk finished, but passed through a group whose <c>groupType</c> was never captured, so
    /// whether that route carries authorization at all is unknown.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The route is followed and the answer is marked, which is the cautious pair.</b> A group
    /// whose type nobody recorded is not thereby a distribution group, so refusing to traverse it
    /// would drop authorization that exists and report a live delegation as inert. Traversing it
    /// silently would do the opposite, naming principals who may hold nothing. Members reached this
    /// way are therefore returned, and the walk says it cannot vouch for them.
    /// </para>
    /// <para>
    /// <b>Kept apart from <see cref="StoppedAtBudget"/> although both mean incomplete.</b> A budget
    /// says more members exist and were not reached; this says the members reached may not be
    /// members for authorization purposes at all. They thin the answer from opposite ends, and one
    /// standing in for the other would put a false sentence in a run log.
    /// </para>
    /// </remarks>
    ExpandedThroughUnknownGroupType,

    /// <summary>
    /// The walk finished, but a group it passed through claimed a member that no captured object
    /// answers to, so what that group holds is not fully known.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the difference between an empty group and an unreadable one.</b> A membership link
    /// naming something the capture never read cannot become an edge, so the group it belonged to
    /// carries fewer members than the directory says it has - and without this the answer would be
    /// indistinguishable from a group that really holds nobody. A rule would then report the object
    /// clean, which is could-not-work-it-out presented as nothing-to-report. P-164.
    /// </para>
    /// <para>
    /// <b>Kept apart from <see cref="StoppedAtBudget"/> although both mean members were not
    /// reached.</b> A budget is this product's own limit and raising it would find the rest; an
    /// unidentified member is a hole in the capture that no amount of walking will fill. Saying
    /// "ran out of room" where nothing was ever read would put a false sentence in a run log and
    /// point an operator at a setting rather than at their capture scope.
    /// </para>
    /// <para>
    /// <b>And apart from <see cref="ExpandedThroughUnknownGroupType"/>, which thins the answer from
    /// the other end.</b> That one says the members returned may not count for authorization; this
    /// says members exist that were never returned at all.
    /// </para>
    /// </remarks>
    ExpandedWithUnidentifiedMember,
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
/// that stopped, so a reader can see where the answer thins out rather than inferring it, and also
/// a group that claimed a member no captured object answers to - the walk reached everything it
/// could, and what it could reach is not everything the directory says is there.
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
    /// False covers a walk that stopped at a budget, a walk that passed through a group whose type
    /// was never captured, a group that claimed a member no captured object answers to, a principal
    /// nobody captured, and a derivation with no nesting in it. A caller may report what is here in
    /// every case; what it may not do is say that nothing else is inside.
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
