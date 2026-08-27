using SecureAD.Evidence.Run;

namespace SecureAD.Derivation;

/// <summary>
/// What a derived answer does not cover, carried beside the answer rather than left to be
/// rediscovered.
/// </summary>
/// <remarks>
/// <para>
/// <b>A missing input travels through derivation and judgement; it is never converted to an empty
/// set.</b> That conversion is the failure this type exists to prevent. A closure that could not
/// reach half a forest and a closure that reached all of it and found nothing look identical once
/// the difference is dropped, and the first one reads as a clean result.
/// </para>
/// <para>
/// <b>One instance describes the whole derivation rather than one per product.</b> All three
/// products come from one graph built by one pass over one bundle, so their coverage is the same
/// coverage. Three copies would be three things that can disagree about a single fact.
/// </para>
/// </remarks>
/// <param name="IsComplete">
/// Whether everything the derivation set out to establish was established. False does not mean the
/// answers are wrong; it means they are floors.
/// </param>
/// <param name="PartialGroups">
/// Groups whose membership was never worked out, because a budget stopped the expansion first.
/// </param>
/// <param name="MissingPartitions">
/// Declared domains the capture did not read in full, each carrying why. A domain left out by
/// choice and one that could not be reached are both missing from the graph and are not the same
/// fact, which is why the coverage rows are kept whole rather than reduced to a list of names.
/// </param>
/// <param name="UnresolvedTrustees">
/// Names a group claimed as a member that no captured object answers to.
/// </param>
/// <param name="DerivationGenerationId">Which derive run produced the answers this describes.</param>
/// <param name="Limit">Which budget stopped the expansion, when one did.</param>
/// <param name="CollapsedStubs">
/// How many captured objects named a principal another object had already answered for - a
/// foreignSecurityPrincipal standing in for someone from another domain, most often. They are the
/// same principal, so one row is right, but the count says how much of the directory was folded.
/// </param>
/// <param name="UnscopedBuiltins">
/// How many built-in SIDs arrived with no domain to scope them by, and so could not be told apart
/// from the same SID elsewhere in the forest. Zero on a whole capture. Anything else means this
/// many principals may have been merged, which is the defect
/// <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c> exists to prevent - so it is
/// stated rather than assumed to be nothing.
/// </param>
public sealed record DerivationCompleteness(
    bool IsComplete,
    IReadOnlyList<int> PartialGroups,
    IReadOnlyList<DomainCoverage> MissingPartitions,
    IReadOnlyList<string> UnresolvedTrustees,
    Guid DerivationGenerationId,
    ExpansionLimit Limit,
    int CollapsedStubs = 0,
    int UnscopedBuiltins = 0)
{
    /// <summary>
    /// Gathers what the pass, the expansion and the capture's own coverage each had to say.
    /// </summary>
    /// <remarks>
    /// <b>Completeness is derived from the three of them together and never asserted.</b> Each knows
    /// about a different kind of hole - a member nobody could resolve, a budget reached, a domain
    /// never read - and any one of them is enough to make an answer a floor.
    /// </remarks>
    /// <param name="facts">What one pass over the bundle found.</param>
    /// <param name="closure">The membership expansion.</param>
    /// <param name="scope">What the capture covered, one entry per declared domain.</param>
    /// <param name="derivationGenerationId">The derive run's identifier.</param>
    /// <returns>What the derivation does not cover.</returns>
    public static DerivationCompleteness Of(
        NestingFacts facts,
        MembershipClosure closure,
        RunScope scope,
        Guid derivationGenerationId)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(scope);

        // Anything the capture did not read in full is a hole in this graph, whether it was
        // unreachable or deliberately left out. Both are kept, whole, because 0063 requires a
        // reader to tell a choice from a failure without going back to another table.
        var missing = scope.Domains
            .Where(d => d.Outcome != DomainReadOutcome.Read)
            .ToList();

        // A built-in SID nobody could scope may have been merged with the same SID in another
        // domain, which is a principal this graph gets wrong rather than one it merely omits. It
        // therefore counts against completeness. Collapsing a stub does not: the stub and the
        // principal it stands in for are the same principal, so folding them loses no fact.
        var isComplete =
            closure.IsComplete
            && closure.PartialGroups.Count == 0
            && facts.UnresolvedTrustees.Count == 0
            && missing.Count == 0
            && facts.Sids.UnscopedBuiltins == 0;

        return new DerivationCompleteness(
            isComplete,
            closure.PartialGroups,
            missing,
            facts.UnresolvedTrustees,
            derivationGenerationId,
            closure.Limit,
            facts.CollapsedStubs,
            facts.Sids.UnscopedBuiltins);
    }
}

/// <summary>
/// Everything stage 2a derives from one bundle, and what it does not cover.
/// </summary>
/// <remarks>
/// <b>The three products are separate because they answer different questions about the same
/// edges.</b> One principal can be outside a group's authorization membership, inside its protected
/// set, and one attribute change away from holding its authority - all three at once, all three
/// true. A single closure would have to be wrong about two of them.
/// </remarks>
/// <param name="Facts">The nesting the pass read out of the bundle.</param>
/// <param name="Graph">Those facts as a graph, for anything that wants to walk them again.</param>
/// <param name="Membership">Which memberships can take part in authorization.</param>
/// <param name="Protection">Which principals AdminSDHolder covers.</param>
/// <param name="LatentPaths">Which distribution groups are one conversion from conferring privilege.</param>
/// <param name="Completeness">What none of the above covers.</param>
public sealed record Stage2aDerivation(
    NestingFacts Facts,
    NestingGraph Graph,
    MembershipClosure Membership,
    ProtectedPrincipalClosure Protection,
    IReadOnlyList<LatentPrivilegePath> LatentPaths,
    DerivationCompleteness Completeness);
