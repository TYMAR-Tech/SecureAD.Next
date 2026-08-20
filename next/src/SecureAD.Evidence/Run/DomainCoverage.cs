namespace SecureAD.Evidence.Run;

/// <summary>
/// What happened when the run tried to read one domain.
/// </summary>
/// <remarks>
/// There is no member between <see cref="Read"/> and the two failures, and that is the decision
/// rather than an omission. See <see cref="DomainCoverage"/>.
/// </remarks>
public enum DomainReadOutcome
{
    /// <summary>The domain was read in full.</summary>
    Read,

    /// <summary>
    /// The domain was reached and part of it was read. Counts as a failure, per
    /// <c>docs/decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md</c>.
    /// </summary>
    PartiallyRead,

    /// <summary>The domain could not be read at all.</summary>
    NotRead,

    /// <summary>
    /// The operator left the domain out of the run under an attestation.
    /// </summary>
    /// <remarks>
    /// <b>Held apart from <see cref="NotRead"/>, and that is
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> rather than a
    /// preference.</b> This is <i>we did not look</i>; <see cref="NotRead"/> is <i>we tried and
    /// could not</i>. One is a decision the operator already knows about, the other may be the most
    /// important thing the run found, and a reader of coverage must tell them apart without going
    /// back to another table.
    /// </remarks>
    ExcludedByChoice,

    /// <summary>
    /// The forest named no writable controller for the domain, so nothing could read it, and it was
    /// left out under an attestation.
    /// </summary>
    /// <remarks>
    /// An exclusion under
    /// <c>docs/decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md</c> rather
    /// than a read that failed: the run never had a controller to attempt. Separate from
    /// <see cref="ExcludedByChoice"/> because a domain the forest cannot serve is a network, trust
    /// or decommissioning problem worth an administrator's attention, and separate from
    /// <see cref="NotRead"/> because nothing was attempted.
    /// </remarks>
    ExcludedForWantOfCandidates,
}

/// <summary>
/// What became of one declared domain during a run.
/// </summary>
/// <remarks>
/// <para>
/// <b>A partially read domain counts as failed.</b> It is tempting to treat it as a smaller
/// success - most of a domain is more than none of it - and that is the reasoning this type exists
/// to refuse. A domain read in part is a hole of unknown shape. Nothing downstream can see its
/// edges, so a later comparison against it reports fewer changes than really happened while
/// looking exactly like a comparison that found nothing.
/// </para>
/// <para>
/// An incomplete domain must say why, because the operator's remedy depends on it and a refusal
/// that names no cause is a refusal he cannot act on.
/// </para>
/// </remarks>
public sealed record DomainCoverage
{
    private DomainCoverage(string domainFqdn, DomainReadOutcome outcome, string? reason)
    {
        DomainFqdn = domainFqdn;
        Outcome = outcome;
        Reason = reason;
    }

    /// <summary>The domain, lowercased.</summary>
    public string DomainFqdn { get; }

    /// <summary>What happened when the run tried to read it.</summary>
    public DomainReadOutcome Outcome { get; }

    /// <summary>
    /// Why it was not read in full, in words an operator can act on. Null when
    /// <see cref="Outcome"/> is <see cref="DomainReadOutcome.Read"/>, because a domain that was
    /// read has nothing to explain.
    /// </summary>
    public string? Reason { get; }

    /// <summary>Records a domain that was read in full.</summary>
    /// <param name="domainFqdn">The domain.</param>
    public static DomainCoverage Read(string domainFqdn) =>
        new(AsDomainFqdn(domainFqdn), DomainReadOutcome.Read, reason: null);

    /// <summary>Records a domain that was reached but not read in full.</summary>
    /// <param name="domainFqdn">The domain.</param>
    /// <param name="reason">Why the read did not complete.</param>
    public static DomainCoverage PartiallyRead(string domainFqdn, string reason) =>
        new(AsDomainFqdn(domainFqdn), DomainReadOutcome.PartiallyRead, Require(reason));

    /// <summary>Records a domain that could not be read at all.</summary>
    /// <param name="domainFqdn">The domain.</param>
    /// <param name="reason">Why it could not be read.</param>
    public static DomainCoverage NotRead(string domainFqdn, string reason) =>
        new(AsDomainFqdn(domainFqdn), DomainReadOutcome.NotRead, Require(reason));

    /// <summary>
    /// Records a domain that was left out of the run under an operator's attestation.
    /// </summary>
    /// <remarks>
    /// <b>The cause is a member of the outcome, not only a sentence in the reason.</b>
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> requires every reader of
    /// coverage to tell a choice from an unreachable domain without going back to another table,
    /// and prose in <see cref="Reason"/> cannot be counted, compared or queried.
    /// </remarks>
    /// <param name="domainFqdn">The domain.</param>
    /// <param name="kind">Which kind of exclusion it was.</param>
    /// <param name="reason">What the operator stated, in words a reader can act on.</param>
    public static DomainCoverage Excluded(string domainFqdn, ExclusionKind kind, string reason) =>
        new(
            AsDomainFqdn(domainFqdn),
            kind == ExclusionKind.ForWantOfCandidates
                ? DomainReadOutcome.ExcludedForWantOfCandidates
                : DomainReadOutcome.ExcludedByChoice,
            Require(reason));

    /// <summary>
    /// Deliberately not called <c>Normalize</c>. That name belongs to <c>AceNormalizer</c> in
    /// <c>CONCEPT-REGISTRY.md</c>, and gate 2 refused it here - correctly, because a second thing
    /// called normalisation is how one question comes to have two answers.
    /// </summary>
    private static string AsDomainFqdn(string domainFqdn)
    {
        ArgumentNullException.ThrowIfNull(domainFqdn);
        ArgumentException.ThrowIfNullOrWhiteSpace(domainFqdn);
        return domainFqdn.Trim().ToLowerInvariant();
    }

    private static string Require(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return reason.Trim();
    }
}
