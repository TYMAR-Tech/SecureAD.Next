namespace SecureAD.Evidence.Run;

/// <summary>
/// How much of the forest a run actually read, set against what it declared it would.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CoverageId"/> records what the forest reported when the run started.
/// This records what became of each of those domains. The two are separate because a run whose
/// declaration was not achieved must keep its declared identity - otherwise a controller dying at
/// hour two would give the run a private key and strand it on a comparison island of one, hiding
/// the failure instead of reporting it.
/// </para>
/// <para>
/// Construction refuses two disagreements between the declaration and the outcomes, in both
/// directions. A reported domain that was never declared means capture and discovery disagree
/// about what the forest is, and choosing which to believe is not this type's business. A declared
/// domain with no outcome at all is the dangerous one: it is a domain nobody looked at, and
/// treating that silence as success is the single defect this product cannot have.
/// </para>
/// </remarks>
public sealed record RunCoverage
{
    private RunCoverage(
        CoverageId declared,
        IReadOnlyList<DomainCoverage> domains,
        IReadOnlyList<ForestPartitionCoverage> forestPartitions,
        SysvolCoverage sysvol,
        IReadOnlyList<string> incompleteDomains,
        IReadOnlyList<string> unreadForestPartitions)
    {
        Declared = declared;
        Domains = domains;
        ForestPartitions = forestPartitions;
        Sysvol = sysvol;
        IncompleteDomains = incompleteDomains;
        UnreadForestPartitions = unreadForestPartitions;
    }

    /// <summary>What the forest reported when the run started.</summary>
    public CoverageId Declared { get; }

    /// <summary>What became of each declared domain, ordered by domain name.</summary>
    public IReadOnlyList<DomainCoverage> Domains { get; }

    /// <summary>
    /// What became of the two partitions that belong to the forest rather than to any domain,
    /// ordered by kind.
    /// </summary>
    /// <remarks>
    /// Held beside <see cref="Domains"/> rather than among them, per
    /// <c>docs/decisions/0035</c>: the configuration and schema partitions are the forest's, so a
    /// run that could not read one has failed rather than found a domain with a problem. Before
    /// this existed there was nowhere to record that failure, and a run that never read the schema
    /// partition still reported every domain as covered.
    /// </remarks>
    public IReadOnlyList<ForestPartitionCoverage> ForestPartitions { get; }

    /// <summary>
    /// What became of the Group Policy files on the SYSVOL share.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Held beside <see cref="Domains"/> for the same reason <see cref="ForestPartitions"/> is, and
    /// on a narrower licence. Per
    /// <c>docs/decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md</c> a thing
    /// that is not a capture unit may record coverage only where its incompleteness has knowable
    /// edges; SYSVOL qualifies because the policy list comes from the directory before any file is
    /// opened.
    /// </para>
    /// <para>
    /// <b>It is deliberately absent from <see cref="AllDeclaredUnitsAreComplete"/>.</b> A SYSVOL
    /// failure does not fail the run, so this value genuinely varies between bundles, while that
    /// flag is an internal check that is true in all of them. A future session proposing to unify
    /// the two should read <c>0044</c> first: merging them converts an always-true invariant into a
    /// customer-facing verdict, which is the defect <c>F-S29-3</c> was raised about.
    /// </para>
    /// </remarks>
    public SysvolCoverage Sysvol { get; }

    /// <summary>
    /// The domains that were not read in full, ordered by name.
    /// </summary>
    /// <remarks>
    /// Kept separately so a refusal can name them. An operator told only that his run is unusable
    /// has been told what, and not what to fix.
    /// </remarks>
    public IReadOnlyList<string> IncompleteDomains { get; }

    /// <summary>
    /// The forest-wide partitions that could not be read, ordered by kind, and named for the same
    /// reason as <see cref="IncompleteDomains"/>.
    /// </summary>
    public IReadOnlyList<string> UnreadForestPartitions { get; }

    /// <summary>
    /// Whether every declared domain and both forest-wide partitions have a recorded outcome saying
    /// they were read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It is an internal consistency check, not a statement about a customer's forest, and it was
    /// called <c>IsComplete</c> until <c>F-S29-3</c> while being consulted as though it were the
    /// second thing.</b> Capture is fail-fast per
    /// <c>docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md</c>: a domain that could
    /// not be read returns before the seal, and a domain with no recorded outcome makes
    /// <see cref="Of"/> throw. So in any bundle a reader can open, this is true. It cannot report a
    /// forest that was partly read, because no such bundle exists.
    /// </para>
    /// <para>
    /// <b>Kept because it is the enforcement of a rule, not because it varies.</b>
    /// <c>docs/decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md</c> says a
    /// run that did not read every domain it set out to read may not be a baseline and may not be
    /// compared. Today that is guaranteed upstream: capture refuses to seal a bundle in which a
    /// declared domain was left unread without an attestation. This is what would catch a bundle
    /// written by some future second path - controller failover, parallel capture, anything
    /// re-analysis-shaped - that produced a hole.
    /// Removing it would leave the rule stated and unenforced.
    /// </para>
    /// <para>
    /// <b>An excluded domain makes this false, and that is not a failure.</b> The property is
    /// literally <i>every declared domain has an outcome saying it was read</i>, and an exclusion is
    /// not a read - so a run that legitimately left a domain out reports false here while being
    /// perfectly sound. Read as <i>this run may not be a baseline</i> it would be wrong since
    /// <c>0052</c> reintroduced exclusion and <c>0069</c> gave each scope its own baseline. The
    /// remark above previously said incompleteness was guaranteed away by refusing to seal, which
    /// taken with this definition would have meant a run with any exclusion could never seal at all.
    /// It can; the bundle has a table for storing exclusions. Corrected 2026-08-21.
    /// </para>
    /// <para>
    /// <b>It is therefore never shown to a reader as coverage.</b> What a run covered is stated by
    /// the partition rows and by <c>unread_partition</c>, both of which vary by forest. Presenting
    /// an always-true flag as a coverage verdict is the defect <c>F-S29-3</c> was raised about, one
    /// level up.
    /// </para>
    /// <para>
    /// <b>The name takes the <c>*AreComplete</c> shape deliberately.</b> It says the record of the
    /// declared units is exhaustive - the same sense
    /// <c>PartitionCoverage.ContinuationReferencesAreComplete</c> carries, one level up - rather
    /// than claiming a forest was fully read. Gate 4 already accepts that shape, and widening the
    /// gate a second time in one session to admit a longer name would cost more than the extra
    /// precision was worth.
    /// </para>
    /// </remarks>
    public bool AllDeclaredUnitsAreComplete =>
        IncompleteDomains.Count == 0 && UnreadForestPartitions.Count == 0;

    /// <summary>
    /// Sets the outcomes of a run against what it declared.
    /// </summary>
    /// <param name="declared">The evidence identity the run recorded when it started.</param>
    /// <param name="domains">What became of each declared domain.</param>
    /// <param name="forestPartitions">
    /// What became of the configuration and schema partitions. Both are required, and there is no
    /// overload that omits them: every forest has exactly one of each, so unlike the domain list
    /// their denominator is known without discovery, and a default of <i>none reported</i> would
    /// let a run that never looked at the schema partition pass as complete.
    /// </param>
    /// <param name="sysvol">
    /// What became of the Group Policy files. Required, with no overload that omits it, for the
    /// reason already written for the forest partitions: a default of <i>none reported</i> would
    /// let a run that never attempted SYSVOL pass as though it had nothing to report. Per
    /// <c>docs/decisions/0044</c> a failure here does not make the run invalid - it makes it a run
    /// that must say what it missed.
    /// </param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// The outcomes and the declaration do not describe the same set of domains, or the forest-wide
    /// partitions are not reported exactly once each.
    /// </exception>
    public static RunCoverage Of(
        CoverageId declared,
        IEnumerable<DomainCoverage> domains,
        IEnumerable<ForestPartitionCoverage> forestPartitions,
        SysvolCoverage sysvol)
    {
        ArgumentNullException.ThrowIfNull(declared);
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentNullException.ThrowIfNull(forestPartitions);
        ArgumentNullException.ThrowIfNull(sysvol);

        var reported = domains.OrderBy(d => d.DomainFqdn, StringComparer.Ordinal).ToArray();
        var reportedNames = reported.Select(d => d.DomainFqdn).ToHashSet(StringComparer.Ordinal);

        var undeclared = reportedNames.Except(declared.DeclaredDomains, StringComparer.Ordinal).ToArray();
        if (undeclared.Length > 0)
        {
            throw new ArgumentException(
                $"Coverage was reported for {string.Join(", ", undeclared)}, which the run never "
                + "declared. Capture and discovery disagree about what this forest contains, and "
                + "this is not the component that decides which of them is right.",
                nameof(domains));
        }

        var unreported = declared.DeclaredDomains.Except(reportedNames, StringComparer.Ordinal).ToArray();
        if (unreported.Length > 0)
        {
            throw new ArgumentException(
                $"No coverage was reported for {string.Join(", ", unreported)}, which the run "
                + "declared. A declared domain with no outcome is a domain nobody looked at, and "
                + "it must not be able to pass as one that was read.",
                nameof(domains));
        }

        var partitions = forestPartitions
            .OrderBy(p => p.Kind)
            .ToArray();

        foreach (var required in new[] { NamingContextKind.Configuration, NamingContextKind.Schema })
        {
            var timesReported = partitions.Count(p => p.Kind == required);
            if (timesReported != 1)
            {
                throw new ArgumentException(
                    $"The {required} partition was reported {timesReported} times, and every forest "
                    + "has exactly one. A run that does not say what became of it cannot be told "
                    + "from one that read it, and per docs/decisions/0014 an unread schema "
                    + "partition is the failure that stops any permission being resolved at all.",
                    nameof(forestPartitions));
            }
        }

        var incomplete = reported
            .Where(d => d.Outcome != DomainReadOutcome.Read)
            .Select(d => d.DomainFqdn)
            .ToArray();

        var unread = partitions
            .Where(p => p.Outcome != ForestPartitionReadOutcome.Read)
            .Select(p => p.Kind.ToString())
            .ToArray();

        return new RunCoverage(declared, reported, partitions, sysvol, incomplete, unread);
    }
}
