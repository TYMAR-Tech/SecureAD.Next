using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// The two things about one domain that a run knows and no store holds.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything else on a summarised domain is read back out of the bundle.</b> The name, what
/// became of reading it and how much came out of it are all recorded, and reading them back is what
/// keeps the summary from becoming a second account of the run. These two are not recorded
/// anywhere: how long a domain took is known while it is being read, and which site the answering
/// controller was in is settled at preflight and never written down. Putting either into the
/// evidence would bump its format for a diagnostic field.
/// </para>
/// <para>
/// <b>The naming context is a key and never a name.</b> It arrives so this row can be matched to
/// the coverage the store holds; the domain that reaches the file is the store's own, and this
/// distinguished name is passed through <see cref="PortableNames.DomainNameOf"/> only to do the
/// matching.
/// </para>
/// </remarks>
/// <param name="NamingContext">The domain partition, as the run names it.</param>
/// <param name="ElapsedMilliseconds">How long reading it took, failover attempts included.</param>
/// <param name="ControllerInOperatorSite">
/// Whether it was read from a controller in the capture machine's own site, or null where the
/// machine had no site to compare against. Never a host and never a site name.
/// </param>
public readonly record struct DomainRunTiming(
    string NamingContext,
    long ElapsedMilliseconds,
    bool? ControllerInOperatorSite);

/// <summary>
/// Assembles a <see cref="CaptureSummary"/> by reading the stores, so the portable summary counts
/// nothing for itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>The stores are authoritative for counts and states, and the run for durations.</b> That is
/// the owner's decision of 2026-09-22 and it is the whole shape of this type: it opens the bundle
/// and reads what is recorded, and the only values it accepts from the caller are the ones nothing
/// records - the elapsed times and the site relationship. A summary that recounted what the bundle
/// already holds would be a second answer to a question the evidence has already answered, and the
/// first sign of the two disagreeing would be a customer reading a figure the product cannot
/// reproduce.
/// </para>
/// <para>
/// <b>A bundle that cannot be opened yields a summary with no domain rows, not a summary of
/// zeros.</b> A capture that failed or was stopped has no sealed evidence to read, and the honest
/// account of it is its state, how long it ran and what went wrong - with the domain table simply
/// absent. A table of noughts would read as a forest containing nothing, which is
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c>'s exact case.
/// </para>
/// </remarks>
public static class PortableSummaryReading
{
    /// <summary>
    /// What a capture did, read back from its own bundle.
    /// </summary>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="elapsedMilliseconds">How long the whole capture took.</param>
    /// <param name="stages">Where that time went, as the run measured it.</param>
    /// <param name="domains">
    /// The per-domain elapsed times and site relationships, which the run holds and no store does.
    /// </param>
    /// <param name="ending">
    /// Why the capture ended badly, or null where it did not. Only its category, code and severity
    /// are used; the sentence it carries stays in the run log, because a sentence about a directory
    /// failure routinely quotes the thing it failed on.
    /// </param>
    /// <returns>The summary, which is safe to write wherever the run may be discussed.</returns>
    public static CaptureSummary OfCapture(
        string bundleDirectory,
        long elapsedMilliseconds,
        IReadOnlyList<StageTiming> stages,
        IReadOnlyList<DomainRunTiming> domains,
        AuditError? ending)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(stages);
        ArgumentNullException.ThrowIfNull(domains);

        var observed = RunStateReader.Observe(bundleDirectory);

        // Damaged rather than a guess. A directory the state reader refuses is one it could not
        // recognise as a run, and naming any other state here would be this type deciding a
        // question docs/decisions/0028 gives to one place.
        var state = observed.IsSuccess ? observed.Value.State : RunState.Damaged;

        var problems = new List<AuditError>();

        if (!observed.IsSuccess)
            problems.Add(observed.Error);

        if (ending is { } failure)
            problems.Add(failure);

        IReadOnlyList<SummarisedDomain> rows = [];

        var opened = BundleReader.Open(bundleDirectory);

        if (opened.IsSuccess)
        {
            using var bundle = opened.Value!;

            var scope = bundle.ReadScope();

            if (scope.IsSuccess)
                rows = Rows(scope.Value!, CapturedTotals(bundle.Connection), domains);
            else
                problems.Add(scope.Error);

            var failures = bundle.ReadDomainCaptureFailures();

            if (failures.IsSuccess)
                problems.AddRange(failures.Value!.Select(f => f.Error));
            else
                problems.Add(failures.Error);
        }
        else
            problems.Add(opened.Error);

        return new CaptureSummary(
            ProductVersion,
            RuntimeInformation.FrameworkDescription,
            RuntimeInformation.OSDescription,
            state,
            elapsedMilliseconds,
            stages,
            rows,
            Counted(problems));
    }

    /// <summary>
    /// What a derivation did, in the shape the summary carries.
    /// </summary>
    /// <remarks>
    /// <b>Here rather than in the derivation, so that all three sections are assembled one way.</b>
    /// This takes what a caller has already read back out of its own store - the derivation's types
    /// live in an assembly this one cannot see - and does the one thing that is common to all three
    /// sections: gathering failures into counts that carry no message text.
    /// </remarks>
    /// <param name="state">What became of the run, in the derivation's own vocabulary.</param>
    /// <param name="elapsedMilliseconds">How long it took.</param>
    /// <param name="principals">How many principals it knows about.</param>
    /// <param name="nestingEdges">How many direct nesting relationships it holds.</param>
    /// <param name="phases">Where the time went inside it.</param>
    /// <param name="problems">What went wrong, whose descriptions are dropped here.</param>
    /// <returns>The section.</returns>
    public static DerivationSummary OfDerivation(
        string state,
        long elapsedMilliseconds,
        long principals,
        long nestingEdges,
        IReadOnlyList<StageTiming> phases,
        IEnumerable<AuditError> problems)
    {
        ArgumentNullException.ThrowIfNull(phases);
        ArgumentNullException.ThrowIfNull(problems);

        return new DerivationSummary(
            state, elapsedMilliseconds, principals, nestingEdges, phases, Counted(problems));
    }

    /// <summary>
    /// What a judging did, in the shape the summary carries.
    /// </summary>
    /// <param name="state">What became of it.</param>
    /// <param name="elapsedMilliseconds">How long it took.</param>
    /// <param name="objectsJudged">How many captured objects were streamed through it.</param>
    /// <param name="phases">Where the time went.</param>
    /// <param name="rules">One row per scheduled rule.</param>
    /// <param name="findings">How many findings there were, by severity.</param>
    /// <param name="problems">What went wrong, whose descriptions are dropped here.</param>
    /// <returns>The section.</returns>
    public static JudgingSummary OfJudging(
        string state,
        long elapsedMilliseconds,
        long objectsJudged,
        IReadOnlyList<StageTiming> phases,
        IReadOnlyList<RuleTiming> rules,
        IReadOnlyDictionary<Severity, int> findings,
        IEnumerable<AuditError> problems)
    {
        ArgumentNullException.ThrowIfNull(phases);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(problems);

        return new JudgingSummary(
            state, elapsedMilliseconds, objectsJudged, phases, rules, findings, Counted(problems));
    }

    /// <summary>
    /// Gathers failures into one row per kind, which is the only shape the summary may carry them
    /// in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The description is dropped here rather than filtered later. A sentence written for an
    /// operator names the thing that went wrong - a distinguished name, an account, a server - and
    /// there is deliberately no method on <see cref="PortableSummaryFile"/> it could be handed to.
    /// </para>
    /// <para>
    /// <b>Private, because a list of counts handed out on its own cannot say whether anyone
    /// looked.</b> It is reached only through the three methods that assemble a whole section, each
    /// of which carries the state of the run it describes beside it.
    /// </para>
    /// </remarks>
    /// <param name="problems">Every failure the run recorded.</param>
    /// <returns>One row per category, code and severity, worst first.</returns>
    private static IReadOnlyList<ProblemCount> Counted(IEnumerable<AuditError> problems) =>
        [
            .. problems
                .GroupBy(p => (p.Category, p.Code, p.Severity))
                .Select(g => new ProblemCount(g.Key.Category, g.Key.Code, g.Key.Severity, g.Count()))
                .OrderByDescending(p => p.Severity)
                .ThenBy(p => p.Category)
                .ThenBy(p => p.Code, StringComparer.Ordinal),
        ];

    /// <summary>
    /// Which build produced the numbers, so a reader can place them.
    /// </summary>
    /// <remarks>
    /// Taken from this assembly rather than the entry one, because the window and the command line
    /// are two entry assemblies producing the same file and the question is which build of the
    /// product wrote it.
    /// </remarks>
    private static string ProductVersion =>
        typeof(PortableSummaryReading).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(PortableSummaryReading).Assembly.GetName().Version?.ToString()
        ?? "unknown";

    /// <summary>
    /// Joins what the store recorded about each domain to what the run measured about reading it.
    /// </summary>
    /// <remarks>
    /// <b>The coverage leads, and the timings are matched to it.</b> Every declared domain has a
    /// coverage row including the ones nobody read, so walking the coverage is what keeps an unread
    /// domain in the table rather than silently absent from it. A domain the run recorded no timing
    /// for gets no time rather than a nought - which is why the timing is matched in and never
    /// defaulted here.
    /// </remarks>
    private static IReadOnlyList<SummarisedDomain> Rows(
        RunScope scope,
        IReadOnlyDictionary<string, (long Objects, long Entries)> totals,
        IReadOnlyList<DomainRunTiming> domains)
    {
        var timings = new Dictionary<string, DomainRunTiming>(StringComparer.OrdinalIgnoreCase);

        foreach (var timing in domains)
        {
            // The distinguished name is spent here and goes no further. What is kept is the domain
            // it belongs to, which is the only part of it the owner permitted into the file - and
            // even that is used as a key, with the name on the row coming from the coverage.
            var key = PortableNames.DomainNameOf(timing.NamingContext);

            if (key.Length > 0)
                timings[key] = timing;
        }

        return
        [
            .. scope.Domains.Select(domain =>
            {
                var counted = totals.TryGetValue(domain.DomainFqdn, out var found)
                    ? found
                    : (Objects: 0L, Entries: 0L);

                var measured = timings.TryGetValue(domain.DomainFqdn, out var timing)
                    ? timing
                    : default;

                return new SummarisedDomain(
                    domain.DomainFqdn,
                    domain.Outcome,
                    counted.Objects,
                    counted.Entries,
                    measured.ElapsedMilliseconds,
                    measured.ControllerInOperatorSite);
            }),
        ];
    }

    /// <summary>
    /// Counts the captured objects and their access control entries, per domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Restricted to domain partitions, and that is not tidying.</b> Every captured object
    /// carries the domain it belongs to, and the configuration and schema partitions belong to the
    /// forest root - so counting without this bills every schema and configuration object to one
    /// domain, which would make the root look several times larger than it is and the figure would
    /// be entirely plausible.
    /// </para>
    /// <para>
    /// <b>A null entry count is not a zero and is not turned into one.</b> <c>ace_count</c> is null
    /// where a descriptor could not be read, which <c>SUM</c> passes over; the total is therefore
    /// the entries that were read, beside the coverage outcome that says whether reading was whole.
    /// </para>
    /// </remarks>
    /// <param name="connection">The open evidence database.</param>
    /// <returns>Objects and entries by domain, empty where the tables could not be read.</returns>
    private static Dictionary<string, (long Objects, long Entries)> CapturedTotals(
        SqliteConnection connection)
    {
        var totals = new Dictionary<string, (long Objects, long Entries)>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                """
                SELECT o.domain_fqdn, COUNT(*), COALESCE(SUM(o.ace_count), 0)
                FROM captured_object o
                JOIN partition_coverage p ON p.coverage_id = o.coverage_id
                WHERE p.naming_context_kind = 'Domain'
                GROUP BY o.domain_fqdn
                """;

            using var reader = command.ExecuteReader();

            while (reader.Read())
                totals[reader.GetString(0)] = (reader.GetInt64(1), reader.GetInt64(2));
        }
        catch (SqliteException)
        {
            // An unreadable table yields no rows, which the caller renders as a domain with no
            // count beside an outcome that says what became of it. Failing the whole summary over
            // it would lose the account of a run that otherwise completed.
            return new Dictionary<string, (long Objects, long Entries)>(StringComparer.OrdinalIgnoreCase);
        }

        return totals;
    }
}
