using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Audit.Sysvol;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Cli;

/// <summary>
/// The command that starts a capture, and derives from what it seals.
/// </summary>
/// <remarks>
/// <para>
/// This is the only place in the product that reads a command line, per
/// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c>. Everything beyond parsing is
/// <see cref="CaptureSession"/>'s, so that a window added later drives the same entry point rather
/// than becoming a second one - two ways to start a capture is two capture behaviours, and the
/// first sign they have diverged is a bundle that came out different depending on how it was
/// started.
/// </para>
/// <para>
/// <b>Nothing here is public.</b> This project's surface is its command line rather than its types,
/// which is why it stays outside the assemblies the architecture gates reflect over, and why
/// <c>CommandLineSurfaceGateTests</c> fails the build if it ever exports one.
/// </para>
/// <para>
/// <b>It completes without anyone watching.</b> No prompt, no dialog, no question at the moment of
/// failure - a capture of a large forest is hours, and a run that blocks at 03:00 on a prompt
/// nobody sees has produced nothing by morning.
/// </para>
/// </remarks>
internal static class Program
{
    /// <summary>Exit code for a run that produced a sealed bundle, or a check that passed.</summary>
    private const int Success = 0;

    /// <summary>Exit code for a run that ended without a bundle, or a check that failed.</summary>
    private const int Failed = 1;

    /// <summary>Exit code for arguments that could not be understood.</summary>
    private const int NotUnderstood = 2;

    /// <summary>
    /// Exit code for a run an operator stopped. The conventional value for a process ended by an
    /// interrupt, so a scheduler can tell a cancelled run from a failed one.
    /// </summary>
    private const int Cancelled = 130;

    private static async Task<int> Main(string[] args)
    {
        if (SysvolWorker.IsInvocation(args))
            return await SysvolWorker.RunAsync(args).ConfigureAwait(false);

        var parsed = CommandLine.Parse(args);

        if (parsed is null)
        {
            Console.Error.WriteLine(CommandLine.Usage);
            return NotUnderstood;
        }

        using var stopping = new CancellationTokenSource();

        Console.CancelKeyPress += (_, eventArgs) =>
        {
            // Handled rather than left to kill the process: a capture that is interrupted still has
            // an outcome file to write, and a run that vanishes leaving a half-written file with
            // nothing saying so is what docs/decisions/0029 forbids.
            eventArgs.Cancel = true;
            stopping.Cancel();
        };

        try
        {
            // No automatic own-account membership scan runs until a processing limit has been
            // measured and approved, and a real run always captures for itself. Both are stated
            // here rather than defaulted, per gate 1.
            return await RunAsync(parsed, stopping.Token, discoveryBudget: null, capture: null,
                requesterPolicy: JudgingRun.ProductionPathRequesterPolicy)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Stopped. No bundle was produced.");
            return Cancelled;
        }
        catch (Exception unexpected)
        {
            // A last resort, and it is here because the first real capture died with an unhandled
            // exception and a stack trace. An audit tool that is scheduled must end with something
            // an operator can read in the morning, per docs/decisions/0039 and 0029 - and a defect
            // in this product must be visibly that, rather than looking like something the forest
            // did. The detail is kept, because a fault nobody can report is a fault nobody fixes.
            Console.Error.WriteLine(
                "The run stopped on a fault in this product, not on anything the directory did. "
                + "No bundle was produced. Please report the following:");
            Console.Error.WriteLine(unexpected.ToString());
            return Failed;
        }
    }

    /// <param name="discoveryBudget">
    /// The limits an automatic own-account membership scan runs under, or null for no scan. Named
    /// at every call site rather than defaulted, so a run that schedules nothing has said so.
    /// </param>
    /// <param name="capture">
    /// Where the sealed bundle comes from, or null to capture from a directory. A substitute exists
    /// so the post-capture path can be exercised without contacting a forest; production passes null.
    /// </param>
    internal static async Task<int> RunAsync(
        CommandLine options, CancellationToken cancellationToken,
        SelfMembershipDiscoveryBudget? discoveryBudget,
        Func<CancellationToken, Task<Result<CaptureRunResult>>>? capture,
        PathRequesterPolicy requesterPolicy = JudgingRun.ProductionPathRequesterPolicy)
    {
        // Before this machine's own addresses are read, because deriving contacts nothing: it opens
        // a sealed bundle that already exists. Asking the network anything first would make a
        // read-only operation depend on the machine being able to see a forest.
        if (options.DeriveOnly is not null)
            return Derive(options.DeriveOnly, afterCapture: false, cancellationToken);

        if (options.JudgeOnly is not null)
            return Judge(options.JudgeOnly, afterCapture: false, cancellationToken, discoveryBudget, requesterPolicy);

        if (options.DescribeOnly is not null)
            return Describe(options.DescribeOnly, options.Sizes, cancellationToken);

        Console.WriteLine(options.ClassScopeDescription);

        if (capture is not null)
        {
            if (options.PreviewOnly || options.ValidateOnly)
                throw new ArgumentException("A capture substitute cannot perform preview or validation.", nameof(capture));
            return FinishCapture(await capture(cancellationToken).ConfigureAwait(false), options.CaptureOnly, cancellationToken, discoveryBudget, requesterPolicy);
        }

        // A machine whose own addresses cannot be read has no site, and every domain then reports
        // as chosen without full knowledge rather than the run pretending it was sited.
        var addresses = MachineAddresses.OfThisMachine();
        if (!addresses.IsSuccess)
        {
            Console.Error.WriteLine(addresses.Error!.Description);
        }

        var localAddresses = addresses.IsSuccess ? addresses.Value! : [];

        if (options.PreviewOnly)
        {
            return await PreviewAsync(options, localAddresses, cancellationToken)
                .ConfigureAwait(false);
        }

        // The ceiling the operator stated, or the capture's own default where he said nothing. It
        // is never read from the window's settings file - 0047 - so a scheduled run does what its
        // command line says rather than inheriting a number from somebody's profile.
        var session = new CaptureSession(
            new RunLibrary(options.LibraryRoot!, TimeProvider.System),
            options.Concurrency is { } domainsAtOnce
                ? DirectoryConnectionSettings.Default with { DomainsAtOnce = domainsAtOnce }
                : DirectoryConnectionSettings.Default,
            TimeProvider.System,
            new MachineDomain(),
            localAddresses);

        if (options.ValidateOnly)
        {
            var preflight = await session
                .ValidateAsync(options.Forest, options.Overrides, cancellationToken)
                .ConfigureAwait(false);

            if (!preflight.IsSuccess)
            {
                Console.Error.WriteLine(preflight.Error!.Description);
                return Failed;
            }

            return Describe(preflight.Value!);
        }

        // No exclusions from here, and there cannot be any. An attestation names the person who
        // authorised leaving a domain out, and a command line has nobody to ask - per
        // docs/decisions/0059-an-exclusion-is-attested-once-per-run.md an attestation is made every
        // run and never carried forward, so there is nothing to read from a previous one either. A
        // forest with a domain nothing can read therefore still refuses to produce a bundle here,
        // exactly as it did before the window gained the attestation. 0059 records that scheduling
        // meets this same wall and leaves it open.
        var run = await session
            .RunAsync(
                options.Forest,
                options.Overrides,
                ImmutableDictionary<string, AttestedExclusion>.Empty,
                Warn,
                options.ObjectScope,
                cancellationToken)
            .ConfigureAwait(false);

        return FinishCapture(run, options.CaptureOnly, cancellationToken, discoveryBudget, requesterPolicy);
    }

    private static int FinishCapture(
        Result<CaptureRunResult> run,
        bool captureOnly,
        CancellationToken cancellationToken,
        SelfMembershipDiscoveryBudget? discoveryBudget, PathRequesterPolicy requesterPolicy)
    {
        if (!run.IsSuccess)
        {
            Console.Error.WriteLine(run.Error!.Description);
            return Failed;
        }

        if (!run.Value!.ProducedABundle)
        {
            Console.Error.WriteLine(
                "The run ended without a sealed bundle. What happened is recorded in "
                + run.Value.BundleDirectory + ".");
            return Failed;
        }

        Console.Out.WriteLine("Sealed: " + run.Value.BundleDirectory);

        // ASKED FOR, AND THEREFORE SAID OUT LOUD. A bundle that was captured and not analysed is
        // complete evidence rather than a partial run - but a reader who finds no findings beside
        // it must not have to work out which of the two it is, and the absence of a judgement is
        // exactly the silence docs/decisions/0002 refuses to let stand for a fact.
        if (captureOnly)
        {
            Console.Out.WriteLine(
                "Captured only, as asked. Nothing has been derived or judged, so this bundle has "
                + "no findings yet - which is not the same as a forest with none. Run "
                + "'securead --derive \"" + run.Value.BundleDirectory + "\"' and then "
                + "'securead --judge \"" + run.Value.BundleDirectory + "\"' to analyse it, here or "
                + "on another machine.");

            return Success;
        }

        // Capture, derive, judge - the whole audit, so a scheduled run finishes with findings rather
        // than stopping one stage short of an answer. Judging only runs if deriving succeeded: the
        // rules that read derived facts would otherwise refuse the run, per docs/decisions/0091,
        // and reporting that as a judging failure would blame the wrong stage.
        var derived = Derive(run.Value.BundleDirectory, afterCapture: true, cancellationToken);

        return derived is Success
            ? Judge(run.Value.BundleDirectory, afterCapture: true, cancellationToken, discoveryBudget, requesterPolicy)
            : derived;
    }

    /// <summary>
    /// Derives facts about more than one object from the bundle the run has just sealed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Deriving follows a capture here for the same reason it does in the window.</b> The
    /// decision to audit was the decision to derive, and a scheduled run that sealed evidence and
    /// left the closures for somebody to ask for later would need somebody to remember asking.
    /// </para>
    /// <para>
    /// <b>A derivation that could not be done does not fail the run.</b> The bundle is sealed and
    /// that is what the capture was for - it read a forest that has moved on since, and it cannot be
    /// had again. Deriving can be done again from the same bundle whenever the defect is fixed, so
    /// reporting a non-zero exit here would tell a scheduler to alarm about work that is safe.
    /// What went wrong is printed, because a limit nobody is told about is a limit nobody acts on.
    /// </para>
    /// <para>
    /// <b>Nothing watches the progress.</b> <see cref="Stage2aRun.Unwatched"/> is passed rather than
    /// a reporter writing lines, because a scheduled run has no operator to tell and a log filling
    /// with counts nobody reads is what the predecessor's progress reporting became.
    /// </para>
    /// <para>
    /// <b>Cancelling is absorbed here rather than left to reach <c>Main</c>.</b> Main reports a
    /// cancelled run as one that produced no bundle, and by this point that is false - the evidence
    /// is sealed. The exit code is still the one for an interrupt, so a scheduler can tell a
    /// stopped run from a finished one.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Reports what a sealed bundle holds, without opening it for analysis and without writing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Written because nothing could answer it.</b> Every size and budget argument about this
    /// product had been made against the predecessor's figures, because no sealed run had ever
    /// reported its own shape. The first production capture then produced a bundle several times
    /// the expected size, on a customer laptop with no room for a second copy of it, and the only
    /// way to ask what was inside was to attach a database tool to the original.
    /// </para>
    /// <para>
    /// <b>It says what it could not read, and separately from what is simply absent.</b> An object
    /// whose permissions were refused is not an object with no permissions, and a policy nobody
    /// could open is not a policy that grants nothing. The whole reason for a denominator is that
    /// incompleteness has knowable edges.
    /// </para>
    /// </remarks>
    /// <param name="bundleDirectory">The run folder to describe.</param>
    /// <param name="sizes">Whether to measure where the bytes went, at the cost of a full read.</param>
    /// <param name="cancellationToken">Cancellation, checked between tables.</param>
    private static int Describe(
        string bundleDirectory, bool sizes, CancellationToken cancellationToken)
    {
        // Named by an operator rather than produced by a capture, so it is worth checking before
        // anything opens it, exactly as Derive does above.
        if (!Directory.Exists(bundleDirectory))
        {
            Console.Error.WriteLine("There is no bundle at " + bundleDirectory + ".");
            return Failed;
        }

        Result<BundleContents> read;
        try
        {
            read = BundleContents.Read(bundleDirectory, sizes, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Stopped. Nothing was written.");
            return Cancelled;
        }

        if (!read.IsSuccess)
        {
            Console.Error.WriteLine(read.Error!.Description);
            return Failed;
        }

        var contents = read.Value!;

        // Said before the numbers, and deliberately: this is run against a customer's only copy of
        // a bundle, on a machine with no room for another, and an operator should not have to
        // infer from the absence of a warning that nothing was touched.
        Console.WriteLine();
        Console.WriteLine("Read from " + bundleDirectory + " - nothing was written.");
        Console.WriteLine();

        Console.WriteLine("What this bundle holds");
        Line("Objects captured", contents.Objects);
        Line("Access control entries", contents.AccessControlEntries);
        Line("Group Policy objects", contents.PoliciesDeclared);
        Line("Trustees", contents.Trustees);
        Line("Domains covered", contents.Domains);

        Console.WriteLine();
        Console.WriteLine("Security descriptors");
        Line("Distinct descriptors stored", contents.DescriptorsStored);
        Line("Objects referencing one", contents.DescriptorUses);
        Console.WriteLine(contents.ReuseFactor is { } reuse
            ? string.Format(
                CultureInfo.CurrentCulture,
                "  Stored once, used {0:N1} times on average",
                reuse)
            : "  Nothing stored, so nothing to share.");

        Console.WriteLine();
        Console.WriteLine("Access control entries");
        Line("Entries across all descriptors", contents.AccessControlEntries);
        Line("Distinct entries stored", contents.DistinctEntries);
        if (contents.EntryRepetition is { } repetition)
        {
            // WORDED FOR WHAT THE BUNDLE NOW DOES. Until P-272 an entry was written out once for
            // every object beneath the container it was set on, and this line said "stored 294
            // times" because that is what had happened. It is stored once and pointed at, so saying
            // "stored" would now describe work the product no longer does - and a size figure a
            // customer would act on has to match the file in front of him.
            Console.WriteLine(string.Format(
                CultureInfo.CurrentCulture,
                "  Stored once, referenced {0:N1} times on average",
                repetition));
        }

        Console.WriteLine();
        Console.WriteLine("What could not be read");
        Line("Descriptors that failed to parse", contents.DescriptorsUnparsed);
        Line("Objects with unreadable permissions", contents.PermissionsUnreadable);
        Line("SYSVOL paths unreadable", contents.SysvolPathsUnreadable);
        Line("Group Policy files that errored", contents.PolicyFileErrors);
        Line("Domains that failed", contents.DomainsFailed);

        if (contents.PoliciesNotReadInFull > 0)
        {
            Console.WriteLine();
            Console.WriteLine(string.Format(
                CultureInfo.CurrentCulture,
                "  {0:N0} of {1:N0} Group Policy objects were not read in full:",
                contents.PoliciesNotReadInFull,
                contents.PoliciesDeclared));

            foreach (var (reason, policies) in contents.WhyPoliciesWentUnread)
            {
                Console.WriteLine(string.Format(
                    CultureInfo.CurrentCulture, "    {0,6:N0}  {1}", policies, reason));
            }
        }

        if (contents.SpaceByTable is { Count: > 0 } space)
        {
            Console.WriteLine();
            Console.WriteLine(string.Format(
                CultureInfo.CurrentCulture, "{0,-38} {1,14} {2,14}", "Where the space went", "ROWS", "CONTENT"));

            foreach (var weight in space.Take(15))
            {
                Console.WriteLine(string.Format(
                    CultureInfo.CurrentCulture,
                    "  {0,-36} {1,14:N0} {2,14}",
                    weight.Table,
                    weight.Rows,
                    Bytes(weight.ContentBytes)));
            }

            Console.WriteLine();
            Line("Content measured above", space.Sum(w => w.ContentBytes), asBytes: true);
            Line("File on disk", contents.FileBytes, asBytes: true);
            Console.WriteLine("  The difference is indexes and page overhead.");
        }
        else
        {
            Console.WriteLine();
            Line("evidence.db", contents.FileBytes, asBytes: true);
        }

        Console.WriteLine();
        return Success;

        static void Line(string label, long value, bool asBytes = false) =>
            Console.WriteLine(string.Format(
                CultureInfo.CurrentCulture,
                "  {0,-42} {1,14}",
                label,
                asBytes ? Bytes(value) : value.ToString("N0", CultureInfo.CurrentCulture)));
    }

    /// <summary>A byte count at a scale a person reads, rather than a bare number.</summary>
    private static string Bytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => string.Format(CultureInfo.CurrentCulture, "{0:N2} GB", bytes / (1024d * 1024 * 1024)),
        >= 1024 * 1024 => string.Format(CultureInfo.CurrentCulture, "{0:N1} MB", bytes / (1024d * 1024)),
        >= 1024 => string.Format(CultureInfo.CurrentCulture, "{0:N1} KB", bytes / 1024d),
        _ => string.Format(CultureInfo.CurrentCulture, "{0:N0} B", bytes),
    };

    private static int Derive(
        string bundleDirectory, bool afterCapture, CancellationToken cancellationToken)
    {
        Result<DerivationRunState> derived;

        // Named by an operator rather than produced by a capture, so it is worth checking before
        // anything opens it. A typed path that does not exist should say so plainly instead of
        // failing somewhere inside the reader.
        if (!afterCapture && !Directory.Exists(bundleDirectory))
        {
            Console.Error.WriteLine("There is no bundle at " + bundleDirectory + ".");
            return Failed;
        }

        // The capture wrote the first stretch of this file; this appends to it, so one bundle's
        // log reads top to bottom whatever produced each part of it.
        using var file = RunLogFile.Open(bundleDirectory, "deriving", TimeProvider.System)
            is { IsSuccess: true } opened
            ? opened.Value
            : null;

        IRunLog log = file ?? RunLog.Discarded;

        try
        {
            derived = Stage2aRun.Derive(
                bundleDirectory,
                ExpansionBudget.Bulk,
                DateTimeOffset.UtcNow,
                Stage2aRun.Unwatched,
                log,
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Absorbed here rather than left to reach Main. Main reports a cancelled run as one
            // that produced no bundle, which was true while this command only captured and is not
            // true now: by this point the evidence is sealed. An operator told his bundle does not
            // exist would capture the forest a second time for nothing.
            Console.Error.WriteLine(
                "Stopped while deriving. The evidence is sealed and safe at "
                + bundleDirectory
                + ". Nothing was derived from it.");

            return Cancelled;
        }

        if (!derived.IsSuccess)
        {
            Console.Error.WriteLine(
                "The evidence is sealed and safe. Nothing could be derived from it: "
                + derived.Error!.Description);

            // After a capture this is a success: the run was asked to read a forest and it did,
            // and the evidence is sealed whatever happened next. Asked only to derive, the same
            // outcome is a failure - nothing the operator wanted was produced, and a scheduler
            // told otherwise would report a job that did nothing as having worked.
            return afterCapture ? Success : Failed;
        }

        Console.Out.WriteLine(derived.Value switch
        {
            DerivationRunState.CompletedDegraded =>
                "Derived, and at least one part could not be completed. What was derived says "
                + "which, and anything resting on it is not working from the whole picture.",
            _ => "Derived: " + CurrentDerivationPath(bundleDirectory),
        });

        return Success;
    }

    /// <summary>
    /// Runs every rule over a bundle and writes the findings beside the evidence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What this makes possible.</b> Until now the command line captured and derived, and judging
    /// happened only in the application - so a scheduled overnight run stopped one stage short of an
    /// answer, and a lab check could not be repeated without somebody opening the GUI. The owner
    /// asked for this on 2026-08-26: <i>"i will be making it so the user can run the audit and it
    /// complete the judging via CLI, so it can run overnight."</i>
    /// </para>
    /// <para>
    /// <b>The whole catalogue, never a chosen subset.</b> <see cref="RuleCatalogue.All"/> is what an
    /// audit is, per <c>docs/decisions/0082</c>. A command line that let a caller pick rules would
    /// be a second definition of the audit and a way to produce a judgement quietly missing one.
    /// </para>
    /// <para>
    /// <b>Refusing is a real outcome and is reported as one.</b> A bundle nobody derived cannot
    /// satisfy the rules that read derived facts, and <c>docs/decisions/0091</c> refuses the run
    /// rather than reporting every object as unjudgeable. That refusal is a failure here, because
    /// the operator asked for findings and has none.
    /// </para>
    /// </remarks>
    private static int Judge(
        string bundleDirectory, bool afterCapture, CancellationToken cancellationToken,
        SelfMembershipDiscoveryBudget? discoveryBudget, PathRequesterPolicy requesterPolicy)
    {
        if (!afterCapture && !Directory.Exists(bundleDirectory))
        {
            Console.Error.WriteLine("There is no bundle at " + bundleDirectory + ".");
            return Failed;
        }

        // Appends to the same file the capture and the derivation wrote, so one bundle's log reads
        // top to bottom whatever produced each part of it.
        using var file = RunLogFile.Open(bundleDirectory, "judging", TimeProvider.System)
            is { IsSuccess: true } opened
            ? opened.Value
            : null;

        IRunLog log = file ?? RunLog.Discarded;

        Result<JudgementRunState> judged;
        var started = DateTimeOffset.UtcNow;

        try
        {
            // Match the GUI's assessment scope; the all-object overload remains for historical tests,
            // not a different production policy for unattended judging.
            judged = JudgingRun.JudgeAudit(
                bundleDirectory,
                RuleCatalogue.All,
                requesterPolicy,
                started,
                started,
                JudgingRun.NobodyIsWatching,
                log,
                cancellationToken,
                discoveryBudget);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(
                "Stopped while judging. The evidence is sealed and safe at "
                + bundleDirectory
                + ". Nothing was judged from it.");

            return Cancelled;
        }

        if (!judged.IsSuccess)
        {
            Console.Error.WriteLine(
                "The evidence is sealed and safe. Nothing could be judged from it: "
                + judged.Error!.Description);

            // After a capture this is still a success: the run was asked to read a forest and it
            // did. Asked only to judge, it is a failure - the operator wanted findings and has none.
            return afterCapture && requesterPolicy == PathRequesterPolicy.Disabled ? Success : Failed;
        }

        if (requesterPolicy == PathRequesterPolicy.SupportedCapturedQuestions)
        {
            var openedCoverage = JudgementReader.Open(bundleDirectory);
            if (!openedCoverage.IsSuccess) return Failed;
            using var coverageReader = openedCoverage.Value;
            if (coverageReader.ReadPathRequesterCoverage().Verdict != PathRequesterCoverageState.EvaluatedSupportedQuestions)
                return Failed;
        }

        Console.Out.WriteLine(Summarise(bundleDirectory));
        return Success;
    }

    /// <summary>
    /// One line an operator can read in the morning: how many rules ran, and what they found.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The rule count is there because a finding count on its own does not mean what it looks
    /// like.</b> "0 findings" from nine rules is a quiet forest; "0 findings" from two rules is a
    /// judging that mostly did not happen, and the two must not print identically -
    /// <c>docs/decisions/0002</c>.
    /// </para>
    /// <para>
    /// <b>The rule count was not enough, and 2026-09-05 proved it.</b> Three rules ran, succeeded,
    /// and examined <b>no objects at all</b> - every one of 8,378 counted as not applicable, because
    /// they declared no subject class to mean <i>every object</i> and an empty list matched nothing.
    /// The summary read "17 rules ran, 16 findings" and looked entirely healthy. A suite of 3,139
    /// tests was green. Recorded as <c>F-S45-4</c>.
    /// </para>
    /// <para>
    /// <b>So a rule that examined nothing is now named.</b> Rules are scoped, so a low count is
    /// ordinary - SEC-090 judges fourteen computers in this lab and that is correct. <b>Zero is
    /// different</b>: it means the rule was offered the whole forest and found nothing it was even
    /// about, which is a defect in the rule far more often than it is a fact about the directory.
    /// Naming it costs one line and would have caught all three.
    /// </para>
    /// </remarks>
    private static string Summarise(string bundleDirectory)
    {
        var opened = JudgementReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return "Judged: " + bundleDirectory;

        using var reader = opened.Value!;
        var stored = reader.Read();

        var failed = stored.RulesRun
            .Count(r => r.Outcome is not RuleExecutionOutcome.Succeeded);

        var faults = failed == 0
            ? string.Empty
            : $", {failed} did not complete";

        var summary = $"Judged: {stored.RulesRun.Count} rules ran{faults}, "
            + $"{stored.Findings.Count} findings." + Requesters(reader);

        var examinedNothing = stored.RulesRun
            .Where(r => r.ObjectsJudged == 0)
            .Select(r => r.RuleId)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        if (examinedNothing.Count == 0)
            return summary;

        return summary
            + Environment.NewLine
            + $"  WARNING: {string.Join(", ", examinedNothing)} examined no objects at all. "
            + "A rule offered the whole forest that finds nothing it is even about is usually "
            + "broken rather than satisfied - check its subject classes before trusting a zero.";
    }

    /// <summary>
    /// What the own-account membership scan covered, for the operator reading this in the morning.
    /// </summary>
    /// <remarks>
    /// <b>Printed even when the scan did nothing</b>, because a silent line reads as a forest where
    /// nobody can add themselves to a group. The wording is this host's; the facts come from the
    /// store, so an unattended run and the window cannot disagree about what was covered.
    /// </remarks>
    private static string Requesters(JudgementReader reader)
    {
        if (reader.ReadSelfMembershipSummary() is not { } requesters)
            return string.Empty;

        var limits = requesters.Discovery.Limitations.Count;

        return Environment.NewLine + "  " + requesters.Discovery.Verdict switch
        {
            "NotStarted" =>
                "Own-account membership questions were not scheduled: no processing limit is "
                + "configured. This is not a result saying nobody can add themselves to a group.",
            "ExplicitRequestsOnly" =>
                $"Own-account membership: {requesters.AssessmentsStored} stored answer(s) from "
                + "explicit requests; no automatic scan ran.",
            "ProcessingStopped" =>
                $"Own-account membership: {requesters.AssessmentsStored} answer(s) stored, then the "
                + $"scan stopped at its configured limit. {limits} limitation(s) recorded; this is "
                + "not the whole capture.",
            _ =>
                $"Own-account membership: {requesters.AssessmentsStored} answer(s) over "
                + $"{requesters.Discovery.PairsDiscovered} pair(s), "
                + $"{requesters.AuthorizationUnknown} undecided, {limits} limitation(s) recorded.",
        };
    }

    private static string CurrentDerivationPath(string bundleDirectory)
    {
        var generation = AnalysisStoreLifecycle
            .Resolve(bundleDirectory, AnalysisStoreKind.Derivation)
            .Value!;
        return BundleLayout.AnalysisGenerationDataPath(
            bundleDirectory, generation.Kind, generation.GenerationId);
    }

    /// <summary>
    /// Says what preflight found out about every domain, then whether the run would proceed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A line per domain, whether or not it failed.</b> An operator shown only the faults cannot
    /// tell a domain that passed from one that was never asked about, and
    /// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c> exists so
    /// that all the answers arrive together rather than one attempt at a time.
    /// </para>
    /// <para>
    /// <b>A controller nothing answered from is printed as unreachable and given no rung.</b> That
    /// is finding <c>F-S35-1</c>: a host that does not resolve must not come back described as a
    /// controller that refuses protected connections, because the two have opposite remedies -
    /// correct the name, or fix the controller's configuration.
    /// </para>
    /// <para>
    /// The partitions the run leaves alone are printed too. An operator told only what will be read
    /// has no way to notice that something he expected is missing from the list, and per
    /// <c>docs/decisions/0052</c> a part of the directory a run leaves alone is stated.
    /// </para>
    /// </remarks>
    private static int Describe(PreflightReport report)
    {
        Console.Out.WriteLine("Forest: " + report.Plan.ForestFqdn);

        foreach (var domain in report.Domains)
        {
            Console.Out.WriteLine("  " + Line(domain));

            foreach (var fault in domain.Faults)
            {
                Console.Out.WriteLine("      " + fault.Description);
            }
        }

        foreach (var partition in report.Plan.NotRead)
        {
            Console.Out.WriteLine("  not read  " + partition);
        }

        // No exclusions: --validate and --preview report what preflight found, before any
        // attestation has been gathered. A domain that cannot be read is stated here even if a
        // later run would be allowed to leave it out, because this is the output an operator reads
        // to decide whether to attest in the first place.
        if (report.Refusal([]) is { } refused)
        {
            Console.Error.WriteLine(refused.Description);
            return Failed;
        }

        Console.Out.WriteLine("Every domain answered. This run would proceed.");

        Warn(report);

        return Success;
    }

    /// <summary>
    /// What an operator needs to be told about the choices a run made for him.
    /// </summary>
    /// <remarks>
    /// <b>Shared by <c>--validate</c> and a capture, deliberately.</b> These lines were on the
    /// validate path alone, so a real capture read three domains from their PDC emulators and
    /// printed nothing but "Sealed" - which is <c>0055</c>'s "and says so" quietly not happening in
    /// the one case that mattered. That was <c>F-S40-11</c>.
    /// </remarks>
    private static void Warn(PreflightReport report)
    {
        foreach (var domain in report.CouldNotReadPasswordSettings)
        {
            Console.Out.WriteLine(
                $"  {domain.NamingContext} will not be able to say whether it has any "
                + "fine-grained password policy.");
        }

        // 0055 permits a run to read a domain from its PDC emulator when nothing else is available,
        // and requires that it says so. A slow audit an operator was warned about is a different
        // thing from a slow audit nobody explained.
        foreach (var domain in report.ReadFromPdcEmulator)
        {
            Console.Out.WriteLine(
                $"  {domain.NamingContext} will be read from {domain.DomainController}, which is "
                + $"that domain's PDC emulator. {NowhereElse(domain)} That machine also carries "
                + "time, password changes and account lockout for the domain.");
        }

        // DomainSelection.IsComplete, acted on. Without this a pinned host name reads as a fully
        // informed choice, and a coin toss between equals produces exactly the same one name.
        foreach (var domain in report.ChosenWithoutFullKnowledge)
        {
            Console.Out.WriteLine(
                $"  {domain.NamingContext} was given {domain.DomainController} without every input "
                + $"to the choice: {Why(domain)}.");
        }
    }

    /// <summary>
    /// Why the run did not move off this domain's PDC emulator.
    /// </summary>
    /// <remarks>
    /// A domain the forest names one controller for and a domain whose alternatives were considered
    /// and not preferred are different facts. Saying "none was found in this site" covers both, and
    /// on a run with no site of its own it also implies a filter that was never applied - which is
    /// <c>F-S40-8</c> reappearing one message along.
    /// </remarks>
    private static string NowhereElse(DomainPreflight domain) =>
        domain.OtherControllersInTheForest == 0
            ? "The forest names no other controller for this domain, so there is nowhere else to "
                + "read it from."
            : $"Ranking still preferred it over the {domain.OtherControllersInTheForest} other "
                + "controller(s) the forest names for this domain.";

    /// <summary>
    /// Why a domain's controller was chosen on less than the ranking wanted.
    /// </summary>
    private static string Why(DomainPreflight domain) => domain.PdcEmulator switch
    {
        PdcEmulatorKnowledge.CouldNotBeRead =>
            "its PDC emulator could not be read, so that machine ranked level with every other "
            + "controller in the domain and may be the one chosen",
        PdcEmulatorKnowledge.NotYetEstablished =>
            "its PDC emulator was never established",
        _ =>
            "this machine's own site could not be established, so no controller could be preferred "
            + "for being near it - run --preview for why",
    };

    /// <summary>
    /// Says what a run would read and from where, writing nothing anywhere.
    /// </summary>
    /// <remarks>
    /// It builds no <see cref="RunLibrary"/> and therefore creates no directory. A read-only look
    /// that leaves a folder behind is a small lie about what it did, and an operator pointing this
    /// at a customer's forest to see what it would do should be able to say it touched nothing.
    /// </remarks>
    private static async Task<int> PreviewAsync(
        CommandLine options,
        IReadOnlyList<System.Net.IPAddress> localAddresses,
        CancellationToken cancellationToken)
    {
        var connections = new LdapDirectoryChannelFactory(
            DirectoryConnectionSettings.Default, new ConnectionSecurityLog());

        var entry = ForestBootstrap.Enter(connections, new MachineDomain(), options.Forest);
        if (!entry.IsSuccess)
        {
            Console.Error.WriteLine(entry.Error!.Description);
            return Failed;
        }

        SecureAD.Kernel.Result<ForestPlan> plan;

        using (entry.Value!.Channel)
        {
            plan = await ForestDiscovery
                .PlanAsync(
                    entry.Value!.Channel, localAddresses, options.Overrides, cancellationToken)
                .ConfigureAwait(false);
        }

        if (!plan.IsSuccess)
        {
            // An override naming a domain this forest does not have arrives here, and it stops the
            // run. ControllerSelection refuses an ineligible controller for the same reason, and
            // neither refusal is softened into a warning on the way out: an operator who named a
            // controller and got a different one has a run that is not the one he asked for.
            Console.Error.WriteLine(plan.Error!.Description);
            return Failed;
        }

        Console.Out.Write(PlanPreview.Describe(plan.Value!));
        return Success;
    }

    /// <summary>
    /// One domain's row: the controller, and the answer to each of the four questions.
    /// </summary>
    private static string Line(DomainPreflight domain)
    {
        var rung = domain.RungReached is { } reached
            ? reached.ToString()
            : "unreachable";

        return $"domain    {domain.NamingContext}  via {domain.DomainController}  "
            + $"connection {rung}  "
            + $"serves {Say(domain.ServesThePartition)}  "
            + $"password settings {Say(domain.PasswordSettingsContainerReadable)}";
    }

    /// <summary>
    /// One answer, in words that do not turn a question nobody asked into a negative answer.
    /// </summary>
    private static string Say(PreflightAnswer answer) => answer switch
    {
        PreflightAnswer.Yes => "yes",
        PreflightAnswer.No => "no",
        _ => "not asked",
    };
}
