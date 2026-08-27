using System.Globalization;
using System.Net;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// The one way a capture is started: it finds the forest this machine is in and reads it into a
/// sealed bundle inside the run library.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A9, the composition root, and it is the entry point
/// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c> requires. Everything it joins was built
/// already and none of it was joined: the run library creates a directory, the channel factory
/// opens a connection, discovery plans the forest and the run driver reads it. Until this existed
/// the product had four halves and no way to start.
/// </para>
/// <para>
/// <b>It decides nothing an operator could decide differently.</b> There is no scope and no choice
/// of transport. A caller supplies the run library root and whether to read or only check - and
/// nothing else, per <c>0039</c>: a graphical surface is a caller of this, never a second
/// implementation of it.
/// </para>
/// <para>
/// <b>It is not given a controller to start from.</b> The run finds its own forest, per
/// <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c>: the machine's own domain name is
/// something it already knows, and a host name is not. A typed name is the recovery path for a
/// machine that is not domain-joined, and is tried only when finding the forest fails. The
/// controller that answers is never pinned - which controller each domain is read from is
/// <see cref="ControllerSelection"/>'s answer, made after the forest has described itself.
/// </para>
/// <para>
/// <b>The run library root is required and has no default.</b> That is
/// <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c>. A tool that decides for itself
/// where several gigabytes of evidence go is a tool that fills the wrong disk.
/// </para>
/// <para>
/// <b>Every domain's controller is contacted before anything is read.</b> Capture is fail-fast, and
/// a forest is only readable as it stands today, so discovering at hour two that a child domain was
/// never reachable costs the whole capture. <see cref="ValidateAsync"/> is that check on its own,
/// which is what makes it worth ten seconds before a run of several hours.
/// </para>
/// </remarks>
public sealed class CaptureSession
{
    private readonly RunLibrary _library;
    private readonly DirectoryConnectionSettings _settings;
    private readonly TimeProvider _time;
    private readonly IMachineDomain _machine;
    private readonly IReadOnlyList<IPAddress> _localAddresses;

    /// <summary>
    /// Creates the session.
    /// </summary>
    /// <param name="library">The run library every bundle is created inside.</param>
    /// <param name="settings">
    /// How this run connects, including whether it was declared permitted to read over an
    /// unprotected connection. Required rather than defaulted, so a run that permits nothing has
    /// said so.
    /// </param>
    /// <param name="time">The clock the run's directory name and object times are read from.</param>
    /// <param name="machine">
    /// The machine's own domain names, which is how the run finds the forest it is in.
    /// </param>
    /// <param name="localAddresses">
    /// The machine's own addresses, matched against the forest's subnets to find the operator's
    /// site. Supplied rather than read here, so a run can be exercised from outside the forest it
    /// is auditing.
    /// </param>
    public CaptureSession(
        RunLibrary library,
        DirectoryConnectionSettings settings,
        TimeProvider time,
        IMachineDomain machine,
        IReadOnlyList<IPAddress> localAddresses)
    {
        ArgumentNullException.ThrowIfNull(library);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(machine);
        ArgumentNullException.ThrowIfNull(localAddresses);

        _library = library;
        _settings = settings;
        _time = time;
        _machine = machine;
        _localAddresses = localAddresses;
    }

    /// <summary>
    /// Connects, discovers the forest, and asks every preflight question of every domain - without
    /// reading a single object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What this catches is everything that would otherwise end a multi-hour run: a controller that
    /// refuses every rung of the connection ladder, a forest whose cross-references cannot be read,
    /// a domain whose DNS name resolves to nothing, and a controller that does not serve the
    /// partition it was chosen for.
    /// </para>
    /// <para>
    /// It is the same check a run performs before reading, rather than a second one. Two
    /// implementations of "can this run work" would eventually disagree, and the first sign of it
    /// would be a validate that passed and a run that did not.
    /// </para>
    /// <para>
    /// <b>A success here does not mean the run may proceed.</b> It means every domain was asked and
    /// the answers are in the report, which is
    /// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c>: every
    /// question is answered for every domain before any is allowed to stop the run. Whether the run
    /// may proceed is <see cref="PreflightReport.RunMayProceed"/>, asked <i>of</i> the report.
    /// </para>
    /// <para>
    /// <b>The two failures that are still single and still stop everything.</b> Finding the forest
    /// at all, and the discovery that follows it. Neither can be reported per domain, because until
    /// the forest has described itself there are no domains to report on - so a per-domain shape
    /// here would be a table with nothing in it and no reason given.
    /// </para>
    /// </remarks>
    /// <param name="typedName">
    /// A forest or domain name an operator typed, used only when this machine cannot find a forest
    /// of its own. Null for the ordinary case.
    /// </param>
    /// <param name="overrides">
    /// Controllers an operator named for particular domains, keyed by domain naming context. Per
    /// run and never stored, per <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public async Task<Result<PreflightReport>> ValidateAsync(
        string? typedName,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(overrides);

        var connections = new LdapDirectoryChannelFactory(_settings, new ConnectionSecurityLog());

        var entry = Enter(connections, typedName);
        if (!entry.IsSuccess)
        {
            return Result<PreflightReport>.Failure(entry.Error!);
        }

        Result<ForestPlan> plan;

        // The bootstrap connection is closed as soon as it has answered. It is never pinned, per
        // 0053, so nothing beyond this point has any use for it.
        using (entry.Value!.Channel)
        {
            plan = await ForestDiscovery
                .PlanAsync(entry.Value!.Channel, _localAddresses, overrides, cancellationToken)
                .ConfigureAwait(false);
        }

        if (!plan.IsSuccess)
        {
            return Result<PreflightReport>.Failure(plan.Error!);
        }

        return await Preflight
            .RunAsync(connections, plan.Value!, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Asks one named controller whether it serves the domain it was named for.
    /// </summary>
    /// <remarks>
    /// One connection to one machine, and no discovery. This is <c>F-S41-4</c> closed: checking a
    /// typed host used to cost a pass over the whole forest to answer a question about one server,
    /// which an operator correcting a typo paid for on every press. The reasoning is
    /// <see cref="NamedControllerCheck"/>'s and is not repeated here.
    /// </remarks>
    /// <param name="host">The controller the operator named, by DNS host name.</param>
    /// <param name="namingContext">The domain it was named for.</param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public async Task<NamedControllerAnswer> CheckNamedControllerAsync(
        string host, string namingContext, CancellationToken cancellationToken)
    {
        var connections = new LdapDirectoryChannelFactory(_settings, new ConnectionSecurityLog());

        return await NamedControllerCheck
            .AskAsync(connections, host, namingContext, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Finds the forest and plans the run, without contacting any domain's controller.
    /// </summary>
    /// <remarks>
    /// One connection, to whichever controller answered for the machine's own domain, and the
    /// configuration partition read that follows it. No domain is asked anything, which is what
    /// separates this from <see cref="ValidateAsync"/>: it says what the run intends, not what the
    /// forest will allow.
    /// </remarks>
    /// <param name="typedName">
    /// A forest or domain name an operator typed, used only when this machine cannot find a forest
    /// of its own. Null for the ordinary case.
    /// </param>
    /// <param name="overrides">
    /// Controllers an operator named for particular domains, keyed by the domain's DNS name.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public async Task<Result<ForestPlan>> PlanAsync(
        string? typedName,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(overrides);

        var connections = new LdapDirectoryChannelFactory(_settings, new ConnectionSecurityLog());

        var entry = Enter(connections, typedName);
        if (!entry.IsSuccess)
        {
            return Result<ForestPlan>.Failure(entry.Error!);
        }

        using (entry.Value!.Channel)
        {
            return await ForestDiscovery
                .PlanAsync(entry.Value!.Channel, _localAddresses, overrides, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Finds the forest: the machine's own domain first, a typed name only if that fails.
    /// </summary>
    /// <remarks>
    /// The rule and the reasoning live on <see cref="ForestBootstrap.Enter"/>, which takes a
    /// factory and can therefore be exercised without a directory. This session builds its own
    /// factory per <c>0039</c>, so a rule written here could not be.
    /// </remarks>
    private Result<ForestEntry> Enter(
        IDirectoryChannelFactory connections, string? typedName) =>
        ForestBootstrap.Enter(connections, _machine, typedName);

    /// <summary>
    /// Validates, then reads the whole forest into a sealed bundle inside the run library.
    /// </summary>
    /// <remarks>
    /// The bundle's directory is created here rather than chosen by the caller, per <c>0025</c>.
    /// A run that ends badly leaves its evidence unpromoted and writes an outcome file beside it,
    /// which is <see cref="CaptureRun"/>'s and is not repeated here.
    /// </remarks>
    /// <param name="typedName">
    /// A forest or domain name an operator typed, used only when this machine cannot find a forest
    /// of its own. Null for the ordinary case.
    /// </param>
    /// <param name="overrides">
    /// Controllers an operator named for particular domains, keyed by domain naming context.
    /// </param>
    /// <param name="reportPreflight">
    /// Called once with what preflight found, before any object is read. It is how a caller says
    /// out loud what <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c>
    /// requires be said - that a domain is being read from its PDC emulator - without this type
    /// deciding how anyone's screen looks.
    /// </param>
    /// <param name="exclusions">
    /// What an operator stated for each domain the run leaves out, keyed by naming context. Empty
    /// for a run that leaves nothing out. Per
    /// <c>docs/decisions/0059-an-exclusion-is-attested-once-per-run.md</c> these belong to this run
    /// alone: nothing here is stored for a later one and nothing is read back from an earlier one.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public async Task<Result<CaptureRunResult>> RunAsync(
        string? typedName,
        IReadOnlyDictionary<string, string> overrides,
        IReadOnlyDictionary<string, AttestedExclusion> exclusions,
        Action<PreflightReport>? reportPreflight,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(overrides);
        ArgumentNullException.ThrowIfNull(exclusions);

        var preflight = await ValidateAsync(typedName, overrides, cancellationToken)
            .ConfigureAwait(false);

        if (!preflight.IsSuccess)
        {
            return Result<CaptureRunResult>.Failure(preflight.Error!);
        }

        var report = preflight.Value!;

        // Said before the reading starts, not after: a run that took its warning to the end and
        // printed it beside "Sealed" has told an operator about a choice he could no longer change.
        reportPreflight?.Invoke(report);

        // 0054 requires a domain the forest names no controller for to be excluded under an
        // operator's attestation. That attestation now exists - 0062 and the New Audit window's
        // exclusion step - so an incomplete plan is allowed through exactly as far as it has been
        // accounted for, and no further. A shortfall nobody has put a name to still stops the run
        // rather than sealing a bundle silently missing a domain, which is the one outcome that
        // record exists to prevent. --validate and --preview still report it.
        if (!report.Plan.IsComplete)
        {
            var planned = report.Plan.Units.Count(u => u.Kind == NamingContextKind.Domain);
            var unread = report.Plan.DeclaredDomains.Count - planned;

            if (unread > exclusions.Count)
            {
                return Result<CaptureRunResult>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "ADomainHasNoCandidateControllers",
                    ErrorSeverity.Failed,
                    $"This forest declares {report.Plan.DeclaredDomains.Count} domains and a "
                    + $"controller was found for {planned} of them. The forest names no writable "
                    + $"controller holding the rest, so nothing can read them, and "
                    + $"{unread - exclusions.Count} of those have no attestation against them. "
                    + "Leaving a domain out of an audit requires an operator's attestation, so no "
                    + "bundle is produced rather than one that is silently missing a domain. Run "
                    + "with --preview to see which domains the forest says this about.",
                    context: null));
            }
        }

        // Every domain was asked before any of them was allowed to stop the run, per 0048, so the
        // refusal names all of them rather than the first one met.
        if (report.Refusal() is { } refused)
        {
            return Result<CaptureRunResult>.Failure(refused);
        }

        var directory = _library.CreateRun(report.Plan.ForestFqdn);
        if (!directory.IsSuccess)
        {
            return Result<CaptureRunResult>.Failure(directory.Error!);
        }

        // Before any capture traffic, per 0048. A run that dies at hour two still leaves behind
        // which controller served each domain and how well protected the connection to it was.
        PreflightFile.Write(directory.Value!, report, _time.GetUtcNow());

        // THE LOG IS OPENED HERE RATHER THAN TAKEN AS AN ARGUMENT, and the reason is the line above
        // it: until CreateRun there is no directory to write beside, so no caller could have opened
        // one. Deriving and judging take an IRunLog because they are handed a bundle that already
        // exists; capture is the stage that makes it, so capture owns the log.
        //
        // What that costs is real and worth stating: every refusal above this point - a forest that
        // could not be found, a domain nobody attested for, a controller that refused every rung -
        // is returned to the caller and never reaches a file. Those are the failures where no
        // bundle exists at all, so run-outcome.json is what speaks for them, per 0029.
        using var file = RunLogFile.Open(directory.Value!, "capture", _time) is { IsSuccess: true } opened
            ? opened.Value
            : null;

        // A log that could not be opened does not stop a capture. Losing the account of a run is
        // not a reason to lose the run, which is hours against a directory that has moved on since.
        IRunLog log = file ?? RunLog.Discarded;

        log.Note(
            CapturePhase,
            "started",
            [
                new RunLogDetail("forest", report.Plan.ForestFqdn),
                new RunLogDetail(
                    "domains",
                    report.Plan.Units.Count(u => u.Kind == NamingContextKind.Domain)
                        .ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("excluded", exclusions.Count.ToString(CultureInfo.InvariantCulture)),
            ]);

        var connections = new LdapDirectoryChannelFactory(_settings, new ConnectionSecurityLog());

        // The share is read with the token the run already holds. There is no alternate-credential
        // path, per docs/decisions/0039: one way to start a capture, and the predecessor's
        // in-memory password is not carried over.
        var run = new CaptureRun(connections, new SmbSysvolFileReader(), _time);

        // An attested exclusion takes the domain out of the reading, not only out of the evidence.
        // Recording that a domain was left out while still capturing it produces a bundle that
        // contradicts itself - an attestation saying nobody looked, filed beside the objects
        // captured when somebody did - and the attestation is the half that looks authoritative.
        //
        // Coverage still measures against every domain the forest declared, so what this produces
        // is a bundle that reports the domain as not read rather than one that quietly omits it.
        var captured = await run
            .RunAsync(
                report.Plan.Excluding(exclusions.Keys),
                directory.Value!,
                exclusions,
                cancellationToken)
            .ConfigureAwait(false);

        // A capture that ended badly carries its own error rather than returning a failure, so the
        // log reads it off the result. Both endings are written: a run that sealed nothing is the
        // case an operator most needs an account of.
        if (captured.Error is { } failure)
            log.Record(CapturePhase, failure, [new RunLogDetail("bundle", captured.BundleDirectory)]);
        else
            log.Note(
                CapturePhase,
                "finished",
                [
                    new RunLogDetail("outcome", captured.Outcome.ToString()),
                    new RunLogDetail("bundle", captured.BundleDirectory),
                ]);

        return captured;
    }

    /// <summary>The name the capture coordinator logs under.</summary>
    private const string CapturePhase = "Capture";
}
