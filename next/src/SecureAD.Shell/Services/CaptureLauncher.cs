using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// Plans, checks and starts a capture by driving the one entry point into capture.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a caller, not a second way in.</b>
/// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c> settles that there is a single entry
/// point and that a window drives it. Everything here is the same construction the command line
/// performs: a run library over the operator's root, the default connection settings, the system
/// clock. Nothing about a capture is decided differently because a window asked for it.
/// </para>
/// <para>
/// <b>The only work it does of its own is translation.</b> It ranks nothing, decides nothing and
/// contacts nothing. Where a fact was three-state on the way in it is three-state on the way out,
/// which is the whole point of <see cref="Established"/>: a mapping that flattened "not asked" into
/// "no" would put <c>F-S40-8</c> back into the product one layer along.
/// </para>
/// <para>
/// <b>Cancellation is passed through rather than abandoning the run.</b> A capture that is stopped
/// still has an outcome to record; a run that vanishes leaving a half-written file with nothing
/// saying so is what <c>0029</c> forbids.
/// </para>
/// </remarks>
internal sealed class CaptureLauncher : ICaptureLauncher
{
    /// <inheritdoc/>
    public async Task<Result<AuditPlanView>> PlanAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryRoot);
        ArgumentNullException.ThrowIfNull(overrides);

        var plan = await Session(libraryRoot, DirectoryConnectionSettings.DefaultDomainsAtOnce)
            .PlanAsync(forest, overrides, cancellationToken)
            .ConfigureAwait(false);

        return plan.IsSuccess
            ? Result<AuditPlanView>.Success(Describe(plan.Value!))
            : Result<AuditPlanView>.Failure(plan.Error!);
    }

    /// <inheritdoc/>
    public async Task<NamedControllerView> CheckNamedControllerAsync(
        string libraryRoot,
        string host,
        string namingContext,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContext);

        var answer = await Session(libraryRoot, DirectoryConnectionSettings.DefaultDomainsAtOnce)
            .CheckNamedControllerAsync(host, namingContext, cancellationToken)
            .ConfigureAwait(false);

        return new NamedControllerView(answer.IsUsable, answer.Fault?.Description);
    }

    /// <inheritdoc/>
    public async Task<Result<AuditCheck>> ValidateAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryRoot);
        ArgumentNullException.ThrowIfNull(overrides);

        var report = await Session(libraryRoot, DirectoryConnectionSettings.DefaultDomainsAtOnce)
            .ValidateAsync(forest, overrides, cancellationToken)
            .ConfigureAwait(false);

        return report.IsSuccess
            ? Result<AuditCheck>.Success(Describe(report.Value!))
            : Result<AuditCheck>.Failure(report.Error!);
    }

    /// <inheritdoc/>
    public async Task<Result<CaptureOutcome>> RunAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        IReadOnlyList<ExclusionAttestation> exclusions,
        int domainsAtOnce,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryRoot);
        ArgumentNullException.ThrowIfNull(overrides);
        ArgumentNullException.ThrowIfNull(exclusions);

        // Nothing is reported while the run is in flight. The capture layer has no per-object
        // progress to offer, and a progress bar over a run that cannot report one is a picture of a
        // run rather than a report of it. What preflight found was shown on the Review step, before
        // the operator pressed Start.
        var run = await Session(libraryRoot, domainsAtOnce)
            .RunAsync(
                forest,
                overrides,
                exclusions.ToDictionary(e => e.NamingContext, Describe, StringComparer.OrdinalIgnoreCase),
                reportPreflight: null,
                cancellationToken)
            .ConfigureAwait(false);

        return run.IsSuccess
            ? Result<CaptureOutcome>.Success(
                new CaptureOutcome(run.Value!.ProducedABundle, run.Value.BundleDirectory))
            : Result<CaptureOutcome>.Failure(run.Error!);
    }

    /// <summary>
    /// The attestation as the evidence layer records it.
    /// </summary>
    /// <remarks>
    /// <b>The reason crosses as its permanent identifier, never as the sentence shown on screen.</b>
    /// The wording an operator read may be improved; what the value means may not, because runs
    /// already recorded carry it - <c>0062</c> on the footing <c>0024</c> sets for rule identifiers.
    /// Writing the sentence instead would tie evidence already taken to a string somebody is free
    /// to reword.
    /// </remarks>
    private static AttestedExclusion Describe(ExclusionAttestation attestation) =>
        new(
            attestation.NamingContext,
            attestation.DomainFqdn,
            attestation.Kind == DomainInclusion.ExcludedForWantOfCandidates
                ? ExclusionKind.ForWantOfCandidates
                : ExclusionKind.ByChoice,
            ExclusionReasons.WireName(attestation.Reason),
            attestation.Note,
            attestation.RunBy,
            attestation.AuthorisedBy,
            attestation.MadeUtc);

    /// <summary>
    /// The session this surface drives, wired exactly as the command line wires it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library root is required by all three calls, including the two that write nothing. A
    /// session is constructed over a library, and <c>0025</c> forbids inventing a path for one - so
    /// the operator's own root is used, and the planning calls create no run inside it.
    /// </para>
    /// <para>
    /// <b>The ceiling is a parameter because only one caller has a real answer for it.</b> Planning,
    /// validating and checking a named controller read no domain, so the number governs nothing
    /// there and they pass the default rather than reaching for the operator's setting - which would
    /// suggest those calls are affected by it.
    /// </para>
    /// </remarks>
    /// <param name="libraryRoot">The operator's run library.</param>
    /// <param name="domainsAtOnce">How many domains a capture may read at the same time.</param>
    private static CaptureSession Session(string libraryRoot, int domainsAtOnce)
    {
        var addresses = MachineAddresses.OfThisMachine();

        return new CaptureSession(
            new RunLibrary(libraryRoot, TimeProvider.System),
            DirectoryConnectionSettings.Default with { DomainsAtOnce = domainsAtOnce },
            TimeProvider.System,
            new MachineDomain(),
            addresses.IsSuccess ? addresses.Value! : []);
    }

    /// <summary>
    /// The forest plan as a window shows it.
    /// </summary>
    private static AuditPlanView Describe(ForestPlan plan)
    {
        var sites = plan.Topology.Controllers
            .GroupBy(c => c.HostName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Site, StringComparer.OrdinalIgnoreCase);

        var operatorSite = plan.Selection.OperatorSite;

        var dnsNames = PairDnsNamesToDomains(plan);

        return new AuditPlanView(
            plan.Capture.ForestFqdn,
            operatorSite,
            operatorSite is not null
                ? SiteKnowledge.Known
                : plan.Topology.Subnets.Count == 0
                    ? SiteKnowledge.ForestDeclaresNoSubnets
                    : SiteKnowledge.NoSubnetContainsThisMachine,
            [.. plan.Selection.Domains.Select(d => Describe(d, sites, operatorSite, dnsNames))],
            plan.Selection.DomainsWithNoCandidates,
            sites)
        {
            DomainDnsNames = dnsNames,
        };
    }

    /// <summary>
    /// Pairs each domain's declared DNS name to its naming context, where the two can be paired.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both sides come from the forest.</b> The naming contexts are the partitions it plans to
    /// read and the DNS names are the ones it declared, and this only says which goes with which.
    /// Turning <c>DC=ph,DC=ad,DC=lab</c> into <c>ph.ad.lab</c> by string surgery would be inventing
    /// a name nobody published - true in almost every forest and wrong in the one that renamed a
    /// domain.
    /// </para>
    /// <para>
    /// A domain that pairs with nothing is absent from the result and shows its naming context,
    /// which is what it did before this existed.
    /// </para>
    /// </remarks>
    private static IReadOnlyDictionary<string, string> PairDnsNamesToDomains(ForestPlan plan)
    {
        var paired = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var dnsName in plan.Capture.DeclaredDomains)
        {
            var asNamingContext = string.Join(
                ',', dnsName.Split('.').Select(label => "DC=" + label));

            var match = plan.Selection.Domains.FirstOrDefault(domain => string.Equals(
                domain.NamingContext, asNamingContext, StringComparison.OrdinalIgnoreCase));

            if (match is not null)
            {
                paired[match.NamingContext] = dnsName;
            }
        }

        return paired;
    }

    /// <summary>
    /// One domain's row, before anything has been asked of it.
    /// </summary>
    /// <remarks>
    /// <c>DomainSelection.IsInOperatorSite</c> is false both when the controller is genuinely
    /// elsewhere and when the run has no site of its own, so it is read only where a site exists.
    /// Rendering the second as "another site" is a claim about where a customer's controllers are
    /// that such a run did not measure.
    /// </remarks>
    private static DomainPlanRow Describe(
        DomainSelection domain,
        IReadOnlyDictionary<string, string> sites,
        string? operatorSite,
        IReadOnlyDictionary<string, string> dnsNames) =>
        new(
            domain.NamingContext,
            domain.PinnedController,
            sites.TryGetValue(domain.PinnedController, out var site) ? site : null,
            operatorSite is null
                ? Established.NotEstablished
                : domain.IsInOperatorSite ? Established.Yes : Established.No,
            domain.Failover,
            domain.IsComplete,
            domain.WasOverridden)
        {
            DnsName = dnsNames.TryGetValue(domain.NamingContext, out var dns) ? dns : null,
        };

    /// <summary>
    /// What preflight found, as a window shows it.
    /// </summary>
    private static AuditCheck Describe(PreflightReport report) =>
        new(report.RunMayProceed, [.. report.Domains.Select(Describe)]);

    /// <summary>
    /// One domain's preflight answers.
    /// </summary>
    /// <remarks>
    /// <c>RungReached</c> stays null where nothing answered rather than becoming the lowest rung: a
    /// ladder walk nothing answered has observed nothing about the controller's security posture,
    /// which is <c>F-S35-1</c>.
    /// </remarks>
    private static DomainAnswers Describe(DomainPreflight domain) =>
        new(
            domain.NamingContext,
            domain.DomainController,
            domain.Answered ? Established.Yes : Established.No,
            domain.RungReached?.ToString(),
            Say(domain.ServesThePartition),
            Say(domain.PasswordSettingsContainerReadable),
            IsThePdcEmulator(domain),
            domain.ReadFromPdcEmulator,
            domain.SelectionWasInformed,
            domain.Alternatives,
            domain.ControllerWasNamedByOperator,
            [.. domain.Faults.Select(f => f.Description)]);

    /// <summary>The audit layer's three preflight states, in the shell's words.</summary>
    private static Established Say(PreflightAnswer answer) => answer switch
    {
        PreflightAnswer.Yes => Established.Yes,
        PreflightAnswer.No => Established.No,
        _ => Established.NotEstablished,
    };

    /// <summary>
    /// Whether the controller this domain would be read from is that domain's PDC emulator.
    /// </summary>
    /// <remarks>
    /// <b>Unanswerable until the emulator was established, and it says so.</b> Both
    /// <c>NotYetEstablished</c> and <c>CouldNotBeRead</c> leave the question with no answer, and
    /// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c> forbids either
    /// rendering as "holds no role". Only where the emulator was established is the answer read off
    /// the pinning: <c>ReadFromPdcEmulator</c> where it is the emulator, and a domain re-pinned away
    /// from it where it is not.
    /// </remarks>
    private static Established IsThePdcEmulator(DomainPreflight domain) =>
        domain.PdcEmulator == PdcEmulatorKnowledge.Established
            ? domain.ReadFromPdcEmulator ? Established.Yes : Established.No
            : Established.NotEstablished;
}

