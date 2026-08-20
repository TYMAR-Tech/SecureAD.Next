using System.Collections.Immutable;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;

namespace SecureAD.Cli;

/// <summary>
/// The command that starts a capture.
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
            return await RunAsync(parsed, stopping.Token).ConfigureAwait(false);
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

    private static async Task<int> RunAsync(
        CommandLine options, CancellationToken cancellationToken)
    {
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

        var session = new CaptureSession(
            new RunLibrary(options.LibraryRoot!, TimeProvider.System),
            DirectoryConnectionSettings.Default,
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
                cancellationToken)
            .ConfigureAwait(false);

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
        return Success;
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

        if (report.Refusal() is { } refused)
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
