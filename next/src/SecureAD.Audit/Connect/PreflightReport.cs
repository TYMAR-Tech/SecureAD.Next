using System.Globalization;
using System.Resources;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// The answer to one preflight question about one domain, kept in a shape that cannot report an
/// unasked question as a negative one.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three states rather than a boolean, and that is the whole reason this type exists.</b> A
/// question preflight never got to ask - because nothing answered on the connection - and a
/// question asked and answered <i>no</i> have opposite remedies. The first is a network or naming
/// fault; the second is a fact about the customer's forest.
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids collapsing the two, and a
/// boolean has nowhere to put the difference: <c>false</c> would have to mean both.
/// </para>
/// </remarks>
public enum PreflightAnswer
{
    /// <summary>
    /// The question was never put. Nothing is claimed either way.
    /// </summary>
    NotAsked,

    /// <summary>The question was put and the answer was yes.</summary>
    Yes,

    /// <summary>The question was put and the answer was no.</summary>
    No,
}

/// <summary>
/// What preflight found out about one domain: which controller it asked, and the answer to each of
/// the four questions.
/// </summary>
/// <remarks>
/// <para>
/// The four questions are
/// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c>'s and are not
/// restated here. This type is one row of the answers.
/// </para>
/// <para>
/// <b>A controller that was never reached has no rung, and cannot be given one.</b>
/// <see cref="RungReached"/> is absent rather than carrying a worst-case value, because a ladder
/// walk that was answered by nothing has observed nothing about the controller's security posture.
/// Reporting such a walk as though the controller had refused every protected rung is finding
/// <c>F-S35-1</c> - a security claim about a customer's forest that the product did not measure -
/// and this is the shape that makes repeating it impossible rather than discouraged.
/// </para>
/// <para>
/// <b>One controller, and the type says so by holding one.</b> A candidate list, and which
/// controller was pinned from it, is
/// <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c> and is
/// not built. When it is, a row gains the list beside the controller it settled on; nothing here
/// has to change shape to admit that.
/// </para>
/// </remarks>
/// <param name="NamingContext">The domain partition this row is about.</param>
/// <param name="DomainController">The controller preflight asked.</param>
/// <param name="RungReached">
/// The rung of the connection ladder that answered, or null when nothing answered at all.
/// </param>
/// <param name="ServesThePartition">
/// Whether that controller says it serves <paramref name="NamingContext"/>, asked of its live
/// RootDSE. <see cref="PreflightAnswer.NotAsked"/> when there was no connection to ask on.
/// </param>
/// <param name="PasswordSettingsContainerReadable">
/// Whether the domain's Password Settings Container could be read.
/// <see cref="PreflightAnswer.No"/> says the read did not succeed and deliberately does not say
/// why: Active Directory answers a caller lacking list access with the same result code an absent
/// container would produce.
/// </param>
/// <param name="Faults">
/// What went wrong, in the words an operator should see. Empty for a domain that answered
/// everything.
/// </param>
public sealed record DomainPreflight(
    string NamingContext,
    string DomainController,
    ConnectionSecurityLevel? RungReached,
    PreflightAnswer ServesThePartition,
    PreflightAnswer PasswordSettingsContainerReadable,
    IReadOnlyList<AuditError> Faults)
{
    /// <summary>
    /// What preflight established about this domain's PDC emulator.
    /// </summary>
    /// <remarks>
    /// Three states rather than two, per
    /// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c>: a question that
    /// could not be put has no answer, and rendering one as "holds no role" is what puts an audit on
    /// a PDC emulator with nothing recording that it had.
    /// </remarks>
    public PdcEmulatorKnowledge PdcEmulator { get; init; } = PdcEmulatorKnowledge.NotYetEstablished;

    /// <summary>
    /// Whether this domain is being read from its own PDC emulator.
    /// </summary>
    /// <remarks>
    /// True only where the PDC emulator was established, the pinned controller is it, and no
    /// same-site alternative existed to move to. <c>0055</c> allows the run to proceed in that case
    /// and requires that it says so: a slow audit an operator was warned about is a different thing
    /// from a slow audit nobody explained.
    /// </remarks>
    public bool ReadFromPdcEmulator { get; init; }

    /// <summary>
    /// Whether selection moved this domain off its PDC emulator after preflight established which
    /// controller that was.
    /// </summary>
    public bool WasRepinnedOffPdcEmulator { get; init; }

    /// <summary>
    /// Whether the controller this domain is read from was chosen on every input the ranking wants.
    /// </summary>
    /// <remarks>
    /// This is <c>DomainSelection.IsComplete</c> as it stood after the re-pin pass, carried here so
    /// that something acts on it. A caller reading only <see cref="DomainController"/> cannot tell a
    /// fully informed choice from a coin toss between equals, because both produce exactly one name.
    /// </remarks>
    public bool SelectionWasInformed { get; init; }

    /// <summary>
    /// The other controllers the forest names for this domain, in the order ranking put them.
    /// </summary>
    /// <remarks>
    /// Carried so that a report can tell "there was nowhere else to go" apart from "somewhere else
    /// existed and was not preferred". Those are different facts about a customer's forest, and a
    /// message covering both says neither. It is also the candidate list
    /// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c> asks
    /// <c>preflight.json</c> to name.
    /// </remarks>
    public IReadOnlyList<string> Alternatives { get; init; } = [];

    /// <summary>
    /// How many other controllers the forest names for this domain.
    /// </summary>
    public int OtherControllersInTheForest => Alternatives.Count;

    /// <summary>
    /// Whether an operator named this controller rather than ranking choosing it.
    /// </summary>
    /// <remarks>
    /// The pin origin <c>0048</c> asks for. A controller a human insisted on and one a rule selected
    /// are different things to an auditor reading a bundle afterwards.
    /// </remarks>
    public bool ControllerWasNamedByOperator { get; init; }

    /// <summary>
    /// Whether this domain is being read from a controller in the capture machine's own site, or
    /// null where the machine matched no site and there was nothing to compare against.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Three states, and the third is why this is not <c>DomainSelection.IsInOperatorSite</c>
    /// carried across unchanged.</b> That flag is false both for a domain with no candidate in the
    /// operator's site and for a run whose machine has no site at all, because a boolean has nowhere
    /// to put the difference. The first is a fact about the customer's forest; the second is a fact
    /// about where the audit was run from, and reporting it as <i>no</i> asserts something nobody
    /// established.
    /// </para>
    /// <para>
    /// <b>It is a relationship and never a place.</b> No site name and no host, because the only
    /// question it exists to answer - was this domain read beside the machine or across a link,
    /// which is the whole of <c>P-258</c> - needs neither. That is also what lets it travel in the
    /// portable run summary, which may carry no name out of a customer's forest but a domain's.
    /// </para>
    /// </remarks>
    public bool? ControllerIsInOperatorSite { get; init; }

    /// <summary>
    /// Whether any rung of the ladder answered. The first of the four questions.
    /// </summary>
    public bool Answered => RungReached is not null;

    /// <summary>
    /// Whether all four questions were actually put to this domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A row where this is false is a row that was cut short, and its <see cref="Faults"/> say
    /// where. It exists so that an empty fault list cannot be read as "nothing was wrong" by a
    /// reader holding a row on which nothing was asked - the ambiguity
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids, and gate 4 is the
    /// build failure that obliges the statement.
    /// </para>
    /// </remarks>
    public bool IsComplete =>
        Answered
        && ServesThePartition != PreflightAnswer.NotAsked
        && PasswordSettingsContainerReadable != PreflightAnswer.NotAsked;

    /// <summary>
    /// Whether this domain is in a state a capture could read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A controller that answered and serves the partition. The Password Settings Container is
    /// deliberately not part of this: <c>0048</c> states that Enterprise Admins is not required and
    /// that the supported posture is an ordinary account with read access delegated per domain, so
    /// a run that stopped over one unreadable container would refuse the posture the record
    /// supports. What an unreadable container costs is paid later and in the open - the bundle says
    /// it could not tell, rather than that the domain has no fine-grained password policy.
    /// </para>
    /// </remarks>
    public bool CanBeRead => Answered && ServesThePartition == PreflightAnswer.Yes;
}

/// <summary>
/// Everything preflight learned, for every domain, from one pass - and the licence to proceed that
/// follows from it.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A8. <c>0048</c> decides that *every question is answered for every domain
/// before any is allowed to stop the run*; this type is what carries the answers, and
/// <see cref="Preflight"/> is the pass that fills it in. Before it existed,
/// <c>CaptureSession.ValidateAsync</c> returned the plan or one error, so nine domains with three
/// faults cost four attempts to discover three facts that were all knowable in one - and no screen
/// could show a row per domain, because nothing of that shape existed.
/// </para>
/// <para>
/// <b>Whether the run may proceed is a question asked of the report, not the report's only
/// content.</b> A domain that could not be read still ends the run, per
/// <c>docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md</c> - but it ends it after
/// every domain has been asked, and the operator is told all of it at once.
/// </para>
/// <para>
/// <b>Nothing here is an exclusion.</b> A domain the run could not read and a domain an operator
/// chose to leave out are different events with opposite meanings, and
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> requires that
/// they never share a representation. There is no member here an exclusion could be recorded in,
/// and that is deliberate rather than pending.
/// </para>
/// </remarks>
/// <param name="Plan">The forest as discovery described it, which the run proceeds on if it may.</param>
/// <param name="Domains">One row per domain partition, in the order the plan lists them.</param>
public sealed record PreflightReport(CapturePlan Plan, IReadOnlyList<DomainPreflight> Domains)
{
    private static readonly ResourceManager Wording = new(
        "SecureAD.Audit.Resources.CapturePreflight", typeof(PreflightReport).Assembly);

    /// <summary>
    /// Declared domains for which discovery could not plan a controller, keyed by naming context.
    /// These are not failed connections: no controller was available to ask.
    /// </summary>
    public IReadOnlyDictionary<string, string> DomainsWithNoCandidates =>
        Plan.DomainDnsNames
            .Where(domain => !Plan.Units.Any(unit =>
                unit.Kind == NamingContextKind.Domain
                && string.Equals(unit.NamingContext, domain.Key, StringComparison.OrdinalIgnoreCase)))
            .ToDictionary(domain => domain.Key, domain => domain.Value, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether every domain the forest declared was asked, and asked everything.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not the same question as <see cref="RunMayProceed"/>. This one asks whether the pass did its
    /// own job; that one asks what the answers mean for the run. A report with no rows at all is
    /// the case that matters: without this member it would be indistinguishable from a forest in
    /// which every domain answered, because both hand back an empty <see cref="Blocking"/>.
    /// </para>
    /// </remarks>
    public bool IsComplete =>
        Domains.Count == Plan.DeclaredDomains.Count && Domains.All(d => d.IsComplete);

    /// <summary>
    /// The domains a capture could not read. Empty for a forest that answered.
    /// </summary>
    public IReadOnlyList<DomainPreflight> Blocking =>
        [.. Domains.Where(d => !d.CanBeRead)];

    /// <summary>
    /// The domains that answered but whose Password Settings Container could not be read.
    /// </summary>
    /// <remarks>
    /// Reported separately from <see cref="Blocking"/> because it does not stop the run. It is the
    /// thing a report must later say *could not be told* about, rather than reporting a domain as
    /// having no fine-grained password policy.
    /// </remarks>
    public IReadOnlyList<DomainPreflight> CouldNotReadPasswordSettings =>
        [.. Domains.Where(d =>
            d.CanBeRead && d.PasswordSettingsContainerReadable == PreflightAnswer.No)];

    /// <summary>
    /// Domains being read from their own PDC emulator because the forest offered nowhere else in
    /// the operator's site.
    /// </summary>
    /// <remarks>
    /// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c> permits this and
    /// requires that it is said: a slow audit an operator was warned about is a different thing from
    /// a slow audit nobody explained. It does not stop the run.
    /// </remarks>
    public IReadOnlyList<DomainPreflight> ReadFromPdcEmulator =>
        [.. Domains.Where(d => d.ReadFromPdcEmulator)];

    /// <summary>
    /// Domains whose controller was chosen without every input the ranking wants.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what consumes <c>DomainSelection.IsComplete</c>. A domain lands here when the run has
    /// no site of its own, or when its PDC emulator could not be established - in which case the
    /// busiest machine in the domain sorted level with the rest and may be the one being read from,
    /// with nothing else recording that it might be.
    /// </para>
    /// <para>
    /// It does not block. What it does is stop a pinned host name being read as a fully informed
    /// choice, which is the ambiguity <c>docs/decisions/0002-absent-view-means-degraded-run.md</c>
    /// forbids: an informed choice and a coin toss between equals both produce exactly one name.
    /// </para>
    /// </remarks>
    public IReadOnlyList<DomainPreflight> ChosenWithoutFullKnowledge =>
        [.. Domains.Where(d => !d.SelectionWasInformed)];

    /// <summary>
    /// Whether every domain the forest declared can be read.
    /// </summary>
    public bool RunMayProceed => Refusal([]) is null;

    /// <summary>
    /// Why the run may not proceed, naming every domain that failed rather than the first.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null when nothing is left blocking. It exists because a caller returning a
    /// <see cref="Result{T}"/> needs one error to return, and building it from every blocking row
    /// is what stops the collected answers being thrown away at the last moment - which is the
    /// failure this whole session exists to remove, reappearing one layer up.
    /// </para>
    /// <para>
    /// <b>An exclusion is a domain nobody is going to read, so it cannot be a reason not to start.</b>
    /// A domain the operator attested his way out of - typically because the forest names no
    /// controller for it - fails preflight for exactly the reason it was excluded, and counting it
    /// here made a deliberate exclusion read as an unreachable forest. The exclusions are passed in
    /// rather than known here, because <c>docs/decisions/0059-an-exclusion-is-attested-once-per-run.md</c>
    /// makes them the run's rather than the report's.
    /// </para>
    /// <para>
    /// <b><see cref="Blocking"/> is untouched, deliberately.</b> It is what preflight found and it
    /// is what <c>preflight.json</c> records; an excluded domain that could not be read is still a
    /// fact about the customer's forest. Only the decision to stop is narrowed.
    /// </para>
    /// </remarks>
    /// <param name="excludedNamingContexts">
    /// The naming contexts this run has an operator's attestation for. Empty for a run that leaves
    /// nothing out.
    /// </param>
    public AuditError? Refusal(IReadOnlyCollection<string> excludedNamingContexts)
    {
        ArgumentNullException.ThrowIfNull(excludedNamingContexts);

        IReadOnlyList<DomainPreflight> blocking = excludedNamingContexts.Count == 0
            ? Blocking
            : [.. Blocking.Where(d => !excludedNamingContexts.Contains(
                d.NamingContext, StringComparer.OrdinalIgnoreCase))];

        var unattested = DomainsWithNoCandidates
            .Where(domain => !excludedNamingContexts.Contains(domain.Key, StringComparer.OrdinalIgnoreCase))
            .Select(domain => domain.Value)
            .ToList();

        if (unattested.Count > 0)
        {
            var description = string.Format(
                CultureInfo.CurrentCulture,
                Wording.GetString("MissingControllerAttestation", CultureInfo.CurrentUICulture)
                    ?? throw new MissingManifestResourceException("MissingControllerAttestation"),
                string.Join(", ", unattested));

            return AuditError.Create(
                ErrorCategory.Capture,
                "ADomainHasNoCandidateControllers",
                ErrorSeverity.Failed,
                description + (blocking.Count == 0 ? string.Empty : " " + string.Join(" ", blocking.Select(Describe))),
                context: Plan.ForestFqdn);
        }

        if (blocking.Count == 0)
        {
            return null;
        }

        var reasons = blocking.Select(Describe);

        return AuditError.Create(
            ErrorCategory.Capture,
            "PreflightRefusedTheRun",
            ErrorSeverity.Failed,
            $"{blocking.Count} of {Plan.DeclaredDomains.Count} domains cannot be read, so no capture was "
            + "started. A capture that cannot read every domain the forest declares produces no "
            + "bundle at all, so this is reported before hours are spent rather than after. "
            + string.Join(" ", reasons),
            context: Plan.ForestFqdn);
    }

    /// <summary>
    /// One blocking domain, in a sentence naming the domain, the controller and what happened.
    /// </summary>
    private static string Describe(DomainPreflight domain)
    {
        var cause = domain.Faults.Count > 0
            ? string.Join(" ", domain.Faults.Select(f => f.Description))
            : "No reason was recorded, which is itself a fault in this product.";

        return $"{domain.NamingContext} via {domain.DomainController}: {cause}";
    }
}
