namespace SecureAD.Shell.Services;

/// <summary>
/// What a run established about one fact: nothing, yes, or no.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three states rather than a boolean, and that is the whole reason this type exists.</b> A
/// window is a two-state control over a three-state fact unless something stops it being one, and
/// the three defects <c>F-S40-8</c>, <c>F-S40-10</c> and <c>F-S40-11</c> were each an unasked
/// question rendered as a negative answer. A screen showing an empty checkbox for a question that
/// was never put has told an operator something about a customer's forest that the run did not
/// measure.
/// </para>
/// <para>
/// It is the shell's own word for the distinction the audit layer keeps in
/// <c>PreflightAnswer</c> and <c>PdcEmulatorKnowledge</c>. Those are not exposed here for the same
/// reason <see cref="ICaptureLauncher"/> exposes none of the audit layer: a view model that can see
/// a capture type can start one.
/// </para>
/// </remarks>
internal enum Established
{
    /// <summary>The question was never put. Nothing is claimed either way.</summary>
    NotEstablished,

    /// <summary>The question was put and the answer was yes.</summary>
    Yes,

    /// <summary>The question was put and the answer was no.</summary>
    No,
}

/// <summary>
/// Why this machine's own site is not known, which is not the same fact as it having none.
/// </summary>
/// <remarks>
/// A forest that declares no subnets and a machine whose address matches none of the subnets a
/// forest does declare are different faults with different remedies - define the subnets, or find
/// out why this machine's address is in none of them. Rendering both as "no site" sends an operator
/// looking in the wrong place.
/// </remarks>
internal enum SiteKnowledge
{
    /// <summary>The site was worked out and is named.</summary>
    Known,

    /// <summary>The forest declares no subnets, so no machine can be placed by address.</summary>
    ForestDeclaresNoSubnets,

    /// <summary>The forest declares subnets and none of them contains this machine.</summary>
    NoSubnetContainsThisMachine,
}

/// <summary>
/// One domain's row of the New Audit table: what would be read, from where, and - once preflight
/// has run - what the forest answered about it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every fact that can be unknown is <see cref="Established"/>, and every fact that cannot is a
/// boolean.</b> The distinction is not stylistic. <see cref="ChoiceWasFullyInformed"/> is always
/// known, because the run either had every input to the ranking or it did not;
/// <see cref="ServesThePartition"/> is not, because a controller nothing answered from was never
/// asked.
/// </para>
/// <para>
/// <b>The preflight half is absent until preflight has run, and says so.</b>
/// <see cref="WasPreflighted"/> exists so that a row before the Review step cannot be read as a row
/// on which everything answered no.
/// </para>
/// </remarks>
/// <param name="NamingContext">The domain partition this row is about.</param>
/// <param name="Controller">The controller this domain would be read from.</param>
/// <param name="ControllerSite">
/// The site the forest puts that controller in, or null where the forest names none.
/// </param>
/// <param name="ControllerIsInThisMachinesSite">
/// Whether that controller shares this machine's site.
/// <see cref="Established.NotEstablished"/> where the run has no site of its own, because "another
/// site" is a claim about where a customer's controllers are that such a run did not measure.
/// </param>
/// <param name="Alternatives">
/// The other controllers the forest names for this domain, in the order ranking put them. Empty
/// means the forest names exactly one, which is a different fact from "the others were not
/// preferred".
/// </param>
/// <param name="ChoiceWasFullyInformed">
/// Whether the controller was chosen on every input the ranking wants. False where the run has no
/// site, or where the domain's PDC emulator was not established - in which case the busiest machine
/// in the domain sorted level with the rest and may be the one named here.
/// </param>
/// <param name="ControllerWasNamedByOperator">
/// Whether an operator named this controller rather than ranking choosing it.
/// </param>
internal sealed record DomainPlanRow(
    string NamingContext,
    string Controller,
    string? ControllerSite,
    Established ControllerIsInThisMachinesSite,
    IReadOnlyList<string> Alternatives,
    bool ChoiceWasFullyInformed,
    bool ControllerWasNamedByOperator)
{
    /// <summary>
    /// The domain's DNS name as the forest declares it, or <see langword="null"/> where the two
    /// could not be paired.
    /// </summary>
    /// <remarks>
    /// <b>Paired, never derived.</b> A domain naming context and a DNS name look convertible -
    /// <c>DC=ph,DC=ad,DC=lab</c> against <c>ph.ad.lab</c> - and converting one into the other would
    /// be inventing a name the forest did not give. Both come from the forest here, and where they
    /// do not pair this stays null and the naming context is shown instead.
    /// </remarks>
    public string? DnsName { get; init; }

    /// <summary>
    /// Whether preflight has asked this domain anything yet. False before the Review step.
    /// </summary>
    public bool WasPreflighted { get; init; }

    /// <summary>Whether any rung of the connection ladder answered.</summary>
    public Established Answered { get; init; }

    /// <summary>
    /// The rung that answered, or null where nothing did. Null is never "it refused protection":
    /// a walk nothing answered has observed nothing about the controller's security posture.
    /// </summary>
    public string? RungReached { get; init; }

    /// <summary>Whether that controller says it serves this partition.</summary>
    public Established ServesThePartition { get; init; }

    /// <summary>Whether this domain's Password Settings Container could be read.</summary>
    public Established PasswordSettingsContainerReadable { get; init; }

    /// <summary>
    /// Whether the controller named here is this domain's PDC emulator.
    /// </summary>
    /// <remarks>
    /// Three states per <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c>,
    /// which forbids "not yet established" rendering as "holds no role".
    /// </remarks>
    public Established IsThisDomainsPdcEmulator { get; init; }

    /// <summary>
    /// Whether the run would read this domain from its own PDC emulator, having found nowhere else
    /// to go.
    /// </summary>
    public bool ReadFromPdcEmulator { get; init; }

    /// <summary>What went wrong, in the words the audit layer used. Empty where nothing did.</summary>
    public IReadOnlyList<string> Faults { get; init; } = [];

    /// <summary>
    /// Whether this row warrants the PDC emulator prompt.
    /// </summary>
    /// <remarks>
    /// <b>Narrower than the record of it, deliberately.</b> The prompt appears only where the forest
    /// names another controller for this domain - that is, where the operator could have done
    /// something about it. A warning that fires on every domain of a single-controller forest
    /// teaches an operator to click past warnings, and the next one he clicks past will matter.
    /// What is written into <c>preflight.json</c> is not narrowed: the record is a fact about the
    /// audit, and only the prompting is conditional. See <c>0055</c>.
    /// </remarks>
    public bool PdcEmulatorPromptApplies => ReadFromPdcEmulator && Alternatives.Count > 0;

    /// <summary>
    /// This row with what preflight found written onto it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Preflight's version of a fact wins over discovery's.</b> Selection re-pins a domain whose
    /// chosen controller turns out to be its PDC emulator, per <c>0055</c>, so the controller, the
    /// alternatives and whether the choice was fully informed can all differ from what the Domains
    /// step showed.
    /// </para>
    /// <para>
    /// <b>Where the controller changed, its site is looked up again rather than carried over.</b>
    /// A re-pinned row keeping the previous controller's site would put a measured-looking site
    /// beside a machine nobody measured. The lookup is the forest's own topology, read once at
    /// discovery, and a controller absent from it has no site rather than the old one.
    /// </para>
    /// </remarks>
    /// <param name="answers">What preflight established about this domain.</param>
    /// <param name="controllerSites">
    /// The site the forest puts each controller in, keyed by host name, from discovery.
    /// </param>
    /// <param name="thisMachinesSite">
    /// This machine's own site, or null where it was never established.
    /// </param>
    public DomainPlanRow With(
        DomainAnswers answers,
        IReadOnlyDictionary<string, string> controllerSites,
        string? thisMachinesSite)
    {
        ArgumentNullException.ThrowIfNull(answers);
        ArgumentNullException.ThrowIfNull(controllerSites);

        var site = controllerSites.TryGetValue(answers.Controller, out var found) ? found : null;

        return this with
        {
            Controller = answers.Controller,
            ControllerSite = site,
            ControllerIsInThisMachinesSite = thisMachinesSite is null || site is null
                ? Established.NotEstablished
                : string.Equals(site, thisMachinesSite, StringComparison.OrdinalIgnoreCase)
                    ? Established.Yes
                    : Established.No,
            Alternatives = answers.Alternatives,
            ChoiceWasFullyInformed = answers.ChoiceWasFullyInformed,
            ControllerWasNamedByOperator = answers.ControllerWasNamedByOperator,
            WasPreflighted = true,
            Answered = answers.Answered,
            RungReached = answers.RungReached,
            ServesThePartition = answers.ServesThePartition,
            PasswordSettingsContainerReadable = answers.PasswordSettingsContainerReadable,
            IsThisDomainsPdcEmulator = answers.IsThisDomainsPdcEmulator,
            ReadFromPdcEmulator = answers.ReadFromPdcEmulator,
            Faults = answers.Faults,
        };
    }
}

/// <summary>
/// What preflight established about one domain, and nothing it did not.
/// </summary>
/// <remarks>
/// A shape of its own rather than a half-filled <see cref="DomainPlanRow"/>, because preflight
/// establishes nothing about sites - it asks a controller four questions and reads one attribute.
/// A row returned from preflight carrying site columns would carry them empty, and an empty site
/// column is indistinguishable on screen from a controller that is genuinely elsewhere.
/// </remarks>
/// <param name="NamingContext">The domain this concerns.</param>
/// <param name="Controller">
/// The controller preflight asked, which may not be the one discovery chose: <c>0055</c> re-pins a
/// domain off its PDC emulator once preflight establishes which controller that is.
/// </param>
/// <param name="Answered">Whether any rung of the connection ladder answered.</param>
/// <param name="RungReached">
/// The rung that answered, or null where nothing did. Never a worst case.
/// </param>
/// <param name="ServesThePartition">Whether the controller says it serves this partition.</param>
/// <param name="PasswordSettingsContainerReadable">
/// Whether the domain's Password Settings Container could be read.
/// </param>
/// <param name="IsThisDomainsPdcEmulator">
/// Whether the controller is this domain's PDC emulator.
/// </param>
/// <param name="ReadFromPdcEmulator">
/// Whether the run would read this domain from its own PDC emulator, nothing else being available.
/// </param>
/// <param name="ChoiceWasFullyInformed">
/// Whether the controller was chosen on every input the ranking wants, as it stood after the re-pin
/// pass.
/// </param>
/// <param name="Alternatives">The other controllers the forest names, in ranked order.</param>
/// <param name="ControllerWasNamedByOperator">
/// Whether an operator named this controller rather than ranking choosing it.
/// </param>
/// <param name="Faults">What went wrong, in the words the audit layer used.</param>
internal sealed record DomainAnswers(
    string NamingContext,
    string Controller,
    Established Answered,
    string? RungReached,
    Established ServesThePartition,
    Established PasswordSettingsContainerReadable,
    Established IsThisDomainsPdcEmulator,
    bool ReadFromPdcEmulator,
    bool ChoiceWasFullyInformed,
    IReadOnlyList<string> Alternatives,
    bool ControllerWasNamedByOperator,
    IReadOnlyList<string> Faults);

/// <summary>
/// Everything preflight learned, for every domain, from one pass.
/// </summary>
/// <param name="RunMayProceed">Whether every domain the forest declared can be read.</param>
/// <param name="Domains">One entry per domain, in the order the plan lists them.</param>
internal sealed record AuditCheck(bool RunMayProceed, IReadOnlyList<DomainAnswers> Domains);

/// <summary>
/// What a run would read and from where, as discovery established it and before anything was
/// contacted.
/// </summary>
/// <remarks>
/// The answer columns of every row here are <see cref="Established.NotEstablished"/>, because
/// discovery asks no domain anything. Preflight fills them in through
/// <see cref="DomainPlanRow.With"/>.
/// </remarks>
/// <param name="ForestFqdn">The forest the run found for itself.</param>
/// <param name="ThisMachinesSite">
/// The site this machine is in, or null where that could not be worked out.
/// </param>
/// <param name="SiteKnowledge">Why <paramref name="ThisMachinesSite"/> is null, where it is.</param>
/// <param name="Domains">One row per domain a controller was found for.</param>
/// <param name="DomainsWithNoCandidates">
/// Domains the forest declares and names no writable controller for. Not failures and not
/// exclusions; what happens to them is
/// <c>docs/decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md</c> and is not
/// built.
/// </param>
/// <param name="ControllerSites">
/// The site the forest puts each controller in, keyed by host name. Carried so that a row re-pinned
/// at preflight can be given the new controller's site rather than keeping the old one's.
/// </param>
/// <param name="DomainDnsNames">
/// The DNS name the forest declared for each domain, keyed by naming context. Carried because a
/// run's coverage is keyed by DNS name while a domain left out of a run is identified by its naming
/// context, and pairing the two is the forest's business rather than this window's. A domain the
/// forest paired no name with is absent.
/// </param>
internal sealed record AuditPlanView(
    string ForestFqdn,
    string? ThisMachinesSite,
    SiteKnowledge SiteKnowledge,
    IReadOnlyList<DomainPlanRow> Domains,
    IReadOnlyList<string> DomainsWithNoCandidates,
    IReadOnlyDictionary<string, string> ControllerSites)
{
    /// <summary>The DNS name the forest declared for each domain, keyed by naming context.</summary>
    public IReadOnlyDictionary<string, string> DomainDnsNames { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
