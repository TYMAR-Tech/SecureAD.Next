using System.Collections.ObjectModel;
using System.Globalization;
using System.Resources;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The screens of the New Audit window, in the order they are reached.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two, and the second is not the first again.</b> An earlier pair of steps showed the same
/// table under a different heading, which reviewed nothing and was removed. What is here now
/// differs: the first screen is what the run would read and the one place an operator changes it,
/// and the second states what the run will and will not do - a fact about the run as a whole,
/// which is what somebody committing a machine to a read measured in hours is deciding on.
/// </para>
/// <para>
/// <b>The second screen also carries the run itself.</b> Starting does not move anywhere: the
/// screen that asked whether to start reports the running capture and then what it produced, so an
/// operator watches the thing he authorised in the place he authorised it.
/// </para>
/// </remarks>
internal enum AuditScreen
{
    /// <summary>What would be read, from which controller, and the chance to change it.</summary>
    Domains,

    /// <summary>What the run will and will not do, the button that starts it, and what it did.</summary>
    Review,
}

// The AuditStep enum stood here and was removed when the Review step became a dialog. It had two
// members - Domains and Review - and the second showed the same table under a different heading.
// The order was data rather than branching so a third step could arrive by being added to a list;
// no third step ever did, and what the second one was reaching for turned out to be a summary of
// the whole run rather than another page of the same one. See AuditReview.

/// <summary>
/// One domain's row of the New Audit table.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read-only except for the controller.</b> Everything shown is something discovery or preflight
/// established; the one thing an operator can change is which controller the domain is read from,
/// and he validates it before the run commits rather than finding out three hours in.
/// </para>
/// <para>
/// <b>Every rendered fact distinguishes "not established" from "established and false".</b> That is
/// the standing rule of this screen, and it is why the site, the four answers and the PDC emulator
/// are rendered from <see cref="Established"/> rather than from a checkbox. A two-state control over
/// a three-state fact is the defect, not the styling.
/// </para>
/// </remarks>
internal sealed partial class DomainRowViewModel : AuditRowViewModel
{
    private readonly Func<DomainRowViewModel, Task> _validate;
    private readonly Action<DomainRowViewModel, bool> _include;

    [ObservableProperty]
    private string _namedController = string.Empty;

    [ObservableProperty]
    private string? _problem;

    /// <summary>
    /// What became of checking the named controller, in the same three states every other answer
    /// on this screen uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Silence used to mean three different things here, which is the defect this exists to
    /// end.</b> A good check cleared the refusal and returned, so <i>not checked yet</i>,
    /// <i>checked and usable</i> and <i>the box is empty</i> all drew the same cell - and the only
    /// way to learn the button had done anything was to provoke a failure. That is the unasked
    /// question rendered as an answer that <c>docs/decisions/0056</c> exists to forbid, one column
    /// further along than the columns it was written for.
    /// </para>
    /// <para>
    /// <b>It is reset the moment the name is edited.</b> A check vouches for the host that was
    /// asked about and for no other, so a state left standing over an edited name would be this
    /// screen saying a controller had been proved when a different one had.
    /// </para>
    /// </remarks>
    [ObservableProperty]
    private Established _controllerCheck = Established.NotEstablished;

    /// <summary>Creates the row over what the run established about this domain.</summary>
    /// <param name="plan">The domain as discovery, and possibly preflight, described it.</param>
    /// <param name="validate">Checks the named controller against the forest.</param>
    /// <param name="include">
    /// Puts the domain in or takes it out. Held by the window rather than acted on here, because
    /// taking a domain out means asking the operator to attest to it and a row cannot put a dialog
    /// in front of anybody.
    /// </param>
    public DomainRowViewModel(
        DomainPlanRow plan,
        Func<DomainRowViewModel, Task> validate,
        Action<DomainRowViewModel, bool> include)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(validate);
        ArgumentNullException.ThrowIfNull(include);

        Plan = plan;
        _validate = validate;
        _include = include;
    }

    /// <summary>Whether this domain is in the run, and if not, which kind of exclusion it is.</summary>
    /// <remarks>
    /// <b>Three states behind a two-state control, and that is the whole point of it being here.</b>
    /// The tick box renders this; it is not this. A row that stored the tick box's boolean could
    /// not tell a domain an operator took out from one the forest names no controller for, and
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> requires it to.
    /// </remarks>
    public override DomainInclusion Inclusion { get; protected set; } = DomainInclusion.Included;

    /// <summary>
    /// What the operator stated when he took this domain out, or null where it is in - or out and
    /// not yet accounted for.
    /// </summary>
    /// <remarks>
    /// Null against an excluded row is the state that stops a run: an exclusion nobody has put a
    /// name to. It is not the same as the row being included, and
    /// <see cref="IsExcludedWithoutAttestation"/> is what tells them apart.
    /// </remarks>
    public override ExclusionAttestation? Attestation { get; protected set; }

    /// <summary>
    /// Whether this domain is in the run, for the tick box on the row.
    /// </summary>
    /// <remarks>
    /// <b>Setting it asks; it does not decide.</b> Unticking hands the decision to the window,
    /// which puts the attestation in front of the operator and only then takes the domain out. An
    /// operator who dismisses that dialog leaves the domain in, so the box he just cleared comes
    /// back - which is the visible half of <c>0059</c>'s rule that an attestation must be made
    /// rather than clicked past.
    /// </remarks>
    public override bool IsIncluded
    {
        get => Inclusion == DomainInclusion.Included;
        set => _include(this, value);
    }

    /// <summary>A domain with a controller may be taken out of the run and put back.</summary>
    public override bool MayChangeInclusion => true;

    /// <summary>A domain with a controller may be read from a different one.</summary>
    public override bool MayNameAController => true;

    /// <summary>Whether this domain has been left out with nothing stated for it.</summary>
    public bool IsExcludedWithoutAttestationRow =>
        Inclusion != DomainInclusion.Included && Attestation is null;

    /// <summary>
    /// Takes this domain out of the run under the attestation the operator made.
    /// </summary>
    /// <param name="attestation">What he stated. Required: an exclusion is never silent.</param>
    public void ExcludeUnder(ExclusionAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);

        Inclusion = attestation.Kind;
        Attestation = attestation;

        InclusionChanged();
    }

    /// <summary>
    /// Puts this domain back in the run, discarding whatever was stated for it.
    /// </summary>
    /// <remarks>
    /// The attestation is dropped rather than kept against a re-included domain, because
    /// <c>0059</c> forbids a reason surviving to be offered again, and a stored reason for a domain
    /// that is in the run is exactly the stale attestation that record exists to prevent.
    /// </remarks>
    public void Include()
    {
        Inclusion = DomainInclusion.Included;
        Attestation = null;

        InclusionChanged();
    }

    private void InclusionChanged()
    {
        OnPropertyChanged(nameof(Inclusion));
        OnPropertyChanged(nameof(Attestation));
        OnPropertyChanged(nameof(IsIncluded));
        OnPropertyChanged(nameof(IsExcludedWithoutAttestation));
    }


    /// <summary>What the run established about this domain.</summary>
    public DomainPlanRow Plan { get; private set; }

    /// <summary>The domain partition this row is about.</summary>
    public override string NamingContext => Plan.NamingContext;

    /// <summary>
    /// What to call this domain on screen: the name the forest declares, where it declared one.
    /// </summary>
    /// <remarks>
    /// The table and the notes beneath it used to disagree - a row headed
    /// <c>DC=ph,DC=ad,DC=lab</c> above a line saying <c>PHDC.ph.ad.lab</c> - which is two spellings
    /// of one domain on one row, and the operator is left to work out that they are the same place.
    /// The DNS name is also much the shorter of the two.
    /// </remarks>
    public override string Domain => Plan.DnsName ?? Plan.NamingContext;

    /// <summary>The controller this domain would be read from.</summary>
    public override string Controller => Plan.Controller;

    /// <summary>
    /// Where that controller is, and whether that is near this machine.
    /// </summary>
    /// <remarks>
    /// Short enough for a cell. The sentence it used to be is <see cref="SiteDetail"/> and is one
    /// hover away, which is the trade the table makes throughout: the mark carries the state, the
    /// cell carries the fact, and the sentence carries the reasoning.
    /// </remarks>
    public string Site => Plan.ControllerSite is null
        ? "None named"
        : Plan.ControllerIsInThisMachinesSite switch
        {
            Established.Yes => $"{Plan.ControllerSite} (this machine's)",
            Established.No => $"{Plan.ControllerSite} (elsewhere)",
            _ => $"{Plan.ControllerSite} (ours not known)",
        };

    /// <summary>The site, said in full, for a reader who wants the whole sentence.</summary>
    public string SiteDetail => Plan.ControllerSite is null
        ? "The forest names no site for this controller."
        : Plan.ControllerIsInThisMachinesSite switch
        {
            Established.Yes => $"{Plan.ControllerSite}, which is this machine's site.",
            Established.No => $"{Plan.ControllerSite}, which is not this machine's site.",
            _ => $"{Plan.ControllerSite}. Whether that is this machine's site is not known.",
        };

    /// <summary>
    /// What the run would fall back to, or that there is nothing to fall back to.
    /// </summary>
    public string Failover => Plan.Alternatives.Count == 0
        ? "None. This is the only controller the forest names for this domain."
        : string.Join(", ", Plan.Alternatives);

    /// <summary>
    /// The failover position, but only where it is worth an operator's attention.
    /// </summary>
    /// <remarks>
    /// <b>A column of "three others" on every row is a column nobody reads.</b> The list mattered
    /// as a column while the table was being judged; what an operator acts on is the case where
    /// there is nowhere to go, because a controller that fails part-way through then leaves the run
    /// stuck. The full list is still on the row, on the controller's tooltip.
    /// </remarks>
    public string? FailoverNote => Plan.Alternatives.Count == 0
        ? "The forest names no other controller for this domain, so a read that fails part-way "
          + "through has nowhere to go."
        : null;

    /// <summary>
    /// Whether the controller was chosen knowing everything the ranking wanted.
    /// </summary>
    public string Choice => Plan.ControllerWasNamedByOperator
        ? "Named by you."
        : Plan.ChoiceWasFullyInformed
            ? "Chosen on every input to the ranking."
            : "Chosen without every input to the ranking, so a better controller may exist.";

    /// <summary>
    /// The caveat on the choice, where there is one.
    /// </summary>
    /// <remarks>
    /// Two of the three answers need no telling. <i>Named by you</i> is already visible - the box
    /// on the row has his name in it - and <i>chosen on every input</i> is the ordinary case, which
    /// is exactly the kind of thing a column repeats on every row until nobody reads the column.
    /// </remarks>
    public string? ChoiceNote =>
        Plan.ControllerWasNamedByOperator || Plan.ChoiceWasFullyInformed
            ? null
            : "This controller was ranked without every input the ranking wanted, so a better one "
              + "may exist.";

    /// <summary>
    /// Whether a connection answered, and on which rung of the ladder.
    /// </summary>
    /// <remarks>
    /// A controller nothing answered from is given no rung. Reporting such a walk as though the
    /// controller had refused every protected rung is a security claim about a customer's forest
    /// that the product did not measure - finding <c>F-S35-1</c>.
    /// </remarks>
    public string Connection => !Plan.WasPreflighted
        ? NotAskedYet
        : Plan.Answered switch
        {
            Established.Yes => InWords(Plan.RungReached) ?? "Answered; rung not recorded",
            Established.No => "Nothing answered",
            _ => NotAskedYet,
        };

    /// <summary>The connection, said in full.</summary>
    public string ConnectionDetail => !Plan.WasPreflighted
        ? NotAskedYet
        : Plan.Answered switch
        {
            Established.Yes => InWords(Plan.RungReached) is { } rung
                ? $"The connection reached the {rung.ToLowerInvariant()} rung of the ladder."
                : "Answered; the rung was not recorded.",
            Established.No => "Nothing answered, so nothing is known about how it protects "
                + "connections.",
            _ => NotAskedYet,
        };

    /// <summary>
    /// A rung's name as a reader would say it, rather than as the type spells it.
    /// </summary>
    /// <remarks>
    /// <c>SignedAndSealed</c> is how the value is written down and not how anybody says it, and it
    /// sat in a table where every other cell was ordinary English. Done here rather than by
    /// renaming the enum, because the name is written into bundles that must keep reading the same
    /// way in six months.
    /// </remarks>
    private static string? InWords(string? rung) => rung is null
        ? null
        : string.Concat(rung.Select((c, at) =>
            at > 0 && char.IsUpper(c) ? " " + char.ToLowerInvariant(c) : c.ToString()));

    /// <summary>Whether the controller says it serves this partition.</summary>
    public string ServesThePartition => Say(Plan.ServesThePartition, "Yes", "No");

    /// <summary>Whether it serves this partition, said in full.</summary>
    public string ServesThePartitionDetail => Say(
        Plan.ServesThePartition,
        "Yes.",
        "No - this controller says it does not serve this partition.");

    /// <summary>Whether the domain's Password Settings Container could be read.</summary>
    /// <remarks>
    /// "No" says the read did not succeed and deliberately does not say why: a caller lacking list
    /// access and an absent container produce the same result code.
    /// </remarks>
    public string PasswordSettings => Say(
        Plan.PasswordSettingsContainerReadable, "Readable", "Could not be read");

    /// <summary>Whether the container could be read, said in full.</summary>
    public string PasswordSettingsDetail => Say(
        Plan.PasswordSettingsContainerReadable,
        "Readable.",
        "Could not be read, so this run will not be able to say whether the domain has any "
            + "fine-grained password policy.");

    /// <summary>Whether this controller is the domain's PDC emulator.</summary>
    public string PdcEmulator => Say(Plan.IsThisDomainsPdcEmulator, "Yes", "No");

    /// <summary>Whether it is the PDC emulator, said in full.</summary>
    public string PdcEmulatorDetail => Say(
        Plan.IsThisDomainsPdcEmulator,
        "Yes - this is the domain's PDC emulator.",
        "No.");

    /// <summary>
    /// The warning about reading a domain from its PDC emulator, or null where none applies.
    /// </summary>
    /// <remarks>
    /// <b>Narrowed to the domains where the operator could act on it.</b> A prompt that fires on
    /// every domain of a single-controller forest teaches an operator to click past prompts. What
    /// is written into <c>preflight.json</c> is not narrowed - see <c>0055</c>.
    /// </remarks>
    public string? PdcEmulatorWarning => Plan.PdcEmulatorPromptApplies
        ? $"This domain would be read from {Plan.Controller}, which is its PDC emulator. Ranking "
          + $"still preferred it over the {Plan.Alternatives.Count} other controller(s) the forest "
          + "names for this domain. That machine also carries time, password changes and account "
          + "lockout for the domain, and an audit is a read measured in hours. You can name "
          + "another controller above."
        : null;

    /// <summary>What went wrong for this domain, in the words the audit layer used.</summary>
    public IReadOnlyList<string> Faults => Plan.Faults;

    // ===================================================================================
    // Which state each fact above is in.
    //
    // These say what the run established. They are not presentation: a view model may hold no
    // Brush, Color, Visibility or Style, and ShellMvvmGateTests fails the build for one. The view
    // decides what a state looks like; this decides what the state is.
    //
    // WHICH FACTS DRAW THE EYE IS THE OWNER'S JUDGEMENT, NOT THIS FILE'S. 0056 decision 3 fixes
    // the default - a gap is quiet - and leaves "which gaps carry risk" to be settled per screen
    // against a running window. Every mapping below is a proposed default awaiting that review,
    // recorded in docs/areas/how-the-app-looks.md. Changing one is a one-line edit here.
    // ===================================================================================

    /// <summary>
    /// Whether the controller's site is known, and whether it is this machine's.
    /// </summary>
    /// <remarks>
    /// A controller in another site is established and worth attention: an audit is a read
    /// measured in hours and crossing a site boundary is paid on every one of them. A site that
    /// could not be compared is a gap and stays quiet.
    /// </remarks>
    public FactState SiteState => Plan.ControllerSite is null
        ? FactState.NotEstablished
        : Plan.ControllerIsInThisMachinesSite switch
        {
            Established.Yes => FactState.EstablishedGood,
            Established.No => FactState.EstablishedBad,
            _ => FactState.NotEstablished,
        };

    /// <summary>Whether this domain has anywhere to fall back to.</summary>
    /// <remarks>
    /// Established either way - the forest either names other controllers or it does not. Having
    /// none is the answer worth attention, because a controller that fails part-way through leaves
    /// the run with nowhere to go.
    /// </remarks>
    public FactState FailoverState => Plan.Alternatives.Count == 0
        ? FactState.EstablishedBad
        : FactState.EstablishedGood;

    /// <summary>Whether the controller was chosen knowing everything the ranking wanted.</summary>
    /// <remarks>
    /// A choice made without every input is not a bad choice - it is a choice whose quality was
    /// not established. It takes the quiet treatment rather than the attention-seeking one.
    /// </remarks>
    public FactState ChoiceState => Plan.ControllerWasNamedByOperator || Plan.ChoiceWasFullyInformed
        ? FactState.EstablishedGood
        : FactState.NotEstablished;

    /// <summary>Whether a connection answered, and how protected it was.</summary>
    /// <remarks>
    /// Nothing answering is a fault rather than a fact about the forest: the remedy is technical.
    /// A domain not yet asked is a gap.
    /// </remarks>
    public FactState ConnectionState => !Plan.WasPreflighted
        ? FactState.NotEstablished
        : Plan.Answered switch
        {
            Established.Yes => FactState.EstablishedGood,
            Established.No => FactState.Fault,
            _ => FactState.NotEstablished,
        };

    /// <summary>Whether the controller says it serves this partition.</summary>
    public FactState ServesThePartitionState => State(Plan.ServesThePartition);

    /// <summary>Whether the domain's Password Settings Container could be read.</summary>
    public FactState PasswordSettingsState => State(Plan.PasswordSettingsContainerReadable);

    /// <summary>Whether this controller is the domain's PDC emulator.</summary>
    /// <remarks>
    /// <b>Both answers are good ones.</b> Being read from the PDC emulator is not itself a
    /// problem - in a domain with one controller there was never an alternative, and 0055's
    /// amendment narrowed the prompt to exactly the domains where an operator could have chosen
    /// differently. The concern, where there is one, is carried by
    /// <see cref="PdcEmulatorWarning"/> and styled there. Marking every PDC emulator row as
    /// worth attention would put an amber mark on all three rows of a three-domain lab where
    /// nothing is wrong and nothing can be done.
    /// </remarks>
    public FactState PdcEmulatorState => State(Plan.IsThisDomainsPdcEmulator, badIsBad: false);

    /// <summary>The state of the PDC emulator prompt, where one applies.</summary>
    /// <remarks>
    /// Established and worth attention: the prompt exists only where the operator can act on it.
    /// </remarks>
    public FactState PdcEmulatorWarningState => FactState.EstablishedBad;

    /// <summary>
    /// Whether this domain has anything to say that will not fit in a table cell.
    /// </summary>
    /// <remarks>
    /// The prompt, the faults and a refusal are paragraphs. A paragraph in a cell is either
    /// truncated or it sets the row height for every other domain, so they are shown beneath the
    /// table - and only for the domains that have one, or every row would carry an empty block
    /// naming itself for no reason.
    /// </remarks>
    public bool HasSomethingToSay =>
        PdcEmulatorWarning is not null
        || FailoverNote is not null
        || ChoiceNote is not null
        || Faults.Count > 0
        || Problem is not null;

    /// <summary>
    /// Checks the named controller against the forest, without starting anything.
    /// </summary>
    [RelayCommand]
    public Task ValidateAsync() => _validate(this);

    /// <summary>
    /// How many facts this screen tracks about one domain.
    /// </summary>
    /// <remarks>
    /// Needed as a number on its own, because a domain the forest names no controller for has no
    /// row to count and the run establishes none of these about it either. Bound to
    /// <see cref="FactStates"/> by a test rather than by comment, so the two cannot drift.
    /// </remarks>
    public const int FactsPerDomain = 7;

    /// <summary>
    /// Every fact this screen tracks about this domain, as states rather than as sentences.
    /// </summary>
    /// <remarks>
    /// The count of what a run will not establish is derived from exactly these, and not from a
    /// second list written beside them. A total counting something the table does not show - or
    /// missing something it does - would be a number an operator cannot reconcile with the rows in
    /// front of him, which is worse than no total at all.
    /// </remarks>
    public IReadOnlyList<FactState> FactStates =>
    [
        SiteState,
        FailoverState,
        ChoiceState,
        ConnectionState,
        ServesThePartitionState,
        PasswordSettingsState,
        PdcEmulatorState,
    ];

    /// <summary>
    /// How many of this domain's facts the run has not established.
    /// </summary>
    /// <remarks>
    /// An excluded domain counts all of them: the run will read nothing from it, so nothing about
    /// it will be established, whatever the cells happened to say before it was taken out.
    /// </remarks>
    public int UnestablishedFactCount => Inclusion != DomainInclusion.Included
        ? FactsPerDomain
        : FactStates.Count(s => s == FactState.NotEstablished);

    /// <summary>
    /// Whether anything about this domain is worth an operator's attention.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Anything not simply fine.</b> A fact the run established as bad, a question it never got
    /// an answer to, and a note already printed beneath the table all count. The two unestablished
    /// cases are included deliberately: <c>0056</c> has three states and the third is not a quiet
    /// success, so a domain nobody could answer for must not sit behind a clean-looking button.
    /// </para>
    /// <para>
    /// This is what lights the warning on the Details button. It is not a claim that anything is
    /// wrong - it is a claim that there is something here he has not seen.
    /// </para>
    /// </remarks>
    public override bool NeedsAttention =>
        FactStates.Any(s => s != FactState.EstablishedGood) || HasSomethingToSay;

    /// <summary>Replaces what this row shows with what a later pass established.</summary>
    /// <param name="plan">The domain as the latest pass described it.</param>
    public void Update(DomainPlanRow plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        Plan = plan;

        OnPropertyChanged(nameof(Controller));
        OnPropertyChanged(nameof(Site));
        OnPropertyChanged(nameof(Failover));
        OnPropertyChanged(nameof(Choice));
        OnPropertyChanged(nameof(Connection));
        OnPropertyChanged(nameof(ServesThePartition));
        OnPropertyChanged(nameof(PasswordSettings));
        OnPropertyChanged(nameof(PdcEmulator));
        OnPropertyChanged(nameof(PdcEmulatorWarning));
        OnPropertyChanged(nameof(Faults));
        OnPropertyChanged(nameof(HasSomethingToSay));

        // The states move with the sentences they describe. A sentence that updated while its
        // state did not would put a mark beside a fact it no longer belongs to, which is worse
        // than no mark at all.
        OnPropertyChanged(nameof(SiteState));
        OnPropertyChanged(nameof(FailoverState));
        OnPropertyChanged(nameof(ChoiceState));
        OnPropertyChanged(nameof(ConnectionState));
        OnPropertyChanged(nameof(ServesThePartitionState));
        OnPropertyChanged(nameof(PasswordSettingsState));
        OnPropertyChanged(nameof(PdcEmulatorState));
    }

    private const string NotAskedYet = "Not asked yet.";

    /// <summary>
    /// What the override cell says beside the box, or nothing where nothing has been established.
    /// </summary>
    /// <remarks>
    /// <b>Blank is the honest rendering of an unasked question</b>, and the only one of the three
    /// that may be silent. The other two are said out loud, because an operator who pressed a
    /// button is entitled to know whether it answered - and because a refusal that showed only in
    /// a dialog he has since closed leaves the row looking exactly like one that passed.
    /// </remarks>
    public string ControllerCheckText => ControllerCheck switch
    {
        Established.Yes => "Checked - serves this domain",
        Established.No => "Refused - see Details",
        _ => string.Empty,
    };

    /// <summary>The sentence moves with the state it describes.</summary>
    /// <param name="value">What became of the check.</param>
    partial void OnControllerCheckChanged(Established value) =>
        OnPropertyChanged(nameof(ControllerCheckText));

    /// <summary>
    /// Editing the name withdraws whatever was established about the old one.
    /// </summary>
    /// <remarks>
    /// Both the state and the refusal go, because both are about the host that was asked. Leaving
    /// either would put a verdict on this row that belongs to a name no longer in the box - the
    /// stale-answer failure, one field over. Whether the run may start is not restored here:
    /// <c>RunMayProceed</c> stays false until preflight has been put again with the new name.
    /// </remarks>
    /// <param name="value">The name as it now stands.</param>
    partial void OnNamedControllerChanged(string value)
    {
        ControllerCheck = Established.NotEstablished;
        Problem = null;
    }

    /// <summary>
    /// A refusal appearing or clearing changes whether this domain has anything to say beneath the
    /// table.
    /// </summary>
    partial void OnProblemChanged(string? value) =>
        OnPropertyChanged(nameof(HasSomethingToSay));

    /// <summary>
    /// The state of a three-state answer, where an unasked question never borrows the negative
    /// one.
    /// </summary>
    /// <param name="answer">What the run established.</param>
    /// <param name="badIsBad">
    /// Whether a <see cref="Established.No"/> answer is one worth an operator's attention. False
    /// where both answers are simply facts, such as whether a controller happens to hold the PDC
    /// emulator role.
    /// </param>
    private FactState State(Established answer, bool badIsBad = true) => !Plan.WasPreflighted
        ? FactState.NotEstablished
        : answer switch
        {
            Established.Yes => FactState.EstablishedGood,
            Established.No => badIsBad ? FactState.EstablishedBad : FactState.EstablishedGood,
            _ => FactState.NotEstablished,
        };

    /// <summary>
    /// A three-state answer in words, where an unasked question never borrows the negative one.
    /// </summary>
    private string Say(Established answer, string yes, string no) => !Plan.WasPreflighted
        ? NotAskedYet
        : answer switch
        {
            Established.Yes => yes,
            Established.No => no,
            _ => "Could not be established.",
        };
}

/// <summary>
/// The New Audit window: what would be read, from where, and the one place a run is started.
/// </summary>
/// <remarks>
/// <para>
/// <b>It asks for nothing it can work out.</b> There is no controller to type and no forest to
/// name: the run finds the forest this machine is in, per
/// <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c>. A typed name is the recovery path
/// for a machine that is not joined to the forest being audited, and making it the first field
/// would make the recovery path the ordinary one.
/// </para>
/// <para>
/// <b>Start begins the capture, and there is no second prompt behind it.</b> The Review step is the
/// confirmation. An operator who has read the table and the warnings has confirmed, and a dialog
/// asking whether he meant it is the kind of thing people learn to dismiss.
/// </para>
/// <para>
/// <b>A controller the audit layer refuses stops the run here too, in the audit layer's own
/// words.</b> The predecessor fell back to the automatic choice, so an operator who mistyped a host
/// name got a successful run against a controller he did not name. Nothing here softens that
/// refusal into a warning.
/// </para>
/// </remarks>
internal sealed partial class NewAuditViewModel : ObservableObject
{
    private readonly ICaptureLauncher _capture;
    private readonly INewAuditDialog _dialogs;

    /// <summary>How a captured run gets opened for reading.</summary>
    /// <remarks>
    /// The same seam the run library uses, so a run is opened one way rather than two that can
    /// drift apart. It is only ever asked once a run has sealed evidence.
    /// </remarks>
    private readonly IRunOpener _opener;
    private readonly IDerivationLauncher _deriving;
    private readonly IJudgingLauncher _judging;

    /// <summary>
    /// How many domains this machine reads at the same time.
    /// </summary>
    /// <remarks>
    /// <b>One value drives both the run and the sentence the review shows.</b> Reading the setting
    /// twice - once to describe the capture and once to start it - is how a screen comes to promise
    /// one thing and a run to do another.
    /// </remarks>
    private readonly DomainConcurrency _concurrency;

    private CancellationTokenSource? _stopping;
    private long _progressEpoch;
    private bool _auditHasGaps;
    public AuditProgressViewModel Progress { get; } = new(TimeProvider.System);

    [ObservableProperty]
    private AuditScreen _screen = AuditScreen.Domains;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _isCapturing;

    /// <summary>Whether facts are being derived, which follows the capture and precedes judging.</summary>
    /// <remarks>
    /// Held apart from <see cref="IsJudging"/> for the same reason that is held apart from
    /// <see cref="IsCapturing"/>: they are different phases with different words on screen, and an
    /// operator watching a derivation expand a forest's nesting is not watching rules reach
    /// verdicts.
    /// </remarks>
    [ObservableProperty]
    private bool _isDeriving;

    /// <summary>How many objects the derivation's pass over the evidence has read so far.</summary>
    [ObservableProperty]
    private long _objectsDerived;

    /// <summary>What the derivation has to say, or null before one has run.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasDerivationReport))]
    private string? _derivationReport;

    /// <summary>Whether the evidence is being judged, which follows the capture.</summary>
    /// <remarks>
    /// Held apart from <see cref="IsCapturing"/> because they are different phases with different
    /// words on screen, and because <c>docs/decisions/0072</c> turns on whether a <i>capture</i> is
    /// running. Folding judging into that flag would refuse to open a bundle for the whole of a
    /// judging, which is not what the record says and not what it protects.
    /// </remarks>
    [ObservableProperty]
    private bool _isJudging;

    /// <summary>How many objects the judging has reached a verdict on so far.</summary>
    [ObservableProperty]
    private long _objectsJudged;

    /// <summary>What the judging has to say, or null before one has run.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasJudgingReport))]
    private string? _judgingReport;

    /// <summary>How many findings there were, by severity.</summary>
    /// <remarks>
    /// Empty both before a judging and after one that found nothing. Those are different states and
    /// <see cref="JudgingReport"/> is what separates them, which is why a screen must show the
    /// words beside the counts rather than the counts alone.
    /// </remarks>
    [ObservableProperty]
    private IReadOnlyDictionary<Severity, int> _findings =
        new Dictionary<Severity, int>();

    [ObservableProperty]
    private string? _problem;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCaptureReport))]
    private string? _report;

    public bool HasCaptureReport => Report is not null;
    public bool HasDerivationReport => DerivationReport is not null;
    public bool HasJudgingReport => JudgingReport is not null;

    [ObservableProperty]
    private string? _forestFqdn;

    [ObservableProperty]
    private string _siteDescription = string.Empty;

    /// <summary>
    /// What the window is doing while it is busy, for the indicator beside the Cancel.
    /// </summary>
    /// <remarks>
    /// Deliberately a sentence and not a proportion. The audit layer returns one result at the end
    /// of a pass, so a bar claiming to be four domains through nine would be a number this window
    /// invented - and inventing one to look responsive is the same fault as inventing a fact about
    /// a forest, in a smaller place.
    /// </remarks>
    [ObservableProperty]
    private string? _busyMessage;

    /// <summary>
    /// Whether the last pass was stopped by the operator, so the window can offer it again.
    /// </summary>
    [ObservableProperty]
    private bool _wasStopped;

    /// <summary>
    /// Whether the pass is worth offering again - it was stopped, or it could not finish.
    /// </summary>
    /// <remarks>
    /// Nothing was written either way, so there is nothing to undo and no reason to make him close
    /// the window and start again.
    /// </remarks>
    [ObservableProperty]
    private bool _mayLookAgain;

    /// <summary>Creates the window's state.</summary>
    /// <param name="location">Where this installation keeps its runs.</param>
    /// <param name="capture">How a run is planned, checked and started.</param>
    /// <param name="dialogs">
    /// How this window puts something in front of the operator and waits for him. Taken as a seam
    /// so a refusal can be proved without a person present to dismiss one.
    /// </param>
    /// <param name="deriving">
    /// How facts about more than one object are derived from the sealed evidence, before any rule
    /// reads it.
    /// </param>
    /// <param name="judging">How the sealed evidence is judged once the capture has produced it.</param>
    /// <param name="concurrency">
    /// How many domains this machine reads at the same time. Taken rather than read from a setting
    /// here, so the run and the sentence the review shows come from one value and cannot describe
    /// different captures.
    /// </param>
    public NewAuditViewModel(
        RunLibraryLocation location,
        ICaptureLauncher capture,
        INewAuditDialog dialogs,
        IRunOpener opener,
        IDerivationLauncher deriving,
        IJudgingLauncher judging,
        DomainConcurrency concurrency)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(capture);
        ArgumentNullException.ThrowIfNull(dialogs);
        ArgumentNullException.ThrowIfNull(opener);
        ArgumentNullException.ThrowIfNull(deriving);
        ArgumentNullException.ThrowIfNull(judging);
        ArgumentNullException.ThrowIfNull(concurrency);

        Location = location;
        _capture = capture;
        _dialogs = dialogs;
        _opener = opener;
        _deriving = deriving;
        _judging = judging;
        _concurrency = concurrency;
    }

    /// <summary>Where this installation keeps its runs.</summary>
    public RunLibraryLocation Location { get; }

    private static readonly ResourceManager ScopeWording = new(
        "SecureAD.Shell.Resources.CaptureObjectScope", typeof(NewAuditViewModel).Assembly);
    private bool _includeEnatelSso;

    /// <summary>The inclusion-only override for this audit, never a remembered setting.</summary>
    public bool IncludeEnatelSso
    {
        get => _includeEnatelSso;
        set
        {
            if (MayChangeObjectScope && SetProperty(ref _includeEnatelSso, value))
                OnPropertyChanged(nameof(ExcludedObjectClasses));
        }
    }

    /// <summary>A running or finished audit cannot have its displayed scope changed.</summary>
    public bool MayChangeObjectScope => !IsBusy && !IsCapturing && !HasFinished;

    private bool _captureOnly;

    /// <summary>
    /// Whether this run stops once the evidence is sealed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why the choice exists at all.</b> A capture of a real forest takes hours, and until this
    /// was offered a failure in deriving or judging happened at the end of them, on a directory
    /// that had already moved on. Separating the two acts means a production capture can be taken
    /// and walked away from, and analysed afterwards from the sealed bundle as many times as it
    /// takes. It is what the command line's <c>--capture</c> has always offered; this is the same
    /// thing in the window.
    /// </para>
    /// <para>
    /// <b>Analysing is the default, deliberately.</b> An operator who wants a finished audit should
    /// get one without choosing anything, and the run that stops early is the one he has to ask
    /// for. Reversing that would make the ordinary case the exception.
    /// </para>
    /// <para>
    /// <b>A capture-only run is not a degraded one.</b> Its evidence is complete and sealed, and
    /// the library says so in words - <i>Evidence sealed - not assessed</i> - rather than showing
    /// findings, permissions and control edges as zero. See
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c>: a clean number is the more
    /// reassuring of the two readings and an operator will take it.
    /// </para>
    /// </remarks>
    public bool CaptureOnly
    {
        get => _captureOnly;
        set
        {
            // Frozen once the run is under way, for the reason MayChangeObjectScope is: what the
            // screen says this run will do must go on describing the run that is happening.
            if (value && MayChangeObjectScope && SetProperty(ref _captureOnly, true))
                OnPropertyChanged(nameof(CaptureAndAnalyse));
        }
    }

    /// <summary>
    /// Whether this run derives and judges once the evidence is sealed. The default.
    /// </summary>
    /// <remarks>
    /// The pair are offered as two plain answers rather than as one value a view has to convert,
    /// following <c>AssetsViewModel.ShowsBase</c>. A converter turning a flag into a tick is a place
    /// presentation logic accumulates, outside the one layer that has tests. The words themselves
    /// sit in the view beside the other <c>ChoiceRadio</c> in this product, for the same reason.
    /// </remarks>
    public bool CaptureAndAnalyse
    {
        get => !_captureOnly;
        set
        {
            if (value && MayChangeObjectScope && SetProperty(ref _captureOnly, false, nameof(CaptureOnly)))
                OnPropertyChanged(nameof(CaptureAndAnalyse));
        }
    }

    /// <summary>The exact classes that the current choice leaves unassessed.</summary>
    public IReadOnlyList<string> ExcludedObjectClasses => CaptureObjectScope.For(IncludeEnatelSso).ExcludedClasses;

    public string ObjectClassesHeading => ScopeText("Heading");
    public string IncludeEnatelSsoLabel => ScopeText("IncludeEnatel");
    public string ObjectScopeHelp => ScopeText("Help");
    public string ExcludedClassesHeading => ScopeText("ExcludedClasses");

    private static string ScopeText(string key) =>
        ScopeWording.GetString(key, CultureInfo.CurrentUICulture) ?? throw new InvalidOperationException(key);

    /// <summary>One row per domain a controller was found for.</summary>
    public ObservableCollection<DomainRowViewModel> Domains { get; } = [];

    /// <summary>
    /// Domains the forest declares and names no writable controller for.
    /// </summary>
    /// <remarks>
    /// Shown rather than omitted. A domain missing from an audit with nothing saying it is missing
    /// is the one outcome an audit tool must not produce. What is done about it is an operator's
    /// attestation, per <c>0054</c>: it is an exclusion like any other, and until he has put a name
    /// to it the run does not start.
    /// </remarks>
    public ObservableCollection<ExcludedDomainViewModel> DomainsWithNoController { get; } = [];

    /// <summary>
    /// Every domain the forest declared, readable or not, in the order the table shows them.
    /// </summary>
    /// <remarks>
    /// <b>One table for both kinds.</b> A domain the forest names no writable controller for used
    /// to live in a list beneath the table, and would vanish from the domain screen the moment that
    /// area was cleared. A domain missing from an audit with nothing saying it is missing is the
    /// one outcome this product must not produce, so it is a row like any other - one that refuses
    /// the controls it cannot honour rather than one that hides.
    /// </remarks>
    public ObservableCollection<AuditRowViewModel> Rows { get; } = [];

    /// <summary>Rebuilds the table from both kinds of row.</summary>
    private void RefreshRows()
    {
        Rows.Clear();

        foreach (var row in Domains)
            Rows.Add(row);

        foreach (var domain in DomainsWithNoController)
            Rows.Add(domain);
    }

    /// <summary>
    /// Every domain leaving this run, of either kind, for the Review step to list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One list, two kinds, and the kind is carried rather than implied by position.</b>
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> requires the two be told
    /// apart wherever they appear, so what is exposed is the kind itself and not the collection it
    /// came from.
    /// </para>
    /// <para>
    /// <b>One collection, mutated in place, rather than a fresh list on every read.</b> It began as
    /// a computed property and the section rendered its heading with nothing under it: the list is
    /// rebuilt while the panel holding it is still collapsed, and an items control that is told its
    /// source changed while it cannot measure has no reason to look again once it can. A collection
    /// whose identity never changes drives the control through <c>CollectionChanged</c> instead,
    /// which does not depend on when anything became visible.
    /// </para>
    /// </remarks>
    public ObservableCollection<ExclusionView> Exclusions { get; } = [];

    /// <summary>Rebuilds the list of what is leaving this run.</summary>
    private void RefreshExclusions()
    {
        Exclusions.Clear();

        foreach (var row in Domains.Where(d => d.Inclusion != DomainInclusion.Included))
            Exclusions.Add(new ExclusionView(row.Domain, row.Inclusion, row.Attestation));

        foreach (var domain in DomainsWithNoController)
            Exclusions.Add(new ExclusionView(domain.Domain, domain.Inclusion, domain.Attestation));
    }

    /// <summary>Whether anything is leaving this run at all.</summary>
    public bool HasExclusions => Exclusions.Count > 0;

    /// <summary>
    /// Whether nothing is being left out, so the review can say so rather than showing a gap.
    /// </summary>
    /// <remarks>
    /// An empty section is ambiguous - it reads as easily as <i>nothing was left out</i> as
    /// <i>this was not worked out</i>. Saying it plainly costs one line and removes the question.
    /// </remarks>
    public bool HasNoExclusions => Exclusions.Count == 0;

    /// <summary>
    /// Whether any domain has something worth an operator's attention behind the Details button.
    /// </summary>
    /// <remarks>
    /// <b>One mark for the whole table, because there is one button.</b> The table no longer shows
    /// the site, the connection, whether the controller serves the partition, the password settings
    /// container or the PDC emulator - those are behind Details. Trimming a column is only honest
    /// if what it carried can still announce itself, so the button says when there is something
    /// under it rather than waiting to be opened.
    /// </remarks>
    public bool AnyDomainNeedsAttention => Domains.Any(d => d.NeedsAttention);

    /// <summary>
    /// How much this run will not establish, as one number over the whole forest.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Finding <c>F-0056-1</c>.</b> <c>0056</c> has every fact show in three states, and the
    /// third one - not established - was visible only one cell at a time. An operator could see
    /// each gap and was nowhere told there were eleven of them, which is the number he would
    /// actually act on before committing a machine to a capture measured in hours.
    /// </para>
    /// <para>
    /// <b>Counted from the same states the table renders</b>, through
    /// <see cref="DomainRowViewModel.FactStates"/>, so the total and the cells cannot disagree.
    /// A domain leaving the run contributes all of its facts, because the run will read nothing
    /// from it.
    /// </para>
    /// </remarks>
    public int UnestablishedFactCount =>
        Domains.Sum(d => d.UnestablishedFactCount)
        + (DomainsWithNoController.Count * DomainRowViewModel.FactsPerDomain);

    /// <summary>
    /// How many facts the run will not establish, said as a sentence - or that this is not yet
    /// known.
    /// </summary>
    /// <remarks>
    /// <b>It never shows zero for "not worked out yet".</b> A count of unestablished facts is
    /// itself a fact, and the standing rule of this screen is that nothing states a fact the run
    /// did not measure. Before the pass has run there is no forest to count over, and saying so is
    /// the only honest thing a total can do.
    /// </remarks>
    public string UnestablishedFactSummary => !HasPlan
        ? "Not known yet - nothing has been worked out about this forest."
        : UnestablishedFactCount == 0
            ? "This run expects to establish every fact on this screen."
            : $"{UnestablishedFactCount} facts on this screen this run will not establish.";

    /// <summary>How many exclusions still have nobody's name against them.</summary>
    public int UnattestedExclusionCount =>
        Exclusions.Count(e => e.Attestation is null);

    /// <summary>
    /// Whether anything is leaving this run unanswered for.
    /// </summary>
    /// <remarks>
    /// A boolean beside the count, because the view's <c>Shown</c> converter takes only booleans -
    /// a binding it cannot convert falls back to visible, which would leave the warning on screen
    /// over a run that has nothing wrong with it.
    /// </remarks>
    public bool HasUnattestedExclusions => UnattestedExclusionCount > 0;

    /// <summary>
    /// Why the run cannot start yet, where the reason is an exclusion nobody has answered for.
    /// </summary>
    /// <remarks>
    /// Said rather than left to a disabled button. A Start an operator cannot press and cannot see
    /// a reason for is the screen refusing without explaining itself.
    /// </remarks>
    public string? UnattestedExclusionNote => UnattestedExclusionCount == 0
        ? null
        : UnattestedExclusionCount == 1
            ? "1 domain is leaving this run with nothing stated for it. It needs a reason and an "
            + "authorising name before the run may start."
            : $"{UnattestedExclusionCount} domains are leaving this run with nothing stated for "
          + "them. Each needs a reason and an authorising name before the run may start.";

    /// <summary>Whether a plan has been worked out at all.</summary>
    public bool HasPlan => Domains.Count > 0 || DomainsWithNoController.Count > 0;

    /// <summary>Whether the domain screen is the one showing.</summary>
    public bool IsOnDomains => Screen == AuditScreen.Domains;

    /// <summary>Whether the review screen is the one showing.</summary>
    public bool IsOnReview => Screen == AuditScreen.Review;

    /// <summary>
    /// Whether the run has finished and left something behind.
    /// </summary>
    /// <remarks>
    /// Held apart from <see cref="IsCapturing"/> because the review screen is three moments in one
    /// place: what the run will do, what it is doing, and what it did. Only the last of those
    /// offers to show results.
    /// </remarks>
    [ObservableProperty]
    private bool _hasFinished;

    /// <summary>
    /// Where the evidence is, once a run has produced some.
    /// </summary>
    [ObservableProperty]
    private string? _bundleDirectory;

    /// <summary>
    /// Where a finished run's evidence landed.
    /// </summary>
    /// <remarks>
    /// <b>This used to say reading results was not built.</b> That was true when written and stopped
    /// being true on 2026-08-21, when the Assets section began reading bundles and the run library
    /// began opening them. The path is still given: knowing where a run landed is worth having
    /// whether or not it is being opened from here, and it is the only thing to say about a run
    /// that sealed nothing.
    /// </remarks>
    public string? ResultsNote => !HasFinished
        ? null
        : BundleDirectory is null
            ? "This run produced no evidence to read."
            : "The evidence is at " + BundleDirectory + ".";

    /// <summary>
    /// What this window is asking, as a question.
    /// </summary>
    /// <remarks>
    /// <b>It does not mention choosing which domains to read.</b> Every domain of the forest is
    /// read unless the operator takes one out under an attestation, and a heading offering a choice
    /// would misdescribe what the tick boxes are for.
    /// </remarks>
    public string StepQuestion => Screen switch
    {
        AuditScreen.Review when HasFinished => "What this audit produced",
        AuditScreen.Review when IsCapturing => "This audit is running",
        AuditScreen.Review => "Is this run ready to start?",
        _ => "What would this run read?",
    };

    /// <summary>
    /// How many domains the plan covers, for the window's header.
    /// </summary>
    /// <remarks>
    /// Domains with no readable controller are counted in, because they are domains this forest
    /// declares and leaving them out of the count would understate what the run is failing to
    /// reach.
    /// </remarks>
    public string DomainCountLabel
    {
        get
        {
            var total = Domains.Count + DomainsWithNoController.Count;

            return total == 1 ? "1 domain" : $"{total} domains";
        }
    }

    /// <summary>Whether preflight found every domain readable.</summary>
    public bool RunMayProceed { get; private set; }

    private IReadOnlyList<string> _blockingDomains = [];

    /// <summary>
    /// Checks one row's named controller by asking that controller, and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It contacts one machine.</b> It used to work the whole plan out again - a bootstrap
    /// connection, the configuration partition, and the candidate list for every domain in the
    /// forest - to answer a question about a single host. That is finding <c>F-S41-4</c>, and an
    /// operator correcting a typo in a nine-domain forest paid for the whole forest on every press.
    /// </para>
    /// <para>
    /// <b>It asks the host what it serves rather than asking the forest whether it should.</b> That
    /// is the question the operator actually asked - <i>is this a machine I can read this domain
    /// from</i> - and it is answerable by the machine itself. Whether the forest also names it is a
    /// separate fact, and a host that answers and holds the right partition while the forest does
    /// not list it stays <i>not established</i> in the site column rather than being called a
    /// failure.
    /// </para>
    /// <para>
    /// <b>A refusal is put in front of him and can be dismissed.</b> It is also left on the row, in
    /// the audit layer's own words, because the dialog is gone the moment he closes it and the row
    /// is what he looks at next. Dismissing clears the box so the domain falls back to the ranked
    /// choice: an operator is never held in a refusal whose only exit is closing the window.
    /// </para>
    /// </remarks>
    /// <param name="row">The row whose named controller is being checked.</param>
    public async Task ValidateOverrideAsync(DomainRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);

        if (!Location.IsChosen)
            return;

        var named = row.NamedController?.Trim();

        // An empty box is not a named controller and there is nothing to refuse. The row is
        // already on the ranked choice, and nothing has been established about anything.
        if (string.IsNullOrWhiteSpace(named))
        {
            row.Problem = null;
            row.ControllerCheck = Established.NotEstablished;
            return;
        }

        await WithBusy(async token =>
        {
            var answer = await _capture
                .CheckNamedControllerAsync(Location.Path!, named, row.NamingContext, token)
                .ConfigureAwait(true);

            if (answer.IsUsable)
            {
                // SAID OUT LOUD, because it used to be said by saying nothing. An operator who
                // pressed Validate and saw no change could not tell a controller this run had
                // proved from one it had never asked about.
                row.Problem = null;
                row.ControllerCheck = Established.Yes;
                return;
            }

            row.Problem = answer.Refusal;
            row.ControllerCheck = Established.No;

            RunMayProceed = false;
            OnPropertyChanged(nameof(CanStart));
            StartCommand.NotifyCanExecuteChanged();
            ReviewCommand.NotifyCanExecuteChanged();

            Notice = new Notice($"{named} was refused", answer.Refusal!);

            // THE NAME STAYS IN THE BOX. It used to be cleared here, which silently put the domain
            // back on the ranked controller and then displayed that controller in the column beside
            // the refusal - so the screen appeared to hand back the very host it had just refused,
            // and an operator who dismissed the dialog was left with no sign that his choice had
            // been dropped at all.
            //
            // It is also the rule ControllerSelection already keeps one layer down: an override is
            // obeyed or the run stops, and never quietly replaced. The predecessor fell back
            // silently and gave an operator who mistyped a host a successful run against a
            // controller he did not name. Clearing the box here was that same fallback, moved up
            // into the window.
            //
            // The refusal stays on the row as the account of why, and editing the box withdraws
            // both. A run may not start while any row carries one.
        }).ConfigureAwait(true);
    }

    /// <summary>
    /// Asks every domain the preflight questions again, then moves to the review screen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The questions are put again rather than the answers from the opening pass being
    /// trusted.</b> What an operator does on the first screen is change controllers, so the answers
    /// on screen may have been established about machines the run will no longer read. Reviewing
    /// with them would carry a measurement of one controller under the name of another.
    /// </para>
    /// <para>
    /// <b>Start is on the review screen and nowhere else.</b> That is what keeps opening this
    /// window from being one click away from committing a machine to a capture measured in hours.
    /// </para>
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanReview))]
    public async Task ReviewAsync()
    {
        if (!Location.IsChosen)
            return;

        await WithBusy(async token =>
        {
            ForgetPreflight();
            BusyMessage = AskingEveryDomain;

            var check = await _capture
                .ValidateAsync(Location.Path!, forest: null, Overrides(), token)
                .ConfigureAwait(true);

            if (!check.IsSuccess)
            {
                Problem = check.Error.Description;
                MayLookAgain = true;
                return;
            }

            Adopt(check.Value);
        }).ConfigureAwait(true);

        // Judged after the busy block, not inside it. CanStart requires that nothing is in flight,
        // and the re-check is in flight for the whole of that block - asking there would refuse
        // every time, and the refusal would look exactly like an operator being told no.
        //
        // A pass that failed or was stopped establishes nothing to review: the domains it never
        // reached are unasked rather than unreadable, and summarising them would be the screen
        // stating a fact the run did not measure.
        if (Problem is null && !WasStopped && CanStart)
        {
            Screen = AuditScreen.Review;
        }
    }

    /// <summary>Goes back to the domain screen.</summary>
    /// <remarks>
    /// Available until the run starts. Nothing has been written before then, so there is nothing to
    /// undo and no reason to make an operator close the window to change one controller.
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanGoBack))]
    public void Back() => Screen = AuditScreen.Domains;

    /// <summary>Whether the operator may return to the domain screen.</summary>
    public bool CanGoBack => IsOnReview && !IsCapturing && !HasFinished;

    /// <summary>Leaves the audit, discarding whatever was planned.</summary>
    /// <remarks>
    /// <para>
    /// <b>This is what closing the window used to be.</b> The audit is a surface inside the shell
    /// now - <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c> - and
    /// the shell's rail is inert while a run is being planned, so without this the operator has no
    /// way out of a decision he has changed his mind about.
    /// </para>
    /// <para>
    /// <b>Nothing is lost by pressing it.</b> Planning writes nothing. That is why it is not
    /// confirmed and not drawn in red: <c>0070</c> spends red on the control that stops something
    /// already running, and this one refuses to appear while anything is.
    /// </para>
    /// <para>
    /// <b>Once a run has sealed evidence this control opens it.</b> The wizard has nothing further
    /// to say at that point, so viewing the results and leaving are one act rather than two
    /// controls - the shape the owner chose on 2026-08-21. A run that sealed nothing opens nothing,
    /// because there is no evidence to read and offering some would be a claim the run cannot back.
    /// </para>
    /// <para>
    /// <b>The directory is the whole condition, deliberately.</b> This read
    /// <c>HasFinished &amp;&amp; BundleDirectory is not null</c> at first, which sounds safer and
    /// measures nothing: <see cref="BundleDirectory"/> is assigned only where a capture completed,
    /// in the line before <see cref="HasFinished"/> is set, so a directory that exists already means
    /// a run that finished. Removing the first half failed no test. A condition that cannot be false
    /// when the rest is true reads like a guard and is not one, so it is gone rather than kept for
    /// the look of it.
    /// </para>
    /// <para>
    /// <b>The order is load-bearing.</b> Both acts navigate: <c>ShellViewModel.Leave</c> shows Home,
    /// and opening a run shows Assets, so whichever runs last decides where the operator ends up.
    /// Leaving therefore happens first and opening second. The reverse was shipped on 2026-08-21
    /// and the owner found it in the lab: View results tore down the audit and landed him on Home,
    /// having passed through Assets. <c>TheAuditIsLeftBeforeTheRunIsOpened</c> pins this, by
    /// observing the moment of opening rather than checking afterwards that both things happened.
    /// </para>
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanLeave))]
    public void Leave()
    {
        _dialogs.Leave();

        if (BundleDirectory is { } directory)
            _opener.Open(directory);
    }

    /// <summary>Whether the operator may leave the audit.</summary>
    /// <remarks>
    /// Not while a pass or a capture is running. Those have a Stop of their own, and a second way
    /// out that silently abandoned a running capture would be two controls doing different things
    /// under one idea of "get me out of here".
    /// </remarks>
    public bool CanLeave => !IsBusy && !IsCapturing;

    /// <summary>
    /// What the button that leaves should say, which is not the same thing before and after a run.
    /// </summary>
    /// <remarks>
    /// Before a capture, leaving throws away a plan and the word has to admit it. After one, the
    /// evidence is written and on disk, and "Discard" would say the opposite of what happened.
    /// <para>
    /// <b>Three labels, not two.</b> A run that sealed evidence offers to view it; a run that
    /// finished and sealed nothing is still done, and there is nothing for it to show.
    /// </para>
    /// </remarks>
    public string LeaveLabel => HasFinished
        ? BundleDirectory is null ? "Done" : "View results"
        : "Discard";

    /// <summary>What the review screen states about this run.</summary>
    public AuditReview Review => Describe();

    /// <summary>The whole audit, as it is put to the operator before he commits to it.</summary>
    private AuditReview Describe() =>
        new(
            ForestFqdn ?? "this forest",
            [
                .. Domains
                    .Where(d => d.Inclusion == DomainInclusion.Included)
                    .Select(d => new ReviewedDomain(d.Domain, d.Controller)),
            ],
            [.. Exclusions],
            UnestablishedFactSummary,
            [
                .. Domains
                    .Where(d => d.HasSomethingToSay)
                    .SelectMany(d => new[] { d.FailoverNote, d.ChoiceNote, d.PdcEmulatorWarning }
                        .Concat(d.Faults)
                        .Append(d.Problem)
                        .OfType<string>()
                        // Named, because these sentences say "this domain" and the review screen
                        // is the one place they are read away from the row that gave them. Seen on
                        // screen 2026-08-18: six warnings, three of them word-for-word repeats of
                        // the other three, and nothing saying which domain any of them concerned.
                        // A warning an operator cannot attribute is a warning he cannot act on.
                        .Select(note => $"{d.Domain}: {note}")),
            ],
            _concurrency.Effective);

    /// <summary>Shows everything the table no longer carries, for every domain at once.</summary>
    /// <remarks>
    /// <para>
    /// One button rather than one per row, because an operator opening this is comparing domains,
    /// and something he has to open and close nine times makes him hold the last one in his head.
    /// </para>
    /// <para>
    /// <b>A panel over this surface rather than a window over it</b> -
    /// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c>. Held here
    /// as state, because there is no longer a window whose existence is the answer to "is it
    /// showing".
    /// </para>
    /// </remarks>
    [RelayCommand]
    public void ShowDetails() =>
        Details = new DomainDetailsViewModel([.. Domains], CloseDetails);

    /// <summary>Puts the details panel away.</summary>
    /// <remarks>
    /// A method rather than a lambda at the call site. The lambda read
    /// <c>() =&gt; Details = null)</c>, which <c>NullDefaultGateTests</c> takes for a parameter
    /// defaulted to null - the <c>&gt;</c> of the arrow sits where a type would. The gate is right
    /// to be blunt about that shape, so the code moved rather than the gate.
    /// </remarks>
    private void CloseDetails() => Details = null;

    /// <summary>The details panel while it is showing, and null when it is not.</summary>
    [ObservableProperty]
    private DomainDetailsViewModel? _details;

    /// <summary>Whether the details panel is showing.</summary>
    public bool HasDetails => Details is not null;

    /// <summary>What the surface is telling the operator, or null when it is telling him nothing.</summary>
    [ObservableProperty]
    private Notice? _notice;

    /// <summary>Whether there is a notice to show.</summary>
    public bool HasNotice => Notice is not null;

    /// <summary>Puts the notice away.</summary>
    /// <remarks>
    /// A banner does not dismiss itself when the operator looks elsewhere, the way a message box
    /// did when he pressed OK, so the one control that clears it is stated here. What the notice
    /// reported is not undone by dismissing it: a refused controller keeps its refusal on the row.
    /// </remarks>
    [RelayCommand]
    public void DismissNotice() => Notice = null;

    /// <summary>
    /// Works the whole thing out when the window opens: what would be read, then what every domain
    /// answers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Opening the window is the press.</b> The two buttons this replaced - <i>work out what
    /// would be read</i> and <i>check every domain</i> - asked an operator to ask for something he
    /// had already asked for by opening a window called New Audit. Neither took a decision from
    /// him: he cannot choose what the forest contains, and he cannot answer the preflight questions
    /// himself.
    /// </para>
    /// <para>
    /// <b>It lands on Domains and never on Review.</b> Start lives behind Review, so opening this
    /// window is never one click away from committing a machine to a capture measured in hours.
    /// </para>
    /// <para>
    /// <b>It can be stopped.</b> This is a network act against every domain in the forest, begun
    /// without being asked for, and <c>0048</c> requires a way out of it. What a stopped pass
    /// leaves is what it had reached - the domains it never asked stay <i>not asked</i>, because a
    /// pass an operator ended has discovered nothing about them.
    /// </para>
    /// </remarks>
    [RelayCommand]
    public async Task OpenAsync()
    {
        if (!Location.IsChosen)
        {
            Problem = "Choose a run library on the Home screen first. This product will not decide "
                + "for itself where several gigabytes of evidence go.";
            return;
        }

        await WithBusy(async token =>
        {
            ForgetPreflight();
            BusyMessage = "Finding the forest and working out what would be read\u2026";

            var plan = await _capture
                .PlanAsync(Location.Path!, forest: null, Overrides(), token)
                .ConfigureAwait(true);

            if (!plan.IsSuccess)
            {
                Failed("The forest could not be read", plan.Error.Description);
                return;
            }

            Adopt(plan.Value);

            BusyMessage = AskingEveryDomain;

            var check = await _capture
                .ValidateAsync(Location.Path!, forest: null, Overrides(), token)
                .ConfigureAwait(true);

            if (!check.IsSuccess)
            {
                Failed("The domains could not all be asked", check.Error.Description);
                return;
            }

            Adopt(check.Value);
        }).ConfigureAwait(true);

        // Only once the window has stopped claiming to be working. An operator answering a dialog
        // over a busy indicator cannot tell whether the thing it is asking about has finished
        // happening, and this one asks him to put his name to something.
        //
        // Not after a pass that failed or was stopped: the domains it never reached are unasked
        // rather than unreadable, and asking him to attest to an absence the run never established
        // would be the screen stating a fact the run did not measure.
        if (Problem is null && !WasStopped)
            AttestUnreadableDomains();
    }

    /// <summary>
    /// Reports a pass that could not finish, and leaves a way to try it again.
    /// </summary>
    /// <remarks>
    /// The message is put in front of him as well as left on the screen. The window works itself
    /// out on opening, so a failure leaves a table with nothing in it and no button an operator can
    /// point at - and an empty table with no reason given is the worst thing this screen could do.
    /// The audit layer's words are passed through unchanged, because they now name the stage that
    /// failed and those stages have different remedies.
    /// </remarks>
    private void Failed(string title, string reason)
    {
        Problem = reason;
        MayLookAgain = true;

        Notice = new Notice(title, reason);
    }

    /// <summary>What the indicator says while every domain is being asked.</summary>
    private const string AskingEveryDomain = "Asking every domain whether it can be read\u2026";

    /// <summary>
    /// Takes on what a per-domain pass established, row by row.
    /// </summary>
    private void Adopt(AuditCheck check)
    {
        foreach (var answers in check.Domains)
        {
            var row = Row(answers.NamingContext);

            row?.Update(row.Plan.With(answers, _controllerSites, _site));
        }

        RunMayProceed = check.RunMayProceed;
        _blockingDomains = check.BlockingDomains;
        OnPropertyChanged(nameof(CanStart));
        StartCommand.NotifyCanExecuteChanged();
        ReviewCommand.NotifyCanExecuteChanged();

        // The per-domain states have just moved, and the forest-wide total is derived from them.
        InclusionChanged();
    }

    /// <summary>A fresh pass cannot inherit permission to start from a previous pass.</summary>
    private void ForgetPreflight()
    {
        RunMayProceed = false;
        _blockingDomains = [];
        Problem = null;
    }

    /// <summary>
    /// Puts a domain in or takes it out, asking for an attestation before it goes out.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Unticking asks; it does not exclude.</b> The domain only leaves the run once the operator
    /// has stated a reason and an authorising name. An operator who dismisses the dialog gets the
    /// domain back, tick and all, because <c>0059</c> makes the friction the control: an exclusion
    /// nobody would answer for is not an exclusion this product will make on his behalf.
    /// </para>
    /// <para>
    /// <b>Re-ticking asks nothing.</b> Putting a domain back is not a decision that needs
    /// accounting for - the run reads it, and the evidence speaks for itself.
    /// </para>
    /// </remarks>
    /// <param name="row">The row whose tick box was changed.</param>
    /// <param name="included">Whether the operator wants it in.</param>
    private void SetInclusion(DomainRowViewModel row, bool included)
    {
        if (included)
        {
            row.Include();
            InclusionChanged();
            return;
        }

        var attestation = Attest(row.Domain, DomainInclusion.ExcludedByChoice, row.NamingContext);

        if (attestation is null)
        {
            // He walked away from the dialog. The domain stays in, and the box he cleared comes
            // back - raised explicitly because nothing about the row changed, so nothing would
            // otherwise tell the tick box to redraw itself.
            row.Include();
            InclusionChanged();
            return;
        }

        row.ExcludeUnder(attestation);
        InclusionChanged();
    }

    /// <summary>
    /// Asks the operator to account for one exclusion, and stamps what only the run can know.
    /// </summary>
    /// <remarks>
    /// The account and the time are stamped here rather than collected in the dialog: one is
    /// captured from Windows and the other is observed, so neither is the operator's to give and a
    /// dialog that returned them would be a dialog that could get them wrong. <c>0062</c>.
    /// </remarks>
    private ExclusionAttestation? Attest(string domain, DomainInclusion kind, string namingContext)
    {
        var stated = _dialogs.AskForAttestation(domain, kind);

        return stated is null
            ? null
            : new ExclusionAttestation(
                namingContext,
                // The name the forest declared, where it declared one. Coverage is keyed by DNS
                // name; falling back to the naming context is worse than a mismatch would be only
                // if it were derived, and it is not - it is the identifier this row already shows.
                _domainDnsNames.TryGetValue(namingContext, out var fqdn) ? fqdn : namingContext,
                kind,
                stated.Reason,
                stated.Note,
                SignedInAccount.Name(),
                stated.AuthorisedBy,
                DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Asks the operator to account for every domain the forest named no controller for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One at a time, and only for the ones not yet accounted for.</b> Per <c>0054</c> these are
    /// exclusions rather than gaps, so each needs its own name against it; and a second pass over
    /// the same forest must not ask again about a domain already attested.
    /// </para>
    /// <para>
    /// <b>Dismissing one does not put it back in the run</b>, because there is nothing to put it
    /// back into - the forest names no controller to read it from. It stays out, unattested, and
    /// <see cref="CanStart"/> refuses the run until he answers. That is the one asymmetry with a
    /// domain excluded by choice, and it exists because the two situations really are different.
    /// </para>
    /// </remarks>
    private void AttestUnreadableDomains()
    {
        foreach (var domain in DomainsWithNoController.Where(d => d.IsExcludedWithoutAttestation))
        {
            var attestation = Attest(
                domain.Domain,
                DomainInclusion.ExcludedForWantOfCandidates,
                domain.NamingContext);

            if (attestation is not null)
                domain.AttestUnder(attestation);
        }

        InclusionChanged();
    }

    /// <summary>
    /// Every attestation this run carries, for the bundle to record.
    /// </summary>
    /// <remarks>
    /// Gathered from both collections, because <c>0054</c> makes both kinds exclusions and
    /// <c>0062</c> puts the whole of each into the bundle. <see cref="CanStart"/> has already
    /// refused a run with an exclusion nobody answered for, so nothing null-shaped reaches here.
    /// </remarks>
    private IReadOnlyList<ExclusionAttestation> Attestations() =>
    [
        .. Domains.Select(d => d.Attestation).OfType<ExclusionAttestation>(),
        .. DomainsWithNoController.Select(d => d.Attestation).OfType<ExclusionAttestation>(),
    ];

    /// <summary>Tells the window that what the run covers, or does not, has moved.</summary>
    private void InclusionChanged()
    {
        // The list is rebuilt in place before anything derived from it is announced, so that a
        // panel becoming visible on HasExclusions already has its contents behind it.
        RefreshExclusions();
        RefreshRows();

        OnPropertyChanged(nameof(HasExclusions));
        OnPropertyChanged(nameof(HasNoExclusions));
        OnPropertyChanged(nameof(Review));
        OnPropertyChanged(nameof(AnyDomainNeedsAttention));
        OnPropertyChanged(nameof(UnattestedExclusionCount));
        OnPropertyChanged(nameof(HasUnattestedExclusions));
        OnPropertyChanged(nameof(UnattestedExclusionNote));
        OnPropertyChanged(nameof(UnestablishedFactCount));
        OnPropertyChanged(nameof(UnestablishedFactSummary));
        OnPropertyChanged(nameof(CanStart));
        StartCommand.NotifyCanExecuteChanged();
        ReviewCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Whether the run can be started: preflight passed, nothing is refused, every exclusion has
    /// been answered for, and nothing is in flight.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An unattested exclusion stops the run.</b> It replaces the older rule that any domain
    /// with no controller stopped it outright - which was that rule standing in for an attestation
    /// nothing had yet built. A domain the forest cannot offer a controller for may now leave the
    /// run, but only once somebody has put a name to its leaving, per <c>0054</c> and <c>0062</c>.
    /// A domain excluded by choice is held to exactly the same standard.
    /// </para>
    /// <para>
    /// <b>It no longer asks which step is showing.</b> There is one screen, and what keeps opening
    /// this window from being one click from a capture is that Start lives inside the review rather
    /// than in the footer. This guards the review action, so the conditions it enforces are
    /// unchanged - they are simply checked before the summary is drawn instead of before a second
    /// page was.
    /// </para>
    /// </remarks>
    public bool CanStart =>
        (RunMayProceed || EveryBlockingDomainIsAttested())
        && UnattestedExclusionCount == 0
        && Domains.All(d => d.Problem is null)
        && !IsBusy
        && !IsCapturing
        && Location.IsChosen;

    /// <summary>
    /// Whether the preflight questions may be put again. Asking is always allowed; it is starting
    /// that has conditions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This exists because gating it on <see cref="CanStart"/> was a deadlock, found in the
    /// field on 2026-09-23 while an operator was trying to capture a production forest.</b> A
    /// named controller that is refused sets <see cref="RunMayProceed"/> false, and by design
    /// nothing restores it but a fresh preflight - <see cref="ValidateOverrideAsync"/> deliberately
    /// does not, because a per-row check establishes nothing about the other domains. But the fresh
    /// preflight is this command. So the one action that could clear the refusal sat behind the
    /// refusal, and the screen could not be recovered by any button on it: the operator had named a
    /// good controller, been told it serves the domain, and still could not go on.
    /// </para>
    /// <para>
    /// <b>Nothing is loosened by this.</b> <see cref="ReviewAsync"/> already re-asks every domain
    /// and then consults <see cref="CanStart"/> before it moves to the review screen, so the
    /// conditions that guard a capture are enforced exactly where they were - on the answers, once
    /// they exist. What changes is that an operator may now ask for those answers while things are
    /// wrong, which is precisely when he needs to.
    /// </para>
    /// </remarks>
    public bool CanReview => !IsBusy && !IsCapturing && Location.IsChosen;

    private bool EveryBlockingDomainIsAttested()
    {
        var attested = Attestations()
            .Select(attestation => attestation.NamingContext)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return _blockingDomains.Count > 0 && _blockingDomains.All(attested.Contains);
    }

    /// <summary>
    /// Starts the capture. The Review step was the confirmation; there is no second prompt.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanStart))]
    public async Task StartAsync()
    {
        if (IsCapturing || IsBusy) return;
        _stopping?.Dispose();
        _stopping = new CancellationTokenSource();
        _progressEpoch++;
        _auditHasGaps = false;
        Problem = null;
        Notice = null;
        WasStopped = false;
        HasFinished = false;
        BundleDirectory = null;
        DerivationReport = JudgingReport = null;
        ObjectsDerived = ObjectsJudged = 0;
        Findings = new Dictionary<Severity, int>();
        Progress.Begin(AuditProgressViewModel.Text("Capture"));
        using var clockStop = new CancellationTokenSource();
        var clock = RefreshProgressAsync(clockStop.Token);

        IsCapturing = true;
        Report = "Running. This reads every partition in the forest and may take a while.";

        try
        {
            var outcome = await _capture
                .RunAsync(
                    Location.Path!, forest: null, Overrides(), Attestations(),
                    _concurrency.Effective, IncludeEnatelSso, _stopping.Token)
                .ConfigureAwait(true);

            Report = Describe(outcome);

            // What it produced, so the screen can offer to read it. A run can succeed and seal
            // nothing - CaptureOutcome.ProducedABundle false with a directory means it recorded
            // what happened and wrote no evidence - and that directory must not be offered as
            // results, because there are none in it to read.
            BundleDirectory = outcome.IsSuccess && outcome.Value.ProducedABundle
                ? outcome.Value.BundleDirectory
                : null;

            // Deriving and judging both follow a capture without being asked for - the owner's
            // shape, 2026-08-26 - unless the operator asked for a capture on its own. The decision
            // to audit was the decision to do both, so there is no second prompt and no control to
            // press once the run is under way; the one place it is decided is the review page,
            // before Start. Only sealed evidence is read: a run that sealed nothing has nothing for
            // a closure or a rule to read.
            //
            // A CAPTURE-ONLY RUN STOPS HERE, AND THAT IS NOT A FAILURE. The evidence is complete
            // and sealed, and the library will say so - "Evidence sealed - not assessed" - with no
            // counters at all rather than counters reading zero. It can be derived from and judged
            // later, from the run library, as many times as it takes.
            //
            // Deriving goes first. What it produces are facts about more than one object, which is
            // what a rule reading a group's membership will rest on - so a judging that ran before
            // it would rest on nothing.
            if (BundleDirectory is { } sealedEvidence && !CaptureOnly)
            {
                // Each is asked to absorb its own defects. Deriving that threw its way out of here
                // would skip the judging entirely and land in the catch below, which speaks for a
                // capture and would say no bundle was sealed - by this point one has been.
                _stopping.Token.ThrowIfCancellationRequested();
                await DeriveAsync(sealedEvidence, _stopping.Token).ConfigureAwait(true);
                _stopping.Token.ThrowIfCancellationRequested();
                await JudgeAsync(sealedEvidence, _stopping.Token).ConfigureAwait(true);
                _stopping.Token.ThrowIfCancellationRequested();
            }

            HasFinished = true;
            Progress.End(AuditProgressViewModel.Text(BundleDirectory is null ? "NoEvidence" : _auditHasGaps ? "FinishedWithGaps" : "Finished"));
        }
        catch (OperationCanceledException)
        {
            Progress.End(AuditProgressViewModel.Text("Stopped"));
            Report = BundleDirectory is { } sealedEvidence
                ? $"Stopped. The evidence was already sealed and is safe at {sealedEvidence}."
                : "Stopped. The run recorded why it stopped.";
        }
        catch (Exception failure)
        {
            // A capture that throws must not take the application down with it. Before this, a
            // defect in the audit layer reached the dispatcher unhandled and killed the process
            // mid-run: the operator lost the window, the plan he had just worked through, and any
            // account of what went wrong beyond a Windows crash dialog.
            //
            // Nothing is swallowed. The exception's own words are put in front of him and left on
            // the screen, because a window that quietly returned to idle after a failed run would
            // be worse than the crash - he would not know the run had not happened.
            //
            // WHAT BECAME OF THE EVIDENCE IS READ RATHER THAN ASSUMED. This said "No bundle was
            // sealed" outright, which was true while a capture was the only thing inside this try.
            // It is not true of a fault after the seal, and an operator told his evidence does not
            // exist would capture the forest again for nothing - hours, against a directory that has
            // moved on.
            Report =
                $"The run stopped on an error the product did not expect: {failure.Message}\n\n"
                + (BundleDirectory is { } sealedEvidence
                    ? $"The evidence was sealed and is safe at {sealedEvidence}. "
                    : "No bundle was sealed. ")
                + "This is a defect rather than something you did, and the message above is what "
                + "to report.";

            Notice = new Notice("The run could not finish", Report!);
            Progress.End(AuditProgressViewModel.Text("Failed"));
        }
        finally
        {
            IsCapturing = false;
            clockStop.Cancel();
            await clock.ConfigureAwait(true);
        }
    }

    /// <summary>
    /// Derives facts from the evidence the capture just sealed, reporting progress as it goes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A derivation that fails does not fail the run, and does not stop the judging.</b> The
    /// evidence is sealed and on disk either way, and every rule that exists today reads one object
    /// and needs nothing derived. Refusing to judge because a closure could not be built would
    /// withhold findings that do not depend on it.
    /// </para>
    /// <para>
    /// <b>A degraded derivation is reported rather than passed over.</b> Deriving writes a store
    /// saying what went wrong, and an operator told only that it finished would read a partial
    /// closure as a whole one - which is the failure the whole derive stage is shaped around.
    /// </para>
    /// <para>
    /// <b>Cancelling is allowed to reach the caller.</b> Stopping during a derivation stops the
    /// audit, which is what an operator pressing Cancel means, and <c>StartAsync</c> already says
    /// what became of a run that stopped.
    /// </para>
    /// </remarks>
    private async Task DeriveAsync(string bundleDirectory, CancellationToken cancellationToken)
    {
        IsDeriving = true;
        var epoch = _progressEpoch;
        Progress.Report(AuditProgressViewModel.Text("Deriving"), string.Empty);
        DerivationReport = "Deriving from the evidence. Nothing is read from the directory now.";

        try
        {
            var derived = await _deriving
                .RunAsync(bundleDirectory, new Progress<DerivationProgress>(value =>
                {
                    if (epoch == _progressEpoch && IsDeriving) OnDerived(value);
                }), cancellationToken)
                .ConfigureAwait(true);

            if (!derived.IsSuccess)
            {
                _auditHasGaps = true;
                DerivationReport =
                    $"The evidence was sealed and is safe. Nothing could be derived from it: "
                    + $"{derived.Error!.Description} The facts can be derived again from this "
                    + "bundle without capturing the forest a second time.";
                return;
            }

            DerivationReport = Describe(derived.Value);
            _auditHasGaps |= derived.Value.State != DerivationRunState.Completed || !derived.Value.EveryPhaseThatRanSucceeded;
        }
        catch (OperationCanceledException)
        {
            DerivationReport = AuditProgressViewModel.Text("DerivationStopped");
            throw;
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            _auditHasGaps = true;
            // A defect in deriving costs the derivation and nothing else. Left to escape, it would
            // skip the judging and be reported as a run that failed - so a fault in the newest and
            // least-exercised stage would take the findings down with it, and the findings do not
            // depend on it. Cancelling is excluded deliberately: stopping means stopping the audit,
            // not carrying on to judge.
            DerivationReport =
                $"The evidence was sealed and is safe. Deriving stopped on an error the product "
                + $"did not expect: {failure.Message} This is a defect rather than something you "
                + "did. Judging can proceed only if its required inputs are available. The facts can be derived again from "
                + "this bundle once the defect is fixed.";
        }
        finally
        {
            IsDeriving = false;
        }
    }

    /// <summary>Notes how far the derivation has got, for the screen watching it.</summary>
    private void OnDerived(DerivationProgress progress)
    {
        ObjectsDerived = Math.Max(ObjectsDerived, progress.ObjectsRead);
        Progress.Report(AuditProgressViewModel.PhaseText(progress.Phase),
            progress.Phase == "MembershipAndNesting" ? AuditProgressViewModel.Text("ObjectsRead", ObjectsDerived) : string.Empty);
    }

    /// <summary>
    /// What a finished derivation produced, in the words the completion screen uses.
    /// </summary>
    /// <remarks>
    /// <b>A degraded derivation says so rather than reporting its facts as if they were all of
    /// them.</b> A closure that could not be completed has established less than a complete one, and
    /// wording that omits what it missed reads as a clean result.
    /// </remarks>
    private static string Describe(DerivingOutcome derived) => derived.State switch
    {
        DerivationRunState.Completed =>
            $"Derived {derived.Principals:N0} principals and {derived.NestingEdges:N0} nesting "
            + "relationships.",
        DerivationRunState.CompletedDegraded =>
            $"Derived {derived.Principals:N0} principals and {derived.NestingEdges:N0} nesting "
            + "relationships, and at least one part could not be completed. What was derived says "
            + "which, and rules resting on it are not working from the whole picture.",
        _ =>
            "Nothing was derived. The evidence is sealed and can be derived from again.",
    };

    /// <summary>
    /// Judges the evidence the capture just sealed, reporting progress as it goes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A judging that fails does not fail the run.</b> The evidence is sealed and on disk either
    /// way, and it is the thing the operator cannot get back - it took hours and read a forest that
    /// has moved on since. So a judging that could not finish is reported and the evidence is still
    /// offered, because a judgement can be made again from the same bundle whenever the defect is
    /// fixed.
    /// </para>
    /// <para>
    /// <b>Cancelling is allowed to reach the caller.</b> Stopping during judging stops the audit,
    /// which is what an operator pressing Cancel means, and <c>StartAsync</c> already says what
    /// became of a run that stopped.
    /// </para>
    /// </remarks>
    private async Task JudgeAsync(string bundleDirectory, CancellationToken cancellationToken)
    {
        IsJudging = true;
        var epoch = _progressEpoch;
        Progress.Report(AuditProgressViewModel.Text("PreparingInputs"), string.Empty);
        JudgingReport = "Judging the evidence. Nothing is read from the directory now.";

        try
        {
            var judged = await _judging
                .RunAsync(bundleDirectory, new Progress<JudgingRun.JudgingProgress>(value =>
                {
                    if (epoch == _progressEpoch && IsJudging) OnJudged(value);
                }), cancellationToken)
                .ConfigureAwait(true);

            if (!judged.IsSuccess)
            {
                _auditHasGaps = true;
                JudgingReport =
                    $"The evidence was sealed and is safe. It could not be judged: "
                    + $"{judged.Error!.Description} The findings can be produced again from this "
                    + "bundle without capturing the forest a second time.";
                return;
            }

            Findings = judged.Value.Findings;
            ObjectsJudged = Math.Max(ObjectsJudged, judged.Value.ObjectsJudged);
            JudgingReport = Describe(judged.Value);
            _auditHasGaps |= judged.Value.State != JudgementRunState.Completed;
            Progress.Report(AuditProgressViewModel.Text("ReadingResults"), AuditProgressViewModel.Text("ObjectsProcessed", ObjectsJudged));
        }
        catch (OperationCanceledException)
        {
            JudgingReport = AuditProgressViewModel.Text("JudgingStopped");
            throw;
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            JudgingReport = failure.Message;
            throw;
        }
        finally
        {
            IsJudging = false;
        }
    }

    /// <summary>Notes how far the judging has got, for the screen watching it.</summary>
    /// <remarks>
    /// <b>The Tier-0 line replaces the object counter rather than joining it.</b> Discovery inspects
    /// the same streamed objects the rules are offered, so showing both would print one number twice
    /// under two names and invite a reader to treat them as separate progress. Elapsed time is shown
    /// because the scan has no ceiling: there is no endpoint to forecast from, so the screen reports
    /// what has happened and never what remains.
    /// </remarks>
    private void OnJudged(JudgingRun.JudgingProgress progress)
    {
        ObjectsJudged = Math.Max(ObjectsJudged, progress.ObjectsRead);
        Progress.Report(AuditProgressViewModel.PhaseText(progress.Phase.ToString()),
            progress.Phase == JudgingPhase.PreparingInputs ? string.Empty
            : progress.Tier0ObjectsObserved > 0
                ? AuditProgressViewModel.Text("Tier0Discovery", progress.Tier0ObjectsObserved,
                    AuditProgressViewModel.Spoken(progress.Tier0DiscoveryElapsed))
                : AuditProgressViewModel.Text("ObjectsProcessed", ObjectsJudged));
    }

    /// <summary>
    /// What a finished judging produced, in the words the completion screen uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A degraded judging says so rather than reporting its findings as if they were all of
    /// them.</b> A rule that could not read what it declared has established nothing, and a count
    /// that omits what it missed reads as a clean result.
    /// </para>
    /// <para>
    /// <b>And it says what stopped it.</b> "At least one rule could not reach a verdict" leaves an
    /// administrator with nowhere to go; the reasons name what to capture, or say plainly that the
    /// answer is unavailable and no re-run will produce it. Only the largest few are listed, because
    /// a completion screen that scrolls is one nobody reads to the end of.
    /// </para>
    /// </remarks>
    private static string Describe(JudgingOutcome judged) => (judged.State switch
    {
        JudgementRunState.Completed when judged.Findings.Count == 0 =>
            $"Judged {judged.ObjectsJudged:N0} objects. Every rule reached a verdict and none of "
            + "them found anything.",
        JudgementRunState.Completed =>
            $"Judged {judged.ObjectsJudged:N0} objects. Every rule reached a verdict.",
        JudgementRunState.CompletedDegraded =>
            $"Judged {judged.ObjectsJudged:N0} objects, and at least one rule could not reach a "
            + "verdict. The findings below are what the rules that did finish found, and are not "
            + "the whole picture."
            + Why(judged.CouldNotDecide),
        _ =>
            "The judging did not finish. The evidence is sealed and can be judged again.",
    }) + Requesters(judged);

    /// <summary>
    /// What the own-account membership scan covered, in the words the completion screen uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Said out loud even when it did nothing.</b> These answers are about whether a particular
    /// account could add or remove <i>itself</i> from a group. Saying nothing when the scan did not
    /// run would leave an operator reading a completed judging as a forest where nobody can, which
    /// is the one thing an audit tool must not imply.
    /// </para>
    /// <para>
    /// <b>Finishing the scan is not a claim about the forest.</b> It means every captured
    /// permission this run was allowed to read was examined; limitations name what could not be
    /// decided from the evidence.
    /// </para>
    /// </remarks>
    private static string Requesters(JudgingOutcome judged)
    {
        if (judged.Requesters is not { } requesters)
            return string.Empty;

        var limits = requesters.Discovery.Limitations.Count;
        var caveat = limits == 0
            ? string.Empty
            : $" {limits:N0} coverage limitation(s) are recorded, so this is not every possible "
                + "requester.";

        return Environment.NewLine + requesters.Discovery.Verdict switch
        {
            "NotStarted" =>
                "Own-account membership questions were not scheduled: no processing limit is "
                + "configured for that scan. This is not a finding that nobody can add themselves "
                + "to a group.",
            "ExplicitRequestsOnly" =>
                $"Stored {requesters.AssessmentsStored:N0} own-account membership answer(s) from "
                + "explicitly requested questions. No automatic scan was run.",
            "ProcessingStopped" =>
                $"Stored {requesters.AssessmentsStored:N0} own-account membership answer(s), and "
                + "the scan stopped at its configured limit before reading everything captured. "
                + "What it found is kept and the stopping point is recorded." + caveat,
            _ =>
                $"Stored {requesters.AssessmentsStored:N0} own-account membership answer(s) from "
                + $"{requesters.Discovery.PairsDiscovered:N0} discovered account/group pair(s). "
                + $"{requesters.AuthorizationUnknown:N0} could not be decided from the evidence."
                + caveat,
        };
    }

    /// <summary>
    /// What stopped the rules deciding, worst first, as sentences beneath the summary.
    /// </summary>
    /// <param name="reasons">What the judging recorded, already ordered by how far it reached.</param>
    private static string Why(IReadOnlyList<UnresolvedCount> reasons)
    {
        if (reasons.Count == 0)
            return string.Empty;

        var shown = reasons.Take(4).Select(
            r => $"{Environment.NewLine}  - {r.Reason} ({r.ObjectsAffected:N0} objects)");

        var rest = reasons.Count > 4
            ? $"{Environment.NewLine}  - and {reasons.Count - 4:N0} other reasons."
            : string.Empty;

        return Environment.NewLine + string.Concat(shown) + rest;
    }

    /// <summary>
    /// Stops whatever is running: a capture, or the pass the window began when it opened.
    /// </summary>
    /// <remarks>
    /// One control for both because there is one thing to stop at any moment, and an operator
    /// deciding which of two stop buttons applies to what he is watching is an operator being asked
    /// to understand the shape of the code.
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanStop))]
    public void Stop()
    {
        Progress.RequestStop();
        _stopping?.Cancel();
    }

    /// <summary>Whether there is anything to stop.</summary>
    public bool CanStop => IsBusy || IsCapturing;

    private string? _site;

    private IReadOnlyDictionary<string, string> _controllerSites =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The DNS name the forest declared for each domain, keyed by naming context.
    /// </summary>
    /// <remarks>
    /// Held because a run's coverage is keyed by DNS name while a domain left out of a run is
    /// identified by its naming context. The pairing comes from the forest and is never derived
    /// here.
    /// </remarks>
    private IReadOnlyDictionary<string, string> _domainDnsNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The controllers the operator named, keyed by the forest's declared DNS name. Per run and never
    /// stored, per <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>.
    /// </summary>
    private Dictionary<string, string> Overrides() =>
        Domains
            .Where(d => !string.IsNullOrWhiteSpace(d.NamedController))
            .ToDictionary(
                d => _domainDnsNames[d.NamingContext],
                d => d.NamedController.Trim(),
                StringComparer.OrdinalIgnoreCase);

    private DomainRowViewModel? Row(string namingContext) =>
        Domains.FirstOrDefault(d =>
            string.Equals(d.NamingContext, namingContext, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Takes on what a pass established, keeping any controller the operator has typed.
    /// </summary>
    private void Adopt(AuditPlanView plan)
    {
        ForestFqdn = plan.ForestFqdn;
        _site = plan.ThisMachinesSite;
        _controllerSites = plan.ControllerSites;
        _domainDnsNames = plan.DomainDnsNames;

        SiteDescription = plan.SiteKnowledge switch
        {
            SiteKnowledge.Known => plan.ThisMachinesSite!,
            SiteKnowledge.ForestDeclaresNoSubnets =>
                "Not known - this forest declares no subnets at all, so no machine can be placed "
                + "in a site by address.",
            _ => "Not known - none of the subnets this forest declares contains an address of "
                + "this machine.",
        };

        foreach (var row in plan.Domains)
        {
            var existing = Row(row.NamingContext);

            if (existing is null)
                Domains.Add(new DomainRowViewModel(row, ValidateOverrideAsync, SetInclusion));
            else
                existing.Update(row);
        }

        // Kept across a second pass where the domain is still unreadable, so that an attestation
        // already made is not silently discarded and asked for again by a pass the operator did not
        // know had run.
        var attested = DomainsWithNoController.ToDictionary(d => d.NamingContext);

        DomainsWithNoController.Clear();

        foreach (var domain in plan.DomainsWithNoCandidates)
        {
            DomainsWithNoController.Add(
                attested.TryGetValue(domain, out var existing)
                    ? existing
                    : new ExcludedDomainViewModel(
                        domain,
                        plan.DomainDnsNames.TryGetValue(domain, out var fqdn) ? fqdn : null));
        }

        Problem = null;
        OnPropertyChanged(nameof(HasPlan));
        OnPropertyChanged(nameof(DomainCountLabel));
        OnPropertyChanged(nameof(CanStart));
        StartCommand.NotifyCanExecuteChanged();
        ReviewCommand.NotifyCanExecuteChanged();

        InclusionChanged();
    }

    /// <summary>
    /// Runs <paramref name="work"/> with the screen marked busy, and leaves it unmarked whatever
    /// happens.
    /// </summary>
    private async Task WithBusy(Func<CancellationToken, Task> work)
    {
        _stopping?.Dispose();
        _stopping = new CancellationTokenSource();
        Progress.Begin(AuditProgressViewModel.Text("Preparing"));
        using var clockStop = new CancellationTokenSource();
        var clock = RefreshProgressAsync(clockStop.Token);

        IsBusy = true;
        WasStopped = false;
        MayLookAgain = false;

        try
        {
            await work(_stopping.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            // What the pass reached stays on screen. The domains it never got to are still
            // not preflighted, so every answer of theirs reads "not asked yet" - which is what
            // happened, and is not the same as a domain that was asked and did not answer.
            WasStopped = true;
            MayLookAgain = true;
            Problem = "Stopped. The domains below that were not reached were not asked, rather "
                + "than asked and found wanting.";
        }
        finally
        {
            Progress.End(AuditProgressViewModel.Text(WasStopped ? "Stopped" : "Ready"));
            IsBusy = false;
            BusyMessage = null;
            clockStop.Cancel();
            await clock.ConfigureAwait(true);
        }
    }

    private async Task RefreshProgressAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(true))
                Progress.Refresh();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // This UI clock is owned and awaited by the operation; it must not outlive it.
        }
    }

    partial void OnBusyMessageChanged(string? value)
    {
        if (IsBusy && value is not null) Progress.Report(value, string.Empty);
    }

    /// <summary>
    /// What became of a run, in a sentence. A run that ended without a bundle is not a run that
    /// failed to start, and the two must not read alike.
    /// </summary>
    private static string Describe(Result<CaptureOutcome> outcome)
    {
        if (!outcome.IsSuccess)
            return outcome.Error.Description;

        return outcome.Value.ProducedABundle
            ? $"Sealed: {outcome.Value.BundleDirectory}"
            : "The run ended without a sealed bundle. What happened is recorded in "
              + outcome.Value.BundleDirectory + ".";
    }

    /// <summary>The screen, and everything drawn differently on each one, move together.</summary>
    partial void OnScreenChanged(AuditScreen value)
    {
        OnPropertyChanged(nameof(IsOnDomains));
        OnPropertyChanged(nameof(IsOnReview));
        OnPropertyChanged(nameof(StepQuestion));
        OnPropertyChanged(nameof(Review));
        OnPropertyChanged(nameof(CanGoBack));
        BackCommand.NotifyCanExecuteChanged();
    }

    /// <summary>A finished run changes what the screen offers and what it is headed by.</summary>
    partial void OnHasFinishedChanged(bool value)
    {
        OnPropertyChanged(nameof(MayChangeObjectScope));
        OnPropertyChanged(nameof(StepQuestion));
        OnPropertyChanged(nameof(ResultsNote));
        OnPropertyChanged(nameof(CanGoBack));
        OnPropertyChanged(nameof(LeaveLabel));
        BackCommand.NotifyCanExecuteChanged();
    }

    /// <summary>Where the evidence is decides the results note and what the footer offers.</summary>
    partial void OnBundleDirectoryChanged(string? value)
    {
        OnPropertyChanged(nameof(ResultsNote));
        OnPropertyChanged(nameof(LeaveLabel));
    }

    /// <summary>The panel and the scrim over the surface appear and vanish together.</summary>
    partial void OnDetailsChanged(DomainDetailsViewModel? value) =>
        OnPropertyChanged(nameof(HasDetails));

    /// <summary>The banner appears and vanishes with what it has to say.</summary>
    partial void OnNoticeChanged(Notice? value) =>
        OnPropertyChanged(nameof(HasNotice));

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(MayChangeObjectScope));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanStop));
        OnPropertyChanged(nameof(CanLeave));
        StartCommand.NotifyCanExecuteChanged();
        ReviewCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
        LeaveCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsCapturingChanged(bool value)
    {
        OnPropertyChanged(nameof(MayChangeObjectScope));
        OnPropertyChanged(nameof(StepQuestion));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanStop));
        OnPropertyChanged(nameof(CanLeave));
        StartCommand.NotifyCanExecuteChanged();
        ReviewCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
        LeaveCommand.NotifyCanExecuteChanged();
    }
}
