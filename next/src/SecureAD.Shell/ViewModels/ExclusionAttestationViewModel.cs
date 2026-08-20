using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One reason on the attestation dialog: the wording an operator reads, and the value behind it.
/// </summary>
/// <remarks>
/// The list is bound to objects rather than to the enum directly so that the wording stays in
/// <see cref="ExclusionReasons"/> - where the separation between what a person reads and what a
/// bundle stores is enforced - rather than being spelled a second time in XAML, where it would
/// drift from the first.
/// </remarks>
/// <param name="Reason">The value that reaches the bundle.</param>
internal sealed record ExclusionReasonChoice(ExclusionReason Reason)
{
    /// <summary>How this reason is put to the operator.</summary>
    public string Wording => ExclusionReasons.Wording(Reason);
}

/// <summary>
/// The state behind the exclusion attestation dialog.
/// </summary>
/// <remarks>
/// <para>
/// <b>It starts empty, every time.</b> No reason is selected, no note is carried and no
/// authorising name is remembered, per
/// <c>docs/decisions/0059-an-exclusion-is-attested-once-per-run.md</c>. Pre-filling was considered
/// and refused there: the friction is the control, and making the common case comfortable is what
/// breaks it.
/// </para>
/// <para>
/// <b>It cannot be completed half-answered.</b> <see cref="CanAttest"/> requires a reason and an
/// authorising name, because an exclusion with no accountable name behind it is the liability
/// waiver <c>0049</c> warned against. The free text stays optional - it is the escape that stops
/// the closed list forcing the nearest wrong answer, not a second required field.
/// </para>
/// </remarks>
internal sealed partial class ExclusionAttestationViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanAttest))]
    [NotifyCanExecuteChangedFor(nameof(AttestCommand))]
    private ExclusionReasonChoice? _reason;

    [ObservableProperty]
    private string _note = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanAttest))]
    [NotifyCanExecuteChangedFor(nameof(AttestCommand))]
    private string _authorisedBy = string.Empty;

    /// <summary>Creates the dialog's state for one domain.</summary>
    /// <param name="domain">The domain being left out, as it is named on screen.</param>
    /// <param name="kind">Which kind of exclusion this is.</param>
    public ExclusionAttestationViewModel(string domain, DomainInclusion kind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        Domain = domain;
        Kind = kind;
    }

    /// <summary>The domain being left out.</summary>
    public string Domain { get; }

    /// <summary>Which kind of exclusion this is.</summary>
    public DomainInclusion Kind { get; }

    /// <summary>Every reason an operator may pick, in the order the list offers them.</summary>
    public IReadOnlyList<ExclusionReasonChoice> Reasons { get; } =
        [.. ExclusionReasons.All.Select(r => new ExclusionReasonChoice(r))];

    /// <summary>
    /// Why this is being asked, worded for the kind of exclusion it is.
    /// </summary>
    /// <remarks>
    /// <b>The two are never worded alike.</b>
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> keeps a domain an
    /// operator took out apart from one the forest names no controller for, and the dialog is the
    /// first place an operator meets the difference: one is a decision he is making, the other is a
    /// situation he is being told about and asked to account for.
    /// </remarks>
    public string Preamble => Kind == DomainInclusion.ExcludedForWantOfCandidates
        ? $"The forest declares {Domain} but names no writable controller for it, so this run "
          + "cannot read it. That is an exclusion, and it needs an accountable name against it "
          + "before the run may start."
        : $"You are leaving {Domain} out of this run. The audit will not be able to say anything "
          + "about it.";

    /// <summary>The account this will be recorded against, shown so it is not a surprise later.</summary>
    /// <remarks>
    /// Displayed rather than typed. It is captured from Windows per <c>0062</c>, and showing it
    /// makes the capture visible instead of leaving an operator to discover months later whose name
    /// the exclusion carries.
    /// </remarks>
    public string RunBy => SignedInAccount.Name();

    /// <summary>
    /// Whether enough has been stated for this to be an attestation rather than a dismissal.
    /// </summary>
    public bool CanAttest => Reason is not null && !string.IsNullOrWhiteSpace(AuthorisedBy);

    /// <summary>What the operator stated, or null where he has not stated enough.</summary>
    public ExclusionStatement? Statement => CanAttest
        ? new ExclusionStatement(
            Reason!.Reason,
            string.IsNullOrWhiteSpace(Note) ? null : Note.Trim(),
            AuthorisedBy.Trim())
        : null;

    /// <summary>Whether the operator completed the attestation.</summary>
    public bool WasAttested { get; private set; }

    /// <summary>
    /// Raised when the attestation is complete, so that whatever opened the window can close it.
    /// </summary>
    /// <remarks>
    /// An event rather than a call into the window, because a view's code-behind does nothing but
    /// <c>InitializeComponent</c> - <c>ShellMvvmGateTests</c> fails the build otherwise - and a
    /// view model that could close a window would be a view model that needs one to be tested.
    /// </remarks>
    public event EventHandler? Completed;

    /// <summary>Accepts the attestation, once it is complete.</summary>
    [RelayCommand(CanExecute = nameof(CanAttest))]
    public void Attest()
    {
        WasAttested = true;
        Completed?.Invoke(this, EventArgs.Empty);
    }
}
