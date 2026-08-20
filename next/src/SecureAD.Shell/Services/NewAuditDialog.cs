using System.Windows;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;

namespace SecureAD.Shell.Services;

/// <summary>
/// Puts a freshly planned audit on the shell's audit surface, and takes it off again.
/// </summary>
/// <remarks>
/// <para>
/// The one place in the product that starts an audit. It takes a factory rather than a view model,
/// so each opening plans a fresh run and leaving discards it -
/// <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c>.
/// </para>
/// <para>
/// <b>No window is opened.</b> The audit is a surface inside the shell -
/// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c> - and the shell
/// makes its rail inert while the audit is being planned. What used to be modality by window is now
/// modality by state.
/// </para>
/// <para>
/// <b>The exclusion attestation is still a real dialog</b>, and is the only one left on this path.
/// It asks one short question with an explicit yes-or-no outcome, which is what a modal is for.
/// </para>
/// </remarks>
/// <param name="plan">Builds the state behind a single planned run.</param>
/// <param name="show">Puts that state on the shell's audit surface.</param>
/// <param name="leave">Takes it off again, discarding it.</param>
internal sealed class NewAuditDialog(
    Func<NewAuditViewModel> plan,
    Action<NewAuditViewModel> show,
    Action leave) : INewAuditDialog
{
    private readonly Func<NewAuditViewModel> _plan =
        plan ?? throw new ArgumentNullException(nameof(plan));

    private readonly Action<NewAuditViewModel> _show =
        show ?? throw new ArgumentNullException(nameof(show));

    private readonly Action _leave =
        leave ?? throw new ArgumentNullException(nameof(leave));

    /// <inheritdoc />
    public void Show()
    {
        var state = _plan();

        _show(state);

        // The pass begins once the surface is showing, not before: an operator must be able to see
        // the indicator and reach the Cancel for the whole of the time it runs.
        state.OpenCommand.Execute(null);
    }

    /// <inheritdoc />
    public void Leave() => _leave();

    /// <inheritdoc />
    public ExclusionStatement? AskForAttestation(string domain, DomainInclusion kind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        var state = new ExclusionAttestationViewModel(domain, kind);

        var window = new ExclusionAttestationWindow
        {
            DataContext = state,
            Owner = Owner(),
        };

        // Closed from here rather than from the window's own code-behind, which does nothing but
        // InitializeComponent. Cancel, the close box and Escape all leave WasAttested false, so
        // every way out of this window that is not the one button means "he did not state one".
        state.Completed += (_, _) => window.DialogResult = true;

        window.ShowDialog();

        return state.WasAttested ? state.Statement : null;
    }

    /// <summary>
    /// The window a dialog opened from here belongs to.
    /// </summary>
    /// <remarks>
    /// The shell, because since <c>0071</c> there is no other. A modal with no owner can be sent
    /// behind the window that opened it, which leaves an operator looking at a window that will not
    /// respond and no visible reason why.
    /// </remarks>
    private static Window? Owner() => Application.Current?.MainWindow;
}
