using System.Windows;

namespace SecureAD.Shell.Services;

/// <summary>
/// Asks the operator to confirm, in a window.
/// </summary>
/// <remarks>
/// <para>
/// <b>The confirming button is not the default.</b> <c>MessageBoxResult.No</c> is what Enter and
/// Escape both land on, so a confirmation arriving under a keystroke the operator had already
/// started is declined rather than accepted. The act this exists to guard cannot be undone.
/// </para>
/// <para>
/// <c>confirmLabel</c> is put in the question rather than on the button, because a Windows message
/// box will not relabel Yes and No. The label is still worth carrying on
/// <see cref="IConfirmation"/>: it is what a purpose-built dialog would use, and dropping it from
/// the seam would mean every caller phrasing the act twice and the two drifting apart.
/// </para>
/// </remarks>
internal sealed class Confirmation : IConfirmation
{
    /// <inheritdoc/>
    public bool Confirm(string title, string question, string confirmLabel)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(question);
        ArgumentException.ThrowIfNullOrWhiteSpace(confirmLabel);

        var answer = MessageBox.Show(
            $"{question}{Environment.NewLine}{Environment.NewLine}Choose Yes to {confirmLabel}.",
            title,
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        return answer == MessageBoxResult.Yes;
    }
}
