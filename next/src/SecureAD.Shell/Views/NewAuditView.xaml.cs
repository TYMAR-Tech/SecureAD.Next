using System.Windows.Controls;

namespace SecureAD.Shell.Views;

/// <summary>
/// The audit surface: what a run will read, and then the run itself.
/// </summary>
/// <remarks>
/// Code-behind does nothing but initialise its component - <c>ShellMvvmGateTests</c> fails the
/// build for anything more. The predecessor accumulated logic where it could not be tested and
/// could not be found.
/// </remarks>
internal partial class NewAuditView : UserControl
{
    /// <summary>Creates the surface.</summary>
    public NewAuditView()
    {
        InitializeComponent();
    }
}
