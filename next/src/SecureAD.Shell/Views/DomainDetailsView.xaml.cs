using System.Windows.Controls;

namespace SecureAD.Shell.Views;

/// <summary>
/// The domain details panel.
/// </summary>
/// <remarks>
/// Code-behind does nothing but initialise its component - <c>ShellMvvmGateTests</c> fails the
/// build for anything more.
/// </remarks>
internal partial class DomainDetailsView : UserControl
{
    /// <summary>Creates the panel.</summary>
    public DomainDetailsView()
    {
        InitializeComponent();
    }
}
