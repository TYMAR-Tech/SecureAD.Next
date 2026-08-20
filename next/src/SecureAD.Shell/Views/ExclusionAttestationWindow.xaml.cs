using System.Windows;

namespace SecureAD.Shell.Views;

/// <summary>
/// The exclusion attestation window.
/// </summary>
/// <remarks>
/// Code-behind does nothing but initialise its component - <c>ShellMvvmGateTests</c> fails the
/// build for anything more. The window is closed by whatever opened it, which watches the view
/// model for the attestation being completed rather than putting a click handler here.
/// </remarks>
internal partial class ExclusionAttestationWindow : Window
{
    /// <summary>Creates the window.</summary>
    public ExclusionAttestationWindow()
    {
        InitializeComponent();
    }
}
