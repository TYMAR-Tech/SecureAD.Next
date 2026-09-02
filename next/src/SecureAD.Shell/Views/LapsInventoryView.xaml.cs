using System.Windows.Controls;

namespace SecureAD.Shell.Views;

/// <summary>
/// Which machines in the selected container are managing their local administrator password.
/// </summary>
/// <remarks>
/// <b>It reads sealed evidence rather than the findings.</b> The question includes the healthy
/// machines, and a findings store holds only what a rule reported.
/// </remarks>
internal partial class LapsInventoryView : UserControl
{
    /// <summary>Creates the view.</summary>
    public LapsInventoryView()
    {
        InitializeComponent();
    }
}
