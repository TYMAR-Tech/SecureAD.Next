using System.Windows.Controls;

namespace SecureAD.Shell.Views;

/// <summary>
/// Every check this product makes, and what each one did to the run being read.
/// </summary>
/// <remarks>
/// <b>It exists because an empty findings grid has four meanings.</b> A rule that judged everything
/// it was about and found nothing, one that could not read what it declared, one that failed, and
/// one that was never scheduled all report nothing - and only the first says anything about the
/// forest. This screen says which, in words, for every rule.
/// </remarks>
internal partial class RulesView : UserControl
{
    /// <summary>Creates the view.</summary>
    public RulesView()
    {
        InitializeComponent();
    }
}
