using System.Windows;

namespace SecureAD.Shell.Views;

/// <summary>
/// Carries a data context to a place the visual tree does not reach.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this has to exist.</b> A <c>DataGridColumn</c> is not part of the visual tree - it
/// describes how cells are built rather than being an element - so a binding on one cannot find
/// the screen's view model by walking up to an ancestor. Held in a resource dictionary and given
/// the data context explicitly, this can, and a column binds through it.
/// </para>
/// <para>
/// It derives from <c>Freezable</c> for the one property that makes the idiom work: a
/// <c>Freezable</c> in a resource dictionary inherits the data context of the element that holds
/// the dictionary, which an ordinary object does not.
/// </para>
/// <para>
/// <b>It carries no logic.</b> The alternative was to decide column visibility in the view's
/// code-behind, which the shell's rules forbid and which would put a decision about what an
/// operator sees somewhere no test looks.
/// </para>
/// </remarks>
internal sealed class BindingProxy : Freezable
{
    /// <summary>The data context to carry.</summary>
    public static readonly DependencyProperty DataProperty =
        DependencyProperty.Register(
            nameof(Data), typeof(object), typeof(BindingProxy), new UIPropertyMetadata(null));

    /// <summary>The data context being carried.</summary>
    public object? Data
    {
        get => GetValue(DataProperty);
        set => SetValue(DataProperty, value);
    }

    /// <inheritdoc/>
    protected override Freezable CreateInstanceCore() => new BindingProxy();
}
