using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;

namespace SecureAD.Shell.Controls;

internal sealed class CopyValueButton : Button
{
    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(
        nameof(Text), typeof(string), typeof(CopyValueButton), new PropertyMetadata(""));

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    protected override void OnClick()
    {
        base.OnClick();
        try { Clipboard.SetText(Text); }
        catch (ExternalException error)
        {
            MessageBox.Show(Window.GetWindow(this), "The clipboard could not be updated. The complete value remains selectable.\n\n" + error.Message,
                "Clipboard unavailable", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
