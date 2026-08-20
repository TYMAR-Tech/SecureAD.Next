using System.IO;
using Microsoft.Win32;

namespace SecureAD.Shell.Services;

/// <summary>
/// The folder picker, using the Windows folder dialog WPF ships with in .NET 8.
/// </summary>
/// <remarks>
/// <c>OpenFolderDialog</c> is in-box, which matters here: <c>0046</c> records that this product
/// takes no third-party dependencies, and folder selection is one of the places a WPF application
/// is usually tempted to reach for one.
/// </remarks>
internal sealed class FolderPicker : IFolderPicker
{
    /// <inheritdoc/>
    public string? Pick(string title, string? startingAt)
    {
        var dialog = new OpenFolderDialog
        {
            Title = title,
            Multiselect = false,
        };

        if (!string.IsNullOrWhiteSpace(startingAt) && Directory.Exists(startingAt))
            dialog.InitialDirectory = startingAt;

        return dialog.ShowDialog() == true ? dialog.FolderName : null;
    }
}
