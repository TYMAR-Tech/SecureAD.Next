using System.IO;
using Microsoft.Win32;

namespace SecureAD.Shell.Services.Export;

internal sealed class ExportDestinationPicker : IExportDestinationPicker
{
    public ExportDestination? Pick(string suggestedName)
    {
        var dialog = new SaveFileDialog
        {
            Title = ExportText.Get("SaveTitle"),
            Filter = "CSV files (*.csv)|*.csv",
            DefaultExt = ".csv",
            AddExtension = true,
            OverwritePrompt = true,
            CheckPathExists = true,
            FileName = suggestedName,
        };
        return dialog.ShowDialog() == true ? new(dialog.FileName, File.Exists(dialog.FileName)) : null;
    }
}
