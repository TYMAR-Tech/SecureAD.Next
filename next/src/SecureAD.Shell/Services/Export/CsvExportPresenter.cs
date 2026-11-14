using System.Windows;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;

namespace SecureAD.Shell.Services.Export;

internal sealed class CsvExportPresenter(Window owner, Func<IExportDataset, ExportViewModel> create)
{
    private ExportWindow? _window;

    internal void Show(IExportDataset dataset)
    {
        if (_window is not null) { _window.Activate(); return; }
        using var model = create(dataset);
        var window = new ExportWindow { Owner = owner, DataContext = model };
        _window = window;
        model.CloseRequested += Close;
        window.Closing += (_, args) =>
        {
            if (!model.IsExporting) return;
            args.Cancel = true;
            model.CancelCommand.Execute(null);
        };
        window.Loaded += (_, _) => model.OpenCommand.Execute(null);
        try { window.ShowDialog(); }
        finally
        {
            model.CloseRequested -= Close;
            _window = null;
        }
        void Close() => window.Close();
    }
}
