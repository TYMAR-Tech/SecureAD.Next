using System.ComponentModel;
using System.Windows;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;

namespace SecureAD.Shell.Services;

internal sealed class FindingDetailPresenter : IDisposable
{
    private readonly AssetsViewModel _model;
    private readonly Window _owner;
    private FindingDetailWindow? _window;
    private bool _closing;

    internal FindingDetailPresenter(AssetsViewModel model, Window owner)
    {
        (_model, _owner) = (model, owner);
        _model.PropertyChanged += Changed;
        _owner.Closed += OwnerClosed;
    }

    private void Changed(object? sender, PropertyChangedEventArgs change)
    {
        if (change.PropertyName != nameof(AssetsViewModel.HasFindingPresentation)) return;
        if (!_model.HasFindingPresentation)
        {
            _closing = true;
            _window?.Close();
            _window = null;
            _closing = false;
        }
        else if (_window is null)
        {
            _window = new FindingDetailWindow { Owner = _owner, DataContext = _model };
            _window.Closed += DetailClosed;
            _window.Show();
        }
        else _window.Activate();
    }

    private void DetailClosed(object? sender, EventArgs args)
    {
        _window = null;
        if (!_closing) _model.CloseFindingDetails();
    }

    private void OwnerClosed(object? sender, EventArgs args) => Dispose();

    public void Dispose()
    {
        _model.PropertyChanged -= Changed;
        _owner.Closed -= OwnerClosed;
        _closing = true;
        _model.CloseFindingDetails();
        _window?.Close();
        _window = null;
    }
}
