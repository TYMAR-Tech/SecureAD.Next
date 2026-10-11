using System.ComponentModel;
using System.Windows;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;

namespace SecureAD.Shell.Services;

internal sealed class ObjectDetailPresenter : IDisposable
{
    private readonly AssetsViewModel _model;
    private readonly Window _owner;
    private ObjectDetailWindow? _window;
    private bool _closing;

    internal ObjectDetailPresenter(AssetsViewModel model, Window owner)
    {
        _model = model;
        _owner = owner;
        _model.PropertyChanged += Changed;
        _model.LocateObjectRequested += Locate;
        _owner.Closed += OwnerClosed;
    }

    private void Changed(object? sender, PropertyChangedEventArgs change)
    {
        if (change.PropertyName != nameof(AssetsViewModel.HasObjectPresentation)) return;
        if (!_model.HasObjectPresentation)
        {
            if (_window is not null)
            {
                _closing = true;
                _window.Close();
                _closing = false;
                _window = null;
            }
            return;
        }
        if (_window is null)
        {
            _window = new ObjectDetailWindow { Owner = _owner, DataContext = _model };
            _window.Closed += DetailClosed;
            _window.Show();
        }
        else _window.Activate();
    }

    private void DetailClosed(object? sender, EventArgs args)
    {
        _window = null;
        if (!_closing) _model.DismissObjectDetails();
    }

    private void Locate(object? sender, EventArgs args)
    {
        if (_owner.DataContext is ShellViewModel shell) shell.Show(ShellSection.Assets);
        if (_owner.WindowState == WindowState.Minimized) _owner.WindowState = WindowState.Normal;
        _owner.Activate();
    }

    private void OwnerClosed(object? sender, EventArgs args) => Dispose();

    public void Dispose()
    {
        _model.PropertyChanged -= Changed;
        _model.LocateObjectRequested -= Locate;
        _owner.Closed -= OwnerClosed;
        _closing = true;
        _model.DismissObjectDetails();
        _window?.Close();
        _window = null;
    }
}
