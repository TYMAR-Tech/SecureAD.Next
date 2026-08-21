using System.Windows;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;

namespace SecureAD.Shell;

/// <summary>
/// The application, and the one place allowed to assemble it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the composition root, and it is the only code-behind permitted to hold any.</b>
/// Every other <c>.xaml.cs</c> file under <c>Views/</c> contains nothing but
/// <c>InitializeComponent</c>, enforced by <c>CodeBehindGateTests</c>. The rule exists because the
/// predecessor accumulated logic in views where it could not be tested and could not be found.
/// </para>
/// <para>
/// Concrete services are constructed here and handed to view models as interfaces. A view model
/// that could reach the file system or a directory server directly would be a view model that
/// cannot be tested without one.
/// </para>
/// </remarks>
internal partial class App : Application
{
    /// <summary>Assembles the product and shows its window.</summary>
    /// <param name="e">The startup arguments.</param>
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var location = new RunLibraryLocation(
            new JsonShellSettingsStore(JsonShellSettingsStore.DefaultPath));

        location.Load();

        // One launcher, shared by nothing else: the audit surface is the only place that plans,
        // checks or starts a run. Home chooses the library and starts an audit on it.
        //
        // The audit is handed to the service as a FACTORY rather than as an instance, so each
        // opening plans a fresh run and leaving discards it - 0057, kept by 0071 now that there is
        // no window closing to enforce it. A single shared instance would leave a half-planned run
        // to be found later in a state nobody remembers choosing.
        //
        // Both the service and the shell are referred to from inside lambdas that construct the
        // other. Neither lambda runs until an audit is started, by which time both variables are
        // assigned.
        NewAuditDialog newAudit = null!;
        ShellViewModel shell = null!;

        newAudit = new NewAuditDialog(
            () => new NewAuditViewModel(location, new CaptureLauncher(), newAudit),
            audit => shell.Begin(audit),
            () => shell.Leave());

        // One library object, shown by both sections. Two would let them disagree.
        var library = new RunLibraryViewModel(
            location,
            new RunCatalog(),
            new Confirmation(),
            new RunOpener(bundle =>
            {
                // Opening a run is two acts: the Assets screen reads it, and the shell moves to
                // that screen. Doing only the first would leave the operator on Home wondering
                // whether his click had done anything.
                shell.Assets.Show(bundle, shell.HasAudit);
                shell.Show(ShellSection.Assets);
            }));

        shell = new ShellViewModel(
            new HomeViewModel(location, new FolderPicker(), newAudit, library),
            library,
            new AssetsViewModel(new BundleAssetSource()));

        // Home is the section already showing, so nothing navigates to it and nothing would
        // otherwise ask the library to read itself before the first screen is painted.
        library.Refresh();

        new ShellWindow { DataContext = shell }.Show();
    }
}
