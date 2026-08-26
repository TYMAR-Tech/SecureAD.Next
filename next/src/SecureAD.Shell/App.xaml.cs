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
        RunLibraryViewModel library = null!;

        // The wizard opens the run it has just captured, which the library has never listed - it
        // was written after the last read. So this opener adopts the run (read again, select that
        // path) before navigating, where the library's own opener below must not: refreshing there
        // would discard the selection the operator just made.
        newAudit = new NewAuditDialog(
            () => new NewAuditViewModel(
                location,
                new CaptureLauncher(),
                newAudit,
                new RunOpener(path =>
                {
                    library.Adopt(path);
                    shell.Show(ShellSection.Assets);
                }),
                new JudgingLauncher()),
            audit => shell.Begin(audit),
            () => shell.Leave());

        // One library object. Home is the only screen that shows it.
        library = new RunLibraryViewModel(
            location,
            new RunCatalog(),
            new Confirmation(),
            // Moving to Assets already opens whichever run is selected - ShellViewModel does it on
            // arrival, and it knows whether a capture is running, which this does not. So Open
            // navigates and lets that one path do the reading, rather than being a second door
            // onto it that would have to be kept in step.
            new RunOpener(_ => shell.Show(ShellSection.Assets)));

        shell = new ShellViewModel(
            new HomeViewModel(location, new FolderPicker(), newAudit, library),
            new AssetsViewModel(new BundleAssetSource()));

        // Home is the section already showing, so nothing navigates to it and nothing would
        // otherwise ask the library to read itself before the first screen is painted.
        library.Refresh();

        new ShellWindow { DataContext = shell }.Show();
    }
}
