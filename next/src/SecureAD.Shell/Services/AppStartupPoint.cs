namespace SecureAD.Shell.Services;

internal enum AppStartupPoint
{
    Entered,
    SettingsLoaded,
    ModelsComposed,
    LibraryRefreshStarting,
    LibraryRefreshCompleted,
    WindowShown,
}
