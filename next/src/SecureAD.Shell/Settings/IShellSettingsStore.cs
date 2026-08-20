using SecureAD.Kernel;

namespace SecureAD.Shell.Settings;

/// <summary>
/// Where the operator's choices are kept between runs of the product.
/// </summary>
/// <remarks>
/// This is a seam, and it exists so that a view model can be given settings without being given a
/// disk. A view model that read a file directly could not be tested without one, and the logic that
/// decides what to show when nothing is configured would only be reachable through the file system.
/// </remarks>
internal interface IShellSettingsStore
{
    /// <summary>
    /// Reads the stored settings, or <see cref="ShellSettings.Unconfigured"/> where nothing has
    /// been stored yet.
    /// </summary>
    /// <returns>
    /// The settings, or a failure where something was stored and could not be understood. Those two
    /// are deliberately different: an absent file is a new installation, an unreadable one is a
    /// problem the operator should be told about rather than have silently reset.
    /// </returns>
    Result<ShellSettings> Read();

    /// <summary>Stores <paramref name="settings"/>, replacing anything already there.</summary>
    /// <param name="settings">The settings to keep.</param>
    Result<bool> Write(ShellSettings settings);
}
