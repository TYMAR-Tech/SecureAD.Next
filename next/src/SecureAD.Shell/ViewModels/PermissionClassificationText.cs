using System.Globalization;
using System.Resources;

namespace SecureAD.Shell.ViewModels;

internal static class PermissionClassificationText
{
    private static readonly ResourceManager Messages = new("SecureAD.Shell.Resources.PermissionClassificationPresentation", typeof(PermissionClassificationText).Assembly);
    internal static string Get(string key) => Messages.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
}
