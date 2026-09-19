using System.Globalization;
using System.Resources;

namespace SecureAD.Shell.ViewModels;

internal static class NavigationText
{
    private static readonly ResourceManager Resources = new(
        "SecureAD.Shell.Resources.NavigationPresentation", typeof(NavigationText).Assembly);

    internal static string Get(string key) =>
        Resources.GetString(key, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(key);
}
