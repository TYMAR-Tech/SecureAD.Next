using System.Globalization;
using System.Resources;

namespace SecureAD.Shell.ViewModels;

internal static class LapsInventoryText
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.LapsInventoryPresentation", typeof(LapsInventoryText).Assembly);

    internal static string Get(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
}
