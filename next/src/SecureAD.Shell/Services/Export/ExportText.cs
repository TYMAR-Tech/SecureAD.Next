using System.Globalization;
using System.Resources;

namespace SecureAD.Shell.Services.Export;

internal static class ExportText
{
    private static readonly ResourceManager Messages =
        new("SecureAD.Shell.Resources.ExportPresentation", typeof(ExportText).Assembly);
    internal static string Get(string key) => Messages.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
    internal static string Format(string key, params object[] values) =>
        string.Format(CultureInfo.CurrentCulture, Get(key), values);
}
