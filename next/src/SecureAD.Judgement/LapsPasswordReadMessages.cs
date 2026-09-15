using System.Globalization;
using System.Resources;

namespace SecureAD.Judgement;

internal static class LapsPasswordReadMessages
{
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.LapsPasswordRead", typeof(LapsPasswordReadMessages).Assembly);
    internal static string Get(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
}
