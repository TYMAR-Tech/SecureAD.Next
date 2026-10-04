using System.Globalization;
using System.Resources;
using SecureAD.Judgement;

namespace SecureAD.Shell.ViewModels;

internal static class SavedPathText
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.SavedPathPresentation", typeof(SavedPathText).Assembly);

    internal static string Summary(Tier0FindingSummary? summary) => summary is null
        ? Get("NotRequested")
        : summary.Availability == PathRiskAvailability.Recorded
            ? Get("Summary", summary.AccountsWithFindings, summary.UnresolvedAccessChecks)
            : Get(summary.Availability.ToString());

    internal static string Get(string key, params object?[] arguments)
    {
        var text = Resources.GetString(key, CultureInfo.CurrentUICulture)
            ?? throw new MissingManifestResourceException(key);
        return arguments.Length == 0 ? text : string.Format(CultureInfo.CurrentCulture, text, arguments);
    }
}
