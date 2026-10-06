using System.Globalization;
using System.Resources;

namespace SecureAD.Shell.ViewModels;

internal static class ObjectNavigationText
{
    private static readonly ResourceManager Messages = new("SecureAD.Shell.Resources.ObjectNavigationPresentation", typeof(ObjectNavigationText).Assembly);
    internal static string Get(string key) => Messages.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
    internal static string Format(string key, params object[] values) => string.Format(CultureInfo.CurrentCulture, Get(key), values);
    public static string SearchLabel => Get(nameof(SearchLabel));
    public static string SearchHint => Get(nameof(SearchHint));
    public static string SearchAction => Get(nameof(SearchAction));
    public static string ClearSearch => Get(nameof(ClearSearch));
    public static string Domain => Get(nameof(Domain));
    public static string Location => Get(nameof(Location));
    public static string Coverage => Get(nameof(Coverage));
    public static string CaptureIncomplete => Get(nameof(CaptureIncomplete));
    public static string RunGaps => Get(nameof(RunGaps));
    public static string ScopeNotes => Get(nameof(ScopeNotes));
    public static string CoverageBoundary => Get(nameof(CoverageBoundary));
    public static string NoTreeGaps => Get(nameof(NoTreeGaps));
}
