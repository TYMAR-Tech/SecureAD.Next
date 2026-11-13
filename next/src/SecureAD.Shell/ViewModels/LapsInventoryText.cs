using System.Globalization;
using System.Resources;
using SecureAD.Judgement;
using SecureAD.Evidence.Findings;

namespace SecureAD.Shell.ViewModels;

internal static class LapsInventoryText
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.LapsInventoryPresentation", typeof(LapsInventoryText).Assembly);

    internal static string Get(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);

    internal static string Label(LapsValuePresence values) => Get(values switch
    {
        LapsValuePresence.None => "ValuesNone",
        LapsValuePresence.WindowsOnly => "ValuesWindows",
        LapsValuePresence.LegacyOnly => "ValuesLegacy",
        LapsValuePresence.Both => "ValuesBoth",
        LapsValuePresence.WindowsOnLegacyOnly => "ValuesPlatform",
        _ => throw new ArgumentOutOfRangeException(nameof(values)),
    });

    internal static string ScopeNotes(LapsComputer computer) =>
        computer.AccountState is LapsAttributes.AccountState.Unknown
            ? Get(computer.DomainController.IsDomainController ? "ControllerAccountUnknown" : "AccountUnknown")
        : computer.DomainController.IsDomainController && computer.IsDisabled ? "Domain controller, disabled"
        : computer.DomainController.IsDomainController ? "Domain controller"
        : computer.IsDisabled ? Get("ScopeDisabled")
        : string.Empty;
}
