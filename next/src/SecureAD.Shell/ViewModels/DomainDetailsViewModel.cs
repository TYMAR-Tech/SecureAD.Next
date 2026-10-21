using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The state behind the domain details panel.
/// </summary>
/// <remarks>
/// <b>The same rows the table shows, rendered in full.</b> Deliberately not a parallel set of
/// records: those rows already carry every sentence and every state the trimmed columns were
/// rendering, and a second description of one domain is two accounts that can disagree. What
/// changes here is only how much of each row is drawn.
/// </remarks>
internal sealed partial class DomainDetailsViewModel : ObservableObject
{
    private readonly Action _close;

    /// <summary>Creates the panel's state over the rows the table carries.</summary>
    /// <param name="domains">The rows, as the audit surface holds them.</param>
    /// <param name="close">What to do when the operator has finished reading.</param>
    public DomainDetailsViewModel(IReadOnlyList<DomainRowViewModel> domains,
        IReadOnlyList<ExclusionView> exclusions, Action close)
    {
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentNullException.ThrowIfNull(exclusions);
        ArgumentNullException.ThrowIfNull(close);

        Domains = domains;
        Exclusions = exclusions;
        var names = domains.Select(domain => domain.Domain).Concat(exclusions.Select(domain => domain.Domain))
            .Distinct(StringComparer.Ordinal).Take(2).ToArray();
        Heading = names.Length == 1 ? names[0] : "Domain details";
        _close = close;
    }

    /// <summary>Every domain, with everything it answered.</summary>
    public IReadOnlyList<DomainRowViewModel> Domains { get; }

    public IReadOnlyList<ExclusionView> Exclusions { get; }
    public string Heading { get; }

    /// <summary>Puts the panel away.</summary>
    /// <remarks>
    /// A panel rather than a window means there is no close box and no Escape doing it for free,
    /// so the one control that does it is stated here.
    /// </remarks>
    [RelayCommand]
    public void Close() => _close();
}
