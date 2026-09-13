using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Shell.Settings;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// What this installation has been told.
/// </summary>
/// <remarks>
/// <para>
/// <b>It carries one setting, and the other one is not here.</b> Where runs are kept is chosen on
/// Home, which is where an operator needs it - at the moment he has nowhere to put a run. Repeating
/// the chooser here would be a second control over one value, and
/// <see cref="RunLibraryLocation"/> exists precisely so there is one.
/// </para>
/// <para>
/// <b>Every sentence on this screen was approved by the owner on 2026-09-13</b>, together with the
/// command line's help text and the sentence the new-audit review shows, so that the three cannot
/// drift into disagreeing about what the number means. They are held here rather than in the view
/// because a string in XAML is a string no test can read.
/// </para>
/// <para>
/// <b>The wording must never read as a politeness dial.</b> Lowering this makes a capture slower and
/// never safer, and anything presenting it to an operator as consideration for their domain
/// controllers has misread it - <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c>, as
/// amended, and <c>0047</c> for why it is a setting at all.
/// </para>
/// </remarks>
internal sealed partial class SettingsViewModel : ObservableObject
{
    [ObservableProperty]
    private string _typed = string.Empty;

    [ObservableProperty]
    private string? _problem;

    /// <summary>Creates the settings screen over the values it can change.</summary>
    /// <param name="concurrency">How many domains this machine reads at the same time.</param>
    public SettingsViewModel(DomainConcurrency concurrency)
    {
        ArgumentNullException.ThrowIfNull(concurrency);

        Concurrency = concurrency;
        Typed = concurrency.Effective.ToString(System.Globalization.CultureInfo.CurrentCulture);
    }

    /// <summary>How many domains this machine reads at the same time.</summary>
    public DomainConcurrency Concurrency { get; }

    /// <summary>The heading over the one setting this screen carries.</summary>
    /// <remarks>
    /// <b>An instance property, and that is not incidental.</b> WPF resolves a binding path against
    /// an instance; a static member binds to nothing and renders as empty text. A screen whose
    /// explanation silently disappears is exactly the shape of failure this product refuses, and it
    /// would look like a design choice rather than a defect.
    /// </remarks>
    public string ConcurrencyHeading => "Domains read at the same time";

    /// <summary>
    /// What the setting is, and what the product does when nobody has chosen.
    /// </summary>
    /// <remarks>
    /// <b>"Nine" is written as a word rather than composed from the constant</b>, which makes it a
    /// claim that could go stale in silence. It is bound to
    /// <see cref="Audit.Connect.DirectoryConnectionSettings.DefaultDomainsAtOnce"/> by a test that
    /// fails if the two part company, so the sentence the owner approved is the sentence shown and
    /// the number behind it cannot move without someone being told.
    /// </remarks>
    public string WhatItIs =>
        "SecureAD reads every domain of the forest. This is how many of them it reads at once - "
        + "nine by default, which is every domain of the forest this was built for.";

    /// <summary>Whose machine the number governs, which is the whole reason it may be set.</summary>
    public string WhoseMachineItGoverns =>
        "This is a limit on this computer, not on your domain controllers. Each domain being read "
        + "writes its own database here, so what it governs is this machine's disk. Every "
        + "controller is read in the same way, at the same rate, whatever this is set to.";

    /// <summary>What lowering it buys, which is nothing, and what it costs.</summary>
    public string WhatLoweringItCosts =>
        "Lowering it makes a capture take longer. It does not make it gentler on your directory. "
        + "Lower it only if this computer's disk is slow, shared, or on a network.";

    /// <summary>Whether there is something to tell the operator about what he just did.</summary>
    public bool HasProblem => !string.IsNullOrWhiteSpace(Problem);

    /// <summary>
    /// Stores what the operator typed, or says why it was not stored.
    /// </summary>
    /// <remarks>
    /// <b>Parsed here rather than prevented at the keyboard.</b> A control that silently refuses
    /// keystrokes leaves an operator holding a number he did not type and no account of why, and it
    /// cannot distinguish "not a number" from "below one" - which are different mistakes deserving
    /// different sentences. Nothing is stored until it is understood.
    /// </remarks>
    [RelayCommand]
    public void Save()
    {
        if (!int.TryParse(
                Typed,
                System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.CurrentCulture,
                out var wanted))
        {
            Problem =
                $"\"{Typed}\" is not a number of domains. Type a whole number of "
                + $"{DomainConcurrency.Fewest} or more.";

            return;
        }

        var stored = Concurrency.Choose(wanted);

        // Choose has already worded its own refusal, including the one for zero, and it is the
        // component that knows why. Restating it here would be a second copy of a sentence free to
        // disagree with the first.
        Problem = stored.IsSuccess ? null : Concurrency.Problem;

        if (stored.IsSuccess)
        {
            Typed = wanted.ToString(System.Globalization.CultureInfo.CurrentCulture);
        }
    }

    partial void OnProblemChanged(string? value) => OnPropertyChanged(nameof(HasProblem));
}
