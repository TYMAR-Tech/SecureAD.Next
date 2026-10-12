using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Kernel;

namespace SecureAD.Shell.Settings;

internal enum ThemeVariant
{
    Dark,
    Light,
}

internal interface IThemeApplier
{
    void Apply(ThemeVariant theme);
}

internal sealed class WpfThemeApplier(ResourceDictionary resources) : IThemeApplier
{
    private static readonly string[] PaletteNames = ["Palette.Dark.xaml", "Palette.Light.xaml"];
    private const string BrushesName = "Brushes.xaml";

    public void Apply(ThemeVariant theme)
    {
        var dictionaries = resources.MergedDictionaries;
        var paletteIndex = DictionaryIndex(dictionaries, PaletteNames, "theme palette");
        var brushesIndex = DictionaryIndex(dictionaries, [BrushesName], "semantic brushes");

        dictionaries[paletteIndex] = new ResourceDictionary
        {
            Source = new Uri($"/SecureAD;component/Themes/Palette.{theme}.xaml", UriKind.Relative),
        };
        dictionaries[brushesIndex] = new ResourceDictionary
        {
            Source = new Uri($"/SecureAD;component/Themes/{BrushesName}", UriKind.Relative),
        };
    }

    private static int DictionaryIndex(
        Collection<ResourceDictionary> dictionaries,
        IReadOnlyCollection<string> names,
        string description)
    {
        var matches = dictionaries.Select((dictionary, position) => (dictionary, position))
            .Where(item => item.dictionary.Source is { } source
                && names.Any(name => source.OriginalString.EndsWith(name, StringComparison.OrdinalIgnoreCase)))
            .Select(item => item.position)
            .ToArray();
        return matches.Length switch
        {
            1 => matches[0],
            0 => throw new InvalidOperationException($"The application {description} dictionary is not registered."),
            _ => throw new InvalidOperationException($"The application has more than one {description} dictionary."),
        };
    }
}

internal sealed partial class ApplicationTheme : ObservableObject
{
    private readonly IShellSettingsStore _store;
    private readonly IThemeApplier _applier;

    [ObservableProperty] private ThemeVariant _current = ThemeVariant.Dark;
    [ObservableProperty] private string? _problem;

    public ApplicationTheme(IShellSettingsStore store, IThemeApplier applier)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(applier);
        _store = store;
        _applier = applier;
    }

    public void Load()
    {
        var read = _store.Read();
        if (!read.IsSuccess)
        {
            Problem = read.Error.Description;
            _applier.Apply(Current);
            return;
        }

        Current = Parse(read.Value.Appearance);
        Problem = null;
        _applier.Apply(Current);
    }

    public Result<bool> Choose(ThemeVariant theme)
    {
        if (!Enum.IsDefined(theme))
            throw new ArgumentOutOfRangeException(nameof(theme));

        var current = _store.Read();
        if (!current.IsSuccess)
        {
            Problem = current.Error.Description;
            return Result<bool>.Failure(current.Error);
        }

        var written = _store.Write(current.Value with { Appearance = theme.ToString() });
        if (!written.IsSuccess)
        {
            Problem = written.Error.Description;
            return written;
        }

        Current = theme;
        Problem = null;
        _applier.Apply(theme);
        return written;
    }

    internal static ThemeVariant Parse(string? value) => value is null
        ? ThemeVariant.Dark
        : Enum.TryParse<ThemeVariant>(value, ignoreCase: true, out var theme) && Enum.IsDefined(theme)
            ? theme
            : throw new InvalidDataException($"The appearance setting \"{value}\" is not Dark or Light.");
}
