using SecureAD.Shell.Settings;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The operator's settings, kept between runs of the product.
///
/// <para>
/// The distinction under test is between an installation nobody has configured and one whose
/// settings cannot be read. Collapsing the two would silently discard a path the operator chose and
/// then ask them for it again as though they had never answered.
/// </para>
/// </summary>
public sealed class JsonShellSettingsStoreTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-settings-" + Guid.NewGuid().ToString("n"));

    private readonly string _path;

    public JsonShellSettingsStoreTests()
    {
        Directory.CreateDirectory(_directory);
        _path = Path.Combine(_directory, "shell-settings.json");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A held lock is not worth failing a run over.
        }
    }

    [Fact]
    public void AnInstallationWithNoSettingsFileIsUnconfigured()
    {
        var read = Store().Read();

        Assert.True(read.IsSuccess);
        Assert.Null(read.Value.RunLibraryPath);
    }

    [Fact]
    public void APathThatWasWrittenIsReadBack()
    {
        Store().Write(new ShellSettings(@"D:\audits"));

        Assert.Equal(@"D:\audits", Store().Read().Value.RunLibraryPath);
    }

    [Fact]
    public void WritingCreatesTheDirectoryTheSettingsFileLivesIn()
    {
        var nested = new JsonShellSettingsStore(
            Path.Combine(_directory, "a", "b", "shell-settings.json"));

        Assert.True(nested.Write(new ShellSettings(@"D:\audits")).IsSuccess);
    }

    [Fact]
    public void APathCanBeChanged()
    {
        Store().Write(new ShellSettings(@"D:\audits"));
        Store().Write(new ShellSettings(@"E:\elsewhere"));

        Assert.Equal(@"E:\elsewhere", Store().Read().Value.RunLibraryPath);
    }

    /// <summary>
    /// The case that must not be mistaken for a new installation.
    /// </summary>
    [Fact]
    public void ASettingsFileThatCannotBeParsedIsAFailure()
    {
        File.WriteAllText(_path, "{ not json");

        Assert.False(Store().Read().IsSuccess);
    }

    [Fact]
    public void ASettingsFileThatCannotBeParsedSaysSo()
    {
        File.WriteAllText(_path, "{ not json");

        Assert.False(string.IsNullOrWhiteSpace(Store().Read().Error.Description));
    }

    /// <summary>
    /// A directory that is not there today is still the operator's answer. Validating it here would
    /// make an unplugged drive look like a question they never answered.
    /// </summary>
    [Fact]
    public void APathIsStoredWithoutBeingCheckedAgainstTheDisk()
    {
        Store().Write(new ShellSettings(@"Z:\not-mounted"));

        Assert.Equal(@"Z:\not-mounted", Store().Read().Value.RunLibraryPath);
    }

    /// <summary>
    /// The scanner self-test: proves a write genuinely produces the file the assertions above read,
    /// so none of them can pass against an installation that stored nothing.
    /// </summary>
    [Fact]
    public void WritingProducesTheFileTheTestsAssumeExists()
    {
        Assert.False(File.Exists(_path));

        Store().Write(new ShellSettings(@"D:\audits"));

        Assert.True(File.Exists(_path));
    }

    /// <summary>
    /// Settings stay on the machine, per <c>0047</c>. A roamed local run library path is a
    /// confident answer that is wrong on the next machine, and the product cannot tell that apart
    /// from a library that moved - so the operator gets an error where they should get a question.
    /// </summary>
    [Fact]
    public void SettingsAreKeptInTheLocalProfileRatherThanTheRoamingOne()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        Assert.StartsWith(local, JsonShellSettingsStore.DefaultPath, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Guards the assertion above on machines where the two profile folders are configured to the
    /// same place, which would let it pass without measuring anything.
    /// </summary>
    [Fact]
    public void TheLocalAndRoamingProfileFoldersAreActuallyDifferentHere()
    {
        Assert.NotEqual(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
    }

    private JsonShellSettingsStore Store() => new(_path);
}
