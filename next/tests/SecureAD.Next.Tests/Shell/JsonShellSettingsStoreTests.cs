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
        Store().Write(new ShellSettings(@"D:\audits", DomainsAtOnce: null));

        Assert.Equal(@"D:\audits", Store().Read().Value.RunLibraryPath);
    }

    [Fact]
    public void WritingCreatesTheDirectoryTheSettingsFileLivesIn()
    {
        var nested = new JsonShellSettingsStore(
            Path.Combine(_directory, "a", "b", "shell-settings.json"));

        Assert.True(nested.Write(new ShellSettings(@"D:\audits", DomainsAtOnce: null)).IsSuccess);
    }

    [Fact]
    public void APathCanBeChanged()
    {
        Store().Write(new ShellSettings(@"D:\audits", DomainsAtOnce: null));
        Store().Write(new ShellSettings(@"E:\elsewhere", DomainsAtOnce: null));

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
        Store().Write(new ShellSettings(@"Z:\not-mounted", DomainsAtOnce: null));

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

        Store().Write(new ShellSettings(@"D:\audits", DomainsAtOnce: null));

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

    // -------------------------------------------------------------------------------------------
    // The concurrency ceiling, the second setting this product has ever had - 0047, amended
    // 2026-09-13.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A settings file written before this setting existed still reads, and does not mean zero.
    /// </summary>
    /// <remarks>
    /// <b>This is the file already sitting in every operator's profile</b>, written by a build that
    /// had never heard of a concurrency ceiling. It must read as "not chosen" rather than as a
    /// ceiling of zero, which would be a capture that waits for ever while looking exactly like one
    /// that is working. The JSON is written literally rather than produced by the current
    /// serialiser, because a serialiser that has learned the new property cannot reproduce a file
    /// written by one that had not.
    /// </remarks>
    [Fact]
    public void AFileWrittenBeforeTheCeilingExistedReadsAsNotChosen()
    {
        File.WriteAllText(_path, """{ "RunLibraryPath": "D:\\audits" }""");

        var read = Store().Read();

        Assert.True(read.IsSuccess);
        Assert.Equal(@"D:\audits", read.Value.RunLibraryPath);
        Assert.Null(read.Value.DomainsAtOnce);
    }

    /// <summary>
    /// A ceiling that was written is read back.
    /// </summary>
    [Fact]
    public void ACeilingThatWasWrittenIsReadBack()
    {
        Store().Write(new ShellSettings(@"D:\audits", 4));

        var read = Store().Read();

        Assert.True(read.IsSuccess);
        Assert.Equal(4, read.Value.DomainsAtOnce);
    }

    /// <summary>
    /// A settings file asking for no domains at once is refused.
    /// </summary>
    /// <remarks>
    /// <b>Nothing in the product writes this</b>, so a file carrying it was edited by hand. It is
    /// refused rather than repaired: substituting the default would run a capture the operator did
    /// not ask for while his file says otherwise, and this store already refuses to quietly correct
    /// a file on his behalf.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(-3)]
    public void ASettingsFileAskingForNoDomainsAtOnceIsRefused(int ceiling)
    {
        File.WriteAllText(
            _path,
            $$"""{ "RunLibraryPath": "D:\\audits", "DomainsAtOnce": {{ceiling}} }""");

        var read = Store().Read();

        Assert.False(read.IsSuccess);
        Assert.Contains("1 or more", read.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// One domain at a time is a legitimate stored answer and is not refused with zero.
    /// </summary>
    /// <remarks>
    /// The negative control for the refusal above. Without it, a guard that rejected every stored
    /// ceiling would pass both tests that matter and lock every operator out of the one setting
    /// this screen offers.
    /// </remarks>
    [Fact]
    public void ASettingsFileAskingForOneDomainAtATimeIsAccepted()
    {
        File.WriteAllText(
            _path,
            """{ "RunLibraryPath": "D:\\audits", "DomainsAtOnce": 1 }""");

        var read = Store().Read();

        Assert.True(read.IsSuccess);
        Assert.Equal(1, read.Value.DomainsAtOnce);
    }
}
