using SecureAD.Audit.Connect;
using SecureAD.Shell.Settings;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// How many domains this machine reads at the same time, as a stored setting.
/// </summary>
/// <remarks>
/// <para>
/// <b>The second setting this product has ever had.</b>
/// <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c> said the run library path was
/// the only one and required that a second be added by overturning that sentence; the owner
/// overturned it on 2026-09-13.
/// </para>
/// <para>
/// <b>What these hold is the difference between "not chosen" and "chosen as zero".</b> Collapsing
/// the two is not a tidiness failure - it is a capture that waits for ever while looking exactly
/// like one that is working, per
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c>.
/// </para>
/// </remarks>
public sealed class DomainConcurrencyTests
{
    /// <summary>
    /// An installation nobody has configured reads domains at the capture's own default.
    /// </summary>
    [Fact]
    public void AnInstallationNobodyHasConfiguredUsesTheDefault()
    {
        var ceiling = new DomainConcurrency(new FakeSettingsStore());

        ceiling.Load();

        Assert.Null(ceiling.Chosen);
        Assert.False(ceiling.IsChosen);
        Assert.Equal(DirectoryConnectionSettings.DefaultDomainsAtOnce, ceiling.Effective);
    }

    /// <summary>
    /// A settings file written before this setting existed does not mean a ceiling of zero.
    /// </summary>
    /// <remarks>
    /// <b>This is the upgrade case, and it is the one that would have shipped a broken product.</b>
    /// Every operator who had already chosen a run library has a file with no concurrency property
    /// in it. Read into a plain <c>int</c> that is zero, and the first capture after upgrading would
    /// have waited for ever with nothing on screen saying why. The stored value is nullable so that
    /// an absent property reads as a question nobody has been asked.
    /// </remarks>
    [Fact]
    public void ASettingsFileWrittenBeforeThisSettingExistedDoesNotMeanZero()
    {
        var store = new FakeSettingsStore
        {
            // Exactly what such a file deserialises to: a path, and nothing else.
            Stored = new ShellSettings(@"D:\audits", DomainsAtOnce: null),
        };

        var ceiling = new DomainConcurrency(store);
        ceiling.Load();

        Assert.Null(ceiling.Chosen);
        Assert.Equal(DirectoryConnectionSettings.DefaultDomainsAtOnce, ceiling.Effective);
        Assert.NotEqual(0, ceiling.Effective);
    }

    /// <summary>
    /// A ceiling the operator chose is the one a capture uses.
    /// </summary>
    [Fact]
    public void AChosenCeilingIsTheOneACaptureUses()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", 3) };

        var ceiling = new DomainConcurrency(store);
        ceiling.Load();

        Assert.Equal(3, ceiling.Chosen);
        Assert.True(ceiling.IsChosen);
        Assert.Equal(3, ceiling.Effective);
    }

    /// <summary>
    /// Choosing a ceiling stores it.
    /// </summary>
    [Fact]
    public void ChoosingACeilingStoresIt()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", DomainsAtOnce: null) };
        var ceiling = new DomainConcurrency(store);

        var stored = ceiling.Choose(4);

        Assert.True(stored.IsSuccess);
        Assert.Equal(4, store.Stored.DomainsAtOnce);
        Assert.Equal(4, ceiling.Effective);
    }

    /// <summary>
    /// Choosing a ceiling leaves the run library where it was.
    /// </summary>
    /// <remarks>
    /// <b>Two settings in one file, and neither may erase the other.</b> Writing a whole fresh
    /// record is the obvious implementation and the wrong one: an operator who changed his
    /// concurrency would find the product asking him where his runs are kept, and nothing would
    /// say why.
    /// </remarks>
    [Fact]
    public void ChoosingACeilingLeavesTheRunLibraryAlone()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", DomainsAtOnce: null) };

        new DomainConcurrency(store).Choose(4);

        Assert.Equal(@"D:\audits", store.Stored.RunLibraryPath);
    }

    /// <summary>
    /// Choosing a run library leaves the ceiling where it was.
    /// </summary>
    /// <remarks>
    /// The other direction, and it was the live defect: <c>RunLibraryLocation.Choose</c> wrote
    /// <c>new ShellSettings(path)</c> until 2026-09-13, which was lossless only while there was one
    /// setting to lose.
    /// </remarks>
    [Fact]
    public void ChoosingARunLibraryLeavesTheCeilingAlone()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", 3) };

        new RunLibraryLocation(store).Choose(@"E:\audits");

        Assert.Equal(@"E:\audits", store.Stored.RunLibraryPath);
        Assert.Equal(3, store.Stored.DomainsAtOnce);
    }

    /// <summary>
    /// A ceiling below one is refused, and nothing is stored.
    /// </summary>
    /// <remarks>
    /// <b>Refused rather than clamped.</b> Raising a zero to one quietly would run a capture the
    /// operator did not ask for while showing him the number he did.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ACeilingBelowOneIsRefusedAndNothingIsStored(int refused)
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", 3) };
        var ceiling = new DomainConcurrency(store);
        ceiling.Load();

        var stored = ceiling.Choose(refused);

        Assert.False(stored.IsSuccess);
        Assert.Equal(3, store.Stored.DomainsAtOnce);
        Assert.Equal(3, ceiling.Effective);
    }

    /// <summary>
    /// A refused ceiling says what is wrong with it, in terms an administrator can act on.
    /// </summary>
    [Fact]
    public void ARefusedCeilingSaysWhyRatherThanJustFailing()
    {
        var ceiling = new DomainConcurrency(new FakeSettingsStore());

        ceiling.Choose(0);

        Assert.NotNull(ceiling.Problem);
        Assert.Contains("1 or more", ceiling.Problem, StringComparison.Ordinal);
        Assert.Contains("wait for ever", ceiling.Problem, StringComparison.Ordinal);
    }

    /// <summary>
    /// One domain at a time is a real answer, and is the behaviour the product had before the
    /// fan-out landed.
    /// </summary>
    [Fact]
    public void OneDomainAtATimeIsAllowed()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", DomainsAtOnce: null) };
        var ceiling = new DomainConcurrency(store);

        var stored = ceiling.Choose(DomainConcurrency.Fewest);

        Assert.True(stored.IsSuccess);
        Assert.Equal(1, ceiling.Effective);
    }

    /// <summary>
    /// A settings file that cannot be read is reported rather than treated as "not chosen".
    /// </summary>
    /// <remarks>
    /// The two are different sentences, and only one of them is true. Reading a damaged file as an
    /// unconfigured installation would silently return an operator to the default and tell him
    /// nothing.
    /// </remarks>
    [Fact]
    public void ASettingsFileThatCannotBeReadIsReported()
    {
        var store = new FakeSettingsStore
        {
            ReadFails = SecureAD.Kernel.AuditError.Create(
                SecureAD.Kernel.ErrorCategory.Shell,
                "ShellSettingsUnusable",
                SecureAD.Kernel.ErrorSeverity.Failed,
                "The settings file could not be read.",
                "shell-settings.json"),
        };

        var ceiling = new DomainConcurrency(store);
        ceiling.Load();

        Assert.NotNull(ceiling.Problem);
        Assert.Null(ceiling.Chosen);
    }

    /// <summary>
    /// A ceiling that could not be stored is not adopted.
    /// </summary>
    /// <remarks>
    /// The same rule <see cref="RunLibraryLocation"/> applies to the run library path: a product
    /// that acts on a setting it could not save behaves differently after a restart with nothing
    /// explaining why.
    /// </remarks>
    [Fact]
    public void ACeilingThatCouldNotBeStoredIsNotAdopted()
    {
        var store = new FakeSettingsStore
        {
            Stored = new ShellSettings(@"D:\audits", 3),
            WriteFails = SecureAD.Kernel.AuditError.Create(
                SecureAD.Kernel.ErrorCategory.Shell,
                "ShellSettingsUnusable",
                SecureAD.Kernel.ErrorSeverity.Failed,
                "The settings file could not be written.",
                "shell-settings.json"),
        };

        var ceiling = new DomainConcurrency(store);
        ceiling.Load();

        var stored = ceiling.Choose(7);

        Assert.False(stored.IsSuccess);
        Assert.Equal(3, ceiling.Effective);
        Assert.NotNull(ceiling.Problem);
    }
}
