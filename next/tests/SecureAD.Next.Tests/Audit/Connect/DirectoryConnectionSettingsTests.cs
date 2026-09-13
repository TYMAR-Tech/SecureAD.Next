using SecureAD.Audit.Connect;
using Xunit;

namespace SecureAD.Next.Tests.Audit.Connect;

/// <summary>
/// The settings a run connects under, and the one of them an operator may change.
/// </summary>
public sealed class DirectoryConnectionSettingsTests
{
    /// <summary>
    /// Nine, which is every domain of the forest this is built for. The owner chose it on
    /// 2026-09-13 because these run from laptops on NVMe, where making domains queue buys nothing.
    /// </summary>
    [Fact]
    public void AnOrdinaryRunReadsNineDomainsAtOnce()
    {
        Assert.Equal(9, DirectoryConnectionSettings.Default.DomainsAtOnce);
    }

    /// <summary>
    /// The ceiling is settable, which is the whole point of it being a setting: a machine whose
    /// disk cannot keep nine databases in flight can be told to read fewer.
    /// </summary>
    [Fact]
    public void ARunMayBeToldToReadFewerDomainsAtOnce()
    {
        var settings = DirectoryConnectionSettings.Default with { DomainsAtOnce = 3 };

        Assert.Equal(3, settings.DomainsAtOnce);
    }

    /// <summary>
    /// One at a time is the serial behaviour the product had before 0041, and it stays reachable -
    /// it is the setting's floor rather than something the validation refuses.
    /// </summary>
    [Fact]
    public void ARunMayBeToldToReadOneDomainAtATime()
    {
        var settings = DirectoryConnectionSettings.Default with { DomainsAtOnce = 1 };

        Assert.Equal(1, settings.DomainsAtOnce);
    }

    /// <summary>
    /// Zero would wait forever while looking exactly like a capture that is working, which is worse
    /// than failing.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ARunCannotBeToldToReadNoDomainsAtOnce(int domainsAtOnce)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => DirectoryConnectionSettings.Default with { DomainsAtOnce = domainsAtOnce });
    }

    /// <summary>
    /// The refusal says what to do about it, because an operator who set this deliberately needs to
    /// know what the acceptable range is rather than that they were wrong.
    /// </summary>
    [Fact]
    public void RefusingAZeroCeilingSaysWhyItCannotWork()
    {
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => DirectoryConnectionSettings.Default with { DomainsAtOnce = 0 });

        Assert.Contains("at least one domain", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Changing the ceiling changes nothing else. It is a fact about this machine's disk, and must
    /// not quietly become a second way to set a timeout or an allowance.
    /// </summary>
    [Fact]
    public void ChangingTheCeilingLeavesEveryOtherSettingAlone()
    {
        var original = DirectoryConnectionSettings.Default;

        var changed = original with { DomainsAtOnce = 2 };

        Assert.Equal(original.Credential, changed.Credential);
        Assert.Equal(original.Allowance, changed.Allowance);
        Assert.Equal(original.ConnectTimeout, changed.ConnectTimeout);
        Assert.Equal(original.ResponseTimeout, changed.ResponseTimeout);
    }
}
