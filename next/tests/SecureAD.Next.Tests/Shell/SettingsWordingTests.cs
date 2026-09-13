using SecureAD.Audit.Connect;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// What the settings screen tells an operator, and what it refuses.
/// </summary>
/// <remarks>
/// <para>
/// <b>The wording is the safeguard here, so the wording is what is held.</b> This number governs the
/// machine running the audit and never a customer's domain controller -
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> as amended. An administrator who
/// reads it as consideration towards his directory will lower it, get a slower capture, and believe
/// he has got a gentler one. Nothing in the code can prevent that; only the sentences can.
/// </para>
/// <para>
/// Approved by the owner on 2026-09-13 together with the command line's help text and the sentence
/// the new-audit review shows, so that the three cannot drift into describing one number three ways.
/// </para>
/// </remarks>
public sealed class SettingsViewModelTests
{
    /// <summary>
    /// The screen opens showing the ceiling a capture would actually use.
    /// </summary>
    /// <remarks>
    /// Not blank, and not zero. An operator who has never chosen still has an answer - the capture's
    /// default - and the box shows him what it is rather than implying nothing is set.
    /// </remarks>
    [Fact]
    public void TheScreenOpensShowingTheCeilingACaptureWouldUse()
    {
        var screen = Screen(new FakeSettingsStore());

        Assert.Equal(
            DirectoryConnectionSettings.DefaultDomainsAtOnce.ToString(
                System.Globalization.CultureInfo.CurrentCulture),
            screen.Typed);
    }

    /// <summary>
    /// Saving a number stores it.
    /// </summary>
    [Fact]
    public void SavingANumberStoresIt()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", DomainsAtOnce: null) };
        var screen = Screen(store);

        screen.Typed = "4";
        screen.Save();

        Assert.Null(screen.Problem);
        Assert.Equal(4, store.Stored.DomainsAtOnce);
    }

    /// <summary>
    /// Saving something that is not a number says so, and stores nothing.
    /// </summary>
    /// <remarks>
    /// <b>A different sentence from the one zero gets</b>, because they are different mistakes. A
    /// control that refused both with one message would leave an operator who typed "nine" looking
    /// for a range problem he does not have.
    /// </remarks>
    [Fact]
    public void SavingSomethingThatIsNotANumberSaysSoAndStoresNothing()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", 3) };
        var screen = Screen(store);

        screen.Typed = "nine";
        screen.Save();

        Assert.NotNull(screen.Problem);
        Assert.Contains("is not a number of domains", screen.Problem, StringComparison.Ordinal);
        Assert.Equal(3, store.Stored.DomainsAtOnce);
    }

    /// <summary>
    /// Saving zero is refused, and the refusal says what it would have caused.
    /// </summary>
    /// <remarks>
    /// <b>The value that must never be accepted quietly.</b> A capture bounded at zero waits for
    /// ever while looking precisely like one that is working: no error, no end, and an operator
    /// watching a progress indicator that will never move.
    /// </remarks>
    [Fact]
    public void SavingZeroIsRefusedAndSaysWhatItWouldHaveCaused()
    {
        var store = new FakeSettingsStore { Stored = new ShellSettings(@"D:\audits", 3) };
        var screen = Screen(store);

        screen.Typed = "0";
        screen.Save();

        Assert.NotNull(screen.Problem);
        Assert.Contains("wait for ever", screen.Problem, StringComparison.Ordinal);
        Assert.Equal(3, store.Stored.DomainsAtOnce);
    }

    /// <summary>
    /// The screen says whose machine the number governs.
    /// </summary>
    /// <remarks>
    /// <b>This is the sentence the whole setting turns on.</b> Without it the heading reads as a
    /// throttle over the directory, which is what <c>0041</c> refused to offer and what this is
    /// not.
    /// </remarks>
    [Fact]
    public void TheScreenSaysTheNumberGovernsThisComputerAndNotTheControllers()
    {
        var screen = Screen(new FakeSettingsStore());

        Assert.Contains(
            "a limit on this computer, not on your domain controllers",
            screen.WhoseMachineItGoverns,
            StringComparison.Ordinal);

        Assert.Contains(
            "writes its own database here",
            screen.WhoseMachineItGoverns,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The screen says outright that lowering the number buys nothing.
    /// </summary>
    /// <remarks>
    /// An administrator's instinct is that a smaller number is kinder to production. It is not, and
    /// leaving him to infer it would be leaving him to infer the opposite.
    /// </remarks>
    [Fact]
    public void TheScreenSaysLoweringItDoesNotMakeItGentlerOnTheDirectory()
    {
        var screen = Screen(new FakeSettingsStore());

        Assert.Contains(
            "does not make it gentler on your directory",
            screen.WhatLoweringItCosts,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The screen says "nine by default", and nine is what the capture actually does.
    /// </summary>
    /// <remarks>
    /// <b>The number is written as a word in a sentence the owner approved, which makes it a claim
    /// that could go stale in silence.</b> This is what stops it: change
    /// <see cref="DirectoryConnectionSettings.DefaultDomainsAtOnce"/> and this fails, so the
    /// sentence is reworded deliberately rather than quietly becoming false on a screen an operator
    /// trusts.
    /// </remarks>
    [Fact]
    public void TheScreenSaysNineAndNineIsWhatACaptureActuallyDoes()
    {
        var screen = Screen(new FakeSettingsStore());

        Assert.Contains("nine by default", screen.WhatItIs, StringComparison.Ordinal);
        Assert.Equal(9, DirectoryConnectionSettings.DefaultDomainsAtOnce);
    }

    private static SettingsViewModel Screen(FakeSettingsStore store)
    {
        var ceiling = new DomainConcurrency(store);
        ceiling.Load();

        return new SettingsViewModel(ceiling);
    }
}

/// <summary>
/// What the new-audit review states about how the run will be read.
/// </summary>
/// <remarks>
/// <b>It describes the run, not the setting.</b> The ceiling is clamped to the number of domains
/// there are, so a review announcing "up to 9 at a time" over a three-domain forest would be
/// describing a capture nobody is about to run.
/// </remarks>
public sealed class AuditReviewConcurrencyTests
{
    /// <summary>
    /// A ceiling at or above the number of domains reads all of them at once.
    /// </summary>
    [Theory]
    [InlineData(3, 9)]
    [InlineData(3, 3)]
    public void ACeilingThatCoversEveryDomainReadsThemAllAtOnce(int domains, int ceiling)
    {
        Assert.Equal(
            $"All {domains} will be read at the same time.",
            Review(domains, ceiling).ConcurrencyStatement);
    }

    /// <summary>
    /// A ceiling below the number of domains says how many overlap and what happens to the rest.
    /// </summary>
    [Fact]
    public void ACeilingBelowTheDomainCountSaysWhatHappensToTheRest()
    {
        Assert.Equal(
            "Up to 4 at a time; the rest follow as those finish.",
            Review(domains: 9, ceiling: 4).ConcurrencyStatement);
    }

    /// <summary>
    /// A ceiling of one says so plainly.
    /// </summary>
    /// <remarks>
    /// This is the behaviour the product had before the fan-out landed, and it is a legitimate
    /// choice rather than a degraded one.
    /// </remarks>
    [Fact]
    public void ACeilingOfOneSaysOneAtATime()
    {
        Assert.Equal(
            "They will be read one at a time.",
            Review(domains: 9, ceiling: 1).ConcurrencyStatement);
    }

    /// <summary>
    /// A single domain is not described as several read together.
    /// </summary>
    /// <remarks>
    /// The owner's laboratory forest is one domain, so this is the sentence he sees most. "All 1
    /// will be read at the same time" is the kind of phrasing that tells an administrator nobody
    /// read the screen.
    /// </remarks>
    [Fact]
    public void OneDomainIsNotDescribedAsSeveralAtOnce()
    {
        Assert.Equal(
            "It will be read on its own.",
            Review(domains: 1, ceiling: 9).ConcurrencyStatement);
    }

    /// <summary>
    /// A review with every domain excluded does not claim anything will be read.
    /// </summary>
    [Fact]
    public void ARunWithNothingLeftToReadSaysSo()
    {
        Assert.Equal("Nothing will be read.", Review(domains: 0, ceiling: 9).ConcurrencyStatement);
    }

    /// <summary>
    /// The caveat names whose machine is governed and sends the operator to the one place it is set.
    /// </summary>
    /// <remarks>
    /// The review states the number and does not offer it. Without the second half of this sentence
    /// an operator who wanted to change it would have nowhere to go and might reasonably conclude it
    /// could not be changed.
    /// </remarks>
    [Fact]
    public void TheCaveatNamesThisComputerAndPointsAtSettings()
    {
        var caveat = Review(domains: 3, ceiling: 9).ConcurrencyCaveat;

        Assert.Contains("not on your domain controllers", caveat, StringComparison.Ordinal);
        Assert.Contains("Change it in Settings", caveat, StringComparison.Ordinal);
    }

    private static AuditReview Review(int domains, int ceiling) =>
        new(
            "contoso.com",
            [.. Enumerable.Range(1, domains).Select(i => new ReviewedDomain($"d{i}", $"dc{i}"))],
            [],
            "nothing unestablished",
            [],
            ceiling);
}
