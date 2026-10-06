using SecureAD.Cli;
using Xunit;

namespace SecureAD.Next.Tests.Cli;

/// <summary>
/// The argument rules an operator meets before anything connects.
/// </summary>
/// <remarks>
/// These had no tests before `S-40`, which was tolerable while the command line was three flags and
/// is not now that one of them carries a per-domain instruction that stops a run when it is wrong.
/// </remarks>
public sealed class CommandLineTests
{
    [Fact]
    public void EnatelObjectsAreExcludedUnlessRequested()
    {
        Assert.False(CommandLine.Parse(["--library", "synthetic"])!.IncludeEnatelSso);
    }

    [Theory]
    [InlineData("--capture")]
    [InlineData("--preview")]
    [InlineData("--validate")]
    public void AnEnatelInclusionChoiceIsRetainedForCaptureRelatedCommands(string mode)
    {
        var options = CommandLine.Parse(["--library", "synthetic", mode, "--include-enatel-sso"]);

        Assert.Equal(new[] { "dnsNode", "dnsZone" }, options?.ObjectScope.ExcludedClasses);
    }

    [Theory]
    [InlineData("--derive")]
    [InlineData("--judge")]
    [InlineData("--describe")]
    public void EnatelScopeCannotChangeAnExistingBundle(string mode)
    {
        Assert.Null(CommandLine.Parse([mode, "synthetic", "--include-enatel-sso"]));
    }

    [Fact]
    public void ABundleCanBeDescribedByName()
    {
        var options = CommandLine.Parse(["--describe", "D:\\runs\\one"]);

        Assert.Equal(("D:\\runs\\one", false), (options?.DescribeOnly, options?.Sizes));
    }

    [Fact]
    public void MeasuringWhereTheSpaceWentIsAskedForRatherThanAssumed()
    {
        // It reads every row of every table, so on a bundle of tens of gigabytes it must never
        // happen merely because somebody asked how many objects there were.
        var options = CommandLine.Parse(["--describe", "D:\\runs\\one", "--sizes"]);

        Assert.Equal(("D:\\runs\\one", true), (options?.DescribeOnly, options?.Sizes));
    }

    [Theory]
    [InlineData("--derive")]
    [InlineData("--judge")]
    public void MeasuringSpaceIsRefusedBesideAVerbThatMeasuresNothing(string mode)
    {
        // Refused rather than ignored, on the same grounds --concurrent is refused beside
        // --validate: an operator who states a flag and is silently not given it has been failed.
        Assert.Null(CommandLine.Parse([mode, "synthetic", "--sizes"]));
    }

    [Fact]
    public void MeasuringSpaceIsRefusedWithoutADescriptionAtAll()
    {
        Assert.Null(CommandLine.Parse(["--library", "synthetic", "--sizes"]));
    }

    [Theory]
    [InlineData("--derive")]
    [InlineData("--judge")]
    public void DescribingAndAnalysingAreNotAskedForAtOnce(string other)
    {
        // A bundle is described, or derived, or judged. One command doing two would hide which
        // half failed - the reason --derive and --judge already refuse each other.
        Assert.Null(CommandLine.Parse(["--describe", "synthetic", other, "synthetic"]));
    }

    [Fact]
    public void DescribingNeedsNoLibraryAndRefusesOneOffered()
    {
        // It reads a bundle that exists rather than writing a run, so a library says two different
        // things at once.
        Assert.Null(CommandLine.Parse(["--describe", "synthetic", "--library", "somewhere"]));
    }

    [Fact]
    public void TheCliDisclosesTheIncludedScopesRemainingDnsExclusions()
    {
        var options = CommandLine.Parse(["--library", "synthetic", "--include-enatel-sso"]);

        Assert.Equal("Excluded object classes: dnsNode, dnsZone", options?.ClassScopeDescription);
    }

    /// <summary>
    /// A preview writes nothing, so it needs nowhere to write to.
    /// </summary>
    /// <remarks>
    /// Require a library here and the tool creates a directory during what an operator asked to be
    /// a read-only look at someone else's forest.
    /// </remarks>
    [Fact]
    public void APreviewNeedsNoRunLibrary()
    {
        var parsed = CommandLine.Parse(["--preview"]);

        Assert.NotNull(parsed);
        Assert.True(parsed.PreviewOnly);
        Assert.Null(parsed.LibraryRoot);
    }

    /// <summary>
    /// A run still may not choose where several gigabytes of evidence go.
    /// </summary>
    [Fact]
    public void ARunStillRequiresARunLibrary()
    {
        Assert.Null(CommandLine.Parse([]));
        Assert.Null(CommandLine.Parse(["--validate"]));
    }

    /// <summary>
    /// An override names the domain it applies to.
    /// </summary>
    [Fact]
    public void AnOverrideIsReadPerDomain()
    {
        var parsed = CommandLine.Parse(
            ["--library", @"D:\audits", "--controller", "contoso.com=DC01.contoso.com"]);

        Assert.NotNull(parsed);
        Assert.Equal("DC01.contoso.com", parsed.Overrides["contoso.com"]);
    }

    /// <summary>
    /// Several domains may each be given a controller.
    /// </summary>
    [Fact]
    public void EachDomainMayBeGivenItsOwnController()
    {
        var parsed = CommandLine.Parse([
            "--library", @"D:\audits",
            "--controller", "contoso.com=DC01.contoso.com",
            "--controller", "eu.contoso.com=DC05.eu.contoso.com",
        ]);

        Assert.NotNull(parsed);
        Assert.Equal(2, parsed.Overrides.Count);
        Assert.Equal("DC05.eu.contoso.com", parsed.Overrides["eu.contoso.com"]);
    }

    /// <summary>
    /// A controller with no domain is refused rather than guessed at.
    /// </summary>
    /// <remarks>
    /// One host name does not say which of nine domains it is for, and picking one would send the
    /// run at a controller the operator did not name for that domain.
    /// </remarks>
    [Theory]
    [InlineData("DC01.contoso.com")]
    [InlineData("=DC01.contoso.com")]
    [InlineData("contoso.com=")]
    public void AMalformedOverrideIsRefused(string argument)
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--controller", argument]));
    }

    /// <summary>
    /// The same domain named twice is refused rather than last-one-wins.
    /// </summary>
    /// <remarks>
    /// An operator who repeats a domain has contradicted himself. Choosing one of the two for him
    /// means a run reading from a controller he also asked it not to use.
    /// </remarks>
    [Fact]
    public void TheSameDomainNamedTwiceIsRefused()
    {
        Assert.Null(CommandLine.Parse([
            "--library", @"D:\audits",
            "--controller", "contoso.com=DC01.contoso.com",
            "--controller", "contoso.com=DC02.contoso.com",
        ]));
    }

    /// <summary>
    /// Validate and preview ask for different things and are not combined.
    /// </summary>
    [Fact]
    public void ValidateAndPreviewTogetherAreRefused()
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--validate", "--preview"]));
    }

    /// <summary>
    /// Capturing without analysing is asked for explicitly, and needs somewhere to write.
    /// </summary>
    /// <remarks>
    /// <b>It is a whole capture that stops, not a smaller one.</b> The bundle it seals is complete
    /// evidence and can be derived and judged later, here or elsewhere - which is why it needs a
    /// library exactly as an ordinary run does, and why leaving the library out is refused rather
    /// than defaulted.
    /// </remarks>
    [Fact]
    public void CapturingWithoutAnalysingIsAskedForAndNeedsALibrary()
    {
        var parsed = CommandLine.Parse(["--library", @"D:\audits", "--capture"]);

        Assert.NotNull(parsed);
        Assert.True(parsed.CaptureOnly);
        Assert.Equal(@"D:\audits", parsed.LibraryRoot);

        Assert.Null(CommandLine.Parse(["--capture"]));
    }

    /// <summary>
    /// An ordinary run is not a capture-only run, so the flag cannot be reached by omission.
    /// </summary>
    [Fact]
    public void AnOrdinaryRunAnalysesWhatItCaptured()
    {
        var parsed = CommandLine.Parse(["--library", @"D:\audits"]);

        Assert.NotNull(parsed);
        Assert.False(parsed.CaptureOnly);
    }

    /// <summary>
    /// Asking to capture and to look without capturing is a contradiction, and is refused.
    /// </summary>
    /// <remarks>
    /// The cost of resolving it either way is severe and asymmetric: an operator who meant to spend
    /// seconds looking and instead read a forest for two hours has been failed by the parser, and
    /// one who meant to capture and got a preview finds out when there is no bundle.
    /// </remarks>
    [Theory]
    [InlineData("--validate")]
    [InlineData("--preview")]
    public void CaptureBesideALookThatReadsNothingIsRefused(string other)
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--capture", other]));
    }

    /// <summary>
    /// Capturing and deriving an existing bundle are different runs and are not combined.
    /// </summary>
    [Fact]
    public void CaptureBesideABundleOnlyModeIsRefused()
    {
        Assert.Null(CommandLine.Parse(["--derive", @"D:\b", "--capture"]));
        Assert.Null(CommandLine.Parse(["--judge", @"D:\b", "--capture"]));
    }

    /// <summary>
    /// An unrecognised argument stops the run rather than being ignored.
    /// </summary>
    [Fact]
    public void AnUnrecognisedArgumentIsRefused()
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--recurse"]));
    }

    /// <summary>
    /// A forest name is optional, because the ordinary run finds the forest it is already in.
    /// </summary>
    [Fact]
    public void AForestNameIsOptional()
    {
        var ordinary = CommandLine.Parse(["--library", @"D:\audits"]);
        Assert.NotNull(ordinary);
        Assert.Null(ordinary.Forest);

        var typed = CommandLine.Parse(["--library", @"D:\audits", "--forest", "contoso.com"]);
        Assert.NotNull(typed);
        Assert.Equal("contoso.com", typed.Forest);
    }

    /// <summary>
    /// Deriving names the bundle to derive from.
    /// </summary>
    [Fact]
    public void DerivingNamesTheBundle()
    {
        var parsed = CommandLine.Parse(["--derive", @"D:\audits\contoso-20260828"]);

        Assert.NotNull(parsed);
        Assert.Equal(@"D:\audits\contoso-20260828", parsed.DeriveOnly);
    }

    /// <summary>
    /// Deriving needs no run library, because it writes beside a bundle that already exists.
    /// </summary>
    /// <remarks>
    /// Requiring one would make an operator name a directory this command never writes to, and the
    /// obvious thing to type would be the library the bundle came from - which is not where the
    /// derivation goes.
    /// </remarks>
    [Fact]
    public void DerivingNeedsNoRunLibrary()
    {
        var parsed = CommandLine.Parse(["--derive", @"D:\audits\contoso-20260828"]);

        Assert.NotNull(parsed);
        Assert.Null(parsed.LibraryRoot);
    }

    /// <summary>
    /// Deriving is not combined with a run library.
    /// </summary>
    /// <remarks>
    /// <b>Each of the four below asks for two different things at once.</b> Deriving reads a bundle
    /// that exists; the rest contact a forest. Guessing which was meant is how an operator ends up
    /// with a capture he did not ask for, against a forest he may not have meant to touch.
    /// </remarks>
    [Fact]
    public void DerivingIsNotCombinedWithARunLibrary()
    {
        Assert.Null(CommandLine.Parse(["--derive", @"D:\b", "--library", @"D:\audits"]));
    }

    /// <summary>Deriving is not combined with a forest name.</summary>
    [Fact]
    public void DerivingIsNotCombinedWithAForestName()
    {
        Assert.Null(CommandLine.Parse(["--derive", @"D:\b", "--forest", "contoso.com"]));
    }

    /// <summary>Deriving is not combined with a validate.</summary>
    [Fact]
    public void DerivingIsNotCombinedWithAValidate()
    {
        Assert.Null(CommandLine.Parse(["--derive", @"D:\b", "--validate"]));
    }

    /// <summary>Deriving is not combined with a preview.</summary>
    [Fact]
    public void DerivingIsNotCombinedWithAPreview()
    {
        Assert.Null(CommandLine.Parse(["--derive", @"D:\b", "--preview"]));
    }

    /// <summary>Deriving is not combined with a named controller.</summary>
    [Fact]
    public void DerivingIsNotCombinedWithANamedController()
    {
        Assert.Null(CommandLine.Parse(
            ["--derive", @"D:\b", "--controller", "contoso.com=DC01.contoso.com"]));
    }

    /// <summary>
    /// The order the two are typed in does not change the refusal.
    /// </summary>
    [Fact]
    public void DerivingIsRefusedWhicheverWayRoundItIsTyped()
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--derive", @"D:\b"]));
    }

    /// <summary>
    /// Deriving without naming a bundle is refused rather than defaulted to somewhere.
    /// </summary>
    [Fact]
    public void DerivingWithoutABundleIsRefused()
    {
        Assert.Null(CommandLine.Parse(["--derive"]));
    }

    /// <summary>
    /// An ordinary run does not look like a derive.
    /// </summary>
    /// <remarks>
    /// The two are told apart by this one member, so a capture that carried a derive path would run
    /// the wrong half of the program.
    /// </remarks>
    [Fact]
    public void AnOrdinaryRunNamesNoBundleToDeriveFrom()
    {
        var parsed = CommandLine.Parse(["--library", @"D:\audits"]);

        Assert.NotNull(parsed);
        Assert.Null(parsed.DeriveOnly);
    }

    // -------------------------------------------------------------------------------------------
    // --concurrent. How many domains are read at the same time - 0041 as amended 2026-09-13.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// An operator may state how many domains to read at once.
    /// </summary>
    [Fact]
    public void ARunMayBeToldHowManyDomainsToReadAtOnce()
    {
        var parsed = CommandLine.Parse(["--library", @"D:\audits", "--concurrent", "4"]);

        Assert.NotNull(parsed);
        Assert.Equal(4, parsed.Concurrency);
    }

    /// <summary>
    /// Saying nothing is not the same as saying a number, and it is not zero.
    /// </summary>
    /// <remarks>
    /// The capture's own default applies when the operator does not state one. Reading an unstated
    /// ceiling as zero is precisely the defect <see cref="ACeilingOfZeroIsRefused"/> guards the
    /// other end of.
    /// </remarks>
    [Fact]
    public void ARunThatSaysNothingCarriesNoCeiling()
    {
        var parsed = CommandLine.Parse(["--library", @"D:\audits"]);

        Assert.NotNull(parsed);
        Assert.Null(parsed.Concurrency);
    }

    /// <summary>
    /// Zero is refused, because a capture bounded at zero never finishes.
    /// </summary>
    /// <remarks>
    /// <b>This is the one value that must not be accepted quietly.</b> It would wait for ever while
    /// looking exactly like a capture that is working - an operator would see a run in progress, no
    /// error, and no end to it. <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c>
    /// refuses it at construction; this refuses it before a run is even assembled.
    /// </remarks>
    [Fact]
    public void ACeilingOfZeroIsRefused()
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--concurrent", "0"]));
    }

    /// <summary>
    /// A ceiling that is not a usable whole number is refused rather than ignored.
    /// </summary>
    /// <remarks>
    /// Refused, not dropped. An operator who mistypes and has the option silently discarded gets a
    /// run that did something other than what he asked for, with nothing telling him so - which is
    /// the rule <c>CommandLine</c> already applies to a malformed <c>--controller</c>.
    /// </remarks>
    [Theory]
    [InlineData("-1")]
    [InlineData("nine")]
    [InlineData("2.5")]
    [InlineData("")]
    public void ACeilingThatIsNotAWholeNumberOfOneOrMoreIsRefused(string value)
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--concurrent", value]));
    }

    /// <summary>
    /// A ceiling with no value after it is refused.
    /// </summary>
    [Fact]
    public void ACeilingWithNothingAfterItIsRefused()
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", "--concurrent"]));
    }

    /// <summary>
    /// A ceiling is refused where nothing would read a domain.
    /// </summary>
    /// <remarks>
    /// <b>Neither mode reads an object</b>, so the number would govern nothing. A preview contacts
    /// nothing at all and a validate asks each controller the four questions without reading. It is
    /// refused rather than accepted-and-ignored so an operator is never told a number was taken
    /// when it was not.
    /// </remarks>
    [Theory]
    [InlineData("--validate")]
    [InlineData("--preview")]
    public void ACeilingIsRefusedWhereNoDomainWouldBeRead(string mode)
    {
        Assert.Null(CommandLine.Parse(["--library", @"D:\audits", mode, "--concurrent", "4"]));
    }

    /// <summary>
    /// A ceiling is refused beside a bundle that has already been captured.
    /// </summary>
    /// <remarks>
    /// Deriving and judging read evidence that already exists and contact no controller, so a
    /// ceiling asks for two different things at once - which this file refuses rather than guesses
    /// between.
    /// </remarks>
    [Theory]
    [InlineData("--derive")]
    [InlineData("--judge")]
    public void ACeilingIsRefusedBesideABundleAlreadyCaptured(string mode)
    {
        Assert.Null(CommandLine.Parse([mode, @"D:\audits\run", "--concurrent", "4"]));
    }

    /// <summary>
    /// A capture that stops after sealing may still be told how many domains to read at once.
    /// </summary>
    /// <remarks>
    /// <c>--capture</c> does a whole capture and stops before deriving, so it reads every domain and
    /// the ceiling governs it exactly as it governs a full run.
    /// </remarks>
    [Fact]
    public void ACaptureThatStopsAfterSealingStillTakesACeiling()
    {
        var parsed = CommandLine.Parse(
            ["--library", @"D:\audits", "--capture", "--concurrent", "2"]);

        Assert.NotNull(parsed);
        Assert.Equal(2, parsed.Concurrency);
    }

    /// <summary>
    /// The usage names the option, and says whose machine it governs.
    /// </summary>
    /// <remarks>
    /// <b>The wording is the safeguard, so the wording is what is asserted.</b> An operator reading
    /// "how many domains at once" with nothing else said would reasonably take it for consideration
    /// towards his domain controllers, lower it, and get a slower capture believing he had got a
    /// gentler one. The owner approved this sentence on 2026-09-13 alongside the settings screen and
    /// the review, and this holds the half that cannot be inferred from the option's name.
    /// </remarks>
    [Fact]
    public void TheUsageSaysTheCeilingGovernsThisMachineAndNotTheDirectory()
    {
        Assert.Contains("--concurrent", CommandLine.Usage, StringComparison.Ordinal);

        Assert.Contains(
            "governs THIS machine, not your domain controllers",
            CommandLine.Usage,
            StringComparison.Ordinal);

        Assert.Contains(
            "never makes it gentler on the directory",
            CommandLine.Usage,
            StringComparison.Ordinal);
    }
}
