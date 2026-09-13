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
}
