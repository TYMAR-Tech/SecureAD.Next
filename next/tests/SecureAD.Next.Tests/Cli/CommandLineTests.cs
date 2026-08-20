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
}
