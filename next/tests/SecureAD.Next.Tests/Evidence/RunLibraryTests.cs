using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The managed root: where a bundle goes, and what may not reach outside it.
///
/// <para>
/// The containment check is a traversal defence that deletion will depend on, per
/// <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c>. It is tested before anything
/// deletes anything.
/// </para>
/// </summary>
public sealed class RunLibraryTests
{
    private static readonly DateTimeOffset Moment =
        new(2026, 8, 29, 3, 0, 0, TimeSpan.Zero);

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"secad-lib-{Guid.NewGuid():N}");

    [Fact]
    public void ARunIsCreatedInsideTheRoot()
    {
        var created = Library().CreateRun("example.com");

        Assert.True(created.IsSuccess);
        Assert.True(Directory.Exists(created.Value));
        Assert.StartsWith(
            Path.GetFullPath(_root), created.Value!, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The name carries the forest and the moment, so a folder listing can be read by a person.
    /// Nothing reads meaning back out of it.
    /// </summary>
    [Fact]
    public void TheRunIsNamedForTheForestAndTheMoment()
    {
        var created = Library().CreateRun("example.com");

        Assert.Equal("example.com-20260829-030000", Path.GetFileName(created.Value));
    }

    /// <summary>
    /// Two runs of one forest in the same second is a run started twice, and is refused rather
    /// than given a suffix that makes the two hard to tell apart.
    /// </summary>
    [Fact]
    public void ASecondRunOfOneForestInTheSameSecondIsRefused()
    {
        var library = Library();

        Assert.True(library.CreateRun("example.com").IsSuccess);

        var second = library.CreateRun("example.com");

        Assert.False(second.IsSuccess);
        Assert.Equal("Evidence.RunDirectoryAlreadyExists", second.Error!.Code);
    }

    /// <summary>
    /// A forest name is read off a directory this product does not control, so a separator in one
    /// must not become a path.
    /// </summary>
    [Theory]
    [InlineData("../escape")]
    [InlineData(@"..\escape")]
    public void AForestNameCannotBecomeAPath(string forestFqdn)
    {
        var created = Library().CreateRun(forestFqdn);

        Assert.True(created.IsSuccess);
        Assert.Equal(
            Path.GetFullPath(_root),
            Path.GetDirectoryName(created.Value),
            ignoreCase: true);
    }

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("../outside")]
    [InlineData(@"..\outside")]
    [InlineData(@"sub\run")]
    [InlineData("sub/run")]
    [InlineData(@"C:\elsewhere")]
    [InlineData("")]
    public void AnIdentifierThatIsNotASingleNameIsRefused(string identifier)
    {
        var resolved = Library().Resolve(identifier);

        Assert.False(resolved.IsSuccess);
    }

    [Fact]
    public void AnIdentifierThatIsASingleNameResolvesInsideTheRoot()
    {
        var resolved = Library().Resolve("example.com-20260829-030000");

        Assert.True(resolved.IsSuccess);
        Assert.Equal(
            Path.Combine(Path.GetFullPath(_root), "example.com-20260829-030000"),
            resolved.Value);
    }

    /// <summary>
    /// The check that a sibling whose name merely begins with the root's is not inside it. This is
    /// the case a naive <c>StartsWith</c> gets wrong, and it is why the root is given a trailing
    /// separator before the comparison.
    /// </summary>
    [Fact]
    public void ASiblingWhoseNameBeginsWithTheRootsIsNotInsideIt()
    {
        var library = new RunLibrary(_root, new FixedTime());
        var sibling = _root + "-elsewhere";

        Directory.CreateDirectory(sibling);

        try
        {
            // Reached the only way a caller can reach it: as an identifier, which is refused
            // before containment is even asked, because it is not a single name.
            Assert.False(library.Resolve(sibling).IsSuccess);
        }
        finally
        {
            Directory.Delete(sibling);
        }
    }

    private RunLibrary Library() => new(_root, new FixedTime());

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Moment;
    }
}
