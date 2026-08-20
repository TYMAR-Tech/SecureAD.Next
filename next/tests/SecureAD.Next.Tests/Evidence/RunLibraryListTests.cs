using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Listing the runs in a library, which is what a run library screen binds to.
///
/// <para>
/// The distinction these tests exist to hold is between <i>this is not one of ours</i> and <i>this
/// is ours and is broken</i>. A library root is a folder on an operator's disk and may hold
/// anything; presenting a stray folder as a damaged audit would be a claim about a run that never
/// happened, and hiding a genuinely damaged run among such folders would conceal a real failure.
/// </para>
/// </summary>
public sealed class RunLibraryListTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "securead-runlist-" + Guid.NewGuid().ToString("n"));

    private readonly RunLibrary _library;

    public RunLibraryListTests()
    {
        Directory.CreateDirectory(_root);
        _library = new RunLibrary(_root, TimeProvider.System);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A held lock is not worth failing a run over.
        }
    }

    [Fact]
    public void AnEmptyLibraryListsNothing()
    {
        Assert.Empty(List());
    }

    [Fact]
    public void ASealedRunIsListed()
    {
        SealedRun("contoso.example-20260101-000000");

        Assert.Equal(RunState.Sealed, Assert.Single(List()).State);
    }

    [Fact]
    public void AListedRunCarriesItsDirectoryNameAsItsIdentifier()
    {
        SealedRun("contoso.example-20260101-000000");

        Assert.Equal("contoso.example-20260101-000000", Assert.Single(List()).Identifier);
    }

    [Fact]
    public void AListedRunCarriesTheFullPathOfItsBundle()
    {
        var expected = SealedRun("contoso.example-20260101-000000");

        Assert.Equal(expected, Assert.Single(List()).Path);
    }

    /// <summary>
    /// The operator keeps notes, an installer, anything, beside their runs. None of it is an audit.
    /// </summary>
    [Fact]
    public void ADirectoryThatIsNotARunIsLeftOut()
    {
        Directory.CreateDirectory(Path.Combine(_root, "holiday-photos"));

        Assert.Empty(List());
    }

    /// <summary>
    /// The opposite case, and the reason the one above is a skip rather than a blanket filter. This
    /// run exists, cannot be trusted, and the operator has to be told.
    /// </summary>
    [Fact]
    public void ARunWhoseSealDoesNotMatchIsListedAsDamaged()
    {
        var directory = SealedRun("contoso.example-20260101-000000");
        File.AppendAllText(BundleLayout.EvidencePath(directory), "tampered");

        Assert.Equal(RunState.Damaged, Assert.Single(List()).State);
    }

    [Fact]
    public void ADamagedRunCarriesTheExplanation()
    {
        var directory = SealedRun("contoso.example-20260101-000000");
        File.AppendAllText(BundleLayout.EvidencePath(directory), "tampered");

        Assert.False(string.IsNullOrWhiteSpace(Assert.Single(List()).Detail));
    }

    /// <summary>A sealed run needs no explanation, and inventing one would be noise.</summary>
    [Fact]
    public void ASealedRunCarriesNoExplanation()
    {
        SealedRun("contoso.example-20260101-000000");

        Assert.Null(Assert.Single(List()).Detail);
    }

    [Fact]
    public void RunsAreListedInIdentifierOrder()
    {
        SealedRun("b-forest-20260101-000000");
        SealedRun("a-forest-20260101-000000");

        Assert.Equal(
            new[] { "a-forest-20260101-000000", "b-forest-20260101-000000" },
            List().Select(r => r.Identifier));
    }

    [Fact]
    public void ARunAndAStrayFolderTogetherYieldOnlyTheRun()
    {
        SealedRun("contoso.example-20260101-000000");
        Directory.CreateDirectory(Path.Combine(_root, "holiday-photos"));

        Assert.Equal("contoso.example-20260101-000000", Assert.Single(List()).Identifier);
    }

    /// <summary>
    /// The scanner self-test. Proves the helper genuinely creates a run the reader recognises, so
    /// that none of the assertions above can pass by listing an empty library.
    /// </summary>
    [Fact]
    public void TheHelperProducesARunTheReaderRecognises()
    {
        var directory = SealedRun("contoso.example-20260101-000000");

        Assert.True(File.Exists(BundleLayout.EvidencePath(directory)));
        Assert.True(File.Exists(BundleLayout.SealPath(directory)));
        Assert.True(RunStateReader.Observe(directory).IsSuccess);
    }

    private IReadOnlyList<RunListing> List()
    {
        var listed = _library.List();
        Assert.True(listed.IsSuccess, listed.IsSuccess ? "" : listed.Error.Description);
        return listed.Value;
    }

    private string SealedRun(string identifier)
    {
        var directory = Path.Combine(_root, identifier);
        Directory.CreateDirectory(directory);

        File.WriteAllText(BundleLayout.EvidencePath(directory), "not really a database");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(directory),
            BundleLayout.SealPath(directory));

        return directory;
    }
}
