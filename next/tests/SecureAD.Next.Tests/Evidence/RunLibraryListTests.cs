using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
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

    private static readonly DateTimeOffset Started = new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 21, 11, 30, 0, TimeSpan.Zero);

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

    /// <summary>
    /// The newest run is the one an operator reaches for, so it is the one at the top.
    ///
    /// <para>
    /// The three runs are named so that neither alphabetical direction produces the right answer:
    /// by name ascending they are a, m, z and by name descending z, m, a, while the correct answer
    /// is m, a, z. Runs were listed in name order until 2026-08-21, which read as newest-last with
    /// one forest in the library and as nothing at all with two.
    /// </para>
    /// </summary>
    [Fact]
    public void TheNewestRunIsListedFirst()
    {
        StubRunCreated("z-forest-20260101-000000", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        StubRunCreated("a-forest-20260102-000000", new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc));
        StubRunCreated("m-forest-20260103-000000", new DateTime(2026, 1, 3, 0, 0, 0, DateTimeKind.Utc));

        Assert.Equal(
            new[]
            {
                "m-forest-20260103-000000",
                "a-forest-20260102-000000",
                "z-forest-20260101-000000",
            },
            List().Select(r => r.Identifier));
    }

    /// <summary>
    /// Two runs that cannot be separated by time are still listed in a fixed order, so the screen
    /// does not reshuffle between refreshes.
    /// </summary>
    [Fact]
    public void RunsSharingAMomentAreListedInAStableOrder()
    {
        var moment = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        StubRunCreated("a-forest-20260101-000000", moment);
        StubRunCreated("b-forest-20260101-000000", moment);

        Assert.Equal(
            new[] { "b-forest-20260101-000000", "a-forest-20260101-000000" },
            List().Select(r => r.Identifier));
    }

    /// <summary>
    /// A run that recorded when it finished is placed by that, and says the moment is its own.
    ///
    /// <para>
    /// This is the test the ordering rests on. Every other run in this class is a stub whose
    /// evidence file is not a database, so its moment always falls back to the directory's
    /// creation time - and without a real bundle here, the whole feature could read nothing from
    /// any bundle and every ordering assertion would still pass.
    /// </para>
    /// </summary>
    [Fact]
    public void ARunThatRecordedWhenItFinishedIsPlacedByThat()
    {
        WriteARealBundle("contoso.example-20260101-000000");

        var listed = Assert.Single(List());

        Assert.True(listed.Moment.Recorded);
        Assert.Equal(Finished, listed.Moment.Utc);
    }

    /// <summary>
    /// A run that never recorded a moment is still listed and still placed, and the listing says
    /// the moment did not come from the run. Presenting the file system's answer as the run's own
    /// would be a fact nobody recorded.
    /// </summary>
    [Fact]
    public void ARunThatRecordedNoMomentDoesNotClaimOne()
    {
        SealedRun("contoso.example-20260101-000000");

        Assert.False(Assert.Single(List()).Moment.Recorded);
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

    /// <summary>
    /// A stub run whose directory was created at <paramref name="createdUtc"/>. Its evidence file
    /// is not a database, so it records no moment of its own and the library must place it by the
    /// directory - which is the fallback these ordering tests drive.
    /// </summary>
    private void StubRunCreated(string identifier, DateTime createdUtc) =>
        Directory.SetCreationTimeUtc(SealedRun(identifier), createdUtc);

    /// <summary>
    /// A genuine bundle, written by <see cref="BundleWriter"/> and sealed, recording that it
    /// completed at <see cref="Finished"/>.
    /// </summary>
    private void WriteARealBundle(string identifier)
    {
        var directory = Path.Combine(_root, identifier);
        Directory.CreateDirectory(directory);

        using var writer = BundleWriter.Create(directory, Started);
        writer.WriteCoverage(new PartitionCoverage(
            "DC=contoso,DC=com",
            NamingContextKind.Domain,
            "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed,
            12,
            4200,
            3,
            [],
            false));

        writer.Complete(
            RunCoverage.Of(
                CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                [DomainCoverage.Read("contoso.com")],
                [
                    ForestPartitionCoverage.Read(
                        "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read(
                        "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
                ],
                SysvolCoverage.Of([])),
            Finished);
    }
}
