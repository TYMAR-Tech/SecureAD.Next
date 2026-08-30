using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The bundle's read half: what opens, what is refused, and what a bundle says about itself.
/// </summary>
/// <remarks>
/// Against a real bundle written by <see cref="BundleWriter"/> rather than a hand-built file. A
/// reader tested against a fixture agrees with the fixture, and the only thing worth proving is
/// that it agrees with the writer.
/// </remarks>
public sealed class BundleReaderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-reader-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 21, 11, 30, 0, TimeSpan.Zero);

    // ---------------------------------------------------------------------------------------
    // What opens
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ASealedBundleOpens()
    {
        WriteABundle();

        using var opening = Open();

        Assert.True(opening.IsSuccess);
    }

    [Fact]
    public void AnOpenedBundleNamesTheForestItCaptured()
    {
        WriteABundle();

        using var opening = Open();

        Assert.Equal("contoso.com", opening.Value.Description.ForestFqdn);
    }

    [Fact]
    public void AnOpenedBundleReportsWhenTheCaptureStarted()
    {
        WriteABundle();

        using var opening = Open();

        Assert.Equal(Started, opening.Value.Description.CaptureStartedUtc);
    }

    [Fact]
    public void AnOpenedBundleReportsWhenTheCaptureFinished()
    {
        WriteABundle();

        using var opening = Open();

        Assert.Equal(Finished, opening.Value.Description.CaptureCompletedUtc);
    }

    [Fact]
    public void AnOpenedBundleCarriesTheCoverageIdentityTheRunRecorded()
    {
        WriteABundle();

        using var opening = Open();

        Assert.Equal(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]).Value,
            opening.Value.Description.CoverageId);
    }

    /// <summary>
    /// The bundle's own account of its capture, which is a different question from the seal. A
    /// run that reached every declared unit says so here; the seal only says the claim has not
    /// been edited since.
    /// </summary>
    [Fact]
    public void AnOpenedBundleReportsWhetherEveryDeclaredUnitWasRead()
    {
        WriteABundle();

        using var opening = Open();

        Assert.True(opening.Value.Description.EveryDeclaredUnitRecordedAsRead);
    }

    [Fact]
    public void AnOpenedBundleCarriesTheCaptureSemanticVersions()
    {
        WriteABundle();

        using var opening = Open();

        Assert.Equal(
            (CapturedAttributeCatalog.Version, SchemaGuidCatalog.Version, SecurityDescriptorParser.Version),
            (opening.Value.Description.CapturedAttributeCatalogVersion,
             opening.Value.Description.SchemaGuidCatalogVersion,
             opening.Value.Description.SecurityDescriptorParserVersion));
    }

    [Theory]
    [InlineData("captured_attribute_catalog_version", "Evidence.CapturedAttributeCatalogVersionUnsupported")]
    [InlineData("schema_guid_catalog_version", "Evidence.SchemaGuidCatalogVersionUnsupported")]
    [InlineData("security_descriptor_parser_version", "Evidence.SecurityDescriptorParserVersionUnsupported")]
    public void ABundleWithDifferentCaptureSemanticsIsRefused(string column, string reason)
    {
        WriteABundle();
        WithTheEvidenceOpen($"UPDATE bundle SET {column} = 0");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        using var opening = Open();

        Assert.Equal(reason, opening.Error.Code);
    }

    [Fact]
    public void AnOpenedBundleRoundTripsTheContinuationReconciliation()
    {
        using (var writer = BundleWriter.Create(_directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            writer.Complete(
                OneDomainRead(),
                Finished,
                new ContinuationReconciliation(
                    ContinuationReconciliationOutcome.Incomplete,
                    ["DC=child,DC=contoso,DC=com"],
                    ["not an LDAP URL"],
                    ["DC=contoso,DC=com"]));
        }

        using var opening = Open();

        var reconciliation = opening.Value.ContinuationReconciliation;
        Assert.Equal(
            "Incomplete|DC=child,DC=contoso,DC=com|not an LDAP URL|DC=contoso,DC=com",
            $"{reconciliation.Outcome}|{string.Join(';', reconciliation.UnplannedNamingContexts)}|"
            + $"{string.Join(';', reconciliation.UnreadableReferences)}|"
            + string.Join(';', reconciliation.UnitsWithSuppressedReferrals));
    }

    [Fact]
    public void ASealedBundleThatReachedNoDomainStillOpensAndSaysSo()
    {
        WriteABundle(NoDomainRead());

        using var opening = Open();

        Assert.False(opening.Value.Description.EveryDeclaredUnitRecordedAsRead);
    }

    // ---------------------------------------------------------------------------------------
    // What is refused
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The mechanism, stated as a test. An interrupted run leaves its evidence under a name no
    /// reader asks for, so there is nothing here to open.
    /// </summary>
    [Fact]
    public void AnInterruptedRunHasNothingToOpen()
    {
        using (var writer = BundleWriter.Create(_directory, Started))
            writer.WriteCoverage(SomeCoverage());

        using var opening = Open();

        Assert.False(opening.IsSuccess);
    }

    [Fact]
    public void ABundleWithNoSealIsRefusedAsUnsealedRatherThanAsDamaged()
    {
        WriteABundle();
        File.Delete(BundleLayout.SealPath(_directory));

        using var opening = Open();

        Assert.Equal("Evidence.SealAbsent", opening.Error.Code);
    }

    /// <summary>
    /// A seal something happened to is not a seal nobody wrote. The remedy differs - copy the
    /// bundle again - so the refusal does.
    /// </summary>
    [Fact]
    public void ADamagedSealIsRefusedAsUnreadable()
    {
        WriteABundle();
        File.WriteAllText(BundleLayout.SealPath(_directory), "{ not json");

        using var opening = Open();

        Assert.Equal("Evidence.SealUnreadable", opening.Error.Code);
    }

    /// <summary>
    /// Evidence edited after the run declared itself finished is no longer the evidence, and is
    /// refused under its own code however plausible the edit looks.
    /// </summary>
    [Fact]
    public void EditedEvidenceIsRefusedAsAMismatch()
    {
        WriteABundle();
        EditTheEvidence();

        using var opening = Open();

        Assert.Equal("Evidence.SealMismatch", opening.Error.Code);
    }

    [Fact]
    public void EditedEvidenceIsNotOpened()
    {
        WriteABundle();
        EditTheEvidence();

        using var opening = Open();

        Assert.False(opening.IsSuccess);
    }

    // --- A bundle this build can read and cannot recompute ---
    //
    // schema_version and canonicalization_version move independently: one describes the tables,
    // the other describes the Kernel's output, and F-S1-1 records the coupling removed to keep
    // them apart. So a bundle from a build with the same tables and an older hash recipe passes
    // the schema gate. Every ace_hash and ace_set_hash in it is then a value this build cannot
    // reproduce, and until 2026-08-19 nothing read the column that says so.
    //
    // The bundle is re-sealed after the edit on purpose. An earlier build sealed its own output
    // correctly, so a stale bundle arrives intact - and a test that left the seal broken would
    // prove only that BundleReader still refuses a mismatch, which is a different test above.

    [Fact]
    public void ABundleCanonicalisedByAnEarlierVersionIsRefusedUnderItsOwnCode()
    {
        WriteABundleCanonicalisedBy(AceCanonicalization.Version - 1);

        using var opening = Open();

        Assert.Equal("Evidence.CanonicalizationVersionUnsupported", opening.Error.Code);
    }

    [Fact]
    public void ABundleCanonicalisedByAnEarlierVersionIsNotOpened()
    {
        WriteABundleCanonicalisedBy(AceCanonicalization.Version - 1);

        using var opening = Open();

        Assert.False(opening.IsSuccess);
    }

    /// <summary>
    /// The refusal names both numbers, because an operator seeing only one of them cannot tell
    /// whether the bundle is old or the build is.
    /// </summary>
    [Fact]
    public void TheRefusalNamesTheVersionStoredAndTheVersionThisBuildProduces()
    {
        WriteABundleCanonicalisedBy(AceCanonicalization.Version - 1);

        using var opening = Open();

        Assert.Contains(
            (AceCanonicalization.Version - 1).ToString(),
            opening.Error.Description,
            StringComparison.Ordinal);
        Assert.Contains(
            AceCanonicalization.Version.ToString(),
            opening.Error.Description,
            StringComparison.Ordinal);
    }

    // --- A bundle whose tables this build does not know ---
    //
    // The sibling of the three checks above, and until 2026-09 it had none. The two version
    // refusals are written as a pair in one paragraph of BundleReader's remarks and only one of
    // them was ever reached by a test - P-19's shape again, a rule applied to a list of two with
    // the second entry never re-asked. The seam was already built and working; nothing was hard
    // about this except noticing it was missing.
    //
    // schema_version is edited rather than a bundle being written by an older build, for the same
    // reason the canonicalization tests do it, and the bundle is re-sealed afterwards: an earlier
    // build sealed its own output correctly, so a stale bundle arrives intact.

    [Fact]
    public void ABundleWrittenAgainstAnEarlierSchemaIsRefusedUnderItsOwnCode()
    {
        WriteABundleWrittenAgainstSchema(BundleSchema.Version - 1);

        using var opening = Open();

        Assert.Equal("Evidence.SchemaVersionUnsupported", opening.Error.Code);
    }

    [Fact]
    public void ABundleWrittenAgainstAnEarlierSchemaIsNotOpened()
    {
        WriteABundleWrittenAgainstSchema(BundleSchema.Version - 1);

        using var opening = Open();

        Assert.False(opening.IsSuccess);
    }

    /// <summary>
    /// A later schema is refused as firmly as an earlier one. Nothing here is kept backward
    /// compatible, and a build reading a bundle from a newer one is the case where guessing would
    /// be most tempting and least safe.
    /// </summary>
    [Fact]
    public void ABundleWrittenAgainstALaterSchemaIsAlsoRefused()
    {
        WriteABundleWrittenAgainstSchema(BundleSchema.Version + 1);

        using var opening = Open();

        Assert.Equal("Evidence.SchemaVersionUnsupported", opening.Error.Code);
    }

    /// <summary>
    /// The refusal names both numbers, for the reason its canonicalization sibling does.
    /// </summary>
    [Fact]
    public void TheSchemaRefusalNamesTheVersionStoredAndTheVersionThisBuildReads()
    {
        WriteABundleWrittenAgainstSchema(BundleSchema.Version - 1);

        using var opening = Open();

        Assert.Contains(
            (BundleSchema.Version - 1).ToString(),
            opening.Error.Description,
            StringComparison.Ordinal);
        Assert.Contains(
            BundleSchema.Version.ToString(),
            opening.Error.Description,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A bundle holding no descriptor holds no hash that could be stale. Refusing it would report
    /// a version problem to an operator whose problem is that nothing was captured.
    /// </summary>
    [Fact]
    public void ABundleThatCapturedNoDescriptorOpensWhateverTheVersion()
    {
        WriteABundle();

        using var opening = Open();

        Assert.True(opening.IsSuccess);
    }

    /// <summary>
    /// Every refusal carries the bundle it was about. An operator holding several runs cannot act
    /// on a sentence that does not say which one failed.
    /// </summary>
    [Fact]
    public void ARefusalNamesTheBundleItWasAbout()
    {
        WriteABundle();
        File.Delete(BundleLayout.SealPath(_directory));

        using var opening = Open();

        Assert.Contains(_directory, opening.Error.Context, StringComparison.Ordinal);
    }

    /// <summary>
    /// A bundle that will not open is an outcome a reasonable run produces, not a defect, so it
    /// arrives as a failed result rather than as an exception.
    /// </summary>
    [Fact]
    public void ARefusalIsAFailedResultAndNotAnException()
    {
        WriteABundle();
        File.Delete(BundleLayout.SealPath(_directory));

        using var opening = Open();

        Assert.Equal(ErrorSeverity.Failed, opening.Error.Severity);
    }

    // ---------------------------------------------------------------------------------------
    // Reading does not write
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The seal covers the evidence exactly as it was sealed, so a reader that journalled into
    /// the directory would invalidate the proof by the act of reading it.
    /// </summary>
    [Fact]
    public void OpeningABundleLeavesItStillIntact()
    {
        WriteABundle();

        using (var opening = Open())
            Assert.True(opening.IsSuccess);

        Assert.Equal(SealState.Intact, BundleSealing.Verify(_directory).State);
    }

    [Fact]
    public void OpeningABundleWritesNoJournalBesideIt()
    {
        WriteABundle();

        using (Open())
        {
        }

        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory) + "-wal"));
    }

    /// <summary>
    /// A reader that keeps the evidence file open after it is closed would stop a bundle being
    /// moved, copied or deleted by the operator who owns it.
    /// </summary>
    [Fact]
    public void AClosedReaderLetsGoOfTheEvidenceFile()
    {
        WriteABundle();

        using (Open())
        {
        }

        File.Delete(BundleLayout.EvidencePath(_directory));

        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory)));
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Opens the bundle under test. Disposable whether or not it opened, so a refused result can
    /// be written the same way as an accepted one.
    /// </summary>
    private Opening Open() => new(BundleReader.Open(_directory));

    private void WriteABundle() => WriteABundle(OneDomainRead());

    // ---------------------------------------------------------------------------------------
    // What the run covered
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The ordinary case, and the one a screen shows as <i>3 of 3 domains read</i>.
    /// </summary>
    [Fact]
    public void AWholeForestRunReportsEveryDomainRead()
    {
        WriteABundle(ThreeDomains(
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
            DomainCoverage.Read("us.contoso.com")));

        using var opening = Open();
        var scope = opening.Value.ReadScope();

        Assert.True(scope.IsSuccess);
        Assert.Equal(3, scope.Value.DeclaredCount);
        Assert.Equal(3, scope.Value.ReadCount);
        Assert.True(scope.Value.AllDeclaredDomainsAreComplete);
    }

    /// <summary>
    /// A sealed bundle cannot honestly say a domain was not read, so one that does is refused
    /// rather than counted.
    ///
    /// <para>
    /// Capture is fail-fast per <c>0003</c>: a domain that could not be read ends the run before
    /// anything is sealed, which is the guarantee <c>UnreadOutcomeIsUnreachableTests</c> holds over
    /// the whole product. Reading the state back here would be the first thing to break it, and a
    /// screen would then report a shortfall that the product's own rules say cannot exist.
    /// </para>
    /// </summary>
    [Fact]
    public void ASealedBundleClaimingADomainWasNotReadIsRefused()
    {
        WriteABundle(ThreeDomains(
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
            DomainCoverage.Read("us.contoso.com")));

        WithTheEvidenceOpen(
            "UPDATE domain_coverage SET outcome = 'NotRead', reason = 'No controller answered.' "
            + "WHERE domain_fqdn = 'us.contoso.com'");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        using var opening = Open();
        var scope = opening.Value.ReadScope();

        Assert.False(scope.IsSuccess);
        Assert.Equal("Evidence.CoverageImpossible", scope.Error.Code);
    }

    /// <summary>
    /// A domain the operator left out is counted apart from one that could not be read, per
    /// <c>0063</c>. An operator already knows what he excluded; the shortfall is the part he has
    /// not been told about, and merging the two would hide it.
    /// </summary>
    [Fact]
    public void AnExcludedDomainIsCountedApartFromAShortfall()
    {
        WriteABundle(ThreeDomainsExcluding(
            "us.contoso.com",
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
            DomainCoverage.Excluded(
                "us.contoso.com", ExclusionKind.ByChoice, "Believed to hold nothing.")));

        using var opening = Open();
        var scope = opening.Value.ReadScope();

        Assert.True(scope.IsSuccess);
        Assert.Equal(1, scope.Value.ExcludedCount);
        Assert.Equal(0, scope.Value.ShortfallCount);
        Assert.False(scope.Value.AllDeclaredDomainsAreComplete);
    }

    /// <summary>
    /// A partially read domain is not counted as read. It is a hole of unknown shape, and counting
    /// it would let a later comparison report fewer changes than really happened while looking
    /// exactly like one that found nothing.
    /// </summary>
    [Fact]
    public void APartiallyReadDomainIsNotCountedAsRead()
    {
        WriteABundle(ThreeDomains(
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
            DomainCoverage.PartiallyRead("us.contoso.com", "The controller stopped answering.")));

        using var opening = Open();
        var scope = opening.Value.ReadScope();

        Assert.True(scope.IsSuccess);
        Assert.Equal(2, scope.Value.ReadCount);
        Assert.Equal(1, scope.Value.ShortfallCount);
    }

    /// <summary>
    /// An outcome written by a later build is refused rather than mapped onto the nearest one this
    /// build knows. Reading it as <c>NotRead</c> would invent a failure and <c>Read</c> would
    /// invent a success; refusing leaves the caller able to say only that coverage could not be
    /// established, which is the one true statement available.
    /// </summary>
    [Fact]
    public void AnOutcomeThisBuildDoesNotRecogniseIsRefused()
    {
        WriteABundle(OneDomainRead());
        WithTheEvidenceOpen("UPDATE domain_coverage SET outcome = 'ReadOverATrust'");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        using var opening = Open();
        var scope = opening.Value.ReadScope();

        Assert.False(scope.IsSuccess);
        Assert.Equal("Evidence.CoverageUnrecognised", scope.Error.Code);
        Assert.Contains("ReadOverATrust", scope.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>Three declared domains, none excluded.</summary>
    private static RunCoverage ThreeDomains(params DomainCoverage[] domains) =>
        RunCoverage.Of(
            CoverageId.ForDomains(
                "contoso.com", ["contoso.com", "eu.contoso.com", "us.contoso.com"]),
            domains,
            BothForestPartitions(),
            SysvolCoverage.Of([]));

    /// <summary>Three declared domains, one of them deliberately left out.</summary>
    private static RunCoverage ThreeDomainsExcluding(
        string excluded, params DomainCoverage[] domains) =>
        RunCoverage.Of(
            CoverageId.ForDomainsExcluding(
                "contoso.com", ["contoso.com", "eu.contoso.com", "us.contoso.com"], [excluded]),
            domains,
            BothForestPartitions(),
            SysvolCoverage.Of([]));

    private static ForestPartitionCoverage[] BothForestPartitions() =>
    [
        ForestPartitionCoverage.Read(
            "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
        ForestPartitionCoverage.Read(
            "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
    ];

    private void WriteABundle(RunCoverage coverage)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());
        writer.Complete(coverage, Finished);
    }

    /// <summary>
    /// Writes a bundle holding one descriptor recorded as canonicalised by
    /// <paramref name="version"/>, sealed as an earlier build would have sealed its own output.
    /// </summary>
    private void WriteABundleCanonicalisedBy(int version)
    {
        using (var writer = BundleWriter.Create(_directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(AnObject());
            writer.WriteSecurityDescriptor(objectId, [0x01, 0x00, 0x04, 0x80], NoAces());
            writer.Complete(OneDomainRead(), Finished);
        }

        WithTheEvidenceOpen(
            $"UPDATE security_descriptor SET canonicalization_version = {version}");

        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));
    }

    /// <summary>
    /// Writes a bundle recorded as having been written against schema <paramref name="version"/>,
    /// sealed as the build that wrote it would have sealed its own output.
    /// </summary>
    private void WriteABundleWrittenAgainstSchema(int version)
    {
        WriteABundle();

        WithTheEvidenceOpen($"UPDATE bundle SET schema_version = {version}");

        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));
    }

    /// <summary>The one captured object the stale descriptor hangs off.</summary>
    private static EvidenceObject AnObject() =>
        new(SomeCoverage(), "CN=Alice,DC=contoso,DC=com", Guid.NewGuid(), [], Started);

    /// <summary>An empty entry set, so the test turns on the version and nothing else.</summary>
    private static AceNormalizationResult NoAces() => new(
        Guid.Empty,
        OwnerSid: null,
        GroupSid: null,
        DaclState.Present,
        IsDaclProtected: false,
        [],
        Errors: [],
        DaclCompleteness.Complete,
        DaclWasCanonical: true);

    private void EditTheEvidence() =>
        WithTheEvidenceOpen("UPDATE bundle SET forest_fqdn = 'fabrikam.com'");

    private void WithTheEvidenceOpen(string statement)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(_directory),
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
            }.ToString());

        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = statement;
        command.ExecuteNonQuery();
        connection.Close();
        SqliteConnection.ClearPool(connection);
    }

    /// <summary>The smallest coverage a sealed bundle can honestly carry.</summary>
    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    /// <summary>
    /// A run that sealed a bundle without reaching its one domain. Sealed evidence of an
    /// incomplete capture, which is a thing that exists.
    /// </summary>
    private static RunCoverage NoDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.NotRead("contoso.com", "No controller answered.")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        "DC=contoso,DC=com",
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    /// <summary>
    /// A result that can be written in a <c>using</c> whether it holds a reader or a refusal, so
    /// a test of a refusal does not have to remember not to dispose one.
    /// </summary>
    private readonly struct Opening(Result<BundleReader> result) : IDisposable
    {
        public bool IsSuccess => result.IsSuccess;

        public BundleReader Value => result.Value;

        public AuditError Error => result.Error!;

        public void Dispose()
        {
            if (result.IsSuccess)
                result.Value.Dispose();
        }
    }
}
