using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using SQLitePCL;
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
    public void DescriptorIdentityLookupDoesNotReconstructAccessEntries()
    {
        WriteABundleCanonicalisedBy(AceCanonicalization.Version);
        using var opening = Open();
        var reconstructedDescriptors = 0;
        var sentinel = false;
        strdelegate_trace callback = (_, sql) =>
        {
            if (sql == "SELECT 971") sentinel = true;
            if (sql.Contains("JOIN security_descriptor AS s", StringComparison.Ordinal))
                reconstructedDescriptors++;
        };
        raw.sqlite3_trace(opening.Value.Connection.Handle!, callback, null!);
        using (var command = opening.Value.Connection.CreateCommand())
        {
            command.CommandText = "SELECT 971";
            command.ExecuteScalar();
        }

        var descriptor = opening.Value.ReadDescriptorId(AnObject().DistinguishedName);

        raw.sqlite3_trace(opening.Value.Connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(callback);
        Assert.True(sentinel);
        Assert.NotNull(descriptor);
        Assert.Equal(0, reconstructedDescriptors);
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

    // ---------------------------------------------------------------------------------------
    // A policy's machine-side registry settings
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The machine-side settings come back, in the order the file stated them.
    /// </summary>
    /// <remarks>
    /// Ordering is load-bearing rather than tidiness: a policy may set the same value twice and a
    /// machine applies the last one, so a reader that returned them in any other order would hand a
    /// rule the wrong answer.
    /// </remarks>
    [Fact]
    public void APolicysMachineRegistrySettingsComeBackInFileOrder()
    {
        WriteABundleHoldingAPolicy(
        [
            (GpoSettingScope.Machine, "ADPasswordEncryptionPrincipal", "first"),
            (GpoSettingScope.Machine, "ADPasswordEncryptionPrincipal", "second"),
        ]);

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(PolicyGuid);

        Assert.Equal(GpoSettingsOutcome.Read, settings.Outcome);
        Assert.True(settings.IsComplete);
        Assert.Equal(["first", "second"], settings.Settings.Select(s => s.AsString()));
    }

    /// <summary>
    /// A setting written in the user scope is not returned as a machine setting.
    /// </summary>
    /// <remarks>
    /// <b>This is SEC-093's N3, and it can only be tested here.</b> The rule never sees a
    /// user-scope row, because the filter is in the query. LAPS is a machine policy, so a decryptor
    /// configured under the user half of a policy does not apply to any machine - and a reader that
    /// dropped the filter would have the rule report a finding against a setting that does nothing.
    /// </remarks>
    [Fact]
    public void ASettingInTheUserScopeIsNotReturnedAsAMachineSetting()
    {
        WriteABundleHoldingAPolicy(
        [
            (GpoSettingScope.User, "ADPasswordEncryptionPrincipal", "S-1-5-21-1-2-3-513"),
        ]);

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(PolicyGuid);

        Assert.True(settings.IsComplete);
        Assert.Empty(settings.Settings);
    }

    /// <summary>
    /// Only the machine half comes back when a policy configures both.
    /// </summary>
    [Fact]
    public void OnlyTheMachineHalfComesBackWhenAPolicyConfiguresBoth()
    {
        WriteABundleHoldingAPolicy(
        [
            (GpoSettingScope.User, "ADPasswordEncryptionPrincipal", "user side"),
            (GpoSettingScope.Machine, "ADPasswordEncryptionPrincipal", "machine side"),
        ]);

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(PolicyGuid);

        Assert.Equal(["machine side"], settings.Settings.Select(s => s.AsString()));
    }

    /// <summary>
    /// A policy whose folder could not be read says so, rather than coming back as a policy that
    /// configures nothing.
    /// </summary>
    /// <remarks>
    /// <b>The distinction gate 4 caught in SEC-093.</b> An empty list on its own cannot tell a rule
    /// whether a policy sets nothing or whether nobody looked, and a rule reading the first for the
    /// second reports a policy as harmless when it was never examined.
    /// </remarks>
    [Fact]
    public void APolicyWhoseFilesWereRefusedSaysSoRatherThanComingBackEmpty()
    {
        WriteABundleHoldingAPolicy([], GpoCoverage.Unreadable(
            PolicyGuid, "Workstation LAPS", @"\\contoso.com\SYSVOL\x", "Access is denied."));

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(PolicyGuid);

        Assert.Equal(GpoSettingsOutcome.Unreadable, settings.Outcome);
        Assert.False(settings.IsComplete);
        Assert.Empty(settings.Settings);
        Assert.Equal("Access is denied.", settings.Reason);
    }

    /// <summary>
    /// A policy some of whose files were read is reported as partially read, because a setting
    /// absent here may be in the part that was refused.
    /// </summary>
    [Fact]
    public void APolicyOnlyPartlyReadIsReportedAsPartiallyRead()
    {
        WriteABundleHoldingAPolicy([], GpoCoverage.PartiallyRead(
            PolicyGuid, "Workstation LAPS", @"\\contoso.com\SYSVOL\x", "One file was refused."));

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(PolicyGuid);

        Assert.Equal(GpoSettingsOutcome.PartiallyRead, settings.Outcome);
        Assert.False(settings.IsComplete);
    }

    /// <summary>
    /// A bundle captured without SYSVOL reports that nothing was read, rather than reporting every
    /// policy as configuring nothing.
    /// </summary>
    /// <remarks>
    /// A capture with no SYSVOL is a fact about the run; a policy with no settings is a fact about
    /// the policy. The two send an operator to different places, which is why they are kept apart.
    /// </remarks>
    [Fact]
    public void ABundleCapturedWithoutSysvolSaysNothingWasRead()
    {
        WriteABundle();

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(PolicyGuid);

        Assert.Equal(GpoSettingsOutcome.NotCaptured, settings.Outcome);
        Assert.False(settings.IsComplete);
        Assert.Empty(settings.Settings);
    }

    /// <summary>
    /// One policy's settings are not returned for another.
    /// </summary>
    [Fact]
    public void AnotherPolicysSettingsAreNotReturned()
    {
        WriteABundleHoldingAPolicy(
        [
            (GpoSettingScope.Machine, "ADPasswordEncryptionPrincipal", "S-1-5-21-1-2-3-513"),
        ]);

        using var opening = Open();
        var settings = opening.Value.ReadGpoMachineRegistrySettings(
            Guid.Parse("dddddddd-0000-0000-0000-00000000000d"));

        Assert.Equal(GpoSettingsOutcome.NotCaptured, settings.Outcome);
        Assert.Empty(settings.Settings);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    /// <summary>
    /// Closing a reader releases the file protection it holds, not merely its connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A reader opened over a <see cref="ProtectedStoreFile"/> takes ownership of that file's
    /// lease. Protection is meant to last while a reader is active; once the last one finishes,
    /// the owner must be able to move, replace or delete the closed run. Before this was fixed the
    /// reader closed only its connection, so the evidence and its seal stayed locked after both
    /// the reader and the store were disposed.
    /// </para>
    /// <para>
    /// Nothing here forces a collection, deliberately. A release that happens only once a
    /// finaliser runs is the defect rather than the fix, and a test that collects first would pass
    /// against the broken code and prove the opposite of what is wanted.
    /// </para>
    /// </remarks>
    [Fact]
    public void ClosingAReaderReleasesTheFilesItProtected()
    {
        WriteABundle();

        var store = ProtectedStoreFile.OpenEvidence(_directory).Value!;
        var reader = BundleReader.Open(store).Value!;

        store.Dispose();
        reader.Dispose();

        File.WriteAllText(BundleLayout.EvidencePath(_directory), "replacement");
        File.WriteAllText(BundleLayout.SealPath(_directory), "replacement");

        Assert.Equal(
            ("replacement", "replacement"),
            (File.ReadAllText(BundleLayout.EvidencePath(_directory)),
             File.ReadAllText(BundleLayout.SealPath(_directory))));
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Opens the bundle under test. Disposable whether or not it opened, so a refused result can
    /// be written the same way as an accepted one.
    /// </summary>
    private Opening Open() => new(BundleReader.Open(_directory));

    private void WriteABundle() => WriteABundle(OneDomainRead());

    private static readonly Guid PolicyGuid =
        Guid.Parse("a1b2c3d4-0000-0000-0000-000000000001");

    /// <summary>
    /// Writes a bundle holding one policy, its SYSVOL coverage, and the registry settings given.
    /// </summary>
    /// <param name="settings">Each setting's scope, value name and string value, in order.</param>
    /// <param name="coverage">
    /// What became of reading the policy's files. A policy read in full unless stated.
    /// </param>
    private void WriteABundleHoldingAPolicy(
        IReadOnlyList<(GpoSettingScope Scope, string ValueName, string Value)> settings,
        GpoCoverage? coverage = null)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());

        for (var ordinal = 0; ordinal < settings.Count; ordinal++)
        {
            var (scope, valueName, value) = settings[ordinal];

            writer.WriteGpoRegistrySetting(
                PolicyGuid,
                ordinal,
                scope,
                @"Software\Policies\Microsoft\Windows\LAPS",
                valueName,
                (uint)RegistryValueType.String,
                Encoding.Unicode.GetBytes(value + '\0'));
        }

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
                SysvolCoverage.Of(
                [
                    coverage ?? GpoCoverage.Read(
                        PolicyGuid, "Workstation LAPS", @"\\contoso.com\SYSVOL\x"),
                ])),
            Finished);
    }

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

    /// <summary>
    /// A bundle from an older build is missing the columns that build never had, and is still
    /// refused under the schema-version code rather than as unreadable evidence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The two tests above edit <c>schema_version</c> and leave every column in place, and that
    /// is why this defect survived them.</b> A real older bundle differs in both ways at once: the
    /// number is lower <i>and</i> the table is narrower. Reading the whole description first meant
    /// the <c>SELECT</c> failed on the missing column before the version could be compared, so the
    /// version gate — which was correct, and whose message was exactly right — could never fire for
    /// the bundles it exists to refuse.
    /// </para>
    /// <para>
    /// <b>Seen against <c>ad.lab</c> on 2026-09-03.</b> A schema 8 bundle opened against this
    /// schema 9 build reported <c>no such column: captured_attribute_catalog_version</c> and told
    /// the operator "this is a defect in this build rather than damage to the bundle". Neither was
    /// true, and he went looking for a defect that did not exist. This is the documented shape of a
    /// check that passes while measuring nothing.
    /// </para>
    /// <para>
    /// <b>Nothing here makes an old bundle readable.</b> It is refused exactly as firmly as before;
    /// what changes is that the refusal names the reason.
    /// </para>
    /// </remarks>
    [Fact]
    public void ABundleFromAnOlderBuildIsRefusedForItsVersionAndNotAsUnreadable()
    {
        WriteABundleShapedLikeAnOlderBuild();

        using var opening = Open();

        Assert.False(opening.IsSuccess);
        Assert.Equal("Evidence.SchemaVersionUnsupported", opening.Error.Code);

        // The operator must be told the version, not a column name from inside the database.
        Assert.DoesNotContain(
            "no such column", opening.Error.Description, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A bundle as an older build would have left it: recorded one version back, and without the
    /// column that version did not have.
    /// </summary>
    private void WriteABundleShapedLikeAnOlderBuild()
    {
        WriteABundle();

        // SQLite can drop a column, which is the closest this test can get to a table an earlier
        // build wrote without keeping a copy of that build around.
        WithTheEvidenceOpen(
            "ALTER TABLE bundle DROP COLUMN captured_attribute_catalog_version");

        WithTheEvidenceOpen(
            $"UPDATE bundle SET schema_version = {BundleSchema.Version - 1}");

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
