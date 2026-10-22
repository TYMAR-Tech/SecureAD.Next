using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    internal static async Task VerifyLightweightFindingsScreen(string directory)
    {
        FindingsPage original;
        Tier0FindingSummary? summary;
        using (var reader = JudgementReader.Open(directory).Value)
        {
            original = reader.ReadPage(FindingsQuery.Everything()).Value;
            Assert.False(original.HasMore);
            summary = reader.ReadTier0FindingSummary(CancellationToken.None);
            if (summary is not null)
            {
                var coverage = reader.ReadPathRiskCoverage(CancellationToken.None);
                Assert.Equal(coverage.CalculationFingerprint, summary.CalculationFingerprint);
                Assert.Equal(coverage.Families.Sum(family => family.Unknown), summary.UnresolvedAccessChecks);
                Assert.Equal(original.Findings.Count(finding => finding.RuleId == "SEC-071"), summary.AccountsWithFindings);
            }
        }
        var expected = original.Findings.Select(finding => FindingDisplaySnapshot(new(finding))).ToArray();
        var permissionHeaders = original.Findings.Any(finding => finding.Evidence is PrivilegedSidHistoryEvidence
            or ObjectOwnershipEvidence or ObjectTakeoverEvidence or LapsPasswordReaderEvidence or LapsDecryptorEvidence);
        using var counts = new FindingsVerificationCounts(directory);
        using var locks = new FindingsHeavyLocks(directory, permissionHeaders: permissionHeaders);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Null(screen.Refusal);
        Assert.Null(screen.ViewRefusal);
        Assert.False(screen.IsLoading);
        Assert.Equal(expected, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.Equal(SavedPathText.Summary(summary), screen.Tier0SummaryText);
        Assert.Equal(original.Findings.Count == 0, screen.NothingWasFound);
        for (var index = 0; index < original.Findings.Count; index++)
        {
            var proof = original.Findings[index].Evidence;
            var complete = original.Findings[index].Coverage == EvidenceCompleteness.Complete && (proof switch
            {
                KerberoastableAccountEvidence value => value.MembershipRoutes.IsComplete,
                BroadGroupMembershipEvidence value => value.IsComplete,
                GroupMembershipReviewEvidence value => value.IsComplete,
                DelegationConfigurationEvidence value => value.IsComplete,
                ServiceAccountFindingEvidence value => value.IsComplete,
                AttributeWritePermissionEvidence value => value.IsComplete,
                ReplicationPermissionEvidence value => value.IsComplete,
                PrivilegedSidHistoryEvidence value => value.IsComplete,
                ObjectOwnershipEvidence value => value.IsComplete,
                ObjectTakeoverEvidence value => value.IsComplete,
                LapsPasswordReaderEvidence value => value.IsComplete,
                LapsDecryptorEvidence value => value.IsComplete,
                _ => true,
            });
            Assert.Equal(complete ? "Complete" : "May be incomplete", screen.Findings[index].Coverage);
        }
        Assert.True(source.ReadRuleExecutions(directory).IsSuccess);
        Assert.True(source.ReadFindingsFilterValues(directory).IsSuccess);
        Assert.True(source.CaptureReadValidity()());
        screen.Pane = AssetsPane.Objects;
        await screen.ReadCompletion;
        screen.Pane = AssetsPane.Findings;
        await screen.ReadCompletion;
        Assert.Equal(expected, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.Equal((1L, permissionHeaders ? 1L : 0L, 0L, 0L, 0L, 0L),
            (counts.Count("judgement"), counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        screen.Suspend();
        source.CloseRun();
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Equal(expected, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.Equal((2L, permissionHeaders ? 2L : 0L, 0L, 0L, 0L, 0L),
            (counts.Count("judgement"), counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        FindingsViewTests.VerifySavedRowsRender(screen);
    }

    [Fact]
    public async Task Arch03CompleteFindingsScreenKeepsFilteringPagingSelectionAndRevisitsIsolated()
    {
        var directory = FindingsPagingRun();
        using var locks = new FindingsHeavyLocks(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Null(screen.ViewRefusal);
        Assert.Equal(50, screen.Findings.Count);
        Assert.True(screen.HasMoreFindings);
        Assert.Equal(("Display 000", "Recorded 000", "Complete"),
            (screen.Findings[0].Principal, screen.Findings[0].Detail, screen.Findings[0].Coverage));
        var first = screen.Findings.Select(FindingDisplaySnapshot).ToArray();
        screen.SelectedFinding = screen.Findings[0];
        Assert.True(screen.SelectedFinding.HasGuidance);
        screen.CloseFindingDetails();
        Assert.Null(screen.SelectedFinding);
        screen.NextFindings();
        await screen.ReadCompletion;
        Assert.Equal(5, screen.Findings.Count);
        Assert.Equal(new[] { "Extra 0", "Extra 1", "Extra 2", "Display 050", "Low display" },
            screen.Findings.Select(row => row.Principal));
        Assert.False(screen.HasMoreFindings);
        screen.PreviousFindings();
        await screen.ReadCompletion;
        Assert.Equal(first, screen.Findings.Select(FindingDisplaySnapshot));
        screen.SeverityFilter = "Low";
        await screen.ReadCompletion;
        Assert.Equal("Low display", Assert.Single(screen.Findings).Principal);
        screen.RuleFilter = "SEC-022";
        await screen.ReadCompletion;
        Assert.True(screen.NothingWasFound);
        Assert.Empty(screen.Findings);
        Assert.Null(screen.ViewRefusal);
        screen.ClearFindingsFilters();
        await screen.ReadCompletion;
        Assert.Equal(first, screen.Findings.Select(FindingDisplaySnapshot));
        screen.RuleFilter = "SEC-022";
        await screen.ReadCompletion;
        Assert.Equal(first, screen.Findings.Select(FindingDisplaySnapshot));
        screen.Pane = AssetsPane.Objects;
        await screen.ReadCompletion;
        screen.Pane = AssetsPane.Findings;
        await screen.ReadCompletion;
        Assert.Equal(first, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.Equal((1L, 0L), (counts.Count("judgement"), counts.Heavy));
        screen.Suspend();
    }

    [Fact]
    public async Task Arch03ObjectFindingsAndReturnNavigationDoNotOpenOriginalProof()
    {
        var directory = FindingsPagingRun();
        using var locks = new FindingsHeavyLocks(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        var before = screen.Findings.Select(FindingDisplaySnapshot).ToArray();
        screen.OpenFinding(screen.Findings[0]);
        await screen.ObjectReadCompletion;
        Assert.NotNull(screen.Opened);
        Assert.Null(screen.ObjectRefusal);
        Assert.Equal(ObjectSectionCatalog.Findings, screen.Opened.Selected!.Key);
        var findings = screen.Findings();
        Assert.Null(findings.Refusal);
        Assert.Equal(new[] { "SEC-022", "SEC-030" }, findings.Findings.Select(finding => finding.Rule));
        Assert.Equal("Display 000", findings.Findings[0].Principal);
        Assert.Equal(0L, counts.Heavy);
        screen.CloseObject();
        await screen.ReadCompletion;
        Assert.Equal(before, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.Equal((1L, 0L), (counts.Count("judgement"), counts.Proof));
        screen.Suspend();
    }

    internal static async Task VerifySavedRouteAction(string directory)
    {
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Null(screen.ViewRefusal);
        var row = Assert.Single(screen.Findings, finding => finding.HasTier0Routes);
        var before = screen.Findings.Select(FindingDisplaySnapshot).ToArray();
        Assert.Equal(0L, counts.Heavy);
        screen.OpenSavedRoutesCommand.Execute(row);
        await screen.ObjectReadCompletion;
        Assert.NotNull(screen.Opened);
        Assert.Null(screen.ObjectRefusal);
        var saved = source.ReadSavedTier0Path(directory, row.DistinguishedName).Value!;
        Assert.True(saved.IsBound);
        Assert.Equal(FindingsPublication(directory).GenerationId, saved.Description.GenerationId);
        Assert.Equal(saved.Description.GenerationId, saved.Page.Coverage.GenerationId);
        Assert.Equal(UserDn, saved.Account!.DistinguishedName);
        Assert.NotEmpty(saved.Page.Questions);
        Assert.True(counts.Count("permission") > 0);
        Assert.True(counts.Count("path") > 0);
        screen.CloseObject();
        await screen.ReadCompletion;
        Assert.Equal(before, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.Equal(1L, counts.Count("judgement"));
        screen.Suspend();
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("missing")]
    [InlineData("seal")]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    [InlineData("schema")]
    [InlineData("kind")]
    [InlineData("completeness")]
    public async Task Arch03CompleteFindingsScreenRefusesMissingCorruptOrForeignProducts(string defect)
    {
        var directory = CreateRun();
        var root = FindingsPublication(directory);
        var path = Path.Combine(directory, root.Segment(StoreSegmentRole.Judgement).FileName);
        if (defect == "bytes") File.AppendAllText(path, "corrupt");
        else if (defect == "missing") File.Delete(path);
        else if (defect == "seal") File.Delete(path + ".seal");
        else
        {
            ChangeFindingsDatabase(directory, defect switch
            {
                "generation" => "UPDATE judgement SET judgement_generation_id='11111111-2222-3333-4444-555555555555'",
                "evidence" => "UPDATE judgement SET evidence_seal='foreign evidence'",
                "derivation" => "UPDATE judgement SET derivation_generation_id='11111111-2222-3333-4444-555555555555'",
                "schema" => "UPDATE judgement SET schema_version=999",
                "kind" => "PRAGMA ignore_check_constraints=ON; UPDATE finding SET list_kind='Unknown'",
                "completeness" => "PRAGMA ignore_check_constraints=ON; UPDATE finding SET evidence_complete=7",
                _ => throw new ArgumentOutOfRangeException(nameof(defect)),
            });
        }
        using var locks = new FindingsHeavyLocks(directory, publication: root);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.NotNull(screen.ViewRefusal);
        Assert.Empty(screen.Findings);
        Assert.False(screen.NothingWasFound);
        Assert.False(screen.IsLoading);
        screen.Suspend();
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("availability")]
    [InlineData("unresolved")]
    [InlineData("calculation")]
    public async Task Arch03CompleteFindingsScreenRefusesContradictorySmallSec071Summary(string defect)
    {
        var directory = UnexpectedFindingsPathRun();
        ChangeFindingsDatabase(directory, defect switch
        {
            "missing" => "DELETE FROM tier0_finding_product",
            "availability" => "UPDATE tier0_finding_product SET availability='NotRequested'",
            "unresolved" => "UPDATE tier0_finding_product SET unresolved_checks=unresolved_checks+1",
            "calculation" => "UPDATE tier0_path_calculation SET fingerprint=zeroblob(32)",
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        });
        using var locks = new FindingsHeavyLocks(directory);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.NotNull(screen.ViewRefusal);
        Assert.Empty(screen.Findings);
        Assert.False(screen.NothingWasFound);
        screen.Suspend();
    }

    [Fact]
    public async Task Arch03CancelledFindingsReadCannotPublishAlreadyReadRows()
    {
        var directory = CreateRun();
        using var locks = new FindingsHeavyLocks(directory);
        using var source = new BundleAssetSource();
        using var stopping = new CancellationTokenSource();
        source.SelectRun(directory);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.ReadAsync(directory, (reader, _) =>
        {
            var page = reader.ReadFindingsList(directory, FindingsQuery.Everything());
            Assert.True(page.IsSuccess, page.Error?.Description);
            stopping.Cancel();
            return page;
        }, stopping.Token));
    }

    [Fact]
    public void Arch03FindingsContinuationRefusesForeignAndUnboundGenerations()
    {
        var directory = FindingsPagingRun();
        using var source = new BundleAssetSource();
        var first = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value;
        var mark = Assert.IsType<FindingsPageMark>(first.Next);
        Assert.Equal(FindingsPublication(directory).GenerationId, mark.GenerationId);
        foreach (var generation in new Guid?[] { null, Guid.NewGuid() })
        {
            var read = source.ReadFindingsList(directory, FindingsQuery.Everything().ResumingAfter(mark with { GenerationId = generation }));
            Assert.False(read.IsSuccess);
            Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error.Code);
        }
    }

    [Fact]
    public void Arch03SupportingMembershipAndOriginalDetailsAreSelectionLocal()
    {
        var directory = FindingsMembershipRun();
        ChangeFindingsDatabase(directory, """
            UPDATE membership_route SET authorization='Broken' WHERE subject_id='2'
            """);
        using var source = new BundleAssetSource();
        var first = source.ReadFindingsList(directory, FindingsQuery.Everything() with { PageSize = 1 });
        Assert.True(first.IsSuccess, first.Error?.Description);
        var display = new FindingRowViewModel(Assert.Single(first.Value.Findings));
        Assert.True(display.HasMembershipEvidence);
        Assert.Equal("May be incomplete", display.Coverage);
        Assert.Contains("Direct protection basis: Recorded direct protection", display.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("Initial membership:", display.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("--primary group-->", display.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("Contains a distribution group", display.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("not every possible path", display.MembershipDetails, StringComparison.Ordinal);
        Assert.Contains("membership evidence or capture coverage is incomplete", display.MembershipCompleteness, StringComparison.Ordinal);
        var original = source.ReadFindings(directory, FindingsQuery.Everything() with { PageSize = 1 });
        Assert.True(original.IsSuccess, original.Error?.Description);
        Assert.Equal(new[] { "HTTP/a.ad.lab", "HTTP/a.ad.lab" },
            Assert.IsType<KerberoastableAccountEvidence>(Assert.Single(original.Value.Findings).Evidence).ServicePrincipalNames);
        var later = source.ReadFindingsList(directory, FindingsQuery.Everything().ResumingAfter(first.Value.Next!.Value));
        Assert.False(later.IsSuccess);
        Assert.NotNull(later.Error);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Judgement)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    [InlineData(StoreSegmentRole.PathProof)]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    public void Arch03FailedPublicationPreservesTheExactPreviousLightweightResult(StoreSegmentRole role)
    {
        var directory = CreateRun();
        var root = FindingsPublication(directory);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var previous = File.ReadAllBytes(manifest);
        var hashes = root.Segments.Select(segment => BundleSealing.HashFile(Path.Combine(directory, segment.FileName))).ToArray();
        using var writer = JudgementWriter.Create(directory, root.EvidenceSeal, null, Started, Started);
        Directory.CreateDirectory(BundleLayout.AnalysisSegmentDataPath(directory, new(AnalysisStoreKind.Judgement, writer.GenerationId), role) + ".seal");
        Assert.Throws<UnauthorizedAccessException>(() => writer.Complete(Started));
        Assert.Equal(previous, File.ReadAllBytes(manifest));
        Assert.Equal(hashes, root.Segments.Select(segment => BundleSealing.HashFile(Path.Combine(directory, segment.FileName))));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(2, reader.ReadListPage(FindingsQuery.Everything()).Value.Findings.Count);
        Assert.Equal(root.GenerationId, reader.Description.GenerationId);
    }

    [Fact]
    public void Arch03NativeFindingsSchemaContainsOnlyServingValues()
    {
        var directory = AttributeWriteRuleTests.FindingsRun();
        var root = FindingsPublication(directory);
        using var connection = FindingsDatabase(Path.Combine(directory, root.Segment(StoreSegmentRole.Judgement).FileName));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
        var tables = new List<string>();
        using var rows = command.ExecuteReader();
        while (rows.Read()) tables.Add(rows.GetString(0));
        Assert.Equal(new[]
        {
            "finding", "finding_circular_group", "group_inventory", "group_inventory_product", "judgement",
            "laps_inventory", "laps_inventory_product",
            "member_attribution_product", "membership_route",
            "membership_route_step", "membership_route_summary", "rule_execution", "rule_execution_missing_input",
            "tier0_distance", "tier0_distance_product", "tier0_finding_product", "tier0_path_calculation",
        }, tables);
    }

    [Fact]
    public void Arch03FinalCancellationPreservesThePreviousLightweightGeneration()
    {
        var directory = CreateRun();
        var root = FindingsPublication(directory);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var previous = File.ReadAllBytes(manifest);
        using var stopping = new CancellationTokenSource();
        var sealedParts = 0;
        var log = new JudgingStatusTests.StatusLog(line =>
        {
            if (line.Message == "file sealing" && line.Value("artifact") == AnalysisStoreKind.Judgement.ToString()
                && ++sealedParts == 4) stopping.Cancel();
        });
        using var writer = JudgementWriter.Create(directory, root.EvidenceSeal, null, Started, Started);
        Assert.Throws<OperationCanceledException>(() => writer.Complete(Started, stopping.Token, null, log));
        Assert.Equal(4, sealedParts);
        Assert.Equal(previous, File.ReadAllBytes(manifest));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(2, reader.ReadListPage(FindingsQuery.Everything()).Value.Findings.Count);
        Assert.Equal(root.GenerationId, reader.Description.GenerationId);
    }

    private static string FindingDisplaySnapshot(FindingRowViewModel row) => JsonSerializer.Serialize(new
    {
        row.Severity, row.Rank, row.Rule, row.Principal, row.Target, row.DistinguishedName, row.Domain, row.Detail,
        row.Coverage, row.State, row.HasTier0Routes, row.HasMembershipEvidence, row.MembershipCompleteness,
        row.MembershipDetails, row.HasGuidance, row.WhyItMatters, row.WhatToDo, row.About, row.Category, row.MicrosoftReference,
    });

    private static string FindingsPagingRun()
    {
        var names = Enumerable.Range(0, 51).Select(index => $"CN=A{index:D3},DC=ad,DC=lab").ToArray();
        var directory = LapsBundle.BuildMany(names.Select(dn => (dn, (string?)null, (string?)null, (string?)null, (string?)null, 0x400202u)).ToArray(),
            DateTimeOffset.UnixEpoch);
        var findings = new List<Finding>();
        using (var evidence = BundleReader.Open(directory).Value)
            for (var index = 0; index < names.Length; index++)
            {
                var captured = evidence.ReadObjectAttributes(names[index])!;
                var finding = new Finding("SEC-022", 1, Severity.High, new(FindingSubjectKind.Account, names[index]),
                    Assert.IsType<Guid>(captured.ObjectGuid), names[index], "ad.lab", "computer", $"Recorded {index:D3}",
                    EvidenceCompleteness.Complete, new UserAccountControlEvidence(0x400202)) { PrincipalName = $"Display {index:D3}" };
                findings.Add(finding);
                if (index == 49)
                    for (var extra = 0; extra < 3; extra++)
                        findings.Add(finding with { Subject = new(FindingSubjectKind.Account, names[index] + ":" + extra), PrincipalName = "Extra " + extra });
            }
        findings.Add(findings[0] with
        {
            RuleId = "SEC-030", Severity = Severity.Low, Detail = "Recorded low finding", PrincipalName = "Low display",
            Evidence = new AdminCountWithoutProtectionEvidence("S-1-5-21-1-2-3-1100"),
        });
        WriteFindingsFixture(directory, findings);
        return directory;
    }

    private static string FindingsMembershipRun()
    {
        var directory = CreateRun();
        var initial = new MembershipRoutePrincipal("S-1-5-21-1-2-3-1200", "ad.lab", "CN=Recorded initial group,DC=ad,DC=lab");
        var root = new MembershipRoutePrincipal("S-1-5-21-1-2-3-512", "ad.lab", "CN=Recorded privileged group,DC=ad,DC=lab");
        var reason = MembershipRouteIncompleteReason.MembershipEvidenceIncomplete;
        var routes = new MembershipRouteSummary([new(initial,
            [new(2, "Recorded privileged root", MembershipRouteAuthorization.DistributionGroup, false,
                [new(new("S-1-5-21-1-2-3-1100", null, FirstDn), false), new(initial, true), new(root, false)])], reason)], reason);
        using var captured = BundleReader.Open(directory).Value;
        var findings = new[] { FirstDn, SecondDn }.Select((dn, index) => new Finding("SEC-021", 1, Severity.Critical,
            new(FindingSubjectKind.Account, dn), Assert.IsType<Guid>(captured.ReadObjectAttributes(dn)!.ObjectGuid), dn, "ad.lab", "computer", "Recorded membership finding",
            EvidenceCompleteness.Complete, new KerberoastableAccountEvidence("S-1-5-21-1-2-3-" + (1100 + index),
                ["HTTP/a.ad.lab", "HTTP/a.ad.lab"], 512, 0)
            {
                ProtectionCatalogueVersion = 2,
                DirectProtectionCatalogueEntryId = 500,
                DirectProtectionName = "Recorded direct protection",
                MembershipRoutes = routes,
            }) { PrincipalName = "Recorded member " + index }).ToArray();
        WriteFindingsFixture(directory, findings);
        return directory;
    }

    private static void WriteFindingsFixture(string directory, IReadOnlyList<Finding> findings)
    {
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!;
        using var writer = JudgementWriter.Create(directory, seal.Hash, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        foreach (var group in findings.GroupBy(finding => finding.RuleId, StringComparer.Ordinal))
            writer.Write(RuleExecution.Judged(new(group.Key, "Recorded display fixture", group.First().Severity, 1,
                ["computer"], ["userAccountControl"], []), group.Count(), 0, group.ToArray()));
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
    }

    private static string UnexpectedFindingsPathRun()
    {
        var directory = Bundle(members: [], rootDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})",
            writeAdditional: (writer, domain) =>
            {
                var guid = Guid.NewGuid();
                var id = writer.WriteObject(new(domain, CoreDn, guid,
                [
                    new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("group")]),
                    new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-512")!)]),
                    new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                    new("member", StoredAttributeCompleteness.Complete, []),
                ], Started));
                var descriptor = new RawSecurityDescriptor("O:S-1-5-21-1-2-3G:SYD:");
                var bytes = new byte[descriptor.BinaryLength];
                descriptor.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
            });
        Derive(directory);
        var judged = JudgingRun.JudgeWithTier0Discovery(directory, [new UnexpectedTier0Route()], [new RequesterDaclRequest(UserDn, "DC=contoso,DC=com")], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, selfMembershipDiscoveryBudget: null, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    private static StoreRootManifest FindingsPublication(string directory) =>
        AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;

    private static SqliteConnection FindingsDatabase(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    private static void ChangeFindingsDatabase(string directory, string sql)
    {
        var root = FindingsPublication(directory);
        using (var connection = FindingsDatabase(Path.Combine(directory, root.Segment(StoreSegmentRole.Judgement).FileName)))
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            Assert.True(command.ExecuteNonQuery() > 0);
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
    }

    private sealed class FindingsHeavyLocks : IDisposable
    {
        private readonly List<FileStream> _files = [];
        internal FindingsHeavyLocks(string directory, bool capture = true, StoreRootManifest? publication = null,
            bool permissionHeaders = false)
        {
            var paths = (publication ?? FindingsPublication(directory)).Segments.Where(segment => segment.Role != StoreSegmentRole.Judgement
                    && (!permissionHeaders || segment.Role != StoreSegmentRole.PermissionProof))
                .Select(segment => Path.Combine(directory, segment.FileName)).ToList();
            if (capture)
            {
                paths.Add(Path.Combine(directory, BundleLayout.EvidenceFileName));
                var derivation = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation);
                if (derivation.IsSuccess)
                    paths.Add(Path.Combine(directory, derivation.Value.Segment(StoreSegmentRole.Derivation).FileName));
            }
            foreach (var path in paths) _files.Add(new(path, FileMode.Open, FileAccess.Read, FileShare.None));
        }
        public void Dispose()
        {
            foreach (var file in _files) file.Dispose();
        }
    }

    private sealed class FindingsVerificationCounts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new(StringComparer.Ordinal);
        internal FindingsVerificationCounts(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name == "store.verifications") listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                foreach (var tag in tags)
                {
                    if (tag.Value is not string path || !path.StartsWith(directory, StringComparison.OrdinalIgnoreCase)) continue;
                    var name = Path.GetFileName(path);
                    var kind = name.Contains(".permission-proof.", StringComparison.Ordinal) ? "permission"
                        : name.Contains(".path-proof.", StringComparison.Ordinal) ? "path"
                        : name.Contains(".facts.", StringComparison.Ordinal) ? "facts" : name.Split('.')[0];
                    _counts.AddOrUpdate(kind, value, (_, count) => count + value);
                }
            });
            _listener.Start();
        }
        internal long Count(string kind) => _counts.GetValueOrDefault(kind);
        internal long Proof => Count("permission") + Count("path") + Count("facts");
        internal long Heavy => Proof + Count("evidence") + Count("derivation");
        public void Dispose() => _listener.Dispose();
    }
}
