using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("SEC-027")]
    [InlineData("SEC-031")]
    [InlineData("SEC-032")]
    [InlineData("SEC-060")]
    [InlineData("SEC-090")]
    [InlineData("SEC-093")]
    public void CoverageProjectionAndWriterPreserveBothPartialAndCompleteEvidence(string ruleId)
    {
        foreach (var complete in new[] { false, true })
        {
            var directory = CoverageRun(ruleId, complete, out var finding);
            Assert.Equal(complete, FindingListItem.FromFinding(finding).EvidenceIsComplete);
            Assert.Equal(complete ? 1L : 0L, ReadSummaryCompleteness(directory));
            using var source = new BundleAssetSource();
            var read = source.ReadFindingsList(directory, FindingsQuery.Everything());
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.Equal(complete, Assert.Single(read.Value.Findings).EvidenceIsComplete);
            var display = new FindingRowViewModel(finding);
            Assert.Equal(complete ? "Complete" : "May be incomplete", display.Coverage);
            Assert.Equal(complete ? FactState.EstablishedGood : FactState.NotEstablished, display.State);
            Assert.Equal("May be incomplete", new FindingRowViewModel(finding with
            {
                Coverage = EvidenceCompleteness.MayBeMissingConfidentialValues,
            }).Coverage);
        }
    }

    [Theory]
    [InlineData("SEC-027")]
    [InlineData("SEC-031")]
    [InlineData("SEC-032")]
    [InlineData("SEC-060")]
    [InlineData("SEC-090")]
    [InlineData("SEC-093")]
    public void EarlierSummaryCoverageUsesSavedHeadersWithoutRewritingResults(string ruleId)
    {
        var directory = CoverageRun(ruleId, false, out var finding);
        ChangeFindingsDatabase(directory, "UPDATE finding SET evidence_complete=1");
        var before = CoverageFiles(directory);
        using (var counts = new FindingsVerificationCounts(directory))
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        using (var source = new BundleAssetSource())
        {
            foreach (var query in new[] { FindingsQuery.Everything(), FindingsQuery.About(FirstDn), FindingsQuery.Everything() })
            {
                var read = source.ReadFindingsList(directory, query);
                Assert.True(read.IsSuccess, read.Error?.Description);
                var item = Assert.Single(read.Value.Findings);
                Assert.False(item.EvidenceIsComplete);
                Assert.Equal((finding.Subject, finding.ObjectGuid, finding.RuleId, finding.Severity, finding.Detail),
                    (item.Subject, item.ObjectGuid, item.RuleId, item.Severity, item.Detail));
                Assert.Equal(1, read.Value.RulesRan);
                Assert.Equal("May be incomplete", new FindingRowViewModel(item).Coverage);
            }
            Assert.Equal((1L, 1L, 0L, 0L, 0L, 0L),
                (counts.Count("judgement"), counts.Count("permission"), counts.Count("path"),
                    counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
        Assert.Equal(1L, ReadSummaryCompleteness(directory));
    }

    [Fact]
    public void UnresolvedDecryptorCoverageRemainsIncompleteEvenWhenExpansionFinished()
    {
        var directory = CoverageRun("SEC-093", true, out var finding);
        finding = finding with
        {
            Evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence) with
            {
                DecryptorSid = null, DecryptorName = null, BroadPrincipalRoutes = [],
            },
        };
        WriteFindingsFixture(directory, [finding]);
        Assert.False(FindingListItem.FromFinding(finding).EvidenceIsComplete);
        Assert.Equal(0L, ReadSummaryCompleteness(directory));
        ChangeFindingsDatabase(directory, "UPDATE finding SET evidence_complete=1");
        using var source = new BundleAssetSource();
        var read = source.ReadFindingsList(directory, FindingsQuery.Everything());
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.False(Assert.Single(read.Value.Findings).EvidenceIsComplete);
    }

    public static IEnumerable<object[]> CoverageHeaderDefects()
    {
        foreach (var rule in new[] { "SEC-027", "SEC-031", "SEC-032", "SEC-060", "SEC-090", "SEC-093" })
            foreach (var defect in new[] { "missing", "invalid", "text" })
                yield return [rule, defect];
    }

    [Theory]
    [MemberData(nameof(CoverageHeaderDefects))]
    public void CoverageHeaderDefectIsAnExplicitRefusal(string ruleId, string defect)
    {
        var directory = CoverageRun(ruleId, false, out _);
        var (table, column) = CoverageHeader(ruleId);
        ChangeCoverageProof(directory, defect switch
        {
            "missing" when ruleId == "SEC-093" => """
                DELETE FROM finding_laps_decryptor_path;
                DELETE FROM finding_laps_decryptor_route;
                DELETE FROM finding_laps_decryptor
                """,
            "missing" => $"DELETE FROM {table}",
            "invalid" => $"UPDATE {table} SET {column}={(ruleId == "SEC-027" ? -1 : 2)}",
            "text" => $"UPDATE {table} SET {column}='not recorded'",
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        });
        using var source = new BundleAssetSource();
        var read = source.ReadFindingsList(directory, FindingsQuery.Everything());
        Assert.False(read.IsSuccess);
        Assert.NotNull(read.Error);
        Assert.Contains("completeness header", read.Error.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CoverageReadsOnlyReturnedHeadersAndDoesNotHydrateSupportingPaths()
    {
        var directory = CoverageRun("SEC-090", false, out var first);
        Finding second;
        using (var captured = BundleReader.Open(directory).Value)
            second = first with
            {
                Subject = new(FindingSubjectKind.DirectoryObject, "second saved finding"),
                ObjectGuid = Assert.IsType<Guid>(captured.ReadObjectAttributes(SecondDn)!.ObjectGuid),
                DistinguishedName = SecondDn,
            };
        WriteFindingsFixture(directory, [first, second]);
        using (var original = JudgementReader.Open(directory).Value)
            Assert.Single(original.ReadPage(FindingsQuery.About(FirstDn)).Value.Findings);
        ChangeFindingsDatabase(directory, "UPDATE finding SET evidence_complete=1");
        ChangeCoverageProof(directory, """
            UPDATE finding_laps_password_reader SET route_length=route_length+1 WHERE finding_id=1;
            DELETE FROM finding_laps_password_reader WHERE finding_id=2
            """);
        using var source = new BundleAssetSource();
        var firstPage = source.ReadFindingsList(directory, FindingsQuery.Everything() with { PageSize = 1 });
        Assert.True(firstPage.IsSuccess, firstPage.Error?.Description);
        Assert.False(Assert.Single(firstPage.Value.Findings).EvidenceIsComplete);
        Assert.True(firstPage.Value.HasMore);
        var next = Assert.IsType<FindingsPageMark>(firstPage.Value.Next);
        Assert.Equal(FindingsPublication(directory).GenerationId, next.GenerationId);
        using (var original = JudgementReader.Open(directory).Value)
            Assert.Throws<InvalidDataException>(() => original.ReadPage(FindingsQuery.About(FirstDn)));
        var later = source.ReadFindingsList(directory, FindingsQuery.Everything().ResumingAfter(next) with { PageSize = 1 });
        Assert.False(later.IsSuccess);
        Assert.Contains("completeness header", later.Error.Description, StringComparison.Ordinal);
        var selected = source.ReadFindingsList(directory, FindingsQuery.About(FirstDn));
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        Assert.Equal(first.Subject, Assert.Single(selected.Value.Findings).Subject);
    }

    [Fact]
    public void CoverageHeadersAreBoundToEachFindingRatherThanItsNameOrRowPosition()
    {
        var directory = CoverageRun("SEC-090", false, out var first);
        var second = first with
        {
            Subject = new(FindingSubjectKind.DirectoryObject, "another finding on the same object"),
            Evidence = Assert.IsType<LapsPasswordReaderEvidence>(first.Evidence) with { ExpansionWasComplete = true },
        };
        WriteFindingsFixture(directory, [first, second]);
        ChangeFindingsDatabase(directory, "UPDATE finding SET evidence_complete=1");
        using var source = new BundleAssetSource();
        var firstPage = source.ReadFindingsList(directory, FindingsQuery.About(FirstDn) with { PageSize = 1 });
        Assert.True(firstPage.IsSuccess, firstPage.Error?.Description);
        var firstItem = Assert.Single(firstPage.Value.Findings);
        Assert.Equal(first.Subject, firstItem.Subject);
        Assert.False(firstItem.EvidenceIsComplete);
        var later = source.ReadFindingsList(directory, FindingsQuery.About(FirstDn)
            .ResumingAfter(Assert.IsType<FindingsPageMark>(firstPage.Value.Next)) with { PageSize = 1 });
        Assert.True(later.IsSuccess, later.Error?.Description);
        var secondItem = Assert.Single(later.Value.Findings);
        Assert.Equal(second.Subject, secondItem.Subject);
        Assert.True(secondItem.EvidenceIsComplete);
        Assert.False(later.Value.HasMore);
    }

    [Theory]
    [InlineData("schema_version=0")]
    [InlineData("role='PathProof'")]
    [InlineData("generation='11111111-2222-3333-4444-555555555555'")]
    [InlineData("evidence_seal='foreign source'")]
    [InlineData("derivation_generation='11111111-2222-3333-4444-555555555555'")]
    public void CoverageMetadataRefusesForeignProofPartBindings(string change)
    {
        var directory = CoverageRun("SEC-031", false, out _);
        ChangeCoverageProof(directory, "UPDATE judgement_part SET " + change);
        using var source = new BundleAssetSource();
        var read = source.ReadFindingsList(directory, FindingsQuery.Everything());
        Assert.False(read.IsSuccess);
        Assert.Contains("saved proof part", read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SEC-027")]
    [InlineData("SEC-031")]
    [InlineData("SEC-032")]
    [InlineData("SEC-060")]
    [InlineData("SEC-090")]
    [InlineData("SEC-093")]
    public async Task BothFindingsEntryPointsKeepSavedCoverageAndReturnContext(string ruleId)
    {
        var directory = CoverageRun(ruleId, false, out _);
        ChangeFindingsDatabase(directory, "UPDATE finding SET evidence_complete=1");
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Null(screen.Refusal);
        Assert.Null(screen.ViewRefusal);
        var row = Assert.Single(screen.Findings);
        Assert.Equal("May be incomplete", row.Coverage);
        screen.RuleFilter = ruleId;
        await screen.ReadCompletion;
        row = Assert.Single(screen.Findings);
        screen.SelectedFinding = row;
        screen.OpenFinding(row);
        await screen.ObjectReadCompletion;
        Assert.Null(screen.ObjectRefusal);
        var section = screen.Findings();
        Assert.Null(section.Refusal);
        Assert.Equal("May be incomplete", Assert.Single(section.Findings).Coverage);
        screen.CloseObject();
        await screen.ReadCompletion;
        Assert.Equal(ruleId, screen.RuleFilter);
        Assert.Equal("May be incomplete", Assert.Single(screen.Findings).Coverage);
        Assert.NotNull(screen.SelectedFinding);
        Assert.Equal(ruleId, screen.SelectedFinding.Rule);
        screen.Suspend();
    }

    private static string CoverageRun(string ruleId, bool complete, out Finding finding)
    {
        var directory = LapsBundle.BuildMany(
            [(FirstDn, null, null, null, null, 512), (SecondDn, null, null, null, null, 512)], DateTimeOffset.UnixEpoch);
        using (var captured = BundleReader.Open(directory).Value)
            finding = new(ruleId, 1, ruleId == "SEC-031" ? Severity.Low : ruleId == "SEC-032" ? Severity.Medium : Severity.High,
                new(FindingSubjectKind.DirectoryObject, "saved coverage finding"),
                Assert.IsType<Guid>(captured.ReadObjectAttributes(FirstDn)!.ObjectGuid), FirstDn, "ad.lab", "computer",
                "Recorded finding with independently saved limitations.", EvidenceCompleteness.Complete, CoverageEvidence(ruleId, complete))
            { PrincipalName = "Recorded principal" };
        WriteFindingsFixture(directory, [finding]);
        return directory;
    }

    private static FindingEvidence CoverageEvidence(string ruleId, bool complete)
    {
        const string trustee = "S-1-5-21-1-2-3-1200";
        const string broad = "S-1-1-0";
        const string history = "S-1-5-21-4-5-6-512";
        PathStep[] path = [new(trustee, "Recorded group"), new(broad, "Everyone")];
        return ruleId switch
        {
            "SEC-027" => new PrivilegedSidHistoryEvidence("S-1-5-21-1-2-3-1100", [history],
                [new(history, 512, "Domain Admins")], complete ? 0 : 2),
            "SEC-031" or "SEC-032" => new ObjectOwnershipEvidence(trustee, "Recorded owner",
                ObjectOwnerStanding.Exists, "computer", complete),
            "SEC-060" => new ObjectTakeoverEvidence(trustee, "Recorded group", broad, "Everyone", path,
                ObjectTakeoverRight.WriteDacl, null, complete),
            "SEC-090" => new LapsPasswordReaderEvidence(trustee, "Recorded group", broad, "Everyone", path,
                "msLAPS-EncryptedPassword", LapsReadRights.Both, LapsGrantReach.ThisAttributeOnly, null, complete),
            "SEC-093" => new LapsDecryptorEvidence("Recorded policy", trustee, LapsDecryptorForm.SecurityIdentifier,
                trustee, "Recorded group", [new(broad, "Everyone", path)], complete),
            _ => throw new ArgumentOutOfRangeException(nameof(ruleId)),
        };
    }

    private static (string Table, string Column) CoverageHeader(string ruleId) => ruleId switch
    {
        "SEC-027" => ("finding_privileged_sid_history", "unreadable_values"),
        "SEC-031" or "SEC-032" => ("finding_object_ownership", "membership_was_complete"),
        "SEC-060" => ("finding_object_takeover", "expansion_was_complete"),
        "SEC-090" => ("finding_laps_password_reader", "expansion_was_complete"),
        "SEC-093" => ("finding_laps_decryptor", "expansion_was_complete"),
        _ => throw new ArgumentOutOfRangeException(nameof(ruleId)),
    };

    private static long ReadSummaryCompleteness(string directory)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, FindingsPublication(directory).Segment(StoreSegmentRole.Judgement).FileName),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT evidence_complete FROM finding";
        return Assert.IsType<long>(command.ExecuteScalar());
    }

    private static string[] CoverageFiles(string directory) =>
        FindingsPublication(directory).Segments.Select(segment => BundleSealing.HashFile(Path.Combine(directory, segment.FileName)))
            .Append(BundleSealing.HashFile(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement))).ToArray();

    private static void ChangeCoverageProof(string directory, string sql)
    {
        var root = FindingsPublication(directory);
        using (var connection = FindingsDatabase(Path.Combine(directory, root.Segment(StoreSegmentRole.PermissionProof).FileName)))
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            Assert.True(command.ExecuteNonQuery() > 0);
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
    }
}
