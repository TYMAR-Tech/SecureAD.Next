using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(127)]
    public void SidHistoryPagesKeepAllSavedOccurrencesAndExistingCatalogueAnswers(int flagged)
    {
        var directory = SidHistoryRun(flagged, 51, out var finding);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(SavedSidHistory.Statement, row.Detail);
            Assert.False(row.EvidenceIsComplete);
            var first = source.ReadSidHistory(directory, row.Reference!.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal(2, first.Value.Context.UnreadableValues);
            var ordinals = new List<int>();
            var page = first.Value;
            do
            {
                Assert.All(page.Values, value => Assert.Equal(PrivilegedSidCatalogue.PrivilegedName(value.Sid), value.RecognisedType));
                ordinals.AddRange(page.Values.Select(value => value.Ordinal));
                if (page.Next is not { } next) break;
                var read = source.ReadSidHistory(directory, row.Reference.Value, next);
                Assert.True(read.IsSuccess, read.Error?.Description);
                page = read.Value;
            } while (true);
            var history = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence).HistoryValues;
            Assert.Equal(history.Select((sid, ordinal) => (sid, ordinal))
                .Where(value => PrivilegedSidCatalogue.PrivilegedName(value.sid) is not null).Select(value => value.ordinal), ordinals);
            var other = source.ReadSidHistory(directory, row.Reference.Value, first.Value.Start with { Kind = SidHistoryPageKind.Other });
            Assert.True(other.IsSuccess, other.Error?.Description);
            Assert.Equal(50, other.Value.Values.Count);
            Assert.All(other.Value.Values, value => Assert.Null(value.RecognisedType));
            var last = source.ReadSidHistory(directory, row.Reference.Value, other.Value.Next);
            Assert.True(last.IsSuccess, last.Error?.Description);
            Assert.Equal(history.Select((sid, ordinal) => (sid, ordinal))
                .Last(value => PrivilegedSidCatalogue.PrivilegedName(value.sid) is null).ordinal, Assert.Single(last.Value.Values).Ordinal);
            Assert.Null(last.Value.Next);
            Assert.Equal(finding.ObjectGuid, last.Value.Context.Object.ObjectGuid);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing-values")]
    [InlineData("sid")]
    [InlineData("object-sid")]
    public void SidHistoryRefusesInvalidOrMissingSavedValues(string defect)
    {
        var directory = SidHistoryRun(1, 0, out _);
        ChangeCoverageProof(directory, defect switch
        {
            "missing-values" => "DELETE FROM finding_privileged_sid_history_value",
            "sid" => "UPDATE finding_privileged_sid_history_value SET sid='not a SID'",
            _ => "UPDATE finding_privileged_sid_history SET object_sid='not a SID'",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadSidHistory(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedSidHistory.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("object")]
    [InlineData("kind")]
    [InlineData("negative")]
    [InlineData("past-end")]
    public void SidHistoryContinuationRemainsBoundToTheSelectedSavedQuestion(string defect)
    {
        var directory = SidHistoryRun(51, 0, out _);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var first = source.ReadSidHistory(directory, row.Reference!.Value, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var mark = first.Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "finding" => mark with { FindingId = mark.FindingId + 1 },
            "object" => mark with { ObjectGuid = Guid.NewGuid() },
            "kind" => mark with { Kind = (SidHistoryPageKind)99 },
            "negative" => mark with { Ordinal = -2 },
            _ => mark with { Ordinal = 100000 },
        };
        Assert.False(source.ReadSidHistory(directory, row.Reference.Value, mark).IsSuccess);
    }

    [Fact]
    public void SidHistoryMissingObjectSidAndNoOtherValuesDoNotSuppressTheFinding()
    {
        var directory = SidHistoryRun(1, 0, out _, ownSid: false);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var first = source.ReadSidHistory(directory, row.Reference!.Value, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        Assert.Null(first.Value.Context.ObjectSid);
        Assert.Single(first.Value.Values);
        var other = source.ReadSidHistory(directory, row.Reference.Value, first.Value.Start with { Kind = SidHistoryPageKind.Other });
        Assert.True(other.IsSuccess, other.Error?.Description);
        Assert.Empty(other.Value.Values);
        Assert.Null(other.Value.Next);
    }

    private static string SidHistoryRun(int flagged, int other, out Finding finding, bool ownSid = true)
    {
        var directory = LapsBundle.BuildMany([(FirstDn, null, null, null, null, 512)], DateTimeOffset.UnixEpoch);
        var values = Enumerable.Range(0, flagged).Select(index => (Ordinal: index * 2, Sid: "S-1-5-21-1-2-3-512", Flagged: true))
            .Concat(Enumerable.Range(0, other).Select(index => (Ordinal: index * 2 + 1, Sid: $"S-1-5-21-1-2-3-{1200 + index}", Flagged: false)))
            .OrderBy(value => value.Ordinal).ToArray();
        var evidence = new PrivilegedSidHistoryEvidence(ownSid ? "S-1-5-21-1-2-3-1100" : null,
            values.Select(value => value.Sid).ToArray(), values.Where(value => value.Flagged)
                .Select(value => new PrivilegedSidHistoryMatch(value.Sid, 512, "Domain Admins")).ToArray(), 2);
        using (var captured = BundleReader.Open(directory).Value)
            finding = new("SEC-027", 1, Severity.High, new(FindingSubjectKind.Account, "Recorded principal"),
                Assert.IsType<Guid>(captured.ReadObjectAttributes(FirstDn)!.ObjectGuid), FirstDn, "ad.lab", "computer",
                "Original full SID-history prose must not be loaded.", EvidenceCompleteness.Complete, evidence) { PrincipalName = "Recorded principal" };
        WriteFindingsFixture(directory, [finding]);
        return directory;
    }
}
