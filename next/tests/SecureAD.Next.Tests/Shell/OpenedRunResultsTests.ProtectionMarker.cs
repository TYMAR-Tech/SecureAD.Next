using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public void ProtectionMarkerReadsARealExistingRulePublicationWithoutRejudging()
    {
        var directory = AdminCountWithoutProtectionTests.FindingsRun();
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var read = source.ReadProtectionMarker(directory, row.Reference!.Value);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Matches(row));
            Assert.Equal("S-1-5-21-11-22-33-1105", read.Value.Sid);
            Assert.Equal("Medium", new SecureAD.Shell.ViewModels.FindingRowViewModel(row).Severity);
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void ProtectionMarkerReadsOnlyTheSelectedSavedAssessmentWithoutInputReplay()
    {
        var directory = ProtectionMarkerRun();
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            Assert.Equal(SavedProtectionMarker.Statement, row.Detail);
            var read = source.ReadProtectionMarker(directory, row.Reference!.Value);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Matches(row));
            Assert.Equal("S-1-5-21-1-2-3-1100", read.Value.Sid);
            Assert.True(source.ReadProtectionMarker(directory, row.Reference.Value).IsSuccess);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("sid")]
    public void ProtectionMarkerRefusesMissingOrMalformedSavedIdentity(string defect)
    {
        var directory = ProtectionMarkerRun();
        ChangeCoverageProof(directory, defect == "missing" ? "DELETE FROM finding_admincount_without_protection"
            : "UPDATE finding_admincount_without_protection SET sid='not a SID'");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadProtectionMarker(directory, row.Reference!.Value);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedProtectionMarker.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProtectionMarkerCannotSubstituteAnotherGenerationOrFinding(bool generation)
    {
        var directory = ProtectionMarkerRun();
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = reference.FindingId + 1 };
        Assert.False(source.ReadProtectionMarker(directory, reference).IsSuccess);
    }

    [Fact]
    public void ProtectionMarkerDoesNotTreatAnotherRulesSavedIdentityAsThisAssessment()
    {
        var directory = SidHistoryRun(1, 0, out _);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var read = source.ReadProtectionMarker(directory, reference);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedProtectionMarker.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    private static string ProtectionMarkerRun()
    {
        var directory = LapsBundle.BuildMany([(FirstDn, null, null, null, null, 512)], DateTimeOffset.UnixEpoch);
        using var captured = BundleReader.Open(directory).Value;
        var finding = new Finding("SEC-030", 1, Severity.Medium, new(FindingSubjectKind.Account, "Recorded principal"),
            Assert.IsType<Guid>(captured.ReadObjectAttributes(FirstDn)!.ObjectGuid), FirstDn, "ad.lab", "computer",
            "The original saved marker explanation must not be loaded.", EvidenceCompleteness.Complete,
            new AdminCountWithoutProtectionEvidence("S-1-5-21-1-2-3-1100")) { PrincipalName = "Recorded principal" };
        WriteFindingsFixture(directory, [finding]);
        return directory;
    }
}
