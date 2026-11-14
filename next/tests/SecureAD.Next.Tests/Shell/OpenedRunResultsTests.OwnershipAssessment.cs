using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    public static IEnumerable<object[]> SavedOwnerCases() => OwnershipAssessmentDetailTests.AssessmentCases();
    public static IEnumerable<object[]> InvalidOwnerCases() => new[] { "SEC-031", "SEC-032" }.SelectMany(rule =>
        new[] { "sid", "standing", "class", "name", "missing", "membership" }.Select(defect => new object[] { rule, defect }));

    [Theory]
    [MemberData(nameof(SavedOwnerCases))]
    public void OwnershipAssessmentReadsOnlySelectedSavedHeaderWithoutRightsReplay(string rule, ObjectOwnerStanding standing, bool complete)
    {
        var directory = OwnershipAssessmentRun(rule, standing, complete);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            var read = source.ReadOwnershipAssessment(directory, row.Reference!.Value);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Matches(row));
            Assert.Equal(standing, read.Value.Standing);
            Assert.Equal(complete, read.Value.MembershipWasComplete);
            Assert.Equal("S-1-5-21-1-2-3-1200", read.Value.OwnerSid);
            Assert.Equal(standing == ObjectOwnerStanding.Exists ? "Recorded owner" : null, read.Value.OwnerName);
            Assert.Equal("Recorded target", read.Value.Name);
            Assert.Equal(3, row.RuleVersion);
            Assert.Equal("computer", read.Value.Object.ObjectClass);
            Assert.Equal(complete, row.EvidenceIsComplete);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [MemberData(nameof(InvalidOwnerCases))]
    public void OwnershipAssessmentRefusesInvalidOwnerStandingAndTargetFacts(string rule, string defect)
    {
        var directory = OwnershipAssessmentRun(rule, ObjectOwnerStanding.Exists, true);
        FindingReference reference;
        using (var original = new BundleAssetSource())
            reference = Assert.Single(original.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        ChangeCoverageProof(directory, defect switch
        {
            "sid" => "UPDATE finding_object_ownership SET owner_sid='not a SID'",
            "standing" => "UPDATE finding_object_ownership SET standing='Unknown'",
            "class" => "UPDATE finding_object_ownership SET object_class='another class'",
            "name" => "UPDATE finding_object_ownership SET owner_name=''",
            "membership" => "UPDATE finding_object_ownership SET membership_was_complete=2",
            _ => "DELETE FROM finding_object_ownership",
        });
        using var source = new BundleAssetSource();
        var read = source.ReadOwnershipAssessment(directory, reference);
        Assert.False(read.IsSuccess);
        Assert.Contains(defect is "missing" or "membership" ? "no valid completeness header" : SavedOwnershipAssessment.InvalidDetails,
            read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OwnershipAssessmentCannotUseAnotherGenerationOrMissingFinding(bool generation)
    {
        var directory = OwnershipAssessmentRun("SEC-031", ObjectOwnerStanding.Exists, true);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = reference.FindingId + 1 };
        Assert.False(source.ReadOwnershipAssessment(directory, reference).IsSuccess);
    }

    [Fact]
    public void OwnershipAssessmentRefusesAnotherRuleFamily()
    {
        var directory = ProtectionMarkerRun();
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        Assert.False(source.ReadOwnershipAssessment(directory, reference).IsSuccess);
    }

    private static string OwnershipAssessmentRun(string rule, ObjectOwnerStanding standing, bool complete)
    {
        var directory = LapsBundle.BuildMany([(FirstDn, null, null, null, null, 512)], DateTimeOffset.UnixEpoch);
        using var captured = BundleReader.Open(directory).Value;
        var finding = new Finding(rule, 3, rule == "SEC-031" ? Severity.Low : Severity.Medium,
            new(FindingSubjectKind.DirectoryObject, FirstDn), Assert.IsType<Guid>(captured.ReadObjectAttributes(FirstDn)!.ObjectGuid),
            FirstDn, "ad.lab", "computer", "Original owner prose must not be loaded.", EvidenceCompleteness.Complete,
            new ObjectOwnershipEvidence("S-1-5-21-1-2-3-1200", standing == ObjectOwnerStanding.Exists ? "Recorded owner" : null,
                standing, "computer", complete)) { PrincipalName = "Recorded target" };
        WriteFindingsFixture(directory, [finding]);
        return directory;
    }
}
