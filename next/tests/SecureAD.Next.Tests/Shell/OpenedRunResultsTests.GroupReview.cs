using SecureAD.Evidence.Findings;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    public void GroupReviewReadsRealSavedHeadersAndOriginalOccurrencesWithoutRejudging(string rule)
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun(rule);
        GroupMembershipReviewEvidence original;
        using (var reader = JudgementReader.Open(directory).Value) original = Assert.IsType<GroupMembershipReviewEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            var header = source.ReadGroupReview(directory, row.Reference!.Value);
            Assert.True(header.IsSuccess, header.Error?.Description);
            Assert.True(header.Value.Matches(row));
            Assert.Equal(57, header.Value.ReferenceCount);
            Assert.Equal(original.DirectMembers, header.Value.DirectCount);
            Assert.Equal(original.ReviewThreshold, header.Value.ReviewThreshold);
            Assert.Equal(original.KnownTotal?.KnownMembers, header.Value.KnownTotal);
            var first = source.ReadGroupReviewReferences(directory, row.Reference.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.Equal(50, first.Value.References.Count);
            var second = source.ReadGroupReviewReferences(directory, row.Reference.Value, first.Value.Next);
            Assert.True(second.IsSuccess, second.Error?.Description);
            Assert.Equal(7, second.Value.References.Count); Assert.Null(second.Value.Next);
            Assert.Equal(original.MemberValues.Select(value => value.Text),
                first.Value.References.Concat(second.Value.References).Select(value => value.DistinguishedName));
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void GroupReviewKnownTotalMayBeLowerThanTheDistinctDirectReferenceCount()
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun("SEC-050", unresolved: true);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var header = source.ReadGroupReview(directory, row.Reference!.Value);
        Assert.True(header.IsSuccess, header.Error?.Description);
        Assert.Equal(55, header.Value.DirectCount); Assert.Equal(10, header.Value.ReviewThreshold);
        Assert.Equal(0, header.Value.KnownTotal); Assert.Equal(55, header.Value.UnresolvedReferences);
        Assert.True(header.Value.TotalLimitations.HasFlag(GroupMembershipLimitations.UnresolvedReferences));
        Assert.False(header.Value.IsComplete);
    }

    [Theory]
    [InlineData("SEC-050", false)]
    [InlineData("SEC-050", true)]
    [InlineData("SEC-051", false)]
    [InlineData("SEC-051", true)]
    public void GroupReviewRejectsAnotherGenerationOrMissingFinding(string rule, bool generation)
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun(rule);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = long.MaxValue };
        Assert.False(source.ReadGroupReview(directory, reference).IsSuccess);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("affected")]
    [InlineData("destination")]
    public void GroupReviewRejectsReferencesFromAnotherSource(string defect)
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun("SEC-051");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var mark = source.ReadGroupReviewReferences(directory, reference, null).Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() }, "finding" => mark with { FindingId = mark.FindingId + 1 },
            "affected" => mark with { AffectedGuid = Guid.NewGuid() }, _ => mark with { DestinationGuid = Guid.NewGuid() },
        };
        Assert.False(source.ReadGroupReviewReferences(directory, reference, mark).IsSuccess);
    }

    [Theory]
    [InlineData(-2147483646L)]
    [InlineData(2L)]
    [InlineData(null)]
    public void DirectNestingKeepsTheActualForeignGroupAndRecordedType(long? type)
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun("SEC-051", foreign: true, groupType: type);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadGroupReview(directory, row.Reference!.Value);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal("child.contoso.com", read.Value.Affected.Identity.DomainFqdn);
        Assert.Equal("contoso.com", read.Value.Destination.Identity.DomainFqdn);
        Assert.Equal("CN=Renamed privileged group,DC=contoso,DC=com", read.Value.Destination.Identity.DistinguishedName);
        Assert.True(read.Value.HasForeignReference); Assert.Equal(type, read.Value.Affected.GroupType);
        var page = source.ReadGroupReviewReferences(directory, row.Reference.Value, null);
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.All(page.Value.References, value => Assert.Contains("CN=ForeignSecurityPrincipals,", value.Value, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("link-member")]
    [InlineData("reference-sid")]
    [InlineData("reference-class")]
    [InlineData("reference-domain")]
    [InlineData("witness-source")]
    [InlineData("witness-attribute")]
    [InlineData("witness-value")]
    [InlineData("witness-ordinal")]
    public void DirectNestingRefusesChangedSavedRelationshipBindings(string field)
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun("SEC-051", foreign: true);
        MembershipReviewRuleTests.ChangeReviewProof(directory, evidence =>
        {
            var reference = Assert.Single(evidence.Links).MemberReferenceGuid;
            return field switch
            {
                "generation" => evidence with { DerivationGenerationId = Guid.NewGuid() },
                "link-member" => evidence with { Links = evidence.Links.Select(link => link with { MemberGuid = Guid.NewGuid() }).ToArray() },
                "reference-sid" => evidence with { Principals = evidence.Principals.Select(identity => identity.ObjectGuid == reference
                    ? identity with { Sid = "S-1-5-21-4-5-6-9999" } : identity).ToArray() },
                "reference-class" => evidence with { Principals = evidence.Principals.Select(identity => identity.ObjectGuid == reference
                    ? identity with { ObjectClass = "group" } : identity).ToArray() },
                "reference-domain" => evidence with { Principals = evidence.Principals.Select(identity => identity.ObjectGuid == reference
                    ? identity with { DomainFqdn = "child.contoso.com" } : identity).ToArray() },
                _ => evidence with { Links = evidence.Links.Select(link => link with
                {
                    Witnesses = link.Witnesses.Select(witness => field switch
                    {
                        "witness-source" => witness with { SourceObjectGuid = evidence.NestedGroupGuid!.Value },
                        "witness-attribute" => witness with { Attribute = "memberOf" },
                        "witness-ordinal" => witness with { Ordinal = witness.Ordinal + 1 },
                        _ => witness with { Value = "CN=Another group,DC=contoso,DC=com" },
                    }).ToArray(),
                }).ToArray() },
            };
        });
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var read = source.ReadGroupReviewReferences(directory, reference, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedGroupReview.InvalidDetails("SEC-051"), read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GroupReviewRefusesMissingOrInconsistentRequiredSavedTotals(bool missing)
    {
        var directory = MembershipReviewRuleTests.GroupReviewDetailsRun("SEC-050");
        MembershipReviewRuleTests.ChangeReviewProof(directory, evidence => missing ? evidence with { KnownTotal = null }
            : evidence with { KnownTotal = evidence.KnownTotal! with { KnownMembers = evidence.KnownTotal.KnownMembers + 1 } });
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var read = source.ReadGroupReview(directory, reference);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedGroupReview.InvalidDetails("SEC-050"), read.Error.Description, StringComparison.Ordinal);
    }
}
