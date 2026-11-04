using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(51)]
    public void SelectedConstrainedDelegationUsesOnlyItsProtectedSavedPartAndPreservesOriginalResults(int count)
    {
        var directory = ConstrainedDelegationReadTests.PublishedRun(count);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            Assert.Equal(SavedDelegationConfiguration.ConstrainedStatement, row.Detail);
            var read = source.ReadConstrainedDelegation(directory, row.Reference!.Value, null);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Context.Matches(row));
            Assert.True(read.Value.Context.EstablishedTier0);
            Assert.Equal("contoso.com", read.Value.Context.Resource.DomainFqdn);
            Assert.Equal(Math.Min(50, count), read.Value.Services.Count);
            Assert.Equal("LDAP/service.contoso.com:389/instance-000", read.Value.Services[0]);
            if (count == 51)
            {
                var last = source.ReadConstrainedDelegation(directory, row.Reference.Value, read.Value.Next);
                Assert.True(last.IsSuccess, last.Error?.Description);
                Assert.Single(last.Value.Services);
                Assert.Equal("LDAP/service.contoso.com:389/instance-050", last.Value.Services[0]);
                Assert.Null(last.Value.Next);
                Assert.Equal(read.Value.Context, last.Value.Context);
            }
            Assert.True(source.ReadConstrainedDelegation(directory, row.Reference.Value, null).IsSuccess);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("resource")]
    [InlineData("negative")]
    [InlineData("unaligned")]
    [InlineData("past-end")]
    public void ConstrainedServiceContinuationCannotCrossFindingResourceOrGeneration(string defect)
    {
        var directory = ConstrainedDelegationReadTests.PublishedRun(51);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var first = source.ReadConstrainedDelegation(directory, row.Reference!.Value, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var mark = first.Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "finding" => mark with { FindingId = mark.FindingId + 1 },
            "resource" => mark with { ResourceGuid = Guid.NewGuid() },
            "negative" => mark with { Offset = -50 },
            "unaligned" => mark with { Offset = 1 },
            _ => mark with { Offset = 100 },
        };
        var read = source.ReadConstrainedDelegation(directory, row.Reference.Value, mark);
        Assert.False(read.IsSuccess);
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("wrong-rule")]
    public void ConstrainedDelegationRefusesMissingOrMisboundSavedRecordWithoutAProseFallback(string defect)
    {
        var directory = ConstrainedDelegationReadTests.PublishedRun(1);
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_delegation_configuration",
            "generation" => "UPDATE finding_delegation_configuration SET generation='not the selected generation'",
            _ => "UPDATE finding_delegation_configuration SET proof=replace(proof,'Constrained','ResourceBased')",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadConstrainedDelegation(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedDelegationConfiguration.ConstrainedInvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("zero")]
    [InlineData("missing")]
    public void ConstrainedDelegationCannotSubstituteTheFirstFindingForAnInvalidSelectedIdentity(string defect)
    {
        var directory = ConstrainedDelegationReadTests.PublishedRun(1);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var reference = row.Reference!.Value;
        reference = defect switch
        {
            "generation" => reference with { GenerationId = Guid.NewGuid() },
            "zero" => reference with { FindingId = 0 },
            _ => reference with { FindingId = reference.FindingId + 100 },
        };
        Assert.False(source.ReadConstrainedDelegation(directory, reference, null).IsSuccess);
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
    }

    [Fact]
    public void ConstrainedDelegationCannotSubstituteAnotherDelegationFamily()
    {
        var directory = DelegationConfigurationRuleTests.FindingsRun();
        using var source = new BundleAssetSource();
        var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
        var rbcd = Assert.Single(rows, row => row.RuleId == "SEC-013");
        Assert.False(source.ReadConstrainedDelegation(directory, rbcd.Reference!.Value, null).IsSuccess);
        Assert.Equal(2, source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Count);
    }
}
