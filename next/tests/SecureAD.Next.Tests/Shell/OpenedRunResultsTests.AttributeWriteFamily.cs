using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    public static IEnumerable<object[]> WriteFamilyPages() => AttributeWritePermissionFamilyReadTests.Kinds
        .SelectMany(kind => new[] { 1, 51 }.Select(count => new object[] { kind, count }));
    public static IEnumerable<object[]> WriteFamilies() => AttributeWritePermissionFamilyReadTests.Families();
    public static IEnumerable<object[]> WriteFamilyDefects() => AttributeWritePermissionFamilyReadTests.Kinds
        .SelectMany(kind => new[] { "kind", "attribute", "entry-generation", "missing" }.Select(defect => new object[] { kind, defect }));
    public static IEnumerable<object[]> WriteFamilyCrossMarks()
    {
        var kinds = new[] { AttributeWritePermissionKind.ResourceBasedConstrainedDelegation,
            AttributeWritePermissionKind.ServicePrincipalName, AttributeWritePermissionKind.KeyCredentialLink };
        return kinds.SelectMany(from => kinds.Where(to => to != from).Select(to => new object[] { from, to }));
    }

    [Theory]
    [MemberData(nameof(WriteFamilyPages))]
    public void AttributeWriteFamilyReadsOriginalSharedEntriesWithoutAnalysisOrValueLoading(AttributeWritePermissionKind kind, int count)
    {
        var directory = AttributeWriteRuleTests.Published("O:SYG:SYD:"
            + string.Concat(Enumerable.Repeat("(A;;WP;;;S-1-5-21-1-2-3-1200)", count)));
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings,
                item => item.RuleId == AttributeWritePermissionReadTests.Family(kind).Rule);
            Assert.Equal(0L, counts.Heavy);
            Assert.Equal(SavedAttributeWritePermission.ScopeNoteForRule(row.RuleId), row.Detail);
            var read = source.ReadAttributeWritePermission(directory, row.Reference!.Value, null);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Context.Matches(row));
            Assert.Equal(kind, read.Value.Context.PermissionKind);
            Assert.Equal(AttributeWritePermissionReadTests.Family(kind).Attribute, read.Value.Context.AttributeName);
            Assert.Equal(Math.Min(count, 50), read.Value.Entries.Count);
            Assert.Equal(Enumerable.Range(0, Math.Min(count, 50)), read.Value.Entries.Select(entry => entry.Ordinal));
            if (count > 50)
            {
                var last = source.ReadAttributeWritePermission(directory, row.Reference.Value, read.Value.Next);
                Assert.True(last.IsSuccess, last.Error?.Description);
                Assert.Equal(50, Assert.Single(last.Value.Entries).Ordinal);
                Assert.Null(last.Value.Next);
                Assert.Equal(read.Value.Context, last.Value.Context);
            }
            Assert.True(source.ReadAttributeWritePermission(directory, row.Reference.Value, null).IsSuccess);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [MemberData(nameof(WriteFamilies))]
    public void AttributeWriteFamilyDoesNotConfuseAttributeAndValidatedWriteMeanings(AttributeWritePermissionKind kind)
    {
        var kinds = new[] { AttributeWritePermissionKind.ResourceBasedConstrainedDelegation,
            AttributeWritePermissionKind.ServicePrincipalName, AttributeWritePermissionKind.KeyCredentialLink };
        var descriptor = "O:SYG:SYD:" + string.Concat(kinds.Select(value =>
            $"(OA;;WP;{AttributeWritePermissionReadTests.Family(value).Guid};;S-1-5-21-1-2-3-1200)"))
            + "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;S-1-5-21-1-2-3-1200)";
        var directory = AttributeWriteRuleTests.Published(descriptor);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings,
            item => item.RuleId == AttributeWritePermissionReadTests.Family(kind).Rule);
        var read = source.ReadAttributeWritePermission(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        var entry = Assert.Single(read.Value.Entries);
        Assert.Equal(SavedPropertyWriteScope.Attribute, entry.Scope);
        Assert.Equal(AttributeWritePermissionFamilyReadTests.AttributeLabel(kind), entry.PermissionScope);
        Assert.Equal(Array.IndexOf(kinds, kind), entry.Ordinal);
    }

    [Theory]
    [MemberData(nameof(WriteFamilyDefects))]
    public void AttributeWriteFamilyRefusesWrongKindAttributeMissingProofAndEntryGeneration(AttributeWritePermissionKind kind, string defect)
    {
        var directory = AttributeWriteRuleTests.FindingsRun();
        var filter = $"json_extract(proof,'$.PermissionKind')='{kind}'";
        var other = AttributeWritePermissionFamilyReadTests.Other(kind);
        ChangeCoverageProof(directory, defect switch
        {
            "kind" => $"UPDATE finding_attribute_write SET proof=json_set(proof,'$.PermissionKind','{other}') WHERE {filter}",
            "attribute" => $"UPDATE finding_attribute_write SET proof=json_set(proof,'$.Attribute.Guid','{AttributeWritePermissionReadTests.Family(other).Guid}') WHERE {filter}",
            "entry-generation" => "UPDATE permission_entry SET generation='not the selected generation'",
            _ => $"DELETE FROM finding_attribute_write_entry WHERE finding_id IN (SELECT finding_id FROM finding_attribute_write WHERE {filter}); DELETE FROM finding_attribute_write WHERE {filter}",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings,
            item => item.RuleId == AttributeWritePermissionReadTests.Family(kind).Rule);
        var read = source.ReadAttributeWritePermission(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedAttributeWritePermission.InvalidDetailsForRule(row.RuleId), read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(WriteFamilyCrossMarks))]
    public void AttributeWriteFamilyContinuationCannotCrossRulesEvenOnTheSameHolderAndTarget(
        AttributeWritePermissionKind from, AttributeWritePermissionKind to)
    {
        var directory = AttributeWriteRuleTests.Published("O:SYG:SYD:"
            + string.Concat(Enumerable.Repeat("(A;;WP;;;S-1-5-21-1-2-3-1200)", 51)));
        using var source = new BundleAssetSource();
        var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
        var first = Assert.Single(rows, row => row.RuleId == AttributeWritePermissionReadTests.Family(from).Rule);
        var other = Assert.Single(rows, row => row.RuleId == AttributeWritePermissionReadTests.Family(to).Rule);
        Assert.Equal(first.ObjectGuid, other.ObjectGuid);
        Assert.Equal(first.Subject, other.Subject);
        var read = source.ReadAttributeWritePermission(directory, first.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.NotNull(read.Value.Next);
        Assert.False(source.ReadAttributeWritePermission(directory, other.Reference!.Value, read.Value.Next).IsSuccess);
    }
}
