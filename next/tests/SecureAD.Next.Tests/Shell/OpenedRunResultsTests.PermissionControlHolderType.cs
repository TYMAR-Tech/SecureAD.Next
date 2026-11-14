using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public void PermissionHolderTypeLookupReadsCapturedClassesAndMissingTypesWithoutOtherProducts()
    {
        var directory = HolderTypeMetadataBundle();
        using var run = new OpenedRunResults(directory);
        using var evidenceLock = new FileStream(Path.Combine(directory, BundleLayout.EvidenceFileName),
            FileMode.Open, FileAccess.Read, FileShare.None);
        var read = run.ReadNavigation(reader => new[]
        {
            reader.ReadPrincipalObjectClass("S-1-5-21-1-2-3-1100", "other.example"),
            reader.ReadPrincipalObjectClass("S-1-5-21-1-2-3-1101", "contoso.com"),
            reader.ReadPrincipalObjectClass("S-1-5-21-1-2-3-1102", "contoso.com"),
            reader.ReadPrincipalObjectClass("S-1-5-21-1-2-3-1103", "contoso.com"),
            reader.ReadPrincipalObjectClass("S-1-5-21-1-2-3-9999", "contoso.com"),
        });
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(new string?[] { "group", "user", "computer", null, null }, read.Value);
    }

    [Fact]
    public void PermissionHolderTypeLookupKeepsBuiltinResourceScopeAndRefusesAmbiguousCapturedIdentities()
    {
        var directory = HolderTypeMetadataBundle();
        using var run = new OpenedRunResults(directory);
        var read = run.ReadNavigation(reader => new[]
        {
            reader.ReadPrincipalObjectClass("S-1-5-32-544", "contoso.com"),
            reader.ReadPrincipalObjectClass("S-1-5-32-544", "other.example"),
            reader.ReadPrincipalObjectClass("S-1-5-32-544", "missing.example"),
            reader.ReadPrincipalObjectClass("S-1-5-32-544", null),
        });
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(new string?[] { "group", "group", null, null }, read.Value);
        var ambiguous = run.ReadNavigation(reader => reader.ReadPrincipalObjectClass("S-1-5-21-1-2-3-1199", "contoso.com"));
        Assert.False(ambiguous.IsSuccess);
        Assert.Equal("Shell.SavedResultsInvalidEvidence", ambiguous.Error.Code);
        Assert.Contains("more than one captured object", ambiguous.Error.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void PermissionHolderCapturedGroupTypeRemainsBoundToTheHeaderAndRequestedChain()
    {
        var directory = CapturedPermissionHolderBundle();
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
            var read = source.ReadPermissionControl(directory, row.Reference!.Value);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.Equal("group", read.Value.HolderObjectClass);
            Assert.True(read.Value.Matches(row));
            var chain = source.ReadPermissionControlChain(directory, row.Reference.Value, null);
            Assert.True(chain.IsSuccess, chain.Error?.Description);
            Assert.Equal(read.Value, chain.Value.Context);
            Assert.True(chain.Value.IsExpectedPage(null));
            Assert.Equal((1L, 0L, 0L, 0L), (counts.Count("navigation"), counts.Count("evidence"),
                counts.Count("derivation"), counts.Count("facts")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void PermissionHolderWellKnownTypeUsesTheCatalogueWithoutInventingAnAccountClass()
    {
        var directory = PermissionControlCalculationTests.Saved("(A;;WD;;;WD)");
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
        var read = source.ReadPermissionControl(directory, row.Reference!.Value);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Null(read.Value.HolderObjectClass);
        var panel = new PermissionControlViewModel(read.Value, (_, _) =>
            Task.FromResult(source.ReadPermissionControlChain(directory, row.Reference.Value, null)), () => true);
        Assert.Equal("Well-known identity", panel.HolderType);
        Assert.Equal(0L, counts.Count("navigation"));
        panel.Suspend();
    }

    private static string CapturedPermissionHolderBundle()
    {
        const string broadDn = "CN=Broad group,DC=contoso,DC=com";
        var directory = SelfMembershipDiscoveryTests.Bundle(
            $"O:SYG:SYD:(A;;WD;;;{SelfMembershipDiscoveryTests.TargetSid})", users: 0, members: [broadDn],
            writeAdditional: (writer, coverage) => writer.WriteObject(new(coverage, broadDn, Guid.NewGuid(),
            [
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("group")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-513")!)]),
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
            ], DateTimeOffset.UnixEpoch)));
        SelfMembershipDiscoveryTests.Derive(directory);
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [new BroadPrincipalCanTakeOverObject()],
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, JudgingRun.NobodyIsWatching, RunLog.Discarded,
            cancellationToken: CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }

    private static string HolderTypeMetadataBundle()
    {
        var directory = TempDirectories.Create("holder-type");
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        var first = new PartitionCoverage("DC=contoso,DC=com", NamingContextKind.Domain, "dc.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 7, 1, [], false);
        var second = new PartitionCoverage("DC=other,DC=example", NamingContextKind.Domain, "dc.other.example",
            ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false);
        writer.WriteCoverage(first); writer.WriteCoverage(second);
        Write(first, "CN=Group,DC=contoso,DC=com", "S-1-5-21-1-2-3-1100", ["top", "group"]);
        Write(first, "CN=User,DC=contoso,DC=com", "S-1-5-21-1-2-3-1101", ["top", "user"]);
        Write(first, "CN=Computer,DC=contoso,DC=com", "S-1-5-21-1-2-3-1102", ["top", "user", "computer"]);
        Write(first, "CN=Missing type,DC=contoso,DC=com", "S-1-5-21-1-2-3-1103", []);
        Write(first, "CN=First,DC=contoso,DC=com", "S-1-5-21-1-2-3-1199", ["group"]);
        Write(first, "CN=Second,DC=contoso,DC=com", "S-1-5-21-1-2-3-1199", ["user"]);
        Write(first, "CN=Administrators,CN=Builtin,DC=contoso,DC=com", "S-1-5-32-544", ["group"]);
        Write(second, "CN=Administrators,CN=Builtin,DC=other,DC=example", "S-1-5-32-544", ["group"]);
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com", "other.example"]),
            [DomainCoverage.Read("contoso.com"), DomainCoverage.Read("other.example")],
            [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
             ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
            SysvolCoverage.Of([])), DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;

        void Write(PartitionCoverage coverage, string dn, string sid, string[] classes) =>
            writer.WriteObject(new(coverage, dn, Guid.NewGuid(),
            [
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
                .. classes.Length == 0 ? Array.Empty<EvidenceAttribute>() :
                    [new("objectClass", StoredAttributeCompleteness.Complete, classes.Select(EvidenceValue.OfText).ToArray())],
            ], DateTimeOffset.UnixEpoch));
    }
}
