using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoHierarchyRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoLinkHierarchyTests
{
    [Fact]
    public void GpoHierarchyOrdinaryProcessingIsDomainThenParentThenLeafWithFirstStoredLast()
    {
        var result = Read(Links(Link(3) + Link(4), Link(1) + Link(2), Link(5) + Link(6)));
        Assert.True(result.DomainOuEvidenceComplete);
        Assert.Equal([PolicyDn(6), PolicyDn(5), PolicyDn(2), PolicyDn(1), PolicyDn(4), PolicyDn(3)], Processing(result));
        Assert.Equal([LeafOu, ParentOu, GpoSecurityRun.Parent], result.Containers.Select(row => row.DistinguishedName));
        Assert.All(result.Links, row => Assert.Equal(GpoLinkHierarchyState.Included, row.State));
        Assert.False(result.SiteScopeResolved);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchySiteUnresolved");
    }

    [Fact]
    public void GpoHierarchyEnforcedAncestorsFollowOrdinaryLinksAndTheClosestEnforcedScope()
    {
        var result = Read(Links(Link(3, "2") + Link(4), Link(1, "2") + Link(2), Link(5, "2") + Link(6)));
        Assert.Equal([PolicyDn(6), PolicyDn(2), PolicyDn(4), PolicyDn(3), PolicyDn(1), PolicyDn(5)], Processing(result));
        Assert.True(result.DomainOuEvidenceComplete);
    }

    [Fact]
    public void GpoHierarchyEnforcedLinksRetainThePublishedAppendOrderWithinAScope()
    {
        var result = Read(Links(leaf: Link(1, "2") + Link(2, "2")));
        Assert.Equal([PolicyDn(1), PolicyDn(2)], Processing(result));
        Assert.Equal([1, 2], result.Links.Select(row => row.Link.Order));
    }

    [Theory]
    [InlineData("leaf")]
    [InlineData("parent")]
    public void GpoHierarchyBlockInheritanceKeepsOwnLinksAndEnforcedAncestors(string boundary)
    {
        var result = Read(Links(Link(3), Link(1) + Link(2, "2"), Link(5),
            leafOptions: boundary == "leaf" ? "1" : null, parentOptions: boundary == "parent" ? "1" : null));
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 3).State);
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 2).State);
        Assert.Equal(GpoLinkHierarchyState.Excluded, Row(result, 5).State);
        Assert.Equal(boundary == "leaf" ? GpoLinkHierarchyState.Excluded : GpoLinkHierarchyState.Included, Row(result, 1).State);
        Assert.Equal("InheritanceBlocked", Row(result, 5).Reason);
        Assert.Null(Row(result, 5).DomainOuProcessingOrder);
    }

    [Theory]
    [InlineData("0", false, false)]
    [InlineData("1", true, false)]
    [InlineData("2", false, true)]
    [InlineData("3", true, true)]
    public void GpoHierarchyLinkOptionsKeepDisabledAndEnforcedIndependent(string options, bool disabled, bool enforced)
    {
        var result = Read(Links(leaf: Link(1, options)));
        var link = Assert.Single(result.Links);
        Assert.Equal(disabled, link.Disabled);
        Assert.Equal(enforced, link.Enforced);
        Assert.Equal(disabled ? GpoLinkHierarchyState.Excluded : GpoLinkHierarchyState.Included, link.State);
        Assert.Equal(options, link.Link.Options);
        Assert.Equal(!disabled, link.DomainOuProcessingOrder is not null);
    }

    [Theory]
    [InlineData("4")]
    [InlineData("unknown")]
    [InlineData("-1")]
    [InlineData("4294967296")]
    [InlineData("")]
    public void GpoHierarchyUnqualifiedLinkOptionsAreNotInventedOrOrdered(string options)
    {
        var result = Read(Links(leaf: Link(1, options)));
        var link = Assert.Single(result.Links);
        Assert.Equal(GpoLinkHierarchyState.Unresolved, link.State);
        Assert.Null(link.Options);
        Assert.Null(link.DomainOuProcessingOrder);
        Assert.False(result.DomainOuEvidenceComplete);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyLinkOptionsUnsupported");
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("2")]
    [InlineData("")]
    public void GpoHierarchyUnknownBlockStateDoesNotEraseOwnOrEnforcedLinks(string option)
    {
        var result = Read(Links(Link(3), Link(1) + Link(2, "2"), leafOptions: option));
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 3).State);
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 2).State);
        Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 1).State);
        Assert.Equal("DescendantInheritanceUnknown", Row(result, 1).Reason);
        Assert.False(result.DomainOuEvidenceComplete);
    }

    [Fact]
    public void GpoHierarchyAKnownHigherBlockStillExcludesBeyondAnUnknownLowerBlock()
    {
        var result = Read(Links(Link(3), Link(1), Link(5) + Link(6, "2"), leafOptions: "unknown", parentOptions: "1"));
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 3).State);
        Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 1).State);
        Assert.Equal(GpoLinkHierarchyState.Excluded, Row(result, 5).State);
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 6).State);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void GpoHierarchyMalformedLinkDataKeepsItsOriginalAndAnIndependentReadableLink(bool unreadFirst)
    {
        var original = unreadFirst ? "[LDAP://;0]" + Link(1) : Link(1) + "unread";
        var result = Read(Links(leaf: original));
        var link = Assert.Single(result.Links);
        Assert.Equal(GpoLinkHierarchyState.Included, link.State);
        Assert.Equal(unreadFirst ? 2 : 1, link.Link.Order);
        Assert.Equal(link.Link.Order, link.Link.Precedence);
        Assert.Equal(original, result.Containers[0].Values!.Find("gPLink")!.OnlyValue!.Text);
        Assert.False(result.DomainOuEvidenceComplete);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyLinkMalformed");
    }

    [Theory]
    [InlineData("container")]
    [InlineData("policy")]
    public void GpoHierarchyMismatchedCapturedDomainCannotStandInForTheOriginalResource(string changed)
    {
        var directory = Build(Links(Link(3), Link(1)));
        var dn = changed == "container" ? LeafOu : PolicyDn(3);
        using (var connection = new SqliteConnection("Data Source=" + BundleLayout.EvidencePath(directory) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE captured_object SET domain_fqdn='child.example.test' WHERE distinguished_name=$dn COLLATE NOCASE";
            command.Parameters.AddWithValue("$dn", dn);
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealCapture(directory);
        using var reader = GpoLinkHierarchyReader.Open(directory, CancellationToken.None).Value;
        var altered = reader.Bundle.ReadObjectIdentity(dn)!;
        Assert.Equal("child.example.test", reader.Bundle.ReadObjectAttributesAt(altered, ["objectClass"]).DomainFqdn);
        var result = reader.Read(reader.Bundle.ReadObjectIdentity(Subject)!, CancellationToken.None);
        Assert.False(result.DomainOuEvidenceComplete);
        if (changed == "container")
        {
            Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 1).State);
            Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyContainerUnqualified");
        }
        else Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 3).State);
    }

    [Theory]
    [InlineData("leaf")]
    [InlineData("parent")]
    public void GpoHierarchyMissingAncestorIsNotAnEmptyUnblockedContainer(string missing)
    {
        var options = Links(Link(3), Link(1), Link(5, "2") + Link(6));
        var result = Read(options with { Containers = options.Containers.Where(row => row.Dn != (missing == "leaf" ? LeafOu : ParentOu)).ToArray() });
        Assert.False(result.DomainOuEvidenceComplete);
        Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 5).State);
        Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 6).State);
        if (missing == "leaf") Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 1).State);
        else Assert.Equal(GpoLinkHierarchyState.Included, Row(result, 3).State);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyContainerUnavailable");
    }

    [Fact]
    public void GpoHierarchyNonOuContainersAreSkippedWithoutDroppingTheDomain()
    {
        var result = Read(Links(domain: Link(1)) with { ComputerDn = "CN=Computer,CN=Computers," + GpoSecurityRun.Parent });
        Assert.Equal(GpoSecurityRun.Parent, Assert.Single(result.Containers).DistinguishedName);
        Assert.Equal(GpoLinkHierarchyState.Included, Assert.Single(result.Links).State);
    }

    [Fact]
    public void GpoHierarchyStopsAtTheChildDomainRatherThanFollowingItsParentDomain()
    {
        var childOu = "OU=Child computers," + GpoSecurityRun.Child;
        var result = Read(new Options
        {
            ComputerDn = "CN=Computer," + childOu,
            Containers = [new(childOu, Link(1, child: true)), new(GpoSecurityRun.Parent, Link(2), Class: "domainDNS")],
            Policies = [new(1, ChildDomain: true), new(2)],
        });
        Assert.Equal([childOu, GpoSecurityRun.Child], result.Containers.Select(row => row.DistinguishedName));
        Assert.Equal(PolicyDn(1, true), Assert.Single(result.Links).Link.DistinguishedName);
    }

    [Fact]
    public void GpoHierarchyEscapedCommaDoesNotInventAnAncestor()
    {
        var leaf = "OU=Leaf\\,OU=Not a parent," + ParentOu;
        var result = Read(new Options
        {
            ComputerDn = "CN=Computer," + leaf,
            Containers = [new(leaf, Link(1)), new(ParentOu), new(GpoSecurityRun.Parent, Class: "domainDNS")],
        });
        Assert.Equal(leaf, result.Containers[0].DistinguishedName);
        Assert.Equal(3, result.Containers.Length);
        Assert.Equal(GpoLinkHierarchyState.Included, Assert.Single(result.Links).State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GpoHierarchyMissingOrAmbiguousPolicyReferencesDoNotChooseAnObject(bool ambiguous)
    {
        var result = Read(Links(leaf: Link(1)) with { Policies = ambiguous ? [new(1), new(1)] : [] });
        var link = Assert.Single(result.Links);
        Assert.Equal(GpoLinkHierarchyState.Unresolved, link.State);
        Assert.Null(link.Policy);
        Assert.False(result.DomainOuEvidenceComplete);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyPolicyUnavailable");
    }

    [Fact]
    public void GpoHierarchyAmbiguousContainerDoesNotChooseItsFirstRecordedLinks()
    {
        var options = Links(Link(3), Link(1));
        var result = Read(options with { Containers = [.. options.Containers, new(LeafOu, Link(4))] });
        Assert.False(result.DomainOuEvidenceComplete);
        Assert.DoesNotContain(result.Links, row => row.Link.DistinguishedName == PolicyDn(3) || row.Link.DistinguishedName == PolicyDn(4));
        Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 1).State);
    }

    [Fact]
    public void GpoHierarchyRepeatedPolicyLinksRetainEveryOriginalOccurrenceAndOrder()
    {
        var result = Read(Links(Link(1) + Link(1, "2"), Link(1)));
        Assert.Equal(3, result.Links.Length);
        Assert.Equal([1, 2, 1], result.Links.Select(row => row.Link.Order));
        Assert.Equal([0, 0, 1], result.Links.Select(row => row.ContainerIndex));
        Assert.Equal(3, result.Links.Select(row => row.DomainOuProcessingOrder).Distinct().Count());
        Assert.Equal(Link(1) + Link(1, "2"), result.Containers[0].Values!.Find("gPLink")!.OnlyValue!.Text);
    }

    [Fact]
    public void GpoHierarchyCanBindAPolicyInAnotherCapturedDomain()
    {
        var result = Read(Links(leaf: Link(1, child: true)) with { Policies = [new(1, ChildDomain: true)] });
        var link = Assert.Single(result.Links);
        Assert.Equal(GpoLinkHierarchyState.Included, link.State);
        Assert.Equal("child.example.test", link.Policy!.DomainFqdn);
        Assert.Equal(result.CaptureGenerationId, link.Policy.CaptureGenerationId);
    }

    [Fact]
    public void GpoHierarchyWrongPolicyClassIsNotAValidGpoReference()
    {
        var result = Read(Links(leaf: Link(1)) with { Policies = [new(1, Class: "container")] });
        Assert.Equal(GpoLinkHierarchyState.Unresolved, Assert.Single(result.Links).State);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyPolicyUnqualified");
    }

    [Fact]
    public void GpoHierarchyDisabledLinkRemainsExcludedWhenItsPolicyWasNotCaptured()
    {
        var result = Read(Links(leaf: Link(1, "1")) with { Policies = [] });
        Assert.Equal(GpoLinkHierarchyState.Excluded, Assert.Single(result.Links).State);
        Assert.Equal("LinkDisabled", Assert.Single(result.Links).Reason);
        Assert.False(result.DomainOuEvidenceComplete);
    }

    [Theory]
    [InlineData("class")]
    [InlineData("guid")]
    public void GpoHierarchyUnqualifiedAncestorCannotProvideConfidentLinks(string defect)
    {
        var options = Links(Link(3), Link(1));
        var result = Read(options with { Containers = options.Containers.Select(row => row.Dn != LeafOu ? row
            : defect == "class" ? row with { Class = "container" } : row with { NoGuid = true }).ToArray() });
        Assert.Equal(GpoLinkHierarchyState.Unresolved, Row(result, 1).State);
        Assert.DoesNotContain(result.Links, row => row.Link.DistinguishedName == PolicyDn(3));
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyContainerUnqualified");
    }

    [Theory]
    [InlineData("class")]
    [InlineData("guid")]
    public void GpoHierarchyUnqualifiedComputerIsNotAnEmptySuccessfulHierarchy(string defect)
    {
        var result = Read(new Options { ComputerClass = defect == "class" ? "user" : "computer", ComputerNoGuid = defect == "guid" });
        Assert.False(result.DomainOuEvidenceComplete);
        Assert.Empty(result.Links);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchyComputerUnavailable");
    }

    [Fact]
    public void GpoHierarchyEmptyDomainOuScopeDoesNotClaimNoSitePolicies()
    {
        var result = Read(new Options());
        Assert.True(result.DomainOuEvidenceComplete);
        Assert.Empty(result.Links);
        Assert.False(result.SiteScopeResolved);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoHierarchySiteUnresolved");
    }

    [Fact]
    public void GpoHierarchySelectedCaptureIdentityAndHintsAreHandledSeparately()
    {
        var directory = Build(Links(leaf: Link(1)));
        using var reader = GpoLinkHierarchyReader.Open(directory, CancellationToken.None).Value;
        using var foreign = GpoLinkHierarchyReader.Open(Build(new Options()), CancellationToken.None).Value;
        var selected = reader.Bundle.ReadObjectIdentity(Subject)!;
        Assert.Throws<InvalidDataException>(() => foreign.Read(selected, CancellationToken.None));
        var result = reader.Read(selected with { DomainFqdn = "wrong.test", ObjectClass = "user" }, CancellationToken.None);
        Assert.Equal(selected, result.Computer);
        Assert.Equal(GpoLinkHierarchyState.Included, Assert.Single(result.Links).State);
    }

    [Fact]
    public void GpoHierarchySourceIsUnchangedAndReaderLifetimeAndCancellationAreExplicit()
    {
        var directory = Build(Links(leaf: Link(1)));
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(directory));
        var reader = GpoLinkHierarchyReader.Open(directory, CancellationToken.None).Value;
        var selected = reader.Bundle.ReadObjectIdentity(Subject)!;
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.Read(selected, cancelled.Token));
        var result = reader.Read(selected, CancellationToken.None);
        Assert.Equal(GpoLinkHierarchyState.Included, Assert.Single(result.Links).State);
        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(directory)));
        Assert.Equal(64, result.EvidenceSeal.Length);
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.Read(selected, CancellationToken.None));
    }

    [Fact]
    public void GpoHierarchyExistingLinkedPolicyFiguresUseCorrectedNormalPriorityWithoutNewPresentation()
    {
        var result = Read(Links(leaf: Link(1) + Link(2)));
        var view = new PolicyLinksSectionViewModel(new("test", "test", ["gPLink"]), result.Containers[0].Values);
        Assert.Equal([PolicyDn(1), PolicyDn(2)], view.Links.Select(link => link.DistinguishedName));
        Assert.Equal([1, 2], view.Links.Select(link => link.Precedence));
        Assert.Equal([1, 2], view.Links.Select(link => link.Order));
        Assert.False(view.HasErrors);
    }

    private static GpoLinkHierarchy Read(Options options)
    {
        using var reader = GpoLinkHierarchyReader.Open(Build(options), CancellationToken.None).Value;
        return reader.Read(reader.Bundle.ReadObjectIdentity(options.ComputerDn)!, CancellationToken.None);
    }
    private static GpoHierarchyLink Row(GpoLinkHierarchy hierarchy, int id) =>
        Assert.Single(hierarchy.Links, row => row.Link.DistinguishedName == PolicyDn(id));
    private static IEnumerable<string> Processing(GpoLinkHierarchy hierarchy) =>
        hierarchy.Links.Where(row => row.DomainOuProcessingOrder is not null).OrderBy(row => row.DomainOuProcessingOrder)
            .Select(row => row.Link.DistinguishedName);
}
