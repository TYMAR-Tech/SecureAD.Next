using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The offline rebuild of the directory tree: what it shows, what it refuses to invent, and what
/// it says about the parts of the directory it cannot show.
/// </summary>
public sealed class DirectoryTreeTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-tree-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 21, 11, 30, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";

    // ---------------------------------------------------------------------------------------
    // What the tree shows
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A root is a partition the run recorded reading, and the grid starts there.
    /// </summary>
    [Fact]
    public void TheTreeIsRootedAtThePartitionsTheRunRead()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal([DomainDn], tree.Roots.Select(r => r.DistinguishedName));
    }

    [Fact]
    public void AContainerObjectsWereCapturedUnderIsInTheTree()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("OU=People," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(2)));
        });

        var tree = ReadTree();

        Assert.Equal(["OU=People," + DomainDn], ChildrenOf(tree.Roots[0]));
    }

    /// <summary>
    /// The container between an object and its root is real containment, not a guess: an object
    /// named under <c>OU=People</c> is under it whether or not anything sits directly in it.
    /// Without this the branch would hang off nothing.
    /// </summary>
    [Fact]
    public void AContainerWithNothingDirectlyInItStillJoinsItsBranchToTheRoot()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("OU=People," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("OU=Staff,OU=People," + DomainDn, GuidNumbered(2)));
            writer.WriteObject(ObjectAt("CN=Alice,OU=Staff,OU=People," + DomainDn, GuidNumbered(3)));
        });

        var tree = ReadTree();
        var people = tree.Roots[0].Children.Single();

        Assert.Equal(["OU=Staff,OU=People," + DomainDn], ChildrenOf(people));
    }

    [Fact]
    public void ACapturedContainerCarriesTheIdentityThatSurvivesARenameOrMove()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("OU=People," + DomainDn, GuidNumbered(7)));
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(2)));
        });

        var tree = ReadTree();

        Assert.Equal(GuidNumbered(7), tree.Roots[0].Children.Single().ObjectGuid);
    }

    [Fact]
    public void AContainerIsNamedByItsFirstRelativeNameForShowing()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("OU=People," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(2)));
        });

        var tree = ReadTree();

        Assert.Equal("People", tree.Roots[0].Children.Single().Name);
    }

    /// <summary>
    /// A distinguished name looks like a delimited list and is not one. A container called
    /// <c>Smith, John</c> is one container, and splitting it at that comma would put a node in the
    /// tree that does not exist.
    /// </summary>
    [Fact]
    public void AContainerWhoseNameCarriesACommaIsOneContainer()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt(@"OU=Smith\, John," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt(@"CN=Alice,OU=Smith\, John," + DomainDn, GuidNumbered(2)));
        });

        var tree = ReadTree();

        Assert.Equal("Smith, John", tree.Roots[0].Children.Single().Name);
    }

    /// <summary>
    /// Only the ordinary leaf is captured, so its stored parent is correct even before P-41;
    /// this isolates reconstruction of the ancestors above the escaped-backslash container.
    /// </summary>
    [Fact]
    public void AnEscapedBackslashContainerRetainsItsUncapturedAncestor()
    {
        const string parent = "OU=Tier 0," + DomainDn;
        const string container = @"OU=Controllers\\," + parent;
        WriteBundle(writer =>
            writer.WriteObject(ObjectAt("CN=Agent," + container, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal([parent], ChildrenOf(tree.Roots.Single(r => r.DistinguishedName == DomainDn)));
    }

    /// <summary>
    /// The parent already exists here, independently of ancestor reconstruction; the container
    /// must attach to it rather than skip it or become an orphan root.
    /// </summary>
    [Fact]
    public void AnEscapedBackslashContainerAttachesToItsImmediateParent()
    {
        const string parent = "OU=Tier 0," + DomainDn;
        const string container = @"OU=Controllers\\," + parent;
        WriteBundle(writer =>
        {
            writer.WriteObject(ContainerAt(parent, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Agent," + container, GuidNumbered(2)));
        });

        var tree = ReadTree();
        var parentNode = tree.Roots.Single(r => r.DistinguishedName == DomainDn)
            .Children.Single(c => c.DistinguishedName == parent);

        Assert.Equal([container], ChildrenOf(parentNode));
    }

    [Fact]
    public void ChildrenAreOrderedByNameSoTheTreeReadsTheSameEveryTime()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("CN=One,OU=Zebra," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Two,OU=Apple," + DomainDn, GuidNumbered(2)));
            writer.WriteObject(ObjectAt("CN=Three,OU=Mango," + DomainDn, GuidNumbered(3)));
        });

        var tree = ReadTree();

        Assert.Equal(["Apple", "Mango", "Zebra"], tree.Roots[0].Children.Select(c => c.Name));
    }

    // ---------------------------------------------------------------------------------------
    // What it refuses to invent
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A tree that showed a container above the partition the run read would be showing part of a
    /// directory nothing looked at.
    /// </summary>
    [Fact]
    public void NothingIsInventedAboveARoot()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.DoesNotContain("DC=com", tree.Roots.Select(r => r.DistinguishedName));
    }

    /// <summary>
    /// A container that was never captured is still a node, because the objects beneath it are in
    /// the evidence and would otherwise be unreachable from the tree - a gap in the capture shown
    /// as a smaller directory.
    /// </summary>
    [Fact]
    public void AContainerThatWasNeverCapturedIsStillANodeSoItsBranchIsReachable()
    {
        WriteBundle(writer =>
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal(["OU=People," + DomainDn], ChildrenOf(tree.Roots[0]));
    }

    [Fact]
    public void AContainerThatWasNeverCapturedSaysSoRatherThanLookingCaptured()
    {
        WriteBundle(writer =>
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal(TreeNodeOrigin.NeverCaptured, tree.Roots[0].Children.Single().Origin);
    }

    [Fact]
    public void AContainerThatWasNeverCapturedHasNoInventedIdentity()
    {
        WriteBundle(writer =>
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Null(tree.Roots[0].Children.Single().ObjectGuid);
    }

    // ---------------------------------------------------------------------------------------
    // What it says about what it cannot show
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ATreeOfAFullyReadForestReportsNoGaps()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.True(tree.BranchesAreComplete);
    }

    /// <summary>
    /// A branch the run could not read produces a tree smaller than the forest, and a smaller tree
    /// looks exactly like a smaller directory unless the tree says otherwise.
    /// </summary>
    [Fact]
    public void ADomainTheRunCouldNotReadIsReportedAsAGap()
    {
        WriteBundle(
            writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))),
            OneDomainNotRead());

        var tree = ReadTree();

        Assert.Contains(
            tree.Gaps, g => g.Reason == TreeGapReason.DomainNotFullyRead);
    }

    [Fact]
    public void ATreeWithAGapDoesNotClaimItsBranchesAreComplete()
    {
        WriteBundle(
            writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))),
            OneDomainNotRead());

        var tree = ReadTree();

        Assert.False(tree.BranchesAreComplete);
    }

    [Fact]
    public void AGapSaysWhatTheRunRecordedAboutIt()
    {
        WriteBundle(
            writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))),
            OneDomainNotRead());

        var gap = GapFor(TreeGapReason.DomainNotFullyRead);

        Assert.Contains("No controller answered", gap.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AContainerThatWasNeverCapturedIsReportedAsAGap()
    {
        WriteBundle(writer =>
            writer.WriteObject(ObjectAt("CN=Alice,OU=People," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal(
            ["OU=People," + DomainDn],
            tree.Gaps
                .Where(g => g.Reason == TreeGapReason.ContainerNeverCaptured)
                .Select(g => g.DistinguishedName));
    }

    /// <summary>
    /// A partition this product does not read is stated rather than left silent, so a reader
    /// cannot take a forest whose DNS partitions were skipped for a forest that has none.
    /// </summary>
    [Fact]
    public void APartitionThisProductDoesNotReadIsReportedAsAGap()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1)));
            writer.RecordUnreadPartition("DC=DomainDnsZones," + DomainDn);
        });

        var tree = ReadTree();

        Assert.Contains(tree.Gaps, g => g.Reason == TreeGapReason.PartitionNotRead);
    }

    /// <summary>
    /// An organisational unit holding nothing is still part of the directory, and an administrator
    /// navigating his own forest expects to see it. A tree built only from observed containment
    /// drops every one of them.
    /// </summary>
    [Fact]
    public void AContainerHoldingNothingIsStillInTheTree()
    {
        WriteBundle(writer =>
            writer.WriteObject(ContainerAt("OU=Empty," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal(["OU=Empty," + DomainDn], ChildrenOf(tree.Roots[0]));
    }

    [Fact]
    public void AContainerHoldingNothingIsMarkedAsCapturedRatherThanUnknown()
    {
        WriteBundle(writer =>
            writer.WriteObject(ContainerAt("OU=Empty," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal(TreeNodeOrigin.Captured, tree.Roots[0].Children.Single().Origin);
    }

    /// <summary>
    /// An ordinary object is not a container and does not become a branch of the tree, however
    /// many of them there are.
    /// </summary>
    [Fact]
    public void AnObjectThatIsNotAContainerIsNotInTheTree()
    {
        WriteBundle(writer =>
            writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Empty(tree.Roots[0].Children);
    }

    /// <summary>
    /// The class list cannot be complete, so it is a union with observed containment: a container
    /// of some class nobody listed still appears the moment anything is captured inside it. This is
    /// what keeps an omission from costing a branch of the directory.
    /// </summary>
    [Fact]
    public void AContainerOfAnUnlistedClassStillAppearsOnceSomethingIsInsideIt()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(
                ObjectWithClass("CN=Odd," + DomainDn, GuidNumbered(1), "msExchSomethingContainer"));
            writer.WriteObject(ObjectAt("CN=Alice,CN=Odd," + DomainDn, GuidNumbered(2)));
        });

        var tree = ReadTree();

        Assert.Equal(["CN=Odd," + DomainDn], ChildrenOf(tree.Roots[0]));
    }

    /// <summary>
    /// The one object whose parent lies outside the tree is the partition root itself: a captured
    /// <c>DC=ad,DC=lab</c> names <c>DC=lab</c> as its parent, and no such object exists in the
    /// directory - the forest root domain <i>is</i> ad.lab.
    ///
    /// <para>
    /// Seen on a running window 2026-08-18. The earlier guard stopped the walk at a root but still
    /// added the first name above one, so a phantom container appeared in the tree and was then
    /// reported as one the run had failed to capture. Every existing test missed it because none
    /// captured a partition root object.
    /// </para>
    /// </summary>
    [Fact]
    public void TheParentOfAPartitionRootIsNotInventedAsAContainer()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.Equal([DomainDn], tree.Roots.Select(r => r.DistinguishedName));
    }

    [Fact]
    public void TheParentOfAPartitionRootIsNotReportedAsAnUncapturedContainer()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(DomainDn, GuidNumbered(1))));

        var tree = ReadTree();

        Assert.DoesNotContain(
            tree.Gaps, g => g.Reason == TreeGapReason.ContainerNeverCaptured);
    }

    [Fact]
    public void TreePartitionKindsComeFromCapturedCoverage()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(new("CN=Settings," + DomainDn, NamingContextKind.Configuration,
                "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 0, 0, [], false));
            writer.WriteCoverage(new("CN=Definitions," + DomainDn, NamingContextKind.Schema,
                "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 0, 0, [], false));
        });

        var roots = ReadTree().Roots;

        Assert.Equal(NamingContextKind.Domain, roots.Single(node => node.DistinguishedName == DomainDn).PartitionKind);
        Assert.Equal(NamingContextKind.Configuration, roots.Single(node => node.Name == "Settings").PartitionKind);
        Assert.Equal(NamingContextKind.Schema, roots.Single(node => node.Name == "Definitions").PartitionKind);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TreeKeepsCapturedClassForEmptyAndPopulatedContainers(bool populated)
    {
        const string name = "CN=NamedUnlikeAnOu,";
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectWithClass(name + DomainDn, GuidNumbered(1), "organizationalUnit"));
            if (populated) writer.WriteObject(ObjectAt("CN=Alice," + name + DomainDn, GuidNumbered(2)));
        });

        var node = Assert.Single(ReadTree().Roots.Single().Children);

        Assert.Equal("organizationalUnit", node.ObjectClass);
        Assert.Equal(TreeNodeOrigin.Captured, node.Origin);
        Assert.Equal(GuidNumbered(1), node.ObjectGuid);
    }

    [Fact]
    public void AnUncapturedParentDoesNotGainAClassFromItsName()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt("CN=Alice,OU=Unknown," + DomainDn, GuidNumbered(1))));

        var node = Assert.Single(ReadTree().Roots.Single().Children);

        Assert.Equal(TreeNodeOrigin.NeverCaptured, node.Origin);
        Assert.Null(node.ObjectClass);
        Assert.Null(node.PartitionKind);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------------------------------

    private DirectoryTree ReadTree()
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;
        return reader.ReadTree();
    }

    private TreeGap GapFor(TreeGapReason reason) =>
        ReadTree().Gaps.Single(g => g.Reason == reason);

    private static IEnumerable<string> ChildrenOf(TreeNode node) =>
        node.Children.Select(c => c.DistinguishedName);

    private void WriteBundle(Action<BundleWriter> write) => WriteBundle(write, OneDomainRead());

    private void WriteBundle(Action<BundleWriter> write, RunCoverage coverage)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());
        write(writer);
        writer.Complete(coverage, Finished);
    }

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static RunCoverage OneDomainNotRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com", "sales.contoso.com"]),
            [
                DomainCoverage.Read("contoso.com"),
                DomainCoverage.NotRead("sales.contoso.com", "No controller answered."),
            ],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        DomainDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static EvidenceObject ObjectAt(string dn, Guid guid) =>
        new(SomeCoverage(), dn, guid, [], Started);

    /// <summary>An object of a class that makes it a container.</summary>
    private static EvidenceObject ContainerAt(string dn, Guid guid) =>
        ObjectWithClass(dn, guid, "organizationalUnit");

    private static EvidenceObject ObjectWithClass(string dn, Guid guid, string objectClass) =>
        new(
            SomeCoverage(),
            dn,
            guid,
            [
                new EvidenceAttribute(
                    "objectClass",
                    StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
            ],
            Started);

    private static Guid GuidNumbered(int n) => Guid.Parse($"00000000-0000-0000-0000-{n:D12}");
}
