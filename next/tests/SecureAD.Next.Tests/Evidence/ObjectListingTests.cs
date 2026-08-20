using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Listing the objects a bundle captured: the three scopes, the order, the paging, and what a
/// listing says when the directory it covers was not read in full.
/// </summary>
public sealed class ObjectListingTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-listing-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 21, 11, 30, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";
    private const string PeopleDn = "OU=People," + DomainDn;
    private const string StaffDn = "OU=Staff," + PeopleDn;

    // ---------------------------------------------------------------------------------------
    // The three scopes
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Base is the directory's own meaning: the object itself and nothing else.
    /// </summary>
    [Fact]
    public void BaseListsTheSelectedObjectAlone()
    {
        WriteATree();

        var page = List(PeopleDn, ListingScope.Base);

        Assert.Equal([PeopleDn], page.Objects.Select(o => o.DistinguishedName));
    }

    /// <summary>
    /// One level is the selected object and what is directly inside it - and the object itself is
    /// included, which is how the directory defines the scope and what the predecessor showed.
    /// </summary>
    [Fact]
    public void OneLevelListsTheObjectAndWhatIsDirectlyInsideIt()
    {
        WriteATree();

        var page = List(PeopleDn, ListingScope.OneLevel);

        Assert.Equal(
            ["CN=Alice," + PeopleDn, PeopleDn, StaffDn],
            page.Objects.Select(o => o.DistinguishedName));
    }

    [Fact]
    public void OneLevelDoesNotReachIntoAContainerBeneathIt()
    {
        WriteATree();

        var page = List(PeopleDn, ListingScope.OneLevel);

        Assert.DoesNotContain(
            "CN=Bob," + StaffDn, page.Objects.Select(o => o.DistinguishedName));
    }

    [Fact]
    public void SubtreeReachesEverythingBeneathHoweverDeep()
    {
        WriteATree();

        var page = List(PeopleDn, ListingScope.Subtree);

        Assert.Contains("CN=Bob," + StaffDn, page.Objects.Select(o => o.DistinguishedName));
    }

    [Fact]
    public void SubtreeDoesNotReachOutsideTheContainer()
    {
        WriteATree();

        var page = List(PeopleDn, ListingScope.Subtree);

        Assert.DoesNotContain(
            "CN=Elsewhere," + DomainDn, page.Objects.Select(o => o.DistinguishedName));
    }

    /// <summary>
    /// <c>_</c> matches any single character in a SQL <c>LIKE</c>, and <c>CN=IIS_IUSRS</c> is a
    /// real group in every forest. Without an ESCAPE clause a subtree listing would quietly pull in
    /// objects from a container that merely resembles the one selected - the product reporting
    /// objects as being somewhere they are not.
    /// </summary>
    [Fact]
    public void AContainerWhoseNameHoldsAWildcardCharacterListsOnlyItsOwnObjects()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("CN=IIS_IUSRS," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Real,CN=IIS_IUSRS," + DomainDn, GuidNumbered(2)));
            writer.WriteObject(ObjectAt("CN=Impostor,CN=IISXIUSRS," + DomainDn, GuidNumbered(3)));
        });

        var page = List("CN=IIS_IUSRS," + DomainDn, ListingScope.Subtree);

        Assert.Equal(
            ["CN=IIS_IUSRS," + DomainDn, "CN=Real,CN=IIS_IUSRS," + DomainDn],
            page.Objects.Select(o => o.DistinguishedName));
    }

    // ---------------------------------------------------------------------------------------
    // What a row carries
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The class an administrator recognises the object by is the most specific one the controller
    /// sent, not the first. Every object in the directory is a <c>top</c>.
    /// </summary>
    [Fact]
    public void AnObjectIsTypedByItsMostSpecificClass()
    {
        WriteBundle(writer => writer.WriteObject(ObjectWithClasses(
            "CN=Alice," + DomainDn, GuidNumbered(1), "top", "person", "user")));

        var page = List("CN=Alice," + DomainDn, ListingScope.Base);

        Assert.Equal("user", page.Objects[0].ObjectClass);
    }

    /// <summary>
    /// A class that did not arrive is not guessed at from anything else.
    /// </summary>
    [Fact]
    public void AnObjectWhoseClassDidNotArriveHasNoneInvented()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt("CN=Alice," + DomainDn, GuidNumbered(1))));

        var page = List("CN=Alice," + DomainDn, ListingScope.Base);

        Assert.Null(page.Objects[0].ObjectClass);
    }

    // ---------------------------------------------------------------------------------------
    // Order and paging
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ObjectsAreOrderedByNameSoTheListReadsTheSameEveryTime()
    {
        WriteBundle(writer =>
        {
            writer.WriteObject(ObjectAt("CN=Zoe," + DomainDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=alice," + DomainDn, GuidNumbered(2)));
            writer.WriteObject(ObjectAt("CN=Mike," + DomainDn, GuidNumbered(3)));
        });

        var page = List(DomainDn, ListingScope.Subtree);

        Assert.Equal(["alice", "Mike", "Zoe"], page.Objects.Select(o => o.Name));
    }

    /// <summary>
    /// The order is applied before the page is cut, so the first page really is the first hundred
    /// by name rather than the first hundred the database happened to reach.
    /// </summary>
    [Fact]
    public void TheFirstPageIsTheFirstObjectsByName()
    {
        WriteManyObjects(250);

        var page = List(DomainDn, ListingScope.Subtree);

        Assert.Equal("CN=object-0000," + DomainDn, page.Objects[0].DistinguishedName);
    }

    [Fact]
    public void APageHoldsNoMoreThanItsSize()
    {
        WriteManyObjects(250);

        var page = List(DomainDn, ListingScope.Subtree);

        Assert.Equal(100, page.Objects.Count);
    }

    [Fact]
    public void TheSecondPageCarriesOnWhereTheFirstStopped()
    {
        WriteManyObjects(250);

        var page = List(DomainDn, ListingScope.Subtree, pageNumber: 2);

        Assert.Equal("CN=object-0100," + DomainDn, page.Objects[0].DistinguishedName);
    }

    /// <summary>
    /// A pager that counts what it fetched says "1-100 of 100" about a container holding
    /// thousands. The total is of the whole listing.
    /// </summary>
    [Fact]
    public void TheTotalCountsTheWholeListingAndNotThePage()
    {
        WriteManyObjects(250);

        var page = List(DomainDn, ListingScope.Subtree);

        Assert.Equal(250, page.Total);
    }

    [Fact]
    public void APageBeyondTheEndIsEmptyRatherThanAnError()
    {
        WriteManyObjects(10);

        var page = List(DomainDn, ListingScope.Subtree, pageNumber: 9);

        Assert.Empty(page.Objects);
    }

    // ---------------------------------------------------------------------------------------
    // What the listing cannot know
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AListingOfAFullyReadDomainSaysItIsWhole()
    {
        WriteATree();

        var page = List(PeopleDn, ListingScope.Subtree);

        Assert.True(page.ObjectsAreComplete);
    }

    /// <summary>
    /// A short list is indistinguishable from a smaller directory. This is the statement that
    /// tells them apart.
    /// </summary>
    [Fact]
    public void AListingOverADomainTheRunCouldNotReadSaysItIsShort()
    {
        WriteATree(PartlyReadDomain());

        var page = List(PeopleDn, ListingScope.Subtree);

        Assert.False(page.ObjectsAreComplete);
    }

    [Fact]
    public void AShortListingSaysWhatWasNotRead()
    {
        WriteATree(PartlyReadDomain());

        var page = List(PeopleDn, ListingScope.Subtree);

        Assert.Contains("short by an unknown number", page.Shortfall, StringComparison.Ordinal);
    }

    /// <summary>
    /// One object either is in the evidence or is not, so a base listing is never short and must
    /// not carry a warning that would teach an operator to ignore them.
    /// </summary>
    [Fact]
    public void ABaseListingIsNeverReportedAsShort()
    {
        WriteATree(PartlyReadDomain());

        var page = List(PeopleDn, ListingScope.Base);

        Assert.True(page.ObjectsAreComplete);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------------------------------

    private ObjectPage List(string containerDn, ListingScope scope, int pageNumber = 1)
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;
        return reader.ListObjects(containerDn, scope, pageNumber);
    }

    private void WriteATree() => WriteATree(OneDomainRead());

    private void WriteATree(RunCoverage coverage) => WriteBundle(
        writer =>
        {
            writer.WriteObject(ObjectAt(PeopleDn, GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Alice," + PeopleDn, GuidNumbered(2)));
            writer.WriteObject(ObjectAt(StaffDn, GuidNumbered(3)));
            writer.WriteObject(ObjectAt("CN=Bob," + StaffDn, GuidNumbered(4)));
            writer.WriteObject(ObjectAt("CN=Elsewhere," + DomainDn, GuidNumbered(5)));
        },
        coverage);

    private void WriteManyObjects(int count) => WriteBundle(writer =>
    {
        for (var i = 0; i < count; i++)
            writer.WriteObject(ObjectAt($"CN=object-{i:D4},{DomainDn}", GuidNumbered(i)));
    });

    private void WriteBundle(Action<BundleWriter> write) => WriteBundle(write, OneDomainRead());

    private void WriteBundle(Action<BundleWriter> write, RunCoverage coverage)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());
        write(writer);
        writer.Complete(coverage, Finished);
    }

    private static RunCoverage OneDomainRead() => Coverage(DomainCoverage.Read("contoso.com"));

    private static RunCoverage PartlyReadDomain() =>
        Coverage(DomainCoverage.PartiallyRead("contoso.com", "A controller stopped answering."));

    private static RunCoverage Coverage(DomainCoverage domain) =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [domain],
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

    private static EvidenceObject ObjectWithClasses(string dn, Guid guid, params string[] classes) =>
        new(
            SomeCoverage(),
            dn,
            guid,
            [
                new EvidenceAttribute(
                    "objectClass",
                    StoredAttributeCompleteness.Complete,
                    [.. classes.Select(EvidenceValue.OfText)]),
            ],
            Started);

    private static Guid GuidNumbered(int n) => Guid.Parse($"00000000-0000-0000-0000-{n:D12}");
}
