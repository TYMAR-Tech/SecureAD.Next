using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>P-173: listing coverage comes from captured scope and exclusions, not just returned objects.</summary>
public sealed class ObjectListingCoverageTests(ITestOutputHelper output)
{
    private const string Root = "DC=contoso,DC=com";
    private const string Child = "DC=child," + Root;
    private const string Grandchild = "DC=grand," + Child;
    private const string People = "OU=People," + Root;
    private readonly DateTimeOffset _started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    /// <summary>An excluded domain has no captured rows with which to join domain coverage.</summary>
    [Fact]
    public void ASubtreeIncludingAnExcludedChildDomainIsIncomplete()
    {
        var directory = WriteBundle(Exclusion(Child));

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.False(page.ObjectsAreComplete);
    }

    /// <summary>Only scopes that intersect the recorded excluded naming context are incomplete.</summary>
    [Theory]
    [InlineData(Child, Root, ListingScope.Base, true)]
    [InlineData(Child, Root, ListingScope.OneLevel, false)]
    [InlineData(Grandchild, Root, ListingScope.Base, true)]
    [InlineData(Grandchild, Root, ListingScope.OneLevel, true)]
    [InlineData(Grandchild, Root, ListingScope.Subtree, false)]
    [InlineData(Child, People, ListingScope.OneLevel, true)]
    [InlineData(Child, People, ListingScope.Subtree, true)]
    [InlineData(Child, "DC=sibling," + Root, ListingScope.Subtree, true)]
    [InlineData("DC=contoso,DC=net", Root, ListingScope.Subtree, true)]
    [InlineData("DC=notcontoso,DC=com", Root, ListingScope.Subtree, true)]
    [InlineData(Child, Child, ListingScope.Base, true)]
    [InlineData(Child, Child, ListingScope.OneLevel, false)]
    [InlineData(Child, Child, ListingScope.Subtree, false)]
    [InlineData(Child, "OU=Uncaptured," + Child, ListingScope.OneLevel, false)]
    [InlineData(Child, "OU=Uncaptured," + Child, ListingScope.Subtree, false)]
    [InlineData("dc=CHILD,dc=CONTOSO,dc=COM", Root, ListingScope.Subtree, false)]
    [InlineData("dc=CHILD,dc=CONTOSO,dc=COM", Root, ListingScope.OneLevel, false)]
    [InlineData(@"DC=else\,DC=contoso,DC=com", Root, ListingScope.Subtree, true)]
    [InlineData(@"DC=grand\\," + Child, Root, ListingScope.OneLevel, true)]
    public void AnExclusionAffectsOnlyIntersectingScopes(
        string excludedDn, string selectedDn, ListingScope scope, bool expected)
    {
        var directory = WriteBundle(Exclusion(excludedDn));

        var page = List(directory, selectedDn, scope);

        Assert.Equal(expected, page.ObjectsAreComplete);
    }

    /// <summary>Exclusion causes survive readback rather than becoming an attempted read failure.</summary>
    [Theory]
    [InlineData(ExclusionKind.ByChoice, "ExcludedByChoice")]
    [InlineData(ExclusionKind.ForWantOfCandidates, "ExcludedForWantOfCandidates")]
    public void AnExclusionWarningNamesTheRecordedDnAndCause(ExclusionKind kind, string outcome)
    {
        var directory = WriteBundle(Exclusion(Child, kind));

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.Equal($"'{Child}' was recorded as {outcome}, so this list is short by an unknown "
            + "number of objects. Operator's test exclusion.", page.Shortfall);
    }

    /// <summary>A missing free-text note must not erase the recorded exclusion reason.</summary>
    [Fact]
    public void AnExclusionWithoutANoteRetainsItsRecordedReason()
    {
        var directory = WriteBundle(Exclusion(Child) with { Note = null });

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.EndsWith("objects. populated-domain", page.Shortfall, StringComparison.Ordinal);
    }

    /// <summary>An unrelated first exclusion must not hide a later relevant one.</summary>
    [Fact]
    public void ARelevantExclusionIsCheckedAfterAnUnrelatedExclusion()
    {
        var directory = WriteBundle(
            Exclusion("DC=aaa,DC=else,DC=com", domain: "aaa.example"),
            Exclusion(Child));

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.False(page.ObjectsAreComplete);
    }

    /// <summary>Partial descendant reads follow the actual query scope, not just the selected row.</summary>
    [Theory]
    [InlineData(Child, "child.contoso.com", Root, ListingScope.Subtree, false)]
    [InlineData(Child, "child.contoso.com", Root, ListingScope.OneLevel, false)]
    [InlineData(Child, "child.contoso.com", Root, ListingScope.Base, true)]
    [InlineData(Grandchild, "grand.child.contoso.com", Root, ListingScope.Subtree, false)]
    [InlineData(Grandchild, "grand.child.contoso.com", Root, ListingScope.OneLevel, true)]
    [InlineData(Child, "child.contoso.com", People, ListingScope.Subtree, true)]
    public void APartialReadAffectsOnlyTheScopeThatReachesIt(
        string partialDn, string partialDns, string selectedDn, ListingScope scope, bool expected)
    {
        var directory = WriteBundle([], (partialDn, partialDns));

        var page = List(directory, selectedDn, scope);

        Assert.Equal(expected, page.ObjectsAreComplete);
    }

    /// <summary>An actual failed read keeps its cause and is never relabeled as an exclusion.</summary>
    [Fact]
    public void APartialDescendantReadKeepsItsFailureExplanation()
    {
        var directory = WriteBundle([], (Child, "child.contoso.com"));

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.Equal("'child.contoso.com' was recorded as PartiallyRead, so this list is short by "
            + "an unknown number of objects. The test controller stopped answering.", page.Shortfall);
    }

    /// <summary>Incomplete coverage does not estimate or inflate the number captured.</summary>
    [Fact]
    public void AnIncompleteListingKeepsTheCapturedTotal()
    {
        var directory = WriteBundle(Exclusion(Child));

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.Equal(4, page.Total);
    }

    /// <summary>The warning does not fabricate rows for the excluded domain.</summary>
    [Fact]
    public void AnExcludedDomainDoesNotAddInventedObjects()
    {
        var directory = WriteBundle(Exclusion(Child));

        var page = List(directory, Root, ListingScope.Subtree);

        Assert.Equal(
            new[] { Root, People, "CN=RootComputer," + Root, "CN=InsideComputer," + People }
                .Order(StringComparer.Ordinal),
            page.Objects.Select(o => o.DistinguishedName).Order(StringComparer.Ordinal));
    }

    /// <summary>The existing LAPS caller shares scope coverage without changing machine assessment.</summary>
    [Theory]
    [InlineData(Child, ListingScope.OneLevel, false)]
    [InlineData(Child, ListingScope.Subtree, false)]
    [InlineData(Grandchild, ListingScope.Base, true)]
    [InlineData(Grandchild, ListingScope.OneLevel, true)]
    [InlineData(Grandchild, ListingScope.Subtree, false)]
    public void LapsInventoryUsesTheSameExclusionScope(string excludedDn, ListingScope scope, bool expected)
    {
        var directory = WriteBundle(Exclusion(excludedDn));

        var page = ListLaps(directory, scope);

        Assert.Equal(expected, page.ComputersAreComplete);
    }

    /// <summary>The LAPS inventory must disclose the cause, not just return a short count.</summary>
    [Fact]
    public void LapsInventoryRetainsTheExclusionExplanation()
    {
        var directory = WriteBundle(Exclusion(Child, ExclusionKind.ForWantOfCandidates));

        var page = ListLaps(directory, ListingScope.Subtree);

        Assert.Contains("was recorded as ExcludedForWantOfCandidates", page.Shortfall, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ListingScope.Base, true)]
    [InlineData(ListingScope.Subtree, false)]
    public void P248SavedLapsSharedCoverageKeepsScopeCompleteness(ListingScope scope, bool expected)
    {
        var directory = WriteBundle(Exclusion(Child));
        using var reader = BundleReader.Open(directory).Value;

        var coverage = reader.ReadListingCoverage(Root, scope);

        Assert.Equal(expected, coverage.IsComplete);
    }

    private AttestedExclusion Exclusion(
        string dn, ExclusionKind kind = ExclusionKind.ByChoice, string domain = "renamed.example") =>
        new(dn, domain, kind, "populated-domain", "Operator's test exclusion.",
            "CONTOSO\\Auditor", "Test authorizer", _started);

    private string WriteBundle(params AttestedExclusion[] exclusions) => WriteBundle(exclusions, null);

    private string WriteBundle(IReadOnlyList<AttestedExclusion> exclusions, (string Dn, string Dns)? partial)
    {
        var directory = TempDirectories.Create("p173-listing");
        output.WriteLine("Synthetic evidence: {0}", directory);
        var partition = new PartitionCoverage(Root, NamingContextKind.Domain, "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 4, 0, [], false);

        using var writer = BundleWriter.Create(directory, _started);
        writer.WriteCoverage(partition);
        writer.WriteObject(ObjectAt(partition, Root, "domainDNS"));
        writer.WriteObject(ObjectAt(partition, People, "organizationalUnit"));
        writer.WriteObject(ObjectAt(partition, "CN=RootComputer," + Root, "computer"));
        writer.WriteObject(ObjectAt(partition, "CN=InsideComputer," + People, "computer"));

        foreach (var exclusion in exclusions)
            writer.RecordExcludedDomain(exclusion);

        var domains = new List<DomainCoverage> { DomainCoverage.Read("contoso.com") };
        domains.AddRange(exclusions.Select(e => DomainCoverage.Excluded(e.DomainFqdn, e.Kind, e.Reason)));

        if (partial is { } domain)
        {
            var partialPartition = partition with { NamingContextDn = domain.Dn, ObjectsRead = 2 };
            writer.WriteCoverage(partialPartition);
            writer.WriteObject(ObjectAt(partialPartition, domain.Dn, "domainDNS"));
            writer.WriteObject(ObjectAt(partialPartition, "CN=ChildComputer," + domain.Dn, "computer"));
            domains.Add(DomainCoverage.PartiallyRead(domain.Dns, "The test controller stopped answering."));
        }

        writer.Complete(RunCoverage.Of(
            CoverageId.ForDomainsExcluding("contoso.com",
                domains.Select(d => d.DomainFqdn), exclusions.Select(e => e.DomainFqdn)),
            domains,
            [
                ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([])), _started.AddMinutes(1));
        return directory;
    }

    private EvidenceObject ObjectAt(PartitionCoverage partition, string dn, string objectClass) =>
        new(partition, dn, Guid.NewGuid(),
            [
                new EvidenceAttribute("objectClass", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
                new EvidenceAttribute("userAccountControl", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("4096")]),
            ], _started);

    private static ObjectPage List(string directory, string dn, ListingScope scope, int pageNumber = 1)
    {
        var opening = BundleReader.Open(directory);
        Assert.True(opening.IsSuccess, opening.Error?.Description);
        using var reader = opening.Value;
        return reader.ListObjects(dn, scope, pageNumber);
    }

    private static LapsPage ListLaps(string directory, ListingScope scope)
    {
        SavedLapsTestRun.Judge(directory);
        return SavedLapsTestRun.Read(directory, Root, scope);
    }
}
