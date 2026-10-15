using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Kernel.Security;
using SecureAD.Shell.Services;
using SQLitePCL;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class NavigationBrowsingTests
{
    internal const string Root = "DC=contoso,DC=com";
    internal const string Folder = "OU=Container%_\\, East," + Root;
    internal const string Group = "CN=Operators," + Folder;
    internal static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;

    [Theory]
    [InlineData("search")]
    [InlineData("identity")]
    [InlineData("members")]
    [InlineData("page")]
    public void OrdinaryBrowsingUsesOnlyTheProtectedNavigationProduct(string action)
    {
        var directory = Capture();
        using var evidence = new FileStream(BundleLayout.EvidencePath(directory), FileMode.Open, FileAccess.Read, FileShare.None);
        using var source = new BundleAssetSource();
        switch (action)
        {
            case "search":
                var search = source.SearchObjects(directory, "operator-204", null);
                Assert.True(search.IsSuccess, search.Error?.Description);
                Assert.Equal("Person 204", Assert.Single(search.Value.Objects).Name);
                break;
            case "identity":
                var identity = source.ReadObjectIdentity(directory, Group);
                Assert.True(identity.IsSuccess, identity.Error?.Description);
                Assert.Equal(("group", "S-1-5-32-544", "contoso.com"),
                    (identity.Value!.ObjectClass, identity.Value.PrincipalSid, identity.Value.DomainFqdn));
                break;
            case "members":
                var members = source.ResolveMembershipReferences(directory, [Person(0), "CN=Missing," + Root, Person(0)]);
                Assert.True(members.IsSuccess, members.Error?.Description);
                Assert.Equal(new[] { Person(0), "CN=Missing," + Root, Person(0) }, members.Value.References.Select(value => value.RecordedName));
                Assert.Null(members.Value.References[1].DistinguishedName);
                Assert.Equal(members.Value.References[0], members.Value.References[2]);
                break;
            case "page":
                var page = source.ListObjects(directory, Folder, ListingScope.Subtree, (ObjectPageMark?)null);
                Assert.True(page.IsSuccess, page.Error?.Description);
                Assert.Equal(100, page.Value.Objects.Count);
                Assert.Equal(207, page.Value.Total);
                Assert.NotNull(page.Value.Next);
                break;
            default: throw new ArgumentOutOfRangeException(nameof(action));
        }
        Assert.True(source.CaptureReadValidity()());
    }

    [Fact]
    public void NavigationSearchAndIdentityMatchTheOriginalCaptureIncludingAccountOnlyMatches()
    {
        var directory = Capture();
        using var raw = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        foreach (var query in new[] { "operator-204", "%_", "Person", "not present", "'", "OPERATORS" })
        {
            var before = raw.SearchObjects(query, null);
            var after = navigation.SearchObjects(query, null);
            Assert.Equal(JsonSerializer.Serialize(before.Objects), JsonSerializer.Serialize(after.Objects));
            Assert.Equal(before.Coverage, after.Coverage);
        }
        Assert.Equal(raw.ReadObjectIdentity(Group), navigation.ReadObjectIdentity(Group));
        Assert.Null(navigation.ReadObjectIdentity("CN=Not captured," + Root));
    }

    [Theory]
    [InlineData(ListingScope.Base)]
    [InlineData(ListingScope.OneLevel)]
    [InlineData(ListingScope.Subtree)]
    public void OrderedContinuationPreservesEveryRowTotalScopeAndExistingNameOrder(ListingScope scope)
    {
        var directory = Capture();
        using var evidence = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        var expected = new List<ListedObject>();
        for (var number = 1; ; number++)
        {
            var page = evidence.ListObjects(Root, scope, number);
            expected.AddRange(page.Objects);
            if (expected.Count == page.Total) break;
        }
        var actual = new List<ListedObject>();
        var statements = new List<string>();
        strdelegate_trace trace = (_, sql) => statements.Add(sql);
        raw.sqlite3_trace(navigation.Connection.Handle!, trace, null!);
        ObjectPageMark? after = null;
        do
        {
            var page = navigation.ListObjects(Root, scope, after);
            Assert.Equal(expected.Count, page.Total);
            Assert.InRange(page.Objects.Count, 1, 100);
            actual.AddRange(page.Objects);
            Assert.True(actual.Count <= expected.Count, "A directory continuation repeated an earlier page.");
            after = page.Next;
        } while (after is not null);
        raw.sqlite3_trace(navigation.Connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Equal(expected.Count, actual.Select(row => row.DistinguishedName).Distinct().Count());
        Assert.DoesNotContain(statements, sql => sql.Contains("OFFSET", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("container")]
    [InlineData("scope")]
    [InlineData("position")]
    public void DirectoryContinuationRefusesAnotherCaptureOrQuestion(string defect)
    {
        var directory = Capture();
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        var mark = navigation.ListObjects(Root, ListingScope.Subtree, (ObjectPageMark?)null).Next!;
        mark = defect switch
        {
            "capture" => mark with { Fingerprint = "foreign" },
            "container" => mark with { ContainerDn = Folder },
            "scope" => mark with { Scope = ListingScope.Base },
            _ => mark with { ObjectId = 0 },
        };
        Assert.Throws<ArgumentException>(() => navigation.ListObjects(Root, ListingScope.Subtree, mark));
    }

    [Fact]
    public void SelectedAttributesDoNotReadUnrelatedMemberPayloadsAndPreserveRequestedValues()
    {
        var directory = Capture();
        using var reader = BundleReader.Open(directory).Value;
        var observed = CountMemberValues(reader);
        Assert.Equal(123, reader.ReadObjectAttributes(Group)!.Find("member")!.Values.Count);
        Assert.Equal(123, observed());
        var before = observed();

        var selected = reader.ReadObjectAttributes(Group, new[] { "sAMAccountName", "objectSid", "servicePrincipalName", "description" })!;

        Assert.Equal(before, observed());
        Assert.Equal(new[] { "description", "objectSid", "sAMAccountName", "servicePrincipalName" },
            selected.Attributes.Select(attribute => attribute.LdapDisplayName));
        Assert.Empty(selected.Find("description")!.Values);
        Assert.Equal(Sid.ToBytes("S-1-5-32-544"), selected.Find("objectSid")!.OnlyValue!.Bytes);
        Assert.Equal(new[] { "HTTP/original", "HTTP/original" }, selected.Find("servicePrincipalName")!.Values.Select(value => value.Text));
        Assert.Equal(new[] { 0, 1 }, selected.Find("servicePrincipalName")!.Values.Select(value => value.Ordinal));
        Assert.Null(selected.Find("member"));
    }

    [Fact]
    public void MembershipReadsOnlyRequestedOriginalValuesWithExactWholeAttributeCounts()
    {
        var directory = Capture();
        using var reader = BundleReader.Open(directory).Value;
        var observed = CountMemberValues(reader);
        var all = new List<AttributeValue>();
        CapturedMembershipMark? after = null;
        foreach (var expected in new[] { 50, 50, 23 })
        {
            var before = observed();
            var page = reader.ReadCapturedMembership(Group, false, after)!;
            Assert.Equal(expected, page.Values.Count);
            Assert.Equal(expected == 50 ? 51 : 23, observed() - before);
            Assert.Equal(123, page.Total);
            Assert.Equal("513", page.PrimaryGroupId);
            all.AddRange(page.Values);
            after = page.Next;
        }
        Assert.Null(after);
        Assert.Equal(Enumerable.Range(0, 123), all.Select(value => value.Ordinal));
        Assert.Equal(Person(0), all[0].Text);
        Assert.Equal(all[0].Text, all[1].Text);
        var parents = reader.ReadCapturedMembership(Group, true, null)!;
        Assert.Equal(1, parents.Total);
        Assert.Equal(Root, Assert.Single(parents.Values).Text);
        Assert.Null(parents.Next);
        Assert.Null(reader.ReadCapturedMembership("CN=Not captured," + Root, false, null));
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("object")]
    [InlineData("attribute")]
    [InlineData("position")]
    public void OriginalMembershipContinuationRefusesAnotherCaptureObjectOrAttribute(string defect)
    {
        var directory = Capture();
        using var reader = BundleReader.Open(directory).Value;
        var mark = reader.ReadCapturedMembership(Group, false, null)!.Next!;
        mark = defect switch
        {
            "capture" => mark with { Fingerprint = "foreign" },
            "object" => mark with { DistinguishedName = Person(0) },
            "attribute" => mark with { Parents = true },
            _ => mark with { Ordinal = -1 },
        };
        Assert.Throws<ArgumentException>(() => reader.ReadCapturedMembership(Group, false, mark));
    }

    internal static string Person(int index) => $"CN=Person {index:D3}," + Folder;

    internal static string Capture()
    {
        var directory = TempDirectories.Create("browsing-native");
        using var writer = BundleWriter.Create(directory, When);
        var partition = new PartitionCoverage(Root, NamingContextKind.Domain, "dc.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 208, 1, [], false);
        writer.WriteCoverage(partition);
        void Write(string dn, string kind, params EvidenceAttribute[] attributes)
        {
            var id = writer.WriteObject(new(partition, dn, Guid.NewGuid(),
                [new("objectClass", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("top"), EvidenceValue.OfText(kind)]), .. attributes], When));
            if (dn != Group) return;
            var bytes = SdBytes.SelfRelativeSd(Sid.ToBytes("S-1-5-18"), null, []);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(Guid.Empty, SecurityDescriptorParser.Parse(bytes)));
        }
        Write(Root, "domainDNS");
        Write(Folder, "organizationalUnit");
        Write(Group, "group",
            Text("sAMAccountName", "Operators"),
            new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-32-544")!)]),
            Text("primaryGroupID", "513"),
            new("member", StoredAttributeCompleteness.Complete,
                Enumerable.Range(0, 123).Select(index => EvidenceValue.OfText(Person(index == 1 ? 0 : index))).ToArray()),
            Text("memberOf", Root),
            new("servicePrincipalName", StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfText("HTTP/original"), EvidenceValue.OfText("HTTP/original")]));
        for (var index = 0; index < 205; index++)
            Write(Person(index), "user", Text("sAMAccountName", $"operator-{index:D3}"));
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
            SysvolCoverage.Of([])), When.AddMinutes(1));
        return directory;
    }

    private static EvidenceAttribute Text(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static Func<int> CountMemberValues(BundleReader reader)
    {
        var count = 0;
        reader.Connection.CreateFunction("observe_member_value", (string value) => { count++; return value; });
        using var command = reader.Connection.CreateCommand();
        command.CommandText = """
            CREATE TEMP VIEW member_value AS
                SELECT object_id,ordinal,observe_member_value(value) AS value FROM main.member_value
            """;
        command.ExecuteNonQuery();
        return () => count;
    }
}
