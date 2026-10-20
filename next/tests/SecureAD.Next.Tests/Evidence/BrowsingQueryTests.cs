using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class BrowsingQueryTests
{
    [Fact]
    public void OneLevelMergesParentOrderAndCountsOnlyOnceForEachScope()
    {
        var directory = NavigationBrowsingTests.Capture();
        using var original = BundleReader.Open(directory).Value;
        using var file = ProtectedStoreFile.OpenNavigation(directory).Value;
        using var navigation = BundleReader.Open(file).Value;
        using var nextReader = BundleReader.Open(file).Value;
        var expected = Enumerable.Range(1, 3)
            .SelectMany(number => original.ListObjects(NavigationBrowsingTests.Folder, ListingScope.OneLevel, number).Objects)
            .ToArray();
        using var trace = new BrowsingQueryTrace(navigation.Connection);
        using var nextTrace = new BrowsingQueryTrace(nextReader.Connection);
        var actual = new List<ListedObject>();
        ObjectPageMark? mark = null;
        do
        {
            var page = (mark is null ? navigation : nextReader)
                .ListObjects(NavigationBrowsingTests.Folder, ListingScope.OneLevel, mark);
            Assert.Equal(207, page.Total);
            actual.AddRange(page.Objects);
            mark = page.Next;
        } while (mark is not null);
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.Single(trace.Statements.Concat(nextTrace.Statements), sql => sql.Contains("COUNT(*)", StringComparison.Ordinal));
        var pages = trace.Statements.Concat(nextTrace.Statements).Where(sql => sql.Contains("o.name_sort", StringComparison.Ordinal)).ToArray();
        Assert.Equal(3, pages.Length);
        foreach (var sql in pages)
        {
            var plan = trace.Plan(sql);
            Assert.Contains(plan, line => line.Contains("MERGE (UNION ALL)", StringComparison.Ordinal));
            Assert.Contains(plan, line => line.Contains("SEARCH o USING INDEX ix_navigation_parent_order", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, line => line.StartsWith("SCAN o", StringComparison.Ordinal));
        }
        Assert.Equal(1, nextReader.ListObjects(NavigationBrowsingTests.Folder, ListingScope.Base, (ObjectPageMark?)null).Total);
        Assert.Equal(207, navigation.ListObjects(NavigationBrowsingTests.Folder, ListingScope.OneLevel, 1).Total);
        Assert.Equal(2, trace.Statements.Concat(nextTrace.Statements).Count(sql => sql.Contains("COUNT(*)", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData(NavigationBrowsingTests.Folder, true)]
    [InlineData(NavigationBrowsingTests.Group, false)]
    public void SubtreeChoosesItsOrderWalkFromScopeSize(string container, bool wide)
    {
        var directory = NavigationBrowsingTests.Capture();
        using var original = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        using var trace = new BrowsingQueryTrace(navigation.Connection);
        var actual = navigation.ListObjects(container, ListingScope.Subtree, (ObjectPageMark?)null);
        var expected = original.ListObjects(container, ListingScope.Subtree, 1);
        Assert.Equal(expected.Total, actual.Total);
        Assert.Equal(JsonSerializer.Serialize(expected.Objects), JsonSerializer.Serialize(actual.Objects));
        var sql = Assert.Single(trace.Statements, statement => statement.Contains("o.name_sort", StringComparison.Ordinal));
        var plan = trace.Plan(sql);
        if (wide)
        {
            Assert.Contains(plan, line => line.Contains("ix_navigation_name_order", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, line => line.Contains("TEMP B-TREE", StringComparison.Ordinal));
        }
        else
        {
            Assert.Contains(plan, line => line.Contains("ix_navigation_reversed", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, line => line.Contains("ix_navigation_name_order", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void IndexedIdentityReadsTheSameOriginalPermissionsAndSelectedValues()
    {
        var directory = NavigationBrowsingTests.Capture();
        using var evidence = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        var identity = navigation.ReadObjectIdentity(NavigationBrowsingTests.Group.ToUpperInvariant())!;
        string[] selected = ["objectClass", "sAMAccountName", "servicePrincipalName"];
        var permissions = evidence.ReadPermissions(identity.DistinguishedName);
        var attributes = evidence.ReadObjectAttributes(identity.DistinguishedName, selected);
        using var trace = new BrowsingQueryTrace(evidence.Connection);
        Assert.Equal(JsonSerializer.Serialize(permissions), JsonSerializer.Serialize(evidence.ReadPermissionsAt(identity)));
        Assert.Equal(JsonSerializer.Serialize(attributes), JsonSerializer.Serialize(evidence.ReadObjectAttributesAt(identity, selected)));
        AssertIndexedObjectReads(trace);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("row")]
    [InlineData("dn")]
    [InlineData("guid")]
    public void IndexedIdentityRefusesForeignOrMismatchedRows(string change)
    {
        var directory = NavigationBrowsingTests.Capture();
        using var evidence = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        var identity = navigation.ReadObjectIdentity(NavigationBrowsingTests.Group)!;
        identity = change switch
        {
            "generation" => identity with { CaptureGenerationId = Guid.NewGuid() },
            "row" => identity with { ObjectId = identity.ObjectId + 1 },
            "dn" => identity with { DistinguishedName = NavigationBrowsingTests.Folder },
            _ => identity with { ObjectGuid = Guid.NewGuid() },
        };
        Assert.Throws<InvalidDataException>(() => evidence.ReadPermissionsAt(identity));
        Assert.Throws<InvalidDataException>(() => evidence.ReadObjectAttributesAt(identity, ["objectClass"]));
    }

    [Theory]
    [InlineData("permissions")]
    [InlineData("selected")]
    [InlineData("all")]
    public void ApplicationObjectReadsRefuseAMismatchedNavigationPosition(string action)
    {
        var directory = NavigationBrowsingTests.Capture();
        var root = AnalysisStoreLifecycle.ResolveCapture(directory).Value;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.NavigationPath(directory, root.GenerationId), Pooling = false,
        }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE captured_object SET object_guid=$guid WHERE distinguished_name=$dn";
            command.Parameters.AddWithValue("$guid", Guid.NewGuid().ToString("D"));
            command.Parameters.AddWithValue("$dn", NavigationBrowsingTests.Group);
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        TestSealing.ResealNavigation(directory);
        using var source = new BundleAssetSource();
        Assert.True(source.ReadObjectIdentity(directory, NavigationBrowsingTests.Group).IsSuccess);
        var error = action switch
        {
            "permissions" => source.ReadPermissions(directory, NavigationBrowsingTests.Group).Error,
            "selected" => source.ReadObjectAttributes(directory, NavigationBrowsingTests.Group, ["objectClass"]).Error,
            _ => source.ReadObjectAttributes(directory, NavigationBrowsingTests.Group).Error,
        };
        Assert.NotNull(error);
        Assert.Contains("The selected identity does not match", error.Description, StringComparison.Ordinal);
    }

    private static void AssertIndexedObjectReads(BrowsingQueryTrace trace)
    {
        var queries = trace.Statements.Where(sql => sql.Contains("FROM captured_object", StringComparison.Ordinal)).ToArray();
        Assert.NotEmpty(queries);
        foreach (var sql in queries)
            Assert.DoesNotContain(trace.Plan(sql), line => line.StartsWith("SCAN ", StringComparison.Ordinal));
    }
}
