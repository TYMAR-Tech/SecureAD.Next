using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Evidence;

public sealed partial class BulkObjectLookupTests
{
    private readonly ITestOutputHelper _output;

    public BulkObjectLookupTests(ITestOutputHelper output) => _output = output;

    [Theory]
    [InlineData("exact")]
    [InlineData("duplicate")]
    [InlineData("case-duplicate")]
    [InlineData("unicode")]
    [InlineData("escaped")]
    [InlineData("cross-domain")]
    [InlineData("embedded-null")]
    public void NameReusePreservesSqliteAnswersAndCountsActualStatements(string scenario)
    {
        string[] names = scenario switch
        {
            "duplicate" => [Alice, Alice],
            "case-duplicate" => [Alice.ToLowerInvariant(), Alice],
            "unicode" => ["CN=\u00c4lice," + Domain, "CN=\u00e4lice," + Domain],
            "escaped" => [@"CN=Smith\, Jane," + Domain, @"CN=Smith\, John," + Domain],
            "cross-domain" => [Alice, "CN=Alice,DC=child," + Domain],
            "embedded-null" => ["CN=Alice\0x," + Domain, "CN=Alice\0y," + Domain],
            _ => [Alice, Bob],
        };
        var directory = Write(names.Select((name, index) => (name, (Guid?)Guid.NewGuid(), 16 << index)).ToArray());
        using var reference = Open(directory);
        using var reader = Open(directory);
        var requests = names.Concat(names.Select(name => name.Replace("CN=", "cn=", StringComparison.Ordinal)))
            .Append("CN=Missing," + Domain).Distinct(StringComparer.Ordinal).ToArray();
        var expected = requests.ToDictionary(name => name,
            name => (Match: ReferenceMatch(reference.Connection, name), Identity: ReferenceIdentity(reference, name)),
            StringComparer.Ordinal);
        using var counts = new LookupCounts(reader);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        using var baselineTrace = new JudgingInputReuseTests.Statements(reference.Connection);
        var firstPassStatements = 0;
        for (var pass = 0; pass < 3; pass++)
        {
            foreach (var name in requests)
            {
                Assert.Equal(ReferenceMatch(reference.Connection, name), reader.ReadObjectNameMatch(name));
                Assert.Equal(ReferenceIdentity(reference, name), reader.ReadObjectIdentity(name));
            }
            if (pass == 0) firstPassStatements = trace.Sql.Count;
            else Assert.Equal(firstPassStatements, trace.Sql.Count);
        }
        Assert.Equal(3L * requests.Length, counts["name-request"]);
        Assert.Equal(2L * requests.Length, counts["name-cache-hit"]);
        Assert.Equal(3L * requests.Length, counts["identity-request"]);
        Assert.Equal(2L * requests.Length, counts["identity-cache-hit"]);
        Assert.Equal(1, counts["uniqueness-sql"]);
        AssertSqlCounters(counts, trace.Sql);
        Assert.Equal(expected.Values.Count(value => value.Match.ObjectId is not null), counts["identity-row-sql"]);
        Assert.Equal(expected.Values.Count(value => value.Match.Ambiguous), counts["identity-nocase-sql"]);
        if (expected.Values.Any(value => value.Match.Ambiguous)) Assert.Equal(0, counts["exact-sql"]);
        else Assert.Equal(requests.Length, counts["exact-sql"]);
        Assert.Equal(6 * requests.Length, NameSqlCount(baselineTrace.Sql));
        Assert.True(NameSqlCount(trace.Sql) < NameSqlCount(baselineTrace.Sql));
        _output.WriteLine(FormattableString.Invariant(
            $"{scenario}: {6 * requests.Length} logical requests; original SQL={NameSqlCount(baselineTrace.Sql)}, corrected SQL={NameSqlCount(trace.Sql)} (including uniqueness); exact={counts["exact-sql"]}, exact hits={counts["exact-hit"]}, NOCASE={counts["name-nocase-sql"] + counts["identity-nocase-sql"]}, identity rows={counts["identity-row-sql"]}, uniqueness={counts["uniqueness-sql"]}; identical answers"));
    }

    [Theory]
    [InlineData("unique")]
    [InlineData("ambiguous")]
    [InlineData("missing")]
    public void IdentityOnlyReuseKeepsOriginalFirstRowAndMissingResults(string kind)
    {
        var directory = Write([(Alice.ToLowerInvariant(), Guid.NewGuid(), 16),
            (kind == "ambiguous" ? Alice : Bob, Guid.NewGuid(), 32)]);
        using var reference = Open(directory);
        using var reader = Open(directory);
        var name = kind == "missing" ? "CN=Missing," + Domain : Alice;
        var expected = ReferenceIdentity(reference, name);
        using var counts = new LookupCounts(reader);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        Assert.Equal(expected, reader.ReadObjectIdentity(name));
        var statements = trace.Sql.Count;
        Assert.Equal(expected, reader.ReadObjectIdentity(name));
        Assert.Equal(statements, trace.Sql.Count);
        Assert.Equal(2, counts["identity-request"]);
        Assert.Equal(1, counts["identity-cache-hit"]);
        Assert.Equal(1, counts["identity-nocase-sql"]);
        Assert.Equal(0, counts["uniqueness-sql"]);
        Assert.Equal(0, counts["exact-sql"]);
        AssertSqlCounters(counts, trace.Sql);
        var match = reader.ReadObjectNameMatch(name);
        Assert.Equal(kind == "ambiguous", match.Ambiguous);
        Assert.Equal(ReferenceMatch(reference.Connection, name), match);
    }

    [Fact]
    public void QualifiedExactLookupUsesTheExistingIndexAndIdentityUsesTheSelectedRow()
    {
        var guid = Guid.NewGuid();
        var directory = Write([(Alice, guid, 16), (Bob, guid, 32)]);
        using var reader = Open(directory);
        using var counts = new LookupCounts(reader);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        var match = reader.ReadObjectNameMatch(Bob);
        var identity = reader.ReadObjectIdentity(Bob)!;
        Assert.Equal(match.ObjectId, identity.ObjectId);
        Assert.Equal(Bob, identity.DistinguishedName);
        Assert.Equal(guid, identity.ObjectGuid);
        Assert.Equal(reader.Description.CaptureGenerationId, identity.CaptureGenerationId);
        Assert.Equal(1, counts["exact-hit"]);
        Assert.Equal(0, counts["name-nocase-sql"]);
        Assert.Equal(0, counts["identity-nocase-sql"]);
        var exact = Assert.Single(trace.Sql.Where(IsExactNameSql));
        var plan = new BrowsingQueryTrace(reader.Connection);
        using (plan)
        {
            Assert.Contains(plan.Plan(exact), detail => detail.Contains("SEARCH captured_object", StringComparison.Ordinal)
                && detail.Contains("ix_captured_object_dn", StringComparison.Ordinal));
            var row = Assert.Single(trace.Sql.Where(IsIdentityRowSql));
            Assert.Contains(plan.Plan(row), detail => detail.Contains("SEARCH o USING INTEGER PRIMARY KEY", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void AnUnrelatedDuplicateDisablesExactLookupWithoutHidingAUniqueName()
    {
        var directory = Write([(Alice.ToLowerInvariant(), Guid.NewGuid(), 16),
            (Alice, Guid.NewGuid(), 32), (Bob, Guid.NewGuid(), 64)]);
        using var reference = Open(directory);
        using var reader = Open(directory);
        using var counts = new LookupCounts(reader);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        Assert.Equal(ReferenceMatch(reference.Connection, Bob), reader.ReadObjectNameMatch(Bob));
        Assert.Equal(ReferenceIdentity(reference, Bob), reader.ReadObjectIdentity(Bob));
        Assert.Equal(0, counts["exact-sql"]);
        Assert.Equal(1, counts["name-nocase-sql"]);
        Assert.Equal(1, counts["identity-row-sql"]);
        AssertSqlCounters(counts, trace.Sql);
    }

    [Fact]
    public void RepeatedHierarchyAndWmiReadsReuseNamesButStillReadOriginalPolicyInputs()
    {
        var directory = LapsPrecedenceRun.Build([new(1,
            [LapsPrecedenceRun.TextValue(LapsPrecedenceRun.Principal, LapsPrecedenceRun.GroupA)])]);
        using var reader = GpoLinkHierarchyReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        using var counts = new LookupCounts(reader.Bundle);
        using var trace = new JudgingInputReuseTests.Statements(reader.Bundle.Connection);
        var first = reader.Read(computer, CancellationToken.None);
        var policy = Assert.Single(first.Links).Policy!;
        var firstFilter = reader.Bundle.ReadGpoWmiFilter(policy, CancellationToken.None);
        Assert.True(firstFilter.Definition.IsSuccess, firstFilter.Definition.Error?.Description);
        var sql = trace.Sql.Count;
        var lookupSql = NameSqlCount(trace.Sql);
        var second = reader.Read(computer, CancellationToken.None);
        var secondFilter = reader.Bundle.ReadGpoWmiFilter(policy, CancellationToken.None);
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Equal(JsonSerializer.Serialize(firstFilter), JsonSerializer.Serialize(secondFilter));
        Assert.NotSame(first.Containers[0].Values, second.Containers[0].Values);
        Assert.NotSame(firstFilter.PolicyValues, secondFilter.PolicyValues);
        Assert.Equal(lookupSql, NameSqlCount(trace.Sql));
        Assert.True(trace.Sql.Count > sql);
        Assert.True(counts["name-cache-hit"] >= 3);
        Assert.True(counts["identity-cache-hit"] >= 3);
        AssertSqlCounters(counts, trace.Sql);
    }

    [Fact]
    public void ReadersOfTheSameProtectedFileQualifyAndReuseIndependently()
    {
        var directory = Write([(Alice, Guid.NewGuid(), 16)]);
        using var file = ProtectedStoreFile.OpenEvidence(directory).Value;
        using var first = BundleReader.Open(file).Value;
        first.PrepareBulkObjectLookup();
        first.ReadObjectNameMatch(Alice);
        first.ReadObjectIdentity(Alice);
        using var second = BundleReader.Open(file).Value;
        using var counts = new LookupCounts(second);
        using var trace = new JudgingInputReuseTests.Statements(second.Connection);
        Assert.Equal(first.ReadObjectNameMatch(Alice), second.ReadObjectNameMatch(Alice));
        Assert.Equal(first.ReadObjectIdentity(Alice), second.ReadObjectIdentity(Alice));
        Assert.Equal(1, counts["uniqueness-sql"]);
        Assert.Equal(1, counts["exact-sql"]);
        Assert.Equal(1, counts["identity-row-sql"]);
        AssertSqlCounters(counts, trace.Sql);
    }

    [Fact]
    public void ReuseCannotCrossCapturesReadersOrSourceRolesAndEndsAtDisposal()
    {
        var directory = Write([(Alice, Guid.NewGuid(), 16)]);
        var other = Write([(Bob, Guid.NewGuid(), 32), (Alice, Guid.NewGuid(), 64)]);
        using var first = Open(directory);
        first.ReadObjectNameMatch(Alice);
        var original = first.ReadObjectIdentity(Alice)!;
        Assert.Null(first.ReadObjectNameMatch(Bob).ObjectId);
        Assert.Null(first.ReadObjectIdentity(Bob));
        using var second = Open(other);
        Assert.NotNull(second.ReadObjectNameMatch(Bob).ObjectId);
        Assert.NotNull(second.ReadObjectIdentity(Bob));
        var selected = second.ReadObjectIdentity(Alice)!;
        Assert.NotEqual(original.ObjectId, selected.ObjectId);
        Assert.NotEqual(original.ObjectGuid, selected.ObjectGuid);
        Assert.NotEqual(original.CaptureGenerationId, selected.CaptureGenerationId);
        using (var navigation = BundleReader.OpenNavigation(directory).Value)
        {
            using var counts = new LookupCounts(navigation);
            Assert.Equal(original, navigation.ReadObjectIdentity(Alice));
            Assert.Equal(1, counts["identity-nocase-sql"]);
            Assert.Equal(0, counts["identity-cache-hit"]);
        }
        Assert.Throws<IOException>(() =>
        {
            using var write = new FileStream(BundleLayout.EvidencePath(directory), FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        });
        first.Dispose();
        Assert.Throws<ObjectDisposedException>(() => first.ReadObjectIdentity(Alice));
        Assert.Throws<ObjectDisposedException>(() => first.ReadObjectIdentity(Bob));
        Assert.Throws<ObjectDisposedException>(() => first.ReadObjectNameMatch(Alice));
        Assert.Throws<ObjectDisposedException>(() => first.ReadObjectNameMatch(Bob));
        Assert.Equal(selected, second.ReadObjectIdentity(Alice));
    }

    [Theory]
    [InlineData("unique")]
    [InlineData("missing")]
    [InlineData("ambiguous")]
    public void CancelledReadersCannotReturnCachedNameOrIdentityResults(string kind)
    {
        var directory = Write([(Alice, Guid.NewGuid(), 16),
            (kind == "ambiguous" ? Alice : Bob, Guid.NewGuid(), 32)]);
        using var cancellation = new CancellationTokenSource();
        using var file = ProtectedStoreFile.OpenEvidence(directory, cancellation.Token).Value;
        using var reader = BundleReader.Open(file, cancellation.Token).Value;
        var name = kind == "missing" ? "CN=Missing," + Domain : Alice;
        reader.ReadObjectNameMatch(name);
        reader.ReadObjectIdentity(name);
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.ReadObjectNameMatch(name));
        Assert.Throws<OperationCanceledException>(() => reader.ReadObjectIdentity(name));
    }

    private static (long? ObjectId, bool Ambiguous) ReferenceMatch(SqliteConnection connection, string name)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT object_id FROM captured_object WHERE distinguished_name=$dn COLLATE NOCASE LIMIT 2";
        command.Parameters.AddWithValue("$dn", name);
        using var rows = command.ExecuteReader();
        if (!rows.Read()) return (null, false);
        var id = rows.GetInt64(0);
        return rows.Read() ? (null, true) : (id, false);
    }

    private static CapturedObjectIdentity? ReferenceIdentity(BundleReader reader, string name) =>
        ObjectAttributesReader.ReadIdentity(reader.Connection, name, false, objectId: null) is { } identity
            ? identity with { CaptureGenerationId = reader.Description.CaptureGenerationId } : null;

    private static bool IsExactNameSql(string sql) =>
        sql.StartsWith("SELECT object_id FROM captured_object WHERE distinguished_name=", StringComparison.Ordinal)
        && !sql.Contains("COLLATE NOCASE", StringComparison.Ordinal);

    private static bool IsIdentityRowSql(string sql) =>
        sql.StartsWith("SELECT o.distinguished_name,", StringComparison.Ordinal)
        && sql.Contains("WHERE o.object_id=", StringComparison.Ordinal);

    private static void AssertSqlCounters(LookupCounts counts, IReadOnlyList<string> sql)
    {
        Assert.Equal(sql.Count(IsExactNameSql), counts["exact-sql"]);
        Assert.Equal(sql.Count(value => value.StartsWith("SELECT object_id FROM captured_object WHERE distinguished_name=", StringComparison.Ordinal)
            && value.Contains("COLLATE NOCASE", StringComparison.Ordinal)), counts["name-nocase-sql"]);
        Assert.Equal(sql.Count(IsIdentityRowSql), counts["identity-row-sql"]);
        Assert.Equal(sql.Count(value => value.StartsWith("SELECT o.distinguished_name,", StringComparison.Ordinal)
            && value.Contains("WHERE o.distinguished_name=", StringComparison.Ordinal)), counts["identity-nocase-sql"]);
        Assert.Equal(sql.Count(value => value.Contains("GROUP BY distinguished_name COLLATE NOCASE", StringComparison.Ordinal)), counts["uniqueness-sql"]);
        var exact = sql.Count(IsExactNameSql);
        Assert.Equal(exact == 0 ? 0 : exact - sql.Count(value =>
            value.StartsWith("SELECT object_id FROM captured_object WHERE distinguished_name=", StringComparison.Ordinal)
            && value.Contains("COLLATE NOCASE", StringComparison.Ordinal)), counts["exact-hit"]);
    }

    private static int NameSqlCount(IEnumerable<string> sql) => sql.Count(value =>
        value.StartsWith("SELECT object_id FROM captured_object WHERE distinguished_name=", StringComparison.Ordinal)
        || value.StartsWith("SELECT o.distinguished_name,", StringComparison.Ordinal)
        || value.Contains("GROUP BY distinguished_name COLLATE NOCASE", StringComparison.Ordinal));

    private sealed class LookupCounts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new(StringComparer.Ordinal);
        internal long this[string operation] => _counts.GetValueOrDefault(operation);

        internal LookupCounts(BundleReader reader)
        {
            var source = reader.Connection.DataSource;
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecureAD.Evidence.Readback" && instrument.Name == "evidence.name_lookup")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                string? operation = null;
                string? path = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "operation") operation = tag.Value as string;
                    if (tag.Key == "source") path = tag.Value as string;
                }
                if (path == source && operation is not null)
                    _counts.AddOrUpdate(operation, value, (_, old) => checked(old + value));
            });
            _listener.Start();
        }

        public void Dispose() => _listener.Dispose();
    }
}
