using System.Reflection;
using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class BundleWriterCommandReuseTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "securead-command-reuse-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTimeOffset When = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
    private const string Domain = "DC=example,DC=invalid";
    private const string Child = "DC=child,DC=example,DC=invalid";
    private const string GuidText = "bf9679c0-0de6-11d0-a285-00aa003049e2";

    [Theory]
    [InlineData("omitted")]
    [InlineData("empty")]
    [InlineData("not-returned")]
    public void OmittedObjectValuesDoNotLeak(string mode)
    {
        using var writer = Open();
        writer.WriteObject(Object(1, [Text("sAMAccountName", "before"), Binary("objectSid", [1, 2, 3])]));
        EvidenceAttribute[] absent = mode switch
        {
            "empty" => [Text("sAMAccountName"), Binary("objectSid")],
            "not-returned" => [new("sAMAccountName", StoredAttributeCompleteness.NotReturned, []), new("objectSid", StoredAttributeCompleteness.NotReturned, [])],
            _ => [],
        };
        var id = writer.WriteObject(Object(2, absent) with { ObjectGuid = null, DistinguishedName = "CN=Root" });
        Finish(writer);
        using var connection = Read();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT samaccountname, objectsid, object_guid, parent_dn FROM captured_object WHERE object_id = {id}";
        using var read = command.ExecuteReader();
        Assert.True(read.Read());
        for (var i = 0; i < 4; i++) Assert.True(read.IsDBNull(i), $"Column {i} retained the preceding row's value.");
    }

    [Fact]
    public void RejectedRowCannotSupplyNextRowsValues()
    {
        using var writer = Open();
        Assert.Throws<InvalidOperationException>(() => writer.WriteObject(Object(1,
            [Text("sAMAccountName", "rejected"), Binary("objectSid", [1, 2]), Text("notInTheCatalogue", "refuse")])));
        var id = writer.WriteObject(Object(2, []));
        Finish(writer);
        Assert.Equal(1L, Scalar("SELECT COUNT(*) FROM captured_object"));
        Assert.Equal(1L, Scalar($"SELECT COUNT(*) FROM captured_object WHERE object_id = {id} AND samaccountname IS NULL AND objectsid IS NULL"));
    }

    [Fact]
    public void DuplicateColumnsKeepSqlitesFirstValue()
    {
        using var reference = new SqliteConnection("Data Source=:memory:");
        reference.Open();
        using var command = reference.CreateCommand();
        command.CommandText = "CREATE TABLE sample (value TEXT); INSERT INTO sample (value, value) VALUES ('first', 'second'); SELECT value FROM sample";
        var expected = command.ExecuteScalar();
        using var writer = Open();
        writer.WriteObject(Object(1, [Text("sAMAccountName", "first"), Text("SAMACCOUNTNAME", "second")]));
        Finish(writer);
        Assert.Equal(expected, Scalar("SELECT samaccountname FROM captured_object"));
    }

    [Fact]
    public void AllHotCommandsAndParametersAreReused()
    {
        using var writer = Open();
        WriteFull(writer, 1, "BA");
        var before = Commands(writer);
        Assert.Equal(8, before.Length);
        var parameters = before.Select(c => c.Parameters.Cast<SqliteParameter>().ToArray()).ToArray();
        WriteFull(writer, 2, "WD");
        var after = Commands(writer);
        Assert.Equal(before.Length, after.Length);
        for (var i = 0; i < before.Length; i++)
        {
            Assert.Same(before[i], after[i]);
            Assert.Equal(parameters[i].Length, after[i].Parameters.Count);
            for (var j = 0; j < parameters[i].Length; j++) Assert.Same(parameters[i][j], after[i].Parameters[j]);
        }
        Finish(writer);
        Assert.Equal(2L, Scalar("SELECT COUNT(*) FROM captured_object"));
        Assert.Equal(2L, Scalar("SELECT COUNT(*) FROM access_entry"));
        Assert.Equal(2L, Scalar("SELECT COUNT(*) FROM descriptor_entry"));
    }

    [Fact]
    public void AttributeRowsKeepObjectOrdinalAndStorageType()
    {
        using var writer = Open();
        writer.WriteObject(Object(1, [Text("member", "a", "b"), Binary("sIDHistory", [1, 2], [3, 4])]));
        writer.WriteObject(Object(2, [Text("MEMBER", "c"), Binary("sidhistory", [5, 6])]));
        Finish(writer);
        using var connection = Read();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT object_id, ordinal, value FROM member_value ORDER BY object_id, ordinal";
        using (var read = command.ExecuteReader())
        {
            foreach (var row in new[] { (1L, 0L, "a"), (1L, 1L, "b"), (2L, 0L, "c") })
            {
                Assert.True(read.Read());
                Assert.Equal(row.Item1, read.GetInt64(0));
                Assert.Equal(row.Item2, read.GetInt64(1));
                Assert.Equal(row.Item3, read.GetString(2));
            }
            Assert.False(read.Read());
        }
        command.CommandText = "SELECT object_id, ordinal, value FROM sidhistory_value ORDER BY object_id, ordinal";
        using (var read = command.ExecuteReader())
        {
            foreach (var row in new[] { (1L, 0L, new byte[] { 1, 2 }), (1L, 1L, new byte[] { 3, 4 }), (2L, 0L, new byte[] { 5, 6 }) })
            {
                Assert.True(read.Read());
                Assert.Equal(row.Item1, read.GetInt64(0));
                Assert.Equal(row.Item2, read.GetInt64(1));
                Assert.Equal(row.Item3, Assert.IsType<byte[]>(read.GetValue(2)));
            }
            Assert.False(read.Read());
        }
    }

    [Theory]
    [InlineData("owner_sid")]
    [InlineData("group_sid")]
    [InlineData("object_type_guid")]
    [InlineData("inherited_object_type_guid")]
    public void PermissionRowsResetOptionalFields(string column)
    {
        using var writer = Open();
        var first = Object(1, []);
        StoreDescriptor(writer, writer.WriteObject(first), first.ObjectGuid!.Value, $"O:SYG:BAD:(OA;CI;WP;{GuidText};{GuidText};BA)");
        var second = Object(2, []);
        var id = writer.WriteObject(second);
        StoreDescriptor(writer, id, second.ObjectGuid!.Value, "D:(A;;RP;;;WD)");
        Finish(writer);
        Assert.IsType<DBNull>(Scalar($"SELECT {column} FROM object_security_descriptor AS link JOIN security_descriptor AS d USING (descriptor_id) JOIN descriptor_entry USING (descriptor_id) JOIN access_entry USING (entry_id) WHERE link.object_id = {id}"));
    }

    [Fact]
    public void CommandsBelongToOneWriter()
    {
        using var first = Open();
        using var second = Open(Path.Combine(_directory, "other"));
        WriteFull(first, 1, "BA");
        WriteFull(second, 2, "WD");
        var a = Commands(first);
        var b = Commands(second);
        Assert.Equal(8, a.Length);
        Assert.Equal(8, b.Length);
        Assert.NotSame(a[0].Connection, b[0].Connection);
        foreach (var command in a) Assert.Same(a[0].Connection, command.Connection);
        foreach (var command in b)
        {
            Assert.Same(b[0].Connection, command.Connection);
            Assert.DoesNotContain(command, a);
        }
    }

    [Fact]
    public void RetainedCommandsSurvivePartitionRollback()
    {
        using var writer = BundleWriter.Create(_directory, When);
        var coverage = Coverage();
        writer.BeginPartition(Domain, coverage.Kind, coverage.Controller, coverage.ConnectionSecurity);
        WriteFull(writer, 1, "BA");
        var before = Commands(writer);
        writer.AbortPartition();
        writer.BeginPartition(Domain, coverage.Kind, coverage.Controller, coverage.ConnectionSecurity);
        WriteFull(writer, 2, "WD");
        writer.CompletePartition(coverage);
        Assert.Equal(before, Commands(writer));
        Finish(writer);
        Assert.Equal(1L, Scalar("SELECT COUNT(*) FROM captured_object"));
        Assert.Equal("S-1-1-0", Scalar("SELECT sid FROM trustee"));
        Assert.Equal("row2", Scalar("SELECT samaccountname FROM captured_object WHERE object_id = 1"));
    }

    [Fact]
    public void WarmCommandsUseReplacementTransactionAfterAbsorb()
    {
        using var writer = Open();
        WriteFull(writer, 1, "BA");
        var before = Commands(writer);
        var transaction = before[0].Transaction;
        using (var shard = BundleWriter.Create(_directory, When, BundleShard.Number(1)))
        {
            shard.WriteCoverage(Coverage(Child));
            WriteFull(shard, 3, "AU", Child);
            shard.CompleteShard();
        }
        writer.Absorb(BundleLayout.ShardPath(_directory, BundleShard.Number(1)), BundleShard.Number(1));
        WriteFull(writer, 2, "WD");
        var after = Commands(writer);
        Assert.Equal(before, after);
        Assert.NotNull(after[0].Transaction);
        Assert.NotSame(transaction, after[0].Transaction);
        foreach (var command in after) Assert.Same(after[0].Transaction, command.Transaction);
        Finish(writer);
        foreach (var pair in new[] { ("row1", "S-1-5-32-544"), ("row2", "S-1-1-0"), ("row3", "S-1-5-11") })
            Assert.Equal(pair.Item2, Scalar($"SELECT t.sid FROM captured_object AS o JOIN object_security_descriptor USING (object_id) JOIN descriptor_entry USING (descriptor_id) JOIN access_entry USING (entry_id) JOIN trustee AS t USING (trustee_id) WHERE o.samaccountname = '{pair.Item1}'"));
    }

    [Theory]
    [InlineData("unfinished")]
    [InlineData("complete")]
    [InlineData("shard")]
    public void FinishingReleasesCommandsAndValues(string mode)
    {
        using var writer = BundleWriter.Create(_directory, When, mode == "shard" ? BundleShard.Number(1) : BundleShard.Whole);
        writer.WriteCoverage(Coverage());
        WriteFull(writer, 1, "BA");
        var commands = Commands(writer);
        Assert.Equal(8, commands.Length);
        var disposed = new HashSet<SqliteCommand>();
        foreach (var command in commands)
            command.Disposed += (_, _) => disposed.Add(command);
        if (mode == "complete") Finish(writer);
        else if (mode == "shard") writer.CompleteShard();
        else writer.Dispose();
        foreach (var command in commands)
        {
            Assert.Contains(command, disposed);
            Assert.Empty(command.Parameters.Cast<SqliteParameter>());
        }
        Assert.Empty(Commands(writer));
        writer.Dispose();
    }

    private BundleWriter Open(string? directory = null)
    {
        var writer = BundleWriter.Create(directory ?? _directory, When);
        writer.WriteCoverage(Coverage());
        return writer;
    }

    private static void WriteFull(BundleWriter writer, int number, string trustee, string domain = Domain)
    {
        var row = Object(number, [Text("sAMAccountName", "row" + number), Binary("objectSid", [(byte)number]),
            Text("member", "first" + number, "second" + number), Binary("sIDHistory", [(byte)number, 0])], domain);
        StoreDescriptor(writer, writer.WriteObject(row), row.ObjectGuid!.Value, $"O:SYG:BAD:(A;;RP;;;{trustee})");
    }

    private static void StoreDescriptor(BundleWriter writer, long id, Guid guid, string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static EvidenceObject Object(int number, EvidenceAttribute[] attributes, string domain = Domain) =>
        new(Coverage(domain), $"CN=Object{number},{domain}", new Guid(number, 0, 0, new byte[8]), attributes, When);
    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Binary(string name, params byte[][] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfBytes).ToArray());
    private static PartitionCoverage Coverage(string domain = Domain) => new(domain, NamingContextKind.Domain, "dc." + domain, ConnectionSecurityLevel.SignedAndSealed, 1, 3, 1, [], false);
    private static void Finish(BundleWriter writer) => writer.Complete(RunCoverage.Of(
        CoverageId.ForDomains("example.invalid", ["example.invalid", "child.example.invalid"]),
        [DomainCoverage.Read("example.invalid"), DomainCoverage.Read("child.example.invalid")],
        [ForestPartitionCoverage.Read("CN=Configuration," + Domain, NamingContextKind.Configuration), ForestPartitionCoverage.Read("CN=Schema," + Domain, NamingContextKind.Schema)], SysvolCoverage.Of([])), When.AddHours(1));

    // Row equality alone would pass if commands were recreated. Inspect identity without adding
    // test-only APIs to the production writer, and separately assert the persisted evidence.
    private static SqliteCommand[] Commands(BundleWriter writer) =>
        Assert.IsType<List<SqliteCommand>>(typeof(BundleWriter).GetField("_insertCommands", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(writer)).ToArray();

    private SqliteConnection Read()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = BundleLayout.EvidencePath(_directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }
    private object? Scalar(string sql)
    {
        using var connection = Read();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
    }
}
