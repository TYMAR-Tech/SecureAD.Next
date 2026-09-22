using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PermissionClassificationWriteReuseTests
{
    private const string FirstGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string SecondGuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";

    [Fact]
    public void ReusedParametersPreserveChangingNullAndDuplicateEntries()
    {
        using var store = new Store();
        var result = Produce(
            Entry(2, FirstGuid, SecondGuid),
            Ace(7, Holder, 0x60000),
            Entry(12, SecondGuid, FirstGuid),
            Ace(18, Holder, 0x40000),
            Ace(21, Holder, 0x60000));

        store.Write(result);

        Assert.Equal(JsonSerializer.Serialize(result), JsonSerializer.Serialize(store.Read(result)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConflictingSupportWithinTransactionRollsBackEverything(bool inherited)
    {
        using var store = new Store();
        var result = Produce(Entry(2, FirstGuid, FirstGuid), Entry(7, FirstGuid, FirstGuid));
        var second = result.Entries[1];
        second = inherited
            ? second with { InheritedObjectType = Changed(second.InheritedObjectType!) }
            : second with { ObjectType = Changed(second.ObjectType!) };
        result = result with { Entries = [result.Entries[0], second] };
        store.Observe(result);
        var before = store.Counts();

        Assert.Throws<InvalidDataException>(() => store.Write(result));

        Assert.Equal(before, store.Counts());
    }

    [Fact]
    public void P249SharedReadingIsNotAdoptedWhenTheStoredWordsDiffer()
    {
        using var store = new Store();
        var first = Produce(Entry(2, FirstGuid, null));
        store.Write(first);
        store.StageCollidingReading();
        store.ForgetSharedRows();
        var next = Produce(Entry(2, FirstGuid, null));
        next = next with { Permissions = next.Permissions with { DistinguishedName = "OU=Other,DC=contoso,DC=com" } };
        store.Observe(next);

        Assert.Throws<InvalidDataException>(() => store.Write(next));
    }

    [Fact]
    public void ConflictingCommittedSupportIsNotHiddenByAnotherObject()
    {
        using var store = new Store();
        var first = Produce(Entry(2, FirstGuid, null));
        store.Write(first);
        var next = Produce(Entry(7, FirstGuid, null));
        next = next with
        {
            Permissions = next.Permissions with { DistinguishedName = "OU=Other,DC=contoso,DC=com" },
            Entries = [next.Entries[0] with { ObjectType = Changed(next.Entries[0].ObjectType!) }]
        };
        store.Observe(next);
        var before = store.Counts();

        Assert.Throws<InvalidDataException>(() => store.Write(next));

        Assert.Equal(before, store.Counts());
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(store.Read(first)));
    }

    [Fact]
    public void CancellationRollsBackAndRetryDoesNotReuseUncommittedSupport()
    {
        using var store = new Store();
        using var cancellation = new CancellationTokenSource();
        var callbacks = 0;
        store.Connection.CreateFunction("cancel_write", () => { callbacks++; cancellation.Cancel(); return 0; });
        store.Execute("CREATE TRIGGER cancel_entry AFTER INSERT ON permission_classification_entry BEGIN SELECT cancel_write(); END");
        var result = Produce(Entry(2, FirstGuid, null), Entry(7, SecondGuid, null));
        store.Observe(result);
        var before = store.Counts();

        Assert.Throws<OperationCanceledException>(() => store.Write(result, cancellation.Token));

        Assert.Equal(1, callbacks);
        Assert.Equal(before, store.Counts());
        store.Execute("DROP TRIGGER cancel_entry");
        var retry = result with { Entries = [result.Entries[0] with { ObjectType = Changed(result.Entries[0].ObjectType!) }, result.Entries[1]] };
        store.Write(retry);
        Assert.Equal(JsonSerializer.Serialize(retry), JsonSerializer.Serialize(store.Read(retry)));
    }

    private static PermissionSchemaSupport Changed(PermissionSchemaSupport support) => support with { AmbiguousNames = ["conflicting-captured-name"] };

    private static PermissionEntry Entry(int ordinal, string? objectType, string? inheritedType) => Ace(ordinal, Holder, 0x20) with
    {
        ObjectTypeGuid = objectType, HasObjectType = objectType is not null,
        InheritedObjectTypeGuid = inheritedType, HasInheritedObjectType = inheritedType is not null
    };

    private static PermissionClassification Produce(params PermissionEntry[] entries)
    {
        var schema = SchemaGuidCatalog.CapturedOver(
            [new(FirstGuid, "p249First", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
             new(SecondGuid, "p249Second", SchemaGuidKind.Attribute, SchemaGuidSource.Captured)],
            SchemaGuidCatalog.Embedded, new Dictionary<string, IReadOnlyList<string>>());
        return new PermissionClassificationProducer(schema).CreateObjectResult(Permissions(entries));
    }

    private sealed class Store : IDisposable
    {
        public SqliteConnection Connection { get; } = new("Data Source=:memory:;Foreign Keys=True");
        private readonly Guid generation = Guid.NewGuid();
        private readonly HashSet<string> observed = new(StringComparer.Ordinal);
        private PreparedStatements statements = null!;
        private PermissionWriteSession session = new();
        private int written;

        public Store()
        {
            Connection.Open();
            statements = new PreparedStatements(Connection);
            JudgementSchema.CreateTables(Connection);
            ControlEdgeStorage.Start(Connection, true);
            PermissionClassificationStorage.Start(Connection, generation, true);
        }

        public void Observe(PermissionClassification value)
        {
            if (observed.Add(value.Permissions.DistinguishedName))
                StorageWrites.ControlEdges(Connection, new(value.Permissions.DistinguishedName, null, null, "Computed", ControlUncertainty.None, []), null);
        }

        /// <summary>Forgets the rows this run has shared, as a later run would not know them.</summary>
        public void ForgetSharedRows() => session = new PermissionWriteSession();

        /// <summary>Replaces a stored reading's words while leaving the digest that covers it.</summary>
        /// <remarks>
        /// A genuine SHA-256 collision cannot be produced here, so the condition it would create is
        /// staged instead: a stored row whose fingerprint matches what the writer is about to
        /// compute, holding a different reading. Without the comparison in the writer, the next
        /// object would silently adopt those words as its own.
        /// </remarks>
        public void StageCollidingReading()
        {
            using var command = Connection.CreateCommand();
            command.CommandText = "UPDATE permission_classification_reading SET payload=json_set(payload,'$.Summary','someone else''s words')";
            command.ExecuteNonQuery();
        }

        public void Write(PermissionClassification value, CancellationToken token = default)
        {
            Observe(value);
            try
            {
                using (var transaction = Connection.BeginTransaction())
                {
                    PermissionClassificationStorage.Write(Connection, transaction, generation, value,
                        new PermissionWriteWork(), statements, session, token);
                    transaction.Commit();
                }
            }
            catch
            {
                session.Discard();
                throw;
            }

            session.Promote();
            written++;
        }

        public PermissionClassification Read(PermissionClassification value)
        {
            PermissionClassificationStorage.Complete(Connection, written);
            var description = new JudgementDescription(new string('a', 64), generation, null,
                JudgementRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
            return PermissionClassificationStorage.Read(Connection, description, value.Permissions.DistinguishedName, CancellationToken.None).Classification;
        }

        public long Count(string table)
        {
            using var query = Connection.CreateCommand();
            query.CommandText = "SELECT COUNT(*) FROM " + table;
            return Convert.ToInt64(query.ExecuteScalar());
        }

        public long[] Counts() => [Count("permission_classification_object"), Count("permission_classification_entry"),
            Count("permission_classification_schema"), Count("permission_entry"), Count("shared_proof_value")];

        public void Execute(string sql)
        {
            using var command = Connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        public void Dispose()
        {
            statements.Dispose();
            Connection.Dispose();
        }
    }
}
