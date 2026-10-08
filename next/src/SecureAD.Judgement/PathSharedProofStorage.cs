using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed class PathSharedProofStorage
{
    private sealed record Link(long Id, string Fingerprint);
    private sealed record EntryLink(long Id, int Ordinal, string Fingerprint);

    private readonly SqliteConnection _connection;
    private readonly JudgementDescription _description;
    private readonly CancellationToken _token;
    private readonly PathProofStorage.Writer? _writer;
    private readonly SharedPermissionStorage? _permissions;
    private readonly PreparedStatements? _statements;
    private readonly SqliteTransaction? _transaction;
    private readonly Func<string, byte[]> _lookupHash;
    private readonly Dictionary<Type, JsonSerializerOptions> _inline = [];
    private readonly HashSet<long> _reading = [];
    private Dictionary<PreparedKey, Link>? _prepared;
    private Dictionary<long, Decoded>? _decoded;
    private string? _resource;

    private readonly record struct PreparedKey(Type Type, object Value, string? Resource);
    private sealed record Decoded(string Kind, string Fingerprint, object Value);
    private sealed class PreparedKeyComparer : IEqualityComparer<PreparedKey>
    {
        public bool Equals(PreparedKey x, PreparedKey y) =>
            x.Type == y.Type && ReferenceEquals(x.Value, y.Value) && x.Resource == y.Resource;
        public int GetHashCode(PreparedKey value) =>
            HashCode.Combine(value.Type, RuntimeHelpers.GetHashCode(value.Value), value.Resource);
    }

    internal JsonSerializerOptions Options { get; }

    internal PathSharedProofStorage(SqliteConnection connection, JudgementDescription description, CancellationToken token)
        : this(connection, description, token, null, null, null, OwnershipAuditStorage.Hash)
    {
    }

    internal PathSharedProofStorage(SqliteConnection connection, JudgementDescription description, CancellationToken token,
        PathProofStorage.Writer writer, SqliteTransaction transaction, PreparedStatements statements)
        : this(connection, description, token, writer, transaction, statements, OwnershipAuditStorage.Hash)
    {
    }

    internal PathSharedProofStorage(SqliteConnection connection, JudgementDescription description, CancellationToken token,
        PathProofStorage.Writer? writer, SqliteTransaction? transaction, PreparedStatements? statements,
        Func<string, byte[]> lookupHash)
    {
        (_connection, _description, _token, _writer, _transaction, _statements) =
            (connection, description, token, writer, transaction, statements);
        _lookupHash = lookupHash ?? throw new ArgumentNullException(nameof(lookupHash));
        if (writer is not null)
        {
            if (transaction is null || statements is null) throw new ArgumentException("Shared proof writes require an active transaction.");
            _permissions = new(connection, transaction, statements, new PermissionWriteSession());
        }
        Options = new(ProofSerialization.Options);
        Options.Converters.Insert(0, new Component<OwnAccountMembershipAssessment>(this, "OwnAccount",
            value => value.Target?.DistinguishedName ?? value.Request.TargetDn));
        Options.Converters.Insert(0, new Component<RequesterDaclAssessment>(this, "RequesterDacl",
            value => value.Target?.DistinguishedName ?? value.Request.TargetDn));
        Options.Converters.Insert(0, new Component<IReadOnlyList<ObjectAttributes>>(this, "SchemaEvidence"));
        Options.Converters.Insert(0, new Component<RequesterMembershipEvidence>(this, "MembershipEvidence"));
        Options.Converters.Insert(0, new Component<RequesterMembershipLink>(this, "MembershipLink"));
        Options.Converters.Insert(0, new Component<RequesterResourceContext>(this, "ResourceContext"));
        Options.Converters.Insert(0, new Component<RequesterTrusteeEvidence>(this, "TrusteeEvidence"));
        Options.Converters.Insert(0, new Component<Tier0Target>(this, "Identity"));
        Options.Converters.Insert(0, new Component<Tier0Evidence>(this, "SourceWitness"));
        Options.Converters.Insert(0, new Component<PathRequesterSelectionWitness>(this, "SelectionWitness"));
        Options.Converters.Insert(0, new Entry(this));
    }

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE path_shared_proof (
                proof INTEGER PRIMARY KEY REFERENCES path_proof(id),
                kind TEXT NOT NULL, generation TEXT NOT NULL, derivation_generation TEXT NULL,
                evidence_seal TEXT NOT NULL, resource TEXT NULL,
                lookup_hash BLOB NOT NULL CHECK(length(lookup_hash)=32),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE INDEX ix_path_shared_lookup ON path_shared_proof(kind,lookup_hash);
            """;
        command.ExecuteNonQuery();
    }

    internal PathProofStorage.Reference Write<T>(T value)
    {
        // Hashing, exact comparison and writing traverse the same immutable proof snapshot.
        // Prepare each child once within this call, never retain caller identities across writes.
        var previous = _prepared;
        _prepared = new(new PreparedKeyComparer());
        try
        {
            return (_writer ?? throw new InvalidOperationException("This shared proof reader cannot write.")).Write(value, Options);
        }
        finally { _prepared = previous; }
    }

    internal T Read<T>(long id, string fingerprint)
    {
        using var scope = BeginRead();
        return PathProofStorage.Read<T>(_connection, id, fingerprint, _token, Options);
    }

    internal IDisposable BeginRead()
    {
        var previous = _decoded;
        _decoded ??= [];
        return new ReadScope(this, previous);
    }

    private sealed class ReadScope(PathSharedProofStorage owner, Dictionary<long, Decoded>? previous) : IDisposable
    {
        public void Dispose() => owner._decoded = previous;
    }

    private JsonSerializerOptions Inline<T>()
    {
        if (_inline.TryGetValue(typeof(T), out var options)) return options;
        options = new(Options);
        var converter = options.Converters.Single(value => value is Component<T>);
        options.Converters.Remove(converter);
        _inline.Add(typeof(T), options);
        return options;
    }

    private Link Put<T>(T value, string kind, string? resource)
    {
        _token.ThrowIfCancellationRequested();
        if (_writer is null || _statements is null || _transaction?.Connection != _connection)
            throw new InvalidOperationException("Shared proof writes require their original active transaction.");
        var key = new PreparedKey(typeof(T), value ?? throw Tier0PathStorage.InvalidProof(), resource);
        if (_prepared?.TryGetValue(key, out var prepared) == true) return prepared;
        var previous = _resource;
        _resource = resource ?? previous;
        try
        {
            var options = Inline<T>();
            var digest = Tier0PathCalculation.Fingerprint(value, options);
            var lookup = _lookupHash(digest);
            var candidates = new List<PathProofStorage.Reference>();
            using (var read = _statements.Bind("""
                SELECT proof,generation,derivation_generation,evidence_seal,resource,fingerprint
                FROM path_shared_proof WHERE kind=$kind AND lookup_hash=$lookup ORDER BY proof
                """, _transaction, ("$kind", kind), ("$lookup", lookup)).ExecuteReader())
            {
                while (read.Read())
                {
                    _token.ThrowIfCancellationRequested();
                    if (read.GetString(1) != _description.GenerationId.ToString("D")
                        || NullableText(read, 2) != _description.DerivationGenerationId?.ToString("D")
                        || read.GetString(3) != _description.EvidenceSeal || NullableText(read, 4) != resource) continue;
                    candidates.Add(new(read.GetInt64(0), (byte[])read.GetValue(5)));
                }
            }
            foreach (var stored in candidates)
                if (PathProofStorage.Matches(_connection, stored, value, options, _token))
                    return Remember(new(stored.Id, Convert.ToHexString(stored.Fingerprint)));
            var proof = _writer.Write(value, options);
            if (_statements.Bind("""
                INSERT INTO path_shared_proof VALUES ($proof,$kind,$generation,$derived,$evidence,$resource,$lookup,$hash)
                """, _transaction, ("$proof", proof.Id), ("$kind", kind), ("$generation", _description.GenerationId.ToString("D")),
                ("$derived", _description.DerivationGenerationId?.ToString("D")), ("$evidence", _description.EvidenceSeal),
                ("$resource", resource), ("$lookup", lookup), ("$hash", proof.Fingerprint)).ExecuteNonQuery() != 1)
                throw Tier0PathStorage.InvalidProof();
            return Remember(new(proof.Id, Convert.ToHexString(proof.Fingerprint)));
        }
        finally { _resource = previous; }

        Link Remember(Link link)
        {
            _prepared?.Add(key, link);
            return link;
        }
    }

    private T Get<T>(Link link, string kind, Func<T, string?>? resourceOf)
    {
        _token.ThrowIfCancellationRequested();
        if (_decoded?.TryGetValue(link.Id, out var decoded) == true)
        {
            if (decoded.Kind != kind || decoded.Fingerprint != link.Fingerprint || decoded.Value is not T cached)
                throw Tier0PathStorage.InvalidProof();
            return cached;
        }
        if (link.Id <= 0 || link.Fingerprint is not { Length: 64 } || !_reading.Add(link.Id))
            throw Tier0PathStorage.InvalidProof();
        var previous = _resource;
        try
        {
            using var command = _connection.CreateCommand();
            command.CommandText = """
                SELECT kind,generation,derivation_generation,evidence_seal,resource,fingerprint
                FROM path_shared_proof WHERE proof=$id
                """;
            command.Parameters.AddWithValue("$id", link.Id);
            string? resource;
            using (var read = command.ExecuteReader())
            {
                if (!read.Read() || read.GetString(0) != kind || read.GetString(1) != _description.GenerationId.ToString("D")
                    || NullableText(read, 2) != _description.DerivationGenerationId?.ToString("D")
                    || read.GetString(3) != _description.EvidenceSeal
                    || Convert.ToHexString((byte[])read.GetValue(5)) != link.Fingerprint) throw Tier0PathStorage.InvalidProof();
                resource = NullableText(read, 4);
            }
            if ((resourceOf is null) != (resource is null)) throw Tier0PathStorage.InvalidProof();
            _resource = resource ?? previous;
            var value = PathProofStorage.Read<T>(_connection, link.Id, link.Fingerprint, _token, Inline<T>());
            if (resourceOf is not null && resourceOf(value) != resource) throw Tier0PathStorage.InvalidProof();
            _decoded?.Add(link.Id, new(kind, link.Fingerprint, value!));
            return value;
        }
        finally
        {
            _resource = previous;
            _reading.Remove(link.Id);
        }
    }

    private sealed class Component<T>(PathSharedProofStorage owner, string kind, Func<T, string?>? resource) : JsonConverter<T>
    {
        internal Component(PathSharedProofStorage owner, string kind) : this(owner, kind, null) { }

        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            owner.Get(JsonSerializer.Deserialize<Link>(ref reader, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof(),
                kind, resource);

        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) =>
            JsonSerializer.Serialize(writer, owner.Put(value, kind, resource?.Invoke(value)), ProofSerialization.Options);
    }

    private sealed class Entry(PathSharedProofStorage owner) : JsonConverter<PermissionEntry>
    {
        public override PermissionEntry Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            owner._token.ThrowIfCancellationRequested();
            var link = JsonSerializer.Deserialize<EntryLink>(ref reader, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
            if (link.Id <= 0 || link.Ordinal < 0 || link.Fingerprint is not { Length: 64 } || owner._resource is not { } resource)
                throw Tier0PathStorage.InvalidProof();
            byte[] fingerprint;
            try { fingerprint = Convert.FromHexString(link.Fingerprint); }
            catch (FormatException) { throw Tier0PathStorage.InvalidProof(); }
            return SharedPermissionStorage.ReadReference(owner._connection, resource, owner._description.GenerationId,
                link.Id, link.Ordinal, fingerprint);
        }

        public override void Write(Utf8JsonWriter writer, PermissionEntry value, JsonSerializerOptions options)
        {
            owner._token.ThrowIfCancellationRequested();
            if (owner._permissions is null || owner._resource is not { } resource) throw Tier0PathStorage.InvalidProof();
            var saved = owner._permissions.Write(resource, owner._description.GenerationId, value);
            JsonSerializer.Serialize(writer, new EntryLink(saved.Id, value.Ordinal, Convert.ToHexString(saved.Fingerprint)),
                ProofSerialization.Options);
        }
    }

    internal static void RequirePublishable(SqliteConnection connection, JudgementDescription description)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1 FROM path_shared_proof s LEFT JOIN path_proof p ON p.id=s.proof
            WHERE p.id IS NULL OR s.generation<>$generation OR s.derivation_generation IS NOT $derived
                OR s.evidence_seal<>$evidence LIMIT 1
            """;
        command.Parameters.AddWithValue("$generation", description.GenerationId.ToString("D"));
        command.Parameters.AddWithValue("$derived", (object?)description.DerivationGenerationId?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$evidence", description.EvidenceSeal);
        if (command.ExecuteScalar() is not null) throw Tier0PathStorage.InvalidProof();
    }

    private static string? NullableText(SqliteDataReader read, int column) => read.IsDBNull(column) ? null : read.GetString(column);
}
