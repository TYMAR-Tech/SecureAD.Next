using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed class PathRequesterSelectionStorage : IPathRequesterSelectionSink, IDisposable
{
    private sealed record MembershipIdentity(long Id);
    private sealed record CandidateHeader(PathRequesterFamily Family, string RequesterDn, string TargetDn,
        string? GroupDn, OwnAccountMembershipPermissionKind? PermissionKind, string RequesterFingerprint);

    private readonly SqliteConnection _connection;
    private readonly SqliteTransaction _transaction;
    private readonly JudgementDescription _description;
    private readonly JudgingInputs _sources;
    private readonly PathSharedProofStorage _shared;
    private readonly PreparedStatements _statements;
    private readonly CancellationToken _token;
    private readonly ConditionalWeakTable<object, MembershipIdentity> _membershipCollections = new();
    private long _nextMembership;
    private int _candidateCount;
    private int _sourceCount;
    private bool _completed;

    internal PathRequesterSelectionStorage(SqliteConnection connection, SqliteTransaction transaction,
        JudgementDescription description, JudgingInputs sources, PathSharedProofStorage shared,
        PreparedStatements statements, CancellationToken token)
    {
        sources.RequireFor(description);
        if (transaction.Connection != connection) throw Tier0PathStorage.InvalidProof();
        (_connection, _transaction, _description, _sources, _shared, _statements, _token) =
            (connection, transaction, description, sources, shared, statements, token);
        using var create = connection.CreateCommand();
        create.Transaction = transaction;
        create.CommandText = """
            CREATE TEMP TABLE path_selection_pending (
                question_key TEXT PRIMARY KEY, header TEXT NOT NULL, binding TEXT NOT NULL,
                candidate_sort BLOB NOT NULL, work_sort BLOB NOT NULL);
            CREATE INDEX temp.ix_path_selection_candidate_sort ON path_selection_pending(candidate_sort);
            CREATE INDEX temp.ix_path_selection_work_sort ON path_selection_pending(work_sort);
            CREATE TEMP TABLE path_selection_witness (
                identity TEXT PRIMARY KEY, proof INTEGER NOT NULL, fingerprint BLOB NOT NULL,
                binding TEXT NOT NULL);
            CREATE TEMP TABLE path_selection_use (
                question_key TEXT NOT NULL, ordinal INTEGER NOT NULL, identity TEXT NOT NULL,
                proof INTEGER NOT NULL, fingerprint BLOB NOT NULL, binding TEXT NOT NULL,
                PRIMARY KEY(question_key,ordinal));
            CREATE INDEX temp.ix_path_selection_use_identity ON path_selection_use(question_key,identity);
            CREATE TEMP TABLE path_selection_limitation (
                id INTEGER PRIMARY KEY, value TEXT NOT NULL UNIQUE, sort_key TEXT NOT NULL);
            """;
        create.ExecuteNonQuery();
    }

    public bool Include(PathRequesterCandidate candidate)
    {
        RequireWriting();
        var question = new PathRequesterWorkPlan.Question(1, candidate.Family, candidate.RequesterDn,
            candidate.TargetDn, candidate.GroupDn, candidate.PermissionKind);
        PathRequesterWorkPlan.Validate(question);
        if (candidate.RequesterFingerprint is not { Length: 64 } || candidate.Witnesses is not { Count: > 0 })
            throw Tier0PathStorage.InvalidProof();
        var header = new CandidateHeader(candidate.Family, candidate.RequesterDn, candidate.TargetDn,
            candidate.GroupDn, candidate.PermissionKind, candidate.RequesterFingerprint);
        var json = JsonSerializer.Serialize(header, ProofSerialization.Options);
        var inserted = _statements.Bind("""
            INSERT INTO temp.path_selection_pending VALUES ($key,$header,$binding,$candidate_sort,$work_sort)
            ON CONFLICT(question_key) DO NOTHING
            """, _transaction, ("$key", question.Key), ("$header", json),
            ("$binding", Binding(json)), ("$candidate_sort", OrdinalKey(question.Key)),
            ("$work_sort", WorkKey(question))).ExecuteNonQuery();
        if (inserted is not (0 or 1)) throw Tier0PathStorage.InvalidProof();
        var first = inserted == 1;
        if (first) _candidateCount = checked(_candidateCount + 1);
        foreach (var witness in candidate.Witnesses)
        {
            _token.ThrowIfCancellationRequested();
            var identity = WitnessIdentity(witness);
            if (!first && _statements.Bind("""
                SELECT 1 FROM temp.path_selection_use WHERE question_key=$key AND identity=$identity LIMIT 1
                """, _transaction, ("$key", question.Key), ("$identity", identity)).ExecuteScalar() is not null) continue;
            var reference = Witness(witness, identity);
            var next = _statements.Bind("""
                SELECT COALESCE(MAX(ordinal)+1,0) FROM temp.path_selection_use WHERE question_key=$key
                """, _transaction, ("$key", question.Key)).ExecuteScalar();
            if (next is not long ordinal || ordinal < 0) throw Tier0PathStorage.InvalidProof();
            var binding = UseBinding(question.Key, ordinal, identity, reference);
            if (_statements.Bind("""
                INSERT INTO temp.path_selection_use VALUES ($key,$ordinal,$identity,$proof,$fingerprint,$binding)
                """, _transaction, ("$key", question.Key), ("$ordinal", ordinal), ("$identity", identity),
                ("$proof", reference.Id), ("$fingerprint", reference.Fingerprint), ("$binding", binding)).ExecuteNonQuery() != 1)
                throw Tier0PathStorage.InvalidProof();
        }
        return first;
    }

    public void Source(PathRequesterSelectionSource source)
    {
        RequireWriting();
        _sources.RequireFor(_description);
        if (string.IsNullOrWhiteSpace(source.ResourceDn) || source.Fingerprint is not { Length: 64 })
            throw Tier0PathStorage.InvalidProof();
        Record("Sources", _sourceCount++, _shared.Write(source), null, null);
    }

    public void Limit(PathRequesterSelectionLimitation limitation)
    {
        RequireWriting();
        if (!Enum.IsDefined(limitation.Reason)) throw Tier0PathStorage.InvalidProof();
        var value = JsonSerializer.Serialize(limitation, ProofSerialization.Options);
        var inserted = _statements.Bind("""
            INSERT INTO temp.path_selection_limitation(value,sort_key) VALUES ($value,$sort)
            ON CONFLICT(value) DO NOTHING
            """, _transaction, ("$value", value), ("$sort", Tier0PathCalculation.Fingerprint(limitation))).ExecuteNonQuery();
        if (inserted is not (0 or 1)) throw Tier0PathStorage.InvalidProof();
    }

    internal IEnumerable<PathRequesterWorkPlan.Question> Questions()
    {
        RequireWriting();
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = "SELECT question_key,header,binding,candidate_sort,work_sort FROM temp.path_selection_pending ORDER BY work_sort";
        using var read = command.ExecuteReader();
        var id = 0;
        while (read.Read())
        {
            _token.ThrowIfCancellationRequested();
            var header = ReadHeader(read);
            yield return new(++id, header.Family, header.RequesterDn, header.TargetDn, header.GroupDn, header.PermissionKind);
        }
        if (id != _candidateCount) throw Tier0PathStorage.InvalidProof();
    }

    internal PathCalculationStorage.Selection Complete(PathRequesterSelectionScan scan)
    {
        RequireWriting();
        _sources.RequireFor(_description);
        if (scan.Version != PathRequesterSelector.Version || scan.JudgementGenerationId != _description.GenerationId
            || scan.InputFingerprint is not { Length: 64 }) throw Tier0PathStorage.InvalidProof();
        var candidates = 0;
        using (var command = _connection.CreateCommand())
        {
            command.Transaction = _transaction;
            command.CommandText = "SELECT question_key,header,binding,candidate_sort,work_sort FROM temp.path_selection_pending ORDER BY candidate_sort";
            using var read = command.ExecuteReader();
            while (read.Read())
            {
                _token.ThrowIfCancellationRequested();
                var header = ReadHeader(read);
                var question = new PathRequesterWorkPlan.Question(1, header.Family, header.RequesterDn,
                    header.TargetDn, header.GroupDn, header.PermissionKind);
                var proof = _shared.WriteSelectionCandidate(question, header.RequesterFingerprint, Witnesses(question.Key));
                Record("Candidates", candidates++, proof, question.Key, header.RequesterDn);
            }
        }
        if (candidates != _candidateCount) throw Tier0PathStorage.InvalidProof();
        var limitations = 0;
        using (var command = _connection.CreateCommand())
        {
            command.Transaction = _transaction;
            command.CommandText = "SELECT value,sort_key FROM temp.path_selection_limitation ORDER BY sort_key,id";
            using var read = command.ExecuteReader();
            while (read.Read())
            {
                _token.ThrowIfCancellationRequested();
                var value = JsonSerializer.Deserialize<PathRequesterSelectionLimitation>(read.GetString(0), ProofSerialization.Options)
                    ?? throw Tier0PathStorage.InvalidProof();
                if (!Enum.IsDefined(value.Reason) || Tier0PathCalculation.Fingerprint(value) != read.GetString(1))
                    throw Tier0PathStorage.InvalidProof();
                Record("Limitations", limitations++, _shared.Write(value), null, null);
            }
        }
        var result = new PathCalculationStorage.Selection(scan.Version, scan.JudgementGenerationId,
            scan.InputFingerprint, scan.InputScanCompleted,
            Records("Candidates", candidates), Records("Sources", _sourceCount), Records("Limitations", limitations));
        _completed = true;
        return result;
    }

    private PathProofStorage.Reference Witness(PathRequesterSelectionWitness witness, string identity)
    {
        using (var read = _statements.Bind("""
            SELECT proof,fingerprint,binding FROM temp.path_selection_witness WHERE identity=$identity
            """, _transaction, ("$identity", identity)).ExecuteReader())
        {
            if (read.Read())
            {
                var saved = new PathProofStorage.Reference(read.GetInt64(0), (byte[])read.GetValue(1));
                if (saved.Id <= 0 || saved.Fingerprint.Length != 32
                    || WitnessBinding(identity, saved) != read.GetString(2)) throw Tier0PathStorage.InvalidProof();
                return saved;
            }
        }
        var reference = _shared.PrepareSelectionWitness(witness);
        if (_statements.Bind("""
            INSERT INTO temp.path_selection_witness VALUES ($identity,$proof,$fingerprint,$binding)
            """, _transaction, ("$identity", identity), ("$proof", reference.Id),
            ("$fingerprint", reference.Fingerprint), ("$binding", WitnessBinding(identity, reference))).ExecuteNonQuery() != 1)
            throw Tier0PathStorage.InvalidProof();
        return reference;
    }

    private string WitnessIdentity(PathRequesterSelectionWitness witness)
    {
        if (witness is null || string.IsNullOrWhiteSpace(witness.ResourceDn) || witness.PermissionOrdinal < 0
            || string.IsNullOrWhiteSpace(witness.HolderDn)) throw Tier0PathStorage.InvalidProof();
        object? membership = null;
        if (witness.Membership is { } evidence)
        {
            // Prior record equality compares membership collections by their identity, not
            // their contents. Preserve it without keeping the expanded collections alive.
            membership = new { evidence.Verdict, evidence.SourceFingerprint,
                Links = CollectionIdentity(evidence.Links), Limitations = CollectionIdentity(evidence.Limitations) };
        }
        return JsonSerializer.Serialize(new object?[] { witness.ResourceDn, witness.PermissionOrdinal,
            witness.RequiredMask, witness.HolderDn, witness.MemberDn, membership }, ProofSerialization.Options);
    }

    private long CollectionIdentity<T>(IReadOnlyList<T> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        object? key = values is ImmutableArray<T> immutable ? ImmutableCollectionsMarshal.AsArray(immutable) : values;
        if (key is null) return 0;
        if (!_membershipCollections.TryGetValue(key, out var identity))
            _membershipCollections.Add(key, identity = new(checked(++_nextMembership)));
        return identity.Id;
    }

    private IEnumerable<PathProofStorage.Reference> Witnesses(string key)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = "SELECT ordinal,identity,proof,fingerprint,binding FROM temp.path_selection_use WHERE question_key=$key ORDER BY ordinal";
        command.Parameters.AddWithValue("$key", key);
        using var read = command.ExecuteReader();
        var ordinal = 0L;
        while (read.Read())
        {
            _token.ThrowIfCancellationRequested();
            var identity = read.GetString(1);
            var reference = new PathProofStorage.Reference(read.GetInt64(2), (byte[])read.GetValue(3));
            if (read.GetInt64(0) != ordinal || reference.Id <= 0 || reference.Fingerprint.Length != 32
                || UseBinding(key, ordinal++, identity, reference) != read.GetString(4)) throw Tier0PathStorage.InvalidProof();
            yield return reference;
        }
        if (ordinal == 0) throw Tier0PathStorage.InvalidProof();
    }

    private CandidateHeader ReadHeader(SqliteDataReader read)
    {
        var json = read.GetString(1);
        if (Binding(json) != read.GetString(2)) throw Tier0PathStorage.InvalidProof();
        var header = JsonSerializer.Deserialize<CandidateHeader>(json, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
        var question = new PathRequesterWorkPlan.Question(1, header.Family, header.RequesterDn,
            header.TargetDn, header.GroupDn, header.PermissionKind);
        PathRequesterWorkPlan.Validate(question);
        if (question.Key != read.GetString(0) || header.RequesterFingerprint is not { Length: 64 }
            || !OrdinalKey(question.Key).AsSpan().SequenceEqual((byte[])read.GetValue(3))
            || !WorkKey(question).AsSpan().SequenceEqual((byte[])read.GetValue(4)))
            throw Tier0PathStorage.InvalidProof();
        return header;
    }

    private string Binding(string value) => Tier0PathCalculation.Fingerprint(new
    {
        _description.GenerationId, _description.DerivationGenerationId, _description.EvidenceSeal, Value = value,
    });

    private string WitnessBinding(string identity, PathProofStorage.Reference reference) =>
        Binding(JsonSerializer.Serialize(new { Identity = identity, Reference = reference }, ProofSerialization.Options));

    private string UseBinding(string key, long ordinal, string identity, PathProofStorage.Reference reference) =>
        Binding(JsonSerializer.Serialize(new { Key = key, Ordinal = ordinal, Identity = identity, Reference = reference }, ProofSerialization.Options));

    private void Record(string kind, int ordinal, PathProofStorage.Reference proof, string? key, string? requester)
    {
        if (_statements.Bind("""
            INSERT INTO path_calculation_record(kind,ordinal,proof,fingerprint,question_key,requester)
            VALUES ($kind,$ordinal,$proof,$fingerprint,$key,$requester)
            """, _transaction, ("$kind", kind), ("$ordinal", ordinal), ("$proof", proof.Id),
            ("$fingerprint", proof.Fingerprint), ("$key", key), ("$requester", requester)).ExecuteNonQuery() != 1)
            throw Tier0PathStorage.InvalidProof();
    }

    private PathCalculationStorage.RecordSet Records(string kind, int expected)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        command.CommandText = "SELECT ordinal,proof,fingerprint FROM path_calculation_record WHERE kind=$kind ORDER BY ordinal";
        command.Parameters.AddWithValue("$kind", kind);
        using var read = command.ExecuteReader();
        var count = 0;
        var fingerprint = Tier0PathCalculation.Fingerprint(References());
        if (count != expected) throw Tier0PathStorage.InvalidProof();
        return new(count, fingerprint);
        IEnumerable<PathProofStorage.Reference> References()
        {
            while (read.Read())
            {
                _token.ThrowIfCancellationRequested();
                if (read.GetInt64(0) != count++) throw Tier0PathStorage.InvalidProof();
                yield return new(read.GetInt64(1), (byte[])read.GetValue(2));
            }
        }
    }

    private static byte[] WorkKey(PathRequesterWorkPlan.Question question)
    {
        var key = question.Family switch
        {
            PathRequesterFamily.RequesterDacl => RequesterDaclProofs.Key(new(question.RequesterDn, question.TargetDn)),
            PathRequesterFamily.OwnAccountMembership => OwnAccountMembershipProofs.Key(new(question.RequesterDn, question.TargetDn)
                { PermissionKind = question.PermissionKind!.Value }),
            PathRequesterFamily.MembershipDacl => MembershipDaclProofs.Key(new(question.RequesterDn, question.GroupDn!, question.TargetDn)
                { PermissionKind = question.PermissionKind!.Value }),
            _ => throw Tier0PathStorage.InvalidProof(),
        };
        return [(byte)question.Family, .. OrdinalKey(key)];
    }

    private static byte[] OrdinalKey(string value)
    {
        // UTF-16 code units preserve .NET ordinal ordering, including supplementary names
        // and unpaired code units; SQLite's UTF-8 text order does not.
        var bytes = new byte[checked(value.Length * 2)];
        for (var index = 0; index < value.Length; index++)
        {
            bytes[index * 2] = (byte)(value[index] >> 8);
            bytes[index * 2 + 1] = (byte)value[index];
        }
        return bytes;
    }

    private void RequireWriting()
    {
        _token.ThrowIfCancellationRequested();
        _sources.RequireProtectedBinding(_description);
        if (_completed || _transaction.Connection != _connection) throw new InvalidOperationException("The selection writer no longer owns an active generation transaction.");
    }

    public void Dispose()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = """
            DROP TABLE IF EXISTS temp.path_selection_use;
            DROP TABLE IF EXISTS temp.path_selection_witness;
            DROP TABLE IF EXISTS temp.path_selection_pending;
            DROP TABLE IF EXISTS temp.path_selection_limitation;
            """;
        command.ExecuteNonQuery();
    }
}
