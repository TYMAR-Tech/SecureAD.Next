using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed class ControlEvidenceReadScope : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly JudgementDescription _description;
    private readonly string _target;
    private readonly (long Changes, long Version) _revision;
    private readonly Dictionary<long, PermissionEntry> _values = [];
    private readonly Dictionary<(long Id, int Ordinal), (byte[] Fingerprint, PermissionEntry Entry)> _occurrences = [];
    private readonly Dictionary<(long Id, int Catalogue), SharedProofStorage.PreparedRoutes> _routes = [];
    private bool _disposed;

    internal ControlEvidenceReadScope(SqliteConnection connection, JudgementDescription description, string target)
    {
        _connection = connection;
        _description = description;
        _target = target;
        _revision = Revision(connection);
    }

    internal void RequireFor(SqliteConnection connection, ControlEdge edge)
    {
        if (_disposed || !ReferenceEquals(connection, _connection) || edge.Target != _target
            || edge.GenerationId != _description.GenerationId || edge.DerivationGenerationId != _description.DerivationGenerationId
            || Revision(connection) != _revision) throw FullControlEvaluator.InvalidProof();
    }

    internal void RequireUnchanged()
    {
        if (_disposed || Revision(_connection) != _revision) throw FullControlEvaluator.InvalidProof();
    }

    internal PermissionEntry Permission(SqliteDataReader read, ControlEdge edge)
    {
        if (_disposed || edge.Target != _target || edge.GenerationId != _description.GenerationId
            || edge.DerivationGenerationId != _description.DerivationGenerationId || read.IsDBNull(0))
            throw FullControlEvaluator.InvalidProof();
        var id = read.GetInt64(0);
        var ordinal = read.GetInt32(SharedPermissionStorage.ProjectionColumns);
        var fingerprint = (byte[])read.GetValue(SharedPermissionStorage.ProjectionColumns + 1);
        if (_occurrences.TryGetValue((id, ordinal), out var known))
        {
            if (!fingerprint.AsSpan().SequenceEqual(known.Fingerprint)) throw FullControlEvaluator.InvalidProof();
            return known.Entry;
        }
        if (!_values.TryGetValue(id, out var value))
        {
            value = SharedPermissionStorage.ReadShared(read, edge.GenerationId);
            _values.Add(id, value);
        }
        var entry = SharedPermissionStorage.ReadOccurrence(read, edge.Target, edge.GenerationId, value);
        _occurrences.Add((id, ordinal), (fingerprint.ToArray(), entry));
        return entry;
    }

    internal SharedProofStorage.PreparedRoutes Routes(SqliteConnection connection, ControlEdge edge, long id,
        Func<SharedProofStorage.PreparedRoutes> read)
    {
        RequireFor(connection, edge);
        var key = (id, edge.PrincipalCatalogueVersion);
        if (!_routes.TryGetValue(key, out var routes))
        {
            routes = read();
            _routes.Add(key, routes);
        }
        routes.RequireFor(edge.GenerationId, edge.DerivationGenerationId, edge.PrincipalCatalogueVersion);
        return routes;
    }

    private static (long Changes, long Version) Revision(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT total_changes()";
        var changes = (long)command.ExecuteScalar()!;
        command.CommandText = "PRAGMA data_version";
        return (changes, (long)command.ExecuteScalar()!);
    }

    public void Dispose()
    {
        _values.Clear();
        _occurrences.Clear();
        _routes.Clear();
        _disposed = true;
    }
}
