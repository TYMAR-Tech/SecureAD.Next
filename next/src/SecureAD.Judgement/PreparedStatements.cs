using SecureAD.Evidence;
using Microsoft.Data.Sqlite;

namespace SecureAD.Judgement;

/// <summary>
/// Reusable SQL statements, compiled once and rebound for each row.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists, measured 2026-09-22.</b> Storing the saved permission classifications was
/// 15,447 ms of a 21,309 ms object pass, against 297 ms to reach the verdicts being stored. The
/// breakdown put about 88% of the largest bucket in SQL execution, and the path issues roughly
/// 1.25 million statements per laboratory run - every one of them on a command created, compiled,
/// executed once and thrown away. Three storage redesigns were aimed at the on-disk format before
/// anything measured the statements.
/// </para>
/// <para>
/// <b>Nothing stored changes.</b> The same SQL runs with the same values in the same order; only the
/// compilation is kept. That is deliberate: a change to the saved bytes would need a new format
/// number, a readback and a re-judged run, and none of those is the point here.
/// </para>
/// <para>
/// <b>One command per distinct statement, for the life of the writer.</b> The transaction is
/// reassigned per object because a command outlives the transactions it runs in, while
/// <see cref="SqliteCommand.CommandText"/> is never reassigned, because that is what discards the
/// compiled statement.
/// </para>
/// </remarks>
/// <param name="connection">The open judgement connection these statements belong to.</param>
internal sealed class PreparedStatements(SqliteConnection connection) : IDisposable
{
    private readonly Dictionary<string, SqliteCommand> _commands = new(StringComparer.Ordinal);
    private bool _disposed;
    private RequestedDetailRecordWriter? _records;

    internal RequestedDetailRecordWriter Records => _records ??= new(connection);

    /// <summary>Returns the compiled statement for this SQL, bound to these values.</summary>
    /// <param name="sql">The statement text, which also identifies it.</param>
    /// <param name="transaction">The transaction this execution belongs to.</param>
    /// <param name="parameters">Values in the order the statement's parameters were first declared.</param>
    /// <returns>A command ready to execute.</returns>
    internal SqliteCommand Bind(string sql, SqliteTransaction? transaction,
        params (string Name, object? Value)[] parameters)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_commands.TryGetValue(sql, out var command))
        {
            command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var (name, _) in parameters)
                command.Parameters.Add(new SqliteParameter(name, DBNull.Value));
            _commands.Add(sql, command);
        }

        // THE SAME STATEMENT ALWAYS ARRIVES WITH THE SAME PARAMETERS IN THE SAME ORDER, because the
        // SQL is the cache key and each call site builds its list literally. Assigning by position
        // rather than by name is what makes rebinding cheaper than rebuilding, so a mismatch would
        // silently store one column's value in another: it is checked rather than assumed.
        if (command.Parameters.Count != parameters.Length)
            throw new InvalidOperationException($"Statement expects {command.Parameters.Count} parameters, not {parameters.Length}: {sql}");

        command.Transaction = transaction;
        for (var i = 0; i < parameters.Length; i++)
        {
            var parameter = command.Parameters[i];
            if (!string.Equals(parameter.ParameterName, parameters[i].Name, StringComparison.Ordinal))
                throw new InvalidOperationException($"Statement parameter {i} is {parameter.ParameterName}, not {parameters[i].Name}: {sql}");
            parameter.Value = parameters[i].Value ?? DBNull.Value;
        }

        return command;
    }

    /// <summary>Releases every compiled statement.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _records?.Dispose();
        foreach (var command in _commands.Values) command.Dispose();
        _commands.Clear();
    }
}
