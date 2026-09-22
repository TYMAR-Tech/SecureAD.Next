using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Writes one object's control edges in a transaction of its own, the way judging used to.
/// </summary>
/// <remarks>
/// Judging now shares one batched transaction across several objects, so the storage classes take a
/// transaction rather than opening one. These tests were written against the older arrangement and
/// still want exactly it: a write that commits on success and leaves nothing behind on failure. The
/// disposal on the throwing path is the point, not an afterthought - several of these cases assert
/// that a rejected evaluation stored no rows.
/// </remarks>
internal static class StorageWrites
{
    /// <summary>Writes and commits, rolling back if the write throws.</summary>
    /// <param name="connection">The open judgement connection.</param>
    /// <param name="result">The object evaluation to store.</param>
    /// <param name="ownershipTarget">The ownership target to observe, when there is one.</param>
    internal static void ControlEdges(SqliteConnection connection, ControlObjectEvaluation result,
        Tier0Target? ownershipTarget)
    {
        using var statements = new PreparedStatements(connection);
        using var transaction = connection.BeginTransaction();
        ControlEdgeStorage.Write(connection, transaction, statements, result, ownershipTarget);
        transaction.Commit();
    }
}
