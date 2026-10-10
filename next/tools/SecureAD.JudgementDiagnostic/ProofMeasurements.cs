using Microsoft.Data.Sqlite;

namespace SecureAD.JudgementDiagnostic;

internal static partial class Program
{
    private static ProofReport ReadProofs(SqliteConnection connection, IReadOnlyList<SchemaObject> schema)
    {
        Console.WriteLine("Measuring proof bytes and references without decoding proof contents...");
        var result = new ProofReport
        {
            StoredProofs = ProofAggregate(connection, """
                SELECT COUNT(*),COUNT(*),COALESCE(SUM(byte_length),0),COALESCE(MAX(byte_length),0),
                       COALESCE(SUM(chunk_count),0)
                FROM path_proof
                """, "path_proof", null),
            StoredChunkBytes = ScalarLong(connection, "SELECT COALESCE(SUM(length(data)),0) FROM path_proof_chunk"),
            StoredChunkCount = ScalarLong(connection, "SELECT COUNT(*) FROM path_proof_chunk"),
        };
        foreach (var table in schema.Where(value => value.Kind == "table" && value.Name != "path_proof_chunk"))
        {
            var columns = new List<string>();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = $"PRAGMA foreign_key_list({Quote(table.Name)})";
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    if (reader.GetString(2) == "path_proof" && reader.GetString(4) == "id")
                        columns.Add(reader.GetString(3));
                }
            }
            foreach (var column in columns)
            {
                Console.WriteLine($"Measuring proof references: {table.Name}.{column}");
                result.References.Add(ProofAggregate(connection, $"""
                    SELECT COUNT(*),COUNT(p.id),COALESCE(SUM(p.byte_length),0),
                           COALESCE(MAX(p.byte_length),0),COALESCE(SUM(p.chunk_count),0)
                    FROM {Quote(table.Name)} r LEFT JOIN path_proof p ON p.id=r.{Quote(column)}
                    """, table.Name, column));
            }
        }
        return result;
    }

    private static ProofAggregateResult ProofAggregate(SqliteConnection connection, string sql, string table, string? column)
    {
        using var command = connection.CreateCommand();
        command.CommandTimeout = 0;
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw new DiagnosticException("A proof aggregate did not return a row.");
        return new ProofAggregateResult(table, column, reader.GetInt64(0), reader.GetInt64(1),
            reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4));
    }

    private sealed class ProofReport
    {
        public string Status { get; } = "measured";
        public string Meaning { get; } = "StoredProofs counts each saved proof once. Reference totals count each reference, may overlap across rows/tables, and must not be added as unique stored bytes. Inline proofs in other tables are included in page accounting, not these path_proof totals.";
        public ProofAggregateResult StoredProofs { get; init; } = new("", null, 0, 0, 0, 0, 0);
        public long StoredChunkBytes { get; init; }
        public long StoredChunkCount { get; init; }
        public bool LengthsAgree => StoredProofs.Bytes == StoredChunkBytes && StoredProofs.Chunks == StoredChunkCount;
        public List<ProofAggregateResult> References { get; } = [];
    }

    private sealed record ProofAggregateResult(string Table, string? Column, long Rows, long MatchedProofs,
        long Bytes, long LargestProofBytes, long Chunks)
    {
        public long UnmatchedReferences => Rows - MatchedProofs;
        public double? AverageProofBytes => MatchedProofs == 0 ? null : (double)Bytes / MatchedProofs;
    }
}
