using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

public static partial class RequestedDetailIndex
{
    internal sealed record PayloadLayout(string Table, string Owner, string Ordinal, string Data,
        string Length, string Fingerprint);
    internal sealed record PayloadPiece(long RowId, long Ordinal, int Length, string Hash);
    internal sealed record PayloadPage(KeyValue[] First, KeyValue[] Last, PayloadPiece[] Pieces);

    private static void BuildPayloadIndex(SqliteConnection connection, string schema, Table table,
        RequestedDetailMap map, SqliteTransaction transaction, CancellationToken token)
    {
        var payload = table.Payload ?? throw RequestedDetailMap.Invalid();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        // The producer writes these fingerprints atomically with the final bytes. Publication
        // binds compact locations to this generation; it must not reopen and hash the payload.
        command.CommandText = $"""
            SELECT rowid,{Q(payload.Owner)},{Q(payload.Ordinal)},{Q(payload.Length)},{Q(payload.Fingerprint)}
            FROM {Q(schema)}.{Q(table.Name)} ORDER BY {Q(payload.Owner)},{Q(payload.Ordinal)}
            """;
        using var read = command.ExecuteReader();
        long? owner = null;
        var pieces = new List<PayloadPiece>(MaximumRows);
        RequestedDetailMap.Builder? pages = null;
        long total = 0, scopeRows = 0, pageCount = 0;
        var previousOrdinal = -1L;

        void FinishPage()
        {
            if (pieces.Count == 0) return;
            var key = new KeyValue(1, owner ?? throw RequestedDetailMap.Invalid());
            pages!.Add(Ordinal(pageCount), map.Put(new PayloadPage(
                [key, new(1, pieces[0].Ordinal)], [key, new(1, pieces[^1].Ordinal)], [.. pieces])));
            pageCount++;
            pieces.Clear();
        }

        void FinishScope()
        {
            if (owner is null) return;
            FinishPage();
            var ownerKey = RequestedDetailMap.Key(new KeyValue(1, owner.Value));
            Stage(connection, transaction, ScopeKey(table.Name, ownerKey),
                map.Put(new Scope(table.Name, ownerKey, scopeRows, pageCount, pages!.Finish())));
        }

        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            if (Enumerable.Range(0, 4).Any(column => read.GetFieldType(column) != typeof(long))
                || read.GetFieldType(4) != typeof(byte[])) throw RequestedDetailMap.Invalid();
            var rowId = read.GetInt64(0);
            var nextOwner = read.GetInt64(1);
            var ordinal = read.GetInt64(2);
            var length = read.GetInt64(3);
            var fingerprint = (byte[])read.GetValue(4);
            if (rowId <= 0 || nextOwner <= 0 || ordinal < 0
                || length is < 1 or > RequestedDetailMap.MaximumBytes || fingerprint.Length != 32)
                throw RequestedDetailMap.Invalid();
            if (owner != nextOwner)
            {
                FinishScope();
                owner = nextOwner;
                pages = map.Build();
                scopeRows = pageCount = 0;
                previousOrdinal = -1;
            }
            if (ordinal <= previousOrdinal) throw RequestedDetailMap.Invalid();
            previousOrdinal = ordinal;
            pieces.Add(new(rowId, ordinal, checked((int)length), Convert.ToHexString(fingerprint)));
            scopeRows++;
            total++;
            if (pieces.Count == MaximumRows) FinishPage();
        }
        FinishScope();
        using var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = $"SELECT COUNT(*) FROM {Q(schema)}.{Q(table.Name)}";
        if ((long)count.ExecuteScalar()! != total) throw RequestedDetailMap.Invalid();
        Stage(connection, transaction, TableKey(table.Name), map.Put(table with { Rows = total }));
    }
}
