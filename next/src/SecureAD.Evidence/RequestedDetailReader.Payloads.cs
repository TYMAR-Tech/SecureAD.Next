namespace SecureAD.Evidence;

public sealed partial class RequestedDetailReader
{
    private List<RequestedDetailIndex.Row> ReadPayloadRows(RequestedDetailIndex.Table table,
        RequestedDetailIndex.KeyValue owner, RequestedDetailIndex.Scope scope, string pageHash)
    {
        var payload = table.Payload ?? throw RequestedDetailMap.Invalid();
        var page = _map.Read<RequestedDetailIndex.PayloadPage>(pageHash);
        if (owner.Kind != 1 || owner.Integer <= 0 || page.Pieces is not { Length: > 0 and <= RequestedDetailIndex.MaximumRows }
            || page.Pieces.Length > scope.Rows || page.First is not { Length: 2 } || page.Last is not { Length: 2 }
            || page.First[0] != owner || page.Last[0] != owner
            || page.First[1] != new RequestedDetailIndex.KeyValue(1, page.Pieces[0].Ordinal)
            || page.Last[1] != new RequestedDetailIndex.KeyValue(1, page.Pieces[^1].Ordinal))
            throw RequestedDetailMap.Invalid();
        var previous = -1L;
        foreach (var piece in page.Pieces)
        {
            if (piece.RowId <= 0 || piece.Ordinal <= previous
                || piece.Length is < 1 or > RequestedDetailMap.MaximumBytes || !RequestedDetailMap.ValidHash(piece.Hash))
                throw RequestedDetailMap.Invalid();
            previous = piece.Ordinal;
        }
        using var command = _connection.CreateCommand();
        command.CommandText = $"""
            SELECT rowid,{RequestedDetailMap.Quote(payload.Owner)},{RequestedDetailMap.Quote(payload.Ordinal)},{RequestedDetailMap.Quote(payload.Length)}
            FROM {RequestedDetailMap.Quote(_schema)}.{RequestedDetailMap.Quote(table.Name)}
            WHERE {RequestedDetailMap.Quote(payload.Owner)}=$owner
                AND {RequestedDetailMap.Quote(payload.Ordinal)} BETWEEN $first AND $last
            ORDER BY {RequestedDetailMap.Quote(payload.Ordinal)} LIMIT 51
            """;
        command.Parameters.AddWithValue("$owner", owner.Integer);
        command.Parameters.AddWithValue("$first", page.Pieces[0].Ordinal);
        command.Parameters.AddWithValue("$last", page.Pieces[^1].Ordinal);
        using var read = command.ExecuteReader();
        var rows = new List<RequestedDetailIndex.Row>(page.Pieces.Length);
        while (read.Read())
        {
            CheckCurrent();
            if (rows.Count == page.Pieces.Length
                || Enumerable.Range(0, 4).Any(column => read.GetFieldType(column) != typeof(long)))
                throw RequestedDetailMap.Invalid();
            var piece = page.Pieces[rows.Count];
            if (read.GetInt64(0) != piece.RowId || read.GetInt64(1) != owner.Integer
                || read.GetInt64(2) != piece.Ordinal || read.GetInt64(3) != piece.Length)
                throw RequestedDetailMap.Invalid();
            rows.Add(new(piece.RowId, [owner, new(1, piece.Ordinal)],
            [
                new(1, owner.Integer, 0, null, null),
                new(1, piece.Ordinal, 0, null, null),
                new(4, 0, 0, null, new(0, 2, 4, piece.Length, piece.Hash, null)),
            ]));
        }
        if (rows.Count != page.Pieces.Length) throw RequestedDetailMap.Invalid();
        return rows;
    }
}
