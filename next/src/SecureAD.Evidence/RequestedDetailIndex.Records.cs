using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

public static partial class RequestedDetailIndex
{
    internal sealed record RecordLayout
    {
        internal RecordLayout(string table, string[] columns, int[] keys)
        {
            if (columns.Length == 0 || columns.Distinct(StringComparer.Ordinal).Count() != columns.Length
                || keys.Length == 0 || keys.Any(key => key < 0 || key >= columns.Length))
                throw new ArgumentException("A producer record needs its exact columns and ordered key.");
            (Table, Columns, Keys) = (table, columns, keys);
            Shape = RequestedDetailMap.Key(new { Table, Columns, Keys });
        }

        internal string Table { get; }
        internal string[] Columns { get; }
        internal int[] Keys { get; }
        internal string Shape { get; }
    }

    private static Row ReadRecordedRow(SqliteConnection connection, string schema, Table table,
        RecordLayout layout, SqliteDataReader read, RequestedDetailMap map, SqliteTransaction transaction,
        CancellationToken token)
    {
        var rowId = read.GetInt64(0);
        var recorded = RequestedDetailRecordWriter.Read(connection, transaction, schema, layout, rowId, token);
        var row = recorded.Row;
        var keys = Enumerable.Range(0, table.Keys.Length)
            .Select(position => KeyValue.From(read.GetValue(1 + position))).ToArray();
        if (row.Cells is null || row.Cells.Length != table.Columns.Length || row.Keys is null
            || !row.Keys.SequenceEqual(keys)) throw RequestedDetailMap.Invalid();
        var fragments = new Dictionary<int, Fragment[]>();
        foreach (var field in recorded.Fields)
        {
            if (field.Column < 0 || field.Column >= row.Cells.Length || field.Fragments is null
                || !fragments.TryAdd(field.Column, field.Fragments)) throw RequestedDetailMap.Invalid();
        }
        var offset = 1 + table.Keys.Length;
        var cells = new Cell[row.Cells.Length];
        for (var column = 0; column < cells.Length; column++)
        {
            token.ThrowIfCancellationRequested();
            var cell = row.Cells[column] ?? throw RequestedDetailMap.Invalid();
            var kind = Kind(read.GetString(offset + column * 2));
            if (cell.Kind != kind) throw RequestedDetailMap.Invalid();
            if (kind is 0 or 1 or 2)
            {
                if (cell.Bytes is not null || cell.Large is not null || fragments.ContainsKey(column)
                    || kind == 1 && cell.Integer != read.GetInt64(offset + column * 2 + 1)
                    || kind == 2 && BitConverter.DoubleToInt64Bits(cell.Real)
                        != BitConverter.DoubleToInt64Bits(read.GetDouble(offset + column * 2 + 1)))
                    throw RequestedDetailMap.Invalid();
                cells[column] = cell;
                continue;
            }
            if (cell.Bytes is { } empty)
            {
                if (empty.Length != 0 || cell.Large is not null || fragments.ContainsKey(column))
                    throw RequestedDetailMap.Invalid();
                cells[column] = cell;
                continue;
            }
            var large = cell.Large ?? throw RequestedDetailMap.Invalid();
            if (large.Row != 0 || large.Column != column || large.Kind != kind || large.Length <= 0
                || large.Fragments is not null || !RequestedDetailMap.ValidHash(large.Hash))
                throw RequestedDetailMap.Invalid();
            RequestedDetailMap.Root? root = null;
            if (large.Length > RequestedDetailMap.MaximumBytes)
            {
                if (!fragments.Remove(column, out var pieces)
                    || pieces.LongLength != (large.Length - 1) / RequestedDetailMap.MaximumBytes + 1)
                    throw RequestedDetailMap.Invalid();
                var builder = map.Build();
                for (var ordinal = 0; ordinal < pieces.Length; ordinal++)
                {
                    token.ThrowIfCancellationRequested();
                    var expected = (int)Math.Min(RequestedDetailMap.MaximumBytes,
                        large.Length - (long)ordinal * RequestedDetailMap.MaximumBytes);
                    if (pieces[ordinal].Length != expected || !RequestedDetailMap.ValidHash(pieces[ordinal].Hash))
                        throw RequestedDetailMap.Invalid();
                    builder.Add(Ordinal(ordinal), map.Put(pieces[ordinal]));
                }
                root = builder.Finish();
            }
            else if (fragments.ContainsKey(column)) throw RequestedDetailMap.Invalid();
            cells[column] = cell with { Large = large with { Fragments = root } };
        }
        if (fragments.Count != 0) throw RequestedDetailMap.Invalid();
        return row with { Cells = cells };
    }
}
