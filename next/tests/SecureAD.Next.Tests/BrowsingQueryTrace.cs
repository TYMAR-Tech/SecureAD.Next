using System.Reflection;
using Microsoft.Data.Sqlite;
using SecureAD.Judgement;
using SQLitePCL;
using Xunit;

namespace SecureAD.Next.Tests;

internal sealed class BrowsingQueryTrace : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly strdelegate_trace _callback;
    internal List<string> Statements { get; } = [];

    internal BrowsingQueryTrace(SqliteConnection connection)
    {
        _connection = connection;
        _callback = (_, sql) => Statements.Add(sql);
        raw.sqlite3_trace(connection.Handle!, _callback, null!);
    }

    internal static SqliteConnection Connection(JudgementReader reader) => Assert.IsType<SqliteConnection>(
        typeof(JudgementReader).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(reader));

    internal string[] Plan(string sql)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "EXPLAIN QUERY PLAN " + sql;
        using var rows = command.ExecuteReader();
        var plan = new List<string>();
        while (rows.Read()) plan.Add(rows.GetString(3));
        Assert.NotEmpty(plan);
        return plan.ToArray();
    }

    public void Dispose()
    {
        raw.sqlite3_trace(_connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(_callback);
    }
}
