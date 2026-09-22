using System.Globalization;
using System.Resources;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

internal static class LapsInventoryStorage
{
    private static readonly ResourceManager Messages = new("SecureAD.Judgement.Resources.LapsInventory", typeof(LapsInventoryStorage).Assembly);
    internal static string Message(string key) => Messages.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, """
        CREATE TABLE laps_inventory_product (
            singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
            generation_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('Writing', 'Complete')),
            computer_count INTEGER NULL CHECK (computer_count >= 0)
        );
        CREATE TABLE laps_inventory (
            distinguished_name TEXT COLLATE NOCASE NOT NULL PRIMARY KEY,
            name TEXT COLLATE NOCASE NOT NULL,
            parent_dn TEXT COLLATE NOCASE NULL,
            dn_reversed TEXT COLLATE NOCASE NOT NULL,
            management TEXT NOT NULL,
            result TEXT NOT NULL
        );
        """);

    internal static void CreateIndexes(SqliteConnection connection) => Execute(connection, """
        CREATE INDEX ix_laps_inventory_parent ON laps_inventory(parent_dn, name, distinguished_name);
        CREATE INDEX ix_laps_inventory_subtree ON laps_inventory(dn_reversed, management);
        CREATE INDEX ix_laps_inventory_name ON laps_inventory(name, distinguished_name);
        """);

    internal static void Start(SqliteConnection connection, Guid generation)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO laps_inventory_product VALUES (1, $generation, 'Writing', NULL)";
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.ExecuteNonQuery();
    }

    internal static LapsComputer CreateComputerResult(ObjectAttributes subject)
    {
        var modern = LapsTimestamp.Of(AttributeReading.Text(subject, LapsAttributes.WindowsLapsExpiration));
        var legacy = LapsTimestamp.Of(AttributeReading.Text(subject, LapsAttributes.LegacyLapsExpiration));
        var capability = LapsCapability.Of(subject);
        var management = modern.IsPresent && capability.Kind is LapsCapabilityKind.LegacyLapsOnly
            ? LapsManagement.Unexpected
            : (modern.IsPresent, legacy.IsPresent) switch
            {
                (true, true) => LapsManagement.Migrated,
                (true, false) => LapsManagement.WindowsLaps,
                (false, true) => LapsManagement.LegacyLaps,
                _ => LapsManagement.NotManaged,
            };
        return new(subject.DistinguishedName, DnHelper.ExtractFirstRdn(subject.DistinguishedName),
            subject.ObjectGuid, subject.DomainFqdn,
            new(modern.Raw, modern.Reading, modern.ExpiresUtc), new(legacy.Raw, legacy.Reading, legacy.ExpiresUtc),
            AttributeReading.Text(subject, "operatingSystem"), AttributeReading.Text(subject, "operatingSystemVersion"),
            AttributeReading.Text(subject, "userAccountControl"), AttributeReading.Text(subject, "primaryGroupID"),
            capability, DomainControllerSignals.Of(subject), LapsAttributes.StateOf(subject), management);
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, LapsComputer computer)
    {
        Validate(computer);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO laps_inventory VALUES ($dn, $name, $parent, $reversed, $management, $result)
            """;
        command.Parameters.AddWithValue("$dn", computer.DistinguishedName);
        command.Parameters.AddWithValue("$name", computer.Name);
        command.Parameters.AddWithValue("$parent", (object?)DnHelper.GetParentDn(computer.DistinguishedName) ?? DBNull.Value);
        command.Parameters.AddWithValue("$reversed", DnHelper.ReverseDn(computer.DistinguishedName));
        command.Parameters.AddWithValue("$management", computer.Management.ToString());
        command.Parameters.AddWithValue("$result", JsonSerializer.Serialize(computer, ProofSerialization.Options));
        command.ExecuteNonQuery();
    }

    internal static void Complete(SqliteConnection connection, long expectedComputers)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE laps_inventory_product SET state='Complete', computer_count=$count
            WHERE singleton=1 AND state='Writing' AND (SELECT COUNT(*) FROM laps_inventory)=$count
            """;
        command.Parameters.AddWithValue("$count", expectedComputers);
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT state, computer_count, (SELECT COUNT(*) FROM laps_inventory) FROM laps_inventory_product
            """;
        using var reader = command.ExecuteReader();
        // A writer of findings alone has not produced inventory. Its absence stays explicit on read.
        if (reader.Read() && (reader.GetString(0) != "Complete" || reader.IsDBNull(1) || reader.GetInt64(1) != reader.GetInt64(2)))
            throw Invalid();
    }

    internal static LapsPage Read(SqliteConnection connection, JudgementDescription description,
        string containerDn, ListingScope scope, int pageNumber, ListingCoverage coverage, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);
        ArgumentOutOfRangeException.ThrowIfLessThan(pageNumber, 1);
        ArgumentNullException.ThrowIfNull(coverage);
        cancellationToken.ThrowIfCancellationRequested();
        using (var header = connection.CreateCommand())
        {
            header.CommandText = "SELECT generation_id, state, computer_count FROM laps_inventory_product WHERE singleton=1";
            using var reader = header.ExecuteReader();
            if (!reader.Read()) throw new InvalidOperationException(Message("Unavailable"));
            if (reader.GetString(0) != description.GenerationId.ToString("D") || reader.GetString(1) != "Complete"
                || reader.IsDBNull(2) || reader.GetInt64(2) < 0) throw Invalid();
        }

        var where = scope switch
        {
            ListingScope.Base => "distinguished_name = $dn",
            ListingScope.OneLevel => "(distinguished_name = $dn OR parent_dn = $dn)",
            ListingScope.Subtree => "(dn_reversed = $reversed OR dn_reversed LIKE $prefix ESCAPE '\\')",
            _ => throw new ArgumentOutOfRangeException(nameof(scope)),
        };
        var counts = new Dictionary<LapsManagement, int>();
        using (var command = ScopedCommand(connection, $"SELECT management, COUNT(*) FROM laps_inventory WHERE {where} GROUP BY management", containerDn))
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Enum.TryParse<LapsManagement>(reader.GetString(0), out var state) || !Enum.IsDefined(state)) throw Invalid();
                counts.Add(state, checked((int)reader.GetInt64(1)));
            }
        }

        var computers = new List<LapsComputer>();
        using (var command = ScopedCommand(connection, $"""
            SELECT distinguished_name, management, result FROM laps_inventory WHERE {where}
            ORDER BY name, distinguished_name LIMIT 100 OFFSET $skip
            """, containerDn))
        {
            command.Parameters.AddWithValue("$skip", ((long)pageNumber - 1) * 100);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var computer = JsonSerializer.Deserialize<LapsComputer>(reader.GetString(2), ProofSerialization.Options) ?? throw Invalid();
                Validate(computer);
                if (!string.Equals(computer.DistinguishedName, reader.GetString(0), StringComparison.Ordinal)
                    || computer.Management.ToString() != reader.GetString(1)) throw Invalid();
                computers.Add(computer);
            }
        }
        return new(computers, counts.Values.Sum(), counts, coverage.IsComplete, coverage.Shortfall);
    }

    private static SqliteCommand ScopedCommand(SqliteConnection connection, string sql, string dn)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        var reversed = DnHelper.ReverseDn(dn);
        command.Parameters.AddWithValue("$dn", dn);
        command.Parameters.AddWithValue("$reversed", reversed);
        command.Parameters.AddWithValue("$prefix", reversed.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + ",%");
        return command;
    }

    private static void Validate(LapsComputer row)
    {
        if (string.IsNullOrWhiteSpace(row.DistinguishedName) || string.IsNullOrWhiteSpace(row.Name)
            || row.Capability is null || row.DomainController is null || row.WindowsLaps is null || row.LegacyLaps is null
            || !Enum.IsDefined(row.Management) || !Enum.IsDefined(row.AccountState)
            || !Enum.IsDefined(row.Capability.Kind) || !Enum.IsDefined(row.Capability.Basis)) throw Invalid();
        ValidateTimestamp(row.WindowsLaps);
        ValidateTimestamp(row.LegacyLaps);
    }

    private static void ValidateTimestamp(StoredLapsTimestamp value)
    {
        if (!Enum.IsDefined(value.Reading) || (value.Reading is LapsTimestampReading.Present) != value.ExpiresUtc.HasValue
            || value.ExpiresUtc is { Offset: var offset } && offset != TimeSpan.Zero) throw Invalid();
    }

    private static InvalidDataException Invalid() => new(Message("Invalid"));

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
