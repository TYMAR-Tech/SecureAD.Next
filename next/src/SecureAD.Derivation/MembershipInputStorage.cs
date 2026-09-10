using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Derivation;

internal static class MembershipInputStorage
{
    private static readonly System.Resources.ResourceManager Resources = new("SecureAD.Derivation.Resources.MembershipInput", typeof(MembershipInputStorage).Assembly);
    private static InvalidOperationException Invalid(string key) => new(Resources.GetString(key, System.Globalization.CultureInfo.CurrentUICulture)
        ?? throw new System.Resources.MissingManifestResourceException(key));
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE membership_input_manifest (
                id INTEGER PRIMARY KEY CHECK(id=1), object_count INTEGER NOT NULL,
                capture_complete INTEGER NOT NULL, source_hash TEXT NOT NULL);
            CREATE TABLE membership_input_source (
                ordinal INTEGER PRIMARY KEY, dn TEXT NOT NULL COLLATE NOCASE UNIQUE, proof TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, IReadOnlyList<ObjectAttributes> objects, bool captureComplete)
    {
        using var transaction = connection.BeginTransaction();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO membership_input_source VALUES ($ordinal,$dn,$proof)";
        var ordinal = command.Parameters.Add("$ordinal", SqliteType.Integer);
        var dn = command.Parameters.Add("$dn", SqliteType.Text);
        var proof = command.Parameters.Add("$proof", SqliteType.Text);
        var index = 0;
        foreach (var source in objects.OrderBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            var json = JsonSerializer.Serialize(source, ProofSerialization.Options);
            hash.AppendData(Encoding.UTF8.GetBytes(json + "\n"));
            ordinal.Value = index++;
            dn.Value = source.DistinguishedName;
            proof.Value = json;
            command.ExecuteNonQuery();
        }
        command.Parameters.Clear();
        command.CommandText = "INSERT INTO membership_input_manifest VALUES (1,$count,$complete,$hash)";
        command.Parameters.AddWithValue("$count", index);
        command.Parameters.AddWithValue("$complete", captureComplete);
        command.Parameters.AddWithValue("$hash", Convert.ToHexString(hash.GetHashAndReset()));
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    internal static CapturedMembershipInput Read(SqliteConnection connection, Guid generation)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT object_count,capture_complete,source_hash FROM membership_input_manifest WHERE id=1";
        using var manifest = command.ExecuteReader();
        if (!manifest.Read()) throw Invalid("ManifestMissing");
        var count = manifest.GetInt32(0);
        var complete = manifest.GetBoolean(1);
        var expectedHash = manifest.GetString(2);
        manifest.Close();
        command.CommandText = "SELECT ordinal,dn,proof FROM membership_input_source ORDER BY ordinal";
        using var reader = command.ExecuteReader();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var sources = new List<ObjectAttributes>();
        while (reader.Read())
        {
            var json = reader.GetString(2);
            var source = JsonSerializer.Deserialize<ObjectAttributes>(json, ProofSerialization.Options)
                ?? throw Invalid("SourceMissing");
            if (reader.GetInt32(0) != sources.Count || !string.Equals(source.DistinguishedName, reader.GetString(1), StringComparison.OrdinalIgnoreCase))
                throw Invalid("IdentityInvalid");
            hash.AppendData(Encoding.UTF8.GetBytes(json + "\n"));
            sources.Add(source);
        }
        if (sources.Count != count || Convert.ToHexString(hash.GetHashAndReset()) != expectedHash)
            throw Invalid("ProofInvalid");
        return new(generation, complete, sources);
    }
}
