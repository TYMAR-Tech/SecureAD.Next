using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Ties <see cref="BundleSchema.Version"/> to the tables and indexes that version actually builds,
/// so the number cannot stay still while the shape underneath it changes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Written because exactly that happened.</b> <c>P-272</c> replaced <c>ace</c> with
/// <c>access_entry</c> and <c>descriptor_entry</c> and left the version at 12, so two incompatible
/// shapes were both stamped 12 and nothing said so. <see cref="BundleReader"/> reads
/// <c>schema_version</c> as its <i>first</i> gate - it is the one member whose job is to say "this
/// build cannot read these tables" - and at 12 it returned a pass on precisely the bundles it
/// exists to stop.
/// </para>
/// <para>
/// <b>It was nearly not caught, and how is the point.</b> Those bundles would still have been
/// refused, because their entries carry canonicalisation version 3 and the build canonicalises to
/// 4. That is refusal by luck: a second gate catching what the first waved through, for an
/// unrelated reason, under the wrong code. Had <c>P-272</c> been a schema change without a
/// canonicalisation change - which most schema changes are - nothing would have refused them at
/// all.
/// </para>
/// <para>
/// <b>The fingerprint is taken from the database rather than from the source.</b> What is pinned is
/// what SQLite reports in <c>sqlite_master</c> after <see cref="BundleSchema.CreateTables"/> and
/// <see cref="BundleSchema.CreateDeferredIndexes"/> have run - the objects a reader will actually
/// meet. Hashing the source strings instead would pin this build's idea of the schema against
/// itself, and would miss the per-attribute tables, which are generated from the catalogue rather
/// than written out.
/// </para>
/// <para>
/// <b>The table is append-only.</b> A row here is a statement about bundles that exist. Editing one
/// says something false about what an older build wrote; the way to record a change is a new
/// version and a new row.
/// </para>
/// </remarks>
public sealed class SchemaVersionFingerprintTests
{
    /// <summary>
    /// What the schema fingerprints to, per version. Add a row when the version is raised; never
    /// edit one.
    /// </summary>
    /// <remarks>
    /// Only version 13 is pinned, because that is the first version this check existed for.
    /// Back-filling the earlier ones would mean computing them from builds nobody is running, which
    /// would be a guess wearing the clothes of a record.
    /// </remarks>
    private static readonly Dictionary<int, string> ExpectedByVersion = new()
    {
        // 13 - `ace` replaced by `access_entry` and `descriptor_entry`, with the ordinal on the
        // link and the entry unique on ace_hash. P-272.
        [13] = "ec7e88e927de488e",
        // 14 - per-policy coverage for the optional SEC-083 Group Policy XML scan.
        [14] = "e28bca65d6c77353",
    };

    [Fact]
    public void TheSchemaFingerprintsToWhatThisVersionIsPinnedTo()
    {
        var actual = Fingerprint();

        Assert.True(
            ExpectedByVersion.TryGetValue(BundleSchema.Version, out var expected),
            $"No schema fingerprint is pinned for version {BundleSchema.Version}, and this build "
            + $"produces '{actual}'.\n\n"
            + "If the schema was changed, raising the version was right and this row is what "
            + "records it - add it. If the version was raised without the schema changing, the "
            + "version should not have moved: every bundle written under the old number is now "
            + "refused for nothing.");

        Assert.True(
            string.Equals(expected, actual, StringComparison.Ordinal),
            $"The schema has changed without its version moving. Version {BundleSchema.Version} is "
            + $"pinned to '{expected}' and this build builds '{actual}'.\n\n"
            + "schema_version is the first gate BundleReader applies and the only one whose job is "
            + "to say that a build cannot read a bundle's tables. Two different shapes under one "
            + "number means that gate passes a bundle it should refuse, and whether anything "
            + "downstream notices is luck.\n\n"
            + "Raise BundleSchema.Version and add a row here. Do not edit the existing row: it is "
            + "a statement about bundles that already exist.");
    }

    /// <summary>
    /// The fingerprint really does follow the schema. Without this the check above could be
    /// satisfied by a constant that never moves whatever the tables do.
    /// </summary>
    [Fact]
    public void TheFingerprintChangesWhenTheSchemaDoes()
    {
        var asBuilt = Fingerprint();
        var withOneMoreTable = Fingerprint("CREATE TABLE a_table_nothing_declares (x INTEGER)");

        Assert.NotEqual(asBuilt, withOneMoreTable);
    }

    /// <summary>
    /// Nothing is pinned for a version this build does not have, which would be a pin nobody can
    /// check.
    /// </summary>
    [Fact]
    public void NoFingerprintIsPinnedForAVersionAheadOfThisBuild()
    {
        var ahead = ExpectedByVersion.Keys.Where(v => v > BundleSchema.Version).ToList();

        Assert.True(
            ahead.Count == 0,
            "Pinned fingerprints name schema versions this build does not have: "
            + string.Join(", ", ahead) + ".");
    }

    /// <summary>
    /// The schema as SQLite reports it once built, hashed. Every table and index, by name and by
    /// the statement that created it.
    /// </summary>
    private static string Fingerprint(string? extra = null)
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        BundleSchema.CreateTables(connection);
        BundleSchema.CreateDeferredIndexes(connection);

        if (extra is not null)
        {
            using var addition = connection.CreateCommand();
            addition.CommandText = extra;
            addition.ExecuteNonQuery();
        }

        var builder = new StringBuilder();
        using (var command = connection.CreateCommand())
        {
            // Ordered by name so that the order statements happen to be issued in cannot move the
            // answer, and including the implicit indexes a UNIQUE constraint creates, whose sql is
            // null and whose presence is the constraint.
            command.CommandText =
                """
                SELECT type, name, COALESCE(sql, '')
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_stat%'
                ORDER BY type, name
                """;

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                builder.Append(reader.GetString(0)).Append('\u001f')
                    .Append(reader.GetString(1)).Append('\u001f')
                    .Append(reader.GetString(2)).Append('\u001e');
            }
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()));
        return Convert.ToHexString(hash)[..16].ToLower(CultureInfo.InvariantCulture);
    }
}
