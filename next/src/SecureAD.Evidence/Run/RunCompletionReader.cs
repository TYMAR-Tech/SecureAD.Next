using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence.Run;

/// <summary>
/// The moment a sealed run recorded that it finished.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not <see cref="BundleReader"/>.</b> Opening a bundle through
/// <see cref="BundleReader.Open"/> verifies the seal, which hashes the whole evidence file. The
/// library verifies that seal already, once per run, in <see cref="RunStateReader.Observe"/>;
/// going through the reader as well would hash every bundle in the library twice to fetch one
/// value. So this reads the one column it needs from a bundle whose seal has just been checked.
/// </para>
/// <para>
/// <b>Verification is not skipped, only not repeated</b> - the arrangement
/// <c>BundleAssetSource</c> already has. This is private to the assembly and is called from one
/// place, immediately after the seal was found intact. It must not be given a second caller that
/// has not verified first.
/// </para>
/// <para>
/// The connection is read-only and unpooled, because listing a library must not alter a single
/// byte of anybody's evidence.
/// </para>
/// </remarks>
internal static class RunCompletionReader
{
    /// <summary>
    /// Reads when the run in <paramref name="bundleDirectory"/> recorded that it completed.
    /// </summary>
    /// <param name="bundleDirectory">A run whose seal has just been verified as intact.</param>
    /// <returns>
    /// The recorded moment, or null when it could not be read. Null is returned rather than a
    /// guess: a run whose moment is unknown is placed by the caller and marked as not recorded.
    /// </returns>
    public static DateTimeOffset? CompletedUtc(string bundleDirectory)
    {
        var evidencePath = BundleLayout.EvidencePath(bundleDirectory);

        try
        {
            using var connection = new SqliteConnection(
                new SqliteConnectionStringBuilder
                {
                    DataSource = BundleReader.ImmutableDataSource(evidencePath),
                    Mode = SqliteOpenMode.ReadOnly,
                    Pooling = false,
                }.ToString());

            connection.Open();

            using var command = connection.CreateCommand();
            command.CommandText = "SELECT capture_completed_utc FROM bundle";

            return command.ExecuteScalar() is string stored
                ? DateTimeOffset.ParseExact(
                    stored,
                    "O",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal
                    | System.Globalization.DateTimeStyles.AdjustToUniversal)
                : null;
        }
        catch (Exception ex) when (ex is SqliteException or IOException or FormatException)
        {
            // A bundle that will not answer this question is still a run, and the library must
            // still list it. Ordering degrades to the directory's creation time, which the caller
            // marks as not recorded, so nothing presents a fallback as the run's own statement.
            return null;
        }
    }
}
