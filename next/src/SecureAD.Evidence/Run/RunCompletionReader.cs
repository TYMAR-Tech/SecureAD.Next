using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence.Run;

/// <summary>
/// The moment a sealed run recorded that it finished.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not <see cref="BundleReader"/>.</b> Opening a bundle through
/// <see cref="BundleReader.Open(string, CancellationToken)"/> verifies the seal, which hashes the
/// whole evidence file. This is called once per run every time the library is listed, so going
/// through the reader would make drawing a list cost proportional to the evidence in it.
/// </para>
/// <para>
/// <b>The value is read without the seal having been checked, and that is deliberate.</b> It is a
/// date in a list. <c>docs/decisions/0020-the-seal-detects-corruption-not-tampering.md</c> puts the
/// one verification at the moment a bundle is opened, and a run whose evidence has gone bad is
/// refused there, before anything is read off it. A wrong date on the Home screen is a wrong label;
/// a wrong finding is a wrong answer, and only the second is what the seal exists to prevent.
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
    /// <param name="bundleDirectory">A run that left sealed evidence behind it.</param>
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
