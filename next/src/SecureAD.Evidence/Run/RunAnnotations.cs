using Microsoft.Data.Sqlite;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// What an operator called a run, and what he wrote about it.
/// </summary>
/// <param name="Name">
/// The operator's own name for the run, or null where he has given none.
/// </param>
/// <param name="Notes">What he wrote about it, or null where he wrote nothing.</param>
/// <param name="IsBaseline">
/// Whether this run is the baseline of its scope group - the run later runs of the same scope are
/// compared against, per <c>docs/decisions/0069-a-baseline-is-marked-deliberately.md</c>.
///
/// <para>
/// <b>It lives here, beside the evidence and outside the seal, rather than in settings.</b> A
/// baseline is a fact about the library, not about the person looking at it: an operator opening
/// the same library from another account must see the same baseline, and one who copies the
/// library to another machine must take it with him. Per-user settings would give each account a
/// private answer to <i>what does changed mean here</i>.
/// </para>
/// <para>
/// False is the honest default: a library nobody has marked has no baseline, and there is no run
/// the product may nominate on the operator's behalf - which is the whole of <c>0069</c>.
/// </para>
/// </param>
public sealed record RunAnnotation(string? Name, string? Notes, bool IsBaseline = false)
{
    /// <summary>A run nobody has annotated.</summary>
    public static RunAnnotation None { get; } = new(null, null, false);
}

/// <summary>
/// Reads and writes the operator's own name and notes for a run.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is annotation and it is not evidence.</b> It is typed by a person after the fact, it
/// may be edited or deleted at any time, and it sits in
/// <see cref="BundleLayout.AnnotationsFileName"/>, outside the seal, so changing it cannot break
/// the proof that the evidence is unmodified. Nothing may present it as something the run
/// observed, and no security claim may rest on it - a run named <i>clean</i> is a run somebody
/// typed the word clean against.
/// </para>
/// <para>
/// <b>The absence of the file, of the table, or of a row all mean the same thing:</b> nobody has
/// annotated this run. They are not distinguished because the difference has no meaning to an
/// operator - a bundle written before this table existed and one nobody has named are both
/// unnamed.
/// </para>
/// <para>
/// The sidecar is created by <c>BundleWriter</c> when a bundle is sealed, so reading never writes
/// into a bundle. A run that ended badly has no sidecar and never gets one from the read path;
/// <see cref="Save"/> creates it, because saving is a write and the operator asked for it.
/// </para>
/// </remarks>
public static class RunAnnotations
{
    private const string Schema =
        """
        CREATE TABLE IF NOT EXISTS run_annotation (
            name         TEXT    NULL,
            notes        TEXT    NULL,
            is_baseline  INTEGER NOT NULL DEFAULT 0,
            only_one_row INTEGER NOT NULL DEFAULT 1
                         CHECK (only_one_row = 1),
            PRIMARY KEY (only_one_row)
        )
        """;

    /// <summary>
    /// Reads what the operator wrote about the run in <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <param name="bundleDirectory">A run's bundle directory.</param>
    /// <returns>
    /// The annotation, or <see cref="RunAnnotation.None"/> when there is none to read. A sidecar
    /// that will not open is reported as no annotation rather than as a failure: an unreadable note
    /// must not stop a run being listed, because the listing is how an operator finds the run in
    /// the first place.
    /// </returns>
    public static RunAnnotation Read(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var path = BundleLayout.AnnotationsPath(bundleDirectory);
        if (!File.Exists(path))
            return RunAnnotation.None;

        try
        {
            using var connection = Open(path, SqliteOpenMode.ReadOnly);

            using var command = connection.CreateCommand();

            // COALESCE over a column that may not be there yet: a sidecar written before the
            // baseline mark existed has a two-column table, and naming is_baseline directly would
            // fail the whole read - losing the name and notes it does have. The read path may not
            // write, so it cannot add the column; Save does that when the operator marks one.
            command.CommandText = HasTheBaselineColumn(connection)
                ? "SELECT name, notes, is_baseline FROM run_annotation"
                : "SELECT name, notes, 0 FROM run_annotation";

            using var reader = command.ExecuteReader();
            if (!reader.Read())
                return RunAnnotation.None;

            return new RunAnnotation(
                reader.IsDBNull(0) ? null : reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1),
                !reader.IsDBNull(2) && reader.GetInt64(2) != 0);
        }
        catch (Exception ex) when (ex is SqliteException or IOException)
        {
            return RunAnnotation.None;
        }
    }

    /// <summary>
    /// Records what the operator has called the run in <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <param name="bundleDirectory">A run's bundle directory.</param>
    /// <param name="annotation">
    /// What to record. Blank text is stored as nothing, so that clearing a name leaves the run
    /// unnamed rather than named with a space.
    /// </param>
    /// <returns>Success, or why it could not be written.</returns>
    public static Result<RunAnnotation> Save(string bundleDirectory, RunAnnotation annotation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(annotation);

        var stored = new RunAnnotation(
            Trimmed(annotation.Name), Trimmed(annotation.Notes), annotation.IsBaseline);
        var path = BundleLayout.AnnotationsPath(bundleDirectory);

        try
        {
            using var connection = Open(path, SqliteOpenMode.ReadWriteCreate);

            using var create = connection.CreateCommand();
            create.CommandText = Schema;
            create.ExecuteNonQuery();

            // CREATE TABLE IF NOT EXISTS does nothing to a table that is already there, so a
            // sidecar written before the baseline mark existed keeps its two columns and every
            // write of the third would fail.
            if (!HasTheBaselineColumn(connection))
            {
                using var add = connection.CreateCommand();
                add.CommandText =
                    "ALTER TABLE run_annotation ADD COLUMN is_baseline INTEGER NOT NULL DEFAULT 0";
                add.ExecuteNonQuery();
            }

            using var upsert = connection.CreateCommand();
            upsert.CommandText =
                """
                INSERT INTO run_annotation (name, notes, is_baseline, only_one_row)
                VALUES ($name, $notes, $baseline, 1)
                ON CONFLICT (only_one_row) DO UPDATE SET
                    name = $name, notes = $notes, is_baseline = $baseline
                """;
            upsert.Parameters.AddWithValue("$name", (object?)stored.Name ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$notes", (object?)stored.Notes ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$baseline", stored.IsBaseline ? 1 : 0);
            upsert.ExecuteNonQuery();

            return Result<RunAnnotation>.Success(stored);
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException)
        {
            return Result<RunAnnotation>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunAnnotationNotSaved",
                ErrorSeverity.Failed,
                $"What you wrote about this run could not be saved: {ex.Message} The run itself is "
                + "untouched - annotations are kept beside the evidence and never inside it.",
                path));
        }
    }

    /// <summary>
    /// Whether this sidecar's table carries the baseline mark yet.
    /// </summary>
    /// <remarks>
    /// Asked rather than inferred from a failed query, because a read that failed for some other
    /// reason would then be reported as <i>not a baseline</i> - a confident false standing in for
    /// a broken sidecar.
    /// </remarks>
    private static bool HasTheBaselineColumn(SqliteConnection connection)
    {
        using var columns = connection.CreateCommand();
        columns.CommandText =
            "SELECT COUNT(*) FROM pragma_table_info('run_annotation') WHERE name = 'is_baseline'";

        return Convert.ToInt64(columns.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) > 0;
    }

    private static string? Trimmed(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static SqliteConnection Open(string path, SqliteOpenMode mode)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = mode,
                Pooling = false,
            }.ToString());

        connection.Open();
        return connection;
    }
}
