using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Derivation;

/// <summary>
/// Writes one derivation store: the dictionary, the nesting facts, and what became of each phase.
/// </summary>
/// <remarks>
/// <para>
/// <b>It writes to a partial file and renames only at the end</b>, exactly as a bundle and a
/// judgement do. A derivation killed part way through leaves no file by the name a reader asks
/// for, so a half-built closure can never be consulted as a whole one - which matters more here
/// than anywhere else in the product, because a rule reading a closure has no way to tell a group
/// with two members from a group whose expansion stopped after two.
/// </para>
/// <para>
/// <b>Rows are written in bulk inside one transaction, with one prepared statement reused.</b> The
/// tables here are the largest the product writes outside the capture, and a transaction per row
/// would fsync per row. This is the shape the predecessor arrived at too, and it was right about
/// it.
/// </para>
/// <para>
/// <b>Order is forced by the dictionary.</b> Everything else names principals by an id that only
/// means something once <see cref="WriteSids"/> has run, and foreign keys are on, so the store
/// itself refuses the wrong order rather than trusting the caller to remember it.
/// </para>
/// </remarks>
public sealed class DerivationWriter : IDisposable
{
    private readonly string _bundleDirectory;
    private readonly string _partialPath;
    private readonly SqliteConnection _connection;
    private readonly List<DerivationPhaseOutcome> _outcomes = [];
    private readonly HashSet<string> _phasesRecorded = new(StringComparer.Ordinal);

    private bool _sidsWritten;
    private bool _completenessWritten;
    private bool _finished;
    private bool _disposed;

    private DerivationWriter(string bundleDirectory, string partialPath, SqliteConnection connection)
    {
        _bundleDirectory = bundleDirectory;
        _partialPath = partialPath;
        _connection = connection;
        GenerationId = Guid.NewGuid();
    }

    /// <summary>
    /// Names this derive run, so a fact can be told from one produced by another run.
    /// </summary>
    /// <remarks>
    /// Recorded once in the store's header rather than on every derived row. A store holds exactly
    /// one derivation, so a per-row copy would be a second answer to a question the header already
    /// answers, and two copies are free to disagree.
    /// </remarks>
    public Guid GenerationId { get; }

    /// <summary>
    /// Creates a derivation store beside the evidence it was derived from.
    /// </summary>
    /// <remarks>
    /// <b><paramref name="evidenceSeal"/> is what binds this store to one capture.</b> Two captures
    /// of one forest produce bundles holding mostly the same objects, so derived facts dropped into
    /// the wrong bundle would resolve nearly every SID and be wrong about all of them. A closure is
    /// worse than a finding here: a finding names an object someone can go and look at, while a
    /// closure is consulted silently by every rule resting on it.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle being derived from.</param>
    /// <param name="evidenceSeal">The hash carried by that bundle's evidence seal.</param>
    /// <param name="startedUtc">When deriving started.</param>
    /// <returns>A writer over a fresh partial store.</returns>
    public static DerivationWriter Create(
        string bundleDirectory,
        string evidenceSeal,
        DateTimeOffset startedUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceSeal);

        if (!Directory.Exists(bundleDirectory))
        {
            throw new DirectoryNotFoundException(
                $"There is no bundle at '{bundleDirectory}'. Derived facts are written beside the "
                + "evidence they were derived from, so the bundle must exist first.");
        }

        var partialPath = BundleLayout.DerivationPartialPath(bundleDirectory);
        if (File.Exists(partialPath))
            File.Delete(partialPath);

        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = partialPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
                ForeignKeys = true,
            }.ToString());

        connection.Open();

        // Ordered as the evidence and judgement writers order them, and for the same reason: page
        // size is fixed when the first table is created and cannot be changed afterwards without a
        // VACUUM, nor set at all once write-ahead logging is on.
        //
        // The default page size is kept. Every row here is a handful of integers - narrower than a
        // finding, and nothing like the security descriptors that made 8192 right for the evidence.
        Pragma(connection, "journal_mode = WAL");
        Pragma(connection, "synchronous = NORMAL");

        DerivationSchema.CreateTables(connection);

        var writer = new DerivationWriter(bundleDirectory, partialPath, connection);
        writer.WriteHeader(evidenceSeal, startedUtc);
        return writer;
    }

    /// <summary>
    /// Writes the SID dictionary. Must be called before anything that names a principal.
    /// </summary>
    /// <param name="sidsInIdOrder">
    /// Every interned SID, where the index of each is the id standing in for it.
    /// </param>
    /// <param name="scopesInIdOrder">
    /// The domain each id is scoped to, in the same order. Null for a forest-wide principal, which
    /// is stored as the empty string - see <see cref="DerivationSchema"/> for why the column is not
    /// nullable.
    /// <para>
    /// <b>Required rather than defaulted</b>, per gate 1: a dictionary written without scopes is a
    /// version 1 dictionary, and every domain's built-in groups merge into one.
    /// </para>
    /// </param>
    /// <exception cref="InvalidOperationException">The dictionary has been written already.</exception>
    /// <exception cref="ArgumentException">The two lists are of different lengths.</exception>
    public void WriteSids(
        IReadOnlyList<string> sidsInIdOrder,
        IReadOnlyList<string?> scopesInIdOrder)
    {
        ArgumentNullException.ThrowIfNull(sidsInIdOrder);
        ArgumentNullException.ThrowIfNull(scopesInIdOrder);
        ThrowIfFinished();

        if (scopesInIdOrder.Count != sidsInIdOrder.Count)
        {
            throw new ArgumentException(
                "There must be one scope per SID. A dictionary whose scopes and SIDs disagree in "
                + "length would put a principal under the wrong domain, which is the merge "
                + "docs/decisions/0087 exists to prevent.",
                nameof(scopesInIdOrder));
        }

        if (_sidsWritten)
        {
            throw new InvalidOperationException(
                "The SID dictionary has already been written. It is written once, in full, "
                + "because every other table names principals by the ids it assigns.");
        }

        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO sid (sid_id, sid, scope) VALUES ($id, $sid, $scope)";
        var id = command.Parameters.Add("$id", SqliteType.Integer);
        var sid = command.Parameters.Add("$sid", SqliteType.Text);
        var scope = command.Parameters.Add("$scope", SqliteType.Text);

        for (var i = 0; i < sidsInIdOrder.Count; i++)
        {
            id.Value = i;
            sid.Value = sidsInIdOrder[i];
            scope.Value = scopesInIdOrder[i] ?? string.Empty;
            command.ExecuteNonQuery();
        }

        transaction.Commit();
        _sidsWritten = true;
    }

    /// <summary>
    /// Writes which principal each SID identifies, and how.
    /// </summary>
    /// <param name="identities">One row per SID, current and historical alike.</param>
    public void WriteSidIdentities(IEnumerable<SidIdentityRow> identities)
    {
        ArgumentNullException.ThrowIfNull(identities);
        ThrowIfFinished();
        ThrowIfSidsNotWritten(nameof(WriteSidIdentities));

        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "INSERT INTO sid_identity (sid_id, principal_sid_id, identity_kind) "
            + "VALUES ($sid, $principal, $kind)";
        var sid = command.Parameters.Add("$sid", SqliteType.Integer);
        var principal = command.Parameters.Add("$principal", SqliteType.Integer);
        var kind = command.Parameters.Add("$kind", SqliteType.Text);

        foreach (var identity in identities)
        {
            sid.Value = identity.SidId;
            principal.Value = identity.PrincipalSidId;
            kind.Value = identity.Kind.ToString();
            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>
    /// Writes the per-principal facts a membership question needs.
    /// </summary>
    /// <param name="principals">One row per principal.</param>
    public void WritePrincipals(IEnumerable<PrincipalRow> principals)
    {
        ArgumentNullException.ThrowIfNull(principals);
        ThrowIfFinished();
        ThrowIfSidsNotWritten(nameof(WritePrincipals));

        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "INSERT INTO principal (sid_id, object_guid, is_group, group_type, primary_group_sid_id) "
            + "VALUES ($sid, $guid, $isGroup, $groupType, $primaryGroup)";
        var sid = command.Parameters.Add("$sid", SqliteType.Integer);
        var guid = command.Parameters.Add("$guid", SqliteType.Text);
        var isGroup = command.Parameters.Add("$isGroup", SqliteType.Integer);
        var groupType = command.Parameters.Add("$groupType", SqliteType.Integer);
        var primaryGroup = command.Parameters.Add("$primaryGroup", SqliteType.Integer);

        foreach (var row in principals)
        {
            sid.Value = row.SidId;
            guid.Value = row.ObjectGuid.ToString("D");
            isGroup.Value = row.IsGroup ? 1 : 0;
            groupType.Value = (object?)row.GroupType ?? DBNull.Value;
            primaryGroup.Value = (object?)row.PrimaryGroupSidId ?? DBNull.Value;
            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>
    /// Writes the direct nesting edges.
    /// </summary>
    /// <remarks>
    /// Duplicates are ignored rather than refused. One relationship can be seen twice - through a
    /// group's <c>member</c> and again through the member's <c>memberOf</c> - and that is the
    /// directory agreeing with itself, not a fault worth ending a derivation over.
    /// </remarks>
    /// <param name="edges">The direct nesting relationships.</param>
    public void WriteNestingEdges(IEnumerable<NestingEdge> edges)
    {
        ArgumentNullException.ThrowIfNull(edges);
        ThrowIfFinished();
        ThrowIfSidsNotWritten(nameof(WriteNestingEdges));

        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "INSERT OR IGNORE INTO nesting_edge (group_sid_id, member_sid_id) "
            + "VALUES ($group, $member)";
        var group = command.Parameters.Add("$group", SqliteType.Integer);
        var member = command.Parameters.Add("$member", SqliteType.Integer);

        foreach (var edge in edges)
        {
            group.Value = edge.GroupSidId;
            member.Value = edge.MemberSidId;
            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>
    /// Records what the derivation does not cover.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Written for every derivation, including a complete one.</b> The judgement specification
    /// requires that a partial answer is never serialized as a complete closure, and a store with
    /// no completeness row cannot say which it is - absence would mean both "nothing was missing"
    /// and "nobody recorded whether anything was", which is the conversion of a missing input into
    /// a clean result that this whole stage is shaped against.
    /// </para>
    /// <para>
    /// <b>The three lists are written even when empty</b>, for the same reason the row is: an empty
    /// table beside a recorded completeness means the derivation had none of that kind of hole,
    /// where an absent one would mean nobody looked.
    /// </para>
    /// </remarks>
    /// <param name="completeness">What the pass, the expansion and the capture's coverage said.</param>
    /// <exception cref="InvalidOperationException">Completeness has been recorded already.</exception>
    public void RecordCompleteness(DerivationCompleteness completeness)
    {
        ArgumentNullException.ThrowIfNull(completeness);
        ThrowIfFinished();
        ThrowIfSidsNotWritten(nameof(RecordCompleteness));

        if (_completenessWritten)
        {
            throw new InvalidOperationException(
                "Completeness has already been recorded. One derivation covers one bundle read "
                + "once, so a second record would be a second answer about the same coverage.");
        }

        using var transaction = _connection.BeginTransaction();

        using (var command = _connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "INSERT INTO derivation_completeness "
                + "(is_complete, expansion_limit, collapsed_stubs, unscoped_builtins) "
                + "VALUES ($complete, $limit, $collapsed, $unscoped)";

            command.Parameters.AddWithValue("$complete", completeness.IsComplete ? 1 : 0);
            command.Parameters.AddWithValue("$limit", completeness.Limit.ToString());
            command.Parameters.AddWithValue("$collapsed", completeness.CollapsedStubs);
            command.Parameters.AddWithValue("$unscoped", completeness.UnscopedBuiltins);
            command.ExecuteNonQuery();
        }

        using (var command = _connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "INSERT OR IGNORE INTO completeness_partial_group (sid_id) VALUES ($sid)";
            var sid = command.Parameters.Add("$sid", SqliteType.Integer);

            foreach (var group in completeness.PartialGroups)
            {
                sid.Value = group;
                command.ExecuteNonQuery();
            }
        }

        using (var command = _connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "INSERT OR IGNORE INTO completeness_unresolved_trustee (distinguished_name) "
                + "VALUES ($name)";
            var name = command.Parameters.Add("$name", SqliteType.Text);

            foreach (var trustee in completeness.UnresolvedTrustees)
            {
                name.Value = trustee;
                command.ExecuteNonQuery();
            }
        }

        using (var command = _connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "INSERT OR IGNORE INTO completeness_missing_partition (domain_fqdn, outcome, reason) "
                + "VALUES ($domain, $outcome, $reason)";

            var domain = command.Parameters.Add("$domain", SqliteType.Text);
            var outcome = command.Parameters.Add("$outcome", SqliteType.Text);
            var reason = command.Parameters.Add("$reason", SqliteType.Text);

            foreach (var partition in completeness.MissingPartitions)
            {
                domain.Value = partition.DomainFqdn;
                outcome.Value = partition.Outcome.ToString();

                // Every coverage row that reaches this table was not read in full, and DomainCoverage
                // requires each of those to carry why, so this is never null.
                reason.Value = partition.Reason!;
                command.ExecuteNonQuery();
            }
        }

        transaction.Commit();
        _completenessWritten = true;
    }

    /// <summary>
    /// Records what became of one phase.
    /// </summary>
    /// <remarks>
    /// A row is written for a phase that failed, which is why the outcome carries
    /// <see cref="DerivationPhaseOutcome.Failed"/> rather than the row being absent. A phase that
    /// threw is a fact about the derivation, and absence cannot state it.
    /// </remarks>
    /// <param name="phase">The phase's name.</param>
    /// <param name="outcome">What became of it.</param>
    /// <param name="error">
    /// Why it failed. Null when it did not, and passed explicitly rather than defaulted, so that
    /// recording a phase is always a decision about whether there is anything to explain.
    /// </param>
    public void RecordPhase(string phase, DerivationPhaseOutcome outcome, string? error)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phase);
        ThrowIfFinished();

        if (outcome == DerivationPhaseOutcome.Failed && string.IsNullOrWhiteSpace(error))
        {
            throw new ArgumentException(
                $"Phase '{phase}' is recorded as Failed with no error. A failure nobody can "
                + "diagnose later is most of the cost of the failure with none of the evidence.",
                nameof(error));
        }

        if (!_phasesRecorded.Add(phase))
        {
            throw new InvalidOperationException(
                $"Phase '{phase}' has already been recorded in this derivation. One phase runs "
                + "once, and a second record would mean two answers to one question.");
        }

        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "INSERT INTO derivation_phase (phase, outcome, error) VALUES ($phase, $outcome, $error)";
        command.Parameters.AddWithValue("$phase", phase);
        command.Parameters.AddWithValue("$outcome", outcome.ToString());
        command.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
        command.ExecuteNonQuery();
        transaction.Commit();

        _outcomes.Add(outcome);
    }

    /// <summary>
    /// Finishes the derivation: records what became of the run, builds the indexes, seals the file
    /// and only then gives it the name a reader asks for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The order is the design. Indexes are built now rather than maintained through writing. The
    /// checkpoint comes before the seal, because a hash taken while changes are still in the
    /// write-ahead log covers a database that is not all there. The rename comes last, because it
    /// is the act that makes the derivation readable at all.
    /// </para>
    /// <para>
    /// <b>The state is derived from what the phases did, never passed in.</b> A caller able to
    /// declare a run <see cref="DerivationRunState.Completed"/> while a phase was degraded could
    /// present a partial closure as a whole one, and every rule resting on it would inherit the
    /// lie.
    /// </para>
    /// </remarks>
    /// <param name="completedUtc">When deriving finished.</param>
    public void Complete(DateTimeOffset completedUtc)
    {
        ThrowIfFinished();

        var state = _outcomes.All(o => o == DerivationPhaseOutcome.Succeeded)
            ? DerivationRunState.Completed
            : DerivationRunState.CompletedDegraded;

        FinishWithState(state, completedUtc);

        DerivationSchema.CreateDeferredIndexes(_connection);
        Pragma(_connection, "wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);

        BundleSealing.Seal(_partialPath, BundleLayout.DerivationSealPath(_bundleDirectory));
        File.Move(_partialPath, BundleLayout.DerivationPath(_bundleDirectory), overwrite: true);
        _finished = true;
    }

    /// <summary>
    /// Abandons the derivation because the coordinator itself failed, leaving the partial file
    /// saying so.
    /// </summary>
    /// <remarks>
    /// <b>It does not rename and does not seal.</b> A derivation whose coordinator failed has no
    /// answer to offer, so nothing should be able to open it - but the partial file is left behind
    /// carrying <see cref="DerivationRunState.Failed"/>, because a coordinator or sealing failure
    /// is a defect in this product and deleting the evidence of it would help nobody diagnose it.
    /// </remarks>
    /// <param name="failedUtc">When the coordinator failed.</param>
    public void Abandon(DateTimeOffset failedUtc)
    {
        ThrowIfFinished();

        FinishWithState(DerivationRunState.Failed, failedUtc);

        Pragma(_connection, "wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);
        _finished = true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _connection.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Writes the single row describing this derivation, in the state it starts in.
    /// </summary>
    /// <remarks>
    /// Written at the start rather than the end so a partial file left by a killed process still
    /// says what it was, which is <see cref="DerivationRunState.Running"/> - the one state whose
    /// meaning is *this never finished*.
    /// </remarks>
    private void WriteHeader(string evidenceSeal, DateTimeOffset startedUtc)
    {
        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "INSERT INTO derivation (schema_version, evidence_seal, derivation_generation_id, "
            + "deriving_started_utc, deriving_completed_utc, state) "
            + "VALUES ($version, $seal, $generation, $started, NULL, $state)";
        command.Parameters.AddWithValue("$version", DerivationSchema.Version);
        command.Parameters.AddWithValue("$seal", evidenceSeal);
        command.Parameters.AddWithValue("$generation", GenerationId.ToString("D"));
        command.Parameters.AddWithValue("$started", Text(startedUtc));
        command.Parameters.AddWithValue("$state", DerivationRunState.Running.ToString());
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private void FinishWithState(DerivationRunState state, DateTimeOffset completedUtc)
    {
        using var transaction = _connection.BeginTransaction();
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "UPDATE derivation SET state = $state, deriving_completed_utc = $completed";
        command.Parameters.AddWithValue("$state", state.ToString());
        command.Parameters.AddWithValue("$completed", Text(completedUtc));
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private void ThrowIfSidsNotWritten(string operation)
    {
        if (!_sidsWritten)
        {
            throw new InvalidOperationException(
                $"{operation} was called before the SID dictionary was written. Every other table "
                + "names principals by the ids it assigns, so it has to come first.");
        }
    }

    private void ThrowIfFinished()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_finished)
        {
            throw new InvalidOperationException(
                "This derivation is finished. Its file has been sealed and renamed, and a store "
                + "that could be written to after sealing would not be worth sealing.");
        }
    }

    private static string Text(DateTimeOffset moment) =>
        moment.ToUniversalTime().ToString("O");

    private static void Pragma(SqliteConnection connection, string pragma)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA " + pragma;
        command.ExecuteNonQuery();
    }
}
