using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Storage;

namespace SecureAD.Judgement;

/// <summary>
/// The one way a judgement store gets written.
/// </summary>
/// <remarks>
/// <para>
/// <b>Writing is atomic per rule, and that is the whole design.</b> Each rule's findings commit in
/// one transaction together with its own execution record. One transaction for the entire run would
/// throw away every completed rule when the last one failed; no transaction boundary at all would
/// leave findings written with nothing saying which rule produced them. Per rule, a killed process
/// loses only the rule that was running.
/// </para>
/// <para>
/// <b>The previous judgement survives until this one is finished.</b> Writing goes to
/// <c>judgement.db.partial</c> and only <see cref="Complete"/> renames it over
/// <c>judgement.db</c>, so a judging that dies half way leaves yesterday's answer intact rather
/// than replacing it with a partial one.
/// </para>
/// <para>
/// <b>Every method here is synchronous, deliberately</b>, for the reason <see cref="BundleWriter"/>
/// gives: SQLite has no asynchronous I/O, so an <c>async</c> surface would await nothing and
/// mislead every caller about what it costs.
/// </para>
/// <para>
/// <b>It refuses an execution record that contradicts itself.</b> An outcome of
/// <see cref="RuleExecutionOutcome.Succeeded"/> beside objects it could not judge, or
/// <see cref="RuleExecutionOutcome.Indeterminate"/> with nothing named as missing, is a caller bug
/// that would put an unreadable claim in front of an operator. It is refused here, at the write,
/// rather than discovered by whoever reads it.
/// </para>
/// </remarks>
public sealed class JudgementWriter : IDisposable
{
    private readonly string _bundleDirectory;
    private readonly string _partialPath;
    private readonly SqliteConnection _connection;
    private readonly PreparedStatements _statements;
    private readonly PermissionWriteSession _session = new();
    private SqliteTransaction? _batch;
    private int _batchObjects;
    private readonly List<RuleExecutionOutcome> _outcomes = [];
    private bool _evidenceIsComplete = true;
    private readonly HashSet<string> _rulesWritten = new(StringComparer.Ordinal);

    private long _nextFindingId = 1;
    private long _lapsComputers;
    private bool _finished;
    private bool _disposed;

    /// <summary>The immutable generation this writer will publish.</summary>
    public Guid GenerationId { get; } = Guid.NewGuid();

    private JudgementWriter(string bundleDirectory, string partialPath, SqliteConnection connection)
    {
        _bundleDirectory = bundleDirectory;
        _partialPath = partialPath;
        _connection = connection;
        _statements = new PreparedStatements(connection);
    }

    internal void RecordEvidenceScope(RunScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ThrowIfFinished();
        _evidenceIsComplete = scope.AllDeclaredDomainsAreComplete;
    }

    internal void StartLapsInventory()
    {
        ThrowIfFinished();
        LapsInventoryStorage.Start(_connection, GenerationId);
    }

    /// <summary>
    /// The transaction this object's writes belong to, opened on demand and spanning several objects.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One transaction, not three.</b> Before 2026-09-22 an object's LAPS row ran in autocommit,
    /// its control edges opened and committed their own transaction, and its permission
    /// classification opened and committed another - about 25,000 commits on a capture of 8,407
    /// objects, and an object whose permissions rolled back could still leave its LAPS row behind.
    /// Sharing one transaction is both stronger and cheaper.
    /// </para>
    /// <para>
    /// <b>DO NOT MAKE JUDGING RECOVER FROM A FAILED OBJECT AND CARRY ON.</b> This batch is what
    /// makes the commits affordable, and it is only safe because a failure aborts the run: the
    /// generation is then never marked complete, so it can never be published or read back. Code
    /// that caught a per-object failure and continued would silently discard every other object in
    /// the same batch and leave a judgement that looked whole. If that behaviour is ever wanted,
    /// the batch has to go back to one object first.
    /// </para>
    /// <para>
    /// Whatever is open is rolled back on disposal. An unpublished generation is the correct
    /// outcome of an abandoned run; a half-written one is not.
    /// </para>
    /// </remarks>
    private SqliteTransaction Batch() => _batch ??= _connection.BeginTransaction();

    /// <summary>How many objects share one transaction.</summary>
    /// <remarks>
    /// Chosen to make the commit count negligible without holding an unbounded amount uncommitted:
    /// 500 objects is roughly 12,500 permission entries on the laboratory capture. Not tuned against
    /// the production forest, which has never been measured.
    /// </remarks>
    private const int BatchObjects = 500;

    /// <summary>Records that an object's writes are finished, committing the batch when it is full.</summary>
    internal void CompleteObject()
    {
        ThrowIfFinishedWithinObject();
        if (_batch is null || ++_batchObjects < BatchObjects) return;
        FlushObjects();
    }

    /// <summary>Commits whatever object writes are outstanding.</summary>
    internal void FlushObjects()
    {
        if (_batch is null) return;
        _batch.Commit();
        _batch.Dispose();
        _batch = null;
        _batchObjects = 0;
        // PROMOTED ONLY NOW, because until this commit those rows did not exist and a record
        // claiming otherwise would let a later object reference an identifier that was rolled back.
        _session.Promote();
    }

    internal void WriteLapsInventory(ObjectAttributes subject)
    {
        ThrowIfFinishedWithinObject();
        if (!LapsAttributes.IsComputer(subject)) return;
        LapsInventoryStorage.Write(_connection, Batch(), LapsInventoryStorage.CreateComputerResult(subject));
        _lapsComputers++;
    }

    internal void CompleteLapsInventory()
    {
        ThrowIfFinished();
        LapsInventoryStorage.Complete(_connection, _lapsComputers);
    }

    internal void StartControlEdges(bool captureComplete, bool discoveryScoped = false)
    {
        ThrowIfFinished();
        ControlEdgeStorage.Start(_connection, captureComplete, discoveryScoped);
    }

    internal void StartPermissionClassifications(bool hasCapturedSchema)
    {
        ThrowIfFinished();
        PermissionClassificationStorage.Start(_connection, GenerationId, hasCapturedSchema);
    }

    internal void WritePermissionClassification(PermissionClassification result, CancellationToken cancellationToken)
    {
        ThrowIfFinishedWithinObject();
        try
        {
            PermissionClassificationStorage.Write(_connection, Batch(), GenerationId, result, PermissionWrites, _statements, _session, cancellationToken);
        }
        catch
        {
            // THE BATCH GOES WITH IT. Rows written since the last commit no longer exist, so keeping
            // the identifiers this session remembered for them would let a retry point an entry at a
            // reading that was rolled back - which is what CancellationRollsBackAndRetryDoesNotReuse
            // UncommittedSupport exists to catch.
            AbandonBatch();
            throw;
        }
    }

    /// <summary>Rolls back the open batch and forgets everything it wrote.</summary>
    private void AbandonBatch()
    {
        _batch?.Dispose();
        _batch = null;
        _batchObjects = 0;
        _session.Discard();
    }

    /// <summary>Where storing the saved permission classifications spent its time.</summary>
    internal PermissionWriteWork PermissionWrites { get; } = new();

    internal void CompletePermissionClassifications(long objectsRead)
    {
        ThrowIfFinished();
        PermissionClassificationStorage.Complete(_connection, objectsRead);
    }

    internal void WriteControlEdges(ControlObjectEvaluation evaluation, SecureAD.Derivation.Tier0Target? ownershipTarget)
    {
        ThrowIfFinishedWithinObject();
        ControlEdgeStorage.Write(_connection, Batch(), _statements, evaluation, ownershipTarget);
    }

    internal void CompleteControlEdges()
    {
        ThrowIfFinished();
        ControlEdgeStorage.Complete(_connection);
    }

    internal void StartPathInputs(JudgementDescription description, bool requested)
    {
        ThrowIfFinished();
        PathInputStorage.Start(_connection, description, requested);
    }

    internal void CalculateTier0Paths(JudgementDescription description, IReadOnlyList<RequesterDaclRequest> requests,
        IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests, CancellationToken cancellationToken,
        IReadOnlyList<MembershipDaclRequest> membershipDaclRequests, bool offlineSelection, Action<PathRequesterWorkPhase> beginPhase)
    {
        ThrowIfFinished();
        Tier0PathStorage.Write(_connection, description, _bundleDirectory, requests, ownAccountRequests, cancellationToken,
            membershipDaclRequests, offlineSelection, beginPhase);
    }

    internal void StartAutomaticOwnership(JudgementDescription description, string ownerRightsContextHash)
    {
        ThrowIfFinished();
        OwnershipAuditStorage.Start(_connection, GenerationId, description.EvidenceSeal, description.DerivationGenerationId,
            description.EvaluationAsOf, ownerRightsContextHash);
    }

    internal void AssessAutomaticOwnership(BundleReader bundle, JudgementDescription description,
        SecureAD.Derivation.CapturedMembershipInput? input, SecureAD.Derivation.Tier0InputBinding? binding,
        JudgingContext context, Func<string, string?> domainSid, long objectsRead,
        IProgress<JudgingRun.JudgingProgress> progress, CancellationToken cancellationToken,
        bool scopeAlreadyPlanned = false)
    {
        ThrowIfFinished();
        OwnershipAuditRun.Assess(_connection, bundle, description, input, binding, context, domainSid,
            objectsRead, progress, cancellationToken, scopeAlreadyPlanned);
    }

    /// <summary>
    /// Derives detailed control products for the targets Tier-0 discovery admitted, and no others.
    /// </summary>
    /// <returns>The number of admitted targets whose products were derived.</returns>
    internal int AdmitDiscoveredScope(BundleReader bundle, JudgementDescription description,
        SecureAD.Derivation.CapturedMembershipInput? input, SecureAD.Derivation.Tier0InputBinding binding,
        Tier0DiscoveryScheduler discovery, JudgingContext context, Func<string, string?> domainSid,
        Guid? derivationGeneration, CancellationToken cancellationToken)
    {
        ThrowIfFinished();
        return Tier0AdmissionRun.Admit(_connection, bundle, description, input, binding, discovery, context,
            domainSid, GenerationId, derivationGeneration, cancellationToken);
    }

    internal void WriteMemberAttributions(SecureAD.Derivation.CapturedMembershipInput input,
        MemberAttributionBudget budget, string forest, IReadOnlyDictionary<string, NamingContextKind> namingContexts, CancellationToken cancellationToken)
    {
        ThrowIfFinished();
        MemberAttributionStorage.Write(_connection, input, budget, GenerationId, forest, namingContexts, cancellationToken);
    }

    /// <summary>
    /// How many requester answers share one commit.
    /// </summary>
    /// <remarks>
    /// <b>Measured, not guessed.</b> Written one row at a time each answer was its own committed
    /// transaction, and 50,000 of them cost about 200 seconds on synthetic captures - the commits,
    /// not the analysis. Batching removes that without holding the whole product open: a single
    /// transaction spanning the run would grow the write-ahead log by the size of every answer
    /// before any of it could be checkpointed.
    /// </remarks>
    private const int SelfMembershipBatch = 1_000;

    private SqliteTransaction? _selfMembershipBatch;
    private int _selfMembershipWritten;

    internal void StartSelfMembershipAssessments()
    {
        ThrowIfFinished();
        SelfMembershipStorage.Start(_connection);
    }

    internal void WriteSelfMembershipAssessment(SelfMembershipAssessment assessment)
    {
        ThrowIfFinished();

        // Opened here rather than when the product starts, because the pass over the objects runs
        // in between and writes each object's control edges in a transaction of its own. SQLite has
        // no nested transactions, so the batch can only begin once that pass is finished.
        _selfMembershipBatch ??= _connection.BeginTransaction();
        SelfMembershipStorage.Write(_connection, _selfMembershipBatch, assessment);

        if (++_selfMembershipWritten % SelfMembershipBatch != 0)
            return;

        _selfMembershipBatch.Commit();
        _selfMembershipBatch.Dispose();
        _selfMembershipBatch = _connection.BeginTransaction();
    }

    internal IReadOnlyList<long> SelfMembershipEdgeIds(string target, IEnumerable<string> trusteeSids)
    {
        ThrowIfFinished();
        return ControlEdgeStorage.SelfMembershipEdgeIds(_connection, target, trusteeSids);
    }

    internal void CompleteSelfMembershipAssessments(SelfMembershipDiscoveryCoverage? coverage)
    {
        ThrowIfFinished();
        SelfMembershipStorage.Complete(_connection, _selfMembershipBatch, coverage ?? new(1,
            SelfMembershipDiscoveryMode.ExplicitRequests, false, _evidenceIsComplete, null, 0, 0, 0, 0, []));
        _selfMembershipBatch?.Commit();
        _selfMembershipBatch?.Dispose();
        _selfMembershipBatch = null;
    }

    /// <summary>
    /// Creates a judgement store in <paramref name="bundleDirectory"/> and opens it for writing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><paramref name="evidenceSeal"/> is what binds this store to one capture.</b> It is the
    /// hash the evidence seal carries, and a reader refuses a store whose value does not match the
    /// bundle it was opened beside. Without it a judgement copied into the wrong bundle would
    /// resolve nearly all of its findings and be wrong about every one of them.
    /// </para>
    /// <para>
    /// <b><paramref name="evaluationAsOf"/> is recorded rather than read from the clock later.</b>
    /// A rule about stale accounts asked the same sealed evidence a month apart would otherwise
    /// give two different answers with nothing saying why.
    /// </para>
    /// </remarks>
    /// <param name="bundleDirectory">The bundle being judged.</param>
    /// <param name="evidenceSeal">The hash carried by that bundle's evidence seal.</param>
    /// <param name="startedUtc">When judging started.</param>
    /// <param name="evaluationAsOf">The reference time temporal rules are evaluated against.</param>
    public static JudgementWriter Create(
        string bundleDirectory,
        string evidenceSeal,
        Guid? derivationGenerationId,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceSeal);

        if (!Directory.Exists(bundleDirectory))
        {
            throw new DirectoryNotFoundException(
                $"There is no bundle at '{bundleDirectory}'. A judgement is written beside the "
                + "evidence it judged, so the bundle must exist before it can be judged.");
        }

        AnalysisStoreLifecycle.BeginAttempt(bundleDirectory, AnalysisStoreKind.Judgement);
        var partialPath = BundleLayout.JudgementPartialPath(bundleDirectory);
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

        // Ordered as the evidence writer orders them, and for the same reasons: page size is fixed
        // when the first table is created and cannot be changed afterwards without a VACUUM, and it
        // cannot be set at all once write-ahead logging is on.
        //
        // The default page size is kept. A judgement holds findings and execution records, which are
        // small rows - none of the large security descriptors that made 8192 the right answer for
        // the evidence.
        Pragma(connection, "journal_mode = WAL");
        Pragma(connection, "synchronous = NORMAL");

        JudgementSchema.CreateTables(connection);

        var writer = new JudgementWriter(bundleDirectory, partialPath, connection);
        writer.WriteHeader(evidenceSeal, derivationGenerationId, startedUtc, evaluationAsOf);
        return writer;
    }

    /// <summary>
    /// Records everything one rule did, in one transaction.
    /// </summary>
    /// <remarks>
    /// The findings and the execution record commit together or not at all, so no finding can exist
    /// in a store that does not say which rule produced it.
    /// </remarks>
    /// <param name="execution">What the rule did.</param>
    /// <exception cref="ArgumentException">The execution record contradicts itself.</exception>
    /// <exception cref="InvalidOperationException">
    /// The store is already finished, or this rule has been written once already.
    /// </exception>
    public void Write(RuleExecution execution)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ThrowIfFinished();
        Validate(execution);

        var ruleId = execution.Definition.Id;

        if (!_rulesWritten.Add(ruleId))
        {
            throw new InvalidOperationException(
                $"{ruleId} has already been recorded in this judgement. One rule executes once per "
                + "judging, and a second record would mean two answers to one question.");
        }

        using var transaction = _connection.BeginTransaction();

        Execute(
            transaction,
            "INSERT INTO rule_execution (rule_id, rule_version, outcome, objects_judged, "
            + "objects_not_applicable, objects_not_judged, error) "
            + "VALUES ($rule, $version, $outcome, $judged, $notApplicable, $notJudged, $error)",
            command =>
            {
                command.Parameters.AddWithValue("$rule", ruleId);
                command.Parameters.AddWithValue("$version", execution.Definition.Version);
                command.Parameters.AddWithValue("$outcome", execution.Outcome.ToString());
                command.Parameters.AddWithValue("$judged", execution.ObjectsJudged);
                command.Parameters.AddWithValue("$notApplicable", execution.ObjectsNotApplicable);
                command.Parameters.AddWithValue("$notJudged", execution.ObjectsNotJudged);
                command.Parameters.AddWithValue("$error", (object?)execution.Error ?? DBNull.Value);
            });

        foreach (var missing in execution.MissingInputs)
        {
            Execute(
                transaction,
                "INSERT INTO rule_execution_missing_input (rule_id, attribute, objects_affected) "
                + "VALUES ($rule, $attribute, $affected)",
                command =>
                {
                    command.Parameters.AddWithValue("$rule", ruleId);
                    command.Parameters.AddWithValue("$attribute", missing.Attribute);
                    command.Parameters.AddWithValue("$affected", missing.ObjectsAffected);
                });
        }

        foreach (var finding in execution.Findings)
            WriteFinding(transaction, finding);

        transaction.Commit();
        _outcomes.Add(execution.Outcome);
    }

    /// <summary>
    /// Finishes the judgement: records what became of the run, builds the indexes, seals the file
    /// and only then gives it the name a reader asks for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The order is the design, as it is for a bundle. Indexes are built now rather than maintained
    /// through writing. The checkpoint comes before the seal, because a hash taken while changes are
    /// still in the write-ahead log covers a database that is not all there. The rename comes last,
    /// because it is the act that makes the judgement readable at all.
    /// </para>
    /// <para>
    /// <b>The state is derived from what the rules did, never passed in.</b> A caller that could
    /// declare a run <see cref="JudgementRunState.Completed"/> while a rule was indeterminate could
    /// present a forest as fully judged when it was not.
    /// </para>
    /// </remarks>
    /// <param name="completedUtc">When judging finished.</param>
    /// <param name="cancellationToken">Cancels finalization before the generation is selected for publication.</param>
    public void Complete(DateTimeOffset completedUtc, CancellationToken cancellationToken = default)
    {
        ThrowIfFinished();
        cancellationToken.ThrowIfCancellationRequested();
        LapsInventoryStorage.RequirePublishable(_connection);
        PermissionClassificationStorage.RequirePublishable(_connection);

        var state = _evidenceIsComplete
            && _outcomes.All(o => o == RuleExecutionOutcome.Succeeded)
            ? JudgementRunState.Completed
            : JudgementRunState.CompletedDegraded;

        FinishWithState(state, completedUtc);

        JudgementSchema.CreateDeferredIndexes(_connection);
        cancellationToken.ThrowIfCancellationRequested();
        Pragma(_connection, "wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);

        AnalysisStoreLifecycle.Publish(
            _bundleDirectory,
            AnalysisStoreKind.Judgement,
            GenerationId,
            cancellationToken);
        _finished = true;
    }

    /// <summary>
    /// Abandons the judgement because the coordinator itself failed, leaving the partial file
    /// saying so.
    /// </summary>
    /// <remarks>
    /// <b>It does not rename and does not seal.</b> A judging whose coordinator failed has no
    /// answer to offer, so nothing should be able to open it - but the partial file is left behind
    /// carrying <see cref="JudgementRunState.Failed"/>, because a scheduling or sealing failure is
    /// a defect in this product and deleting the evidence of it would help nobody diagnose it.
    /// </remarks>
    /// <param name="failedUtc">When the coordinator failed.</param>
    public void Abandon(DateTimeOffset failedUtc)
    {
        ThrowIfFinished();

        // Rolled back rather than committed: a coordinator that failed part way through the
        // requester answers has no product to offer, and half a batch is not a partial answer but
        // an arbitrary prefix of one.
        RollBackSelfMembershipBatch();

        FinishWithState(JudgementRunState.Failed, failedUtc);

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

        RollBackSelfMembershipBatch();
        AbandonBatch();
        // BEFORE THE CONNECTION, because a compiled statement outliving its connection is exactly
        // the kind of stranded handle P-250 was raised for.
        _statements.Dispose();
        _connection.Dispose();
        _disposed = true;
    }

    /// <summary>Discards an assessment batch that was never completed.</summary>
    private void RollBackSelfMembershipBatch()
    {
        if (_selfMembershipBatch is null)
            return;

        try { _selfMembershipBatch.Rollback(); }
        catch (InvalidOperationException) { }
        catch (SqliteException) { }

        _selfMembershipBatch.Dispose();
        _selfMembershipBatch = null;
    }

    /// <summary>
    /// Writes the single row describing this judging, in the state it starts in.
    /// </summary>
    /// <remarks>
    /// Written at the start rather than the end so that a partial file left by a killed process
    /// still says what it was, which is <see cref="JudgementRunState.Running"/> - the one state
    /// whose meaning is *this never finished*.
    /// </remarks>
    private void WriteHeader(
        string evidenceSeal,
        Guid? derivationGenerationId,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf)
    {
        using var transaction = _connection.BeginTransaction();

        Execute(
            transaction,
            "INSERT INTO judgement (schema_version, evidence_seal, judgement_generation_id, "
            + "derivation_generation_id, judging_started_utc, judging_completed_utc, state, "
            + "evaluation_as_of) VALUES ($version, $seal, $generation, $derivation, $started, "
            + "NULL, $state, $asOf)",
            command =>
            {
                command.Parameters.AddWithValue("$version", JudgementSchema.Version);
                command.Parameters.AddWithValue("$seal", evidenceSeal);
                command.Parameters.AddWithValue("$generation", GenerationId.ToString("D"));
                command.Parameters.AddWithValue(
                    "$derivation",
                    derivationGenerationId is { } generation
                        ? generation.ToString("D")
                        : DBNull.Value);
                command.Parameters.AddWithValue("$started", Text(startedUtc));
                command.Parameters.AddWithValue("$state", JudgementRunState.Running.ToString());
                command.Parameters.AddWithValue("$asOf", Text(evaluationAsOf));
            });

        transaction.Commit();
    }

    private void FinishWithState(JudgementRunState state, DateTimeOffset completedUtc)
    {
        using var transaction = _connection.BeginTransaction();

        Execute(
            transaction,
            "UPDATE judgement SET state = $state, judging_completed_utc = $completed",
            command =>
            {
                command.Parameters.AddWithValue("$state", state.ToString());
                command.Parameters.AddWithValue("$completed", Text(completedUtc));
            });

        transaction.Commit();
    }

    private void WriteFinding(SqliteTransaction transaction, Finding finding)
    {
        var findingId = _nextFindingId++;

        Execute(
            transaction,
            "INSERT INTO finding (finding_id, rule_id, subject_kind, subject_key, object_guid, "
            + "severity, severity_rank, distinguished_name, principal_name, domain_fqdn, "
            + "object_class, detail, coverage) "
            + "VALUES ($id, $rule, $kind, $key, $guid, $severity, $rank, $dn, $principal, "
            + "$domain, $class, $detail, $coverage)",
            command =>
            {
                command.Parameters.AddWithValue("$id", findingId);
                command.Parameters.AddWithValue("$rule", finding.RuleId);
                command.Parameters.AddWithValue("$kind", finding.Subject.Kind.ToString());
                command.Parameters.AddWithValue("$key", finding.Subject.Key);
                command.Parameters.AddWithValue("$guid", finding.ObjectGuid.ToString("D"));
                command.Parameters.AddWithValue("$severity", finding.Severity.ToString());

                // The enum's own order is the rank, so the two cannot disagree. The word is what a
                // person reads; the rank is the only thing a grid may sort on, because ordering on
                // the word is alphabetical and puts Low above Medium.
                command.Parameters.AddWithValue("$rank", (int)finding.Severity);

                command.Parameters.AddWithValue("$dn", finding.DistinguishedName);
                command.Parameters.AddWithValue("$principal", finding.Subject.Key);
                command.Parameters.AddWithValue("$domain", finding.DomainFqdn);
                command.Parameters.AddWithValue("$class", finding.ObjectClass);
                command.Parameters.AddWithValue("$detail", finding.Detail);
                command.Parameters.AddWithValue("$coverage", finding.Coverage.ToString());
            });

        WriteFindingEvidence(transaction, findingId, finding.Evidence);
    }

    /// <summary>
    /// Writes the evidence for one finding into the table its kind declares.
    /// </summary>
    /// <remarks>
    /// An evidence kind with no table is refused loudly rather than dropped. The predecessor's
    /// schemaless context blob accepted anything and lost the parts nothing knew how to read; a type
    /// per kind means the gap shows up here, at the write, naming the type.
    /// </remarks>
    private void WriteFindingEvidence(
        SqliteTransaction transaction, long findingId, FindingEvidence evidence)
    {
        switch (evidence)
        {
            case UnconstrainedDelegationEvidence delegation:
                Execute(
                    transaction,
                    "INSERT INTO finding_unconstrained_delegation (finding_id, "
                    + "user_account_control, is_computer, server_trust_account_bit, "
                    + "primary_group_is_domain_controller, under_domain_controllers_ou) "
                    + "VALUES ($id, $uac, $computer, $trust, $group, $ou)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$uac", (long)delegation.UserAccountControl);
                        command.Parameters.AddWithValue("$computer", delegation.IsComputer ? 1 : 0);
                        command.Parameters.AddWithValue(
                            "$trust", delegation.DomainController.ServerTrustAccountBit ? 1 : 0);
                        command.Parameters.AddWithValue(
                            "$group",
                            delegation.DomainController.PrimaryGroupIsDomainController ? 1 : 0);
                        command.Parameters.AddWithValue(
                            "$ou", delegation.DomainController.UnderDomainControllersOu ? 1 : 0);
                    });
                return;

            case AdminCountWithoutProtectionEvidence marker:
                Execute(
                    transaction,
                    "INSERT INTO finding_admincount_without_protection (finding_id, sid) "
                    + "VALUES ($id, $sid)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$sid", marker.Sid);
                    });
                return;

            case UserAccountControlEvidence preauth:
                Execute(
                    transaction,
                    "INSERT INTO finding_user_account_control (finding_id, "
                    + "user_account_control) VALUES ($id, $uac)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue(
                            "$uac", (long)preauth.UserAccountControl);
                    });
                return;

            case PrivilegedSidHistoryEvidence history:
                Execute(
                    transaction,
                    "INSERT INTO finding_privileged_sid_history (finding_id, object_sid, "
                    + "unreadable_values) VALUES ($id, $sid, $unreadable)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue(
                            "$sid", (object?)history.ObjectSid ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$unreadable", history.UnreadableValues);
                    });

                // Every value, not only the matches. A row here for a value the rule could not rank
                // is what stops the stored evidence saying the account carried nothing else.
                for (var ordinal = 0; ordinal < history.HistoryValues.Count; ordinal++)
                {
                    var value = history.HistoryValues[ordinal];
                    var position = ordinal;

                    Execute(
                        transaction,
                        "INSERT INTO finding_privileged_sid_history_value (finding_id, ordinal, "
                        + "sid) VALUES ($id, $ordinal, $sid)",
                        command =>
                        {
                            command.Parameters.AddWithValue("$id", findingId);
                            command.Parameters.AddWithValue("$ordinal", position);
                            command.Parameters.AddWithValue("$sid", value);
                        });
                }

                return;

            case KerberoastableAccountEvidence kerberoastable:
                Execute(
                    transaction,
                    "INSERT INTO finding_kerberoastable_account (finding_id, object_sid, "
                    + "user_account_control, unreadable_service_names, protection_catalogue_version, "
                    + "direct_protection_entry_id, direct_protection_name) "
                    + "VALUES ($id, $sid, $uac, $unreadable, $catalogue, $directId, $directName)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$sid", kerberoastable.ObjectSid);
                        command.Parameters.AddWithValue(
                            "$uac", (long)kerberoastable.UserAccountControl);
                        command.Parameters.AddWithValue(
                            "$unreadable", kerberoastable.UnreadableServiceNames);
                        command.Parameters.AddWithValue("$catalogue", (object?)kerberoastable.ProtectionCatalogueVersion ?? DBNull.Value);
                        command.Parameters.AddWithValue("$directId", (object?)kerberoastable.DirectProtectionCatalogueEntryId ?? DBNull.Value);
                        command.Parameters.AddWithValue("$directName", (object?)kerberoastable.DirectProtectionName ?? DBNull.Value);
                    });

                MembershipRouteStorage.Write(_connection, transaction,
                    findingId.ToString(System.Globalization.CultureInfo.InvariantCulture), kerberoastable.MembershipRoutes);

                for (var ordinal = 0;
                     ordinal < kerberoastable.ServicePrincipalNames.Count;
                     ordinal++)
                {
                    var spn = kerberoastable.ServicePrincipalNames[ordinal];
                    var position = ordinal;

                    Execute(
                        transaction,
                        "INSERT INTO finding_kerberoastable_account_spn (finding_id, ordinal, "
                        + "service_principal_name) VALUES ($id, $ordinal, $spn)",
                        command =>
                        {
                            command.Parameters.AddWithValue("$id", findingId);
                            command.Parameters.AddWithValue("$ordinal", position);
                            command.Parameters.AddWithValue("$spn", spn);
                        });
                }

                return;

            case LapsDeploymentEvidence laps:
                Execute(
                    transaction,
                    "INSERT INTO finding_laps_deployment (finding_id, "
                    + "windows_laps_expiration, legacy_laps_expiration, capability_kind, "
                    + "capability_basis, operating_system, operating_system_version) "
                    + "VALUES ($id, $modern, $legacy, $kind, $basis, $os, $version)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue(
                            "$modern", (object?)laps.WindowsLapsExpiration ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$legacy", (object?)laps.LegacyLapsExpiration ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$kind", laps.Capability.Kind.ToString());
                        command.Parameters.AddWithValue(
                            "$basis", laps.Capability.Basis.ToString());
                        command.Parameters.AddWithValue(
                            "$os", (object?)laps.Capability.Name ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$version", (object?)laps.Capability.Version ?? DBNull.Value);
                    });
                return;

            case LapsPasswordReaderEvidence readers:
                Execute(
                    transaction,
                    "INSERT INTO finding_laps_password_reader (finding_id, trustee_sid, "
                    + "trustee_name, broad_principal_sid, broad_principal_name, attribute, "
                    + "rights, reach, inherited_from, expansion_was_complete, route_length) "
                    + "VALUES ($id, $trustee, $name, $broad, $broadName, $attribute, $rights, "
                    + "$reach, $inherited, $complete, $length)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$trustee", readers.TrusteeSid);
                        command.Parameters.AddWithValue(
                            "$name", (object?)readers.TrusteeName ?? DBNull.Value);
                        command.Parameters.AddWithValue("$broad", readers.BroadPrincipalSid);
                        command.Parameters.AddWithValue(
                            "$broadName", (object?)readers.BroadPrincipalName ?? DBNull.Value);
                        command.Parameters.AddWithValue("$attribute", readers.Attribute);
                        command.Parameters.AddWithValue("$rights", readers.Rights.ToString());
                        command.Parameters.AddWithValue("$reach", readers.Reach.ToString());
                        command.Parameters.AddWithValue(
                            "$inherited", (object?)readers.InheritedFrom ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$complete", readers.ExpansionWasComplete ? 1L : 0L);
                        command.Parameters.AddWithValue("$length", readers.MembershipPath.Count);
                    });

                // The path, in order. Without it the finding names a broad principal and cannot say
                // which link an operator would cut, which is the whole of P-123's third condition.
                for (var ordinal = 0; ordinal < readers.MembershipPath.Count; ordinal++)
                {
                    var step = readers.MembershipPath[ordinal];
                    var position = ordinal;

                    Execute(
                        transaction,
                        "INSERT INTO finding_laps_password_reader_path "
                        + "(finding_id, ordinal, sid, name) VALUES ($id, $ordinal, $sid, $name)",
                        command =>
                        {
                            command.Parameters.AddWithValue("$id", findingId);
                            command.Parameters.AddWithValue("$ordinal", position);
                            command.Parameters.AddWithValue("$sid", step.Sid);
                            command.Parameters.AddWithValue(
                                "$name", (object?)step.Name ?? DBNull.Value);
                        });
                }

                return;

            case ObjectTakeoverEvidence takeover:
                Execute(
                    transaction,
                    "INSERT INTO finding_object_takeover (finding_id, trustee_sid, "
                    + "trustee_name, broad_principal_sid, broad_principal_name, "
                    + "takeover_right, inherited_from, expansion_was_complete) "
                    + "VALUES ($id, $trustee, $name, $broad, $broadName, $right, $inherited, "
                    + "$complete)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$trustee", takeover.TrusteeSid);
                        command.Parameters.AddWithValue(
                            "$name", (object?)takeover.TrusteeName ?? DBNull.Value);
                        command.Parameters.AddWithValue("$broad", takeover.BroadPrincipalSid);
                        command.Parameters.AddWithValue(
                            "$broadName", (object?)takeover.BroadPrincipalName ?? DBNull.Value);
                        command.Parameters.AddWithValue("$right", takeover.Right.ToString());
                        command.Parameters.AddWithValue(
                            "$inherited", (object?)takeover.InheritedFrom ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$complete", takeover.ExpansionWasComplete ? 1L : 0L);
                    });

                // The path, in order, for the reason SEC-090's does: naming the broad principal
                // without it does not tell an operator which link to cut.
                for (var ordinal = 0; ordinal < takeover.MembershipPath.Count; ordinal++)
                {
                    var step = takeover.MembershipPath[ordinal];
                    var position = ordinal;

                    Execute(
                        transaction,
                        "INSERT INTO finding_object_takeover_path "
                        + "(finding_id, ordinal, sid, name) VALUES ($id, $ordinal, $sid, $name)",
                        command =>
                        {
                            command.Parameters.AddWithValue("$id", findingId);
                            command.Parameters.AddWithValue("$ordinal", position);
                            command.Parameters.AddWithValue("$sid", step.Sid);
                            command.Parameters.AddWithValue(
                                "$name", (object?)step.Name ?? DBNull.Value);
                        });
                }

                return;

            case ObjectOwnershipEvidence ownership:
                Execute(
                    transaction,
                    "INSERT INTO finding_object_ownership (finding_id, owner_sid, owner_name, "
                    + "standing, object_class, membership_was_complete) "
                    + "VALUES ($id, $sid, $name, $standing, $class, $complete)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$sid", ownership.OwnerSid);
                        command.Parameters.AddWithValue(
                            "$name", (object?)ownership.OwnerName ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$standing", ownership.Standing.ToString());
                        command.Parameters.AddWithValue("$class", ownership.ObjectClass);
                        command.Parameters.AddWithValue(
                            "$complete", ownership.MembershipWasComplete ? 1L : 0L);
                    });
                return;

            case LapsDecryptorEvidence decryptor:
                Execute(
                    transaction,
                    "INSERT INTO finding_laps_decryptor (finding_id, policy_display_name, "
                    + "configured_value, form, decryptor_sid, decryptor_name, "
                    + "broad_principal_sid, broad_principal_name, expansion_was_complete, route_length) "
                    + "VALUES ($id, $policy, $value, $form, $sid, $sidName, $broad, $broadName, "
                    + "$complete, $length)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue(
                            "$policy", (object?)decryptor.PolicyDisplayName ?? DBNull.Value);
                        command.Parameters.AddWithValue("$value", decryptor.ConfiguredValue);
                        command.Parameters.AddWithValue("$form", decryptor.Form.ToString());
                        command.Parameters.AddWithValue(
                            "$sid", (object?)decryptor.DecryptorSid ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$sidName", (object?)decryptor.DecryptorName ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$broad", (object?)decryptor.BroadPrincipalSid ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$broadName", (object?)decryptor.BroadPrincipalName ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$complete", decryptor.ExpansionWasComplete ? 1L : 0L);
                        command.Parameters.AddWithValue("$length", decryptor.MembershipPath.Count);
                    });

                // The route, in order. Microsoft's supported way to authorize more than one
                // decryptor is a wrapper group, so the finding is usually about what ended up
                // nested inside one, and the endpoints alone would not say which link to cut.
                for (var ordinal = 0; ordinal < decryptor.MembershipPath.Count; ordinal++)
                {
                    var step = decryptor.MembershipPath[ordinal];
                    var position = ordinal;

                    Execute(
                        transaction,
                        "INSERT INTO finding_laps_decryptor_path "
                        + "(finding_id, ordinal, sid, name) VALUES ($id, $ordinal, $sid, $name)",
                        command =>
                        {
                            command.Parameters.AddWithValue("$id", findingId);
                            command.Parameters.AddWithValue("$ordinal", position);
                            command.Parameters.AddWithValue("$sid", step.Sid);
                            command.Parameters.AddWithValue(
                                "$name", (object?)step.Name ?? DBNull.Value);
                        });
                }

                return;

            default:
                throw new ArgumentException(
                    $"There is no table for evidence of type {evidence.GetType().Name}, so this "
                    + "finding cannot be stored without losing what it rests on. Add a table for "
                    + "the kind and a case here.",
                    nameof(evidence));
        }
    }

    /// <summary>
    /// Refuses an execution record whose parts contradict each other.
    /// </summary>
    /// <remarks>
    /// Each of these would produce a store a reader cannot interpret, and every one of them is
    /// cheaper to catch here than in front of an operator.
    /// </remarks>
    private static void Validate(RuleExecution execution)
    {
        var ruleId = execution.Definition.Id;

        foreach (var finding in execution.Findings)
        {
            if (!string.Equals(finding.RuleId, ruleId, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"A finding from {finding.RuleId} was handed to {ruleId}'s execution record. A "
                    + "finding belongs to the rule that produced it, and filing it under another "
                    + "would attribute it to a rule that never made it.",
                    nameof(execution));
            }
        }

        switch (execution.Outcome)
        {
            case RuleExecutionOutcome.Succeeded when execution.ObjectsNotJudged > 0:
                throw new ArgumentException(
                    $"{ruleId} succeeded and yet could not judge {execution.ObjectsNotJudged} "
                    + "objects. A rule that could not read what it declared has not succeeded, and "
                    + "recording it as Indeterminate is what keeps silence meaning one thing.",
                    nameof(execution));

            case RuleExecutionOutcome.Succeeded when execution.MissingInputs.Count > 0:
                throw new ArgumentException(
                    $"{ruleId} succeeded and yet named missing inputs.",
                    nameof(execution));

            case RuleExecutionOutcome.Indeterminate when execution.ObjectsNotJudged == 0:
                throw new ArgumentException(
                    $"{ruleId} is indeterminate and judged everything it was offered. An outcome "
                    + "that says a verdict was not reached must say which objects it was not "
                    + "reached on.",
                    nameof(execution));

            case RuleExecutionOutcome.Indeterminate when execution.MissingInputs.Count == 0:
                throw new ArgumentException(
                    $"{ruleId} could not judge {execution.ObjectsNotJudged} objects and named no "
                    + "missing input. A rule declares what it reads precisely so it can say what "
                    + "was absent, and an unexplained gap is the answer this product refuses.",
                    nameof(execution));

            case RuleExecutionOutcome.Error when string.IsNullOrWhiteSpace(execution.Error):
                throw new ArgumentException(
                    $"{ruleId} errored and said nothing about why.", nameof(execution));

            case RuleExecutionOutcome.Error when execution.Findings.Count > 0:
                throw new ArgumentException(
                    $"{ruleId} threw and yet carries findings. A rule that failed part way through "
                    + "has no verdict, and its partial output would read as a complete one.",
                    nameof(execution));

            case RuleExecutionOutcome.DidNotRun when execution.Findings.Count > 0:
                throw new ArgumentException(
                    $"{ruleId} did not run and yet carries findings.", nameof(execution));

            case RuleExecutionOutcome.DidNotRun
                when execution.ObjectsJudged > 0 || execution.ObjectsNotJudged > 0:
                throw new ArgumentException(
                    $"{ruleId} did not run and yet was offered objects.", nameof(execution));

            default:
                return;
        }
    }

    /// <summary>
    /// The guard for everything except the three writes that make up one object.
    /// </summary>
    /// <remarks>
    /// <b>It commits the open object batch, and that is the point.</b> Only
    /// <see cref="WriteLapsInventory"/>, <see cref="WriteControlEdges"/> and
    /// <see cref="WritePermissionClassification"/> may run inside the batch; every other statement on
    /// this connection must set a transaction it cannot see, so it has to find one already committed.
    /// Putting the flush here rather than in each of twenty methods is deliberate: the first version
    /// of this change relied on callers remembering, and 398 tests failed inside
    /// <c>ControlEdgeStorage.Complete</c> because one of them did not.
    /// </remarks>
    private void ThrowIfFinished()
    {
        ThrowIfFinishedWithinObject();
        FlushObjects();
    }

    /// <summary>The same guard, for the per-object writes that legitimately run inside the batch.</summary>
    private void ThrowIfFinishedWithinObject()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_finished)
        {
            throw new InvalidOperationException(
                "This judgement is finished. A judging that has been sealed is not added to; "
                + "judging the bundle again writes a new store over this one.");
        }
    }

    private void Execute(
        SqliteTransaction transaction, string sql, Action<SqliteCommand> bind)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        bind(command);
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// One spelling for a moment in time, so two rows written by different methods sort together.
    /// </summary>
    private static string Text(DateTimeOffset moment) =>
        moment.ToUniversalTime().ToString("O");

    private static void Pragma(SqliteConnection connection, string pragma)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA " + pragma;
        command.ExecuteNonQuery();
    }
}
