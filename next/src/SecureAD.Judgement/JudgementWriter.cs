using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;

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
    private readonly List<RuleExecutionOutcome> _outcomes = [];
    private bool _evidenceIsComplete = true;
    private readonly HashSet<string> _rulesWritten = new(StringComparer.Ordinal);

    private long _nextFindingId = 1;
    private bool _finished;
    private bool _disposed;

    /// <summary>The immutable generation this writer will publish.</summary>
    public Guid GenerationId { get; } = Guid.NewGuid();

    private JudgementWriter(string bundleDirectory, string partialPath, SqliteConnection connection)
    {
        _bundleDirectory = bundleDirectory;
        _partialPath = partialPath;
        _connection = connection;
    }

    internal void RecordEvidenceScope(RunScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ThrowIfFinished();
        _evidenceIsComplete = scope.AllDeclaredDomainsAreComplete;
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
    public void Complete(DateTimeOffset completedUtc)
    {
        ThrowIfFinished();

        var state = _evidenceIsComplete
            && _outcomes.All(o => o == RuleExecutionOutcome.Succeeded)
            ? JudgementRunState.Completed
            : JudgementRunState.CompletedDegraded;

        FinishWithState(state, completedUtc);

        JudgementSchema.CreateDeferredIndexes(_connection);
        Pragma(_connection, "wal_checkpoint(TRUNCATE)");
        _connection.Close();
        SqliteConnection.ClearPool(_connection);

        AnalysisStoreLifecycle.Publish(
            _bundleDirectory,
            AnalysisStoreKind.Judgement,
            GenerationId);
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

        _connection.Dispose();
        _disposed = true;
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
                    + "user_account_control, unreadable_service_names) "
                    + "VALUES ($id, $sid, $uac, $unreadable)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$sid", kerberoastable.ObjectSid);
                        command.Parameters.AddWithValue(
                            "$uac", (long)kerberoastable.UserAccountControl);
                        command.Parameters.AddWithValue(
                            "$unreadable", kerberoastable.UnreadableServiceNames);
                    });

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
                    + "trustee_name, broad_principal_sid, attribute, rights, reach, "
                    + "inherited_from, expansion_was_complete) "
                    + "VALUES ($id, $trustee, $name, $broad, $attribute, $rights, $reach, "
                    + "$inherited, $complete)",
                    command =>
                    {
                        command.Parameters.AddWithValue("$id", findingId);
                        command.Parameters.AddWithValue("$trustee", readers.TrusteeSid);
                        command.Parameters.AddWithValue(
                            "$name", (object?)readers.TrusteeName ?? DBNull.Value);
                        command.Parameters.AddWithValue("$broad", readers.BroadPrincipalSid);
                        command.Parameters.AddWithValue("$attribute", readers.Attribute);
                        command.Parameters.AddWithValue("$rights", readers.Rights.ToString());
                        command.Parameters.AddWithValue("$reach", readers.Reach.ToString());
                        command.Parameters.AddWithValue(
                            "$inherited", (object?)readers.InheritedFrom ?? DBNull.Value);
                        command.Parameters.AddWithValue(
                            "$complete", readers.ExpansionWasComplete ? 1L : 0L);
                    });

                // The path, in order. Without it the finding names a broad principal and cannot say
                // which link an operator would cut, which is the whole of P-123's third condition.
                for (var ordinal = 0; ordinal < readers.MembershipPath.Count; ordinal++)
                {
                    var sid = readers.MembershipPath[ordinal];
                    var position = ordinal;

                    Execute(
                        transaction,
                        "INSERT INTO finding_laps_password_reader_path (finding_id, ordinal, sid) "
                        + "VALUES ($id, $ordinal, $sid)",
                        command =>
                        {
                            command.Parameters.AddWithValue("$id", findingId);
                            command.Parameters.AddWithValue("$ordinal", position);
                            command.Parameters.AddWithValue("$sid", sid);
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

    private void ThrowIfFinished()
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
