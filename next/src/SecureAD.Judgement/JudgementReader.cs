using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

/// <summary>
/// What one judging concluded, read back.
/// </summary>
/// <param name="EvidenceSeal">The capture this was judged against.</param>
/// <param name="State">What became of the judging.</param>
/// <param name="EvaluationAsOf">The reference time temporal rules were evaluated against.</param>
/// <param name="StartedUtc">When judging started.</param>
/// <param name="CompletedUtc">When it finished.</param>
public sealed record JudgementDescription(
    string EvidenceSeal,
    JudgementRunState State,
    DateTimeOffset EvaluationAsOf,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc);

/// <summary>
/// One rule's execution, read back, without the findings it produced.
/// </summary>
/// <param name="RuleId">The rule.</param>
/// <param name="RuleVersion">The version of its logic that ran.</param>
/// <param name="Outcome">What became of it.</param>
/// <param name="ObjectsJudged">Objects it reached a verdict on.</param>
/// <param name="ObjectsNotJudged">Objects it could not.</param>
/// <param name="MissingInputs">The declared attributes that were absent.</param>
/// <param name="Error">Why it threw, when it did.</param>
public sealed record StoredRuleExecution(
    string RuleId,
    int RuleVersion,
    RuleExecutionOutcome Outcome,
    int ObjectsJudged,
    int ObjectsNotApplicable,
    int ObjectsNotJudged,
    IReadOnlyList<MissingInput> MissingInputs,
    string? Error);

/// <summary>
/// Everything one judging concluded: what it found, and which rules were run to produce it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The second list is why this type exists.</b> A list of findings on its own cannot say whether
/// anyone looked: no findings and no rules run means a bundle nobody judged, and no findings beside
/// rules that did run means a forest where nothing matched. Those are opposite answers to the
/// question a customer is actually asking, and a bare list of findings hands both to a screen in
/// the same shape.
/// </para>
/// <para>
/// <b>And the rules are executions rather than names</b>, because a rule that ran and could not read
/// its inputs has not established anything either. Counting it among the rules that ran, with no
/// more said, would be the same failure one level further in.
/// </para>
/// </remarks>
/// <param name="Description">What the judging recorded about itself.</param>
/// <param name="RulesRun">Every rule that was scheduled, and what became of it.</param>
/// <param name="Findings">What was found. Empty is meaningful only beside <paramref name="RulesRun"/>.</param>
public sealed record StoredJudgement(
    JudgementDescription Description,
    IReadOnlyList<StoredRuleExecution> RulesRun,
    IReadOnlyList<Finding> Findings)
{
    /// <summary>
    /// Whether this bundle was never judged, so an empty finding list says nothing about the
    /// forest.
    /// </summary>
    public bool DidNotRun => RulesRun.Count == 0;

    /// <summary>
    /// Whether every scheduled rule reached a verdict on everything it was offered.
    /// </summary>
    /// <remarks>
    /// <b>False means the findings are a floor, not a total.</b> Somewhere a rule could not read
    /// what it declared, so the forest has not been shown to be clean of what that rule looks for.
    /// </remarks>
    public bool EveryRuleReachedEveryVerdict =>
        RulesRun.Count > 0
        && RulesRun.All(r => r.Outcome == RuleExecutionOutcome.Succeeded);
}

/// <summary>
/// Reads a judgement store back, and refuses one that does not belong to the bundle it sits in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Opening checks three things, and each is a different way of being wrong.</b> The seal says
/// whether these bytes are the bytes that were written. The schema version says whether this build
/// understands the tables. The evidence fingerprint says whether this judgement is about
/// <i>this capture</i> - and that is the one no amount of care by the writer can establish, because
/// a store is an ordinary file that can be moved.
/// </para>
/// <para>
/// <b>The fingerprint check is the reason a judgement may be copied at all.</b> Two captures of one
/// forest produce directories with identical file names holding mostly the same objects, so a
/// judgement dropped into the wrong bundle would resolve nearly all of its findings and be wrong
/// about every one of them. Refusing here turns a silent wrong answer into a stated one.
/// </para>
/// </remarks>
public sealed class JudgementReader : IDisposable
{
    private readonly SqliteConnection _connection;
    private bool _disposed;

    private JudgementReader(
        string bundleDirectory, SqliteConnection connection, JudgementDescription description)
    {
        BundleDirectory = bundleDirectory;
        _connection = connection;
        Description = description;
    }

    /// <summary>The bundle this judgement was opened from.</summary>
    public string BundleDirectory { get; }

    /// <summary>What the judging recorded about itself.</summary>
    public JudgementDescription Description { get; }

    /// <summary>
    /// Verifies the judgement's seal and, only if it is intact and it belongs to this bundle, opens
    /// it for reading.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <returns>
    /// The open reader, or an <see cref="AuditError"/> saying which check refused it.
    /// </returns>
    public static Result<JudgementReader> Open(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var verdict = BundleSealing.VerifyJudgement(bundleDirectory);
        if (!verdict.MayBeOpened)
            return Failure(ReasonFor(verdict.State), verdict.Detail, bundleDirectory);

        var judgementPath = BundleLayout.JudgementPath(bundleDirectory);
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = judgementPath,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        try
        {
            connection.Open();
            var description = ReadDescription(connection);

            if (description is null)
            {
                connection.Dispose();
                return Failure(
                    "JudgementUnreadable",
                    $"The judgement at '{judgementPath}' records no run. Its seal is intact, so "
                    + "this is a defect in the build that wrote it rather than damage to the file.",
                    judgementPath);
            }

            var mismatch = EvidenceMismatch(bundleDirectory, description.EvidenceSeal);
            if (mismatch is not null)
            {
                connection.Dispose();
                return Failure("JudgementIsNotForThisEvidence", mismatch, judgementPath);
            }

            return new JudgementReader(bundleDirectory, connection, description);
        }
        catch (SqliteException error)
        {
            connection.Dispose();
            return Failure(
                "JudgementUnreadable",
                $"The seal on the judgement in '{bundleDirectory}' is intact and the store could "
                + $"not be read: {error.Message}. The bytes are the bytes that were sealed, so this "
                + "is a defect in this build rather than damage to the store.",
                judgementPath);
        }
    }

    /// <summary>
    /// Everything this judging concluded.
    /// </summary>
    /// <remarks>
    /// <b>One call, because the parts are only meaningful together.</b> Handing back findings on
    /// their own would let a caller render an empty list as a clean forest without ever asking
    /// whether a rule had run - which is the failure this product exists to prevent, so the type
    /// system is where it is prevented rather than the documentation.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// A finding is stored with no evidence row, so what it rests on has been lost.
    /// </exception>
    public StoredJudgement Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return new StoredJudgement(Description, ReadExecutions(), ReadFindings());
    }

    /// <summary>
    /// One page of findings, worst first, for a grid that must not hold a forest in memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the one place findings leave without the rules beside them, and it is guarded
    /// rather than trusted.</b> <see cref="Read"/> hands the two out together because an empty list
    /// means nothing on its own. A page cannot carry every rule execution on every page, so instead
    /// a judging where no rule ran is <i>refused</i> here: there is no page of findings to show,
    /// and a caller that received an empty page would draw a clean grid over a bundle nobody
    /// judged.
    /// </para>
    /// <para>
    /// <b>Ordered worst first, by rank rather than by the word.</b> The stored severity is the
    /// enum's name, so ordering on it is alphabetical - Critical, High, Low, Medium - which puts
    /// Low above Medium on a security screen and looks entirely normal.
    /// </para>
    /// <para>
    /// <b>The distinguished name ends the sort, and is not decoration.</b> Findings that share a
    /// severity and a rule have no order between them otherwise, so a page boundary landing inside
    /// such a group shows some of them twice and loses others - silently, and differently each
    /// time.
    /// </para>
    /// <para>
    /// <b>One row more than the page is fetched, and not returned.</b> That is how a page knows
    /// another follows without a second query counting rows nobody asked to see.
    /// </para>
    /// </remarks>
    /// <param name="query">Which findings, and where to carry on from.</param>
    /// <returns>The page, or why no page of findings can honestly be shown.</returns>
    public Result<FindingsPage> ReadPage(FindingsQuery query)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);

        if (query.PageSize < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(query),
                query.PageSize,
                "A page holds at least one finding.");
        }

        var executions = ReadExecutions();

        if (executions.Count == 0)
        {
            return Result<FindingsPage>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "JudgementDidNotRun",
                ErrorSeverity.Failed,
                "No rule was run over this bundle, so there is no page of findings to show. An "
                + "empty grid here would say the forest is clean, and what is true is that nobody "
                + "has looked.",
                BundleDirectory));
        }

        var versions = ReadRuleVersions();
        var findings = new List<Finding>();
        FindingsPageMark? next = null;

        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            SELECT f.finding_id, f.rule_id, f.subject_kind, f.subject_key, f.object_guid,
                   f.severity, f.distinguished_name, f.detail, f.coverage,
                   d.user_account_control, d.is_computer, d.server_trust_account_bit,
                   d.primary_group_is_domain_controller, d.under_domain_controllers_ou,
                   f.domain_fqdn, f.object_class, f.severity_rank
            FROM finding f
            LEFT JOIN finding_unconstrained_delegation d ON d.finding_id = f.finding_id
            WHERE ($severity IS NULL OR f.severity = $severity)
              AND ($rule IS NULL OR f.rule_id = $rule)
              AND ($domain IS NULL OR f.domain_fqdn = $domain)
              AND ($container IS NULL OR f.distinguished_name LIKE $containerLike ESCAPE '\')
              AND ($afterRank IS NULL OR
                   f.severity_rank < $afterRank OR
                   (f.severity_rank = $afterRank AND f.rule_id > $afterRule) OR
                   (f.severity_rank = $afterRank AND f.rule_id = $afterRule
                    AND f.distinguished_name > $afterDn))
            ORDER BY f.severity_rank DESC, f.rule_id ASC, f.distinguished_name ASC
            LIMIT $limit
            """;

        Bind(command, "$severity", query.Severity?.ToString());
        Bind(command, "$rule", query.RuleId);
        Bind(command, "$domain", query.DomainFqdn);
        Bind(command, "$container", query.Container);
        Bind(command, "$containerLike", ContainerPattern(query.Container));
        Bind(command, "$afterRank", query.After?.SeverityRank);
        Bind(command, "$afterRule", query.After?.RuleId);
        Bind(command, "$afterDn", query.After?.DistinguishedName);

        // One more than asked for, so the extra row answers "is there another page" and is then
        // dropped. The alternative is a second query counting everything that matched.
        command.Parameters.AddWithValue("$limit", query.PageSize + 1);

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            if (findings.Count == query.PageSize)
            {
                // The extra row. Its existence is the whole answer, so it is not read as a finding
                // and not shown - the mark points at the last row that was.
                var last = findings[^1];
                next = new FindingsPageMark((int)last.Severity, last.RuleId, last.DistinguishedName);
                break;
            }

            findings.Add(ReadFinding(reader, versions));
        }

        return Result<FindingsPage>.Success(
            new FindingsPage(findings, next, executions.Count));
    }

    /// <summary>
    /// Binds a value that may be absent, where absent means <i>every one of them</i>.
    /// </summary>
    private static void Bind(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    /// <summary>
    /// The pattern that matches a container and everything beneath it.
    /// </summary>
    /// <remarks>
    /// <b>The wildcards in the operator's own text are escaped first.</b> A distinguished name may
    /// contain <c>%</c> or <c>_</c>, and left alone they would quietly widen the scope of a grid
    /// that says it is showing one container.
    /// </remarks>
    private static string? ContainerPattern(string? container) =>
        container is null
            ? null
            : "%" + container.Replace(@"\", @"\\", StringComparison.Ordinal)
                             .Replace("%", @"\%", StringComparison.Ordinal)
                             .Replace("_", @"\_", StringComparison.Ordinal);

    private IReadOnlyList<StoredRuleExecution> ReadExecutions()
    {
        var missing = ReadMissingInputs();
        var executions = new List<StoredRuleExecution>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT rule_id, rule_version, outcome, objects_judged, objects_not_applicable, "
            + "objects_not_judged, error FROM rule_execution ORDER BY rule_id";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var ruleId = reader.GetString(0);

            executions.Add(new StoredRuleExecution(
                ruleId,
                reader.GetInt32(1),
                Enum.Parse<RuleExecutionOutcome>(reader.GetString(2)),
                reader.GetInt32(3),
                reader.GetInt32(4),
                reader.GetInt32(5),
                missing.TryGetValue(ruleId, out var inputs) ? inputs : [],
                reader.IsDBNull(6) ? null : reader.GetString(6)));
        }

        return executions;
    }

    /// <summary>
    /// Every finding this judging produced, with the evidence each rests on.
    /// </summary>
    /// <remarks>
    /// Private, and deliberately. An empty list never means the forest is clean - it means no rule
    /// matched anything, which is only a statement about the forest beside the rules that ran. The
    /// two leave this class together or not at all.
    /// </remarks>
    private IReadOnlyList<Finding> ReadFindings()
    {

        var versions = ReadRuleVersions();
        var findings = new List<Finding>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            SELECT f.finding_id, f.rule_id, f.subject_kind, f.subject_key, f.object_guid,
                   f.severity, f.distinguished_name, f.detail, f.coverage,
                   d.user_account_control, d.is_computer, d.server_trust_account_bit,
                   d.primary_group_is_domain_controller, d.under_domain_controllers_ou,
                   f.domain_fqdn, f.object_class
            FROM finding f
            LEFT JOIN finding_unconstrained_delegation d ON d.finding_id = f.finding_id
            ORDER BY f.finding_id
            """;

        using var reader = command.ExecuteReader();

        while (reader.Read())
            findings.Add(ReadFinding(reader, versions));

        return findings;
    }

    /// <summary>
    /// Reads one finding, with the evidence it rests on.
    /// </summary>
    /// <remarks>
    /// <b>One mapping, shared by the whole read and by a page.</b> Two would be two accounts of the
    /// same row, and the day one of them gained a column the other would quietly keep answering
    /// without it.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The finding has no evidence row, so what it rests on has been lost.
    /// </exception>
    private static Finding ReadFinding(SqliteDataReader reader, IReadOnlyDictionary<string, int> versions)
    {
        var ruleId = reader.GetString(1);

        if (reader.IsDBNull(9))
        {
            throw new InvalidOperationException(
                $"Finding {reader.GetInt64(0)} ({ruleId}) is stored with no evidence row, so "
                + "what it rests on has been lost. A finding that cannot say what it rests on "
                + "must not be presented as one.");
        }

        var evidence = new UnconstrainedDelegationEvidence(
            (uint)reader.GetInt64(9),
            reader.GetInt64(10) != 0,
            new DomainControllerSignals(
                reader.GetInt64(11) != 0,
                reader.GetInt64(12) != 0,
                reader.GetInt64(13) != 0));

        return new Finding(
            ruleId,
            versions[ruleId],
            Enum.Parse<Severity>(reader.GetString(5)),
            new FindingSubject(
                Enum.Parse<FindingSubjectKind>(reader.GetString(2)),
                reader.GetString(3)),
            Guid.Parse(reader.GetString(4)),
            reader.GetString(6),
            reader.GetString(14),
            reader.GetString(15),
            reader.GetString(7),
            Enum.Parse<EvidenceCompleteness>(reader.GetString(8)),
            evidence);
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
    /// Whether this judgement was made against the evidence it is sitting beside, and why not.
    /// </summary>
    private static string? EvidenceMismatch(string bundleDirectory, string judgedSeal)
    {
        var evidenceSealPath = BundleLayout.SealPath(bundleDirectory);
        var contents = BundleSealing.ReadSeal(evidenceSealPath);

        if (contents is null || string.IsNullOrWhiteSpace(contents.Hash))
        {
            return $"The judgement in '{bundleDirectory}' names the evidence it judged and there "
                + $"is no readable evidence seal at '{evidenceSealPath}' to check it against. A "
                + "judgement is only meaningful beside the capture it was made from.";
        }

        if (string.Equals(contents.Hash, judgedSeal, StringComparison.Ordinal))
            return null;

        return $"The judgement in '{bundleDirectory}' was made against evidence sealed as "
            + $"{judgedSeal}, and the evidence in that bundle is sealed as {contents.Hash}. This "
            + "judgement is about a different capture. Two captures of one forest hold mostly the "
            + "same objects, so its findings would resolve against this evidence and be wrong "
            + "about it; judge this bundle rather than moving a judgement into it.";
    }

    private static JudgementDescription? ReadDescription(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT schema_version, evidence_seal, state, evaluation_as_of, judging_started_utc, "
            + "judging_completed_utc FROM judgement";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
            return null;

        var version = reader.GetInt32(0);
        if (version != JudgementSchema.Version)
        {
            throw new SqliteException(
                $"The judgement was written against schema version {version} and this build reads "
                + $"version {JudgementSchema.Version}. Nothing here is kept backward compatible, "
                + "and a judgement is rebuilt rather than migrated: delete it and judge the bundle "
                + "again.",
                0);
        }

        if (reader.IsDBNull(5))
            return null;

        return new JudgementDescription(
            reader.GetString(1),
            Enum.Parse<JudgementRunState>(reader.GetString(2)),
            DateTimeOffset.Parse(reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(4), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(5), System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// The version each rule ran at, so a finding can carry the version of the rule that made it
    /// without the store keeping a second copy on every row.
    /// </summary>
    private Dictionary<string, int> ReadRuleVersions()
    {
        var versions = new Dictionary<string, int>(StringComparer.Ordinal);

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT rule_id, rule_version FROM rule_execution";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            versions[reader.GetString(0)] = reader.GetInt32(1);

        return versions;
    }

    private Dictionary<string, List<MissingInput>> ReadMissingInputs()
    {
        var missing = new Dictionary<string, List<MissingInput>>(StringComparer.Ordinal);

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT rule_id, attribute, objects_affected FROM rule_execution_missing_input "
            + "ORDER BY rule_id, attribute";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var ruleId = reader.GetString(0);

            if (!missing.TryGetValue(ruleId, out var inputs))
                missing[ruleId] = inputs = [];

            inputs.Add(new MissingInput(reader.GetString(1), reader.GetInt32(2)));
        }

        return missing;
    }

    private static string ReasonFor(SealState state) => state switch
    {
        SealState.Absent => "JudgementSealAbsent",
        SealState.Unreadable => "JudgementSealUnreadable",
        SealState.Mismatch => "JudgementSealMismatch",
        _ => throw new InvalidOperationException(
            $"{state} may be opened and is not a refusal. Only SealVerdict.MayBeOpened decides "
            + "which states those are, and this switch has fallen out of step with it."),
    };

    private static Result<JudgementReader> Failure(
        string reason, string description, string context) =>
        Result<JudgementReader>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));
}
