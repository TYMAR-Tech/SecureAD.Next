using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Storage;

namespace SecureAD.Judgement;

/// <summary>
/// What one judging concluded, read back.
/// </summary>
/// <param name="EvidenceSeal">The capture this was judged against.</param>
/// <param name="GenerationId">The immutable Judgement generation selected by its manifest.</param>
/// <param name="DerivationGenerationId">The Derivation generation consumed, or null for Evidence-only judging.</param>
/// <param name="State">What became of the judging.</param>
/// <param name="EvaluationAsOf">The reference time temporal rules were evaluated against.</param>
/// <param name="StartedUtc">When judging started.</param>
/// <param name="CompletedUtc">When it finished.</param>
public sealed record JudgementDescription(
    string EvidenceSeal,
    Guid GenerationId,
    Guid? DerivationGenerationId,
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
/// <param name="FindingsProduced">
/// How many findings this rule wrote.
/// <para>
/// <b>Zero is not the same claim as a rule that could not run</b>, which is why it is carried
/// beside the outcome rather than inferred from an empty grid. A rule that judged every object it
/// was about and reported nothing has established something; one recorded as
/// <see cref="RuleExecutionOutcome.Indeterminate"/> has not, and both write zero findings.
/// </para>
/// </param>
/// <param name="Error">Why it threw, when it did.</param>
public sealed record StoredRuleExecution(
    string RuleId,
    int RuleVersion,
    RuleExecutionOutcome Outcome,
    int ObjectsJudged,
    int ObjectsNotApplicable,
    int ObjectsNotJudged,
    IReadOnlyList<MissingInput> MissingInputs,
    int FindingsProduced,
    string? Error);

/// <summary>
/// What every scheduled rule did to one bundle, without the findings they produced.
/// </summary>
/// <remarks>
/// <para>
/// <b>A container rather than a bare list, because the empty list has two meanings.</b> No
/// executions can mean a bundle nobody judged, or a judging that opened and recorded nothing before
/// it stopped. A screen handed a bare list would draw the same thing for both and an operator would
/// read either as "no rules apply here".
/// </para>
/// <para>
/// <b>It carries the run's state so the reason is available where the list is.</b> Until now the
/// executions could only be had through <see cref="StoredJudgement"/>, which says this in the same
/// way; reading them on their own would have removed that statement from the one caller who needs
/// it most - the screen whose whole subject is what was and was not checked.
/// </para>
/// </remarks>
/// <param name="Executions">Every rule that was scheduled, and what became of it.</param>
/// <param name="State">What became of the judging as a whole.</param>
public sealed record StoredRuleExecutions(
    IReadOnlyList<StoredRuleExecution> Executions,
    JudgementRunState State)
{
    /// <summary>
    /// Whether this bundle was never judged, so an empty list says nothing about the rules.
    /// </summary>
    public bool DidNotRun => Executions.Count == 0;
}

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
    private bool _ownershipValidated;

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
    /// Validates and reads saved path inputs. Replays only stored source witnesses; never discovers
    /// requesters, evaluates permissions, writes analysis or returns a reachability verdict.
    /// </summary>
    public PathInputs ReadPathInputs()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return PathInputStorage.Read(_connection, Description, BundleDirectory);
    }

    /// <summary>
    /// Validates and reads one saved Tier-0 path result, replaying only saved requester questions
    /// to verify their source proof. Never discovers new questions, searches paths or publishes results.
    /// An uncaptured subject remains Unknown, not NotReachable.
    /// </summary>
    public Tier0PathResult ReadTier0Path(string subjectDn)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        return Tier0PathStorage.Read(_connection, Description, BundleDirectory, subjectDn);
    }

    /// <summary>Projects path and requester coverage from one complete proof replay of this opened generation; nothing is cached.</summary>
    public (Tier0PathResult Path, PathRequesterCoverage Coverage) ReadTier0PathWithCoverage(
        string subjectDn, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectDn);
        cancellationToken.ThrowIfCancellationRequested();
        return Tier0PathStorage.ReadWithCoverage(_connection, Description, BundleDirectory, subjectDn, cancellationToken);
    }

    /// <summary>
    /// Reads coverage from the saved selection and reconciled proof batches in this exact generation.
    /// Replays only saved proof questions for validation; never selects new accounts or publishes analysis.
    /// </summary>
    public PathRequesterCoverage ReadPathRequesterCoverage()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Tier0PathStorage.ReadCoverage(_connection, Description, BundleDirectory);
    }

    /// <summary>Reads the stored control product, object-first or named-trustee-first, with coverage and hidden counts.</summary>
    public ControlEdgePage ReadControlEdges(string? target, string? holderSid, string? holderScope, bool includeExpected, long afterId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (target is not null && holderSid is not null)
            throw new ArgumentException("Choose an object or a holder, not both.");
        ArgumentOutOfRangeException.ThrowIfNegative(afterId);
        ValidateOwnership();
        return ControlEdgeStorage.Read(_connection, Description, target, holderSid, holderScope, includeExpected, afterId)
            with { GenerationId = Description.GenerationId,
                OwnershipCoverage = OwnershipAuditStorage.ReadCoverage(_connection, Description, target) };
    }

    /// <summary>
    /// Reads one original permission by its stored ID and target, retaining the control product's
    /// source and generation validation. The ID is not a display-page cursor.
    /// </summary>
    public ControlEdge ReadControlEdge(string target, long id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(id);
        ValidateOwnership();
        return ControlEdgeStorage.ReadExact(_connection, Description, target, id);
    }

    private void ValidateOwnership()
    {
        // The reader holds one opened immutable generation; a new generation gets its own validation.
        if (!_ownershipValidated)
        {
            OwnershipAuditValidation.Validate(_connection, Description, BundleDirectory);
            _ownershipValidated = true;
        }
    }

    /// <summary>Reads explicit requester assessments object-first, requester-first, or together.</summary>
    public SelfMembershipAssessmentSet ReadSelfMembershipAssessments(string? target, string? requester)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return SelfMembershipStorage.Read(_connection, Description, target, requester);
    }

    /// <summary>Reads stored requester counts and capture-wide coverage; null means no requester product was derived.</summary>
    public SelfMembershipSummary? ReadSelfMembershipSummary()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return SelfMembershipCoverageStorage.Read(_connection, Description);
    }

    /// <summary>Reads persisted membership beneath a named holder's permission, without walking the directory graph.</summary>
    public MemberAttributionDetail ReadMemberAttribution(string holderSid, string? holderScope, string target)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(holderSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        FullControlStorage.ValidateSelection(_connection, Description, "target = $value COLLATE NOCASE", target, null, null);
        return MemberAttributionStorage.Read(_connection, Description, holderSid, holderScope, target)
            with { GenerationId = Description.GenerationId };
    }

    /// <summary>Reads source group permissions through stored membership, separately from named-holder edge counts.</summary>
    public MemberPermissionPage ReadPermissionsThroughMembership(string memberSid, string? memberScope, bool includeExpected, long afterId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(memberSid);
        ArgumentOutOfRangeException.ThrowIfNegative(afterId);
        var page = MemberAttributionStorage.ReadReverse(_connection, Description, memberSid, memberScope, includeExpected, afterId);
        foreach (var permission in page.Permissions.DistinctBy(value => (value.Target, value.HolderSid, value.HolderScope)))
        {
            FullControlStorage.ValidateSelection(_connection, Description, "target = $value COLLATE NOCASE", permission.Target, null, null);
            ControlEdgeStorage.ReadHolderEdges(_connection, Description, permission.Target, permission.HolderSid, permission.HolderScope);
        }
        return page;
    }

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

        var resolved = AnalysisStoreLifecycle.Resolve(
            bundleDirectory,
            AnalysisStoreKind.Judgement);
        if (!resolved.IsSuccess)
            return Result<JudgementReader>.Failure(resolved.Error!);

        var generation = resolved.Value!;
        var verdict = BundleSealing.VerifyAnalysisGeneration(
            bundleDirectory,
            generation,
            "judgement store",
            "It does not prove every scheduled rule reached a verdict, which is a claim the store makes in its own tables.");
        if (!verdict.MayBeOpened)
            return Failure(ReasonFor(verdict.State), verdict.Detail, bundleDirectory);

        var judgementPath = BundleLayout.AnalysisGenerationDataPath(
            bundleDirectory, generation.Kind, generation.GenerationId);
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

            if (description.GenerationId != generation.GenerationId)
            {
                connection.Dispose();
                return Failure(
                    "JudgementGenerationMismatch",
                    $"The judgement manifest selects generation '{generation.GenerationId:D}', but "
                    + $"the database identifies itself as '{description.GenerationId:D}'.",
                    judgementPath);
            }

            var mismatch = EvidenceMismatch(bundleDirectory, description.EvidenceSeal);
            if (mismatch is not null)
            {
                connection.Dispose();
                return Failure("JudgementIsNotForThisEvidence", mismatch, judgementPath);
            }

            var derivationMismatch = DerivationMismatch(
                bundleDirectory,
                description.DerivationGenerationId);
            if (derivationMismatch is not null)
            {
                connection.Dispose();
                return Failure("JudgementIsNotForThisDerivation", derivationMismatch, judgementPath);
            }

            return new JudgementReader(bundleDirectory, connection, description);
        }

        catch (Exception error) when (
            error is SqliteException
            or FormatException
            or ArgumentException
            or InvalidOperationException)
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
            $"""
            SELECT {FindingColumns}
            FROM finding f
            {EvidenceJoins}
            WHERE ($severity IS NULL OR f.severity = $severity)
              AND ($rule IS NULL OR f.rule_id = $rule)
              AND ($domain IS NULL OR f.domain_fqdn = $domain)
              AND ($container IS NULL OR f.distinguished_name LIKE $containerLike ESCAPE '\')
              AND ($object IS NULL OR f.distinguished_name = $object)
              AND ($afterRank IS NULL OR
                   f.severity_rank < $afterRank OR
                   (f.severity_rank = $afterRank AND f.rule_id > $afterRule) OR
                   (f.severity_rank = $afterRank AND f.rule_id = $afterRule
                    AND f.distinguished_name > $afterDn) OR
                   (f.severity_rank = $afterRank AND f.rule_id = $afterRule
                    AND f.distinguished_name = $afterDn AND f.finding_id > $afterId))
            ORDER BY f.severity_rank DESC, f.rule_id ASC, f.distinguished_name ASC, f.finding_id ASC
            LIMIT $limit
            """;

        Bind(command, "$severity", query.Severity?.ToString());
        Bind(command, "$rule", query.RuleId);
        Bind(command, "$domain", query.DomainFqdn);
        Bind(command, "$container", query.Container);
        Bind(command, "$containerLike", ContainerPattern(query.Container));
        Bind(command, "$object", query.Object);
        Bind(command, "$afterRank", query.After?.SeverityRank);
        Bind(command, "$afterRule", query.After?.RuleId);
        Bind(command, "$afterDn", query.After?.DistinguishedName);
        Bind(command, "$afterId", query.After?.FindingId);

        // One more than asked for, so the extra row answers "is there another page" and is then
        // dropped. The alternative is a second query counting everything that matched.
        command.Parameters.AddWithValue("$limit", query.PageSize + 1);

        using var reader = command.ExecuteReader();

        // Tracked alongside rather than taken from the finding, which does not carry its own
        // identity. The mark needs the identity of the last row SHOWN, so it is recorded as each
        // row is added rather than read from the extra row that ends the page.
        var lastId = 0L;

        while (reader.Read())
        {
            if (findings.Count == query.PageSize)
            {
                // The extra row. Its existence is the whole answer, so it is not read as a finding
                // and not shown - the mark points at the last row that was.
                var last = findings[^1];
                next = new FindingsPageMark((int)last.Severity, last.RuleId, last.DistinguishedName, lastId);
                break;
            }

            lastId = reader.GetInt64(0);
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
    /// What a findings grid's filters may offer, taken from the findings that exist.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read from the data rather than listed in the screen.</b> A severity list written into a
    /// view offers Critical whether or not any finding is critical, so an operator picks it, sees
    /// an empty grid, and has learned nothing except to distrust the filter. The predecessor read
    /// its values the same way.
    /// </para>
    /// <para>
    /// <b>Not scoped by the container.</b> The values are for the whole judgement, so the list does
    /// not change under the operator as he moves about the tree - a filter whose options come and
    /// go while a selection is held is a filter that silently clears itself.
    /// </para>
    /// </remarks>
    /// <returns>The severities and rules some finding has, worst and lowest first.</returns>
    public FindingsFilterValues ReadFilterValues()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var severities = new List<Severity>();
        var rules = new List<string>();

        using (var command = _connection.CreateCommand())
        {
            command.CommandText =
                "SELECT DISTINCT severity, severity_rank FROM finding ORDER BY severity_rank DESC";

            using var reader = command.ExecuteReader();
            while (reader.Read())
                severities.Add(Enum.Parse<Severity>(reader.GetString(0)));
        }

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT DISTINCT rule_id FROM finding ORDER BY rule_id";

            using var reader = command.ExecuteReader();
            while (reader.Read())
                rules.Add(reader.GetString(0));
        }

        return new FindingsFilterValues(severities, rules, ReadExecutions().Count);
    }

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

    /// <summary>
    /// What every scheduled rule did, without the findings it produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Public because a screen needs it without wanting the findings.</b> <see cref="Read"/>
    /// returns the whole store, findings included, which on a real forest is every row a judging
    /// wrote. A screen answering <i>what did the product check</i> wants eleven rows and would
    /// otherwise pay for thousands.
    /// </para>
    /// <para>
    /// <b>Every rule that was scheduled, whatever became of it</b>, including one recorded as
    /// having not run. Absence cannot state that a rule was skipped, which is the reason the table
    /// carries a row for it.
    /// </para>
    /// <para>
    /// <b>Vouched rather than bare</b>, per gate 4. An empty list means either a bundle nobody
    /// judged or a judging that recorded nothing before it stopped, and
    /// <see cref="StoredRuleExecutions.State"/> is what separates them.
    /// </para>
    /// </remarks>
    public StoredRuleExecutions ReadRuleExecutions()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return new StoredRuleExecutions(ReadExecutions(), Description.State);
    }

    private IReadOnlyList<StoredRuleExecution> ReadExecutions()
    {
        var missing = ReadMissingInputs();
        var produced = ReadFindingCountsByRule();
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
                produced.GetValueOrDefault(ruleId),
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
            $"""
            SELECT {FindingColumns}
            FROM finding f
            {EvidenceJoins}
            ORDER BY f.finding_id
            """;

        using var reader = command.ExecuteReader();

        while (reader.Read())
            findings.Add(ReadFinding(reader, versions));

        return findings;
    }

    /// <summary>
    /// Every column <see cref="ReadFinding"/> reads, aliased so the name is the same whichever
    /// query selected it.
    /// </summary>
    /// <remarks>
    /// <b>One list, used by both queries.</b> They had two, and they disagreed - see the remarks on
    /// <see cref="ReadFinding"/> for what that showed an operator. A single list cannot disagree
    /// with itself, and adding a kind of evidence is then one edit here rather than two that must
    /// be kept in step by whoever remembers.
    /// </remarks>
    private const string FindingColumns =
        """
        f.finding_id, f.rule_id, f.subject_kind, f.subject_key, f.object_guid,
        f.severity, f.distinguished_name, f.detail, f.coverage,
        f.domain_fqdn, f.object_class,
        d.user_account_control              AS d_user_account_control,
        d.is_computer                       AS d_is_computer,
        d.server_trust_account_bit          AS d_server_trust_account_bit,
        d.primary_group_is_domain_controller AS d_primary_group_is_domain_controller,
        d.under_domain_controllers_ou       AS d_under_domain_controllers_ou,
        a.sid                               AS a_sid,
        p.user_account_control              AS p_user_account_control,
        h.finding_id                        AS h_finding_id,
        h.object_sid                        AS h_object_sid,
        h.unreadable_values                 AS h_unreadable_values,
        k.finding_id                        AS k_finding_id,
        k.object_sid                        AS k_object_sid,
        k.user_account_control              AS k_user_account_control,
        k.unreadable_service_names          AS k_unreadable_service_names,
        k.protection_catalogue_version      AS k_protection_catalogue_version,
        k.direct_protection_entry_id        AS k_direct_protection_entry_id,
        k.direct_protection_name            AS k_direct_protection_name,
        l.windows_laps_expiration           AS l_windows_laps_expiration,
        l.legacy_laps_expiration            AS l_legacy_laps_expiration,
        l.capability_kind                   AS l_capability_kind,
        l.capability_basis                  AS l_capability_basis,
        l.operating_system                  AS l_operating_system,
        l.operating_system_version          AS l_operating_system_version,
        r.trustee_sid                       AS r_trustee_sid,
        r.trustee_name                      AS r_trustee_name,
        r.broad_principal_sid               AS r_broad_principal_sid,
        r.broad_principal_name              AS r_broad_principal_name,
        r.attribute                         AS r_attribute,
        r.rights                            AS r_rights,
        r.reach                             AS r_reach,
        r.inherited_from                    AS r_inherited_from,
        r.expansion_was_complete            AS r_expansion_was_complete,
        r.finding_id                        AS r_finding_id,
        e.policy_display_name               AS e_policy_display_name,
        e.configured_value                  AS e_configured_value,
        e.form                              AS e_form,
        e.decryptor_sid                     AS e_decryptor_sid,
        e.decryptor_name                    AS e_decryptor_name,
        e.broad_principal_sid               AS e_broad_principal_sid,
        e.broad_principal_name              AS e_broad_principal_name,
        e.expansion_was_complete            AS e_expansion_was_complete,
        e.finding_id                        AS e_finding_id,
        t.trustee_sid                       AS t_trustee_sid,
        t.trustee_name                      AS t_trustee_name,
        t.broad_principal_sid               AS t_broad_principal_sid,
        t.broad_principal_name              AS t_broad_principal_name,
        t.takeover_right                    AS t_takeover_right,
        t.inherited_from                    AS t_inherited_from,
        t.expansion_was_complete            AS t_expansion_was_complete,
        t.finding_id                        AS t_finding_id,
        w.owner_sid                         AS w_owner_sid,
        w.owner_name                        AS w_owner_name,
        w.standing                          AS w_standing,
        w.object_class                      AS w_object_class,
        w.membership_was_complete           AS w_membership_was_complete,
        w.finding_id                        AS w_finding_id
        """;

    /// <summary>One join per kind of evidence, shared for the same reason the columns are.</summary>
    private const string EvidenceJoins =
        """
        LEFT JOIN finding_unconstrained_delegation d ON d.finding_id = f.finding_id
        LEFT JOIN finding_admincount_without_protection a ON a.finding_id = f.finding_id
        LEFT JOIN finding_user_account_control p ON p.finding_id = f.finding_id
        LEFT JOIN finding_privileged_sid_history h ON h.finding_id = f.finding_id
        LEFT JOIN finding_kerberoastable_account k ON k.finding_id = f.finding_id
        LEFT JOIN finding_laps_deployment l ON l.finding_id = f.finding_id
        LEFT JOIN finding_laps_password_reader r ON r.finding_id = f.finding_id
        LEFT JOIN finding_laps_decryptor e ON e.finding_id = f.finding_id
        LEFT JOIN finding_object_takeover t ON t.finding_id = f.finding_id
        LEFT JOIN finding_object_ownership w ON w.finding_id = f.finding_id
        """;

    /// <summary>
    /// Reads one finding, with the evidence it rests on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One mapping, shared by the whole read and by a page.</b> Two would be two accounts of the
    /// same row, and the day one of them gained a column the other would quietly keep answering
    /// without it.
    /// </para>
    /// <para>
    /// <b>Columns are found by name, and that is not a style preference.</b> Until 2026-09-01 this
    /// read by position while the two queries selecting into it had different column lists: position
    /// 16 was <c>a.sid</c> in one and <c>f.severity_rank</c> in the other. A severity rank is never
    /// null, so on a page every non-delegation finding took the SID branch and <b>a severity rank
    /// was shown to an operator as a security identifier</b> - the High rank 2 came back as the SID
    /// "2". It did not throw and it did not look wrong. Names cannot drift silently: a query missing
    /// a column fails here, naming it.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The finding has no evidence row, so what it rests on has been lost.
    /// </exception>
    private Finding ReadFinding(SqliteDataReader reader, IReadOnlyDictionary<string, int> versions)
    {
        var ruleId = reader.GetString(reader.GetOrdinal("rule_id"));

        // Which table answered decides the kind. Checked before anything is read out of any of
        // them, because a finding whose evidence row is missing everywhere has lost what it rests
        // on - and presenting it anyway would show an operator a conclusion with nothing behind it.
        var delegationUac = reader.GetOrdinal("d_user_account_control");
        var markerSid = reader.GetOrdinal("a_sid");
        var preauthUac = reader.GetOrdinal("p_user_account_control");
        var sidHistory = reader.GetOrdinal("h_finding_id");
        var kerberoastable = reader.GetOrdinal("k_finding_id");

        // Discriminated on capability_kind, which is never null on a row that exists. Both
        // timestamp columns are legitimately null - that pair of absences is exactly what a SEC-091
        // finding says - so either of them as the discriminator would drop every SEC-091 finding
        // into the "no evidence" branch below and throw on a finding that is intact.
        var lapsCapability = reader.GetOrdinal("l_capability_kind");

        // trustee_sid, because it is NOT NULL on any row that exists. inherited_from and
        // trustee_name are both legitimately null - an entry set directly on the object has no
        // inherited scope, and a well-known or foreign-forest trustee has no name in this bundle -
        // so either would drop an intact finding into the "no evidence" branch. This is P-112.
        var lapsReaderTrustee = reader.GetOrdinal("r_trustee_sid");

        // configured_value, because it is NOT NULL on any row that exists. Both decryptor_sid and
        // broad_principal_sid are legitimately null - a decryptor this capture could not resolve is
        // exactly what one kind of SEC-093 finding says - so either as the discriminator would drop
        // an intact finding into the "no evidence" branch below and throw on it. This is P-112.
        var lapsDecryptorValue = reader.GetOrdinal("e_configured_value");

        // trustee_sid, because it is NOT NULL on any row that exists, for the same reason SEC-090's
        // discriminator is. inherited_from and trustee_name are both legitimately null. P-112.
        var takeoverTrustee = reader.GetOrdinal("t_trustee_sid");

        // owner_sid, because MS-ADTS 6.1.3 states a descriptor's owner SID cannot be null, and a
        // descriptor carrying none is refused rather than reported - so a row that exists has one.
        // owner_name is legitimately null for a well-known or foreign-forest owner. P-112.
        var ownershipOwner = reader.GetOrdinal("w_owner_sid");

        FindingEvidence evidence;

        if (!reader.IsDBNull(delegationUac))
        {
            evidence = new UnconstrainedDelegationEvidence(
                (uint)reader.GetInt64(delegationUac),
                reader.GetInt64(reader.GetOrdinal("d_is_computer")) != 0,
                new DomainControllerSignals(
                    reader.GetInt64(reader.GetOrdinal("d_server_trust_account_bit")) != 0,
                    reader.GetInt64(reader.GetOrdinal("d_primary_group_is_domain_controller")) != 0,
                    reader.GetInt64(reader.GetOrdinal("d_under_domain_controllers_ou")) != 0));
        }
        else if (!reader.IsDBNull(markerSid))
        {
            evidence = new AdminCountWithoutProtectionEvidence(reader.GetString(markerSid));
        }
        else if (!reader.IsDBNull(preauthUac))
        {
            evidence = new UserAccountControlEvidence((uint)reader.GetInt64(preauthUac));
        }
        else if (!reader.IsDBNull(sidHistory))
        {
            // The discriminator is the finding_id and not object_sid, because object_sid is
            // legitimately null - an account whose own identifier could not be read still carries
            // the history that was read. Keying off a nullable column would silently drop those
            // findings into the "no evidence" branch below and throw on a finding that is intact.
            var findingId = reader.GetInt64(sidHistory);
            var objectSidColumn = reader.GetOrdinal("h_object_sid");

            var values = SidHistoryValues.TryGetValue(findingId, out var stored) ? stored : [];

            evidence = new PrivilegedSidHistoryEvidence(
                reader.IsDBNull(objectSidColumn) ? null : reader.GetString(objectSidColumn),
                values,
                PrivilegedSidHistoryMatches(values),
                (int)reader.GetInt64(reader.GetOrdinal("h_unreadable_values")));
        }
        else if (!reader.IsDBNull(kerberoastable))
        {
            var findingId = reader.GetInt64(kerberoastable);

            evidence = new KerberoastableAccountEvidence(
                reader.GetString(reader.GetOrdinal("k_object_sid")),
                ServicePrincipalNames.TryGetValue(findingId, out var spns) ? spns : [],
                (uint)reader.GetInt64(reader.GetOrdinal("k_user_account_control")),
                (int)reader.GetInt64(reader.GetOrdinal("k_unreadable_service_names")))
            {
                ProtectionCatalogueVersion = reader.IsDBNull(reader.GetOrdinal("k_protection_catalogue_version"))
                    ? null : reader.GetInt32(reader.GetOrdinal("k_protection_catalogue_version")),
                DirectProtectionCatalogueEntryId = reader.IsDBNull(reader.GetOrdinal("k_direct_protection_entry_id"))
                    ? null : reader.GetInt32(reader.GetOrdinal("k_direct_protection_entry_id")),
                DirectProtectionName = reader.IsDBNull(reader.GetOrdinal("k_direct_protection_name"))
                    ? null : reader.GetString(reader.GetOrdinal("k_direct_protection_name")),
                MembershipRoutes = MembershipRoutes.TryGetValue(findingId.ToString(System.Globalization.CultureInfo.InvariantCulture), out var routes)
                    ? routes : throw new InvalidOperationException("A finding has no membership-route completeness record."),
            };
        }
        else if (!reader.IsDBNull(lapsCapability))
        {
            var modern = reader.GetOrdinal("l_windows_laps_expiration");
            var legacy = reader.GetOrdinal("l_legacy_laps_expiration");
            var name = reader.GetOrdinal("l_operating_system");
            var version = reader.GetOrdinal("l_operating_system_version");

            evidence = new LapsDeploymentEvidence(
                reader.IsDBNull(modern) ? null : reader.GetString(modern),
                reader.IsDBNull(legacy) ? null : reader.GetString(legacy),
                new LapsCapability(
                    Enum.Parse<LapsCapabilityKind>(reader.GetString(lapsCapability)),
                    Enum.Parse<LapsCapabilityBasis>(
                        reader.GetString(reader.GetOrdinal("l_capability_basis"))),
                    reader.IsDBNull(name) ? null : reader.GetString(name),
                    reader.IsDBNull(version) ? null : reader.GetString(version)));
        }
        else if (!reader.IsDBNull(lapsReaderTrustee))
        {
            var findingId = reader.GetInt64(reader.GetOrdinal("r_finding_id"));
            var trusteeName = reader.GetOrdinal("r_trustee_name");
            var inheritedFrom = reader.GetOrdinal("r_inherited_from");

            evidence = new LapsPasswordReaderEvidence(
                reader.GetString(lapsReaderTrustee),
                reader.IsDBNull(trusteeName) ? null : reader.GetString(trusteeName),
                reader.GetString(reader.GetOrdinal("r_broad_principal_sid")),
                reader.IsDBNull(reader.GetOrdinal("r_broad_principal_name"))
                    ? null
                    : reader.GetString(reader.GetOrdinal("r_broad_principal_name")),
                MembershipPaths.TryGetValue(findingId, out var path) ? path : [],
                reader.GetString(reader.GetOrdinal("r_attribute")),
                Enum.Parse<LapsReadRights>(reader.GetString(reader.GetOrdinal("r_rights"))),
                Enum.Parse<LapsGrantReach>(reader.GetString(reader.GetOrdinal("r_reach"))),
                reader.IsDBNull(inheritedFrom) ? null : reader.GetString(inheritedFrom),
                reader.GetInt64(reader.GetOrdinal("r_expansion_was_complete")) != 0);
        }
        else if (!reader.IsDBNull(takeoverTrustee))
        {
            var findingId = reader.GetInt64(reader.GetOrdinal("t_finding_id"));
            var trusteeName = reader.GetOrdinal("t_trustee_name");
            var broadName = reader.GetOrdinal("t_broad_principal_name");
            var inheritedFrom = reader.GetOrdinal("t_inherited_from");

            evidence = new ObjectTakeoverEvidence(
                reader.GetString(takeoverTrustee),
                reader.IsDBNull(trusteeName) ? null : reader.GetString(trusteeName),
                reader.GetString(reader.GetOrdinal("t_broad_principal_sid")),
                reader.IsDBNull(broadName) ? null : reader.GetString(broadName),
                TakeoverPaths.TryGetValue(findingId, out var takeoverPath) ? takeoverPath : [],
                Enum.Parse<ObjectTakeoverRight>(
                    reader.GetString(reader.GetOrdinal("t_takeover_right"))),
                reader.IsDBNull(inheritedFrom) ? null : reader.GetString(inheritedFrom),
                reader.GetInt64(reader.GetOrdinal("t_expansion_was_complete")) != 0);
        }
        else if (!reader.IsDBNull(ownershipOwner))
        {
            var ownerName = reader.GetOrdinal("w_owner_name");

            evidence = new ObjectOwnershipEvidence(
                reader.GetString(ownershipOwner),
                reader.IsDBNull(ownerName) ? null : reader.GetString(ownerName),
                Enum.Parse<ObjectOwnerStanding>(
                    reader.GetString(reader.GetOrdinal("w_standing"))),
                reader.GetString(reader.GetOrdinal("w_object_class")),
                reader.GetInt64(reader.GetOrdinal("w_membership_was_complete")) != 0);
        }
        else if (!reader.IsDBNull(lapsDecryptorValue))
        {
            var findingId = reader.GetInt64(reader.GetOrdinal("e_finding_id"));
            var policyName = reader.GetOrdinal("e_policy_display_name");
            var decryptorSid = reader.GetOrdinal("e_decryptor_sid");
            var decryptorName = reader.GetOrdinal("e_decryptor_name");
            var broadSid = reader.GetOrdinal("e_broad_principal_sid");
            var broadName = reader.GetOrdinal("e_broad_principal_name");

            evidence = new LapsDecryptorEvidence(
                reader.IsDBNull(policyName) ? null : reader.GetString(policyName),
                reader.GetString(lapsDecryptorValue),
                Enum.Parse<LapsDecryptorForm>(reader.GetString(reader.GetOrdinal("e_form"))),
                reader.IsDBNull(decryptorSid) ? null : reader.GetString(decryptorSid),
                reader.IsDBNull(decryptorName) ? null : reader.GetString(decryptorName),
                reader.IsDBNull(broadSid) ? null : reader.GetString(broadSid),
                reader.IsDBNull(broadName) ? null : reader.GetString(broadName),
                DecryptorPaths.TryGetValue(findingId, out var route) ? route : [],
                reader.GetInt64(reader.GetOrdinal("e_expansion_was_complete")) != 0);
        }
        else
        {
            throw new InvalidOperationException(
                $"Finding {reader.GetInt64(reader.GetOrdinal("finding_id"))} ({ruleId}) is stored "
                + "with no evidence row, so what it rests on has been lost. A finding that cannot "
                + "say what it rests on must not be presented as one.");
        }
        return new Finding(
            ruleId,
            versions[ruleId],
            Enum.Parse<Severity>(reader.GetString(reader.GetOrdinal("severity"))),
            new FindingSubject(
                Enum.Parse<FindingSubjectKind>(reader.GetString(reader.GetOrdinal("subject_kind"))),
                reader.GetString(reader.GetOrdinal("subject_key"))),
            Guid.Parse(reader.GetString(reader.GetOrdinal("object_guid"))),
            reader.GetString(reader.GetOrdinal("distinguished_name")),
            reader.GetString(reader.GetOrdinal("domain_fqdn")),
            reader.GetString(reader.GetOrdinal("object_class")),
            reader.GetString(reader.GetOrdinal("detail")),
            Enum.Parse<EvidenceCompleteness>(reader.GetString(reader.GetOrdinal("coverage"))),
            evidence);
    }

    /// <summary>
    /// Every stored SID history value, by the finding it belongs to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read once for the store rather than once per finding.</b> SEC-027 is the first evidence
    /// kind with more than one row per finding, and joining it into the finding query would
    /// multiply every finding by its number of history values - so a single account with four of
    /// them would appear four times in the grid. A page of fifty findings must also not become
    /// fifty-one queries.
    /// </para>
    /// <para>
    /// <b>Ordinal is what preserves the order the directory gave.</b> Without the sort this comes
    /// back in whatever order the table yields, and evidence that reorders itself between two reads
    /// of one store is evidence a reader cannot compare.
    /// </para>
    /// </remarks>
    private Dictionary<long, List<string>> SidHistoryValues =>
        _sidHistoryValues ??= ReadChildValues("SELECT finding_id, sid FROM finding_privileged_sid_history_value ORDER BY finding_id, ordinal");

    private Dictionary<long, List<string>>? _sidHistoryValues;

    /// <summary>
    /// Every stored service name, by the finding it belongs to.
    /// </summary>
    /// <remarks>
    /// Read once for the store and sorted by ordinal, for the reasons
    /// <see cref="SidHistoryValues"/> gives: joining a child table into the finding query would
    /// multiply a finding by its number of service names, so one account with four of them would
    /// appear four times in the grid.
    /// </remarks>
    private Dictionary<long, List<string>> ServicePrincipalNames =>
        _servicePrincipalNames ??= ReadChildValues(
            "SELECT finding_id, service_principal_name FROM finding_kerberoastable_account_spn "
            + "ORDER BY finding_id, ordinal");

    private Dictionary<long, List<string>>? _servicePrincipalNames;

    private Dictionary<string, MembershipRouteSummary> MembershipRoutes =>
        _membershipRoutes ??= MembershipRouteStorage.Read(_connection, subjectId: null);

    private Dictionary<string, MembershipRouteSummary>? _membershipRoutes;

    /// <summary>
    /// Every stored membership path, by the finding it belongs to, in path order.
    /// </summary>
    /// <remarks>
    /// Read once for the store and sorted by ordinal, for the reason the other child tables are: a
    /// join would multiply the finding by the length of its path, so a broad principal reached at
    /// depth six would appear six times in the grid.
    /// </remarks>
    private Dictionary<long, List<PathStep>> MembershipPaths =>
        _membershipPaths ??= ReadPathSteps(
            "SELECT finding_id, sid, name FROM finding_laps_password_reader_path "
            + "ORDER BY finding_id, ordinal");

    private Dictionary<long, List<PathStep>>? _membershipPaths;

    /// <summary>
    /// Every stored decryptor route, by the finding it belongs to, in path order.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="MembershipPaths"/> rather than unioned with it. The two tables
    /// answer different questions - who can read the attribute, and who can decrypt what it holds -
    /// and a finding identifier is only unique within one of them.
    /// </remarks>
    private Dictionary<long, List<PathStep>> DecryptorPaths =>
        _decryptorPaths ??= ReadPathSteps(
            "SELECT finding_id, sid, name FROM finding_laps_decryptor_path "
            + "ORDER BY finding_id, ordinal");

    private Dictionary<long, List<PathStep>>? _decryptorPaths;

    /// <summary>
    /// Every stored takeover route, by the finding it belongs to, in path order.
    /// </summary>
    /// <remarks>
    /// Kept apart from the other two for the reason given above: a finding identifier is only
    /// unique within one table, so unioning them would attach one rule's path to another's finding.
    /// </remarks>
    private Dictionary<long, List<PathStep>> TakeoverPaths =>
        _takeoverPaths ??= ReadPathSteps(
            "SELECT finding_id, sid, name FROM finding_object_takeover_path "
            + "ORDER BY finding_id, ordinal");

    private Dictionary<long, List<PathStep>>? _takeoverPaths;

    private Dictionary<long, List<PathStep>> ReadPathSteps(string sql)
    {
        var values = new Dictionary<long, List<PathStep>>();

        using var command = _connection.CreateCommand();
        command.CommandText = sql;

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var findingId = reader.GetInt64(0);

            if (!values.TryGetValue(findingId, out var stored))
                values[findingId] = stored = [];

            stored.Add(new PathStep(
                reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2)));
        }

        return values;
    }

    private Dictionary<long, List<string>> ReadChildValues(string sql)
    {
        var values = new Dictionary<long, List<string>>();

        using var command = _connection.CreateCommand();
        command.CommandText = sql;

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var findingId = reader.GetInt64(0);

            if (!values.TryGetValue(findingId, out var stored))
                values[findingId] = stored = [];

            stored.Add(reader.GetString(1));
        }

        return values;
    }

    /// <summary>
    /// Which of a finding's stored SID history values name a privileged principal.
    /// </summary>
    /// <remarks>
    /// <b>Recomputed rather than stored, like the delegation table's two answers.</b> Whether a
    /// value is privileged, and what Microsoft calls it, are both asked of
    /// <see cref="PrivilegedSidHistory.PrivilegedName"/> - the same decision the rule made when it
    /// wrote the row. Storing either would create a copy that can disagree with the value it came
    /// from, and a second copy of the decision could disagree with the rule itself.
    /// </remarks>
    private static IReadOnlyList<PrivilegedSidHistoryMatch> PrivilegedSidHistoryMatches(
        IReadOnlyList<string> values) =>
    [
        .. values
            .Select(value => (Value: value, Name: PrivilegedSidCatalogue.PrivilegedName(value)))
            .Where(v => v.Name is not null)
            .Select(v => new PrivilegedSidHistoryMatch(
                v.Value,
                Sid.RelativeIdentifier(v.Value) ?? 0,
                v.Name!)),
    ];

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

    private static string? DerivationMismatch(string bundleDirectory, Guid? judgedGeneration)
    {
        if (judgedGeneration is null)
            return null;

        var current = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Derivation);
        if (!current.IsSuccess)
        {
            return $"The judgement in '{bundleDirectory}' consumed Derivation generation "
                + $"'{judgedGeneration:D}', and no complete current Derivation generation can be "
                + "resolved beside it.";
        }

        return current.Value!.GenerationId == judgedGeneration
            ? null
            : $"The judgement in '{bundleDirectory}' consumed Derivation generation "
                + $"'{judgedGeneration:D}', while the current Derivation generation is "
                + $"'{current.Value.GenerationId:D}'. Judge the bundle again from its current inputs.";
    }

    private static JudgementDescription? ReadDescription(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT schema_version, evidence_seal, judgement_generation_id, "
            + "derivation_generation_id, state, evaluation_as_of, judging_started_utc, "
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

        if (reader.IsDBNull(7))
            return null;

        return new JudgementDescription(
            reader.GetString(1),
            Guid.Parse(reader.GetString(2)),
            reader.IsDBNull(3) ? null : Guid.Parse(reader.GetString(3)),
            Enum.Parse<JudgementRunState>(reader.GetString(4)),
            DateTimeOffset.Parse(reader.GetString(5), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(6), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(7), System.Globalization.CultureInfo.InvariantCulture));
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

    /// <summary>
    /// How many findings each rule wrote, counted in the database.
    /// </summary>
    /// <remarks>
    /// <b>Counted rather than derived from a list of findings</b>, because the caller that wants
    /// this wants it instead of the findings, not as well: a real forest's judgement holds
    /// thousands of rows and this screen shows one line per rule.
    /// </remarks>
    private Dictionary<string, int> ReadFindingCountsByRule()
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT rule_id, COUNT(*) FROM finding GROUP BY rule_id";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            counts[reader.GetString(0)] = reader.GetInt32(1);

        return counts;
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
