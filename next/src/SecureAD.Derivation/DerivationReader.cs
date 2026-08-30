using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Derivation;

/// <summary>
/// What a derivation recorded about itself.
/// </summary>
/// <param name="SchemaVersion">The shape of the store, so a reader can refuse one it cannot read.</param>
/// <param name="EvidenceSeal">The capture these facts were derived from.</param>
/// <param name="GenerationId">Which derive run produced them.</param>
/// <param name="State">What became of that run.</param>
/// <param name="StartedUtc">When deriving started.</param>
/// <param name="CompletedUtc">When it finished.</param>
public sealed record DerivationDescription(
    int SchemaVersion,
    string EvidenceSeal,
    Guid GenerationId,
    DerivationRunState State,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc);

/// <summary>
/// One phase of a derivation, read back.
/// </summary>
/// <param name="Phase">The phase, as it named itself.</param>
/// <param name="Outcome">What became of it.</param>
/// <param name="Error">Why it failed, when it did.</param>
public sealed record StoredDerivationPhase(
    string Phase,
    DerivationPhaseOutcome Outcome,
    string? Error);

/// <summary>
/// How much a derivation holds.
/// </summary>
/// <remarks>
/// <b>Counts rather than the rows themselves.</b> A forest's nesting is millions of edges and
/// nothing yet has a use for them; what the window needs is to say what a derivation produced
/// instead of how far its pass read. Handing back the rows would be an API designed against no
/// caller, which is what the rule interface is still deferred for.
/// </remarks>
/// <param name="Principals">Principals the derivation knows about.</param>
/// <param name="Identities">SIDs resolving to a principal, current and historical alike.</param>
/// <param name="NestingEdges">Direct nesting relationships, each held once.</param>
public sealed record DerivationSize(long Principals, long Identities, long NestingEdges);

/// <summary>
/// Everything a derivation store holds about the run that wrote it.
/// </summary>
/// <remarks>
/// <b>One call, because the parts are only meaningful together</b> - the reason
/// <c>StoredJudgement</c> gives. A count of principals without the phase outcomes beside it lets a
/// caller report a degraded derivation as though it were whole, which is the failure this stage is
/// shaped around.
/// </remarks>
/// <param name="Description">What the run recorded about itself.</param>
/// <param name="Phases">Every phase, whatever became of it.</param>
/// <param name="Size">How much the store holds.</param>
/// <param name="Completeness">
/// What the derivation does not cover. Not nullable, and not omitted for a whole derivation: a
/// caller that had to check for its absence before trusting the size beside it would eventually
/// forget to, and the reading it would then give is the clean one.
/// </param>
public sealed record StoredDerivation(
    DerivationDescription Description,
    IReadOnlyList<StoredDerivationPhase> Phases,
    DerivationSize Size,
    DerivationCompleteness Completeness)
{
    /// <summary>Whether every phase that ran succeeded.</summary>
    /// <remarks>
    /// A phase that did not run is not a failure and is not counted as one - it had no input, which
    /// is a different sentence from having misbehaved.
    /// </remarks>
    public bool EveryPhaseThatRanSucceeded =>
        Phases.All(p => p.Outcome is DerivationPhaseOutcome.Succeeded or DerivationPhaseOutcome.DidNotRun);
}

/// <summary>
/// Reads a derivation store back, the way <c>BundleReader</c> reads evidence and
/// <c>JudgementReader</c> reads a judgement.
/// </summary>
/// <remarks>
/// <para>
/// <b>Refusing a store this build cannot read is its first job.</b> The SID dictionary gained a
/// scope at schema version 2, because a SID is unique within its scope and not within a forest. A
/// version 1 store keys principals by SID alone, so every domain's built-in groups are merged in it
/// - reading one as though it were current would hand back the fabricated cross-domain privilege
/// path that <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c> exists to prevent.
/// </para>
/// <para>
/// <b>It reads the header, the phases and the size, and no closures.</b> Nothing consumes a
/// membership closure yet; the rule interface that would is deliberately unbuilt until a rule needs
/// it. An API shaped now would be shaped against no caller, which is how the predecessor's
/// <c>GetPrecomputedClosure</c> came to have none.
/// </para>
/// </remarks>
public sealed class DerivationReader : IDisposable
{
    private readonly SqliteConnection _connection;
    private bool _disposed;

    private DerivationReader(
        string bundleDirectory, SqliteConnection connection, DerivationDescription description)
    {
        BundleDirectory = bundleDirectory;
        _connection = connection;
        Description = description;
    }

    /// <summary>The bundle this derivation was opened from.</summary>
    public string BundleDirectory { get; }

    /// <summary>What the derivation recorded about itself.</summary>
    public DerivationDescription Description { get; }

    /// <summary>
    /// Verifies the derivation's seal and, only if it is intact and this build understands the
    /// store, opens it for reading.
    /// </summary>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    /// <returns>The open reader, or an <see cref="AuditError"/> saying which check refused it.</returns>
    public static Result<DerivationReader> Open(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var resolved = AnalysisStoreLifecycle.Resolve(
            bundleDirectory,
            AnalysisStoreKind.Derivation);
        if (!resolved.IsSuccess)
            return Result<DerivationReader>.Failure(resolved.Error!);

        var generation = resolved.Value!;
        var verdict = BundleSealing.VerifyAnalysisGeneration(
            bundleDirectory,
            generation,
            "derived facts",
            "It does not prove every closure is complete, which is a claim the store makes in its own tables.");
        if (!verdict.MayBeOpened)
        {
            return Failure(
                "DerivationSealNotIntact",
                verdict.Detail,
                bundleDirectory);
        }

        var path = BundleLayout.AnalysisGenerationDataPath(
            bundleDirectory, generation.Kind, generation.GenerationId);
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
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
                    "DerivationUnreadable",
                    $"The derivation at '{path}' records no run. Its seal is intact, so this is a "
                    + "defect in the build that wrote it rather than damage to the file.",
                    path);
            }

            if (description.GenerationId != generation.GenerationId)
            {
                connection.Dispose();
                return Failure(
                    "DerivationGenerationMismatch",
                    $"The derivation manifest selects generation '{generation.GenerationId:D}', "
                    + $"but the database identifies itself as '{description.GenerationId:D}'. The "
                    + "database and manifest are not one generation and cannot be read together.",
                    path);
            }

            var evidenceMismatch = EvidenceMismatch(bundleDirectory, description.EvidenceSeal);
            if (evidenceMismatch is not null)
            {
                connection.Dispose();
                return Failure("DerivationIsNotForThisEvidence", evidenceMismatch, path);
            }

            if (description.SchemaVersion != DerivationSchema.Version)
            {
                connection.Dispose();
                return Failure(
                    "DerivationSchemaNotUnderstood",
                    $"The derivation at '{path}' is schema version {description.SchemaVersion} and "
                    + $"this build reads version {DerivationSchema.Version}. It is refused rather "
                    + "than read, because the versions differ in what a stored principal means: "
                    + "before version 2 a SID was keyed without its scope, so every domain's "
                    + "built-in groups were held as one principal and their memberships merged. "
                    + "Delete it and derive the bundle again - the evidence is untouched and "
                    + "nothing else rests on it.",
                    path);
            }

            var opened = new DerivationReader(bundleDirectory, connection, description);
            _ = opened.Read();
            return opened;
        }

        catch (Exception error) when (
            error is SqliteException
            or FormatException
            or ArgumentException
            or InvalidOperationException)
        {
            connection.Dispose();
            return Failure(
                "DerivationUnreadable",
                $"The seal on the derivation in '{bundleDirectory}' is intact and the store could "
                + $"not be read: {error.Message}. The bytes are the bytes that were sealed, so this "
                + "is a defect in this build rather than damage to the store.",
                path);
        }
    }

    private static string? EvidenceMismatch(string bundleDirectory, string derivedSeal)
    {
        var evidenceSealPath = BundleLayout.SealPath(bundleDirectory);
        var contents = BundleSealing.ReadSeal(evidenceSealPath);

        if (contents is null || string.IsNullOrWhiteSpace(contents.Hash))
        {
            return $"The derivation in '{bundleDirectory}' names the Evidence it was derived from "
                + $"and there is no readable Evidence seal at '{evidenceSealPath}' to check it "
                + "against. Derived facts are meaningful only beside their source capture.";
        }

        if (string.Equals(contents.Hash, derivedSeal, StringComparison.Ordinal))
            return null;

        return $"The derivation in '{bundleDirectory}' was made from Evidence sealed as "
            + $"{derivedSeal}, and the Evidence in that bundle is sealed as {contents.Hash}. "
            + "These derived facts belong to a different capture; derive this bundle again rather "
            + "than moving a derivation into it.";
    }

    /// <summary>
    /// Everything this derivation recorded about the run that wrote it.
    /// </summary>
    public StoredDerivation Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return new StoredDerivation(Description, ReadPhases(), ReadSize(), ReadCompleteness());
    }

    /// <summary>Closes the store.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _connection.Dispose();
        _disposed = true;
    }

    private static DerivationDescription? ReadDescription(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT schema_version, evidence_seal, derivation_generation_id, "
            + "deriving_started_utc, deriving_completed_utc, state FROM derivation";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
            return null;

        return new DerivationDescription(
            reader.GetInt32(0),
            reader.GetString(1),
            Guid.Parse(reader.GetString(2)),
            Enum.Parse<DerivationRunState>(reader.GetString(5)),
            DateTimeOffset.Parse(reader.GetString(3), CultureInfo.InvariantCulture),
            reader.IsDBNull(4)
                ? default
                : DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture));
    }

    private IReadOnlyList<StoredDerivationPhase> ReadPhases()
    {
        var phases = new List<StoredDerivationPhase>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT phase, outcome, error FROM derivation_phase ORDER BY phase";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            phases.Add(new StoredDerivationPhase(
                reader.GetString(0),
                Enum.Parse<DerivationPhaseOutcome>(reader.GetString(1)),
                reader.IsDBNull(2) ? null : reader.GetString(2)));
        }

        return phases;
    }

    private DerivationSize ReadSize()
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT (SELECT COUNT(*) FROM principal), "
            + "(SELECT COUNT(*) FROM sid_identity), "
            + "(SELECT COUNT(*) FROM nesting_edge)";

        using var reader = command.ExecuteReader();
        reader.Read();

        return new DerivationSize(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2));
    }

    /// <remarks>
    /// A store this build opened has a completeness row, because every writer that could produce
    /// schema 3 records one. A missing row is therefore not "the derivation was complete" but a
    /// store that is not what it claims to be, and it is refused rather than read as whole.
    /// </remarks>
    private DerivationCompleteness ReadCompleteness()
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT is_complete, expansion_limit, collapsed_stubs, unscoped_builtins "
            + "FROM derivation_completeness";

        using var reader = command.ExecuteReader();

        if (!reader.Read())
        {
            throw new InvalidOperationException(
                "This derivation records no completeness, though its schema version says it must. "
                + "The store is not what it claims to be, and reading it would report a derivation "
                + "of unknown coverage as a whole one.");
        }

        var isComplete = reader.GetInt32(0) != 0;
        var limit = Enum.Parse<ExpansionLimit>(reader.GetString(1));
        var collapsedStubs = reader.GetInt32(2);
        var unscopedBuiltins = reader.GetInt32(3);

        return new DerivationCompleteness(
            isComplete,
            ReadPartialGroups(),
            ReadMissingPartitions(),
            ReadUnresolvedTrustees(),
            // Taken from the header rather than a column of its own, because the run that wrote the
            // completeness is the run that wrote the store. Two copies would be two things that can
            // disagree about which derivation this is.
            Description.GenerationId,
            limit,
            collapsedStubs,
            unscopedBuiltins);
    }

    private IReadOnlyList<int> ReadPartialGroups()
    {
        var groups = new List<int>();

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT sid_id FROM completeness_partial_group ORDER BY sid_id";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            groups.Add(reader.GetInt32(0));

        return groups;
    }

    private IReadOnlyList<string> ReadUnresolvedTrustees()
    {
        var trustees = new List<string>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT distinguished_name FROM completeness_unresolved_trustee "
            + "ORDER BY distinguished_name";

        using var reader = command.ExecuteReader();

        while (reader.Read())
            trustees.Add(reader.GetString(0));

        return trustees;
    }

    private IReadOnlyList<DomainCoverage> ReadMissingPartitions()
    {
        var partitions = new List<DomainCoverage>();

        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT domain_fqdn, outcome, reason FROM completeness_missing_partition "
            + "ORDER BY domain_fqdn";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var domain = reader.GetString(0);
            var outcome = Enum.Parse<DomainReadOutcome>(reader.GetString(1));
            var reason = reader.GetString(2);

            // Rebuilt through the factories rather than by setting fields, so a stored row is held
            // to the same rules as one the capture made.
            partitions.Add(outcome switch
            {
                DomainReadOutcome.PartiallyRead => DomainCoverage.PartiallyRead(domain, reason),
                DomainReadOutcome.NotRead => DomainCoverage.NotRead(domain, reason),
                DomainReadOutcome.ExcludedByChoice =>
                    DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, reason),
                DomainReadOutcome.ExcludedForWantOfCandidates =>
                    DomainCoverage.Excluded(domain, ExclusionKind.ForWantOfCandidates, reason),

                // Read included: a domain that was read in full is not a missing partition, so its
                // presence here means the table holds something no writer could have put there.
                _ => throw new InvalidOperationException(
                    $"This derivation lists '{domain}' as a partition it did not read, with the "
                    + $"outcome '{outcome}', which is not a way of not reading one."),
            });
        }

        return partitions;
    }

    private static Result<DerivationReader> Failure(
        string reason, string description, string context) =>
        Result<DerivationReader>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));
}
