using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// Judging a sealed bundle: read every object once, offer it to every rule, and write what they
/// concluded beside the evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>One pass over the bundle, not one per rule.</b> The evidence is read sequentially and each
/// object is offered to every scheduled rule while it is in hand. Judging forty rules therefore
/// costs the same read as judging one, and adding a rule costs comparisons rather than another walk
/// of the forest.
/// </para>
/// <para>
/// <b>A rule that throws loses only itself.</b> It is recorded as
/// <see cref="RuleExecutionOutcome.Error"/>, offered no further objects, and the rules beside it
/// carry on. Its findings are discarded, because a rule that failed part way through has no verdict
/// and its partial output would read as a complete one.
/// </para>
/// <para>
/// <b>Nothing here decides what a run means.</b> The outcome of each rule follows from what it did,
/// and the state of the run follows from those outcomes, in
/// <see cref="JudgementWriter.Complete"/>. A coordinator that could name the state would be able to
/// call a judging complete while a rule had read nothing.
/// </para>
/// <para>
/// <b>Judging is measured in hours, not seconds, and is built for that.</b> The predecessor took
/// four to five hours over the owner's production forest. So this reports progress as it goes and
/// stops when asked, and a caller that offers neither is asking an operator to watch a still screen
/// for an afternoon with no way out.
/// </para>
/// </remarks>
public static class JudgingRun
{
    /// <summary>
    /// How far a judging has got.
    /// </summary>
    /// <remarks>
    /// <b>Objects rather than a percentage.</b> Nothing counts a bundle's objects before streaming
    /// it, so a percentage would need a count this does not have, and one wrong by a little would
    /// stall at 99 or pass 100 in front of an operator watching for hours.
    /// </remarks>
    /// <param name="ObjectsRead">How many objects have been offered to the rules so far.</param>
    public readonly record struct JudgingProgress(long ObjectsRead);

    /// <summary>
    /// Judges the bundle in <paramref name="bundleDirectory"/> and writes the judgement beside it.
    /// </summary>
    /// <remarks>
    /// Replaces any judgement already there, and only at the end: a judging that fails part way
    /// leaves the previous answer intact rather than replacing it with a partial one.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle to judge.</param>
    /// <param name="rules">The rules to run. Each is recorded whatever becomes of it.</param>
    /// <param name="startedUtc">When judging started.</param>
    /// <param name="evaluationAsOf">
    /// The reference time temporal rules are evaluated against, recorded so that the same sealed
    /// evidence gives the same answer next year.
    /// </param>
    /// <param name="progress">
    /// Told how many objects have been read. Pass <see cref="NobodyIsWatching"/> where there is no
    /// operator to tell - required rather than defaulted, because gate 1 records that progress,
    /// cancellation and the performance log all became quietly unused in the predecessor by being
    /// optional. Reported every <see cref="ProgressEvery"/> objects rather than every object,
    /// because a run of millions would otherwise spend its time raising events.
    /// </param>
    /// <param name="cancellationToken">Stops the judging. See the remarks on what that leaves.</param>
    /// <returns>What became of the run, or why it could not be judged at all.</returns>
    /// <exception cref="OperationCanceledException">
    /// The judging was cancelled. <b>The earlier judgement is left intact</b>: the partial file is
    /// never renamed over it, so a cancelled re-judging costs the operator nothing but the time it
    /// ran for. That is the same guarantee a crash gets, by the same mechanism.
    /// </exception>
    public static Result<JudgementRunState> Judge(
        string bundleDirectory,
        IReadOnlyList<IRule> rules,
        DateTimeOffset startedUtc,
        DateTimeOffset evaluationAsOf,
        IProgress<JudgingProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(log);

        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(bundleDirectory));

        if (seal is null || string.IsNullOrWhiteSpace(seal.Hash))
        {
            var refusal = Failure(
                "EvidenceSealUnreadable",
                $"There is no readable evidence seal in '{bundleDirectory}', so a judgement written "
                + "here could not say which capture it was made against. A judgement that cannot "
                + "name its evidence is not one this product will write.",
                bundleDirectory);

            log.Record(JudgePhase, refusal.Error!, []);
            return refusal;
        }

        var opened = BundleReader.Open(bundleDirectory);
        if (!opened.IsSuccess)
        {
            log.Record(JudgePhase, opened.Error!, []);
            return Result<JudgementRunState>.Failure(opened.Error!);
        }

        using var bundle = opened.Value!;

        var scope = bundle.ReadScope();
        if (!scope.IsSuccess)
        {
            log.Record(JudgePhase, scope.Error!, []);
            return Result<JudgementRunState>.Failure(scope.Error!);
        }

        // What the scheduled rules say they read beyond the captured object. Gathered before any
        // object is offered, because the answer decides whether this judging can run at all.
        var wanted = rules
            .SelectMany(r => r.Definition.RequiredDerivedFacts)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        DerivationReader? derivation = null;

        // The reference time reaches the rules from the same value that is written to
        // evaluation_as_of, so a rule's answer and the record of what it was answering against
        // cannot drift apart. A rule reading the clock instead would give a different answer every
        // time this sealed evidence was re-judged, and nothing in the bundle would say why.
        JudgingContext context = JudgingContext.At(evaluationAsOf);
        Guid? derivationGeneration = null;

        if (wanted.Count > 0)
        {
            // Opened rather than merely checked for. DerivationReader.Open is what enforces the
            // binding - it refuses a store whose generation does not match the manifest, and one
            // whose evidence seal is not this bundle's - so asking it to open is a stronger question
            // than asking whether a file is present. A derivation belonging to different evidence
            // would produce confidently wrong findings, which docs/decisions/0091 names as the one
            // thing this product must not do.
            var openedDerivation = DerivationReader.Open(bundleDirectory);

            if (!openedDerivation.IsSuccess)
            {
                var refusal = Failure(
                    "DerivationUnavailable",
                    $"{string.Join(", ", wanted)} was declared by a scheduled rule, and this bundle's "
                    + $"derivation could not be opened: {openedDerivation.Error!.Description} A rule "
                    + "that reads derived facts is not run against evidence alone, because silence "
                    + "from it would read as nothing found. Derive this bundle and judge it again.",
                    bundleDirectory);

                log.Record(JudgePhase, refusal.Error!, []);
                return refusal;
            }

            derivation = openedDerivation.Value!;
            var stored = derivation.Read();
            derivationGeneration = stored.Description.GenerationId;

            var product = stored.ProtectedPrincipals;

            if (wanted.Contains(
                    nameof(DerivedFactKind.ProtectedPrincipals), StringComparer.OrdinalIgnoreCase)
                && product.Availability != ProtectedPrincipalProductAvailability.Available)
            {
                derivation.Dispose();

                var refusal = Failure(
                    "DerivedFactsAbsent",
                    $"A scheduled rule reads {DerivedFactKind.ProtectedPrincipals}, and this "
                    + $"bundle's derivation does not carry it ({product.Availability}). The phase "
                    + "not having run is not the same as nothing being protected, so this judging "
                    + "stops rather than reporting an answer it does not have.",
                    bundleDirectory);

                log.Record(JudgePhase, refusal.Error!, []);
                return refusal;
            }

            context = context with
            {
                ProtectedPrincipals = product.Value,
                Permissions = bundle.ReadPermissions,

                // Not a derived fact and so not gated by a declaration: every bundle carries the
                // schema rows, and a rule reading an object-specific access control entry cannot
                // tell which attribute the entry names without them.
                SchemaGuids = bundle.ReadSchemaGuids(),

                // Memoised for the same reason the expansion is: one delegated group appears on
                // every computer under an organisational unit, so its name would otherwise be
                // looked up once per machine to say the same thing.
                PrincipalNames = Memoised(bundle.PrincipalNameFor),

                // Not a derived fact either: a policy's settings are captured from its own SYSVOL
                // files and sit in the bundle. Unmemoised, because a policy is judged once and its
                // settings are not asked for a second time.
                GpoMachineRegistrySettings = bundle.ReadGpoMachineRegistrySettings,

                // Read once for the whole forest, not per object. Whether an owner keeps the right
                // to rewrite an object's permissions turns partly on this, so a rule that could not
                // read it must refuse rather than assume the permissive default.
                OwnerImplicitRights = DirectoryHeuristics.OwnerImplicitRights(
                    bundle.ReadForestHeuristics()),
            };

            // The same refusal for the same reason, and the consequence of skipping it is worse
            // here than for the protected principals. A rule that reads a LAPS timestamp treats an
            // absent value as a fact about a machine; without this answer it cannot know the forest
            // was not withholding the attribute, and SEC-094 would report every modern-capable
            // machine in the estate.
            if (wanted.Contains(
                nameof(DerivedFactKind.AttributeVisibility), StringComparer.OrdinalIgnoreCase))
            {
                var visibility = stored.AttributeVisibility;

                if (visibility.Availability != AttributeVisibilityAvailability.Available)
                {
                    derivation.Dispose();

                    var refusal = Failure(
                        "DerivedFactsAbsent",
                        $"A scheduled rule reads {DerivedFactKind.AttributeVisibility}, and this "
                        + $"bundle's derivation does not carry it ({visibility.Availability}). "
                        + "Whether this forest withholds an attribute is what separates a machine "
                        + "that is unmanaged from one this run was not allowed to see, so this "
                        + "judging stops rather than reporting an answer it does not have.",
                        bundleDirectory);

                    log.Record(JudgePhase, refusal.Error!, []);
                    return refusal;
                }

                context = context with { AttributeVisibility = visibility.Value };
            }

            // The expansion is a lookup rather than a product, so what is checked here is that the
            // nesting it walks was derived at all. A rule handed a walk over an empty edge table
            // would find nothing inside every group it asked about and report a scoped delegation
            // as safe - which is worse than silence, and is why this refuses instead.
            if (wanted.Contains(
                nameof(DerivedFactKind.PrincipalExpansion), StringComparer.OrdinalIgnoreCase))
            {
                if (!derivation.NestingWasDerived())
                {
                    derivation.Dispose();

                    var refusal = Failure(
                        "DerivedFactsAbsent",
                        $"A scheduled rule reads {DerivedFactKind.PrincipalExpansion}, and this "
                        + "bundle's derivation carries no group nesting to walk. Expanding a group "
                        + "over nothing finds nothing inside it, so every delegation would look "
                        + "scoped and every broad principal would go unreported. This judging "
                        + "stops rather than reporting an answer it does not have.",
                        bundleDirectory);

                    log.Record(JudgePhase, refusal.Error!, []);
                    return refusal;
                }

                // Captured by reference to the open reader, the same way permissions are read off
                // the open bundle. Both live as long as the loop below, and no longer.
                var reader = derivation;

                // MEMOISED FOR THE RUN, because the same principal is asked about once per object.
                // Every computer under one organisational unit inherits the same delegation, so a
                // rule expanding the delegated group repeats an identical walk for each of them - a
                // hundred thousand machines is a hundred thousand identical answers. The walk is
                // over persisted edges and the derivation does not change while a judging runs, so
                // the second answer cannot differ from the first.
                //
                // Invisible on a small forest, which is why nothing surfaced it: the lab has
                // fourteen computers.
                var expansions = new Dictionary<(string Sid, string Scope), PrincipalExpansion>();

                context = context with
                {
                    MembersOfPrincipal = (sid, scope) =>
                    {
                        var key = (sid, scope);

                        if (expansions.TryGetValue(key, out var known))
                            return known;

                        var walked = reader.MembersOf(sid, scope);
                        expansions[key] = walked;
                        return walked;
                    },
                };
            }
        }

        using var _ = derivation;

        using var writer = JudgementWriter.Create(
            bundleDirectory,
            seal.Hash,
            derivationGeneration,
            startedUtc,
            evaluationAsOf);
        writer.RecordEvidenceScope(scope.Value!);

        log.Note(
            JudgePhase,
            "started",
            [new RunLogDetail("rules", rules.Count.ToString(CultureInfo.InvariantCulture))]);

        var tallies = rules.Select(r => new Tally(r)).ToList();

        long objectsRead = 0;

        foreach (var subject in bundle.StreamObjects().Objects)
        {
            // Checked per object rather than per batch. A rule catalogue that has grown expensive
            // could spend a long time on one object, and a cancel that waits for the batch boundary
            // is a cancel the operator has to press twice to believe.
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var tally in tallies)
                tally.Offer(subject, context);

            objectsRead++;

            if (objectsRead % ProgressEvery == 0)
                progress.Report(new JudgingProgress(objectsRead));
        }

        // The last report is unconditional, so a run that ends between two reports does not leave
        // the operator looking at a count short of what was actually read.
        progress.Report(new JudgingProgress(objectsRead));

        foreach (var tally in tallies)
            writer.Write(tally.ToExecution());

        writer.Complete(DateTimeOffset.UtcNow);

        var state = scope.Value!.AllDeclaredDomainsAreComplete
            && tallies.All(t => t.Outcome == RuleExecutionOutcome.Succeeded)
            ? JudgementRunState.Completed
            : JudgementRunState.CompletedDegraded;

        // A rule that could not reach a verdict is named rather than counted. Which rule stopped is
        // the question an operator asks next, and a tally of failures does not answer it.
        foreach (var unfinished in tallies.Where(t => t.Outcome != RuleExecutionOutcome.Succeeded))
        {
            log.Note(
                JudgePhase,
                "a rule did not reach a verdict on every object",
                [
                    new RunLogDetail("rule", unfinished.RuleId),
                    new RunLogDetail("outcome", unfinished.Outcome.ToString()),
                ]);
        }

        log.Note(
            JudgePhase,
            "finished",
            [
                new RunLogDetail("state", state.ToString()),
                new RunLogDetail("objects", objectsRead.ToString(CultureInfo.InvariantCulture)),
            ]);

        return state;
    }

    /// <summary>The name the judging coordinator logs under.</summary>
    private const string JudgePhase = "Judge";

    /// <summary>
    /// Progress for a judging nobody is watching.
    /// </summary>
    /// <remarks>
    /// <b>Named rather than defaulted.</b> A caller that passes this has said it has no operator to
    /// tell; a caller that passed nothing would only have said it did not think about it, and gate
    /// 1 exists because that is how the predecessor's progress reporting went unused.
    /// </remarks>
    public static IProgress<JudgingProgress> NobodyIsWatching { get; } = new Unwatched();

    /// <summary>Discards what it is told.</summary>
    private sealed class Unwatched : IProgress<JudgingProgress>
    {
        public void Report(JudgingProgress value)
        {
            // Nobody is watching, by the caller's own statement.
        }
    }

    /// <summary>
    /// How many objects pass between progress reports.
    /// </summary>
    /// <remarks>
    /// Chosen so that a forest large enough to take hours still reports often enough to look alive,
    /// without a run of millions spending its time raising events. It is not tuned against a real
    /// forest, because no measurement of one exists yet.
    /// </remarks>
    private const int ProgressEvery = 1_000;

    /// <summary>
    /// Wraps a lookup so it is asked once per distinct argument for the life of a judging.
    /// </summary>
    /// <remarks>
    /// <b>Safe because nothing being read changes while a judging runs.</b> The evidence is sealed
    /// and the derivation is already written, so a second answer could only ever repeat the first.
    /// What it saves is real: a rule asks about the same delegated group once per object, and an
    /// organisational unit holding a hundred thousand computers means a hundred thousand identical
    /// questions.
    /// </remarks>
    private static Func<string, string?> Memoised(Func<string, string?> lookup)
    {
        var known = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        return argument =>
        {
            if (known.TryGetValue(argument, out var answer))
                return answer;

            answer = lookup(argument);
            known[argument] = answer;
            return answer;
        };
    }

    private static Result<JudgementRunState> Failure(
        string reason, string description, string context) =>
        Result<JudgementRunState>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));

    /// <summary>
    /// What one rule has made of the objects offered to it so far.
    /// </summary>
    /// <remarks>
    /// <b>Counted as it goes rather than derived at the end.</b> The objects are streamed and gone,
    /// so anything not counted while an object is in hand cannot be recovered without reading the
    /// bundle again.
    /// </remarks>
    private sealed class Tally(IRule rule)
    {
        private readonly List<Finding> _findings = [];
        private readonly Dictionary<string, int> _missing = new(StringComparer.OrdinalIgnoreCase);

        private int _judged;
        private int _notApplicable;
        private int _notJudged;
        private string? _error;

        public RuleExecutionOutcome Outcome =>
            _error is not null ? RuleExecutionOutcome.Error
            : _notJudged > 0 ? RuleExecutionOutcome.Indeterminate
            : RuleExecutionOutcome.Succeeded;

        /// <summary>Which rule this is tallying, so a log line can name it.</summary>
        public string RuleId => rule.Definition.Id;

        /// <summary>
        /// Offers one object to the rule, unless it has already thrown or the rule is not about
        /// objects of this kind.
        /// </summary>
        /// <remarks>
        /// <b>An object the rule is not about is counted apart and never offered.</b> It is not a
        /// gap in the evidence, and treating it as one told an operator that three objects in four
        /// of a real forest were unreadable.
        /// </remarks>
        /// <param name="subject">The object to judge.</param>
        /// <param name="context">
        /// The reference time, and the derived facts - which are empty for an Evidence-only
        /// judging.
        /// </param>
        public void Offer(ObjectAttributes subject, JudgingContext context)
        {
            if (_error is not null)
                return;

            if (!rule.Definition.IsAbout(subject))
            {
                _notApplicable++;
                return;
            }

            RuleVerdict verdict;

            try
            {
                verdict = rule.Judge(subject, context);
            }
            catch (Exception error) when (error is not OutOfMemoryException
                                              and not StackOverflowException)
            {
                // A rule is code, and code has defects. One that throws is a fact about this
                // product rather than about the forest, and it must not take the rules beside it
                // down - so it is recorded, its partial findings are dropped, and it is offered
                // nothing further.
                _error = error.ToString();
                _findings.Clear();
                _judged = 0;
                _notApplicable = 0;
                _notJudged = 0;
                _missing.Clear();
                return;
            }

            if (verdict.IsComplete)
            {
                _judged++;
                _findings.AddRange(verdict.Findings);
                return;
            }

            _notJudged++;

            foreach (var attribute in verdict.InputsNotCaptured)
                _missing[attribute] = _missing.GetValueOrDefault(attribute) + 1;

            // Counted in the same table as a missing attribute, under a token that names the kind
            // and the reason. The store already groups these by name, and a second table would let
            // one report a judging as complete while the other disagreed.
            foreach (var unresolved in verdict.Unresolved)
                _missing[unresolved.Token] = _missing.GetValueOrDefault(unresolved.Token) + 1;
        }

        public RuleExecution ToExecution() =>
            _error is not null
                ? RuleExecution.Threw(rule.Definition, _error)
                : new RuleExecution(
                    rule.Definition,
                    Outcome,
                    _judged,
                    _notApplicable,
                    _notJudged,
                    [.. _missing
                        .OrderBy(m => m.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(m => new MissingInput(m.Key, m.Value))],
                    _findings,
                    null);
    }
}
