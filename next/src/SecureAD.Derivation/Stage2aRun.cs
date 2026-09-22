using System.Diagnostics;
using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Derivation;

/// <summary>
/// How far a derivation has got, for an operator watching one.
/// </summary>
/// <param name="Phase">The phase that has just started.</param>
/// <param name="ObjectsRead">How many objects the pass over the bundle has read.</param>
public sealed record DerivationProgress(string Phase, long ObjectsRead);

/// <summary>
/// Runs stage 2a over one sealed bundle: reads the nesting, derives the three products, and writes
/// them beside the evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>Each phase is isolated, and the isolation is not uniform, because the phases are not
/// independent.</b> A phase that throws is recorded by name and the run carries on, so the facts
/// the others derived are still written. But a phase whose input never arrived cannot be run at
/// all, and saying it failed would blame it for something upstream - so it is recorded as
/// <see cref="DerivationPhaseOutcome.DidNotRun"/>, which is a different sentence.
/// </para>
/// <para>
/// <b>The dependencies are real and shape what survives what.</b> Everything rests on the pass over
/// the bundle, so if it fails nothing else can run. The protected-principal derivation needs only
/// the graph, so it survives a failed expansion. The latent-privilege derivation needs the
/// expansion's answer as well, because what it reports is who is inside a distribution group.
/// </para>
/// <para>
/// <b>A failed phase does not abandon the store.</b> Abandoning is for a coordinator that could not
/// do its job; a phase throwing is the thing this design expects and absorbs. The derivation
/// completes, carrying <see cref="DerivationRunState.CompletedDegraded"/>, because a store that
/// says what went wrong is worth more than no store at all - and unlike a judgement, deriving is
/// expensive enough that discarding three good phases over one bad one would be paid for again on
/// the next attempt.
/// </para>
/// </remarks>
public static class Stage2aRun
{
    private const int ProgressEvery = 1_000;

    /// <summary>
    /// Derives one bundle.
    /// </summary>
    /// <param name="bundleDirectory">The bundle to derive from.</param>
    /// <param name="budget">The limits the expansion runs under.</param>
    /// <param name="startedUtc">When deriving started.</param>
    /// <param name="progress">
    /// Where to report progress. Named rather than defaulted: a caller passing
    /// <see cref="Unwatched"/> has said it has no operator to tell.
    /// </param>
    /// <param name="log">
    /// Where the run says what it did. Required rather than defaulted, per gate 1 and
    /// <c>docs/decisions/0088-a-run-writes-a-log.md</c> - this stage is the one whose first real
    /// failure reached an operator as a bare SQLite message with no phase and no subject.
    /// </param>
    /// <param name="cancellationToken">Stops the derivation.</param>
    /// <returns>What became of the run, or why it could not start.</returns>
    public static Result<DerivationRunState> Derive(
        string bundleDirectory,
        ExpansionBudget budget,
        DateTimeOffset startedUtc,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken)
    {
        var clock = new PhaseClock();
        var began = Stopwatch.GetTimestamp();

        var derived = DeriveIntoStore(
            bundleDirectory, budget, startedUtc, progress, log, clock, cancellationToken);

        // ONLY ONCE THE STORE IS CLOSED. The section is read back out of the derivation, and the
        // writer inside DeriveIntoStore holds it open until that method returns - which is the
        // whole reason this wrapper exists rather than a few lines at the end of the body.
        if (derived.IsSuccess)
            AppendPortableSummary(bundleDirectory, Stopwatch.GetElapsedTime(began), clock.Phases);

        return derived;
    }

    /// <summary>
    /// Appends what this derivation did to the run's portable summary.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Counts and states are read back; only the durations come from the run.</b> That is the
    /// owner's decision of 2026-09-22, and here it also means the summary reports what a later
    /// reader of this store will see rather than what the pass believed it had written.
    /// </para>
    /// <para>
    /// <b>Appended, because a capture-only run is derived later and possibly elsewhere.</b> A
    /// bundle derived twice gets two derivation sections, which is what the run log does and is the
    /// honest record.
    /// </para>
    /// <para>
    /// <b>A summary that cannot be written never stops anything</b>, which is why nothing here
    /// examines a result. Losing the account of a derivation is not a reason to lose it.
    /// </para>
    /// </remarks>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="elapsed">How long deriving took.</param>
    /// <param name="phases">Where that time went.</param>
    private static void AppendPortableSummary(
        string bundleDirectory, TimeSpan elapsed, IReadOnlyList<StageTiming> phases)
    {
        var opened = DerivationReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return;

        using var reader = opened.Value!;
        var stored = reader.Read();

        PortableSummaryFile.AppendDerivation(
            bundleDirectory,
            PortableSummaryReading.OfDerivation(
                stored.Description.State.ToString(),
                (long)elapsed.TotalMilliseconds,
                stored.Size.Principals,
                stored.Size.NestingEdges,
                phases,
                Problems(stored)));
    }

    /// <summary>
    /// Turns the phases that did not simply succeed into the shape the summary may carry them in.
    /// </summary>
    /// <remarks>
    /// <b>The stored error text is deliberately not read.</b> A phase records the message it threw,
    /// which quotes whatever it was working on; the phase's own name and the outcome are what a
    /// reader outside that environment can act on, and <see cref="AuditError.Create"/> builds the
    /// code from them so it cannot be a freeform string.
    /// </remarks>
    /// <param name="stored">The derivation, read back.</param>
    /// <returns>One error per phase that failed or was degraded.</returns>
    private static IEnumerable<AuditError> Problems(StoredDerivation stored) =>
        stored.Phases
            .Where(phase => phase.Outcome
                is DerivationPhaseOutcome.Failed or DerivationPhaseOutcome.Degraded)
            .Select(phase => AuditError.Create(
                ErrorCategory.Evidence,
                phase.Outcome == DerivationPhaseOutcome.Failed
                    ? "DerivationPhaseFailed"
                    : "DerivationPhaseDegraded",
                phase.Outcome == DerivationPhaseOutcome.Failed
                    ? ErrorSeverity.Failed
                    : ErrorSeverity.Degraded,
                $"The {phase.Phase} phase did not complete cleanly.",
                phase.Phase));

    /// <summary>
    /// Where a derivation's time went, gathered as each phase finishes.
    /// </summary>
    /// <remarks>
    /// <b>Accumulated rather than read back, because nothing records it.</b> The store says what
    /// each phase produced and what became of it; how long each took is known only while it is
    /// running, and a derivation of a large forest is where an operator most wants to know which
    /// phase the time belonged to.
    /// </remarks>
    private sealed class PhaseClock
    {
        private readonly List<StageTiming> _phases = [];

        /// <summary>Each phase and how long it took, in the order they ran.</summary>
        public IReadOnlyList<StageTiming> Phases => _phases;

        /// <summary>Records a phase that has just finished, however it finished.</summary>
        /// <param name="phase">The phase, as it names itself.</param>
        /// <param name="startedTimestamp">What <see cref="Stopwatch.GetTimestamp"/> read when it started.</param>
        public void Record(string phase, long startedTimestamp) =>
            _phases.Add(new StageTiming(
                phase, (long)Stopwatch.GetElapsedTime(startedTimestamp).TotalMilliseconds));
    }

    private static Result<DerivationRunState> DeriveIntoStore(
        string bundleDirectory,
        ExpansionBudget budget,
        DateTimeOffset startedUtc,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        PhaseClock clock,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(log);

        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(bundleDirectory));

        if (seal is null || string.IsNullOrWhiteSpace(seal.Hash))
        {
            var refusal = Failure(
                "EvidenceSealUnreadable",
                $"There is no readable evidence seal in '{bundleDirectory}', so derived facts "
                + "written here could not say which capture they came from. A closure that cannot "
                + "name its evidence is consulted silently by every rule resting on it, which "
                + "makes naming it the whole of its trustworthiness.",
                bundleDirectory);

            log.Record(DerivePhase, refusal.Error!, []);
            return refusal;
        }

        var opened = BundleReader.Open(bundleDirectory);
        if (!opened.IsSuccess)
            return Result<DerivationRunState>.Failure(opened.Error!);

        using var bundle = opened.Value!;

        var scope = bundle.ReadScope();
        if (!scope.IsSuccess)
            return Result<DerivationRunState>.Failure(scope.Error!);

        using var writer = DerivationWriter.Create(bundleDirectory, seal.Hash, startedUtc);

        // Run first, and independently of everything below it. It reads the schema partition out of
        // the seal and needs no graph, no closure and no budget, so a nesting pass that produces
        // nothing must not take it down with it - a rule asking whether an attribute is withheld
        // has the same question whatever became of the membership.
        RunAttributeVisibility(bundle, writer, progress, log, clock);

        var facts = ReadNesting(bundle, writer, progress, log, clock, cancellationToken);

        if (facts is null)
        {
            // Nothing downstream has an input. Each is recorded by name so a reader can tell a
            // derivation that produced nothing from one that was never asked to.
            writer.RecordPhase(AuthorizationMembershipExpander.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);
            writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);
            writer.RecordPhase(LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);

            log.Note(
                DerivePhase,
                "the pass over the evidence produced nothing, so no closure was attempted",
                []);

            writer.WriteSids([], []);

            // Empty rather than absent, for the same reason the completeness row below is written:
            // a pass that produced nothing established no domain SIDs, and a reader must be able to
            // see that stated rather than infer it from a missing table.
            writer.WriteDomainReadCoverage([]);

            // An empty store is also what a forest with no groups would produce. This row is what
            // keeps the run that read nothing from reading as the clean one.
            writer.RecordCompleteness(
                DerivationCompleteness.NothingWasRead(scope.Value!, writer.GenerationId));

            progress.Report(new DerivationProgress("PublishingDerivation", 0));
            writer.Complete(DateTimeOffset.UtcNow);
            return DerivationRunState.CompletedDegraded;
        }

        // What the pass found, before anything is expanded from it. These are the numbers that
        // said the graph was the wrong shape when the scoping defect of 0087 was found.
        log.Note(
            DerivePhase,
            "read the nesting",
            [
                new RunLogDetail("principals", facts.Principals.Count.ToString(CultureInfo.InvariantCulture)),
                // "collected" rather than "edges", because member and memberOf describe the same
                // relationship from both ends and the pass keeps both. The store holds each once,
                // so this is roughly twice the row count and saying "edges" would invite the reader
                // to compare it against nesting_edge and conclude half of them went missing.
                new RunLogDetail("edgesCollected", facts.Edges.Count.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("unresolved", facts.UnresolvedTrustees.Count.ToString(CultureInfo.InvariantCulture)),
                // Beside "unresolved" rather than instead of it, because they answer different
                // questions. That is how many names went unmatched across the whole forest; this is
                // how many groups are consequently unable to say what they hold, which is the number
                // that decides how much judging goes quiet. P-164.
                new RunLogDetail(
                    "groupsWithUnidentifiedMembers",
                    facts.GroupsWithUnidentifiedMembers.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("collapsed", facts.CollapsedStubs.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("unscopedBuiltins", facts.Sids.UnscopedBuiltins.ToString(CultureInfo.InvariantCulture)),
            ]);

        progress.Report(new DerivationProgress("BuildingNestingGraph", 0));
        var graph = NestingGraph.Build(facts);

        // Every derived product names principals by this dictionary, so it is persisted before any
        // phase can write a product that references it.
        progress.Report(new DerivationProgress("WritingMembershipEvidence", 0));
        WriteFacts(writer, facts);
        writer.WriteMembershipInput(facts.MembershipSources, bundle.StreamObjects().IsComplete);

        // After the facts because it needs the domain SIDs the pass established, and before any
        // phase that could fail, because it is the one product that makes a later reader able to
        // tell an orphaned identifier from an unreadable domain - and that answer should not depend
        // on whether an expansion happened to finish.
        WriteDomainReadCoverage(writer, facts, scope.Value!);

        var closure = Run(
            writer,
            AuthorizationMembershipExpander.PhaseName,
            progress,
            log,
            clock,
            () => AuthorizationMembershipExpander.ClosureOf(graph, budget, cancellationToken),
            result => result.IsComplete
                ? DerivationPhaseOutcome.Succeeded
                : DerivationPhaseOutcome.Degraded);

        var completeness = closure is null
            ? DerivationCompleteness.WithoutExpansion(facts, scope.Value!, writer.GenerationId)
            : DerivationCompleteness.Of(facts, closure, scope.Value!, writer.GenerationId);
        RunProtection(writer, graph, facts, closure, !completeness.IsComplete, scope.Value!, progress, log, clock, cancellationToken);
        RunLatent(writer, graph, closure, progress, log, clock, cancellationToken);

        // Written from the same closure the products were derived from, so a cycle recorded here is
        // one that actually shaped those answers rather than one found by a second walk that might
        // disagree. Nothing is written when the expansion did not run: derivation_phase already
        // says so, and inventing an empty result would claim a forest with no loops in it.
        if (closure is not null)
            writer.WriteNestingCycles(closure.Cycles);

        // What none of the three products covers, recorded beside them rather than left for a
        // reader to infer. Written after the facts because the partial groups it names are sid
        // dictionary ids, and the dictionary is written by WriteFacts.
        writer.RecordCompleteness(completeness);

        progress.Report(new DerivationProgress("PublishingDerivation", 0));
        var state = writer.Complete(DateTimeOffset.UtcNow);

        log.Note(DerivePhase, "finished", [new RunLogDetail("state", state.ToString())]);

        return state;
    }

    /// <summary>
    /// The name the coordinator itself logs under, as against the phases it runs.
    /// </summary>
    private const string DerivePhase = "Derive";

    /// <summary>
    /// Progress for a derivation nobody is watching.
    /// </summary>
    /// <remarks>
    /// <b>Named rather than defaulted</b>, for the reason the judging run gives: a caller that
    /// passes this has said it has no operator to tell, where a caller that passed nothing would
    /// only have said it did not think about it.
    /// </remarks>
    public static IProgress<DerivationProgress> Unwatched { get; } = new NobodyWatching();

    /// <summary>The name the expansion phase is recorded under.</summary>


    private static NestingFacts? ReadNesting(
        BundleReader bundle,
        DerivationWriter writer,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        PhaseClock clock,
        CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();

        try
        {
            long objectsRead = 0;
            log.Note(MembershipNestingPass.PhaseName, "started", []);
            progress.Report(new DerivationProgress(MembershipNestingPass.PhaseName, 0));

            var counted = Counted(bundle.StreamObjects().Objects, () =>
            {
                objectsRead++;
                if (objectsRead % ProgressEvery == 0)
                    progress.Report(new DerivationProgress(MembershipNestingPass.PhaseName, objectsRead));
            });

            var facts = MembershipNestingPass.Read(
                counted,
                bundle.Description.ForestFqdn,
                cancellationToken);

            progress.Report(new DerivationProgress(MembershipNestingPass.PhaseName, objectsRead));

            writer.RecordPhase(
                MembershipNestingPass.PhaseName,
                facts.UnresolvedTrustees.Count > 0
                    ? DerivationPhaseOutcome.Degraded
                    : DerivationPhaseOutcome.Succeeded,
                error: null);

            log.Note(
                MembershipNestingPass.PhaseName,
                "finished",
                [
                    new RunLogDetail(
                        "objectsRead", objectsRead.ToString(CultureInfo.InvariantCulture)),
                ]);

            return facts;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            writer.RecordPhase(
                MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Failed, error.Message);

            log.Record(
                MembershipNestingPass.PhaseName,
                AuditError.Create(
                    ErrorCategory.Evidence,
                    "NestingPassFailed",
                    ErrorSeverity.Failed,
                    error.Message,
                    context: null),
                [new RunLogDetail("exception", error.GetType().Name)]);

            return null;
        }
        finally
        {
            // Recorded on both endings. A pass that ran for twenty minutes and then threw is the
            // one whose cost a reader most wants to see, and dropping the time on failure would
            // leave it inside the summary's unexplained remainder.
            clock.Record(MembershipNestingPass.PhaseName, started);
        }
    }

    private static void RunAttributeVisibility(
        BundleReader bundle,
        DerivationWriter writer,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        PhaseClock clock)
    {
        var product = Run(
            writer,
            AttributeVisibilityDeriver.PhaseName,
            progress,
            log,
            clock,
            () => AttributeVisibilityDeriver.Derive(bundle.ReadSchemaAttributes()),

            // Degraded rather than Succeeded when nothing came back, because no forest has zero
            // attribute definitions: an empty answer means this capture was refused the schema
            // partition, and a phase reporting success on it would tell every reader downstream
            // that the question had been answered.
            result => result.SchemaAttributesWereAsked
                ? DerivationPhaseOutcome.Succeeded
                : DerivationPhaseOutcome.Degraded);

        if (product is not null)
            writer.WriteAttributeVisibility(product);
    }

    private static void RunProtection(
        DerivationWriter writer,
        NestingGraph graph,
        NestingFacts facts,
        MembershipClosure? closure,
        bool routeEvidenceIncomplete,
        SecureAD.Evidence.Run.RunScope scope,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        PhaseClock clock,
        CancellationToken cancellationToken)
    {
        // It needs the graph and nothing else, so a failed expansion does not stop it. What a failed
        // expansion does change is what it can claim: without one, the membership evidence beneath
        // it is not known to be whole.
        var evidenceIsPartial =
            closure is null
            || !closure.IsComplete
            || facts.UnresolvedTrustees.Count > 0;

        // The two signals that name the principals this run cannot speak for. Kept out of
        // evidenceIsPartial above deliberately: that one is a fact about the whole run and turns
        // every answer in the forest Unknown, which is the outcome P-163 exists to prevent.
        var unreadDomains = DomainSidsNotReadInFull(facts, scope);
        var stubOnly = facts.StubOnlyPrincipals;

        if (unreadDomains.Count > 0 || stubOnly.Count > 0)
        {
            log.Note(
                DerivePhase,
                "found principals whose own domain was not read in full",
                [
                    new RunLogDetail(
                        "unreadDomains", unreadDomains.Count.ToString(CultureInfo.InvariantCulture)),

                    // Counted apart from the domains, because they are the principals no coverage
                    // row could have reached: a domain left out entirely establishes no SID.
                    new RunLogDetail(
                        "principalsKnownOnlyByAStub",
                        stubOnly.Count.ToString(CultureInfo.InvariantCulture)),
                ]);
        }

        // The catalogue this forest actually enforces, rather than the one Microsoft publishes. A
        // forest that never set dSHeuristics gets the published set and says it was asked; one that
        // set a mask gets a narrower set; a bundle that does not carry the value gets the published
        // set and says nobody looked.
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(facts.ForestHeuristics);

        var product = Run(
            writer,
            ProtectedPrincipalDeriver.PhaseName,
            progress,
            log,
            clock,
            () =>
            {
                var derived = ProtectedPrincipalDeriver.Derive(
                    graph, facts.Sids, catalogue, evidenceIsPartial, cancellationToken, facts.ForestRootDomainSid,
                    unreadDomains, stubOnly);
                return !routeEvidenceIncomplete ? derived : derived with
                {
                    MembershipRoutesBySid = derived.MembershipRoutesBySid.Select(summary => summary.WithIncompleteReasons(
                        summary.IncompleteReasons | MembershipRouteIncompleteReason.MembershipEvidenceIncomplete)).ToArray(),
                };
            },
            result => evidenceIsPartial || result.MembershipRoutesBySid.Any(summary => !summary.IsComplete)
                ? DerivationPhaseOutcome.Degraded
                : DerivationPhaseOutcome.Succeeded);

        if (product is not null)
            writer.WriteProtectedPrincipals(product);
    }

    private static void RunLatent(
        DerivationWriter writer,
        NestingGraph graph,
        MembershipClosure? closure,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        PhaseClock clock,
        CancellationToken cancellationToken)
    {
        if (closure is null)
        {
            // What it reports is who is inside a distribution group, which is the expansion's
            // answer. Without one there is nothing to say, and saying nothing would read as no
            // latent privilege anywhere.
            writer.RecordPhase(
                LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);

            log.Note(
                LatentPrivilegeDeriver.PhaseName,
                "did not run: the expansion it reads had no answer to give",
                []);

            return;
        }

        Run(
            writer,
            LatentPrivilegeDeriver.PhaseName,
            progress,
            log,
            clock,
            () => LatentPrivilegeDeriver.Derive(graph, closure, cancellationToken),
            _ => closure.IsComplete
                ? DerivationPhaseOutcome.Succeeded
                : DerivationPhaseOutcome.Degraded);
    }

    /// <summary>
    /// Runs one phase, recording what became of it either way.
    /// </summary>
    /// <remarks>
    /// <b>Cancellation is not a phase failure and is not caught here.</b> An operator stopping a
    /// derivation has not found a defect in it, and recording one would put a fault in the store
    /// that nobody caused.
    /// </remarks>
    private static T? Run<T>(
        DerivationWriter writer,
        string phase,
        IProgress<DerivationProgress> progress,
        IRunLog log,
        PhaseClock clock,
        Func<T> work,
        Func<T, DerivationPhaseOutcome> outcomeOf)
        where T : class
    {
        progress.Report(new DerivationProgress(phase, 0));
        log.Note(phase, "started", []);

        var started = Stopwatch.GetTimestamp();

        try
        {
            var result = work();
            var outcome = outcomeOf(result);

            writer.RecordPhase(phase, outcome, error: null);
            log.Note(phase, "finished", [new RunLogDetail("outcome", outcome.ToString())]);
            return result;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            writer.RecordPhase(phase, DerivationPhaseOutcome.Failed, error.Message);

            // The type is named as well as the message. "UNIQUE constraint failed" says what the
            // store refused; SqliteException says which layer refused it, and the two together are
            // what turned a day of guessing into a search.
            log.Record(
                phase,
                AuditError.Create(
                    ErrorCategory.Evidence,
                    "DerivationPhaseFailed",
                    ErrorSeverity.Degraded,
                    error.Message,
                    phase),
                [new RunLogDetail("exception", error.GetType().Name)]);

            return null;
        }
        finally
        {
            // Both endings, and a cancellation too - which this deliberately does not catch. A
            // phase that ran for a while before something stopped it still cost the run that time.
            clock.Record(phase, started);
        }
    }

    private static void WriteFacts(DerivationWriter writer, NestingFacts facts)
    {
        writer.WriteSids(facts.Sids.InIdOrder(), facts.Sids.ScopesInIdOrder());
        writer.WriteSidIdentities(facts.Identities);
        writer.WritePrincipals(facts.Principals);
        writer.WriteNestingEdges(facts.Edges);

        // Beside the edges rather than with the completeness lists below, because these are the
        // links that could not become edges and a reader of one needs the other to know what the
        // edges leave out. P-164.
        writer.WriteUnresolvedNestingLinks(facts.UnresolvedLinks);
    }

    /// <summary>
    /// Joins what the run said about reading each domain to the SID that domain's principals share.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Two halves of one fact live in two different places, and neither is usable alone.</b> The
    /// bundle records coverage by domain name, because that is what an operator declared and what a
    /// run reports against. An identifier arrives carrying a domain SID and no name at all. Joining
    /// them here, once, is what lets a later reader turn <c>S-1-5-21-a-b-c-RID</c> into a statement
    /// about whether the whole of that domain was read.
    /// </para>
    /// <para>
    /// <b>A domain the pass could not establish a SID for is dropped, not defaulted.</b> There is
    /// no identifier prefix to key it under, so a row would be unreachable at best and attached to
    /// the wrong domain at worst.
    /// </para>
    /// </remarks>
    private static void WriteDomainReadCoverage(
        DerivationWriter writer, NestingFacts facts, SecureAD.Evidence.Run.RunScope scope)
    {
        var rows = new List<DomainReadCoverageRow>();

        foreach (var domain in scope.Domains)
        {
            if (!facts.DomainSidsByFqdn.TryGetValue(domain.DomainFqdn, out var domainSid))
                continue;

            rows.Add(new DomainReadCoverageRow(domainSid, domain.DomainFqdn, domain.Outcome));
        }

        writer.WriteDomainReadCoverage(rows);
    }

    /// <summary>
    /// The domain SID prefixes of every declared domain this run did not read in full.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Anything short of <see cref="DomainReadOutcome.Read"/> counts</b>, which is the owner's
    /// decision of 2026-09-12 and matches how an unresolvable identifier is already judged in
    /// <c>OutcomeForMissingPrincipal</c>. A domain read in part is a hole of unknown shape, and an
    /// account inside it is one nothing was established about whether it was left out on purpose or
    /// by a failure.
    /// </para>
    /// <para>
    /// <b>A domain with no established SID yields nothing here, and that is not a gap this method
    /// can close.</b> A domain excluded outright contributes no objects to attribute a prefix from,
    /// so it cannot be matched this way - its principals reach the graph only as stubs, which is why
    /// <see cref="NestingFacts.StubOnlyPrincipals"/> exists and is applied beside this. P-163.
    /// </para>
    /// </remarks>
    private static HashSet<string> DomainSidsNotReadInFull(
        NestingFacts facts, SecureAD.Evidence.Run.RunScope scope)
    {
        var prefixes = new HashSet<string>(StringComparer.Ordinal);

        foreach (var domain in scope.Domains)
        {
            if (domain.Outcome == SecureAD.Evidence.Run.DomainReadOutcome.Read)
                continue;

            if (facts.DomainSidsByFqdn.TryGetValue(domain.DomainFqdn, out var domainSid))
                prefixes.Add(domainSid);
        }

        return prefixes;
    }

    /// <summary>
    /// Counts objects as they stream past, without holding any of them.
    /// </summary>
    private static IEnumerable<ObjectAttributes> Counted(
        IEnumerable<ObjectAttributes> objects, Action onEach)
    {
        foreach (var subject in objects)
        {
            onEach();
            yield return subject;
        }
    }

    private static Result<DerivationRunState> Failure(string reason, string description, string context) =>
        Result<DerivationRunState>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence, reason, ErrorSeverity.Failed, description, context));

    private sealed class NobodyWatching : IProgress<DerivationProgress>
    {
        public void Report(DerivationProgress value)
        {
        }
    }
}
