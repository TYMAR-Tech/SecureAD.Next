using System.Globalization;
using SecureAD.Evidence;
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
        RunAttributeVisibility(bundle, writer, progress, log);

        var facts = ReadNesting(bundle, writer, progress, log, cancellationToken);

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

            // An empty store is also what a forest with no groups would produce. This row is what
            // keeps the run that read nothing from reading as the clean one.
            writer.RecordCompleteness(
                DerivationCompleteness.NothingWasRead(scope.Value!, writer.GenerationId));

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
                new RunLogDetail("collapsed", facts.CollapsedStubs.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("unscopedBuiltins", facts.Sids.UnscopedBuiltins.ToString(CultureInfo.InvariantCulture)),
            ]);

        var graph = NestingGraph.Build(facts);

        // Every derived product names principals by this dictionary, so it is persisted before any
        // phase can write a product that references it.
        WriteFacts(writer, facts);

        var closure = Run(
            writer,
            AuthorizationMembershipExpander.PhaseName,
            progress,
            log,
            () => AuthorizationMembershipExpander.ClosureOf(graph, budget, cancellationToken),
            result => result.IsComplete
                ? DerivationPhaseOutcome.Succeeded
                : DerivationPhaseOutcome.Degraded);

        RunProtection(writer, graph, facts, closure, progress, log, cancellationToken);
        RunLatent(writer, graph, closure, progress, log, cancellationToken);

        // Written from the same closure the products were derived from, so a cycle recorded here is
        // one that actually shaped those answers rather than one found by a second walk that might
        // disagree. Nothing is written when the expansion did not run: derivation_phase already
        // says so, and inventing an empty result would claim a forest with no loops in it.
        if (closure is not null)
            writer.WriteNestingCycles(closure.Cycles);

        // What none of the three products covers, recorded beside them rather than left for a
        // reader to infer. Written after the facts because the partial groups it names are sid
        // dictionary ids, and the dictionary is written by WriteFacts.
        var completeness = closure is null
            ? DerivationCompleteness.WithoutExpansion(facts, scope.Value!, writer.GenerationId)
            : DerivationCompleteness.Of(facts, closure, scope.Value!, writer.GenerationId);
        writer.RecordCompleteness(completeness);

        writer.Complete(DateTimeOffset.UtcNow);

        var state = !completeness.IsComplete
            ? DerivationRunState.CompletedDegraded
            : DerivationRunState.Completed;

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
        CancellationToken cancellationToken)
    {
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
    }

    private static void RunAttributeVisibility(
        BundleReader bundle,
        DerivationWriter writer,
        IProgress<DerivationProgress> progress,
        IRunLog log)
    {
        var product = Run(
            writer,
            AttributeVisibilityDeriver.PhaseName,
            progress,
            log,
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
        IProgress<DerivationProgress> progress,
        IRunLog log,
        CancellationToken cancellationToken)
    {
        // It needs the graph and nothing else, so a failed expansion does not stop it. What a failed
        // expansion does change is what it can claim: without one, the membership evidence beneath
        // it is not known to be whole.
        var evidenceIsPartial =
            closure is null
            || !closure.IsComplete
            || facts.UnresolvedTrustees.Count > 0;

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
            () => ProtectedPrincipalDeriver.Derive(
                graph,
                facts.Sids,
                catalogue,
                evidenceIsPartial,
                cancellationToken,
                facts.ForestRootDomainSid),
            _ => evidenceIsPartial
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
        Func<T> work,
        Func<T, DerivationPhaseOutcome> outcomeOf)
        where T : class
    {
        progress.Report(new DerivationProgress(phase, 0));
        log.Note(phase, "started", []);

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
    }

    private static void WriteFacts(DerivationWriter writer, NestingFacts facts)
    {
        writer.WriteSids(facts.Sids.InIdOrder(), facts.Sids.ScopesInIdOrder());
        writer.WriteSidIdentities(facts.Identities);
        writer.WritePrincipals(facts.Principals);
        writer.WriteNestingEdges(facts.Edges);
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
