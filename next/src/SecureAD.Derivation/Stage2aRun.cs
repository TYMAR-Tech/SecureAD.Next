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
    /// <param name="cancellationToken">Stops the derivation.</param>
    /// <returns>What became of the run, or why it could not start.</returns>
    public static Result<DerivationRunState> Derive(
        string bundleDirectory,
        ExpansionBudget budget,
        DateTimeOffset startedUtc,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentNullException.ThrowIfNull(progress);

        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(bundleDirectory));

        if (seal is null || string.IsNullOrWhiteSpace(seal.Hash))
        {
            return Failure(
                "EvidenceSealUnreadable",
                $"There is no readable evidence seal in '{bundleDirectory}', so derived facts "
                + "written here could not say which capture they came from. A closure that cannot "
                + "name its evidence is consulted silently by every rule resting on it, which "
                + "makes naming it the whole of its trustworthiness.",
                bundleDirectory);
        }

        var opened = BundleReader.Open(bundleDirectory);
        if (!opened.IsSuccess)
            return Result<DerivationRunState>.Failure(opened.Error!);

        using var bundle = opened.Value!;

        var scope = bundle.ReadScope();
        if (!scope.IsSuccess)
            return Result<DerivationRunState>.Failure(scope.Error!);

        using var writer = DerivationWriter.Create(bundleDirectory, seal.Hash, startedUtc);

        var facts = ReadNesting(bundle, writer, progress, cancellationToken);

        if (facts is null)
        {
            // Nothing downstream has an input. Each is recorded by name so a reader can tell a
            // derivation that produced nothing from one that was never asked to.
            writer.RecordPhase(nameof(ExpansionPhase), DerivationPhaseOutcome.DidNotRun, error: null);
            writer.RecordPhase(ProtectedPrincipalDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);
            writer.RecordPhase(LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);

            writer.WriteSids([], []);
            writer.Complete(DateTimeOffset.UtcNow);
            return DerivationRunState.CompletedDegraded;
        }

        var graph = NestingGraph.Build(facts);

        var closure = Run(
            writer,
            nameof(ExpansionPhase),
            progress,
            () => AuthorizationMembershipExpander.Expand(graph, budget, cancellationToken),
            result => result.IsComplete
                ? DerivationPhaseOutcome.Succeeded
                : DerivationPhaseOutcome.Degraded);

        RunProtection(writer, graph, facts, closure, progress, cancellationToken);
        RunLatent(writer, graph, closure, progress, cancellationToken);

        WriteFacts(writer, facts);

        writer.Complete(DateTimeOffset.UtcNow);

        return closure is null || !closure.IsComplete || facts.UnresolvedTrustees.Count > 0
            ? DerivationRunState.CompletedDegraded
            : DerivationRunState.Completed;
    }

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
    private static class ExpansionPhase;

    private static NestingFacts? ReadNesting(
        BundleReader bundle,
        DerivationWriter writer,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        try
        {
            long objectsRead = 0;
            progress.Report(new DerivationProgress(MembershipNestingPass.PhaseName, 0));

            var counted = Counted(bundle.StreamObjects().Objects, () =>
            {
                objectsRead++;
                if (objectsRead % ProgressEvery == 0)
                    progress.Report(new DerivationProgress(MembershipNestingPass.PhaseName, objectsRead));
            });

            var facts = MembershipNestingPass.Read(counted, cancellationToken);

            progress.Report(new DerivationProgress(MembershipNestingPass.PhaseName, objectsRead));

            writer.RecordPhase(
                MembershipNestingPass.PhaseName,
                facts.UnresolvedTrustees.Count > 0
                    ? DerivationPhaseOutcome.Degraded
                    : DerivationPhaseOutcome.Succeeded,
                error: null);

            return facts;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            writer.RecordPhase(
                MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Failed, error.Message);

            return null;
        }
    }

    private static void RunProtection(
        DerivationWriter writer,
        NestingGraph graph,
        NestingFacts facts,
        MembershipClosure? closure,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        // It needs the graph and nothing else, so a failed expansion does not stop it. What a failed
        // expansion does change is what it can claim: without one, the membership evidence beneath
        // it is not known to be whole.
        var evidenceIsPartial =
            closure is null
            || !closure.IsComplete
            || facts.UnresolvedTrustees.Count > 0;

        Run(
            writer,
            ProtectedPrincipalDeriver.PhaseName,
            progress,
            () => ProtectedPrincipalDeriver.Derive(
                graph, facts.Sids, ProtectedGroupCatalogue.Default, evidenceIsPartial, cancellationToken),
            _ => evidenceIsPartial
                ? DerivationPhaseOutcome.Degraded
                : DerivationPhaseOutcome.Succeeded);
    }

    private static void RunLatent(
        DerivationWriter writer,
        NestingGraph graph,
        MembershipClosure? closure,
        IProgress<DerivationProgress> progress,
        CancellationToken cancellationToken)
    {
        if (closure is null)
        {
            // What it reports is who is inside a distribution group, which is the expansion's
            // answer. Without one there is nothing to say, and saying nothing would read as no
            // latent privilege anywhere.
            writer.RecordPhase(
                LatentPrivilegeDeriver.PhaseName, DerivationPhaseOutcome.DidNotRun, error: null);
            return;
        }

        Run(
            writer,
            LatentPrivilegeDeriver.PhaseName,
            progress,
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
        Func<T> work,
        Func<T, DerivationPhaseOutcome> outcomeOf)
        where T : class
    {
        progress.Report(new DerivationProgress(phase, 0));

        try
        {
            var result = work();
            writer.RecordPhase(phase, outcomeOf(result), error: null);
            return result;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            writer.RecordPhase(phase, DerivationPhaseOutcome.Failed, error.Message);
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
