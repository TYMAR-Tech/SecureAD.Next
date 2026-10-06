using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// Which analysis products a sealed run is holding.
/// </summary>
/// <param name="HasDerivedFacts">Whether a complete derivation generation is published.</param>
/// <param name="HasJudgement">Whether a complete judgement generation is published.</param>
/// <remarks>
/// <b>Neither of these is a lifecycle state.</b> A run that sealed its evidence and was never
/// analysed is <see cref="RunState.Sealed"/> exactly like one that was, because what became of the
/// capture and what has since been made from it are different questions.
/// </remarks>
public sealed record RunProducts(bool HasDerivedFacts, bool HasJudgement)
{
    /// <summary>Whether the run has been analysed at all.</summary>
    public bool HasAnything => HasDerivedFacts || HasJudgement;

    /// <summary>Whether evidence was sealed and nothing has been made from it.</summary>
    public bool NothingAssessed => !HasAnything;
}

/// <summary>
/// Decides which analysis products a run holds by asking the store lifecycle, not the file system.
/// </summary>
/// <remarks>
/// <para>
/// <b>A separate axis, deliberately.</b> <see cref="RunState"/> records what became of the run and
/// its own remarks say why that must stay one question: the predecessor kept four vocabularies for
/// it, no two sharing members, and persisted one axis while reconstructing the rest. Adding
/// <i>Derived</i> or <i>Judged</i> members there would repeat that. A capture-only run is sealed;
/// what it does not yet hold is recorded here.
/// </para>
/// <para>
/// <b>Asked through the same door that publishes them.</b>
/// <see cref="AnalysisStoreLifecycle.Resolve"/> already decides whether a kind has a complete
/// published generation, including the manifest naming it and the data and seal being present.
/// Probing for file names here would be a second answer to that question, free to disagree with the
/// first - which is the defect this product keeps finding in itself.
/// </para>
/// <para>
/// <b>Absence is not failure.</b> A run with no judgement is the ordinary state of a capture-only
/// run, so this returns what is there rather than an error. Whether the directory is a run at all
/// is <see cref="RunStateReader"/>'s question and is answered before this one is asked.
/// </para>
/// </remarks>
public static class RunProductsReader
{
    /// <summary>Observes what the run in <paramref name="bundleDirectory"/> holds.</summary>
    /// <param name="bundleDirectory">A directory inside the run library.</param>
    /// <returns>Which products are published, both false when none are.</returns>
    public static RunProducts Observe(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        return new RunProducts(
            Published(bundleDirectory, AnalysisStoreKind.Derivation),
            Published(bundleDirectory, AnalysisStoreKind.Judgement));
    }

    // Mutation-tested 2026-09-22: answering true without asking the lifecycle failed four of the
    // six cases, including the capture-only run that this whole axis exists to identify.
    private static bool Published(string bundleDirectory, AnalysisStoreKind kind) =>
        AnalysisStoreLifecycle.Resolve(bundleDirectory, kind).IsSuccess;
}
