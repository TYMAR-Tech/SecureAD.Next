using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Reading which analysis products a sealed run holds, as a separate axis from what became of it.
///
/// <para>
/// The distinction is the point. A run that sealed its evidence and was never analysed is
/// <see cref="RunState.Sealed"/> exactly like one that was fully judged, so a screen offering to
/// derive or judge it cannot ask the lifecycle state which of the two it is looking at.
/// </para>
/// </summary>
public sealed class RunProductsReaderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-products-" + Guid.NewGuid().ToString("n"));

    public RunProductsReaderTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A reader elsewhere may still hold a handle; the temporary directory is not the subject.
        }
    }

    [Fact]
    public void ACaptureOnlyRunHoldsNeitherProduct()
    {
        var products = RunProductsReader.Observe(_directory);

        Assert.False(products.HasDerivedFacts);
        Assert.False(products.HasJudgement);
        Assert.True(products.NothingAssessed);
        Assert.False(products.HasAnything);
    }

    [Fact]
    public void ADerivedRunHoldsFactsAndNoJudgement()
    {
        Publish(AnalysisStoreKind.Derivation);

        var products = RunProductsReader.Observe(_directory);

        Assert.True(products.HasDerivedFacts);
        Assert.False(products.HasJudgement);
        // It has been analysed in part, so it is not the untouched capture-only case.
        Assert.False(products.NothingAssessed);
        Assert.True(products.HasAnything);
    }

    [Fact]
    public void AJudgedRunHoldsBoth()
    {
        Publish(AnalysisStoreKind.Derivation);
        Publish(AnalysisStoreKind.Judgement);

        var products = RunProductsReader.Observe(_directory);

        Assert.True(products.HasDerivedFacts);
        Assert.True(products.HasJudgement);
        Assert.False(products.NothingAssessed);
    }

    /// <summary>
    /// The two kinds are read independently, so neither can stand in for the other.
    /// </summary>
    /// <remarks>
    /// A judgement without a derivation cannot arise from judging, which derives first. It is
    /// asserted anyway because the failure it guards against is a reader that answers one question
    /// and reports it twice - which would offer to derive a run that had been judged, or refuse to
    /// judge one that was ready.
    /// </remarks>
    [Fact]
    public void EachKindIsAskedSeparately()
    {
        Publish(AnalysisStoreKind.Judgement);

        var products = RunProductsReader.Observe(_directory);

        Assert.False(products.HasDerivedFacts);
        Assert.True(products.HasJudgement);
    }

    [Fact]
    public void AnUnpublishedAttemptIsNotAProduct()
    {
        var generation = Guid.NewGuid();
        AnalysisStoreLifecycle.BeginAttempt(_directory, AnalysisStoreKind.Judgement, generation);
        File.WriteAllText(
            TestSealing.AnalysisInputPath(_directory, AnalysisStoreKind.Judgement, generation),
            "half a result");

        var products = RunProductsReader.Observe(_directory);

        // Staged but never published. Offering this run's results would be offering an answer
        // nothing finished writing.
        Assert.False(products.HasJudgement);
        Assert.True(products.NothingAssessed);
    }

    [Fact]
    public void AMissingDirectoryIsRefusedRatherThanReportedEmpty()
    {
        var absent = Path.Combine(_directory, "no-such-run");

        // Whether a directory is a run at all is RunStateReader's question. Answering "it holds no
        // judgement" about something that is not a run would be a claim about a run that does not
        // exist - the predecessor's mistake, recorded on RunStateReader.
        Assert.False(RunStateReader.Observe(absent).IsSuccess);
    }

    private void Publish(AnalysisStoreKind kind)
    {
        var generation = Guid.NewGuid();
        AnalysisStoreLifecycle.BeginAttempt(_directory, kind, generation);
        File.WriteAllText(TestSealing.AnalysisInputPath(_directory, kind, generation), "result");
        AnalysisStoreLifecycle.Publish(_directory, kind, generation);
    }
}
