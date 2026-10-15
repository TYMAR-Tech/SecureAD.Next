using System.Diagnostics.Metrics;
using SecureAD.Cli;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Readback;

[CollectionDefinition("Completion console", DisableParallelization = true)]
public sealed class CompletionConsoleCollection;

[Collection("Completion console")]
public sealed class CompletionCancellationTests
{
    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public async Task CancellationDuringPublishedSummaryKeepsTheCompletedRootAndDoesNotClaimNothingWasProduced(AnalysisStoreKind kind)
    {
        var directory = Bundle();
        if (kind == AnalysisStoreKind.Judgement) Derive(directory);
        using var cancellation = new CancellationTokenSource();
        using var listener = new MeterListener();
        var cancelledAfterPublication = false;
        listener.InstrumentPublished = (instrument, target) =>
        {
            if (instrument.Name == "store.verifications") target.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Value is not string path || !path.StartsWith(directory, StringComparison.OrdinalIgnoreCase))
                    continue;
                var selected = AnalysisStoreLifecycle.Resolve(directory, kind);
                if (!selected.IsSuccess
                    || path != BundleLayout.AnalysisGenerationDataPath(directory, kind, selected.Value.GenerationId))
                    continue;
                cancelledAfterPublication = true;
                cancellation.Cancel();
            }
        });
        listener.Start();
        var original = Console.Error;
        using var output = new StringWriter();
        try
        {
            Console.SetError(output);
            var verb = kind == AnalysisStoreKind.Judgement ? "--judge" : "--derive";
            var options = CommandLine.Parse([verb, directory])!;
            Assert.Equal(130, await Program.RunAsync(options, cancellation.Token, discoveryBudget: null,
                capture: null, requesterPolicy: PathRequesterPolicy.Disabled));
        }
        finally { Console.SetError(original); }
        Assert.True(cancelledAfterPublication);
        var completed = AnalysisStoreLifecycle.Resolve(directory, kind);
        Assert.True(completed.IsSuccess, completed.Error?.Description);
        Assert.DoesNotContain("Nothing was", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("The evidence is sealed and safe at " + directory, output.ToString(), StringComparison.Ordinal);
        if (kind == AnalysisStoreKind.Judgement)
        {
            using var reader = JudgementReader.Open(directory).Value;
            Assert.True(reader.ReadSummary().IsSuccess);
        }
        else
            Assert.True(SecureAD.Derivation.DerivationReader.ReadSummary(directory).IsSuccess);
    }
}
