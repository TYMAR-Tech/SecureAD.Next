using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Measure;
using SecureAD.Shell.Services;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Judgement;

[Collection(nameof(PathProofNativeIoCollection))]
public sealed class SavedTextApplicationCostTests(ITestOutputHelper output)
{
    [Fact]
    public void CompleteOfflineProducerAndSavedReadbackCostsKeepEveryRuleAndPublishedProduct()
    {
        var directory = TempDirectories.Create("saved-text-application-cost");
        var log = new JudgingStatusTests.StatusLog();
        var before = GC.GetTotalAllocatedBytes(precise: true);
        var clock = Stopwatch.StartNew();
        EnterpriseControlWorkload.Write(directory, CancellationToken.None);
        var capturedAt = clock.Elapsed;
        var captured = EnterpriseBaseline.InspectCaptured(directory);
        Assert.Equal((343L, 795L, 7L, 343L, 5L),
            (captured.Objects, captured.MemberOccurrences, captured.DescriptorPositions, captured.DescriptorLinks, captured.CapturedPartitions));
        var inspectedAt = clock.Elapsed;
        var derived = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, EnterpriseControlWorkload.When,
            Stage2aRun.Unwatched, log, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        var derivedAt = clock.Elapsed;
        var judged = JudgingRun.JudgeAudit(directory, RuleCatalogue.All, JudgingRun.ProductionPathRequesterPolicy,
            EnterpriseControlWorkload.When, EnterpriseControlWorkload.When, JudgingRun.NobodyIsWatching,
            log, CancellationToken.None, null);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        var judgedAt = clock.Elapsed;
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        Assert.Equal(BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement), root.Segments.Select(value => value.Role));
        using var reader = JudgementReader.Open(directory).Value;
        var summary = reader.ReadSummary();
        Assert.True(summary.IsSuccess, summary.Error?.Description);
        Assert.Equal((343L, 32), (summary.Value.ObjectsJudged, summary.Value.RulesRun.Count));
        var groups = reader.ReadGroupInventory(new(null, ListingScope.Subtree, "", GroupInventoryScope.All,
            GroupInventoryKind.All, false, GroupInventorySort.Name), null);
        var tier0 = reader.ReadTier0Overview(Tier0OverviewScope.All, null, CancellationToken.None);
        Assert.Equal(159, groups.Total);
        Assert.NotNull(tier0);
        using var source = new BundleAssetSource();
        var target = EnterpriseControlWorkload.Group(0, 0);
        var classification = source.ReadPermissionClassification(directory, target);
        var controls = source.ReadControlEdges(directory, target, null, null, true, 0);
        Assert.True(classification.IsSuccess, classification.Error?.Description);
        Assert.True(controls.IsSuccess, controls.Error?.Description);
        Assert.NotEmpty(classification.Value.Classification.Entries);
        var saved = JsonSerializer.Serialize(new
        {
            summary.Value.ObjectsJudged, summary.Value.RulesRun, summary.Value.FindingsBySeverity,
            Groups = groups.Total, Tier0 = tier0.Summary.ClassifiedTier0Objects,
            Classification = classification.Value.Classification,
            controls.Value.ExpectedCount, controls.Value.UnknownCount, controls.Value.UnexpectedCount,
        });
        var finished = clock.Elapsed;
        var allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
        Assert.Contains(log.Lines, line => line.Detail.Any(value => value.Value == "prepare-requested-details"));
        Assert.Contains(log.Lines, line => line.Message == "file sealing");
        output.WriteLine(JsonSerializer.Serialize(new
        {
            Synthetic = true, Objects = 343, Rules = 32,
            CaptureWriteAndSealMs = capturedAt.TotalMilliseconds,
            IndependentCaptureInspectionMs = (inspectedAt - capturedAt).TotalMilliseconds,
            DeriveMs = (derivedAt - inspectedAt).TotalMilliseconds,
            JudgeIncludingAllPreparationPublicationAndSealsMs = (judgedAt - derivedAt).TotalMilliseconds,
            SavedReadbackMs = (finished - judgedAt).TotalMilliseconds, TotalMs = finished.TotalMilliseconds,
            AllocatedBytes = allocated, JudgementLogicalBytes = root.Segments.Sum(value => value.ByteLength),
            SavedAnswersSha256 = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(saved))),
            JudgementMvid = typeof(JudgingRun).Assembly.ManifestModule.ModuleVersionId,
            EvidenceMvid = typeof(BundleWriter).Assembly.ManifestModule.ModuleVersionId,
            TestMvid = typeof(SavedTextApplicationCostTests).Assembly.ManifestModule.ModuleVersionId,
            PublicationNotes = log.Lines.Where(line => line.Detail.Any(value =>
                value.Name is "part" or "artifact") || line.Message == "publication finished").ToArray(),
            Limitation = "Existing 343-object control generator and real offline application APIs; not live acquisition, WPF drawing, installed-product loading, lab or production acceptance. Process-wide cumulative allocation, not peak RAM.",
        }));
    }
}
