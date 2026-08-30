using SecureAD.Audit.Capture;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Kernel.Security;
using SecureAD.Next.Tests.Sysvol;
using Xunit;

namespace SecureAD.Next.Tests.EndToEnd;

public sealed class OfflineAuditJourneyTests
{
    private static readonly DateTimeOffset Started =
        new(2026, 8, 28, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CapturedEvidenceIsDerivedJudgedAndReadBack()
    {
        var root = Path.Combine(
            Path.GetTempPath(), "securead-offline-journey", Guid.NewGuid().ToString("N"));
        var controller = ForestWithUnconstrainedAccount();
        var connections = controller.Connections();
        var plan = CapturePlan.For(
            controller.DomainController,
            "example.com",
            "CN=Configuration,DC=example,DC=com",
            "CN=Schema,CN=Configuration,DC=example,DC=com",
            [("DC=example,DC=com", "example.com", controller.DomainController)],
            controller.NamingContexts,
            ["DC=DomainDnsZones,DC=example,DC=com"]);
        Assert.True(plan.IsSuccess, plan.Error?.Description);

        var library = new RunLibrary(root, TimeProvider.System);
        var directory = library.CreateRun("example.com");
        Assert.True(directory.IsSuccess, directory.Error?.Description);

        var captured = await new CaptureRun(
            connections,
            new InMemorySysvolFileReader(),
            TimeProvider.System).RunAsync(
                plan.Value!,
                directory.Value!,
                new Dictionary<string, AttestedExclusion>(),
                CancellationToken.None);
        Assert.True(captured.ProducedABundle, captured.Error?.Description);

        var derived = Stage2aRun.Derive(
            directory.Value!,
            ExpansionBudget.Bulk,
            Started,
            Stage2aRun.Unwatched,
            RunLog.Discarded,
            CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);

        var judged = JudgingRun.Judge(
            directory.Value!,
            RuleCatalogue.All,
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);

        using var opened = JudgementReader.Open(directory.Value!).Value!;
        var finding = Assert.Single(opened.Read().Findings);
        Assert.Equal("SEC-010", finding.RuleId);
        Assert.Equal("svc-web", finding.Subject.Key);
    }

    private static ControllerModel ForestWithUnconstrainedAccount()
    {
        var controller = new ControllerModel();
        controller.AnswersTo.Add("example.com");
        controller.AddObject(
            "CN=svc-web,DC=example,DC=com",
            ("objectClass", ["top", "person", "organizationalPerson", "user"]),
            ("objectGUID", [Guid.NewGuid().ToByteArray()]),
            ("objectSid", [Sid(1104)]),
            ("sAMAccountName", ["svc-web"]),
            ("userAccountControl", ["524800"]),
            ("primaryGroupID", ["513"]));
        return controller;
    }

    private static byte[] Sid(uint relativeIdentifier) =>
        SdBytes.Sid(1, 5, [21, 1111111111, 2222222222, 3333333333, relativeIdentifier]);
}
