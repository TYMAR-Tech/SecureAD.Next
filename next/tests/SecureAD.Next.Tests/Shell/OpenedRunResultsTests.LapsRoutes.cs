using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("SEC-090")]
    [InlineData("SEC-093")]
    public void P248SavedLapsRoutesKeepOrderedSupportAndIncompleteness(string rule)
    {
        var directory = CreateLapsRouteRun(rule);
        using var source = new BundleAssetSource();

        var evidence = Assert.Single(source.ReadFindings(directory, FindingsQuery.About(LapsDn)).Value.Findings).Evidence;
        var route = LapsRoute(evidence);

        Assert.Equal((2, "S-1-5-21-1-2-3-1100", "S-1-1-0", (string?)null, false),
            (route.Count, route[0].Sid, route[1].Sid, route[1].Name, LapsRouteIsComplete(evidence)));
    }

    [Theory]
    [InlineData("SEC-090", "finding_laps_password_reader_path")]
    [InlineData("SEC-093", "finding_laps_decryptor_path")]
    public void P248SavedLapsRoutesRefuseMissingSupport(string rule, string table)
    {
        var directory = CreateLapsRouteRun(rule);
        MutateControlRun(directory, $"DELETE FROM {table} WHERE finding_id=1");
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.About(LapsDn));

        Assert.Equal("Shell.SavedResultsInvalidEvidence", read.Error?.Code);
    }

    [Theory]
    [InlineData("SEC-090", "finding_laps_password_reader_path", "ordinal")]
    [InlineData("SEC-093", "finding_laps_decryptor_path", "step_ordinal")]
    public void P248SavedLapsRoutesRefuseBrokenOrder(
        string rule,
        string table,
        string ordinal)
    {
        var directory = CreateLapsRouteRun(rule);
        MutateControlRun(
            directory,
            $"UPDATE {table} SET {ordinal}={ordinal}+10 WHERE finding_id=1");
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.About(LapsDn));

        Assert.Equal("Shell.SavedResultsInvalidEvidence", read.Error?.Code);
    }

    [Theory]
    [InlineData("SEC-090", "finding_laps_password_reader_path")]
    [InlineData("SEC-093", "finding_laps_decryptor_path")]
    public void P248SavedLapsRoutesDoNotReadAnotherFindingsSupport(string rule, string table)
    {
        var directory = CreateLapsRouteRun(rule);
        MutateControlRun(directory, $"UPDATE {table} SET sid='' WHERE finding_id=2");
        using var source = new BundleAssetSource();

        var evidence = Assert.Single(source.ReadFindings(directory, FindingsQuery.About(LapsDn)).Value.Findings).Evidence;

        Assert.Equal("S-1-1-0", LapsRoute(evidence)[1].Sid);
    }

    [Fact]
    public void P248SavedLapsDecryptorKeepsEveryBroadPrincipalRoute()
    {
        var directory = CreateLapsDecryptorRouteRun();
        using var source = new BundleAssetSource();

        var finding = Assert.Single(
            source.ReadFindings(directory, FindingsQuery.About(LapsDn)).Value.Findings);
        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Collection(
            evidence.BroadPrincipalRoutes,
            route =>
            {
                Assert.Equal("S-1-5-11", route.BroadPrincipalSid);
                Assert.Equal(2, route.MembershipPath.Count);
            },
            route =>
            {
                Assert.Equal("S-1-1-0", route.BroadPrincipalSid);
                Assert.Equal(3, route.MembershipPath.Count);
            });
    }

    [Fact]
    public void P248SavedLapsDecryptorRefusesAFalseRouteCount()
    {
        var directory = CreateLapsRouteRun("SEC-093");
        MutateControlRun(
            directory,
            "UPDATE finding_laps_decryptor SET route_count=route_count+1 WHERE finding_id=1");
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.About(LapsDn));

        Assert.Equal("Shell.SavedResultsInvalidEvidence", read.Error?.Code);
    }

    private static IReadOnlyList<PathStep> LapsRoute(FindingEvidence evidence) => evidence switch
    {
        LapsPasswordReaderEvidence reader => reader.MembershipPath,
        LapsDecryptorEvidence decryptor =>
            Assert.Single(decryptor.BroadPrincipalRoutes).MembershipPath,
        _ => throw new ArgumentException(nameof(evidence)),
    };

    private static bool LapsRouteIsComplete(FindingEvidence evidence) => evidence switch
    {
        LapsPasswordReaderEvidence reader => reader.IsComplete,
        LapsDecryptorEvidence decryptor => decryptor.IsComplete,
        _ => throw new ArgumentException(nameof(evidence)),
    };

    private static string CreateLapsRouteRun(string rule)
    {
        var directory = CreateLapsEvidence();
        IReadOnlyList<PathStep> path = [new("S-1-5-21-1-2-3-1100", "Delegated group"), new("S-1-1-0", null)];
        FindingEvidence support = rule switch
        {
            "SEC-090" => new LapsPasswordReaderEvidence(path[0].Sid, path[0].Name, path[1].Sid, null, path,
                "msLAPS-EncryptedPassword", LapsReadRights.Both, LapsGrantReach.ThisAttributeOnly, LapsRoot, false),
            "SEC-093" => new LapsDecryptorEvidence("Recorded policy", path[0].Sid, LapsDecryptorForm.SecurityIdentifier,
                path[0].Sid, path[0].Name,
                [new LapsDecryptorRouteEvidence(path[1].Sid, null, path)], false),
            _ => throw new ArgumentOutOfRangeException(nameof(rule)),
        };
        var definition = new RuleDefinition(rule, "Recorded LAPS finding", Severity.High, 1, ["computer"], [], []);
        using var writer = JudgementWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            null, LapsStarted, LapsStarted);
        writer.Write(RuleExecution.Judged(definition, 2, 0,
            new[] { LapsDn, "CN=Other," + LapsRoot }.Select(dn => new Finding(rule, 1, Severity.High,
                new(FindingSubjectKind.Account, dn), Guid.NewGuid(), dn, "ad.lab", "computer",
                "Recorded explanation; attribute reading is not decryption or takeover.", EvidenceCompleteness.Complete, support)).ToArray()));
        writer.Complete(LapsStarted);
        return directory;
    }

    private static string CreateLapsDecryptorRouteRun()
    {
        var directory = CreateLapsEvidence();
        IReadOnlyList<LapsDecryptorRouteEvidence> routes =
        [
            new(
                "S-1-5-11",
                "Authenticated Users",
                [
                    new("S-1-5-21-1-2-3-1100", "Delegated group"),
                    new("S-1-5-11", "Authenticated Users"),
                ]),
            new(
                "S-1-1-0",
                "Everyone",
                [
                    new("S-1-5-21-1-2-3-1100", "Delegated group"),
                    new("S-1-5-21-1-2-3-1200", "Nested group"),
                    new("S-1-1-0", "Everyone"),
                ]),
        ];
        var evidence = new LapsDecryptorEvidence(
            "Recorded policy",
            "S-1-5-21-1-2-3-1100",
            LapsDecryptorForm.SecurityIdentifier,
            "S-1-5-21-1-2-3-1100",
            "Delegated group",
            routes,
            false);
        var definition = new RuleDefinition(
            "SEC-093",
            "Recorded LAPS finding",
            Severity.Critical,
            1,
            ["groupPolicyContainer"],
            [],
            []);
        using var writer = JudgementWriter.Create(
            directory,
            BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            null,
            LapsStarted,
            LapsStarted);
        writer.Write(RuleExecution.Judged(
            definition,
            1,
            0,
            [
                new Finding(
                    "SEC-093",
                    1,
                    Severity.Critical,
                    new(FindingSubjectKind.Policy, "Recorded policy"),
                    Guid.NewGuid(),
                    LapsDn,
                    "ad.lab",
                    "groupPolicyContainer",
                    "Recorded explanation; all broad-principal routes remain attached.",
                    EvidenceCompleteness.Complete,
                    evidence),
            ]));
        writer.Complete(LapsStarted);
        return directory;
    }
}
