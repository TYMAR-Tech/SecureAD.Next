using System.Security.AccessControl;
using System.Security.Cryptography;
using SecureAD.Audit.Capture;
using SecureAD.Cli;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Shell;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SelfMembershipDiscoveryTests
{
    internal static readonly DateTimeOffset Started = new(2026, 9, 7, 0, 0, 0, TimeSpan.Zero);
    internal const string UserDn = "CN=Alice,DC=contoso,DC=com";
    internal const string UserSid = "S-1-5-21-1-2-3-1100";
    internal const string TargetDn = "CN=Target,DC=contoso,DC=com";
    internal const string TargetSid = "S-1-5-21-1-2-3-1200";
    internal static readonly SelfMembershipDiscoveryBudget TestBudget = new(100, 1000, 1000, 1000);

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task ConfiguredProductionPathsDiscoverAndPersistBothOwnAccountQuestions(string host)
    {
        var directory = Bundle();
        var hash = Hash(directory);
        if (host == "shell")
        {
            var settings = new FakeSettingsStore { Stored = new ShellSettings(Path.GetDirectoryName(directory)!) };
            var location = new RunLibraryLocation(settings);
            location.Load();
            var capture = new FakeCaptureLauncher { Outcome = new CaptureOutcome(true, directory) };
            var screen = new NewAuditViewModel(location, capture, new FakeNewAuditDialog(), new FakeRunOpener(),
                new DerivationLauncher(), new JudgingLauncher(TestBudget));
            await screen.OpenAsync();
            await screen.StartAsync();
            Assert.DoesNotContain("could not be judged", screen.JudgingReport, StringComparison.OrdinalIgnoreCase);
        }
        else if (host == "cli-offline")
        {
            Derive(directory);
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--judge", directory])!, CancellationToken.None,
                TestBudget, _ => throw new InvalidOperationException("Offline judging must not capture.")));
        }
        else
        {
            var called = false;
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!])!,
                CancellationToken.None, TestBudget, token =>
                {
                    token.ThrowIfCancellationRequested();
                    called = true;
                    Assert.False(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation)));
                    return Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null)));
                }));
            Assert.True(called);
        }
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var reader = opened.Value!;
        var answers = reader.ReadSelfMembershipAssessments(TargetDn, null).Assessments;
        Assert.Equal(2, answers.Count);
        Assert.Equal(new[] { SelfMembershipOperation.Add, SelfMembershipOperation.Remove }, answers.Select(a => a.Request.Operation));
        Assert.All(answers, a =>
        {
            Assert.Equal(UserDn, a.Request.RequesterDn);
            Assert.Null(a.Request.MemberDn);
            Assert.Equal(ControlEvaluationState.Established, a.Authorization);
            Assert.Equal(ControlEvaluationState.Established, a.OwnAccount);
            Assert.Single(a.HolderEdgeIds);
        });
        Assert.Equal(answers.Select(a => a.Request), reader.ReadSelfMembershipAssessments(null, UserDn).Assessments.Select(a => a.Request));
        Assert.Single(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Where(e => e.Capability == ControlCapability.CanAddSelfToGroup));
        Assert.Equal(hash, Hash(directory));
    }

    internal static void Derive(string directory)
    {
        var result = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched,
            RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    internal static string Hash(string directory) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, "evidence.db"))));

    internal static string Bundle(string? sddl = null, bool membership = true, int users = 1,
        string[]? members = null, long? groupType = -2147483646, bool targetDescriptor = true)
    {
        var directory = TempDirectories.Create("self-membership-discovery");
        var coverage = new PartitionCoverage("DC=contoso,DC=com", NamingContextKind.Domain, "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
        using var writer = BundleWriter.Create(directory, Started);
        writer.WriteCoverage(coverage);
        Write("DC=contoso,DC=com", "domainDNS", "S-1-5-21-1-2-3", [], "O:SYG:SYD:");
        for (var index = 0; index < users; index++)
            Write(UserName(index), "user", $"S-1-5-21-1-2-3-{1100 + index}",
                [new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("512")])], "O:SYG:SYD:");
        Write(TargetDn, "group", TargetSid,
        [
            new("groupType", StoredAttributeCompleteness.Complete, groupType is { } type
                ? [EvidenceValue.OfText(type.ToString(System.Globalization.CultureInfo.InvariantCulture))] : []),
            new("member", StoredAttributeCompleteness.Complete, !membership ? []
                : (members ?? Enumerable.Range(0, users).Select(UserName).ToArray()).Select(EvidenceValue.OfText).ToArray()),
        ], !targetDescriptor ? null : sddl ?? $"O:SYG:SYD:(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;{UserSid})");
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
             ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
            SysvolCoverage.Of([])), Started.AddMinutes(1));
        return directory;

        void Write(string dn, string objectClass, string sid, EvidenceAttribute[] extra, string? descriptor)
        {
            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(coverage, dn, guid,
            [
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
                .. extra,
            ], Started));
            if (descriptor is null) return;
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        }
    }

    internal static string UserName(int index) => index == 0 ? UserDn : $"CN=User{index},DC=contoso,DC=com";
}
