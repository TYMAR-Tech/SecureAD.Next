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
        // The stored answers link to self-membership edges on the target group, so the group has to
        // be assessed for those links to exist.
        var directory = Bundle(tier0Route: true, tier0RouteFromTarget: true);
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

    internal const string CoreDn = "CN=Domain Admins,DC=contoso,DC=com";

    /// <summary>
    /// Real Tier-0 relative identifiers the shared classifier recognises: Domain Admins, Schema
    /// Admins, Enterprise Admins, Key Admins, Domain Controllers, Read-only Domain Controllers and
    /// Enterprise Key Admins. Never invented values - a fabricated RID would qualify nothing.
    /// </summary>
    private static readonly int[] Tier0Rids = [512, 518, 519, 526, 516, 521, 527];

    /// <summary>
    /// Builds a bounded capture. <paramref name="tier0Route"/> adds the reason these objects are
    /// worth assessing at all.
    /// </summary>
    /// <param name="tier0Route">
    /// <para>
    /// Writes a Domain Admins group <b>owned by</b> <see cref="UserSid"/>, so the captured user is a
    /// possible route into Tier 0. That admits the user for assessment, and with her the principals
    /// holding permissions <i>on</i> her - which is what these suites are about: who can rewrite this
    /// account, and therefore reach what it can reach.
    /// </para>
    /// <para>
    /// <b>Ownership rather than a DACL grant, deliberately - but it is not free.</b> An owner is
    /// recorded on the descriptor rather than in the ACL, so this adds no row to a <i>target</i>-view
    /// count, which is what most of these suites assert. It does produce an existing-owner edge on
    /// the Tier-0 group itself, so a test asserting an exact <i>holder</i>-view row count for the
    /// owning SID will see one more row than it did. That is a real edge from a real captured fact,
    /// not an artefact; a suite counting holder rows needs a route that its own assertions expect.
    /// </para>
    /// <para>
    /// <b>Required by any test that reads control edges once discovery gates assessment.</b> Under
    /// decision 0116 detailed control products are derived for objects a supported incoming route
    /// from a Tier-0 seed reached, so a fixture whose objects have no such route is correctly
    /// assessed as nothing at all. Passing true is a statement that the test's target genuinely
    /// matters - it is not a switch for making an expected number reappear, and a fixture that
    /// cannot justify the route belongs on the ungated path instead.
    /// </para>
    /// </param>
    internal static string Bundle(string? sddl = null, bool membership = true, int users = 1,
        string[]? members = null, long? groupType = -2147483646, bool targetDescriptor = true, string? userDescriptor = null,
        Action<BundleWriter, PartitionCoverage>? writeAdditional = null, string? rootDescriptor = null, bool rootObject = true,
        bool tier0Route = false, bool tier0RouteFromTarget = false)
    {
        var directory = TempDirectories.Create("self-membership-discovery");
        var coverage = new PartitionCoverage("DC=contoso,DC=com", NamingContextKind.Domain, "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
        using var writer = BundleWriter.Create(directory, Started);
        writer.WriteCoverage(coverage);
        if (rootObject) Write("DC=contoso,DC=com", "domainDNS", "S-1-5-21-1-2-3", [], rootDescriptor ?? "O:SYG:SYD:");
        for (var index = 0; index < users; index++)
            Write(UserName(index), "user", $"S-1-5-21-1-2-3-{1100 + index}",
                [new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("512")])], userDescriptor ?? "O:SYG:SYD:");
        Write(TargetDn, "group", TargetSid,
        [
            new("groupType", StoredAttributeCompleteness.Complete, groupType is { } type
                ? [EvidenceValue.OfText(type.ToString(System.Globalization.CultureInfo.InvariantCulture))] : []),
            new("member", StoredAttributeCompleteness.Complete, !membership ? []
                : (members ?? Enumerable.Range(0, users).Select(UserName).ToArray()).Select(EvidenceValue.OfText).ToArray()),
        ], !targetDescriptor ? null : sddl ?? $"O:SYG:SYD:(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;{UserSid})");
        if (tier0Route)
        {
            // One genuine Tier-0 group per captured principal, owned by that principal, so each is a
            // route into Tier 0 and is admitted along with whoever holds permissions on it. These
            // RIDs are the real ones the shared classifier recognises - Domain Admins, Schema Admins,
            // Enterprise Admins, Key Admins and their peers - not invented values. Ownership is
            // recorded on the descriptor rather than in an ACL, so this costs no control edge that
            // the counting suites must then account for.
            //
            // The target group is routed only when the caller says so, or when the fixture captures
            // no users and the target is therefore the object the test is about. Routing it always
            // would give the target an owned Tier-0 group, and the suites that count holder-view rows
            // for the target would see an extra edge they never asked about.
            var owners = Enumerable.Range(0, users).Select(index => $"S-1-5-21-1-2-3-{1100 + index}")
                .Concat(tier0RouteFromTarget || users == 0 ? [TargetSid] : Array.Empty<string>()).ToArray();
            for (var index = 0; index < Math.Min(owners.Length, Tier0Rids.Length); index++)
                Write(index == 0 ? CoreDn : $"CN=Tier0Group{index},DC=contoso,DC=com", "group",
                    $"S-1-5-21-1-2-3-{Tier0Rids[index]}",
                [
                    new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                    new("member", StoredAttributeCompleteness.Complete, []),
                ], $"O:{owners[index]}G:SYD:");

            // The naming-context root is not itself a Tier-0 seed - the classifier seeds on principal
            // SIDs - so replication rights granted on it admit nothing without this. A Tier-0 group
            // owned by the root makes the root a possible controller of Tier 0, which is what
            // directory-wide replication rights on it would actually mean.
            Write("CN=Tier0RootOwned,DC=contoso,DC=com", "group", "S-1-5-21-1-2-3-521",
            [
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                new("member", StoredAttributeCompleteness.Complete, []),
            ], "O:S-1-5-21-1-2-3G:SYD:");
        }
        writeAdditional?.Invoke(writer, coverage);
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
