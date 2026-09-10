using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-030 against the cases its specification names.
/// </summary>
/// <remarks>
/// <para>
/// <b>These run the whole stage rather than calling the rule directly.</b> Each builds a sealed
/// bundle, derives it, judges it, and reads the judgement back - so what is asserted is what an
/// operator would see, and a defect anywhere between the capture and the store shows up here. A
/// test that handed the rule a fabricated <c>JudgingContext</c> would prove the rule agrees with
/// itself.
/// </para>
/// <para>
/// <b>The negative cases carry the weight.</b> A rule that finds things is easy; this one must also
/// stay silent for the right reasons, and say "I could not tell" rather than "nothing found" when
/// the evidence falls short. Each unknown asserts the specific reason, because reporting the wrong
/// doubt sends an operator to fix the wrong thing.
/// </para>
/// </remarks>
public sealed class AdminCountWithoutProtectionTests
{
    private static readonly DateTimeOffset Started = new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    private const string DomainSid = "S-1-5-21-11-22-33";
    private const string Forest = "ad.lab";

    /// <summary>
    /// P1. The marker is set, inheritance is blocked, and nothing establishes protection.
    /// </summary>
    [Fact]
    public void Sec030_ReportsAMarkedObjectWithABlockedDaclThatNothingProtects()
    {
        var findings = Judge(Ann() with { AdminCount = 1, DaclProtected = true });

        var finding = Assert.Single(findings);
        Assert.Equal("SEC-030", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);

        var evidence = Assert.IsType<AdminCountWithoutProtectionEvidence>(finding.Evidence);
        Assert.Equal(DomainSid + "-1105", evidence.Sid);

        // The wording must not claim history the evidence cannot establish.
        Assert.DoesNotContain("was privileged", finding.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("does not establish", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// N9. The marker is inconsistent but the ACL condition is absent, so this is not SEC-030.
    /// </summary>
    [Fact]
    public void Sec030_IsSilentWhenTheDaclStillInherits()
    {
        Assert.Empty(Judge(Ann() with { AdminCount = 1, DaclProtected = false }));
    }

    /// <summary>
    /// N10 and N11. Without the marker the rule is not about this object at all.
    /// </summary>
    [Fact]
    public void Sec030_IsSilentWithoutTheMarkerEvenWhenInheritanceIsBlocked()
    {
        Assert.Empty(Judge(Ann() with { AdminCount = null, DaclProtected = true }));
    }

    /// <summary>
    /// N1. The object is itself a protected principal, so the marker is correct.
    /// </summary>
    [Fact]
    public void Sec030_IsSilentForAProtectedPrincipalItself()
    {
        var domainAdmins = Ann() with
        {
            Dn = "CN=Domain Admins,DC=ad,DC=lab",
            Sid = DomainSid + "-512",
            Class = "group",
            AdminCount = 1,
            DaclProtected = true,
        };

        Assert.Empty(Judge(domainAdmins));
    }

    /// <summary>
    /// N3. Protection reached through membership suppresses the finding just as a direct claim does.
    /// </summary>
    [Fact]
    public void Sec030_IsSilentForAMemberOfAProtectedGroup()
    {
        var findings = Judge(
            Ann() with { AdminCount = 1, DaclProtected = true },
            alsoWrite: writer => WriteGroup(
                writer, "Domain Admins", DomainSid + "-512", member: "CN=Ann,DC=ad,DC=lab"));

        Assert.Empty(findings);
    }

    /// <summary>
    /// The negative control for every positive case above: without the forest's own
    /// <c>dSHeuristics</c>, nothing can be called unprotected.
    /// </summary>
    /// <remarks>
    /// <b>This is what makes the positive cases mean something.</b> The mask decides whether this
    /// forest stopped protecting the operator groups; unread, the catalogue cannot rule out a route
    /// through one, so <c>0089</c> requires every principal to be `Unknown`. Without this test the
    /// suite could not tell a rule that works from a fixture that happens to supply the mask.
    /// </remarks>
    [Fact]
    public void Sec030_ReportsNothingAsUnprotectedWhenTheForestMaskWasNeverRead()
    {
        var run = JudgeRun(
            Ann() with { AdminCount = 1, DaclProtected = true, ForestMask = false });

        Assert.Equal(0, run.ObjectsJudged);
        var reason = Assert.Single(run.MissingInputs);
        Assert.Equal("ProtectedPrincipals.ForestMaskUnknown", reason.Attribute);
    }

    /// <summary>
    /// U2. An unreadable security descriptor is a doubt, never a clean answer.
    /// </summary>
    [Fact]
    public void Sec030_CannotDecideWhenTheSecurityDescriptorWasNotCaptured()
    {
        var run = JudgeRun(Ann() with { AdminCount = 1, Descriptor = false });

        Assert.Equal(0, run.ObjectsJudged);
        var reason = Assert.Single(run.MissingInputs);
        Assert.Equal("ProtectedPrincipals.SecurityDescriptorUnreadable", reason.Attribute);
    }

    /// <summary>
    /// U6. The only route runs through a group Microsoft's own pages disagree about.
    /// </summary>
    /// <remarks>
    /// RID 498 carries <c>PrincipalProtection=Disputed</c> under <c>0089</c>: Appendix C omits it
    /// while the security-groups page marks it protected. The rule must say the claim is disputed,
    /// not that something was uncaptured - re-running a capture would not settle it.
    /// </remarks>
    [Fact]
    public void Sec030_ReportsADisputedClaimAsDisputedRatherThanAsMissingEvidence()
    {
        var run = JudgeRun(
            Ann() with
            {
                Dn = "CN=Enterprise RODC,DC=ad,DC=lab",
                Sid = DomainSid + "-498",
                Class = "group",
                AdminCount = 1,
                DaclProtected = true,
            });

        Assert.Equal(0, run.ObjectsJudged);
        var reason = Assert.Single(run.MissingInputs);
        Assert.Equal("ProtectedPrincipals.ClaimDisputed", reason.Attribute);

        // The negative control that matters: nothing here may look like a capture failure.
        Assert.DoesNotContain(run.MissingInputs, m => m.Attribute.Contains("objectSid", StringComparison.Ordinal));
    }

    /// <summary>
    /// P1. A primary-group route is settled evidence against protection, so the marker is reported.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This asserted an unsettled doubt until 0118, and the change is visible to a customer.</b>
    /// While primary-group traversal was research-gated, an account reaching Domain Controllers only
    /// through <c>primaryGroupID</c> was <c>Unknown</c>, and <c>SEC-030</c> declined to judge it.
    /// The laboratory observation of 2026-09-10 established that SDProp does not follow the edge, so
    /// the account is <c>NotProtected</c> - and an account carrying <c>adminCount=1</c> with a DACL
    /// still refusing inheritance, while nothing protects it, is exactly what this rule exists to
    /// report.
    /// </para>
    /// <para>
    /// <b>The account in this fixture is a leftover, not a domain controller.</b> A real domain
    /// controller carries neither marker, which is what the observation measured; this one carries
    /// both, which is the residue AdminSDHolder leaves behind when a principal stops being
    /// protected. Under the old rule that residue was hidden behind a doubt.
    /// </para>
    /// </remarks>
    [Fact]
    public void Sec030_ReportsAPrimaryGroupOnlyRouteAsUnprotected()
    {
        var stored = Stored(
            Ann() with
            {
                AdminCount = 1,
                DaclProtected = true,
                PrimaryGroupRid = 516,
            },
            alsoWrite: writer => WriteGroup(
                writer, "Domain Controllers", DomainSid + "-516"));

        var run = Assert.Single(stored.RulesRun);

        Assert.Single(stored.Findings);
        Assert.Equal(0, run.ObjectsNotJudged);

        // Nothing may remain unsettled: a finding beside a stated doubt would tell an operator the
        // answer and then undercut it in the same breath.
        Assert.Empty(run.MissingInputs);
    }

    // ---- fixture ----------------------------------------------------------------------------

    /// <summary>One object's shape, so each test states only what it changes.</summary>
    private sealed record Subject
    {
        public string Dn { get; init; } = "CN=Ann,DC=ad,DC=lab";
        public string Sid { get; init; } = DomainSid + "-1105";
        public string Class { get; init; } = "user";
        public uint? AdminCount { get; init; }
        public bool DaclProtected { get; init; }
        public bool Descriptor { get; init; } = true;
        public int? PrimaryGroupRid { get; init; }

        /// <summary>
        /// Whether the forest states its <c>dSHeuristics</c>. True for every case but the one
        /// proving the conservative gate, because without it the mask reads as never-looked and
        /// every principal is correctly Unknown - which would make the other cases pass for the
        /// wrong reason.
        /// </summary>
        public bool ForestMask { get; init; } = true;
    }

    private static Subject Ann() => new();

    private static IReadOnlyList<Finding> Judge(
        Subject subject, Action<BundleWriter>? alsoWrite = null) =>
        Stored(subject, alsoWrite).Findings;

    private static StoredRuleExecution JudgeRun(
        Subject subject, Action<BundleWriter>? alsoWrite = null) =>
        Assert.Single(Stored(subject, alsoWrite).RulesRun);

    private static StoredJudgement Stored(Subject subject, Action<BundleWriter>? alsoWrite)
    {
        var directory = Build(subject, alsoWrite);

        Assert.True(
            Stage2aRun.Derive(
                directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched,
                RunLog.Discarded, CancellationToken.None).IsSuccess);

        var judged = JudgingRun.Judge(
            directory,
            [new AdminCountWithoutProtection()],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);

        using var reader = JudgementReader.Open(directory).Value!;
        return reader.Read();
    }

    private static string Build(Subject subject, Action<BundleWriter>? alsoWrite)
    {
        var directory = TempDirectories.Create("sec030-tests");

        Directory.CreateDirectory(directory);

        var guid = Guid.NewGuid();

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(Partition);

            var attributes = new List<EvidenceAttribute>
            {
                Text("objectClass", subject.Class),
                Binary("objectSid", SidBytes(subject.Sid)),
            };

            if (subject.AdminCount is { } count)
                attributes.Add(Text("adminCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture)));

            if (subject.PrimaryGroupRid is { } rid)
                attributes.Add(Text("primaryGroupID", rid.ToString(System.Globalization.CultureInfo.InvariantCulture)));

            var objectId = writer.WriteObject(
                new EvidenceObject(Partition, subject.Dn, guid, attributes, Started));

            if (subject.Descriptor)
            {
                var descriptor = new AceNormalizationResult(
                    guid, null, null, DaclState.Present, subject.DaclProtected,
                    [], [], DaclCompleteness.Complete, true);

                writer.WriteSecurityDescriptor(objectId, Bytes(descriptor), descriptor);
            }

            alsoWrite?.Invoke(writer);

            // The one object per forest that carries dSHeuristics. Without it the mask reads
            // NotRead, the catalogue cannot say whether this forest excluded the operator groups,
            // and every principal is conservatively Unknown - so a positive case would silently
            // stop being a positive case. An empty value means "asked, and every character
            // defaults", which is an ordinary forest.
            if (subject.ForestMask)
            {
                writer.WriteObject(
                    new EvidenceObject(
                        Partition,
                        "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=ad,DC=lab",
                        Guid.NewGuid(),
                        [Text("objectClass", "nTDSService"), Text("dSHeuristics", "0")],
                        Started));
            }

            writer.Complete(Coverage, Started.AddMinutes(1));
        }

        return directory;
    }

    /// <summary>
    /// A group object, so a membership route has something real to reach. <c>member</c> lives on
    /// the group and names the member's distinguished name, which is how the directory stores it.
    /// </summary>
    private static void WriteGroup(
        BundleWriter writer, string name, string sid, string? member = null)
    {
        var attributes = new List<EvidenceAttribute>
        {
            Text("objectClass", "group"),
            Binary("objectSid", SidBytes(sid)),
        };

        if (member is not null)
            attributes.Add(Text("member", member));

        writer.WriteObject(
            new EvidenceObject(
                Partition, $"CN={name},DC=ad,DC=lab", Guid.NewGuid(), attributes, Started));
    }

    /// <summary>
    /// Stand-in bytes derived from what the descriptor says, so two that differ hash differently.
    /// </summary>
    private static byte[] Bytes(AceNormalizationResult descriptor) =>
        System.Text.Encoding.UTF8.GetBytes(
            $"{descriptor.ObjectGuid}|{descriptor.DaclState}|{descriptor.IsDaclProtected}");

    private static readonly PartitionCoverage Partition = new(
        "DC=ad,DC=lab",
        NamingContextKind.Domain,
        "dc01.ad.lab",
        ConnectionSecurityLevel.SignedAndSealed,
        1,
        1,
        0,
        [],
        false);

    private static readonly RunCoverage Coverage = RunCoverage.Of(
        CoverageId.ForDomains(Forest, [Forest]),
        [DomainCoverage.Read(Forest)],
        [
            ForestPartitionCoverage.Read(
                "CN=Configuration,DC=ad,DC=lab", NamingContextKind.Configuration),
            ForestPartitionCoverage.Read(
                "CN=Schema,CN=Configuration,DC=ad,DC=lab", NamingContextKind.Schema),
        ],
        SysvolCoverage.Of([]));

    private static EvidenceAttribute Text(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static EvidenceAttribute Binary(string name, byte[] bytes) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)]);

    private static byte[] SidBytes(string text) =>
        Sid.ToBytes(text)
        ?? throw new InvalidOperationException($"'{text}' is not a SID this product will encode.");
}
