using System.Reflection;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Every kind of evidence a finding can rest on survives being stored and read back.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because of <c>P-112</c>, and because adding SEC-027 nearly repeated it.</b> A
/// finding's evidence is written to a table of its own and read back through a mapper shared by the
/// whole-store read and the grid's paged read. When only one kind was exercised, a defect in the
/// others went unseen for a month and showed an operator a severity rank where a security identifier
/// should have been. It did not throw and the screen did not look wrong.
/// </para>
/// <para>
/// <b>The registry below is found by reflection, not written twice.</b> <see cref="Samples"/> is
/// keyed on the evidence type, and <see cref="EveryEvidenceKindHasASample"/> asks the production
/// assembly what kinds exist. So a new kind fails this file the moment it is declared, rather than
/// whenever somebody remembers to add a case - which is the whole difference between a gate and a
/// habit.
/// </para>
/// <para>
/// <b>What a new rule owes, therefore.</b> Add its evidence kind to <see cref="Samples"/> with one
/// assertion about its contents, and the write, the read, the paged read and the discriminator are
/// all covered. Everything else a rule owes is already held: guidance by
/// <c>RuleGuidanceTests</c>, declared inputs by <c>RuleDeclarationTests</c>, and the public types by
/// <c>SurfaceRegisterTests</c> and <c>TypesTableOwnershipTests</c>.
/// </para>
/// </remarks>
public sealed class EvidenceKindCoverageTests
{
    private const string ThisCapture = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

    private static readonly DateTimeOffset Started = new(2026, 8, 25, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// One finding per kind of evidence, with what a reader must get back.
    /// </summary>
    /// <remarks>
    /// <b>Each sample is deliberately awkward.</b> A sample carrying one value of everything would
    /// round-trip through a reader that dropped all but the first, and say nothing. So the SID
    /// history sample carries a match, an unranked value and an unreadable count; the delegation
    /// sample sets signals that disagree with each other.
    /// </remarks>
    private static IReadOnlyList<Sample> Samples { get; } =
    [
        new Sample(
            Definition("SEC-010", "Unconstrained delegation on an account"),
            "CN=svc-delegation,OU=Service Accounts,DC=contoso,DC=com",
            new UnconstrainedDelegationEvidence(
                0x80000, true, new DomainControllerSignals(true, false, true)),
            read =>
            {
                var e = Assert.IsType<UnconstrainedDelegationEvidence>(read);
                Assert.Equal(0x80000u, e.UserAccountControl);
                Assert.True(e.IsComputer);
                Assert.True(e.DomainController.ServerTrustAccountBit);
                Assert.False(e.DomainController.PrimaryGroupIsDomainController);
                Assert.True(e.DomainController.UnderDomainControllersOu);
            }),

        new Sample(
            Definition("SEC-030", "AdminCount without protection"),
            "CN=svc-marker,OU=Service Accounts,DC=contoso,DC=com",
            new AdminCountWithoutProtectionEvidence("S-1-5-21-1-2-3-1104"),
            read => Assert.Equal(
                "S-1-5-21-1-2-3-1104",
                Assert.IsType<AdminCountWithoutProtectionEvidence>(read).Sid)),

        new Sample(
            Definition("SEC-022", "Kerberos pre-authentication not required"),
            "CN=svc-nopreauth,OU=Service Accounts,DC=contoso,DC=com",
            new UserAccountControlEvidence(0x400202),
            read =>
            {
                var e = Assert.IsType<UserAccountControlEvidence>(read);
                Assert.Equal(0x400202u, e.UserAccountControl);
                Assert.True(e.IsDisabled);
            }),

        new Sample(
            Definition("SEC-027", "Privileged identifier carried in SID history"),
            "CN=svc-migrated,OU=Service Accounts,DC=contoso,DC=com",
            new PrivilegedSidHistoryEvidence(
                "S-1-5-21-9-9-9-1105",
                ["S-1-5-21-1-2-3-519", "S-1-5-21-1-2-3-1157"],
                [new PrivilegedSidHistoryMatch("S-1-5-21-1-2-3-519", 519, "Enterprise Admins")],
                UnreadableValues: 1),
            read =>
            {
                var e = Assert.IsType<PrivilegedSidHistoryEvidence>(read);
                Assert.Equal("S-1-5-21-9-9-9-1105", e.ObjectSid);
                Assert.Equal(["S-1-5-21-1-2-3-519", "S-1-5-21-1-2-3-1157"], e.HistoryValues);
                Assert.Equal("Enterprise Admins", Assert.Single(e.Matches).Name);
                Assert.Equal(["S-1-5-21-1-2-3-1157"], e.UnrankedValues);
                Assert.Equal(1, e.UnreadableValues);
                Assert.False(e.IsComplete);
            }),

        new Sample(
            Definition("SEC-021", "Privileged account with a service name registered on it"),
            "CN=svc-sql,OU=Service Accounts,DC=contoso,DC=com",
            new KerberoastableAccountEvidence(
                "S-1-5-21-1-2-3-1106",
                ["MSSQLSvc/db01.contoso.com:1433", "HOST/db01.contoso.com"],
                0x400202,
                UnreadableServiceNames: 1),
            read =>
            {
                var e = Assert.IsType<KerberoastableAccountEvidence>(read);
                Assert.Equal("S-1-5-21-1-2-3-1106", e.ObjectSid);
                Assert.Equal(
                    ["MSSQLSvc/db01.contoso.com:1433", "HOST/db01.contoso.com"],
                    e.ServicePrincipalNames);
                Assert.Equal(0x400202u, e.UserAccountControl);
                Assert.True(e.IsDisabled);
                Assert.Equal(1, e.UnreadableServiceNames);
                Assert.False(e.IsComplete);
            }),

        // Deliberately awkward, per the remarks above: a machine carrying one timestamp and not the
        // other, whose capability was decided from a build number, and whose legacy value is a
        // FILETIME rather than a date. A reader that dropped a column, or that stored a decoded
        // date instead of the raw value, gives a different answer to at least one of these.
        new Sample(
            Definition("SEC-094", "Windows LAPS expected, but only a legacy timestamp present"),
            "CN=FS01,OU=Servers,DC=contoso,DC=com",
            new LapsDeploymentEvidence(
                WindowsLapsExpiration: null,
                LegacyLapsExpiration: "133700000000000000",
                new LapsCapability(
                    LapsCapabilityKind.WindowsLapsCapable,
                    LapsCapabilityBasis.OperatingSystemVersion,
                    "Windows Server 2022 Datacenter",
                    "10.0 (20348)")),
            read =>
            {
                var e = Assert.IsType<LapsDeploymentEvidence>(read);
                Assert.Null(e.WindowsLapsExpiration);
                Assert.Equal("133700000000000000", e.LegacyLapsExpiration);
                Assert.Equal(LapsTimestampReading.Absent, e.WindowsLaps);
                Assert.Equal(LapsTimestampReading.Present, e.LegacyLaps);
                Assert.NotNull(e.LegacyLapsExpiresUtc);
                Assert.Null(e.WindowsLapsExpiresUtc);
                Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, e.Capability.Kind);
                Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, e.Capability.Basis);
                Assert.Equal("Windows Server 2022 Datacenter", e.Capability.Name);
                Assert.Equal("10.0 (20348)", e.Capability.Version);
                Assert.True(e.Capability.IsServer);
            }),

        // Deliberately awkward for the same reason: a broad principal reached at depth three, an
        // entry that was inherited, and a walk that did not complete. A reader that dropped the
        // path child table, that keyed the evidence off the nullable inherited_from column, or that
        // stored the completeness as anything other than what was written, gives a different answer
        // to at least one of these. The path is the part most worth pinning - it is the whole of
        // what makes the finding actionable, and it is stored in a separate table.
        new Sample(
            Definition("SEC-090", "A broad principal can read LAPS passwords"),
            "CN=WS01,OU=Workstations,DC=contoso,DC=com",
            new LapsPasswordReaderEvidence(
                TrusteeSid: "S-1-5-21-1004336348-1177238915-682003330-1123",
                TrusteeName: "LAPS-Readers",
                BroadPrincipalSid: "S-1-5-11",
                BroadPrincipalName: "Authenticated Users",
                MembershipPath:
                [
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-1123", "LAPS-Readers"),
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-1145", "IT-All"),

                    // Deliberately unnamed: a principal from a trusted forest has no name in this
                    // bundle, and a reader that dropped the null would show the wrong thing.
                    new PathStep("S-1-5-11", null),
                ],
                Attribute: "msLAPS-Password",
                Rights: LapsReadRights.Both,
                Reach: LapsGrantReach.EveryAttribute,
                InheritedFrom: "DC=contoso,DC=com",
                ExpansionWasComplete: false),
            read =>
            {
                var e = Assert.IsType<LapsPasswordReaderEvidence>(read);
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-1123", e.TrusteeSid);
                Assert.Equal("LAPS-Readers", e.TrusteeName);
                Assert.Equal("S-1-5-11", e.BroadPrincipalSid);
                Assert.Equal("Authenticated Users", e.BroadPrincipalName);
                Assert.Equal(3, e.MembershipPath.Count);
                Assert.Equal("S-1-5-11", e.MembershipPath[^1].Sid);
                Assert.Null(e.MembershipPath[^1].Name);
                Assert.Equal("LAPS-Readers", e.MembershipPath[0].Name);
                Assert.Equal("LAPS-Readers -> IT-All -> S-1-5-11", e.Route);
                Assert.Equal(2, e.NestingDepth);
                Assert.Equal("msLAPS-Password", e.Attribute);
                Assert.Equal(LapsReadRights.Both, e.Rights);
                Assert.True(e.CanReadThePassword);
                Assert.Equal(LapsGrantReach.EveryAttribute, e.Reach);
                Assert.Equal("DC=contoso,DC=com", e.InheritedFrom);
                Assert.False(e.IsComplete);
            }),
    ];

    /// <summary>
    /// Every kind of evidence the product declares has a sample here.
    /// </summary>
    /// <remarks>
    /// <b>Asked of the assembly rather than of a list somebody maintains.</b> The deciding question
    /// for any gate is what change to the product would make it fail: declaring a new
    /// <see cref="FindingEvidence"/> does, immediately, naming the kind. That is the failure the
    /// SEC-027 build would have had on its first minute instead of its last hour.
    /// </remarks>
    [Fact]
    public void EveryEvidenceKindHasASample()
    {
        var declared = EvidenceKinds();
        var covered = Samples.Select(s => s.Evidence.GetType()).ToHashSet();

        var missing = declared
            .Where(kind => !covered.Contains(kind))
            .Select(kind => "  " + kind.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Kinds of finding evidence with no sample in EvidenceKindCoverageTests. A kind that is "
            + "never written and read back is a kind whose storage nobody has exercised - which is "
            + "how P-112 showed an operator a severity rank as a security identifier for a month. "
            + "Add a sample with one assertion about its contents:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// The scan is looking at a real population, not an empty one.
    /// </summary>
    /// <remarks>
    /// The way this file dies quietly is for <see cref="EvidenceKinds"/> to stop matching - a
    /// namespace moved, a base type renamed - at which point the check above passes over nothing and
    /// every kind is uncovered without a word. This is the failure gate 5 had, and every gate in this
    /// tree carries a self-test for it.
    /// </remarks>
    [Fact]
    public void TheScanFindsTheKindsThatExist()
    {
        var declared = EvidenceKinds();

        Assert.Contains(typeof(UserAccountControlEvidence), declared);
        Assert.Contains(typeof(PrivilegedSidHistoryEvidence), declared);
        Assert.True(declared.Count >= Samples.Count);
    }

    /// <summary>
    /// Every kind is written, then read back through the grid's own paging path, as itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Through <c>ReadPage</c> and not the whole-store read.</b> Those are two queries sharing one
    /// mapper, and it was their disagreement that produced <c>P-112</c>. The paged one is what an
    /// operator's screen actually calls.
    /// </para>
    /// <para>
    /// <b>All kinds in one store, not one store each.</b> The defect only appears when a page holds
    /// more than one kind, because the mapper decides which branch to take per row. A store per kind
    /// would pass while the grid was broken.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryEvidenceKindSurvivesTheGridsPagingPath()
    {
        var directory = ADirectory();

        using (var writer = JudgementWriter.Create(
            directory, ThisCapture, derivationGenerationId: null, Started, Started))
        {
            foreach (var sample in Samples)
                writer.Write(RuleExecution.Judged(sample.Rule, 1, 0, [sample.Finding]));

            writer.Complete(Started);
        }

        using var reader = Opened(directory);
        var page = reader.ReadPage(FindingsQuery.Everything());

        Assert.True(page.IsSuccess, page.Error?.Description);

        foreach (var sample in Samples)
        {
            var found = Assert.Single(
                page.Value!.Findings, f => f.RuleId == sample.Rule.Id);

            sample.AssertRead(found.Evidence);
        }
    }

    /// <summary>Every sealed kind of evidence the production assembly declares.</summary>
    private static IReadOnlyList<Type> EvidenceKinds() =>
    [
        .. typeof(FindingEvidence).Assembly
            .GetExportedTypes()
            .Where(t => t.IsSealed && !t.IsAbstract && t.IsSubclassOf(typeof(FindingEvidence))),
    ];

    private static RuleDefinition Definition(string id, string title) =>
        new(id, title, Severity.High, 1, ["user"], ["objectClass"], RequiredDerivedFacts: []);

    private static JudgementReader Opened(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value!;
    }

    private static string ADirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-evidence-kinds", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        // Written before the writer opens, because a judgement records the seal of the evidence it
        // was made against and refuses to open beside one that does not match.
        File.WriteAllText(
            BundleLayout.SealPath(directory),
            JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, ThisCapture)));

        return directory;
    }

    /// <summary>One kind of evidence, as a finding that can be stored and read back.</summary>
    private sealed record Sample(
        RuleDefinition Rule,
        string DistinguishedName,
        FindingEvidence Evidence,
        Action<FindingEvidence> AssertRead)
    {
        public Finding Finding => new(
            Rule.Id,
            Rule.Version,
            Rule.Severity,
            new FindingSubject(FindingSubjectKind.Account, Rule.Id),
            Guid.NewGuid(),
            DistinguishedName,
            "contoso.com",
            "user",
            $"Sample finding for {Evidence.GetType().Name}.",
            EvidenceCompleteness.Complete,
            Evidence);
    }
}
