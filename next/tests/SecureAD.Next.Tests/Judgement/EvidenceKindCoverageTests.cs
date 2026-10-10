using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;
using Xunit.Abstractions;

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
/// <c>RuleGuidanceTests</c>, and declared inputs by <c>RuleDeclarationTests</c>. <b>Its public types
/// are held by nothing.</b> <c>SurfaceRegisterTests</c> and <c>TypesTableOwnershipTests</c> covered
/// them until 2026-09-12, when both were deleted with the other documentation gates, and nothing
/// has replaced them - that is <c>P-182</c>.
/// </para>
/// </remarks>
public sealed class EvidenceKindCoverageTests(ITestOutputHelper output)
{
    private const string ThisCapture = "0f9c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

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
        new Sample(new BroadAdministrativeGroupMembership().Definition, "CN=Renamed domain administrators,DC=contoso,DC=com",
            new BroadAdministrativeMembershipEvidence(ThisCapture, Guid.NewGuid(), new('a', 64),
                SecureAD.Derivation.PrincipalClassificationRegistry.Version, BroadAdministrativeGroupMembership.PolicyVersion,
                "DC=contoso,DC=com", "CN=Configuration,DC=contoso,DC=com", Guid.NewGuid(), [], [], [], [], true, []),
            read =>
            {
                var evidence = Assert.IsType<BroadAdministrativeMembershipEvidence>(read);
                Assert.Equal(2, evidence.Principals.Count);
                Assert.Equal("S-1-5-21-1-2-3-513", Assert.Single(evidence.BroadSources).Sid);
                var witness = Assert.Single(Assert.Single(evidence.Links).Witnesses);
                Assert.Equal(("member", 0, "CN=Renamed broad global group,DC=contoso,DC=com"),
                    (witness.Attribute, witness.Ordinal, witness.Value));
                Assert.True(evidence.IsComplete);
            }),
        new Sample(new DuplicateServicePrincipalNames().Definition, "CN=SPN owner,DC=contoso,DC=com",
            new DuplicateSpnEvidence(ThisCapture, "contoso.com", Guid.NewGuid(), [], []),
            read =>
            {
                var evidence = Assert.IsType<DuplicateSpnEvidence>(read);
                Assert.Equal(2, evidence.Duplicates.Count);
                Assert.Equal(3, evidence.Duplicates[0].Occurrences.Count);
                Assert.All(evidence.Duplicates, match => Assert.Equal(2, match.Owners.Count));
            }),
        new Sample(
            new CircularGroupMembership().Definition,
            "CN=Cycle A,DC=contoso,DC=com",
            CycleSample(),
            read =>
            {
                var cycle = Assert.IsType<CircularMembershipEvidence>(read);
                Assert.Equal(2, cycle.Groups.Count);
                Assert.Equal(2, cycle.Links.Count);
                Assert.All(cycle.Links, link => Assert.Equal(2, link.Witnesses.Count));
                Assert.True(cycle.InventoryComplete);
                Assert.Contains(cycle.Groups, group => group.DistinguishedName == "CN=Cycle A,DC=contoso,DC=com");
                Assert.Contains(cycle.Groups, group => group.DistinguishedName == "CN=Cycle B,DC=contoso,DC=com");
            }),
        new Sample(
            new UnexpectedTier0Route().Definition,
            "CN=Alice,DC=contoso,DC=com",
            new Tier0RouteFindingEvidence(Guid.NewGuid(), null, ThisCapture, new('a', 64),
                "Tier0ControlPlane", Guid.NewGuid(), "S-1-5-21-1-2-3-1100", "CN=Alice,DC=contoso,DC=com", 3, new('b', 64)),
            read =>
            {
                var evidence = Assert.IsType<Tier0RouteFindingEvidence>(read);
                Assert.Equal("Tier0ControlPlane", evidence.Anchor);
                Assert.Equal(3, evidence.UnexpectedChecks);
                Assert.NotEqual(Guid.Empty, evidence.GenerationId);
                Assert.NotEqual(Guid.Empty, evidence.RequesterGuid);
                Assert.Equal(64, evidence.CalculationFingerprint.Length);
                Assert.Equal(64, evidence.QualificationFingerprint.Length);
            }),
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

        // Awkward on the axes that matter for this kind: the WriteOwner right, which is the one
        // whose truth depends on the forest not having blocked owner rights, reached at depth two
        // through a nested group, with an unnamed broad principal and a walk that did not finish.
        // A reader that keyed this off the nullable inherited_from or trustee_name columns, that
        // dropped the separate path table, or that attached SEC-090's path to this finding, gives a
        // different answer to at least one of these.
        new Sample(
            Definition("SEC-060", "A broad principal can take over an object"),
            "OU=Applications,DC=contoso,DC=com",
            new ObjectTakeoverEvidence(
                TrusteeSid: "S-1-5-21-1004336348-1177238915-682003330-1201",
                TrusteeName: "App-Admins",
                BroadPrincipalSid: "S-1-5-21-1004336348-1177238915-682003330-513",
                BroadPrincipalName: null,
                MembershipPath:
                [
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-1201", "App-Admins"),
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-1202", "App-Operators"),
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-513", null),
                ],
                Right: ObjectTakeoverRight.WriteOwner,
                InheritedFrom: null,
                ExpansionWasComplete: false),
            read =>
            {
                var e = Assert.IsType<ObjectTakeoverEvidence>(read);
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-1201", e.TrusteeSid);
                Assert.Equal("App-Admins", e.TrusteeName);
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-513", e.BroadPrincipalSid);
                Assert.Null(e.BroadPrincipalName);
                Assert.Equal(3, e.MembershipPath.Count);
                Assert.Equal("App-Admins", e.MembershipPath[0].Name);
                Assert.Null(e.MembershipPath[^1].Name);
                Assert.Equal(2, e.NestingDepth);
                Assert.Equal(ObjectTakeoverRight.WriteOwner, e.Right);
                Assert.True(e.ThroughOwnership);

                // Set on the object itself rather than inherited, which is the null the
                // discriminator must not be keyed off.
                Assert.Null(e.InheritedFrom);
                Assert.False(e.IsComplete);
            }),

        // Awkward on the axes that matter for this kind: an owner that no longer exists, which is
        // the state carrying the opposite remedy, on a class the owner-rights hardening could never
        // have applied to, with no name in this bundle and a walk that finished. A reader that
        // keyed this off the nullable owner_name column, or that flattened the standing to a
        // boolean, gives a different answer to at least one of these.
        new Sample(
            Definition("SEC-031", "An object is owned by somebody who is not an administrator"),
            "OU=Finance,DC=contoso,DC=com",
            new ObjectOwnershipEvidence(
                OwnerSid: "S-1-5-21-1004336348-1177238915-682003330-1310",
                OwnerName: null,
                Standing: ObjectOwnerStanding.DoesNotExist,
                ObjectClass: "organizationalUnit",
                MembershipWasComplete: true),
            read =>
            {
                var e = Assert.IsType<ObjectOwnershipEvidence>(read);
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-1310", e.OwnerSid);
                Assert.Null(e.OwnerName);
                Assert.Equal(ObjectOwnerStanding.DoesNotExist, e.Standing);
                Assert.True(e.IsOrphaned);
                Assert.Equal("organizationalUnit", e.ObjectClass);

                // The owner has no name here, so the display falls back to the identifier rather
                // than showing an empty cell.
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-1310", e.Display);
                Assert.True(e.IsComplete);
            }),

        // Awkward on the axes that matter for this kind: a decryptor named as a qualified name
        // rather than an identifier, reached at depth two, with a walk that completed. A reader
        // that keyed the evidence off either nullable identifier column, that dropped the separate
        // path table, or that confused this route with SEC-090's, gives a different answer to at
        // least one of these.
        new Sample(
            Definition("SEC-093", "A broad principal can decrypt LAPS passwords"),
            "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=com",
            new LapsDecryptorEvidence(
                PolicyDisplayName: "Windows LAPS",
                ConfiguredValue: @"CONTOSO\LAPS-Decryptors",
                Form: LapsDecryptorForm.QualifiedName,
                DecryptorSid: "S-1-5-21-1004336348-1177238915-682003330-1180",
                DecryptorName: "LAPS-Decryptors",
                BroadPrincipalSid: "S-1-5-21-1004336348-1177238915-682003330-513",
                BroadPrincipalName: "Domain Users",
                MembershipPath:
                [
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-1180", "LAPS-Decryptors"),

                    // Deliberately unnamed, for the reason the SEC-090 sample gives.
                    new PathStep("S-1-5-21-1004336348-1177238915-682003330-1190", null),
                    new PathStep(
                        "S-1-5-21-1004336348-1177238915-682003330-513", "Domain Users"),
                ],
                ExpansionWasComplete: true),
            read =>
            {
                var e = Assert.IsType<LapsDecryptorEvidence>(read);
                Assert.Equal("Windows LAPS", e.PolicyDisplayName);
                Assert.Equal(@"CONTOSO\LAPS-Decryptors", e.ConfiguredValue);
                Assert.Equal(LapsDecryptorForm.QualifiedName, e.Form);
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-1180", e.DecryptorSid);
                Assert.Equal("LAPS-Decryptors", e.DecryptorName);
                Assert.Equal("S-1-5-21-1004336348-1177238915-682003330-513", e.BroadPrincipalSid);
                Assert.Equal("Domain Users", e.BroadPrincipalName);
                Assert.Equal(3, e.MembershipPath.Count);
                Assert.Null(e.MembershipPath[1].Name);
                Assert.Equal(2, e.NestingDepth);
                Assert.True(e.BroadPrincipalFound);
                Assert.True(e.IsComplete);
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
        var findings = OwnAccountMembershipPathTests.ReadMixedEvidenceSample(
            Samples.Where(sample => sample.Evidence is not (Tier0RouteFindingEvidence or CircularMembershipEvidence or DuplicateSpnEvidence
                or BroadAdministrativeMembershipEvidence))
                .Select(sample => (IRule)new SampleRule(sample)).ToArray(), output)
            .Concat(DuplicateSpnTests.ReadPublishedFindings().Take(1))
            .Concat(BroadAdministrativeGroupMembershipTests.ReadPublishedFindings()).ToArray();

        foreach (var sample in Samples)
        {
            var found = Assert.Single(
                findings, f => f.RuleId == sample.Rule.Id);

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

    private static CircularMembershipEvidence CycleSample()
    {
        var a = new CircularMembershipGroup(Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "CN=Cycle A,DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-1800", null);
        var b = new CircularMembershipGroup(Guid.Parse("22222222-2222-2222-2222-222222222222"),
            "CN=Cycle B,DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-1801", null);
        return new(ThisCapture, Guid.NewGuid(), CircularMembershipIndex.Key([a, b]), [a, b],
            [new(a.ObjectGuid, b.ObjectGuid, [new(a.ObjectGuid, "member", 0, b.DistinguishedName)]),
                new(b.ObjectGuid, a.ObjectGuid, [new(b.ObjectGuid, "member", 0, a.DistinguishedName)])], true);
    }

    private sealed class SampleRule(Sample sample) : IObjectRule
    {
        public RuleDefinition Definition => sample.Rule;
        public RuleVerdict Judge(ObjectAttributes subject) => RuleVerdict.Judged(
            subject.DistinguishedName == "CN=Alice,DC=contoso,DC=com" ? [sample.Finding] : []);
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
