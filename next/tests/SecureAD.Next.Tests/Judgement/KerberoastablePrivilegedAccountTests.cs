using System.Globalization;
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
/// SEC-021 against the cases its specification names.
/// </summary>
/// <remarks>
/// <para>
/// <b>These run the whole stage rather than calling the rule directly</b>, for the reason
/// <c>AdminCountWithoutProtectionTests</c> gives: a test that handed the rule a fabricated
/// <c>JudgingContext</c> would prove the rule agrees with itself. Each builds a sealed bundle, derives
/// it, judges it and reads the judgement back, so an account is privileged here only because the
/// derivation worked it out from a real group membership.
/// </para>
/// <para>
/// <b>The negative controls are the rule.</b> SEC-021 exists to be quiet about the service accounts
/// that fill a real forest and loud about the handful that are privileged, so a rule that reported
/// everything with a service name would satisfy every positive test here.
/// </para>
/// </remarks>
public sealed class KerberoastablePrivilegedAccountTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);

    private const string DomainSid = "S-1-5-21-11-22-33";
    private const string Forest = "ad.lab";

    /// <summary>The Domain Admins group, which the derivation treats as a protected root.</summary>
    private const string DomainAdmins = DomainSid + "-512";

    /// <summary>
    /// A privileged account with a service name is reported, at Critical.
    /// </summary>
    [Fact]
    public void APrivilegedAccountWithAServiceNameIsReported()
    {
        var finding = Assert.Single(Judge(Svc() with { Privileged = true }));

        Assert.Equal("SEC-021", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);

        var evidence = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence);
        Assert.Equal(DomainSid + "-1105", evidence.ObjectSid);
        Assert.Equal(["MSSQLSvc/db01.ad.lab:1433"], evidence.ServicePrincipalNames);
        Assert.False(evidence.IsDisabled);
    }

    /// <summary>
    /// A privileged account with no service name is not reported.
    /// </summary>
    /// <remarks>
    /// The commonest privileged account in any forest. It is not kerberoastable: there is no ticket
    /// to ask for.
    /// </remarks>
    [Fact]
    public void APrivilegedAccountWithNoServiceNameIsNotReported() =>
        Assert.Empty(Judge(Svc() with { Privileged = true, ServicePrincipalNames = [] }));

    /// <summary>
    /// An ordinary account with a service name is not reported.
    /// </summary>
    /// <remarks>
    /// <b>This is the rule.</b> Every application in an estate runs as an account like this, and
    /// Microsoft scopes its own recommendation the same way - of removing a service principal name
    /// it says "This recommendation only showed for sensitive accounts." A rule without this control
    /// would pass every other test here while reporting the whole forest.
    /// </remarks>
    [Fact]
    public void AnOrdinaryAccountWithAServiceNameIsNotReported() =>
        Assert.Empty(Judge(Svc() with { Privileged = false }));

    /// <summary>
    /// A privileged computer account with a service name is not reported.
    /// </summary>
    /// <remarks>
    /// <b>The trap this catches is that a computer's objectClass contains "user".</b> The chain is
    /// <c>top, person, organizationalPerson, user, computer</c>, so a rule asking whether "user" is
    /// present reports every domain controller in the forest - each of which has service names and
    /// is a member of a protected group. Their passwords are machine-generated at 120 characters and
    /// rotated, so there is nothing to crack.
    /// </remarks>
    [Fact]
    public void APrivilegedComputerWithAServiceNameIsNotReported()
    {
        var findings = Judge(Svc() with
        {
            Privileged = true,
            ObjectClasses = ["top", "person", "organizationalPerson", "user", "computer"],
        });

        Assert.Empty(findings);
    }

    /// <summary>
    /// A privileged group managed service account with a service name is not reported.
    /// </summary>
    /// <remarks>
    /// It is Microsoft's own recommended remedy for this finding - its password is generated and
    /// rotated by Windows. Reporting it would report the fix as the defect.
    /// </remarks>
    [Fact]
    public void APrivilegedGroupManagedServiceAccountIsNotReported()
    {
        var findings = Judge(Svc() with
        {
            Privileged = true,
            ObjectClasses =
                ["top", "person", "organizationalPerson", "user", "computer",
                 "msDS-GroupManagedServiceAccount"],
        });

        Assert.Empty(findings);
    }

    /// <summary>
    /// A disabled privileged account is reported, and the wording says it is disabled.
    /// </summary>
    /// <remarks>
    /// <b>This departs from the predecessor's card</b>, which excluded disabled accounts on the
    /// stated basis that a key distribution centre will not issue a ticket for one. Microsoft's
    /// Kerberos material was searched for that statement and it was not found, so excluding them
    /// would rest on a belief this product cannot evidence - the position SEC-022 reached about
    /// AS-REP. The state travels in the evidence and the wording instead.
    /// </remarks>
    [Fact]
    public void ADisabledPrivilegedAccountIsReportedAndSaidToBeDisabled()
    {
        var finding = Assert.Single(
            Judge(Svc() with { Privileged = true, UserAccountControl = 0x202 }));

        Assert.True(Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence).IsDisabled);
        Assert.Contains("currently disabled", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every service name reaches the finding, not only the first.
    /// </summary>
    /// <remarks>
    /// An operator deciding whether the account really runs a service needs to see what it claims to
    /// run. One name out of three answers a narrower question than the one he has.
    /// </remarks>
    [Fact]
    public void EveryServiceNameReachesTheFinding()
    {
        var finding = Assert.Single(Judge(Svc() with
        {
            Privileged = true,
            ServicePrincipalNames =
                ["MSSQLSvc/db01.ad.lab:1433", "HOST/db01.ad.lab", "HTTP/reports.ad.lab"],
        }));

        var evidence = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence);

        Assert.Equal(
            ["MSSQLSvc/db01.ad.lab:1433", "HOST/db01.ad.lab", "HTTP/reports.ad.lab"],
            evidence.ServicePrincipalNames);

        foreach (var spn in evidence.ServicePrincipalNames)
            Assert.Contains(spn, finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// The wording offers the three remedies and never claims the account is then safe.
    /// </summary>
    [Fact]
    public void TheWordingOffersTheRemediesWithoutClaimingSafety()
    {
        var finding = Assert.Single(Judge(Svc() with { Privileged = true }));

        Assert.Contains("remove the service name", finding.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("group managed service account", finding.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("says nothing about any other", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// The rule declares the derived fact it reads, and refuses to judge without it.
    /// </summary>
    /// <remarks>
    /// The declaration is what lets <c>JudgingRun</c> refuse a bundle nobody derived, per
    /// <c>docs/decisions/0091</c>, rather than producing a per-object "could not judge" for every
    /// account in the forest.
    /// </remarks>
    [Fact]
    public void TheRuleDeclaresItsDerivedFactAndRefusesToJudgeWithoutIt()
    {
        var rule = new KerberoastablePrivilegedAccount();

        Assert.Contains(
            nameof(DerivedFactKind.ProtectedPrincipals), rule.Definition.RequiredDerivedFacts);

        Assert.Throws<InvalidOperationException>(() => rule.Judge(
            new ObjectAttributes(
                "CN=x,DC=ad,DC=lab",
                Guid.NewGuid(),
                Started,
                EvidenceCompleteness.Complete,
                [],
                DomainFqdn: Forest)));
    }

    /// <summary>
    /// The key distribution centre's own account is not reported.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This test exists because the product got it wrong against a real forest.</b> On 2026-09-02
    /// the first `ad.lab` run reported `krbtgt` in all three domains at **Critical**, telling the
    /// operator to remove its service name or replace it with a group managed service account.
    /// Neither is possible, and either would break Kerberos for the domain.
    /// </para>
    /// <para>
    /// <b>The values here are the ones the directory actually held</b>: relative identifier 502,
    /// service name <c>kadmin/changepw</c>, disabled. Nothing about them was invented to suit the
    /// fix, which is why this fails if the exclusion is removed.
    /// </para>
    /// <para>
    /// <b>Excluded by relative identifier, not by name</b>, so renaming the account does not bring
    /// the finding back.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheKeyDistributionCentreAccountIsNotReported()
    {
        var findings = Judge(Svc() with
        {
            Privileged = true,
            Dn = "CN=krbtgt,CN=Users,DC=ad,DC=lab",
            Sid = DomainSid + "-502",
            ServicePrincipalNames = ["kadmin/changepw"],
            UserAccountControl = 0x202,
        });

        Assert.Empty(findings);
    }

    /// <summary>
    /// Renaming the key distribution centre account does not bring the finding back.
    /// </summary>
    /// <remarks>
    /// The other half of "by identifier and not by name". Without it an exclusion keyed on the
    /// string "krbtgt" would satisfy the test above.
    /// </remarks>
    [Fact]
    public void TheKeyDistributionCentreAccountIsExcludedEvenWhenRenamed()
    {
        var findings = Judge(Svc() with
        {
            Privileged = true,
            Dn = "CN=kerberos-service,CN=Users,DC=ad,DC=lab",
            Sid = DomainSid + "-502",
            ServicePrincipalNames = ["kadmin/changepw"],
        });

        Assert.Empty(findings);
    }

    /// <summary>
    /// An ordinary privileged account is still reported, so the exclusion is not a blanket one.
    /// </summary>
    /// <remarks>
    /// A rule that excluded everything would pass both tests above. This is what stops that.
    /// </remarks>
    [Fact]
    public void AnAccountBesideTheKeyDistributionCentreIdentifierIsStillReported()
    {
        Assert.Single(Judge(Svc() with { Privileged = true, Sid = DomainSid + "-503" }));
    }

    [Fact]
    public void OneStoredFindingSummarizesIndependentRoutesIncludingTheLongerOne()
    {
        var finding = Assert.Single(Judge(Svc() with { Privileged = true, MultipleRoutes = true }));
        var evidence = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence);
        Assert.Equal(2, finding.RuleVersion);
        Assert.Equal(2, evidence.MembershipRoutes.Memberships.Count);
        Assert.Equal(3, evidence.MembershipRoutes.Memberships.Sum(m => m.Routes.Count));
        Assert.Contains(evidence.MembershipRoutes.Memberships.SelectMany(m => m.Routes), r => r.Steps.Count == 4);
        Assert.All(evidence.MembershipRoutes.Memberships, m => Assert.NotNull(m.InitialMembership.DistinguishedName));
        Assert.Contains("2 membership routes", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("does not establish that every other form of privilege is gone", finding.Detail, StringComparison.Ordinal);
        Assert.True(evidence.MembershipRoutes.IsComplete);
    }

    [Fact]
    public void KnownRoutesAndTheFindingSurviveIncompleteMembershipEvidence()
    {
        var stored = JudgeStore(Svc() with { Privileged = true, MultipleRoutes = true, MissingMember = true });
        var finding = Assert.Single(stored.Findings);
        var summary = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence).MembershipRoutes;
        Assert.Equal(2, summary.Memberships.Count);
        Assert.False(summary.IsComplete);
        Assert.Contains("Partial membership summary", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("not a total", finding.Detail, StringComparison.Ordinal);
        Assert.False(stored.EveryRuleReachedEveryVerdict);
    }

    [Fact]
    public void ADirectCatalogueClaimSurvivesAlongsideMembershipEvidence()
    {
        var finding = Assert.Single(Judge(Svc() with { Privileged = true, Sid = DomainSid + "-500" }));
        var evidence = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence);
        Assert.NotNull(evidence.DirectProtectionCatalogueEntryId);
        Assert.NotNull(evidence.DirectProtectionName);
        Assert.NotNull(evidence.ProtectionCatalogueVersion);
        Assert.Single(evidence.MembershipRoutes.Memberships);
        Assert.Contains("protected in its own right", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void DistributionPathsAreStoredAsProtectionNotAuthorization()
    {
        var finding = Assert.Single(Judge(Svc() with { Privileged = true, MultipleRoutes = true, DistributionRoute = true }));
        var summary = Assert.IsType<KerberoastableAccountEvidence>(finding.Evidence).MembershipRoutes;
        Assert.Contains(summary.Memberships.SelectMany(m => m.Routes), r =>
            r.Authorization == MembershipRouteAuthorization.DistributionGroup && r.EstablishesProtection);
        Assert.Contains("without authorization", finding.Detail, StringComparison.Ordinal);
        Assert.Contains(summary.Memberships.SelectMany(m => m.Routes), r => r.Authorization == MembershipRouteAuthorization.SecurityEnabled);
    }

    /// <summary>One object's shape, so each test states only what it changes.</summary>
    private sealed record Subject
    {
        public string Dn { get; init; } = "CN=svc-sql,DC=ad,DC=lab";
        public string Sid { get; init; } = DomainSid + "-1105";
        public IReadOnlyList<string> ObjectClasses { get; init; } = ["top", "person", "user"];
        public IReadOnlyList<string> ServicePrincipalNames { get; init; } =
            ["MSSQLSvc/db01.ad.lab:1433"];

        public uint UserAccountControl { get; init; } = 0x200;

        /// <summary>
        /// Whether the account is made a member of Domain Admins, which is what the derivation reads
        /// to establish protection. Nothing in these tests asserts privilege directly.
        /// </summary>
        public bool Privileged { get; init; }
        public bool MultipleRoutes { get; init; }
        public bool MissingMember { get; init; }
        public bool DistributionRoute { get; init; }
    }

    private static Subject Svc() => new();

    private static IReadOnlyList<Finding> Judge(Subject subject) => JudgeStore(subject).Findings;

    private static StoredJudgement JudgeStore(Subject subject)
    {
        var directory = Build(subject);

        Assert.True(
            Stage2aRun.Derive(
                directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched,
                RunLog.Discarded, CancellationToken.None).IsSuccess);

        var judged = JudgingRun.Judge(
            directory,
            [new KerberoastablePrivilegedAccount()],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);

        using var reader = JudgementReader.Open(directory).Value!;
        return reader.Read();
    }

    private static string Build(Subject subject)
    {
        var directory = TempDirectories.Create("sec021-tests");

        Directory.CreateDirectory(directory);

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(Partition);

            var attributes = new List<EvidenceAttribute>
            {
                Multi("objectClass", subject.ObjectClasses),
                Binary("objectSid", SidBytes(subject.Sid)),
                Text("userAccountControl",
                    subject.UserAccountControl.ToString(CultureInfo.InvariantCulture)),
            };

            if (subject.ServicePrincipalNames.Count > 0)
                attributes.Add(Multi("servicePrincipalName", subject.ServicePrincipalNames));

            writer.WriteObject(
                new EvidenceObject(Partition, subject.Dn, Guid.NewGuid(), attributes, Started));

            // Domain Admins exists either way. Membership is what changes, so the only difference
            // between a reported and an unreported account is the thing the rule is about.
            WriteGroup(writer, "Domain Admins", DomainAdmins,
                subject.Privileged ? subject.Dn : null);

            if (subject.MultipleRoutes)
            {
                WriteGroup(writer, "Long initial", DomainSid + "-1200", subject.Dn,
                    subject.DistributionRoute ? "2" : "-2147483646");
                WriteGroup(writer, "Long outer", DomainSid + "-1201", "CN=Long initial,DC=ad,DC=lab");
                writer.WriteObject(new EvidenceObject(Partition, "CN=Enterprise Admins,DC=ad,DC=lab", Guid.NewGuid(),
                    [Text("objectClass", "group"), Binary("objectSid", SidBytes(DomainSid + "-519")),
                     Text("groupType", "-2147483646"),
                     Multi("member", ["CN=Domain Admins,DC=ad,DC=lab", "CN=Long outer,DC=ad,DC=lab"])], Started));
            }
            if (subject.MissingMember)
                WriteGroup(writer, "Unresolved", DomainSid + "-1209", "CN=not-captured,DC=ad,DC=lab");

            // The one object per forest carrying dSHeuristics. Without it the exclusion mask reads
            // as never-looked and every principal is conservatively Unknown, so a positive case
            // would silently stop being one.
            writer.WriteObject(
                new EvidenceObject(
                    Partition,
                    "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=ad,DC=lab",
                    Guid.NewGuid(),
                    [Text("objectClass", "nTDSService"), Text("dSHeuristics", "0")],
                    Started));

            writer.Complete(Coverage, Started.AddMinutes(1));
        }

        return directory;
    }

    private static void WriteGroup(
        BundleWriter writer, string name, string sid, string? member, string groupType = "-2147483646")
    {
        var attributes = new List<EvidenceAttribute>
        {
            Text("objectClass", "group"),
            Binary("objectSid", SidBytes(sid)),
            Text("groupType", groupType),
        };

        if (member is not null)
            attributes.Add(Text("member", member));

        writer.WriteObject(
            new EvidenceObject(
                Partition, $"CN={name},DC=ad,DC=lab", Guid.NewGuid(), attributes, Started));
    }

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

    private static EvidenceAttribute Multi(string name, IReadOnlyList<string> values) =>
        new(name, StoredAttributeCompleteness.Complete,
            [.. values.Select(EvidenceValue.OfText)]);

    private static EvidenceAttribute Binary(string name, byte[] bytes) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)]);

    private static byte[] SidBytes(string text) =>
        Sid.ToBytes(text)
        ?? throw new InvalidOperationException($"'{text}' is not a SID this product will encode.");
}
