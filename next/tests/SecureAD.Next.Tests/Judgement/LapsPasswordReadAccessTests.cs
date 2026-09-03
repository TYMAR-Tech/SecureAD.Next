using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-090 against the cases its specification names.
/// </summary>
/// <remarks>
/// <para>
/// <b>The negative controls are the rule.</b> A rule that reported every delegated principal would
/// satisfy the positive test below and would report an entire estate - which is exactly what the
/// predecessor's card did, and is the thing <c>P-123</c> exists to stop. Six of the tests here exist
/// to fail if the rule ever starts claiming to know what an organisation intended.
/// </para>
/// <para>
/// <b>These drive the rule directly rather than through a bundle</b>, because what is under test is
/// the reading of a security descriptor against a group expansion, and both are handed over through
/// <see cref="JudgingContext"/>. The whole-stage path is exercised by the shared evidence sample in
/// <c>EvidenceKindCoverageTests</c>, which writes and reads this evidence kind through the store.
/// </para>
/// </remarks>
public sealed class LapsPasswordReadAccessTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    private const string Machine = "CN=WS01,OU=Workstations,DC=ad,DC=lab";
    private const string Forest = "ad.lab";

    private const string PasswordGuid = "53c5be7e-5403-4013-a04b-b22e05d0e3c1";
    private const string EncryptedGuid = "f3531ec6-6330-4f8e-8d39-7a671fbac605";
    private const string LegacyGuid = "2e0e4a88-f5fa-11df-b3af-001fc000a000";
    private const string UnrelatedGuid = "bf967a0e-0de6-11d0-a285-00aa003049e2";

    private const string Delegated = "S-1-5-21-1-2-3-1123";
    private const string Intermediate = "S-1-5-21-1-2-3-1145";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string Everyone = "S-1-1-0";

    private const int ReadProperty = 0x10;
    private const int ControlAccess = 0x100;

    /// <summary>
    /// Two delegated groups that both reach the same broad principal produce one finding, by the
    /// shortest route.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This aborted a whole audit of <c>ba.ad.lab</c> on 2026-09-03.</b> A finding is identified
    /// by its rule, its subject and its object so that an acceptance stays attached across runs, and
    /// the subject here is the broad principal. Two findings naming the same principal on the same
    /// computer violate that identity, and the judging died on a uniqueness constraint rather than
    /// reporting anything at all - so a defect in one rule took every other rule's results with it.
    /// </para>
    /// <para>
    /// <b>The shortest route is kept</b>, for the reason the walk is breadth first: it is the link
    /// an operator would cut, and showing the longer chain would send him to the wrong one.
    /// </para>
    /// </remarks>
    [Fact]
    public void TwoRoutesToTheSameBroadPrincipalAreOneFindingByTheShortestPath()
    {
        var finding = Assert.Single(Judge(
            [
                Allow("S-1-5-21-9-9-9-1000", ReadProperty | ControlAccess, PasswordGuid),
                Allow("S-1-5-21-9-9-9-2000", ReadProperty | ControlAccess, PasswordGuid),
            ],
            sid => sid == "S-1-5-21-9-9-9-1000"

                // The long way round: two hops.
                ? new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded,
                    [new ExpandedPrincipal(
                        AuthenticatedUsers, Forest, [sid, Intermediate, AuthenticatedUsers], true)])

                // The short way: one hop, and the one to report.
                : new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded,
                    [new ExpandedPrincipal(
                        AuthenticatedUsers, Forest, [sid, AuthenticatedUsers], true)])));

        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.Equal(AuthenticatedUsers, evidence.BroadPrincipalSid);
        Assert.Equal(2, evidence.MembershipPath.Count);
        Assert.Equal("S-1-5-21-9-9-9-2000", evidence.TrusteeSid);
    }

    /// <summary>
    /// Two <i>different</i> broad principals on one computer are two findings, and the subject of
    /// each is the principal rather than the machine.
    /// </summary>
    /// <remarks>
    /// Settled by the owner on 2026-09-03: each route is accepted separately, so accepting one does
    /// not silence another that arrives later. The grid reads "Domain Users can read BAWK1".
    /// </remarks>
    [Fact]
    public void TwoBroadPrincipalsOnOneComputerAreTwoFindingsSubjectedToThePrincipal()
    {
        var findings = Judge(
            [
                Allow(Everyone, ReadProperty | ControlAccess, PasswordGuid),
                Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid),
            ],
            sid => sid == Everyone
                ? new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, [])
                : new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded,
                    [new ExpandedPrincipal(
                        AuthenticatedUsers, Forest, [sid, AuthenticatedUsers], true)]));

        Assert.Equal(2, findings.Count);

        // The subject is the broad principal, not the computer - which is what makes both storable
        // under the judgement store's identity for a finding.
        Assert.Equal(2, findings.Select(f => f.Subject.Key).Distinct().Count());
        Assert.All(findings, f => Assert.DoesNotContain("WS01", f.Subject.Key, StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Subject.Key.Contains("Everyone", StringComparison.Ordinal));
    }

    /// <summary>
    /// A delegated group holding both rights, with a broad principal nested inside it, is reported -
    /// and the finding carries the path.
    /// </summary>
    [Fact]
    public void ABroadPrincipalNestedInsideADelegatedGroupIsReported()
    {
        var finding = Assert.Single(Judge(
            [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)],
            Nested(Delegated, Intermediate, AuthenticatedUsers)));

        Assert.Equal("SEC-090", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);

        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.Equal(Delegated, evidence.TrusteeSid);
        Assert.Equal(AuthenticatedUsers, evidence.BroadPrincipalSid);
        Assert.Equal(LapsReadRights.Both, evidence.Rights);
        Assert.True(evidence.IsComplete);

        // P-123: naming the broad principal without the route does not tell an operator which link
        // to cut. The path is the finding, so it is pinned here and in the detail text.
        Assert.Equal(
            [Delegated, Intermediate, AuthenticatedUsers],
            evidence.MembershipPath.Select(s => s.Sid));
        Assert.Equal(2, evidence.NestingDepth);
        Assert.Contains(Intermediate, finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A delegation to a group containing only named administrators is silent.
    /// </summary>
    /// <remarks>
    /// <b>This is the whole of <c>P-123</c> expressed as a test.</b> The predecessor's rule fired on
    /// any principal outside a hard-coded administrator list, so this delegation would have been
    /// reported as an "unexpected principal". Nothing in the directory says whether it is correct,
    /// and only the organisation running the audit knows - so the product says nothing.
    /// </remarks>
    [Fact]
    public void ANarrowDelegationToOrdinaryAdministratorsIsNotReported() =>
        Assert.Empty(Judge(
            [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)],
            Nested(Delegated, "S-1-5-21-1-2-3-1500", "S-1-5-21-1-2-3-1501")));

    /// <summary>
    /// A grant of Read Property without Control Access is not reported.
    /// </summary>
    /// <remarks>
    /// Microsoft: where Read Property is set on a confidential attribute, Active Directory
    /// <i>also</i> requires Control Access. Without it the directory withholds the value, so
    /// reporting this principal would say it can read a password it cannot.
    /// </remarks>
    [Fact]
    public void ReadPropertyWithoutControlAccessIsNotReported() =>
        Assert.Empty(Judge(
            [Allow(Delegated, ReadProperty, PasswordGuid)],
            Nested(Delegated, AuthenticatedUsers)));

    /// <summary>
    /// A grant of Control Access without Read Property is not reported either.
    /// </summary>
    /// <remarks>
    /// <b>This is the predecessor's defect, pinned.</b> Its query was
    /// <c>(access_mask &amp; 256) != 0</c> and checked nothing else, so it reported exactly this
    /// case. The owner's decision of 2026-09-03 is that such a grant is a stated fact and never a
    /// finding.
    /// </remarks>
    [Fact]
    public void ControlAccessWithoutReadPropertyIsNotReported() =>
        Assert.Empty(Judge(
            [Allow(Delegated, ControlAccess, PasswordGuid)],
            Nested(Delegated, AuthenticatedUsers)));

    /// <summary>
    /// An entry naming a different attribute's GUID is not reported.
    /// </summary>
    [Fact]
    public void AnEntryScopedToAnotherAttributeIsNotReported() =>
        Assert.Empty(Judge(
            [Allow(Delegated, ReadProperty | ControlAccess, UnrelatedGuid)],
            Nested(Delegated, AuthenticatedUsers)));

    /// <summary>
    /// An object entry carrying no object type reaches the attribute, and is reported as reaching
    /// every attribute.
    /// </summary>
    /// <remarks>
    /// <b>Read from <c>ACE_OBJECT_TYPE_PRESENT</c> and not from whether the GUID is null.</b> This
    /// is the blanket extended-rights grant Microsoft tells administrators to hunt for on an
    /// organizational unit, because holders of it can read every confidential attribute - and all
    /// the LAPS password attributes are confidential.
    /// </remarks>
    [Fact]
    public void AnEntryWithNoObjectTypeReachesTheAttribute()
    {
        var finding = Assert.Single(Judge(
            [Allow(Delegated, ReadProperty | ControlAccess, objectTypeGuid: null)],
            Nested(Delegated, AuthenticatedUsers)));

        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.Equal(LapsGrantReach.EveryAttribute, evidence.Reach);
    }

    /// <summary>
    /// A deny entry preceding the allow cancels it, and nothing is reported.
    /// </summary>
    /// <remarks>
    /// Over-reporting here would tell a customer an exposure exists where the directory refuses the
    /// read, which is the direction that must never happen.
    /// </remarks>
    [Fact]
    public void ADenyBeforeTheAllowCancelsIt() =>
        Assert.Empty(Judge(
            [
                Deny(Delegated, ReadProperty | ControlAccess, PasswordGuid),
                Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid),
            ],
            Nested(Delegated, AuthenticatedUsers)));

    /// <summary>
    /// A deny <i>after</i> the allow does not cancel it, because Active Directory adds a deny only
    /// for rights it has not already granted.
    /// </summary>
    /// <remarks>
    /// <b>The opposite of the test above, and the reason <c>DaclWasCanonical</c> exists.</b> A
    /// non-canonical DACL is more open than its entries read, and a rule that treated any deny as
    /// cancelling would report this object as safe when the directory grants the read.
    /// </remarks>
    [Fact]
    public void ADenyAfterTheAllowDoesNotCancelIt() =>
        Assert.Single(Judge(
            [
                Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid),
                Deny(Delegated, ReadProperty | ControlAccess, PasswordGuid),
            ],
            Nested(Delegated, AuthenticatedUsers)));

    /// <summary>
    /// A direct grant to a broad principal is reported, with a path of one.
    /// </summary>
    /// <remarks>
    /// The expansion returns what is <i>inside</i> a principal, so the plainest form of this finding
    /// is the one case a rule reading only the expansion would miss.
    /// </remarks>
    [Fact]
    public void ADirectGrantToABroadPrincipalIsReported()
    {
        var finding = Assert.Single(Judge(
            [Allow(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid)],
            Nested(AuthenticatedUsers)));

        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.Equal([AuthenticatedUsers], evidence.MembershipPath.Select(s => s.Sid));
        Assert.Equal(0, evidence.NestingDepth);
    }

    /// <summary>
    /// A truncated expansion that found a broad principal reports it, and says the answer thinned
    /// out.
    /// </summary>
    [Fact]
    public void ATruncatedExpansionSaysSo()
    {
        var finding = Assert.Single(Judge(
            [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)],
            _ => new PrincipalExpansion(
                Delegated,
                PrincipalExpansionOutcome.StoppedAtBudget,
                [new ExpandedPrincipal(AuthenticatedUsers, Forest, [Delegated, AuthenticatedUsers], true)])));

        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.False(evidence.IsComplete);
    }

    /// <summary>
    /// A truncated expansion that found no broad principal must not report the object clean.
    /// </summary>
    /// <remarks>
    /// <b>Empty is not the same as safe unless the walk completed.</b> This is the case where a
    /// silent rule would be actively misleading, so the verdict is that the input could not be
    /// resolved rather than that nothing was found.
    /// </remarks>
    [Fact]
    public void ATruncatedExpansionFindingNothingDoesNotReportClean()
    {
        var verdict = Verdict(
            [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)],
            _ => new PrincipalExpansion(
                Delegated, PrincipalExpansionOutcome.StoppedAtBudget, []));

        Assert.Empty(verdict.Findings);
        Assert.Contains(
            verdict.Unresolved,
            u => u.Reason == UnresolvedReason.MembershipIncomplete);
    }

    /// <summary>
    /// A well-known trustee that is keyed forest-wide, not under the domain it was captured from,
    /// is still expanded — and does not poison the whole object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The forest found this and the rest of this file did not.</b> The first run against
    /// <c>ad.lab</c> asked for the expansion only at the trustee's captured domain. Well-known
    /// principals are real objects under <c>CN=WellKnown Security Principals</c> in the forest root,
    /// so they carry a domain — but the expansion keys them under the empty scope, so
    /// <c>SYSTEM</c> answered <c>PrincipalNotFound</c> on nearly every computer and SEC-090 reported
    /// <i>Indeterminate</i> across half the estate, hiding two real findings behind a rule that
    /// looked broken.
    /// </para>
    /// <para>
    /// Measured on 2026-09-03 against the derivation: <c>S-1-5-18</c>, <c>S-1-5-11</c>,
    /// <c>S-1-1-0</c>, <c>S-1-5-9</c> and <c>S-1-5-10</c> expand only at the empty scope;
    /// <c>S-1-5-32-544</c> and <c>S-1-5-32-548</c> only at a domain scope. Both directions have to
    /// work, which is why this test answers on scope rather than on SID.
    /// </para>
    /// </remarks>
    [Fact]
    public void AForestWideTrusteeIsExpandedAtTheForestScope()
    {
        var verdict = new LapsPasswordReadAccess().Judge(
            Computer(),
            Context(
                _ => Permissions(
                    DescriptorAvailability.Read,
                    [Allow("S-1-5-18", ReadProperty | ControlAccess, PasswordGuid)]),

                // Exactly what the derivation does: this SID is keyed forest-wide, so asking
                // under the domain the trustee was captured from finds nothing.
                (sid, scope) => scope.Length == 0
                    ? new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, [])
                    : new PrincipalExpansion(
                        sid, PrincipalExpansionOutcome.PrincipalNotFound, null)));

        Assert.Empty(verdict.Findings);

        // The point of the test: SYSTEM contains nothing, and saying so is an answer. Leaving it
        // unresolved marks the whole object unjudged and the whole rule Indeterminate.
        Assert.Empty(verdict.Unresolved);
    }

    /// <summary>
    /// A BUILTIN trustee, which carries no domain of its own, is expanded under the domain of the
    /// object being judged.
    /// </summary>
    /// <remarks>
    /// <b>The second half of the same defect, and it survived the first fix.</b> `S-1-5-32-544`
    /// exists in every domain and means a different group in each, so the expansion keys it under a
    /// domain — but the trustee has none, because the SID names no single captured object. What
    /// settles it is that `BUILTIN\Administrators` in a computer's access control list is that
    /// computer's domain's group. Measured against `ad.lab` on 2026-09-03: `S-1-5-32-544` expands
    /// at `ba.ad.lab` and at no other scope.
    /// </remarks>
    [Fact]
    public void ABuiltinTrusteeIsExpandedUnderTheJudgedObjectsDomain()
    {
        var verdict = new LapsPasswordReadAccess().Judge(
            Computer(),
            Context(
                _ => Permissions(
                    DescriptorAvailability.Read,
                    [AllowWithoutDomain("S-1-5-32-544", ReadProperty | ControlAccess, PasswordGuid)]),
                (sid, scope) => scope == Forest
                    ? new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, [])
                    : new PrincipalExpansion(
                        sid, PrincipalExpansionOutcome.PrincipalNotFound, null)));

        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.Unresolved);
    }

    /// <summary>
    /// An object that yields a finding <i>and</i> a trustee that could not be expanded reports the
    /// finding, and the finding says the answer is incomplete.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Losing either half is a real failure, and the forest showed both.</b> One access control
    /// list can name a group that expands cleanly and, beside it, a principal this bundle never
    /// captured. Reporting the finding alone presents a partial answer as a whole one — an operator
    /// would fix the broad principal named and never know another may sit behind the trustee nobody
    /// could expand.
    /// </para>
    /// <para>
    /// <b>But returning both on the verdict costs the findings entirely.</b> The judging counts an
    /// object carrying unresolved inputs as <i>not judged</i> and discards what it found: measured
    /// against <c>ad.lab</c> on 2026-09-03, doing that turned two real findings into zero. So the
    /// incompleteness travels on the finding, which is what
    /// <c>LapsPasswordReaderEvidence.IsComplete</c> is for.
    /// </para>
    /// </remarks>
    [Fact]
    public void AFindingCarriesTheIncompletenessOfATrusteeThatCouldNotBeExpanded()
    {
        var verdict = new LapsPasswordReadAccess().Judge(
            Computer(),
            Context(
                _ => Permissions(
                    DescriptorAvailability.Read,
                    [
                        Allow(AuthenticatedUsers, ReadProperty | ControlAccess, PasswordGuid),
                        Allow("S-1-5-21-9-9-9-4242", ReadProperty | ControlAccess, PasswordGuid),
                    ]),
                sid => sid == AuthenticatedUsers
                    ? new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, [])
                    : new PrincipalExpansion(
                        sid, PrincipalExpansionOutcome.PrincipalNotFound, null)));

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);

        // The finding survives - and says its own answer may not be the whole one.
        Assert.False(evidence.IsComplete);
        Assert.Contains(
            "Not every principal holding this access could be expanded",
            finding.Detail,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A trustee from a trusted forest, which this bundle never captured, is unresolved rather than
    /// silently treated as not broad.
    /// </summary>
    [Fact]
    public void AnUncapturedTrusteeIsUnresolved()
    {
        var verdict = Verdict(
            [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)],
            _ => new PrincipalExpansion(
                Delegated, PrincipalExpansionOutcome.PrincipalNotFound, null));

        Assert.Empty(verdict.Findings);
        Assert.NotEmpty(verdict.Unresolved);
    }

    /// <summary>
    /// An object whose security descriptor was never read is unresolved, not clean.
    /// </summary>
    /// <remarks>
    /// A production domain returned 19,927 of 100,000 objects with no readable descriptor. Reporting
    /// those as granting nothing would say an object is safe when nobody knows whether it is.
    /// </remarks>
    [Fact]
    public void AnUnreadableDescriptorIsUnresolved()
    {
        var verdict = new LapsPasswordReadAccess().Judge(
            Computer(),
            Context(
                _ => Permissions(DescriptorAvailability.Unreadable, []),
                Nested(Delegated, AuthenticatedUsers)));

        Assert.Empty(verdict.Findings);
        Assert.Contains(
            verdict.Unresolved,
            u => u.Reason == UnresolvedReason.SecurityDescriptorUnreadable);
    }

    /// <summary>
    /// A forest whose schema carries no LAPS attribute is not reported, machine by machine.
    /// </summary>
    /// <remarks>
    /// No object in such a forest can carry a password, so there is nothing to be delegated read of.
    /// That is a fact about the forest, and reporting every computer would report the estate for the
    /// state of its schema.
    /// </remarks>
    [Fact]
    public void AForestWithoutTheLapsSchemaIsNotReported()
    {
        var verdict = new LapsPasswordReadAccess().Judge(
            Computer(),
            Context(
                _ => Permissions(
                    DescriptorAvailability.Read,
                    [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)]),
                Nested(Delegated, AuthenticatedUsers),
                schema: new SchemaGuidCatalog([])));

        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.Unresolved);
    }

    /// <summary>
    /// A disabled computer account is not reported.
    /// </summary>
    [Fact]
    public void ADisabledComputerIsNotReported() =>
        Assert.Empty(Judge(
            [Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid)],
            Nested(Delegated, AuthenticatedUsers),
            userAccountControl: 4098));

    /// <summary>
    /// One delegation reaching one broad principal across all three attributes is one finding.
    /// </summary>
    /// <remarks>
    /// <c>Set-LapsADReadPasswordPermission</c> grants across the LAPS password attributes as a set,
    /// so the same principal holds an entry on each. Reporting three findings would present one
    /// delegation as three problems.
    /// </remarks>
    [Fact]
    public void OneDelegationAcrossThreeAttributesIsOneFinding() =>
        Assert.Single(Judge(
            [
                Allow(Delegated, ReadProperty | ControlAccess, PasswordGuid),
                Allow(Delegated, ReadProperty | ControlAccess, EncryptedGuid),
                Allow(Delegated, ReadProperty | ControlAccess, LegacyGuid),
            ],
            Nested(Delegated, AuthenticatedUsers)));

    /// <summary>
    /// The rule declares the expansion it reads, so a judging without it is refused before it
    /// starts rather than reporting per-object silence.
    /// </summary>
    [Fact]
    public void TheRuleDeclaresTheExpansionAndRefusesWithoutIt()
    {
        var rule = new LapsPasswordReadAccess();

        Assert.Contains(
            nameof(DerivedFactKind.PrincipalExpansion), rule.Definition.RequiredDerivedFacts);

        Assert.Throws<InvalidOperationException>(() => rule.Judge(Computer()));
    }

    private static IReadOnlyList<Finding> Judge(
        IReadOnlyList<PermissionEntry> entries,
        Func<string, PrincipalExpansion> expand,
        uint userAccountControl = 4096) =>
        Verdict(entries, expand, userAccountControl).Findings;

    private static RuleVerdict Verdict(
        IReadOnlyList<PermissionEntry> entries,
        Func<string, PrincipalExpansion> expand,
        uint userAccountControl = 4096) =>
        new LapsPasswordReadAccess().Judge(
            Computer(userAccountControl),
            Context(_ => Permissions(DescriptorAvailability.Read, entries), expand));

    /// <summary>
    /// An expansion that puts everything after the first named principal inside the first.
    /// </summary>
    private static Func<string, PrincipalExpansion> Nested(string root, params string[] members) =>
        _ => new PrincipalExpansion(
            root,
            PrincipalExpansionOutcome.Expanded,
            [
                .. members.Select((sid, i) => new ExpandedPrincipal(
                    sid, Forest, [root, .. members.Take(i + 1)], true)),
            ]);

    private static JudgingContext Context(
        Func<string, ObjectPermissions?> permissions,
        Func<string, PrincipalExpansion> expand,
        SchemaGuidCatalog? schema = null) =>
        Context(permissions, (sid, _) => expand(sid), schema);

    /// <summary>
    /// The scope-aware form, for the tests that care which scope a principal is keyed under.
    /// </summary>
    private static JudgingContext Context(
        Func<string, ObjectPermissions?> permissions,
        Func<string, string, PrincipalExpansion> expand,
        SchemaGuidCatalog? schema = null) =>
        JudgingContext.At(Started) with
        {
            Permissions = permissions,
            MembersOfPrincipal = (sid, scope) => expand(sid, scope),
            SchemaGuids = schema ?? Schema(),
        };

    /// <summary>
    /// The three LAPS password attributes as this forest's own schema would name them.
    /// </summary>
    private static SchemaGuidCatalog Schema() => new(
    [
        new SchemaGuidEntry(
            PasswordGuid, "msLAPS-Password", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
        new SchemaGuidEntry(
            EncryptedGuid,
            "msLAPS-EncryptedPassword",
            SchemaGuidKind.Attribute,
            SchemaGuidSource.Captured),
        new SchemaGuidEntry(
            LegacyGuid, "ms-Mcs-AdmPwd", SchemaGuidKind.Attribute, SchemaGuidSource.Captured),
    ]);

    private static ObjectPermissions Permissions(
        DescriptorAvailability availability, IReadOnlyList<PermissionEntry> entries) =>
        new(
            Machine,
            availability,
            availability is DescriptorAvailability.Unreadable ? "access denied" : null,
            Owner: null,
            availability is DescriptorAvailability.Read ? DaclState.Present : DaclState.Unreadable,
            DaclCompleteness.Complete,
            DaclWasCanonical: true,
            IsDaclProtected: false,
            entries,
            Errors: []);

    private static PermissionEntry Allow(string sid, int mask, string? objectTypeGuid) =>
        Entry("AccessAllowedObject", sid, mask, objectTypeGuid, Forest);

    /// <summary>
    /// An entry whose trustee has no domain, which is what a BUILTIN SID really looks like: it
    /// names no single captured object, so nothing resolves a domain for it.
    /// </summary>
    private static PermissionEntry AllowWithoutDomain(
        string sid, int mask, string? objectTypeGuid) =>
        Entry("AccessAllowedObject", sid, mask, objectTypeGuid, domainFqdn: null);

    private static PermissionEntry Deny(string sid, int mask, string? objectTypeGuid) =>
        Entry("AccessDeniedObject", sid, mask, objectTypeGuid, Forest);

    private static int _ordinal;

    private static PermissionEntry Entry(
        string aceType, string sid, int mask, string? objectTypeGuid, string? domainFqdn) =>
        new(
            _ordinal++,
            aceType,
            new PermissionTrustee(sid, null, null, domainFqdn, null, null, null),
            mask,
            objectTypeGuid,
            InheritedObjectTypeGuid: null,
            IsInherited: false,
            InheritanceFlags: 0,
            PropagationFlags: 0,
            HasObjectType: objectTypeGuid is not null,
            HasInheritedObjectType: false,
            ApplicationData: []);

    private static ObjectAttributes Computer(uint userAccountControl = 4096) => new(
        Machine,
        Guid.NewGuid(),
        Started,
        EvidenceCompleteness.Complete,
        [
            new ObjectAttribute(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, "person", null),
                    new AttributeValue(2, "organizationalPerson", null),
                    new AttributeValue(3, "user", null),
                    new AttributeValue(4, "computer", null),
                ]),
            new ObjectAttribute(
                "userAccountControl",
                AttributeCardinality.SingleValued,
                [new AttributeValue(0, userAccountControl.ToString(), null)]),
            new ObjectAttribute(
                "sAMAccountName",
                AttributeCardinality.SingleValued,
                [new AttributeValue(0, "WS01$", null)]),
        ],
        Forest);
}
