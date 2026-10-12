using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Cli;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ServiceAccountRuleTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Child = "DC=child," + Root;
    private const string Configuration = "CN=Configuration," + Root;
    private const string DomainSid = "S-1-5-21-1-2-3";
    private const string ChildSid = "S-1-5-21-4-5-6";
    private const string AccountDn = "CN=Unconventional account," + Root;
    private const string Da = "CN=Renamed domain administration," + Root;
    private const string Ea = "CN=Renamed enterprise administration," + Root;
    private const string Sa = "CN=Renamed schema administration," + Root;
    private const string Ba = "CN=Renamed administrators,CN=Builtin," + Root;
    private const string Bridge = "CN=Security bridge," + Root;
    private static readonly ServiceAccountWithAdministrativeMembership Administrative = new();
    private static readonly ServiceAccountWithNonExpiringPassword NonExpiring = new();
    private static readonly IReadOnlyList<IRule> Pair = [Administrative, NonExpiring];

    [Theory]
    [InlineData("DA", 512, -2147483646)]
    [InlineData("EA", 519, -2147483640)]
    [InlineData("SA", 518, -2147483640)]
    [InlineData("BA", 544, -2147483643)]
    public void Sec100UsesVerifiedAdministrativeIdentifiersAndFixedHighSeverity(string kind, int rid, long type)
    {
        var dn = kind switch { "DA" => Da, "EA" => Ea, "SA" => Sa, _ => Ba };
        using var reader = Published(Group(dn, rid == 544 ? "S-1-5-32-544" : DomainSid + "-" + rid, type, AccountDn), Account());
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<ServiceAccountFindingEvidence>(finding.Evidence);
        Assert.Equal(("SEC-100", Severity.High, Id(AccountDn), AccountDn, "contoso.com", "user"),
            (finding.RuleId, finding.Severity, finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass));
        Assert.Equal(new FindingSubject(FindingSubjectKind.Account, Id(AccountDn).ToString("D") + ":" + Id(dn).ToString("D")), finding.Subject);
        Assert.Equal(Id(dn), evidence.AdministrativeMembership!.TargetGuid);
        Assert.Equal(ServiceAccountKind.SpnBearingUser, evidence.Account.Kind);
        Assert.True(evidence.IsComplete);
    }

    [Theory]
    [InlineData("msDS-ManagedServiceAccount", ServiceAccountKind.StandaloneManagedServiceAccount)]
    [InlineData("msDS-GroupManagedServiceAccount", ServiceAccountKind.GroupManagedServiceAccount)]
    public void Sec100IncludesStructuralManagedAccountsWithoutSpns(string kind, ServiceAccountKind expected)
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(kind, spns: []));
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<ServiceAccountFindingEvidence>(finding.Evidence);
        Assert.Equal("SEC-100", finding.RuleId);
        Assert.Equal(expected, evidence.Account.Kind);
        Assert.Empty(evidence.Account.ServicePrincipalNames);
        Assert.Contains("computer", evidence.Account.ObjectClasses.Select(value => value.Text));
        Assert.Equal(kind, finding.ObjectClass);
    }

    [Fact]
    public void Sec100PreservesNestedSecurityMembershipAndOriginalWitnesses()
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, Bridge),
            Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn), Account());
        var evidence = Evidence(Assert.Single(reader.Read().Findings));
        Assert.Equal(2, evidence.AdministrativeMembership!.Links.Count);
        Assert.Equal(3, evidence.AdministrativeMembership.Principals.Count);
        Assert.All(evidence.AdministrativeMembership.Links, link => Assert.Equal("member", Assert.Single(link.Witnesses).Attribute));
        Assert.Contains(evidence.AdministrativeMembership.Links, link => link.MemberGuid == Id(AccountDn) && link.GroupGuid == Id(Bridge));
    }

    [Fact]
    public void Sec100ReportsPrimaryGroupAuthorizationWithoutClaimingProtection()
    {
        using var reader = Published(Account(primary: 512));
        var finding = Assert.Single(reader.Read().Findings);
        var membership = Evidence(finding).AdministrativeMembership!;
        var witness = Assert.Single(Assert.Single(membership.Links).Witnesses);
        Assert.Equal(("primaryGroupID", 0, "512", Id(AccountDn)), (witness.Attribute, witness.Ordinal, witness.Value, witness.SourceObjectGuid));
        Assert.Contains("primary-group membership", finding.Detail, StringComparison.Ordinal);
        Assert.True(membership.IsComplete);
    }

    [Fact]
    public void Sec100IgnoresProtectionMarkersWithoutAdministrativeMembership()
    {
        var account = With(Account(), "adminCount", [EvidenceValue.OfText("1")]);
        using var reader = Published(account, Group("CN=Controllers," + Root, DomainSid + "-516", -2147483646, AccountDn));
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Succeeded, reader.ReadRuleExecutions().Executions.Single(run => run.RuleId == "SEC-100").Outcome);
    }

    [Theory]
    [InlineData(548)]
    [InlineData(549)]
    [InlineData(550)]
    [InlineData(551)]
    [InlineData(516)]
    [InlineData(526)]
    public void Sec100DoesNotInventABroaderAdministrativeDestinationList(int rid)
    {
        var sid = rid < 512 || rid >= 544 && rid <= 551 ? "S-1-5-32-" + rid : DomainSid + "-" + rid;
        using var reader = Published(Group("CN=Other privileged group," + Root, sid, sid.StartsWith("S-1-5-32-", StringComparison.Ordinal)
            ? -2147483643 : -2147483646, AccountDn), Account());
        Assert.Empty(reader.Read().Findings);
    }

    [Fact]
    public void Sec100RejectsDistributionOnlyRoutesButKeepsAnIndependentSecurityRoute()
    {
        using var distribution = Published(Group(Da, DomainSid + "-512", -2147483646, Bridge),
            Group(Bridge, DomainSid + "-1200", 2, AccountDn), Account());
        Assert.Empty(distribution.Read().Findings);
        using var independent = Published(Group(Da, DomainSid + "-512", -2147483646, Bridge, AccountDn),
            Group(Bridge, DomainSid + "-1200", 2, AccountDn), Account());
        var membership = Evidence(Assert.Single(independent.Read().Findings)).AdministrativeMembership!;
        Assert.Single(membership.Links);
        Assert.DoesNotContain(membership.Principals, principal => principal.ObjectGuid == Id(Bridge));
    }

    [Fact]
    public void Sec100RejectsUnknownTypeRoutesWithoutDroppingEstablishedMembership()
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, Bridge, AccountDn),
            With(Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn), "groupType", []), Account());
        var finding = Assert.Single(reader.Read().Findings);
        Assert.Single(Evidence(finding).AdministrativeMembership!.Links);
        Assert.False(Evidence(finding).IsComplete);
        Assert.Contains(Evidence(finding).AdministrativeMembership!.Limitations, limit => limit.Reason == AdministrativeMembershipReason.GroupTypeUnavailable);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, reader.ReadRuleExecutions().Executions.Single(run => run.RuleId == "SEC-100").Outcome);
    }

    [Fact]
    public void Sec100CountsOneFindingPerAccountAndDestinationNotPerRoute()
    {
        var second = "CN=Second security bridge," + Root;
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, Bridge, second),
            Group(Ba, "S-1-5-32-544", -2147483643, AccountDn),
            Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn), Group(second, DomainSid + "-1201", -2147483646, AccountDn), Account());
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        Assert.Equal(2, findings.Select(finding => finding.Subject).Distinct().Count());
        Assert.Equal(4, Evidence(findings.Single(finding => Evidence(finding).AdministrativeMembership!.TargetGuid == Id(Da))).AdministrativeMembership!.Links.Count);
    }

    [Theory]
    [InlineData("objectSid", false)]
    [InlineData("primaryGroupID", true)]
    [InlineData("userAccountControl", true)]
    public void Sec100MakesMissingAccountInputsExplicitAndRetainsProvableMembership(string attribute, bool positive)
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), With(Account(), attribute, []));
        var run = reader.ReadRuleExecutions().Executions.Single(execution => execution.RuleId == "SEC-100");
        Assert.Equal(RuleExecutionOutcome.Indeterminate, run.Outcome);
        Assert.Contains(run.MissingInputs, input => input.Attribute == attribute);
        Assert.Equal(positive ? 1 : 0, reader.Read().Findings.Count);
        if (attribute == "userAccountControl") Assert.Contains("state could not be read", reader.Read().Findings[0].Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void Sec100RetainsDisabledAccountsAsDormantExposure(string kind)
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(kind, uac: 514));
        var finding = Assert.Single(reader.Read().Findings);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(514u, Evidence(finding).Account.UserAccountControl);
        Assert.Contains("currently disabled", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("dormant exposure", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Sec100KeepsKnownMembershipWhenTargetInventoryOrCaptureScopeIsIncomplete()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account()], omit: [Ba], partial: true);
        Derive(directory);
        var verdict = Assess(directory, routes => routes);
        var assessed = Evidence(Assert.Single(verdict.Findings)).AdministrativeMembership!;
        Assert.False(verdict.IsComplete);
        Assert.Contains(assessed.Limitations, limit => limit.Reason == AdministrativeMembershipReason.IdentityUnverified);
        Assert.Contains(assessed.Limitations, limit => limit.Reason == AdministrativeMembershipReason.CaptureIncomplete);
        using var reader = Open(Judge(directory));
        var finding = Assert.Single(reader.Read().Findings);
        var membership = Evidence(finding).AdministrativeMembership!;
        Assert.False(membership.IsComplete);
        Assert.Contains(membership.Limitations, limit => limit.Reason == AdministrativeMembershipReason.IdentityUnverified);
        Assert.Contains(membership.Limitations, limit => limit.Reason == AdministrativeMembershipReason.CaptureIncomplete);
        Assert.Contains("could not be fully assessed", finding.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("account-issuer")]
    [InlineData("target-issuer")]
    [InlineData("domain-class")]
    [InlineData("duplicate-sid")]
    [InlineData("duplicate-guid")]
    [InlineData("domain-sid")]
    [InlineData("target-type")]
    public void Sec100RefusesUnqualifiedCapturedIdentities(string variant)
    {
        var account = Account();
        var target = Group(Da, DomainSid + "-512", -2147483646, AccountDn);
        var sources = new List<Source> { account, target };
        if (variant is "account-issuer" or "target-issuer" or "domain-sid" or "domain-class")
        {
            var directory = Prepared(account, target);
            using var derivation = DerivationReader.Open(directory).Value;
            var originalRoutes = derivation.MembershipRoutesOf(DomainSid + "-1100", null);
            var changedDn = variant switch { "account-issuer" => AccountDn, "target-issuer" => Da, _ => Root };
            // Reusing the child's current Domain Admins SID would test identity collision before the issuer guard.
            var changedSid = variant == "target-issuer" ? "S-1-5-21-9-8-7-512" : ChildSid + (variant == "account-issuer" ? "-1100" : "");
            var verdict = Assess(directory, _ => originalRoutes with
            {
                Memberships = originalRoutes.Memberships.Select(group => group with
                {
                    Routes = group.Routes.Select(route => route with { Steps = route.Steps.Select(step =>
                        variant is "account-issuer" or "target-issuer" && step.Principal.DistinguishedName == changedDn
                            ? step with { Principal = step.Principal with { Sid = changedSid } } : step).ToArray() }).ToArray(),
                }).ToArray(),
            }, input => input with { Objects = input.Objects.Select(Change).ToArray() },
                changeSubject: subject => variant == "account-issuer" ? Change(subject) : subject);
            Assert.Empty(verdict.Findings);
            Assert.False(verdict.IsComplete);
            Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.IdentityUnreadable);
            return;

            ObjectAttributes Change(ObjectAttributes source) => source.DistinguishedName != changedDn ? source : source with
            {
                Attributes = source.Attributes.Select(attribute => attribute.LdapDisplayName != (variant == "domain-class" ? "objectClass" : "objectSid")
                    ? attribute : attribute with { Values = variant == "domain-class"
                        ? [new(0, "top", null), new(1, "organizationalUnit", null)] : [new(0, null, Sid.ToBytes(changedSid))] }).ToArray(),
            };
        }
        switch (variant)
        {
            case "duplicate-sid": sources.Add(Account(dn: "CN=Conflicting account," + Root)); break;
            case "duplicate-guid": sources.Add(Account(dn: "CN=Conflicting account," + Root, sid: DomainSid + "-1101") with { Guid = Id(AccountDn) }); break;
            case "target-type": sources[1] = With(target, "groupType", [EvidenceValue.OfText("2")]); break;
        }
        using var reader = Published(sources.ToArray());
        Assert.Empty(reader.Read().Findings);
        var run = reader.ReadRuleExecutions().Executions.Single(run => run.RuleId == "SEC-100");
        Assert.Equal(RuleExecutionOutcome.Indeterminate, run.Outcome);
        if (variant == "duplicate-sid")
            Assert.Contains(run.MissingInputs, input => input.Attribute == "AdministrativeMembership.IdentityUnreadable");
    }

    [Fact]
    public void Sec100ExcludesChildDomainEnterpriseAndSchemaLookalikes()
    {
        var childAccount = "CN=Child service," + Child;
        var enterprise = "CN=Child enterprise administrators," + Child;
        var schema = "CN=Child schema administrators," + Child;
        var directory = Prepared(Account(dn: childAccount, sid: ChildSid + "-1100"),
            Group(enterprise, ChildSid + "-519", -2147483640, childAccount), Group(schema, ChildSid + "-518", -2147483640, childAccount));
        using var reader = Open(Judge(directory));
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Succeeded, reader.ReadRuleExecutions().Executions.Single(run => run.RuleId == "SEC-100").Outcome);
        var verdict = Assess(directory, _ => new([
            Routes(enterprise, 519), Routes(schema, 518),
        ], MembershipRouteIncompleteReason.None), subjectDn: childAccount);
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);

        InitialMembershipRoutes Routes(string groupDn, int rid)
        {
            var group = new MembershipRoutePrincipal(ChildSid + "-" + rid, null, groupDn);
            return new(group, [new(0, "Child-domain lookalike", MembershipRouteAuthorization.SecurityEnabled, false,
                [new(new(ChildSid + "-1100", null, childAccount), false), new(group, false)])], MembershipRouteIncompleteReason.None);
        }
    }

    [Fact]
    public void Sec100PreservesCrossDomainUniversalRoutesAndResourceScopedBuiltinIdentity()
    {
        var childAccount = "CN=Child service," + Child;
        var childBridge = "CN=Child global bridge," + Child;
        var universal = "CN=Root universal bridge," + Root;
        var childBuiltin = "CN=Child administrators,CN=Builtin," + Child;
        using var reader = Published(Account(dn: childAccount, sid: ChildSid + "-1100"),
            Group(childBridge, ChildSid + "-1200", -2147483646, childAccount),
            Group(universal, DomainSid + "-1200", -2147483640, childBridge),
            Group(Ea, DomainSid + "-519", -2147483640, universal),
            Group(Ba, "S-1-5-32-544", -2147483643, childBridge));
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        var builtin = Evidence(findings.Single(finding => Evidence(finding).AdministrativeMembership!.TargetGuid == Id(Ba))).AdministrativeMembership!;
        var target = builtin.Principals.Single(principal => principal.ObjectGuid == builtin.TargetGuid);
        Assert.Equal(("S-1-5-32-544", "contoso.com"), (target.Sid, target.SidScope));
        Assert.DoesNotContain(findings, finding => Evidence(finding).AdministrativeMembership!.TargetGuid == Id(childBuiltin));
        Assert.Equal(2, builtin.Domains.Count);
    }

    [Fact]
    public void Sec100RejectsCrossDomainGlobalNestingAsUnsupportedNotClean()
    {
        var childAccount = "CN=Child service," + Child;
        using var reader = Published(Account(dn: childAccount, sid: ChildSid + "-1100"),
            Group(Da, DomainSid + "-512", -2147483646, childAccount));
        Assert.Empty(reader.Read().Findings);
        var run = reader.ReadRuleExecutions().Executions.Single(run => run.RuleId == "SEC-100");
        Assert.Equal(RuleExecutionOutcome.Indeterminate, run.Outcome);
        Assert.Contains(run.MissingInputs, input => input.Attribute == "AdministrativeMembership.MembershipScopeUnsupported");
    }

    [Fact]
    public void Sec100PreservesCapturedForeignReferenceAlongsideItsResolvedAccount()
    {
        var childAccount = "CN=Child service," + Child;
        var stub = "CN=" + ChildSid + "-1100,CN=ForeignSecurityPrincipals," + Root;
        using var reader = Published(Account(dn: childAccount, sid: ChildSid + "-1100"),
            Stub(stub, ChildSid + "-1100"), Group(Ba, "S-1-5-32-544", -2147483643, stub));
        var membership = Evidence(Assert.Single(reader.Read().Findings)).AdministrativeMembership!;
        var link = Assert.Single(membership.Links);
        Assert.Equal((Id(childAccount), Id(stub), stub), (link.MemberGuid, link.MemberReferenceGuid, Assert.Single(link.Witnesses).Value));
        Assert.Equal("foreignSecurityPrincipal", membership.Principals.Single(identity => identity.ObjectGuid == Id(stub)).ObjectClass);
    }

    [Theory]
    [InlineData("account")]
    [InlineData("group")]
    public void Sec100KeepsHistoricalForeignReferencesExplicitlyUnsupportedRatherThanClean(string kind)
    {
        var old = "S-1-5-21-9-8-7-1200";
        var stub = "CN=" + old + ",CN=ForeignSecurityPrincipals," + Root;
        var holder = kind == "group" ? Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn) : Account();
        holder = With(holder, "sIDHistory", [EvidenceValue.OfBytes(Sid.ToBytes(old)!)]);
        var sources = new List<Source> { Group(Ba, "S-1-5-32-544", -2147483643, stub), Stub(stub, old), holder };
        if (kind == "group") sources.Add(Account());
        var directory = Prepared(sources.ToArray());
        var verdict = Assess(directory, routes => routes);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.MembershipIdentityUnsupported);
        using var reader = Open(Judge(directory));
        Assert.Empty(reader.Read().Findings);
        var run = reader.ReadRuleExecutions().Executions.Single(value => value.RuleId == "SEC-100");
        Assert.Equal(RuleExecutionOutcome.Indeterminate, run.Outcome);
        Assert.Contains(run.MissingInputs, value => value.Attribute == "AdministrativeMembership.MembershipIdentityUnsupported");
    }

    [Theory]
    [InlineData("current")]
    [InlineData("ambiguous-history")]
    public void Sec100HistoricalClaimsCannotOverrideCurrentOrAmbiguousCapturedIdentity(string variant)
    {
        var old = DomainSid + "-1201";
        var stub = "CN=" + old + ",CN=ForeignSecurityPrincipals," + Root;
        var other = "CN=Another identity," + Root;
        var holder = With(Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn), "sIDHistory", [EvidenceValue.OfBytes(Sid.ToBytes(old)!)]);
        var competitor = variant == "current" ? Group(other, old, -2147483646)
            : With(Group(other, DomainSid + "-1202", -2147483646), "sIDHistory", [EvidenceValue.OfBytes(Sid.ToBytes(old)!)]);
        var directory = Prepared(Group(Ba, "S-1-5-32-544", -2147483643, stub), Stub(stub, old), holder, competitor, Account());
        var initial = new MembershipRoutePrincipal(DomainSid + "-1200", null, Bridge);
        var verdict = Assess(directory, _ => new([new(initial, [new(0, "Administrative destination", MembershipRouteAuthorization.SecurityEnabled, false,
            [new(new(DomainSid + "-1100", null, AccountDn), false), new(initial, false), new(new("S-1-5-32-544", "contoso.com", Ba), false)])],
            MembershipRouteIncompleteReason.None)], MembershipRouteIncompleteReason.None));
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.IdentityUnreadable);
    }

    [Fact]
    public void Sec100HistoricalAmbiguityDoesNotEraseAnIndependentDirectMembership()
    {
        var old = DomainSid + "-1201";
        var one = With(Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn), "sIDHistory", [EvidenceValue.OfBytes(Sid.ToBytes(old)!)]);
        var two = With(Group("CN=Another history holder," + Root, DomainSid + "-1202", -2147483646), "sIDHistory", [EvidenceValue.OfBytes(Sid.ToBytes(old)!)]);
        var stub = "CN=" + old + ",CN=ForeignSecurityPrincipals," + Root;
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(), one, two, Stub(stub, old),
            Group(Ba, "S-1-5-32-544", -2147483643, stub));
        var finding = Assert.Single(reader.Read().Findings);
        Assert.Single(Evidence(finding).AdministrativeMembership!.Links);
        Assert.False(Evidence(finding).IsComplete);
        Assert.Contains(Evidence(finding).AdministrativeMembership!.Limitations, value => value.Reason == AdministrativeMembershipReason.HistoricalIdentityUnsupported);
    }

    [Fact]
    public void Sec100UsesOriginalMemberOfAndPrimaryValuesWithoutInventingMemberLinks()
    {
        var account = With(Account(), "memberOf", [EvidenceValue.OfText(Da)]);
        using var reader = Published(account);
        var witness = Assert.Single(Assert.Single(Evidence(Assert.Single(reader.Read().Findings)).AdministrativeMembership!.Links).Witnesses);
        Assert.Equal(("memberOf", Id(AccountDn), 0, Da), (witness.Attribute, witness.SourceObjectGuid, witness.Ordinal, witness.Value));
    }

    [Theory]
    [InlineData(MembershipRouteIncompleteReason.NodeBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.EdgeBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.StorageBudgetReached)]
    [InlineData(MembershipRouteIncompleteReason.TimeBudgetReached)]
    public void Sec100PreservesSavedProcessingLimitsWithoutDroppingEstablishedMembership(MembershipRouteIncompleteReason reason)
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account()]);
        Derive(directory);
        var verdict = Assess(directory, routes => routes.WithIncompleteReasons(reason));
        var evidence = Evidence(Assert.Single(verdict.Findings));
        Assert.False(verdict.IsComplete);
        Assert.Equal(reason, evidence.AdministrativeMembership!.RouteIncompleteReasons);
        Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.MembershipProcessingLimit);
    }

    [Fact]
    public void Sec100DoesNotTreatAnUnreadProtectionExclusionMaskAsAnAuthorizationGap()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account()]);
        Derive(directory);
        var verdict = Assess(directory, routes => routes.WithIncompleteReasons(MembershipRouteIncompleteReason.ForestMaskUnreadable));
        Assert.True(verdict.IsComplete);
        Assert.True(Evidence(Assert.Single(verdict.Findings)).IsComplete);
    }

    [Theory]
    [InlineData("member")]
    [InlineData("identity")]
    public void Sec100RejectsSavedRoutesWithoutMatchingOriginalSources(string variant)
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account()]);
        Derive(directory);
        var verdict = Assess(directory, routes => routes, input => input with
        {
            Objects = input.Objects.Select(source => source.DistinguishedName != (variant == "member" ? Da : AccountDn) ? source : variant == "member"
                ? source with { Attributes = source.Attributes.Where(attribute => attribute.LdapDisplayName != "member").ToArray() }
                : source with { ObjectGuid = Guid.NewGuid() }).ToArray(),
        });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Theory]
    [InlineData(512u, false, false)]
    [InlineData(66048u, true, false)]
    [InlineData(66050u, true, true)]
    public void Sec101UsesMicrosoftNonExpiringAndDisabledBitsWithFixedMediumSeverity(uint uac, bool fires, bool disabled)
    {
        var subject = Subject(Account(uac: uac));
        var verdict = NonExpiring.Judge(subject);
        Assert.True(verdict.IsComplete);
        Assert.Equal(fires ? 1 : 0, verdict.Findings.Count);
        if (!fires) return;
        var finding = Assert.Single(verdict.Findings);
        Assert.Equal(("SEC-101", Severity.Medium, FindingSubjectKind.Account, Id(AccountDn).ToString("D")),
            (finding.RuleId, finding.Severity, finding.Subject.Kind, finding.Subject.Key));
        Assert.Equal(uac, Evidence(finding).Account.UserAccountControl);
        Assert.Equal(disabled, finding.Detail.Contains("dormant exposure", StringComparison.Ordinal));
        Assert.Null(Evidence(finding).AdministrativeMembership);
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void Sec101ExcludesComputersAndBothManagedAccountClasses(string kind)
    {
        var verdict = NonExpiring.Judge(Subject(Account(kind, uac: 66048)));
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Fact]
    public void ServicePairDoesNotUseAccountNamesOrContainersAsServiceIdentification()
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(spns: [], uac: 66048,
            name: "svc_service_account"));
        Assert.Empty(reader.Read().Findings);
        Assert.True(NonExpiring.Judge(Subject(Account(spns: [], uac: 66048, dn: "CN=svc-old,OU=Service Accounts," + Root))).IsComplete);
        Assert.Empty(NonExpiring.Judge(Subject(Account(spns: [], uac: 66048, dn: "CN=svc-old,OU=Service Accounts," + Root))).Findings);
    }

    [Theory]
    [InlineData("userAccountControl")]
    [InlineData("servicePrincipalName")]
    [InlineData("objectClass")]
    public void Sec101DoesNotConvertUnreadOrMalformedRequiredValuesIntoCleanAnswers(string attribute)
    {
        var source = With(Account(uac: 66048), attribute, [EvidenceValue.OfBytes([1, 2, 3])]);
        var verdict = NonExpiring.Judge(Subject(source));
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(attribute, verdict.InputsNotCaptured);
    }

    [Fact]
    public void ServicePairPreservesOriginalSpnOccurrencesAndMalformedSiblingLimitations()
    {
        var account = With(Account(uac: 66048), "servicePrincipalName",
            [EvidenceValue.OfText("HTTP/web:8443/instance"), EvidenceValue.OfText(""), EvidenceValue.OfText("http/WEB:8443/instance")]);
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), account);
        Assert.Equal(2, reader.Read().Findings.Count);
        foreach (var finding in reader.Read().Findings)
        {
            var evidence = Evidence(finding);
            Assert.False(evidence.IsComplete);
            Assert.Equal(new[] { 0, 1, 2 }, evidence.Account.ServicePrincipalNames.Select(value => value.Ordinal));
            Assert.Equal("", evidence.Account.ServicePrincipalNames[1].Text);
            Assert.Equal("HTTP/web:8443/instance", evidence.Account.ServicePrincipalNames[0].Text);
            Assert.Contains("servicePrincipalName", evidence.Account.MissingAttributes);
        }
    }

    [Fact]
    public void ServicePairDoesNotLoseMissingGuidEvidence()
    {
        var missing = NonExpiring.Judge(Subject(Account(uac: 66048) with { Guid = null }));
        Assert.Empty(missing.Findings);
        Assert.Contains("objectGUID", missing.InputsNotCaptured);
        var administrative = Administrative.Judge(Subject(Account() with { Guid = null }), JudgingContext.At(Started));
        Assert.Empty(administrative.Findings);
        Assert.Contains("objectGUID", administrative.InputsNotCaptured);
    }

    [Fact]
    public void ServicePairKeepsMissingRoutesDistinctFromNoAdministrativeMembership()
    {
        var directory = Prepared(Account());
        var verdict = Assess(directory, _ => MembershipRouteSummary.NotDerived);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.NotDerived);
    }

    [Fact]
    public void ServicePairMissingSpnAttributeIsNotTheSameAsAnUnsetRegistration()
    {
        var subject = Subject(Account());
        var missing = subject with { Attributes = subject.Attributes.Where(attribute => attribute.LdapDisplayName != "servicePrincipalName").ToArray() };
        var verdict = NonExpiring.Judge(missing);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains("servicePrincipalName", verdict.InputsNotCaptured);
        var unset = NonExpiring.Judge(Subject(Account(spns: [], uac: 66048)));
        Assert.Empty(unset.Findings);
        Assert.True(unset.IsComplete);
    }

    [Fact]
    public void ServicePairSavedProcessingAndForestIdentityGapsHavePlainSeparateWording()
    {
        Assert.Equal("The saved administrative-membership route calculation reached its recorded processing limit. "
            + "Established membership remains evidence; absence of other routes is not a complete answer.",
            UnresolvedWording.For("AdministrativeMembership.MembershipProcessingLimit"));
        Assert.Equal("The captured forest-root identity is unavailable, so Enterprise Admins and Schema Admins membership could not be fully qualified.",
            UnresolvedWording.For("AdministrativeMembership.ForestIdentityUnreadable"));
        Assert.Equal("A captured foreign reference matches SID history, which the saved security-membership routes do not resolve. "
            + "Established current membership remains evidence; membership through the historical identity is not assessed.",
            UnresolvedWording.For("AdministrativeMembership.MembershipIdentityUnsupported"));
    }

    [Theory]
    [InlineData("ordinals")]
    [InlineData("multiple-controls")]
    [InlineData("missing-domain")]
    public void ServicePairRejectsMalformedOrderingControlsAndMissingDomainIdentity(string variant)
    {
        var subject = Subject(Account(uac: 66048));
        subject = variant switch
        {
            "ordinals" => subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName != "objectClass"
                ? attribute : attribute with { Values = attribute.Values.Reverse().ToArray() }).ToArray() },
            "multiple-controls" => subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName != "userAccountControl"
                ? attribute : attribute with { Values = [new(0, "66048", null), new(1, "512", null)] }).ToArray() },
            _ => subject with { DomainFqdn = null },
        };
        var verdict = NonExpiring.Judge(subject);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(variant switch { "ordinals" => "objectClass", "multiple-controls" => "userAccountControl", _ => "DomainFqdn" }, verdict.InputsNotCaptured);
    }

    [Theory]
    [InlineData("cli")]
    [InlineData("shell")]
    public async Task ServicePairRunsThroughSharedOfflineHostsWithoutCapture(string host)
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048)]);
        Derive(directory);
        var hash = Hash(directory);
        if (host == "cli")
        {
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--judge", directory])!, CancellationToken.None,
                null, _ => throw new InvalidOperationException("The service-account pair must use captured evidence offline.")));
        }
        else
        {
            var result = await new JudgingLauncher(null).RunAsync(directory, new Progress<JudgingRun.JudgingProgress>(), CancellationToken.None);
            Assert.True(result.IsSuccess, result.Error?.Description);
        }
        using var reader = Open(directory);
        Assert.Equal(1, reader.Read().Findings.Count(finding => finding.RuleId == "SEC-100"));
        Assert.Equal(1, reader.Read().Findings.Count(finding => finding.RuleId == "SEC-101"));
        Assert.Contains(reader.ReadRuleExecutions().Executions, run => run.RuleId == "SEC-100");
        Assert.Contains(reader.ReadRuleExecutions().Executions, run => run.RuleId == "SEC-101");
        Assert.Equal(hash, Hash(directory));
    }

    [Fact]
    public void ServicePairWholeAndSelectedPageReadsPreserveExactTypedEvidence()
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048));
        var all = reader.Read().Findings;
        var page = reader.ReadPage(FindingsQuery.About(AccountDn));
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(2, page.Value.Findings.Count);
        Assert.Equal(all.Select(finding => JsonSerializer.Serialize(Evidence(finding), ProofSerialization.Options)),
            page.Value.Findings.Select(finding => JsonSerializer.Serialize(Evidence(finding), ProofSerialization.Options)));
        foreach (var finding in all.Concat(page.Value.Findings))
        {
            var evidence = Evidence(finding);
            Assert.Equal(Id(AccountDn), evidence.Account.ObjectGuid);
            Assert.Equal(66048u, evidence.Account.UserAccountControl);
            Assert.Equal("HTTP/service.contoso.com", Assert.Single(evidence.Account.ServicePrincipalNames).Text);
            if (finding.RuleId == "SEC-101") Assert.Null(evidence.AdministrativeMembership);
            else
            {
                Assert.Equal(Id(Da), evidence.AdministrativeMembership!.TargetGuid);
                Assert.Equal(AccountDn, Assert.Single(Assert.Single(evidence.AdministrativeMembership.Links).Witnesses).Value);
            }
        }
    }

    [Theory]
    [InlineData("$.Account.Kind", "'GroupManagedServiceAccount'")]
    [InlineData("$.Account.UserAccountControl", "512")]
    [InlineData("$.Account.ObjectGuid", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.AdministrativeMembership.EvidenceSeal", "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")]
    [InlineData("$.AdministrativeMembership.DerivationGenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.AdministrativeMembership.DerivationSeal", "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")]
    [InlineData("$.AdministrativeMembership.TargetGuid", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.AdministrativeMembership.PrincipalCatalogueVersion", "999")]
    [InlineData("$.AdministrativeMembership.PolicyVersion", "999")]
    [InlineData("$.AdministrativeMembership.Links[0].Witnesses[0].Value", "'CN=Unrelated,DC=contoso,DC=com'")]
    public void ServicePairRejectsRehashedBindingAndProofCorruption(string path, string value)
    {
        var directory = Judge(Prepared(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048)));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding_service_account SET proof=json_set(proof,$path,{value}) WHERE finding_id="
                + "(SELECT finding_id FROM finding WHERE rule_id='SEC-100')";
            command.Parameters.AddWithValue("$path", path);
            Assert.Equal(1, command.ExecuteNonQuery());
            Rehash(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(AccountDn)));
    }

    [Fact]
    public void ServicePairPublicationRequiresOriginalFingerprintAndTypedRows()
    {
        var directory = Judge(Prepared(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048)));
        using var reader = Open(directory);
        var derivationSeal = Evidence(reader.Read().Findings.Single(finding => finding.RuleId == "SEC-100")).AdministrativeMembership!.DerivationSeal;
        var store = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, reader.Description.GenerationId);
        var copy = Path.Combine(directory, "service-publication-check.db");
        File.Copy(store, copy);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = copy, Pooling = false }.ToString());
        connection.Open();
        ServiceAccountFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None);
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE finding_service_account SET fingerprint=zeroblob(32)";
        Assert.Equal(2, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => ServiceAccountFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None));
        Rehash(connection);
        command.CommandText = "DELETE FROM finding_service_account";
        Assert.Equal(2, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => ServiceAccountFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None));
    }

    [Theory]
    [InlineData("$.Account.Kind", "'StandaloneManagedServiceAccount'")]
    [InlineData("$.Account.UserAccountControl", "512")]
    [InlineData("$.Account.ServicePrincipalNames", "json_array()")]
    public void Sec101SavedReadRejectsRehashedSettingOrAssociationCorruption(string path, string value)
    {
        var directory = Judge(Prepared(Account(uac: 66048)));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding_service_account SET proof=json_set(proof,$path,{value})";
            command.Parameters.AddWithValue("$path", path);
            Assert.Equal(1, command.ExecuteNonQuery());
            Rehash(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(AccountDn)));
    }

    [Theory]
    [InlineData("SEC-100", "subject_key", "'unrelated-account:target'")]
    [InlineData("SEC-101", "subject_key", "'unrelated-account'")]
    [InlineData("SEC-100", "domain_fqdn", "'child.contoso.com'")]
    [InlineData("SEC-101", "object_class", "'computer'")]
    [InlineData("SEC-101", "severity", "'High'")]
    [InlineData("SEC-100", "subject_kind", "'DirectoryObject'")]
    public void ServicePairSavedReadRejectsRelabelledAccountDestinationAndSeverity(string rule, string column, string value)
    {
        var directory = Judge(Prepared(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048)));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding SET {column}={value} WHERE rule_id=$rule";
            command.Parameters.AddWithValue("$rule", rule);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(AccountDn)));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("missing-body")]
    public void ServicePairSavedRowsCannotLoseTheirTypedBodyOrBeMovedToAnotherGeneration(string variant)
    {
        var directory = Judge(Prepared(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048)));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = variant == "generation"
                ? "UPDATE finding_service_account SET generation='11111111-1111-1111-1111-111111111111'" : "DELETE FROM finding_service_account";
            Assert.Equal(2, command.ExecuteNonQuery());
            if (variant == "generation") Rehash(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(AccountDn)));
    }

    [Fact]
    public void Sec100HonorsCancellationBeforeMembershipAssessment()
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account());
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        using var derivation = DerivationReader.Open(directory).Value;
        using var cancellation = new CancellationTokenSource();
        var context = JudgingContext.At(Started) with
        {
            AdministrativeMembership = CapturedGroupMembershipIndex.Create(inputs.ReadMembershipInput(), inputs.Binding(),
                inputs.ReadNamingContexts().Value, cancellation.Token),
            MembershipRoutes = derivation.MembershipRoutesOf,
        };
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => Administrative.Judge(inputs.Bundle.ReadObjectAttributes(AccountDn)!, context));
    }

    [Fact]
    public void ServicePairGuidanceKeepsSettingMembershipAndTakeoverSeparate()
    {
        Assert.Equal(Severity.High, Administrative.Definition.Severity);
        Assert.Equal(Severity.Medium, NonExpiring.Definition.Severity);
        Assert.Single(RuleCatalogue.All, rule => rule.Definition.Id == "SEC-100");
        Assert.Single(RuleCatalogue.All, rule => rule.Definition.Id == "SEC-101");
        Assert.DoesNotContain(RuleCatalogue.All, rule => rule.Definition.Id == "SEC-083");
        Assert.Contains("not observed service usage", RuleGuidanceCatalogue.For("SEC-100")!.About, StringComparison.Ordinal);
        Assert.Contains("does not prove that its password has never been rotated", RuleGuidanceCatalogue.For("SEC-101")!.About, StringComparison.Ordinal);
        Assert.Contains("service dependencies", RuleGuidanceCatalogue.For("SEC-100")!.WhatToDo, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SEC-100")]
    [InlineData("SEC-101")]
    [InlineData("SEC-062")]
    public void AdministrativeServiceFindingsKeepSavedGapsVisibleInTheExistingCoverageIndicator(string rule)
    {
        var finding = rule == "SEC-062" ? Assert.Single(BroadAdministrativeGroupMembershipTests.ReadPublishedFindings())
            : ReadPublishedFindings().Single(value => value.RuleId == rule);
        var complete = new FindingRowViewModel(finding);
        Assert.Equal("Complete", complete.Coverage);
        Assert.Equal(FactState.EstablishedGood, complete.State);
        FindingEvidence incomplete = finding.Evidence switch
        {
            ServiceAccountFindingEvidence { AdministrativeMembership: { } membership } evidence => evidence with
                { AdministrativeMembership = membership with { RouteIncompleteReasons = MembershipRouteIncompleteReason.EdgeBudgetReached } },
            ServiceAccountFindingEvidence evidence => evidence with { Account = evidence.Account with
            {
                ServicePrincipalNames = [.. evidence.Account.ServicePrincipalNames, new(evidence.Account.ServicePrincipalNames.Count, "", null)],
                MissingAttributes = ["servicePrincipalName"],
            } },
            BroadGroupMembershipEvidence evidence => evidence with
                { InputsComplete = false, Limitations = [new(finding.DistinguishedName, AdministrativeMembershipReason.CaptureIncomplete)] },
            _ => throw new InvalidOperationException("The fixture must provide an administrative/service finding."),
        };
        var partial = new FindingRowViewModel(finding with { Evidence = incomplete });
        Assert.Equal("May be incomplete", partial.Coverage);
        Assert.Equal(FactState.NotEstablished, partial.State);
        Assert.Equal(finding.Severity, partial.Rank);
        Assert.Equal(finding.Detail, partial.Detail);
        Assert.False(partial.HasTier0Routes);
    }

    [Fact]
    public void ServicePairIsDeterministicWhenPreparedInputAndSavedRoutesAreReordered()
    {
        var other = "CN=Other bridge," + Root;
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, Bridge, other),
            Group(Bridge, DomainSid + "-1200", -2147483646, AccountDn), Group(other, DomainSid + "-1201", -2147483646, AccountDn), Account());
        var original = Assess(directory, routes => routes);
        var reversed = Assess(directory, routes => routes with
        {
            Memberships = routes.Memberships.Reverse().Select(group => group with { Routes = group.Routes.Reverse().ToArray() }).ToArray(),
        }, input => input with { Objects = input.Objects.Reverse().ToArray() });
        Assert.Equal(JsonSerializer.Serialize(Evidence(Assert.Single(original.Findings)), ProofSerialization.Options),
            JsonSerializer.Serialize(Evidence(Assert.Single(reversed.Findings)), ProofSerialization.Options));
    }

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        using var reader = Published(Group(Da, DomainSid + "-512", -2147483646, AccountDn), Account(uac: 66048));
        return reader.ReadPage(FindingsQuery.About(AccountDn)).Value.Findings;
    }

    private static ServiceAccountFindingEvidence Evidence(Finding finding) => Assert.IsType<ServiceAccountFindingEvidence>(finding.Evidence);
    internal sealed record Source(string Dn, Guid? Guid, IReadOnlyList<EvidenceAttribute> Attributes);
    internal static Guid Id(string dn) => new(SHA256.HashData(Encoding.UTF8.GetBytes(dn)).AsSpan(0, 16));
    internal static Source Account(string kind = "user", string[]? spns = null, uint uac = 512, uint primary = 513,
        string dn = AccountDn, string sid = DomainSid + "-1100", string name = "unconventional")
    {
        var classes = new List<string> { "top", "person", "organizationalPerson", "user" };
        if (kind != "user") classes.Add("computer");
        if (kind is "msDS-ManagedServiceAccount" or "msDS-GroupManagedServiceAccount") classes.Add(kind);
        return new(dn, Id(dn), [Texts("objectClass", classes), Binary("objectSid", sid), Texts("userAccountControl", [uac.ToString(CultureInfo.InvariantCulture)]),
            Texts("primaryGroupID", [primary.ToString(CultureInfo.InvariantCulture)]), Texts("servicePrincipalName", spns ?? ["HTTP/service.contoso.com"]),
            Texts("sAMAccountName", [name]), Texts("memberOf", [])]);
    }
    internal static Source Group(string dn, string sid, long type, params string[] members) =>
        new(dn, Id(dn), [Texts("objectClass", ["top", "group"]), Binary("objectSid", sid),
            Texts("groupType", [type.ToString(CultureInfo.InvariantCulture)]), Texts("member", members)]);
    private static Source Domain(string dn, string sid) => new(dn, Id(dn), [Texts("objectClass", ["top", "domainDNS"]), Binary("objectSid", sid)]);
    private static Source Stub(string dn, string sid) => new(dn, Id(dn), [Texts("objectClass", ["top", "foreignSecurityPrincipal"]), Binary("objectSid", sid)]);
    private static EvidenceAttribute Texts(string name, IEnumerable<string> values) => new(name, StoredAttributeCompleteness.Complete,
        values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Binary(string name, string sid) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]);
    internal static Source With(Source source, string name, IReadOnlyList<EvidenceValue> values) => source with
    {
        Attributes = source.Attributes.Where(attribute => attribute.LdapDisplayName != name)
            .Append(new EvidenceAttribute(name, StoredAttributeCompleteness.Complete, values)).ToArray(),
    };
    private static ObjectAttributes Subject(Source source) => new(source.Dn, source.Guid, Started, EvidenceCompleteness.Complete,
        source.Attributes.Select(attribute => new ObjectAttribute(attribute.LdapDisplayName,
            CapturedAttributeCatalog.All.Single(entry => entry.LdapDisplayName == attribute.LdapDisplayName).Cardinality,
            attribute.Values.Select((value, ordinal) => new AttributeValue(ordinal, value.Text, value.Bytes)).ToArray())).ToArray(),
        source.Dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase) ? "child.contoso.com" : "contoso.com");
    private static JudgementReader Published(params Source[] sources) => Open(Judge(Prepared(sources)));
    private static string Prepared(params Source[] sources) { var directory = Capture(sources); Derive(directory); return directory; }
    private static string Judge(string directory)
    {
        var result = JudgingRun.Judge(directory, Pair, Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }
    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
    private static RuleVerdict Assess(string directory, Func<MembershipRouteSummary, MembershipRouteSummary> change,
        Func<CapturedMembershipInput, CapturedMembershipInput>? changeInput = null, string subjectDn = AccountDn,
        Func<ObjectAttributes, ObjectAttributes>? changeSubject = null)
    {
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var input = inputs.ReadMembershipInput();
        input = (changeInput?.Invoke(input) ?? input).Prepare(CancellationToken.None);
        using var derivation = DerivationReader.Open(directory).Value;
        var subject = inputs.Bundle.ReadObjectAttributes(subjectDn)!;
        return Administrative.Judge(changeSubject?.Invoke(subject) ?? subject, JudgingContext.At(Started) with
        {
            AdministrativeMembership = CapturedGroupMembershipIndex.Create(input, inputs.Binding(), inputs.ReadNamingContexts().Value, CancellationToken.None),
            MembershipRoutes = (sid, scope) => change(derivation.MembershipRoutesOf(sid, scope)),
        });
    }

    internal static string Capture(IReadOnlyList<Source> sources, string[]? omit = null, bool partial = false)
    {
        var directory = TempDirectories.Create("service-pair");
        using var writer = BundleWriter.Create(directory, Started);
        foreach (var (context, kind) in new[] { (Root, NamingContextKind.Domain), (Child, NamingContextKind.Domain), (Configuration, NamingContextKind.Configuration) })
        {
            if (partial && context == Child) continue;
            var partition = new PartitionCoverage(context, kind, "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(partition);
            var list = sources.Where(source => Context(source.Dn) == context).ToList();
            if (kind == NamingContextKind.Domain)
            {
                var sid = context == Root ? DomainSid : ChildSid;
                var narrow = "CN=Narrow fixture administrator," + context;
                var defaults = new List<Source> { Domain(context, sid), Account(dn: narrow, sid: sid + "-500", spns: []),
                    Group(context == Root ? Da : "CN=Child domain administrators," + context, sid + "-512", -2147483646, narrow),
                    Group(context == Root ? Ba : "CN=Child administrators,CN=Builtin," + context, "S-1-5-32-544", -2147483643, narrow) };
                if (context == Root)
                {
                    defaults.Add(Group(Ea, sid + "-519", -2147483640, narrow));
                    defaults.Add(Group(Sa, sid + "-518", -2147483640, narrow));
                }
                foreach (var source in defaults)
                    if (!list.Any(existing => existing.Dn == source.Dn)) list.Add(source);
            }
            foreach (var source in list.Where(source => omit?.Contains(source.Dn) != true))
            {
                var id = writer.WriteObject(new(partition, source.Dn, source.Guid, source.Attributes, Started));
                if (source.Guid is { } objectGuid && source.Attributes.SingleOrDefault(attribute =>
                    attribute.LdapDisplayName == "nTSecurityDescriptor")?.Values.SingleOrDefault()?.Bytes is { } bytes)
                    writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(objectGuid, SecurityDescriptorParser.Parse(bytes)));
            }
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com", "child.contoso.com"]),
            [DomainCoverage.Read("contoso.com"), partial ? DomainCoverage.Excluded("child.contoso.com", ExclusionKind.ByChoice, "Synthetic partial scope")
                : DomainCoverage.Read("child.contoso.com")],
            [ForestPartitionCoverage.Read(Configuration, NamingContextKind.Configuration), ForestPartitionCoverage.Read("CN=Schema," + Configuration, NamingContextKind.Schema)],
            SysvolCoverage.Of([])), Started.AddMinutes(1));
        return directory;
    }
    private static string Context(string dn) => dn.EndsWith(Configuration, StringComparison.OrdinalIgnoreCase) ? Configuration
        : dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase) ? Child : Root;
    private static void Rehash(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT finding_id,generation,proof FROM finding_service_account";
        var rows = new List<(long Id, string Generation, string Proof)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read()) rows.Add((reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
        foreach (var row in rows)
        {
            command.CommandText = "UPDATE finding_service_account SET fingerprint=$hash WHERE finding_id=$id";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(row.Generation + "\0" + row.Proof));
            command.Parameters.AddWithValue("$id", row.Id);
            Assert.Equal(1, command.ExecuteNonQuery());
        }
    }
}
