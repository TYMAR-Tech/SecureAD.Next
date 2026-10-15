using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class BroadAdministrativeGroupMembershipTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Child = "DC=child," + Root;
    private const string Configuration = "CN=Configuration," + Root;
    private const string DomainSid = "S-1-5-21-1-2-3";
    private const string ChildSid = "S-1-5-21-4-5-6";
    private const string Da = "CN=Renamed domain administrators," + Root;
    private const string Ea = "CN=Renamed enterprise administrators," + Root;
    private const string Sa = "CN=Renamed schema administrators," + Root;
    private const string Ba = "CN=Renamed administrators,CN=Builtin," + Root;
    private const string Wide = "CN=Renamed broad global group," + Root;
    private const string Narrow = "CN=Administrator," + Root;
    private static readonly BroadAdministrativeGroupMembership Rule = new();

    [Theory]
    [InlineData("DA", 512, -2147483646)]
    [InlineData("EA", 519, -2147483640)]
    [InlineData("SA", 518, -2147483640)]
    [InlineData("BA", 544, -2147483643)]
    public void Sec062UsesQualifiedIdentifiersRatherThanNames(string kind, int rid, long type)
    {
        var target = kind switch { "DA" => Da, "EA" => Ea, "SA" => Sa, _ => Ba };
        var directory = Prepared(Group(target, rid == 544 ? "S-1-5-32-544" : DomainSid + "-" + rid, type, [Wide]), Broad());
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence);
        Assert.Equal(("SEC-062", Severity.High, Id(target), target, "contoso.com", Id(target).ToString("D")),
            (finding.RuleId, finding.Severity, finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.Subject.Key));
        Assert.Equal(FindingSubjectKind.DirectoryObject, finding.Subject.Kind);
        Assert.Equal(Id(target), evidence.TargetGuid);
        Assert.True(evidence.IsComplete);
        Assert.Equal(DomainSid + "-513", Assert.Single(evidence.BroadSources).Sid);
        Assert.Single(evidence.Links);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Theory]
    [InlineData(513)]
    [InlineData(514)]
    [InlineData(515)]
    public void Sec062RecognisesEachBroadDomainGroupWithoutEnumeratingItsAccounts(int rid)
    {
        using var reader = Open(Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]),
            Broad() with { Sid = DomainSid + "-" + rid, Members = ["CN=Deliberately uncaptured population," + Root] }));
        var evidence = Evidence(reader);
        Assert.True(evidence.IsComplete);
        Assert.Equal(DomainSid + "-" + rid, Assert.Single(evidence.BroadSources).Sid);
        Assert.Equal(2, evidence.Principals.Count);
        Assert.DoesNotContain(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.MemberUncaptured);
    }

    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-7")]
    [InlineData("S-1-5-11")]
    public void Sec062KeepsSpecialBroadIdentitiesSymbolicInBuiltinAdministrators(string sid)
    {
        var special = "CN=" + sid + ",CN=ForeignSecurityPrincipals," + Root;
        using var reader = Open(Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [special]), Stub(special, sid)));
        var evidence = Evidence(reader);
        Assert.Equal(sid, Assert.Single(evidence.BroadSources).Sid);
        Assert.True(evidence.IsComplete);
        Assert.Equal(2, evidence.Principals.Count);
        Assert.Null(evidence.BroadSources[0].SidScope);
        Assert.Null(evidence.Principals.Single(principal => principal.ObjectGuid == Id(special)).GroupType);
    }

    [Fact]
    public void Sec062AcceptsCapturedConfigurationSpecialIdentityWithoutInventingADomainIssuer()
    {
        var special = "CN=Authenticated users,CN=WellKnown Security Principals," + Configuration;
        var directory = Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [special]), Stub(special, "S-1-5-11"));
        using var reader = Open(directory);
        var evidence = Evidence(reader);
        var identity = evidence.Principals.Single(principal => principal.ObjectGuid == Id(special));
        using var bundle = BundleReader.Open(directory).Value;
        Assert.Equal(bundle.ReadObjectAttributes(special)!.DomainFqdn, identity.DomainFqdn);
        Assert.Null(identity.SidScope);
        Assert.Equal(Configuration, identity.NamingContext);
        Assert.True(evidence.IsComplete);
    }

    [Fact]
    public void Sec062AggregatesSourcesAndAlternativeSecurityLinksOncePerTarget()
    {
        var one = "CN=Bridge one," + Root;
        var two = "CN=Bridge two," + Root;
        var guests = "CN=Broad guests," + Root;
        using var reader = Open(Prepared(Group(Da, DomainSid + "-512", -2147483646, [one, two, guests]),
            Group(one, DomainSid + "-1201", -2147483646, [Wide]),
            Group(two, DomainSid + "-1202", -2147483646, [Wide]),
            Group(guests, DomainSid + "-514", -2147483646), Broad()));
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence);
        Assert.Equal(2, evidence.BroadSources.Count);
        Assert.Equal(5, evidence.Links.Count);
        Assert.Equal(5, evidence.Principals.Count);
        Assert.True(evidence.IsComplete);
        Assert.Contains(one + " contains " + Wide, finding.Detail);
        Assert.Contains(two + " contains " + Wide, finding.Detail);
    }

    [Fact]
    public void Sec062CyclesTerminateAndDeadNarrowBranchesAreNotSavedAsBroadRoutes()
    {
        var one = "CN=Bridge one," + Root;
        var two = "CN=Bridge two," + Root;
        var dead = "CN=Narrow branch," + Root;
        using var reader = Open(Prepared(Group(Da, DomainSid + "-512", -2147483646, [one, dead]),
            Group(one, DomainSid + "-1201", -2147483646, [two]),
            Group(two, DomainSid + "-1202", -2147483646, [one, Wide]),
            Group(dead, DomainSid + "-1203", -2147483646, [Narrow]), Broad(), User()));
        var evidence = Evidence(reader);
        Assert.True(evidence.IsComplete);
        Assert.Equal(4, evidence.Links.Count);
        Assert.DoesNotContain(evidence.Principals, principal => principal.ObjectGuid == Id(dead) || principal.ObjectGuid == Id(Narrow));
    }

    [Fact]
    public void Sec062MemberAndMemberOfWitnessesRemainOriginalAndAreNotExtraFindings()
    {
        using var reader = Open(Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]),
            Broad() with { MemberOf = [Da] }));
        var evidence = Evidence(reader);
        var link = Assert.Single(evidence.Links);
        Assert.Equal(2, link.Witnesses.Count);
        Assert.Contains(new AdministrativeMembershipWitness(Id(Da), "member", 0, Wide), link.Witnesses);
        Assert.Contains(new AdministrativeMembershipWitness(Id(Wide), "memberOf", 0, Da), link.Witnesses);
        Assert.Equal(reader.Description.EvidenceSeal, evidence.EvidenceSeal);
        Assert.Equal(reader.Description.DerivationGenerationId, evidence.DerivationGenerationId);
        Assert.Equal(PrincipalClassificationRegistry.Version, evidence.PrincipalCatalogueVersion);
    }

    [Fact]
    public void Sec062MemberOfOnlyPositiveSurvivesWithExplicitMemberListUncertainty()
    {
        using var reader = Open(Prepared(Group(Da, DomainSid + "-512", -2147483646), Broad() with { MemberOf = [Da] }));
        var evidence = Evidence(reader);
        Assert.Equal("memberOf", Assert.Single(Assert.Single(evidence.Links).Witnesses).Attribute);
        Assert.False(evidence.IsComplete);
        Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.MembershipValuesUnavailable);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec062RepeatedBuiltinSidAndSharedSourceProduceSeparateResourceDomainFindings()
    {
        var other = "CN=Administrators,CN=Builtin," + Child;
        using var reader = Open(Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [Wide]),
            Group(other, "S-1-5-32-544", -2147483643, [Wide]), Broad()));
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        Assert.Equal(2, findings.Select(finding => finding.Subject.Key).Distinct().Count());
        Assert.Collection(findings.Select(finding => finding.DomainFqdn).Order(),
            domain => Assert.Equal("child.contoso.com", domain), domain => Assert.Equal("contoso.com", domain));
        foreach (var finding in findings)
        {
            var evidence = Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence);
            Assert.Equal(finding.DomainFqdn, evidence.Principals.Single(principal => principal.ObjectGuid == evidence.TargetGuid).SidScope);
            Assert.Single(reader.ReadPage(FindingsQuery.About(finding.DistinguishedName)).Value.Findings);
        }
        Assert.Empty(reader.ReadPage(FindingsQuery.About(Wide)).Value.Findings);
    }

    [Fact]
    public void Sec062ValidForeignStubUsesTheCapturedIssuingGroupAndKeepsTheReference()
    {
        var foreignWide = "CN=Foreign broad group," + Child;
        var stub = "CN=" + ChildSid + "-513,CN=ForeignSecurityPrincipals," + Root;
        using var reader = Open(Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [stub]),
            Group(foreignWide, ChildSid + "-513", -2147483646), Stub(stub, ChildSid + "-513")));
        var evidence = Evidence(reader);
        var link = Assert.Single(evidence.Links);
        Assert.Equal((Id(foreignWide), Id(stub)), (link.MemberGuid, link.MemberReferenceGuid));
        Assert.Equal(ChildSid + "-513", Assert.Single(evidence.BroadSources).Sid);
        Assert.Equal("child.contoso.com", evidence.Principals.Single(principal => principal.ObjectGuid == link.MemberGuid).DomainFqdn);
        Assert.Contains(new AdministrativeMembershipWitness(Id(Ba), "member", 0, stub), link.Witnesses);
        Assert.True(evidence.IsComplete);
    }

    [Fact]
    public void Sec062ForeignIntermediateGroupsUseTheirOwnCapturedSecurityMembership()
    {
        var bridge = "CN=Foreign bridge," + Child;
        var foreignWide = "CN=Foreign broad group," + Child;
        var stub = "CN=" + ChildSid + "-1201,CN=ForeignSecurityPrincipals," + Root;
        using var reader = Open(Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [stub]),
            Group(bridge, ChildSid + "-1201", -2147483646, [foreignWide]),
            Group(foreignWide, ChildSid + "-513", -2147483646), Stub(stub, ChildSid + "-1201")));
        var evidence = Evidence(reader);
        Assert.Equal(2, evidence.Links.Count);
        Assert.True(evidence.IsComplete);
        Assert.Contains(evidence.Links, link => link.GroupGuid == Id(bridge) && link.MemberGuid == Id(foreignWide));
    }

    [Fact]
    public void Sec062UnsupportedForeignShortcutCannotHideASupportedLongerRoute()
    {
        var bridge = "CN=Universal bridge," + Root;
        var foreign = "CN=Foreign global bridge," + Child;
        var wide = "CN=Foreign broad group," + Child;
        var wrongReference = "CN=" + ChildSid + "-1201,CN=ForeignSecurityPrincipals," + Child;
        using var reader = Open(Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [wrongReference, bridge]),
            Group(bridge, DomainSid + "-1201", -2147483640, [foreign]),
            Group(foreign, ChildSid + "-1201", -2147483646, [wide]),
            Group(wide, ChildSid + "-513", -2147483646), Stub(wrongReference, ChildSid + "-1201")));
        var evidence = Evidence(reader);
        Assert.Equal(3, evidence.Links.Count);
        Assert.False(evidence.IsComplete);
        Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.GroupScopeUnsupported);
        Assert.DoesNotContain(evidence.Principals, identity => identity.ObjectGuid == Id(wrongReference));
    }

    [Theory]
    [InlineData("duplicate-guid")]
    [InlineData("duplicate-dn")]
    [InlineData("deleted")]
    public void Sec062AmbiguousAndDeletedCapturedIdentitiesCannotProveMembership(string variant)
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad(), User()]);
        Derive(directory);
        var verdict = Assess(directory, input => input with
        {
            Objects = input.Objects.Select(source => variant == "duplicate-guid" && source.DistinguishedName == Narrow
                ? source with { ObjectGuid = Id(Wide) }
                : variant == "duplicate-dn" && source.DistinguishedName == Narrow ? source with { DistinguishedName = Wide }
                : variant == "deleted" && source.DistinguishedName == Wide ? source with
                {
                    Attributes = [.. source.Attributes.Where(attribute => attribute.LdapDisplayName != "isDeleted"),
                        new("isDeleted", SecureAD.Kernel.Capture.AttributeCardinality.SingleValued, [new(0, "TRUE", null)])],
                } : source).ToArray(),
        });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Fact]
    public void Sec062LimitedSourceCompletenessPreservesPositiveMembershipButNotACompleteAnswer()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        Derive(directory);
        var limited = Enum.GetValues<EvidenceCompleteness>().First(value => value != EvidenceCompleteness.Complete);
        var verdict = Assess(directory, input => input with
        {
            Objects = input.Objects.Select(source => source.DistinguishedName == Wide ? source with { Completeness = limited } : source).ToArray(),
        });
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(verdict.Findings).Evidence);
        Assert.False(verdict.IsComplete);
        Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.SourceIncomplete);
        GroupMembershipFindingStorage.Validate(evidence);
    }

    [Fact]
    public void Sec062DoesNotInferAResourceContextForAnOutOfScopeSource()
    {
        const string outside = "CN=Outside,DC=unrecorded,DC=example";
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        Derive(directory);
        var verdict = Assess(directory, input => input with
        {
            Objects = input.Objects.Select(source => source.DistinguishedName == Wide ? source with { DistinguishedName = outside }
                : source.DistinguishedName == Da ? source with
                {
                    Attributes = source.Attributes.Select(attribute => attribute.LdapDisplayName == "member"
                        ? attribute with { Values = [new(0, outside, null)] } : attribute).ToArray(),
                } : source).ToArray(),
        });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sec062MissingAdministrativeTargetDoesNotTurnAnInventoryIntoACleanResult(bool positive)
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [positive ? Wide : Narrow]), Broad(), User()]);
        Derive(directory);
        var verdict = Assess(directory, input => input with
        {
            Objects = input.Objects.Where(source => source.DistinguishedName != Ea).ToArray(),
        });
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.IdentityUnreadable);
        if (positive)
        {
            var evidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(verdict.Findings).Evidence);
            Assert.False(evidence.IsComplete);
            Assert.Contains(evidence.Limitations, limit => limit.DistinguishedName == Root
                && limit.Reason == AdministrativeMembershipReason.IdentityUnverified);
        }
        else Assert.Empty(verdict.Findings);
    }

    [Fact]
    public void Sec062AnUnrelatedGroupCannotMaskIncompleteAdministrativeCapture()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Narrow]), Broad(), User()]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var input = inputs.ReadMembershipInput() with { IsComplete = false };
        var index = CapturedGroupMembershipIndex.Create(input, inputs.Binding(), inputs.ReadNamingContexts().Value, CancellationToken.None);
        var verdict = Rule.Judge(inputs.Bundle.ReadObjectAttributes(Wide)!, JudgingContext.At(Started) with { AdministrativeMembership = index });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.MembershipIncomplete);
    }

    [Fact]
    public void Sec062ZeroCapturedGroupsCannotClearDeclaredAdministrativeDomains()
    {
        var directory = Capture([]);
        Derive(directory);
        var result = Judge(directory);
        Assert.False(result.IsSuccess);
        Assert.Contains("contains no captured groups", result.Error.Description);
    }

    [Theory]
    [InlineData("DA", -2147483640)]
    [InlineData("BA", -2147483644)]
    [InlineData("EA", -2147483644)]
    public void Sec062ContradictoryAdministrativeGroupTypeCannotEstablishAuthorization(string kind, long type)
    {
        var target = kind == "DA" ? Da : kind == "EA" ? Ea : Ba;
        var sid = kind == "DA" ? DomainSid + "-512" : kind == "EA" ? DomainSid + "-519" : "S-1-5-32-544";
        using var reader = Open(Prepared(Group(target, sid, type, [Wide]), Broad()));
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec062HistoricalSidIsNotAnAdditionalMembershipSource()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]),
            Broad() with { Sid = DomainSid + "-1201", Members = [Narrow] }, User()]);
        Derive(directory);
        var verdict = Assess(directory, input => input with
        {
            Objects = input.Objects.Select(source => source.DistinguishedName == Wide ? source with
            {
                Attributes = [.. source.Attributes.Where(attribute => attribute.LdapDisplayName != "sIDHistory"),
                    new("sIDHistory", SecureAD.Kernel.Capture.AttributeCardinality.MultiValued, [new(0, null, Sid.ToBytes(DomainSid + "-513"))])],
            } : source).ToArray(),
        });
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Theory]
    [InlineData("narrow")]
    [InlineData("operator")]
    [InlineData("child-enterprise")]
    [InlineData("distribution")]
    [InlineData("primary-group-only")]
    public void Sec062CompletedNegativeControlsDoNotBecomeAdministrativeAuthorization(string variant)
    {
        var target = variant == "child-enterprise" ? "CN=Enterprise Admins," + Child : Da;
        var targetSid = variant == "operator" ? "S-1-5-32-548"
            : variant == "child-enterprise" ? ChildSid + "-519" : DomainSid + "-512";
        var type = variant == "operator" ? -2147483643L : variant == "child-enterprise" ? -2147483640L : -2147483646L;
        var bridge = "CN=Distribution bridge," + Root;
        var members = variant is "narrow" or "primary-group-only" ? new[] { Narrow } : variant == "distribution" ? [bridge] : [Wide];
        using var reader = Open(Prepared(Group(target, targetSid, type, members), Broad(), User(),
            Group(bridge, DomainSid + "-1201", 2, [Wide])));
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Theory]
    [InlineData("foreign-global")]
    [InlineData("universal-in-global")]
    [InlineData("builtin-nesting")]
    [InlineData("local-outside-resource")]
    [InlineData("special-in-global")]
    public void Sec062InvalidScopeIsExplicitlyUnknownNotAProvedPositive(string variant)
    {
        var wide = variant == "foreign-global" ? "CN=Foreign broad group," + Child : Wide;
        var sid = variant == "foreign-global" ? ChildSid + "-513" : DomainSid + "-513";
        var special = "CN=S-1-5-11,CN=ForeignSecurityPrincipals," + Root;
        var bridge = "CN=Foreign local bridge," + Child;
        var target = variant is "builtin-nesting" or "local-outside-resource" ? Ba : Da;
        var member = variant == "builtin-nesting" ? "CN=Users,CN=Builtin," + Root
            : variant == "local-outside-resource" ? bridge : variant == "special-in-global" ? special : wide;
        using var reader = Open(Prepared(Group(target, target == Ba ? "S-1-5-32-544" : DomainSid + "-512",
                target == Ba ? -2147483643 : -2147483646, [member]),
            Group(wide, sid, variant == "universal-in-global" ? -2147483640 : -2147483646),
            Group("CN=Users,CN=Builtin," + Root, "S-1-5-32-545", -2147483643),
            Group(bridge, ChildSid + "-1201", -2147483644, [wide]), Stub(special, "S-1-5-11")));
        Assert.Empty(reader.Read().Findings);
        var execution = Assert.Single(reader.ReadRuleExecutions().Executions);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Contains(execution.MissingInputs, input => input.Attribute == "AdministrativeMembership.MembershipScopeUnsupported");
    }

    [Theory]
    [InlineData("member-missing")]
    [InlineData("member-guid")]
    [InlineData("member-sid")]
    [InlineData("member-type")]
    [InlineData("target-type")]
    [InlineData("target-guid")]
    [InlineData("domain-sid")]
    [InlineData("foreign-unresolved")]
    [InlineData("ambiguous-sid")]
    public void Sec062UnavailableEvidenceCannotClearAnAdministrativeGroup(string variant)
    {
        var members = variant == "member-missing" ? new[] { "CN=Uncaptured," + Root } : new[] { Wide };
        var target = Group(Da, DomainSid + "-512", variant == "target-type" ? null : -2147483646, members)
            with { MissingGuid = variant == "target-guid" };
        var wide = Broad() with
        {
            Sid = variant == "member-sid" ? null : DomainSid + "-513",
            Type = variant == "member-type" ? null : -2147483646,
            MissingGuid = variant == "member-guid",
            Kind = variant == "foreign-unresolved" ? "foreignSecurityPrincipal" : "group",
        };
        if (variant == "foreign-unresolved") wide = wide with { Sid = ChildSid + "-513", Type = null };
        var sources = new List<Source> { target, wide };
        if (variant == "domain-sid") sources.Add(new(Root, "domainDNS", null, null, [], []));
        if (variant == "ambiguous-sid") sources.Add(Group("CN=Contradictory current identity," + Root, DomainSid + "-513", -2147483646));
        var directory = Prepared(sources.ToArray());
        using var reader = Open(directory);
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
        var targetVerdict = Assess(directory, input => input);
        Assert.Empty(targetVerdict.Findings);
        Assert.False(targetVerdict.IsComplete);
    }

    [Theory]
    [InlineData("missing-member")]
    [InlineData("missing-type")]
    [InlineData("incomplete-capture")]
    public void Sec062ProvedMembershipRemainsAFindingBesideUncertainty(string variant)
    {
        var other = "CN=Unresolved branch," + Root;
        var members = variant == "incomplete-capture" ? new[] { Wide } : new[] { Wide, other };
        var sources = new List<Source> { Group(Da, DomainSid + "-512", -2147483646, members), Broad() };
        if (variant == "missing-type") sources.Add(Group(other, DomainSid + "-1201", null));
        var directory = Capture(sources.ToArray(), partial: variant == "incomplete-capture");
        Derive(directory);
        Assert.True(Judge(directory).IsSuccess);
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings);
        Assert.False(Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence).IsComplete);
        Assert.Contains("Additional membership could not be fully assessed", finding.Detail);
        Assert.Equal(JudgementRunState.CompletedDegraded, reader.Description.State);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec062SourceInputGenerationMismatchAndCancelledPreparationAreRefused()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var input = inputs.ReadMembershipInput();
        var contexts = inputs.ReadNamingContexts().Value;
        Assert.Throws<InvalidDataException>(() => CapturedGroupMembershipIndex.Create(
            input with { DerivationGenerationId = Guid.NewGuid() }, inputs.Binding(), contexts, CancellationToken.None));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => CapturedGroupMembershipIndex.Create(
            input, inputs.Binding(), contexts, cancelled.Token));
    }

    [Fact]
    public void Sec062CurrentMemberCannotBorrowAnotherDomainsIssuer()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var input = inputs.ReadMembershipInput();
        var changed = input with
        {
            Objects = input.Objects.Select(source => source.DistinguishedName == Wide ? source with
            {
                Attributes = source.Attributes.Select(attribute => attribute.LdapDisplayName == "objectSid"
                    ? attribute with { Values = [new(0, null, Sid.ToBytes(ChildSid + "-513"))] } : attribute).ToArray(),
            } : source).ToArray(),
        };
        var index = CapturedGroupMembershipIndex.Create(changed.Prepare(CancellationToken.None), inputs.Binding(),
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var verdict = Rule.Judge(inputs.Bundle.ReadObjectAttributes(Da)!, JudgingContext.At(Started) with { AdministrativeMembership = index });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.IdentityUnreadable);
    }

    [Fact]
    public void Sec062FailedNestingAndIncompleteEmptyInputCannotPublishCleanResults()
    {
        var conflict = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad() with { Sid = ChildSid + "-513" }]);
        Derive(conflict);
        var refused = Judge(conflict);
        Assert.False(refused.IsSuccess);
        Assert.Contains("DerivedFactsAbsent", refused.Error.Code);
        var empty = Capture([], partial: true);
        Derive(empty);
        var unavailable = Judge(empty);
        Assert.False(unavailable.IsSuccess);
        Assert.Contains("contains no captured groups", unavailable.Error.Description);
    }

    [Fact]
    public void Sec062MissingContextAndDerivationAreNotEmptySuccesses()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        using var bundle = BundleReader.Open(directory).Value;
        var subject = bundle.ReadObjectAttributes(Da)!;
        Assert.Throws<InvalidOperationException>(() => Rule.Judge(subject));
        Assert.False(Rule.Judge(subject, JudgingContext.At(Started)).IsComplete);
        var result = Judge(directory);
        Assert.False(result.IsSuccess);
        Assert.Contains("DerivationUnavailable", result.Error.Code);
    }

    [Fact]
    public void Sec062MembershipOrdinalGapsRetainKnownLinksWithoutCertifyingCompleteness()
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var input = inputs.ReadMembershipInput();
        var altered = input with
        {
            Objects = input.Objects.Select(source => source.DistinguishedName == Da ? source with
            {
                Attributes = source.Attributes.Select(attribute => attribute.LdapDisplayName == "member"
                    ? attribute with { Values = attribute.Values.Select(value => value with { Ordinal = 1 }).ToArray() } : attribute).ToArray(),
            } : source).ToArray(),
        };
        var index = CapturedGroupMembershipIndex.Create(altered.Prepare(CancellationToken.None), inputs.Binding(),
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var verdict = Rule.Judge(inputs.Bundle.ReadObjectAttributes(Da)!, JudgingContext.At(Started) with { AdministrativeMembership = index });
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(verdict.Findings).Evidence);
        Assert.False(verdict.IsComplete);
        Assert.False(evidence.IsComplete);
        Assert.Equal(1, Assert.Single(Assert.Single(evidence.Links).Witnesses).Ordinal);
        Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.MembershipValuesMalformed);
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task Sec062ActualGuiAndUnattendedHostsScheduleAndSaveTheRule(string host)
    {
        var directory = Capture([Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad()]);
        await OwnAccountMembershipPathTests.RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings, finding => finding.RuleId == "SEC-062");
        Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence);
        Assert.Contains(reader.ReadRuleExecutions().Executions, execution => execution.RuleId == "SEC-062");
        Assert.Equal(BroadAdministrativeGroupMembership.Guidance, RuleGuidanceCatalogue.For("SEC-062")!.WhatToDo);
    }

    [Fact]
    public void Sec062PassivePagingPreservesTheSavedBindingAndOriginalValues()
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());
        using var reader = Open(directory);
        var before = Snapshot(directory);
        var whole = Assert.Single(reader.Read().Findings);
        var page = reader.ReadPage(FindingsQuery.About(Da));
        Assert.True(page.IsSuccess, page.Error?.Description);
        var complete = Assert.IsType<BroadGroupMembershipEvidence>(whole.Evidence);
        var paged = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(page.Value.Findings).Evidence);
        var json = JsonSerializer.Serialize(complete, ProofSerialization.Options);
        Assert.Contains("\"BroadSources\"", json, StringComparison.Ordinal);
        Assert.Equal(json, JsonSerializer.Serialize(paged, ProofSerialization.Options));
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void Sec062CaptureOrderingCannotChangeTheGroupGrainOrEvidenceOrder()
    {
        var guests = "CN=Broad guests," + Root;
        var sources = new[]
        {
            Group(Da, DomainSid + "-512", -2147483646),
            Broad() with { MemberOf = [Da] },
            Group(guests, DomainSid + "-514", -2147483646) with { MemberOf = [Da] },
        };
        using var first = Open(Prepared(sources));
        using var second = Open(Prepared(sources.Reverse().ToArray()));
        var one = Assert.Single(first.Read().Findings);
        var two = Assert.Single(second.Read().Findings);
        Assert.Equal((one.Subject, one.ObjectGuid, one.Detail), (two.Subject, two.ObjectGuid, two.Detail));
        var a = Assert.IsType<BroadGroupMembershipEvidence>(one.Evidence);
        var b = Assert.IsType<BroadGroupMembershipEvidence>(two.Evidence);
        Assert.Equal(a.Principals.Select(principal => principal.ObjectGuid), b.Principals.Select(principal => principal.ObjectGuid));
        Assert.Equal(a.Links.Select(link => (link.GroupGuid, link.MemberGuid)), b.Links.Select(link => (link.GroupGuid, link.MemberGuid)));
        var directory = Capture(sources);
        Derive(directory);
        var direct = Assess(directory, input => input);
        var reordered = Assess(directory, input => input with { Objects = input.Objects.Reverse().ToArray() });
        var directEvidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(direct.Findings).Evidence);
        var reorderedEvidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reordered.Findings).Evidence);
        var json = JsonSerializer.Serialize(directEvidence, ProofSerialization.Options);
        Assert.Contains("\"Links\"", json, StringComparison.Ordinal);
        Assert.Equal(json, JsonSerializer.Serialize(reorderedEvidence, ProofSerialization.Options));
    }

    [Theory]
    [InlineData("$.EvidenceSeal", "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")]
    [InlineData("$.DerivationGenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.PrincipalCatalogueVersion", "999")]
    [InlineData("$.PolicyVersion", "999")]
    [InlineData("$.TargetGuid", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.BroadSources[0].Sid", "'S-1-5-21-1-2-3-1100'")]
    [InlineData("$.Links[0].Witnesses[0].Ordinal", "-1")]
    [InlineData("$.Links[0].Witnesses[0].Value", "'CN=Unrelated,DC=contoso,DC=com'")]
    [InlineData("$.Principals[0].GroupType", "2")]
    [InlineData("$.Principals[0].SidScope", "'wrong.example'")]
    public void Sec062SavedReadRejectsRehashedBindingAndProofCorruption(string path, string value)
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding_broad_group_membership SET proof=json_set(proof,$path,{value})";
            command.Parameters.AddWithValue("$path", path);
            Assert.Equal(1, command.ExecuteNonQuery());
            RefreshFingerprint(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(Da)));
    }

    [Fact]
    public void Sec062PublicationRequiresTheTypedBodyAndOriginalEvidenceHash()
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());
        using var reader = Open(directory);
        var copyDirectory = TestSealing.CopyJudgement(directory, reader.Description.GenerationId, "sec062-publish-check");
        var copy = BundleLayout.AnalysisGenerationDataPath(copyDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = copy, Pooling = false, ForeignKeys = false }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, copyDirectory, reader.Description.GenerationId);
        var derivationSeal = FindingInputBinding.DerivationSeal(directory, reader.Description.DerivationGenerationId);
        GroupMembershipFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None);
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE finding_broad_group_membership SET fingerprint=zeroblob(32)";
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => GroupMembershipFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None));
        RefreshFingerprint(connection);
        command.CommandText = "UPDATE finding SET rule_id='SEC-026' WHERE rule_id='SEC-062'";
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => GroupMembershipFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None));
        command.CommandText = "UPDATE finding SET rule_id='SEC-062' WHERE rule_id='SEC-026'";
        Assert.Equal(1, command.ExecuteNonQuery());
        command.CommandText = "DELETE FROM finding_broad_group_membership";
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => GroupMembershipFindingStorage.RequirePublishable(connection, derivationSeal, CancellationToken.None));
    }

    [Fact]
    public void Sec062SavedRowGenerationCannotBeRelabelledEvenWithARefreshedHash()
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE finding_broad_group_membership SET generation=$generation";
            command.Parameters.AddWithValue("$generation", Guid.NewGuid().ToString("D"));
            Assert.Equal(1, command.ExecuteNonQuery());
            RefreshFingerprint(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Fact]
    public void Sec062GuidanceKeepsTheApprovedSeverityAndMembershipOnlyClaim()
    {
        Assert.Equal(Severity.High, Rule.Definition.Severity);
        Assert.Equal(1, Rule.Definition.Version);
        var guidance = RuleGuidanceCatalogue.For("SEC-062")!;
        Assert.Equal("Broad membership reaches this administrative group through the recorded security-group relationships. "
            + "This finding does not prove a successful logon or account takeover.", guidance.WhyItMatters);
        Assert.Equal("Review and remove unintended broad membership paths, replace them with role-specific security groups, "
            + "and check the other recorded routes before concluding the exposure is removed.", guidance.WhatToDo);
    }

    [Theory]
    [InlineData("missing-domain")]
    [InlineData("domain-sid")]
    [InlineData("foreign-reference")]
    [InlineData("disconnected")]
    [InlineData("missing-link")]
    [InlineData("missing-source")]
    [InlineData("identity-value")]
    [InlineData("unsupported-scope")]
    [InlineData("missing-partial-limitation")]
    public void Sec062TypedEvidenceValidationRejectsDisconnectedUnqualifiedOrFalselyCompleteProofs(string variant)
    {
        var wide = "CN=Foreign broad group," + Child;
        var stub = "CN=" + ChildSid + "-513,CN=ForeignSecurityPrincipals," + Root;
        using var reader = Open(Prepared(Group(Ba, "S-1-5-32-544", -2147483643, [stub]),
            Group(wide, ChildSid + "-513", -2147483646), Stub(stub, ChildSid + "-513")));
        var evidence = Evidence(reader);
        var invalid = variant switch
        {
            "missing-domain" => evidence with { Domains = evidence.Domains.Where(domain => domain.DomainFqdn != "child.contoso.com").ToArray() },
            "domain-sid" => evidence with { Domains = evidence.Domains.Select(domain => domain.DomainFqdn == "child.contoso.com"
                ? domain with { Sid = DomainSid } : domain).ToArray() },
            "foreign-reference" => evidence with { Links = evidence.Links.Select(link => link with { MemberReferenceGuid = link.GroupGuid }).ToArray() },
            "disconnected" => evidence with
            {
                Principals = evidence.Principals.Where(identity => identity.ObjectGuid != Id(stub)).ToArray(),
                Links = [new(Id(wide), Id(wide), Id(wide), [new(Id(wide), "member", 0, wide)])],
            },
            "missing-link" => evidence with { Links = [] },
            "missing-source" => evidence with { BroadSources = [] },
            "identity-value" => evidence with { Principals = evidence.Principals.Select(identity => identity with
                { Values = identity.Values.Where(value => value.Attribute != "objectSid").ToArray() }).ToArray() },
            "unsupported-scope" => evidence with { Principals = evidence.Principals.Select(identity => identity.ObjectGuid == Id(wide)
                ? identity with { GroupType = -2147483644, Values = identity.Values.Select(value => value.Attribute == "groupType"
                    ? value with { Value = "-2147483644" } : value).ToArray() } : identity).ToArray() },
            _ => evidence with { InputsComplete = false, Limitations = [] },
        };
        Assert.Throws<InvalidDataException>(() => GroupMembershipFindingStorage.Validate(invalid));
    }

    [Theory]
    [InlineData("subject_key")]
    [InlineData("subject_kind")]
    [InlineData("domain_fqdn")]
    [InlineData("distinguished_name")]
    [InlineData("severity")]
    public void Sec062SavedReadRefusesChangedFindingIdentity(string column)
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding SET {column}=$value WHERE rule_id='SEC-062'";
            command.Parameters.AddWithValue("$value", column == "severity" ? "Low" : column == "subject_kind" ? "Account" : "wrong");
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Fact]
    public void Sec062CancelledPublicationKeepsThePreviouslyPublishedResult()
    {
        var directory = Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());
        Guid generation;
        using (var before = Open(directory)) generation = before.Description.GenerationId;
        using var cancelling = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => JudgingRun.Judge(directory, [Rule], Started, Started,
            new StopPublication(cancelling), RunLog.Discarded, cancelling.Token));
        using var after = Open(directory);
        Assert.Equal(generation, after.Description.GenerationId);
        Assert.Equal(Id(Da).ToString("D"), Assert.Single(after.Read().Findings).Subject.Key);
    }

    private sealed class StopPublication(CancellationTokenSource cancellation) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.PublishingJudgement) cancellation.Cancel();
        }
    }

    internal sealed record Source(string Dn, string Kind, string? Sid, long? Type, string[] Members, string[] MemberOf,
        bool MissingGuid = false, int PrimaryGroup = 513);

    internal static Source Group(string dn, string sid, long? type, string[]? members = null) => new(dn, "group", sid, type, members ?? [], []);
    private static Source Broad() => Group(Wide, DomainSid + "-513", -2147483646);
    internal static Source Stub(string dn, string sid) => new(dn, "foreignSecurityPrincipal", sid, null, [], []);
    private static Source User() => new(Narrow, "user", DomainSid + "-1100", null, [], []);
    internal static Guid Id(string dn) => new(SHA256.HashData(Encoding.UTF8.GetBytes(dn)).AsSpan(0, 16));

    private static string Prepared(params Source[] sources)
    {
        var directory = Capture(sources);
        Derive(directory);
        var judged = Judge(directory);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    private static Result<JudgementRunState> Judge(string directory) => JudgingRun.Judge(directory,
        [RuleCatalogue.All.Single(rule => rule.Definition.Id == "SEC-062")], Started, Started,
        JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }

    private static BroadGroupMembershipEvidence Evidence(JudgementReader reader) =>
        Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        using var reader = Open(FindingsRun());
        var page = reader.ReadPage(FindingsQuery.About(Da));
        Assert.True(page.IsSuccess, page.Error?.Description);
        return page.Value.Findings;
    }

    internal static string FindingsRun() => Prepared(Group(Da, DomainSid + "-512", -2147483646, [Wide]), Broad());

    private static RuleVerdict Assess(string directory, Func<CapturedMembershipInput, CapturedMembershipInput> change)
    {
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var input = change(inputs.ReadMembershipInput()).Prepare(CancellationToken.None);
        var index = CapturedGroupMembershipIndex.Create(input, inputs.Binding(), inputs.ReadNamingContexts().Value, CancellationToken.None);
        return Rule.Judge(inputs.Bundle.ReadObjectAttributes(Da)!, JudgingContext.At(Started) with { AdministrativeMembership = index });
    }

    internal static string Capture(IReadOnlyList<Source> sources, bool partial = false)
    {
        var directory = TempDirectories.Create("sec062");
        using var writer = BundleWriter.Create(directory, Started);
        foreach (var (context, kind) in new[] { (Root, NamingContextKind.Domain), (Child, NamingContextKind.Domain), (Configuration, NamingContextKind.Configuration) })
        {
            if (partial && context == Child) continue;
            var partition = new PartitionCoverage(context, kind, "dc01.contoso.com",
                ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(partition);
            if (kind == NamingContextKind.Domain && sources.All(source => source.Dn != context))
                Write(new(context, "domainDNS", context == Root ? DomainSid : ChildSid, null, [], []));
            foreach (var source in sources.Where(source => Context(source.Dn) == context)) Write(source);
            if (kind == NamingContextKind.Domain && sources.Count != 0)
            {
                var domainSid = context == Root ? DomainSid : ChildSid;
                var administrator = "CN=Narrow fixture administrator," + context;
                Write(new(administrator, "user", domainSid + "-500", null, [], []));
                var defaults = new List<Source>
                {
                    Group("CN=Fixture domain administrators," + context, domainSid + "-512", -2147483646, [administrator]),
                    Group("CN=Fixture administrators,CN=Builtin," + context, "S-1-5-32-544", -2147483643, [administrator]),
                };
                if (context == Root)
                {
                    defaults.Add(Group(Ea, domainSid + "-519", -2147483640, [administrator]));
                    defaults.Add(Group(Sa, domainSid + "-518", -2147483640, [administrator]));
                }
                foreach (var target in defaults)
                    if (!sources.Any(source => source.Sid == target.Sid && Context(source.Dn) == context)) Write(target);
            }

            void Write(Source source)
            {
                var attributes = new List<EvidenceAttribute>
                {
                    Texts("objectClass", ["top", source.Kind]),
                    new("objectSid", StoredAttributeCompleteness.Complete,
                        source.Sid is null ? [] : [EvidenceValue.OfBytes(Sid.ToBytes(source.Sid)!)]),
                    Texts("groupType", source.Type is null ? [] : [source.Type.Value.ToString(CultureInfo.InvariantCulture)]),
                    Texts("member", source.Members),
                    Texts("memberOf", source.MemberOf),
                };
                if (source.Kind == "user")
                {
                    attributes.Add(Texts("userAccountControl", ["512"]));
                    attributes.Add(Texts("primaryGroupID", [source.PrimaryGroup.ToString(CultureInfo.InvariantCulture)]));
                }
                writer.WriteObject(new(partition, source.Dn, source.MissingGuid ? null : Id(source.Dn), attributes, Started));
            }
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com", "child.contoso.com"]),
            [DomainCoverage.Read("contoso.com"), partial ? DomainCoverage.Excluded("child.contoso.com", ExclusionKind.ByChoice, "Synthetic incomplete scope")
                : DomainCoverage.Read("child.contoso.com")],
            [ForestPartitionCoverage.Read(Configuration, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema," + Configuration, NamingContextKind.Schema)], SysvolCoverage.Of([])),
            Started.AddMinutes(1));
        return directory;
    }

    private static string Context(string dn) => dn.EndsWith(Configuration, StringComparison.OrdinalIgnoreCase) ? Configuration
        : dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase) ? Child : Root;
    private static EvidenceAttribute Texts(string name, IEnumerable<string> values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static void RefreshFingerprint(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT generation,proof FROM finding_broad_group_membership";
        string generation;
        string json;
        using (var read = command.ExecuteReader())
        {
            Assert.True(read.Read());
            generation = read.GetString(0);
            json = read.GetString(1);
        }
        command.CommandText = "UPDATE finding_broad_group_membership SET fingerprint=$hash";
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation + "\0" + json));
        Assert.Equal(1, command.ExecuteNonQuery());
    }

    private static string[] Snapshot(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();
}
