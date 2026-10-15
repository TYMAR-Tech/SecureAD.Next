using System.Globalization;
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
using Fixtures = SecureAD.Next.Tests.Judgement.BroadAdministrativeGroupMembershipTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class MembershipReviewRuleTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Child = "DC=child," + Root;
    private const string DomainSid = "S-1-5-21-1-2-3";
    private const string ChildSid = "S-1-5-21-4-5-6";
    private const string Da = "CN=Renamed privileged group," + Root;
    private const string Legacy = "CN=Renamed legacy group,CN=Builtin," + Root;
    private const string ChildLegacy = "CN=Renamed legacy group,CN=Builtin," + Child;
    private const string Wide = "CN=Broad captured group," + Root;
    private const string Bridge = "CN=Nested captured group," + Root;
    private const string Other = "CN=Other nested group," + Root;
    private static readonly IRule SizeRule = new LargePrivilegedGroupReview();
    private static readonly IRule NestedRule = new GroupNestedInDomainAdmins();
    private static readonly IRule LegacyRule = new BroadPreWindows2000Membership();

    [Theory]
    [InlineData("DA", 9, false)]
    [InlineData("DA", 10, false)]
    [InlineData("DA", 11, true)]
    [InlineData("EA", 4, false)]
    [InlineData("EA", 5, false)]
    [InlineData("EA", 6, true)]
    [InlineData("SA", 4, false)]
    [InlineData("SA", 5, false)]
    [InlineData("SA", 6, true)]
    [InlineData("BA", 14, false)]
    [InlineData("BA", 15, false)]
    [InlineData("BA", 16, true)]
    public void Sec050AppliesApprovedStrictDirectThresholdsToVerifiedRoles(string role, int count, bool expected)
    {
        var members = Accounts(count);
        var target = Target(role, members.Select(source => source.Dn).ToArray());
        using var reader = Published([SizeRule], [target, .. members]);
        var findings = reader.Read().Findings.Where(finding => finding.RuleId == "SEC-050").ToArray();
        Assert.Equal(expected ? 1 : 0, findings.Length);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
        if (!expected) return;
        var finding = Assert.Single(findings);
        var evidence = Assert.IsType<GroupMembershipReviewEvidence>(finding.Evidence);
        Assert.Equal((Severity.Low, Fixtures.Id(target.Dn), count), (finding.Severity, finding.ObjectGuid, evidence.DirectMembers));
        Assert.Equal(role == "DA" ? 10 : role == "BA" ? 15 : 5, evidence.ReviewThreshold);
        Assert.Equal(count, evidence.KnownTotal!.KnownMembers);
        Assert.True(evidence.IsComplete);
        Assert.Equal(count, evidence.MemberValues.Count);
        Assert.Equal("Large privileged group", SizeRule.Definition.Name);
        Assert.Contains("Direct count: " + count.ToString(CultureInfo.InvariantCulture), finding.Detail);
        Assert.Contains("Known total: " + count.ToString(CultureInfo.InvariantCulture), finding.Detail);
    }

    [Fact]
    public void Sec050DistinctReferencesMatchInventoryRatherThanOccurrences()
    {
        var members = Accounts(10);
        var values = members.Select(source => source.Dn).Concat([members[0].Dn, members[0].Dn.ToUpperInvariant()]).ToArray();
        using var reader = Published([SizeRule], [Target("DA", values), .. members]);
        Assert.Empty(reader.Read().Findings);
        var groups = reader.ReadGroupInventory(new(null, ListingScope.Subtree, "", GroupInventoryScope.All, GroupInventoryKind.All,
            false, GroupInventorySort.Name), null, CancellationToken.None);
        Assert.Equal(10, Assert.Single(groups.Groups, group => group.DistinguishedName == Da).DirectMembers);
    }

    [Fact]
    public void Sec050DirectCountAndKnownTotalKeepNestingAndPrimaryGroupSeparate()
    {
        var accounts = Accounts(30);
        var direct = accounts.Take(9).Select(source => source.Dn).Concat([Bridge, Other]).ToArray();
        var primary = new Fixtures.Source("CN=Primary-only account," + Root, "user", DomainSid + "-2000", null, [], [], PrimaryGroup: 512);
        using var reader = Published([SizeRule], [Target("DA", direct), .. accounts,
            Fixtures.Group(Bridge, DomainSid + "-1201", -2147483646, accounts.Skip(9).Select(source => source.Dn).ToArray()),
            Fixtures.Group(Other, DomainSid + "-1202", -2147483646, [accounts[0].Dn]), primary]);
        var evidence = Assert.IsType<GroupMembershipReviewEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(11, evidence.DirectMembers);
        Assert.Equal(32, evidence.KnownTotal!.KnownMembers);
        Assert.DoesNotContain(evidence.MemberValues, value => value.Text == primary.Dn);
        Assert.DoesNotContain("Known total: 33", Assert.Single(reader.Read().Findings).Detail);
    }

    [Theory]
    [InlineData("operator")]
    [InlineData("child-enterprise")]
    [InlineData("child-schema")]
    public void Sec050DoesNotWidenItsFourVerifiedRoleScopes(string variant)
    {
        var context = variant == "operator" ? Root : Child;
        var accounts = Accounts(16, context);
        var target = Fixtures.Group("CN=Domain Admins," + context, variant == "operator" ? "S-1-5-32-548"
            : ChildSid + (variant == "child-enterprise" ? "-519" : "-518"), variant == "operator" ? -2147483643 : -2147483640,
            accounts.Select(source => source.Dn).ToArray());
        using var reader = Published([SizeRule], [target, .. accounts]);
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec050UncapturedMembersRemainCountedReferencesWithIncompleteKnownTotal()
    {
        var missing = Enumerable.Range(0, 11).Select(index => "CN=Uncaptured " + index + "," + Root).ToArray();
        using var reader = Published([SizeRule], [Target("DA", missing)]);
        var evidence = Assert.IsType<GroupMembershipReviewEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(11, evidence.DirectMembers);
        Assert.Equal(0, evidence.KnownTotal!.KnownMembers);
        Assert.Equal(11, evidence.KnownTotal.UnresolvedReferences);
        Assert.Contains(nameof(GroupMembershipLimitations.UnresolvedReferences), evidence.KnownTotal.Limitations);
        Assert.False(evidence.IsComplete);
    }

    [Theory]
    [InlineData("wrong-group-type")]
    [InlineData("missing-guid")]
    public void Sec050UnverifiedTargetsAreExplicitlyUnassessed(string variant)
    {
        var accounts = Accounts(11);
        var target = Target("DA", accounts.Select(source => source.Dn).ToArray());
        target = variant switch
        {
            "wrong-domain-sid" => target with { Sid = ChildSid + "-512" },
            "wrong-group-type" => target with { Type = -2147483640 },
            _ => target with { MissingGuid = true },
        };
        using var reader = Published([SizeRule], [target, .. accounts]);
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec050WrongDomainTargetIsUnassessedEvenWhenNestingWasDerived()
    {
        var accounts = Accounts(11);
        var directory = CaptureForRules([Target("DA", accounts.Select(source => source.Dn).ToArray()), .. accounts]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var source = inputs.Bundle.ReadObjectAttributes(Da)!;
        var altered = source with
        {
            Attributes = source.Attributes.Select(attribute => attribute.LdapDisplayName == "objectSid"
                ? attribute with { Values = [new(0, null, Sid.ToBytes(ChildSid + "-512"))] } : attribute).ToArray(),
        };
        var input = inputs.ReadMembershipInput() with
        {
            Objects = inputs.ReadMembershipInput().Objects.Select(item => item.DistinguishedName == Da ? altered : item).ToArray(),
        };
        var index = CapturedGroupMembershipIndex.Create(input.Prepare(CancellationToken.None), inputs.Binding(),
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var verdict = new LargePrivilegedGroupReview().Judge(altered, JudgingContext.At(Started) with { AdministrativeMembership = index });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.IdentityUnreadable);
    }

    [Theory]
    [InlineData(-2147483646L)]
    [InlineData(2L)]
    [InlineData(null)]
    public void Sec051ReviewsTheRecordedGroupLinkWithoutClaimingAuthorization(long? type)
    {
        using var reader = Published([NestedRule], [Target("DA", [Bridge]), Fixtures.Group(Bridge, DomainSid + "-1201", type)]);
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<GroupMembershipReviewEvidence>(finding.Evidence);
        Assert.Equal((Severity.Low, Fixtures.Id(Bridge), Bridge), (finding.Severity, finding.ObjectGuid, finding.DistinguishedName));
        Assert.Equal(GroupNestedInDomainAdmins.Key(Fixtures.Id(Bridge), Fixtures.Id(Da)), finding.Subject.Key);
        Assert.Equal(Fixtures.Id(Da), evidence.TargetGuid);
        Assert.Equal(Fixtures.Id(Bridge), evidence.NestedGroupGuid);
        var witness = Assert.Single(Assert.Single(evidence.Links).Witnesses);
        Assert.Equal(("member", 0, Bridge), (witness.Attribute, witness.Ordinal, witness.Value));
        Assert.Contains("Nesting may be intentional", finding.Detail);
        if (type is null)
        {
            Assert.False(evidence.IsComplete);
            Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.GroupTypeUnavailable);
        }
    }

    [Fact]
    public void Sec051GroupsDuplicateOccurrencesAndRetainsEveryOriginalLink()
    {
        using var reader = Published([NestedRule], [Target("DA", [Bridge, Bridge.ToUpperInvariant()]),
            Fixtures.Group(Bridge, DomainSid + "-1201", -2147483646)]);
        var evidence = Assert.IsType<GroupMembershipReviewEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal([0, 1], evidence.MemberValues.Select(value => value.Ordinal));
        Assert.Equal(2, Assert.Single(evidence.Links).Witnesses.Count);
    }

    [Fact]
    public void Sec051KeepsOneFindingPerGroupAndDomainAdminsPair()
    {
        var childDa = "CN=Other domain administrators," + Child;
        using var reader = Published([NestedRule], [Target("DA", [Bridge]),
            Fixtures.Group(childDa, ChildSid + "-512", -2147483646, [Bridge]),
            Fixtures.Group(Bridge, DomainSid + "-1201", -2147483640)]);
        var findings = reader.Read().Findings.Where(finding => finding.RuleId == "SEC-051").ToArray();
        Assert.Equal(2, findings.Length);
        Assert.All(findings, finding => Assert.Equal(Fixtures.Id(Bridge), finding.ObjectGuid));
        Assert.Equal(2, findings.Select(finding => finding.Subject.Key).Distinct().Count());
    }

    [Fact]
    public void Sec051OnlyDirectGroupsNotNestedDescendantsAccountsOrBacklinksTrigger()
    {
        var user = Accounts(1)[0];
        using var reader = Published([NestedRule], [Target("DA", [Bridge, user.Dn]),
            Fixtures.Group(Bridge, DomainSid + "-1201", -2147483646, [Other]),
            Fixtures.Group(Other, DomainSid + "-1202", -2147483646),
            Fixtures.Group("CN=Backlink-only group," + Root, DomainSid + "-1203", -2147483646) with { MemberOf = [Da] }, user]);
        Assert.Equal(Bridge, Assert.Single(reader.Read().Findings).DistinguishedName);
    }

    [Fact]
    public void Sec051ResolvesCurrentForeignGroupReferenceWithoutLosingTheStub()
    {
        var foreign = "CN=Foreign group," + Child;
        var stub = "CN=Foreign stub,CN=ForeignSecurityPrincipals," + Root;
        using var reader = Published([NestedRule], [Target("DA", [stub]), Fixtures.Stub(stub, ChildSid + "-1201"),
            Fixtures.Group(foreign, ChildSid + "-1201", -2147483640)]);
        var evidence = Assert.IsType<GroupMembershipReviewEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        var link = Assert.Single(evidence.Links);
        Assert.Equal((Fixtures.Id(foreign), Fixtures.Id(stub)), (link.MemberGuid, link.MemberReferenceGuid));
        Assert.Equal(stub, Assert.Single(link.Witnesses).Value);
    }

    [Fact]
    public void Sec051UnknownMembersDoNotBecomeAnEmptySuccessfulReview()
    {
        using var reader = Published([NestedRule], [Target("DA", ["CN=Uncaptured," + Root])]);
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-7")]
    [InlineData("S-1-5-11")]
    public void Sec061UsesSymbolicBroadMembershipAndResourceScopedLegacyIdentity(string sid)
    {
        var stub = "CN=Broad reference,CN=ForeignSecurityPrincipals," + Root;
        using var reader = Published([LegacyRule], [LegacyGroup([stub]), Fixtures.Stub(stub, sid)]);
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence);
        Assert.Equal(("SEC-061", Severity.Medium, Legacy, Fixtures.Id(Legacy)), (finding.RuleId, finding.Severity, finding.DistinguishedName, evidence.TargetGuid));
        Assert.Equal(BroadMembershipTarget.PreWindows2000CompatibleAccess, evidence.TargetKind);
        Assert.Equal(sid, Assert.Single(evidence.BroadSources).Sid);
        Assert.True(evidence.IsComplete);
        Assert.Contains("does not establish object-specific read access", finding.Detail);
    }

    [Theory]
    [InlineData(513)]
    [InlineData(514)]
    [InlineData(515)]
    public void Sec061UsesCapturedBroadGroupIdentityWithoutEnumeratingItsPopulation(int rid)
    {
        using var reader = Published([LegacyRule], [LegacyGroup([Wide]),
            Fixtures.Group(Wide, DomainSid + "-" + rid, -2147483646, ["CN=Uncaptured population," + Root])]);
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(2, evidence.Principals.Count);
        Assert.True(evidence.IsComplete);
        Assert.Equal(DomainSid + "-" + rid, Assert.Single(evidence.BroadSources).Sid);
    }

    [Fact]
    public void Sec061KeepsAlternativeSecurityLinksAndPositiveMembershipBesideGaps()
    {
        using var reader = Published([LegacyRule], [LegacyGroup([Bridge, Other, "CN=Missing," + Root]),
            Fixtures.Group(Bridge, DomainSid + "-1201", -2147483646, [Wide]),
            Fixtures.Group(Other, DomainSid + "-1202", -2147483646, [Wide]),
            Fixtures.Group(Wide, DomainSid + "-513", -2147483646)]);
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(4, evidence.Links.Count);
        Assert.Single(evidence.BroadSources);
        Assert.False(evidence.IsComplete);
        Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.MemberUncaptured);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Theory]
    [InlineData("narrow")]
    [InlineData("distribution")]
    [InlineData("self-only")]
    public void Sec061DoesNotFlagNamedMembersDistributionRoutesOrItsOwnBroadClassification(string variant)
    {
        var user = Accounts(1)[0];
        var member = variant == "self-only" ? Legacy : variant == "distribution" ? Bridge : user.Dn;
        using var reader = Published([LegacyRule], [LegacyGroup([member]), user,
            Fixtures.Group(Bridge, DomainSid + "-1201", 2, [Wide]), Fixtures.Group(Wide, DomainSid + "-513", -2147483646)]);
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(variant == "self-only" ? RuleExecutionOutcome.Indeterminate : RuleExecutionOutcome.Succeeded,
            Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec061OwnCycleCannotEraseIndependentBroadMembership()
    {
        using var reader = Published([LegacyRule], [LegacyGroup([Legacy, Wide]), Fixtures.Group(Wide, DomainSid + "-513", -2147483646)]);
        var evidence = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Single(evidence.Links);
        Assert.DoesNotContain(evidence.BroadSources, source => source.IdentityGuids.Contains(evidence.TargetGuid));
    }

    [Fact]
    public void Sec061SameBuiltinSidInTwoDomainsProducesSeparateFindings()
    {
        var rootStub = "CN=Broad,CN=ForeignSecurityPrincipals," + Root;
        var childStub = "CN=Broad,CN=ForeignSecurityPrincipals," + Child;
        using var reader = Published([LegacyRule], [LegacyGroup([rootStub]), Fixtures.Stub(rootStub, "S-1-5-11"),
            Fixtures.Group(ChildLegacy, "S-1-5-32-554", -2147483643, [childStub]), Fixtures.Stub(childStub, "S-1-5-11")]);
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        Assert.Equal(2, findings.Select(finding => finding.DomainFqdn).Distinct().Count());
    }

    [Fact]
    public void SharedBroadAssessmentsCannotTurnLegacyMembershipIntoAnAdministrativeFinding()
    {
        using var reader = Published([LegacyRule, new BroadAdministrativeGroupMembership()], [
            LegacyGroup([Wide]), Fixtures.Group(Wide, DomainSid + "-513", -2147483646)]);
        Assert.Equal("SEC-061", Assert.Single(reader.Read().Findings).RuleId);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    [InlineData("SEC-061")]
    public void MembershipRulesRequireTheirDeclaredContextAndDerivedInputs(string ruleId)
    {
        var rule = Rule(ruleId);
        var directory = CaptureForRules([LegacyGroup([Wide]), Fixtures.Group(Wide, DomainSid + "-513", -2147483646)]);
        using var bundle = BundleReader.Open(directory).Value;
        var subject = bundle.ReadObjectAttributes(Legacy)!;
        var objectRule = Assert.IsAssignableFrom<IObjectRule>(rule);
        Assert.Throws<InvalidOperationException>(() => objectRule.Judge(subject));
        Assert.False(objectRule.Judge(subject, JudgingContext.At(Started)).IsComplete);
        var refused = JudgingRun.Judge(directory, [rule], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.False(refused.IsSuccess);
        Assert.Contains("DerivationUnavailable", refused.Error.Code);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    [InlineData("SEC-061")]
    public void MembershipFindingsPreserveTypedWholeAndPagedReadbackWithoutReplayingAnalysis(string ruleId)
    {
        using var reader = Published([Rule(ruleId)], PositiveSources());
        var whole = Assert.Single(reader.Read().Findings, finding => finding.RuleId == ruleId);
        var page = reader.ReadPage(FindingsQuery.About(whole.DistinguishedName));
        Assert.True(page.IsSuccess, page.Error?.Description);
        var paged = Assert.Single(page.Value.Findings, finding => finding.RuleId == ruleId);
        Assert.Equal(JsonSerializer.Serialize(whole.Evidence, whole.Evidence.GetType(), ProofSerialization.Options),
            JsonSerializer.Serialize(paged.Evidence, paged.Evidence.GetType(), ProofSerialization.Options));
        var row = new SecureAD.Shell.ViewModels.FindingRowViewModel(whole);
        Assert.DoesNotContain("Unknown", row.Coverage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SEC-050", "generation")]
    [InlineData("SEC-050", "fingerprint")]
    [InlineData("SEC-051", "generation")]
    [InlineData("SEC-061", "fingerprint")]
    public void SavedMembershipMetadataRefusesChangedGenerationOrFingerprint(string ruleId, string field)
    {
        var directory = Prepared([Rule(ruleId)], PositiveSources());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            var table = ruleId == "SEC-061" ? "finding_broad_group_membership" : "finding_membership_review";
            command.CommandText = $"UPDATE {table} SET {field}=" + (field == "generation" ? "'00000000-0000-0000-0000-000000000001'" : "zeroblob(32)");
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(ruleId == "SEC-051" ? Bridge : ruleId == "SEC-061" ? Legacy : Da)));
    }

    [Theory]
    [InlineData("SEC-050", "subject_key")]
    [InlineData("SEC-051", "subject_kind")]
    [InlineData("SEC-061", "domain_fqdn")]
    [InlineData("SEC-061", "object_class")]
    [InlineData("SEC-050", "severity")]
    [InlineData("SEC-051", "distinguished_name")]
    public void SavedMembershipRowsRefuseChangedFindingIdentity(string ruleId, string field)
    {
        var directory = Prepared([Rule(ruleId)], PositiveSources());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding SET {field}=$value WHERE rule_id=$rule";
            command.Parameters.AddWithValue("$value", field == "severity" ? "High" : field == "subject_kind" ? "Account" : "wrong");
            command.Parameters.AddWithValue("$rule", ruleId);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    [InlineData("SEC-061")]
    public void MissingTypedMembershipEvidenceNeverBecomesAnEmptyOrUntypedFinding(string ruleId)
    {
        var directory = Prepared([Rule(ruleId)], PositiveSources());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM " + (ruleId == "SEC-061" ? "finding_broad_group_membership" : "finding_membership_review");
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Fact]
    public void Sec050SavedKnownTotalMustMatchTheSameGenerationInventory()
    {
        var directory = Prepared([SizeRule], PositiveSources());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE group_inventory SET known_total=known_total+1 WHERE distinguished_name=$dn";
            command.Parameters.AddWithValue("$dn", Da);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    [InlineData("SEC-061")]
    public void PublicationRefusesMissingTypedMembershipMetadataAndWrongDerivationSeal(string ruleId)
    {
        var directory = Prepared([Rule(ruleId)], PositiveSources());
        using var reader = Open(directory);
        var working = TestSealing.CopyJudgement(directory, reader.Description.GenerationId, "membership-publication-check");
        var copy = BundleLayout.AnalysisGenerationDataPath(working, AnalysisStoreKind.Judgement, reader.Description.GenerationId);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = copy, Pooling = false, ForeignKeys = false }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, working, reader.Description.GenerationId);
        var seal = FindingInputBinding.DerivationSeal(directory, reader.Description.DerivationGenerationId);
        void Require(string? expected)
        {
            if (ruleId == "SEC-061") GroupMembershipFindingStorage.RequirePublishable(connection, expected, CancellationToken.None);
            else GroupMembershipReviewFindingStorage.RequirePublishable(connection, expected, CancellationToken.None);
        }
        Require(seal);
        Assert.Throws<InvalidDataException>(() => Require(new string('f', 64)));
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM " + (ruleId == "SEC-061" ? "finding_broad_group_membership" : "finding_membership_review");
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => Require(seal));
    }

    [Theory]
    [InlineData("threshold")]
    [InlineData("count")]
    [InlineData("target")]
    [InlineData("catalogue")]
    [InlineData("policy")]
    [InlineData("known-total")]
    public void Sec050RehashedMetadataCannotChangeTheSavedPolicyOrAnswer(string field)
    {
        var directory = Prepared([SizeRule], PositiveSources());
        ChangeReviewProof(directory, evidence => field switch
        {
            "threshold" => evidence with { ReviewThreshold = 9 },
            "count" => evidence with { DirectMembers = 12 },
            "target" => evidence with { TargetGuid = Guid.NewGuid() },
            "catalogue" => evidence with { PrincipalCatalogueVersion = 999 },
            "policy" => evidence with { PolicyVersion = 999 },
            _ => evidence with { KnownTotal = evidence.KnownTotal! with { KnownMembers = 999 } },
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("child")]
    [InlineData("witness")]
    [InlineData("source-ordinal")]
    [InlineData("resource")]
    public void Sec051RehashedMetadataCannotChangeItsOriginalRelationship(string field)
    {
        var directory = Prepared([NestedRule], PositiveSources());
        ChangeReviewProof(directory, evidence => field switch
        {
            "child" => evidence with { NestedGroupGuid = Guid.NewGuid() },
            "witness" => evidence with { Links = evidence.Links.Select(link => link with { Witnesses = [] }).ToArray() },
            "source-ordinal" => evidence with { MemberValues = evidence.MemberValues.Select(value => value with { Ordinal = value.Ordinal + 1 }).ToArray() },
            _ => evidence with { Principals = evidence.Principals.Select(identity => identity.ObjectGuid == evidence.TargetGuid
                ? identity with { DomainFqdn = "child.contoso.com" } : identity).ToArray() },
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    public void SourceListMismatchIsUnassessedRatherThanJudgedFromAnotherOccurrence(string ruleId)
    {
        var directory = CaptureForRules(PositiveSources());
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var index = CapturedGroupMembershipIndex.Create(inputs.ReadMembershipInput(), inputs.Binding(),
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var subject = inputs.Bundle.ReadObjectAttributes(Da)!;
        var altered = subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName == "member"
            ? attribute with { Values = attribute.Values.Skip(1).ToArray() } : attribute).ToArray() };
        var verdict = Assert.IsAssignableFrom<IObjectRule>(Rule(ruleId)).Judge(altered,
            JudgingContext.At(Started) with { AdministrativeMembership = index });
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.IdentityUnreadable);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    public void NonTargetMembershipDoesNotBecomeARepeatedSourceListAssessment(string ruleId)
    {
        var nonTarget = Fixtures.Group("CN=Ordinary group," + Root, DomainSid + "-1500", -2147483646,
            Enumerable.Range(0, 1000).Select(index => "CN=Uncaptured member " + index + "," + Root).ToArray());
        var directory = CaptureForRules([.. PositiveSources(), nonTarget]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var index = CapturedGroupMembershipIndex.Create(inputs.ReadMembershipInput(), inputs.Binding(),
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var subject = inputs.Bundle.ReadObjectAttributes(nonTarget.Dn)!;
        var changed = subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName == "member"
            ? attribute with { Values = [] } : attribute).ToArray() };
        var verdict = Assert.IsAssignableFrom<IObjectRule>(Rule(ruleId)).Judge(changed,
            JudgingContext.At(Started) with { AdministrativeMembership = index });
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    [InlineData("SEC-061")]
    public void EstablishedMembershipFindingsRemainQualifiedWhenCaptureIsIncomplete(string ruleId)
    {
        var directory = CaptureForRules(PositiveSources(), partial: true);
        Derive(directory);
        var result = JudgingRun.Judge(directory, [Rule(ruleId)], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(JudgementRunState.CompletedDegraded, result.Value);
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings, value => value.RuleId == ruleId);
        var (complete, limitations) = finding.Evidence switch
        {
            GroupMembershipReviewEvidence review => (review.IsComplete, review.Limitations),
            BroadGroupMembershipEvidence broad => (broad.IsComplete, broad.Limitations),
            _ => throw new InvalidOperationException("The membership rule did not save its typed evidence."),
        };
        Assert.False(complete);
        Assert.Contains(limitations, limit => limit.Reason == AdministrativeMembershipReason.CaptureIncomplete);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
        var row = new SecureAD.Shell.ViewModels.FindingRowViewModel(finding);
        Assert.Contains("incomplete", row.Coverage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SEC-050")]
    [InlineData("SEC-051")]
    [InlineData("SEC-061")]
    public void MembershipOrdinalGapsKeepPositiveProofWithoutCertifyingItsCompleteness(string ruleId)
    {
        var directory = CaptureForRules(PositiveSources());
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var dn = ruleId == "SEC-061" ? Legacy : Da;
        var subject = inputs.Bundle.ReadObjectAttributes(dn)!;
        var altered = subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName == "member"
            ? attribute with { Values = attribute.Values.Select(value => value with { Ordinal = value.Ordinal + 1 }).ToArray() }
            : attribute).ToArray() };
        var captured = inputs.ReadMembershipInput();
        var input = captured with { Objects = captured.Objects.Select(source => source.DistinguishedName == dn ? altered : source).ToArray() };
        var index = CapturedGroupMembershipIndex.Create(input.Prepare(CancellationToken.None), inputs.Binding(),
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var verdict = Assert.IsAssignableFrom<IObjectRule>(Rule(ruleId)).Judge(altered,
            JudgingContext.At(Started) with { AdministrativeMembership = index });
        var finding = Assert.Single(verdict.Findings);
        Assert.False(verdict.IsComplete);
        if (finding.Evidence is GroupMembershipReviewEvidence review)
        {
            GroupMembershipReviewFindingStorage.Validate(review, requireTotal: false);
            Assert.False(review.IsComplete);
            Assert.All(review.MemberValues, value => Assert.True(value.Ordinal > 0));
            Assert.Contains(review.Limitations, limit => limit.Reason == AdministrativeMembershipReason.MembershipValuesMalformed);
        }
        else
        {
            var evidence = Assert.IsType<BroadGroupMembershipEvidence>(finding.Evidence);
            GroupMembershipFindingStorage.Validate(evidence);
            Assert.False(evidence.IsComplete);
            Assert.Equal(1, Assert.Single(Assert.Single(evidence.Links).Witnesses).Ordinal);
            Assert.Contains(evidence.Limitations, limit => limit.Reason == AdministrativeMembershipReason.MembershipValuesMalformed);
        }
    }

    private static void ChangeReviewProof(string directory, Func<GroupMembershipReviewEvidence, GroupMembershipReviewEvidence> change)
    {
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT finding_id,generation,proof FROM finding_membership_review";
            long id;
            string generation;
            GroupMembershipReviewEvidence evidence;
            using (var row = command.ExecuteReader())
            {
                Assert.True(row.Read());
                id = row.GetInt64(0);
                generation = row.GetString(1);
                evidence = JsonSerializer.Deserialize<GroupMembershipReviewEvidence>(row.GetString(2), ProofSerialization.Options)!;
            }
            var json = JsonSerializer.Serialize(change(evidence), ProofSerialization.Options);
            command.CommandText = "UPDATE finding_membership_review SET proof=$proof,fingerprint=$hash WHERE finding_id=$id";
            command.Parameters.AddWithValue("$proof", json);
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation + "\0" + json));
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    public async Task ActualHostsScheduleAndSaveAllThreeMembershipRules(string host)
    {
        var directory = CaptureForRules(PositiveSources());
        await OwnAccountMembershipPathTests.RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        foreach (var rule in new[] { "SEC-050", "SEC-051", "SEC-061" })
        {
            Assert.Contains(reader.ReadRuleExecutions().Executions, execution => execution.RuleId == rule);
            Assert.Single(reader.Read().Findings, finding => finding.RuleId == rule);
            Assert.NotNull(RuleGuidanceCatalogue.For(rule));
        }
    }

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        using var reader = Open(FindingsRun());
        return reader.Read().Findings;
    }

    internal static string FindingsRun() => Prepared([SizeRule, NestedRule, LegacyRule], PositiveSources());

    [Fact]
    public void Arch03LightweightCompletenessIsSavedAfterFinalMembershipQualifications()
    {
        var missing = Enumerable.Range(0, 11).Select(index => "CN=Uncaptured " + index + "," + Root).ToArray();
        using var reader = Published([SizeRule], [Target("DA", missing)]);
        var original = Assert.Single(reader.Read().Findings);
        Assert.False(Assert.IsType<GroupMembershipReviewEvidence>(original.Evidence).IsComplete);
        var saved = Assert.Single(reader.ReadListPage(FindingsQuery.Everything()).Value.Findings);
        Assert.False(saved.EvidenceIsComplete);
        Assert.Equal(original.Detail, saved.Detail);
        Assert.Equal("May be incomplete", new SecureAD.Shell.ViewModels.FindingRowViewModel(saved).Coverage);
    }

    private static Fixtures.Source[] PositiveSources()
    {
        var accounts = Accounts(10);
        return [Target("DA", [.. accounts.Select(source => source.Dn), Bridge]), .. accounts,
            Fixtures.Group(Bridge, DomainSid + "-1201", -2147483646, [accounts[0].Dn]),
            LegacyGroup([Wide]), Fixtures.Group(Wide, DomainSid + "-513", -2147483646)];
    }
    private static IRule Rule(string id) => id switch { "SEC-050" => SizeRule, "SEC-051" => NestedRule, _ => LegacyRule };
    private static Fixtures.Source[] Accounts(int count, string context = Root) => Enumerable.Range(0, count).Select(index =>
        new Fixtures.Source("CN=Captured account " + index + "," + context, "user",
            (context == Root ? DomainSid : ChildSid) + "-" + (3000 + index), null, [], [])).ToArray();
    private static Fixtures.Source Target(string role, string[] members) => Fixtures.Group(
        role == "DA" ? Da : "CN=Renamed " + role + "," + (role == "BA" ? "CN=Builtin," : "") + Root,
        role == "BA" ? "S-1-5-32-544" : DomainSid + (role == "EA" ? "-519" : role == "SA" ? "-518" : "-512"),
        role == "BA" ? -2147483643 : role == "DA" ? -2147483646 : -2147483640, members);
    private static Fixtures.Source LegacyGroup(string[] members) => Fixtures.Group(Legacy, "S-1-5-32-554", -2147483643, members);
    private static string CaptureForRules(IReadOnlyList<Fixtures.Source> sources, bool partial = false)
    {
        var all = sources.ToList();
        if (!all.Any(source => source.Sid == "S-1-5-32-554" && source.Dn.EndsWith(Root, StringComparison.OrdinalIgnoreCase)
            && !source.Dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase)))
            all.Add(LegacyGroup(["CN=Narrow fixture administrator," + Root]));
        if (!all.Any(source => source.Sid == "S-1-5-32-554" && source.Dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase)))
            all.Add(Fixtures.Group(ChildLegacy, "S-1-5-32-554", -2147483643, ["CN=Narrow fixture administrator," + Child]));
        return Fixtures.Capture(all, partial);
    }
    private static string Prepared(IReadOnlyList<IRule> rules, params Fixtures.Source[] sources)
    {
        var directory = CaptureForRules(sources);
        Derive(directory);
        var result = JudgingRun.Judge(directory, rules, Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }
    private static JudgementReader Published(IReadOnlyList<IRule> rules, params Fixtures.Source[] sources) => Open(Prepared(rules, sources));
    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
