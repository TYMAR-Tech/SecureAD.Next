using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using Fixture = SecureAD.Next.Tests.Judgement.ServiceAccountRuleTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class DelegationConfigurationRuleTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Account = "CN=Delegating account," + Root;
    private const string Resource = "CN=Narrow fixture administrator," + Root;
    private const string SidValue = "S-1-5-21-1-2-3-1200";
    private static readonly IRule Constrained = new ConstrainedDelegationToRelevantService();
    private static readonly IRule Rbcd = new ResourceBasedDelegationOnRelevantResource();

    [Fact]
    public void ResourceDelegationControlAccessUsesThePublishedMicrosoftRightNotPropertyWrite()
    {
        // Microsoft ActiveDirectoryRights: ExtendedRight=256 and WriteProperty=32.
        // https://learn.microsoft.com/dotnet/api/system.directoryservices.activedirectoryrights
        var right = Assert.IsType<int>(typeof(ResourceDelegationGrantReader).GetField("ControlAccess",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.GetRawConstantValue());
        Assert.Equal(256, right);
        Assert.NotEqual(32, right);
    }

    [Fact]
    public void Sec012GroupsSupportedServiceValuesPerCapturedAccountResource()
    {
        using var reader = Published([Constrained], Front(["LDAP/service.contoso.com", "CIFS/service.contoso.com"]),
            Back(["LDAP/service.contoso.com", "CIFS/service.contoso.com"]));
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(finding.Evidence);
        Assert.Equal(("SEC-012", Severity.High, Account), (finding.RuleId, finding.Severity, finding.DistinguishedName));
        Assert.Equal(2, evidence.Services.Count);
        Assert.Equal(DelegationConfigurationRules.Key(Fixture.Id(Account), Fixture.Id(Resource)), finding.Subject.Key);
        Assert.True(evidence.Scope.EstablishedTier0);
        Assert.Contains(Resource, evidence.Scope.AnchorDns);
        Assert.Contains("does not establish successful impersonation", finding.Detail);
        Assert.Contains("Relevant Tier 0 anchors", finding.Detail);
        Assert.Contains("msDS-AllowedToDelegateTo[0]", finding.Detail);
    }

    [Theory]
    [InlineData("ldap/SERVICE.contoso.com")]
    [InlineData("LDAP/service.contoso.com:389")]
    [InlineData("LDAP/service.contoso.com/instance")]
    public void Sec012PreservesCompleteServiceIdentityAndOriginalOccurrences(string name)
    {
        using var reader = Published([Constrained], Front([name, name]), Back([name.ToUpperInvariant()]));
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal([0, 1], evidence.Services.Select(value => value.ConfigurationOrdinal));
        Assert.All(evidence.Services, value => Assert.Equal(name, value.ConfiguredService));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("port-mismatch")]
    [InlineData("not-tier0")]
    public void Sec012DoesNotGuessMissingAmbiguousOrUnqualifiedServiceResources(string variant)
    {
        var target = variant == "not-tier0" ? Back(["LDAP/service.contoso.com"]) with
        {
            Dn = "CN=Ordinary service," + Root,
            Guid = Fixture.Id("CN=Ordinary service," + Root),
        } : Back([variant == "port-mismatch" ? "LDAP/service.contoso.com:389" : "LDAP/service.contoso.com"]);
        if (variant == "not-tier0")
            target = Fixture.With(target, "objectSid", [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-2200")!)]);
        var sources = new List<Fixture.Source> { Front(["LDAP/service.contoso.com"]) };
        if (variant != "missing") sources.Add(target);
        if (variant == "duplicate") sources.Add(Fixture.Account(dn: "CN=Duplicate service," + Root, sid: "S-1-5-21-1-2-3-2201",
            spns: ["LDAP/service.contoso.com"]));
        using var reader = Published([Constrained], sources.ToArray());
        Assert.Empty(reader.Read().Findings);
        var execution = Assert.Single(reader.ReadRuleExecutions().Executions);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        var reason = variant == "duplicate" ? "ServiceResourceAmbiguous" : variant == "not-tier0"
            ? "ResourceRelevanceUnassessed" : "ServiceResourceUnresolved";
        Assert.Contains(execution.MissingInputs, input => input.Attribute == "DelegationConfiguration." + reason);
    }

    [Fact]
    public void Sec012KnownConfigurationSurvivesAnAdditionalUnresolvedDestination()
    {
        using var reader = Published([Constrained], Front(["LDAP/service.contoso.com", "CIFS/unknown.contoso.com"]), Back(["LDAP/service.contoso.com"]));
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Single(evidence.Services);
        Assert.False(evidence.IsComplete);
        Assert.Contains("ServiceResourceUnresolved", evidence.Limitations);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Theory]
    [InlineData(0x100, 1)]
    [InlineData(0x000f01ff, 1)]
    [InlineData(0x20, 0)]
    [InlineData(0x40000, 0)]
    [InlineData(0x10000000, 0)]
    public void Sec013RequiresStoredDelegationRightNotWritePermissionOrExpandedGenericBits(int mask, int expected)
    {
        using var reader = Published([Rbcd], Back(["LDAP/service.contoso.com"], Descriptor((false, mask, SidValue, AceFlags.None))));
        var findings = reader.Read().Findings;
        Assert.Equal(expected, findings.Count);
        if (expected == 0) return;
        var finding = Assert.Single(findings);
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(finding.Evidence);
        Assert.Equal(("SEC-013", Severity.High, Resource), (finding.RuleId, finding.Severity, finding.DistinguishedName));
        Assert.Equal(SidValue, Assert.Single(evidence.Grants).TrusteeSid);
        Assert.Equal([0], evidence.Grants[0].EntryOrdinals);
        Assert.Contains("does not establish authorization for a particular requester", finding.Detail);
    }

    [Theory]
    [InlineData("empty", 0)]
    [InlineData("deny-first", 0)]
    [InlineData("allow-first", 1)]
    [InlineData("inherit-only", 0)]
    [InlineData("null-dacl", 1)]
    public void Sec013KeepsStoredDaclOrderAndDistinguishesNoGrantFromNullDacl(string variant, int expected)
    {
        var bytes = variant switch
        {
            "deny-first" => Descriptor((true, 0x100, SidValue, AceFlags.None), (false, 0x100, SidValue, AceFlags.None)),
            "allow-first" => Descriptor((false, 0x100, SidValue, AceFlags.None), (true, 0x100, SidValue, AceFlags.None)),
            "inherit-only" => Descriptor((false, 0x100, SidValue, AceFlags.InheritOnly)),
            "null-dacl" => NullDescriptor(),
            _ => Descriptor(),
        };
        using var reader = Published([Rbcd], Back(["LDAP/service.contoso.com"], bytes));
        var findings = reader.Read().Findings;
        Assert.Equal(expected, findings.Count);
        if (variant == "null-dacl") Assert.True(Assert.Single(Assert.IsType<DelegationConfigurationEvidence>(
            Assert.Single(findings).Evidence).Grants).NullDacl);
    }

    [Fact]
    public void Sec013KeepsGroupHeldEntriesTogetherWithoutExpandingRequesters()
    {
        var bytes = Descriptor((false, 0x100, SidValue, AceFlags.None), (false, 0x100, SidValue, AceFlags.None),
            (false, 0x100, "S-1-5-11", AceFlags.None));
        using var reader = Published([Rbcd], Back(["LDAP/service.contoso.com"], bytes));
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(2, evidence.Grants.Count);
        Assert.Equal([0, 1], Assert.Single(evidence.Grants, grant => grant.TrusteeSid == SidValue).EntryOrdinals);
        Assert.Equal(bytes, Assert.Single(DelegationConfigurationAssessment.Find(evidence.Resource, DelegationConfigurationRules.ResourceAttribute)!.Values).Bytes);
        Assert.Contains("Original RBCD entries", Assert.Single(reader.Read().Findings).Detail);
        Assert.Contains("mask 0x00000100", Assert.Single(reader.Read().Findings).Detail);
    }

    [Fact]
    public void Sec013MalformedDescriptorIsExplicitlyUnassessedNotACompletedNoGrant()
    {
        using var reader = Published([Rbcd], Back(["LDAP/service.contoso.com"], [1, 2, 3]));
        Assert.Empty(reader.Read().Findings);
        var execution = Assert.Single(reader.ReadRuleExecutions().Executions);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Contains(execution.MissingInputs, value => value.Attribute == "DelegationConfiguration.ResourceDescriptorIncomplete");
    }

    [Theory]
    [InlineData("SEC-012")]
    [InlineData("SEC-013")]
    public void TypedConfigurationSurvivesWholeAndSelectedPageReadback(string id)
    {
        using var reader = Published([id == "SEC-012" ? Constrained : Rbcd], Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))));
        var whole = Assert.Single(reader.Read().Findings);
        var page = reader.ReadPage(FindingsQuery.About(whole.DistinguishedName));
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(JsonSerializer.Serialize(whole.Evidence, whole.Evidence.GetType(), ProofSerialization.Options),
            JsonSerializer.Serialize(Assert.Single(page.Value.Findings).Evidence, typeof(DelegationConfigurationEvidence), ProofSerialization.Options));
    }

    [Theory]
    [InlineData("SEC-012", "subject_key")]
    [InlineData("SEC-013", "domain_fqdn")]
    [InlineData("SEC-013", "severity")]
    public void SavedConfigurationRefusesChangedFindingIdentity(string id, string field)
    {
        var directory = Prepared([id == "SEC-012" ? Constrained : Rbcd], Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding SET {field}=$value WHERE rule_id=$rule";
            command.Parameters.AddWithValue("$value", field == "severity" ? "Low" : "wrong");
            command.Parameters.AddWithValue("$rule", id);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Fact]
    public void SavedConfigurationRefusesMissingMetadata()
    {
        var directory = Prepared([Constrained], Front(["LDAP/service.contoso.com"]), Back(["LDAP/service.contoso.com"]));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM finding_delegation_configuration";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("SEC-012", false)]
    [InlineData("SEC-012", true)]
    [InlineData("SEC-013", false)]
    [InlineData("SEC-013", true)]
    public void MissingConfigurationIsNotAnEmptySettingAndCountsTheActualUnassessedObject(string id, bool captured)
    {
        var source = Fixture.Account(dn: Account, sid: "S-1-5-21-1-2-3-1100", spns: []);
        var attribute = id == "SEC-012" ? DelegationConfigurationRules.ConstrainedAttribute : DelegationConfigurationRules.ResourceAttribute;
        if (captured) source = Fixture.With(source, attribute, []);
        var execution = AssessSingle(id == "SEC-012" ? Constrained : Rbcd, source, subject => captured ? subject : subject with
        {
            Attributes = subject.Attributes.Where(value => value.LdapDisplayName != attribute).ToArray(),
        });
        Assert.Empty(execution.Findings);
        Assert.Equal(captured ? RuleExecutionOutcome.Succeeded : RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(captured ? 1 : 0, execution.ObjectsJudged);
        Assert.Equal(captured ? 0 : 1, execution.ObjectsNotJudged);
        if (!captured) Assert.Equal(new MissingInput(attribute, 1), Assert.Single(execution.MissingInputs));
    }

    [Theory]
    [InlineData("SEC-012", "missing")]
    [InlineData("SEC-013", "missing")]
    [InlineData("SEC-012", "binary")]
    [InlineData("SEC-013", "binary")]
    public void UnreadableClassCannotBeDismissedAsAnUnrelatedObject(string id, string variant)
    {
        var source = Fixture.Account(dn: Account, sid: "S-1-5-21-1-2-3-1100", spns: []);
        var execution = AssessSingle(id == "SEC-012" ? Constrained : Rbcd, source, subject => subject with
        {
            Attributes = variant == "missing" ? subject.Attributes.Where(value => value.LdapDisplayName != "objectClass").ToArray()
                : subject.Attributes.Select(attribute => attribute.LdapDisplayName == "objectClass"
                    ? attribute with { Values = [new AttributeValue(0, null, [1, 2, 3])] } : attribute).ToArray(),
        });
        Assert.Equal((0, 0, 1), (execution.ObjectsJudged, execution.ObjectsNotApplicable, execution.ObjectsNotJudged));
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(new MissingInput(variant == "missing" ? "objectClass" : "DelegationConfiguration.AccountClassUnreadable", 1),
            Assert.Single(execution.MissingInputs));
    }

    [Theory]
    [InlineData("guid")]
    [InlineData("domain")]
    [InlineData("sid")]
    [InlineData("deleted")]
    public void ConfiguredAccountMustMatchItsCapturedAndDerivedIdentity(string variant)
    {
        var execution = AssessSingle(Constrained, Front(["LDAP/service.contoso.com"]), subject => variant switch
        {
            "guid" => subject with { ObjectGuid = Guid.NewGuid() },
            "domain" => subject with { DomainFqdn = "different.contoso.com" },
            "sid" => subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName == "objectSid"
                ? attribute with { Values = [new AttributeValue(0, null, Sid.ToBytes("S-1-5-21-4-5-6-1100"))] } : attribute).ToArray() },
            _ => subject with { Attributes = subject.Attributes.Append(new ObjectAttribute("isDeleted",
                SecureAD.Kernel.Capture.AttributeCardinality.SingleValued, [new AttributeValue(0, "TRUE", null)])).ToArray() },
        });
        Assert.Empty(execution.Findings);
        Assert.Equal((0, 1), (execution.ObjectsJudged, execution.ObjectsNotJudged));
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Contains(execution.MissingInputs, value => value.Attribute == "DelegationConfiguration.AccountIdentityUnavailable");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConditionalRbcdEntryCannotTurnAnUnknownPrefixIntoAProvenGrant(bool allowBefore)
    {
        var acl = new RawAcl(2, 2);
        var conditional = new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 0x100,
            new System.Security.Principal.SecurityIdentifier(SidValue), true, [1, 2, 3, 4]);
        var allowed = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x100,
            new System.Security.Principal.SecurityIdentifier(SidValue), false, null);
        acl.InsertAce(0, allowBefore ? allowed : conditional);
        acl.InsertAce(1, allowBefore ? conditional : allowed);
        var raw = new RawSecurityDescriptor(ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent, null, null, null, acl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var (grants, limits) = ResourceDelegationGrantReader.Read(bytes);
        Assert.Equal(allowBefore ? 1 : 0, grants.Count);
        Assert.Contains("ResourceDelegationEntryUnsupported", limits);
    }

    [Theory]
    [InlineData("size")]
    [InlineData("count")]
    public void TruncatedRbcdDescriptorCannotProduceACompleteOrPartialDefiniteGrant(string change)
    {
        var bytes = Descriptor((false, 0x100, SidValue, AceFlags.None));
        var dacl = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16));
        if (change == "size") Array.Resize(ref bytes, bytes.Length - 1);
        else System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(dacl + 4), 2);
        var (grants, limits) = ResourceDelegationGrantReader.Read(bytes);
        Assert.Empty(grants);
        Assert.Contains("ResourceDescriptorIncomplete", limits);
    }

    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-11")]
    public void EarlierBroadRbcdDenyBlocksTheStoredDelegationGrant(string sid)
    {
        var result = ResourceDelegationGrantReader.Read(Descriptor((true, 0x100, sid, AceFlags.None),
            (false, 0x100, SidValue, AceFlags.None)));
        Assert.Empty(result.Grants);
    }

    [Fact]
    public void OtherGroupDenyIsNotSilentlyTurnedIntoConcreteRequesterAuthorization()
    {
        var result = ResourceDelegationGrantReader.Read(Descriptor((true, 0x100, "S-1-5-21-1-2-3-2301", AceFlags.None),
            (false, 0x100, SidValue, AceFlags.None)));
        Assert.Single(result.Grants);
        Assert.Contains("OtherRequesterDenyMembershipUnassessed", result.Limits);
    }

    [Theory]
    [InlineData("account-source")]
    [InlineData("resource-source")]
    public void SourceHashBindingRefusesCoordinatedRehashOfOtherwiseConsistentConfiguration(string source)
    {
        var directory = Prepared([Constrained], Front(["LDAP/service.contoso.com"]), Back(["LDAP/service.contoso.com"]));
        ChangeProof(directory, evidence =>
        {
            var account = evidence.Account;
            var resource = evidence.Resource;
            if (source == "account-source") account = account with { CapturedUtc = account.CapturedUtc.AddSeconds(1) };
            else resource = resource with { CapturedUtc = resource.CapturedUtc.AddSeconds(1) };
            return evidence with { Account = account, Resource = resource };
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Fact]
    public void SavedConfigurationCompletenessIncludesCapturedSourcesAndSharedScope()
    {
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(ReadPublishedFindings(),
            finding => finding.RuleId == "SEC-012").Evidence);
        var complete = evidence with { InputsComplete = true, Limitations = [], Scope = evidence.Scope with { Limitations = [] } };
        Assert.True(complete.IsComplete);
        Assert.False((complete with { InputsComplete = false }).IsComplete);
        Assert.False((complete with { Account = complete.Account with { Completeness = EvidenceCompleteness.MayBeMissingConfidentialValues } }).IsComplete);
        Assert.False((complete with { Resource = complete.Resource with { Completeness = EvidenceCompleteness.MayBeMissingConfidentialValues } }).IsComplete);
        Assert.False((complete with { Limitations = ["ServiceResourceUnresolved"] }).IsComplete);
        Assert.False((complete with { Scope = complete.Scope with { Limitations = ["DependencyQualificationUnsupported"] } }).IsComplete);
    }

    [Theory]
    [InlineData("ResourceDescriptorIncomplete", "parsed completely")]
    [InlineData("ResourceAnalysis.DependencyQualificationUnsupported", "not implemented")]
    [InlineData("ResourceRelevanceUnassessed", "not declared safe")]
    public void ConfigurationGapWordingDoesNotHideUnsupportedAnalysisAsEmptyOrSafe(string reason, string expected)
    {
        var description = SecureAD.Shell.Services.UnresolvedWording.For("DelegationConfiguration." + reason);
        Assert.Contains(expected, description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("no plainer way", description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("was not captured", description, StringComparison.OrdinalIgnoreCase);
    }

    private static RuleExecution AssessSingle(IRule rule, Fixture.Source source, Func<ObjectAttributes, ObjectAttributes> change)
    {
        var directory = Fixture.Capture([source]);
        Derive(directory);
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var binding = inputs.Binding();
        var identities = CapturedGroupMembershipIndex.Create(inputs.ReadMembershipInput(), binding,
            inputs.ReadNamingContexts().Value, CancellationToken.None);
        var assessment = new DelegationConfigurationAssessment([rule], binding.EvidenceSeal,
            binding.DerivationGenerationId, binding.DerivationSeal, true, identities);
        assessment.Add(change(inputs.Bundle.ReadObjectAttributes(source.Dn)!), CancellationToken.None);
        return Assert.Single(assessment.Complete(_ => throw new InvalidOperationException("Unqualified or empty input must not ask for scope."),
            CancellationToken.None)).Execution;
    }

    [Fact]
    public void Sec012IncludesIdentifiedControllerWithoutRelabellingItTier0()
    {
        var controllerDn = "CN=Captured controller," + Root;
        var controllerSid = "S-1-5-21-1-2-3-2300";
        var controller = Fixture.With(Fixture.Account(dn: controllerDn, sid: controllerSid, spns: ["HTTP/controller.contoso.com"]),
            DelegationConfigurationRules.ConstrainedAttribute, []);
        controller = Fixture.With(controller, DelegationConfigurationRules.ResourceAttribute, []);
        var core = Fixture.With(Back(["LDAP/service.contoso.com"]), "nTSecurityDescriptor",
            [EvidenceValue.OfBytes(Descriptor((false, GenericRightsExpander.WriteDacl, controllerSid, AceFlags.None)))]);
        using var reader = Published([Constrained], Front(["HTTP/controller.contoso.com"]), controller, core);
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(controllerDn, evidence.Resource.DistinguishedName);
        Assert.False(evidence.Scope.EstablishedTier0);
        Assert.Empty(evidence.Scope.ClassificationBases);
        Assert.NotEmpty(evidence.Scope.RelationIds);
        Assert.Contains(Resource, evidence.Scope.AnchorDns);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sec012ResolvesARecordedDomainControllerServiceThroughSharedSecurityMembership(bool primaryOnly)
    {
        var dn = "CN=Renamed DC account," + Root;
        var groupDn = "CN=Renamed DC security group," + Root;
        var resource = Fixture.Account("computer", ["LDAP/captured-dc.contoso.com"], 8192, 516, dn,
            "S-1-5-21-1-2-3-2400");
        resource = Fixture.With(resource, DelegationConfigurationRules.ConstrainedAttribute, []);
        resource = Fixture.With(resource, DelegationConfigurationRules.ResourceAttribute, []);
        var group = Fixture.Group(groupDn, "S-1-5-21-1-2-3-516", -2147483646, primaryOnly ? [] : [dn]);
        using var reader = Published([Constrained], Front(["LDAP/captured-dc.contoso.com"]), resource, group);
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(dn, evidence.Resource.DistinguishedName);
        Assert.True(evidence.Scope.EstablishedTier0);
        Assert.Contains("EffectiveMembership", evidence.Scope.ClassificationBases);
    }

    [Theory]
    [InlineData("SEC-012")]
    [InlineData("SEC-013")]
    public void PositiveDelegationSettingsRemainVisibleWhenCaptureHasRecordedGaps(string id)
    {
        var directory = Fixture.Capture([Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None)))], partial: true);
        Derive(directory);
        var result = JudgingRun.Judge(directory, [id == "SEC-012" ? Constrained : Rbcd], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.False(evidence.IsComplete);
        Assert.Contains("CaptureIncomplete", evidence.Limitations);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Theory]
    [InlineData("SEC-012")]
    [InlineData("SEC-013")]
    public void DisabledAccountsKeepTheirCapturedDelegationConfiguration(string id)
    {
        var front = Fixture.With(Front(["LDAP/service.contoso.com"]), "userAccountControl", [EvidenceValue.OfText("514")]);
        var back = Fixture.With(Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))),
            "userAccountControl", [EvidenceValue.OfText("514")]);
        using var reader = Published([id == "SEC-012" ? Constrained : Rbcd], front, back);
        var evidence = Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal("514", DelegationConfigurationAssessment.Find(evidence.Account, "userAccountControl")!.OnlyValue!.Text);
        Assert.Equal(Severity.High, Assert.Single(reader.Read().Findings).Severity);
    }

    [Theory]
    [InlineData("SEC-012", "generation")]
    [InlineData("SEC-013", "fingerprint")]
    public void SavedConfigurationRefusesRelabelledGenerationOrBrokenHash(string id, string field)
    {
        var directory = Prepared([id == "SEC-012" ? Constrained : Rbcd], Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding_delegation_configuration SET {field}="
                + (field == "generation" ? "'00000000-0000-0000-0000-000000000001'" : "zeroblob(32)");
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("account")]
    [InlineData("resource")]
    [InlineData("configured-value")]
    [InlineData("registration-value")]
    [InlineData("scope-generation")]
    [InlineData("scope-fingerprint")]
    [InlineData("policy")]
    public void RehashedConstrainedProofCannotChangeItsSourceOrSharedScope(string change)
    {
        var directory = Prepared([Constrained], Front(["LDAP/service.contoso.com"]), Back(["LDAP/service.contoso.com"]));
        ChangeProof(directory, evidence => change switch
        {
            "account" => evidence with { Account = evidence.Account with { ObjectGuid = Guid.NewGuid() } },
            "resource" => evidence with { Resource = evidence.Resource with { ObjectGuid = Guid.NewGuid() } },
            "configured-value" => evidence with { Services = evidence.Services.Select(value => value with { ConfiguredService = "LDAP/other" }).ToArray() },
            "registration-value" => evidence with { Services = evidence.Services.Select(value => value with { RegisteredService = "LDAP/other" }).ToArray() },
            "scope-generation" => evidence with { Scope = evidence.Scope with { GenerationId = Guid.NewGuid() } },
            "scope-fingerprint" => evidence with { Scope = evidence.Scope with { Fingerprint = new('a', 64) } },
            _ => evidence with { PolicyVersion = 999 },
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("descriptor")]
    [InlineData("grant-ordinal")]
    [InlineData("grant-holder")]
    [InlineData("parser-version")]
    public void RehashedRbcdProofCannotChangeTheRawSettingsOrGrantAnswer(string change)
    {
        var directory = Prepared([Rbcd], Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))));
        ChangeProof(directory, evidence => change switch
        {
            "descriptor" => evidence with { Account = RemoveDescriptor(evidence.Account), Resource = RemoveDescriptor(evidence.Resource) },
            "grant-ordinal" => evidence with { Grants = evidence.Grants.Select(grant => grant with { EntryOrdinals = [3] }).ToArray() },
            "grant-holder" => evidence with { Grants = evidence.Grants.Select(grant => grant with { TrusteeSid = "S-1-5-11" }).ToArray() },
            _ => evidence with { DescriptorParserVersion = 999 },
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("scope-target")]
    [InlineData("classification")]
    public void SelectedReadRefusesChangedUnderlyingSharedScopeWitness(string change)
    {
        var directory = Prepared([Constrained], Front(["LDAP/service.contoso.com"]), Back(["LDAP/service.contoso.com"]));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = change == "scope-target"
                ? "UPDATE ownership_target SET fingerprint=zeroblob(32) WHERE target=$target"
                : "UPDATE ownership_seed SET classification_fingerprint=zeroblob(32) WHERE target=$target";
            command.Parameters.AddWithValue("$target", Resource);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(Account)));
    }

    [Theory]
    [InlineData("SEC-012")]
    [InlineData("SEC-013")]
    public void PublicationRequiresTypedBodiesAndExactDerivationBinding(string id)
    {
        var directory = Prepared([id == "SEC-012" ? Constrained : Rbcd], Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))));
        using var reader = Open(directory);
        var copy = Path.Combine(directory, "delegation-publication-check.db");
        File.Copy(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, reader.Description.GenerationId), copy);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = copy, Pooling = false, ForeignKeys = false }.ToString());
        connection.Open();
        var seal = FindingInputBinding.DerivationSeal(directory, reader.Description.DerivationGenerationId);
        DelegationConfigurationFindingStorage.RequirePublishable(connection, reader.Description, seal, CancellationToken.None);
        Assert.Throws<InvalidDataException>(() => DelegationConfigurationFindingStorage.RequirePublishable(connection, reader.Description, new('f', 64), CancellationToken.None));
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM finding_delegation_configuration";
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => DelegationConfigurationFindingStorage.RequirePublishable(connection, reader.Description, seal, CancellationToken.None));
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    public async Task ActualHostsScheduleAndSaveBothConfigurationRules(string host)
    {
        var directory = Fixture.Capture([Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None)))]);
        await OwnAccountMembershipPathTests.RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        foreach (var id in new[] { "SEC-012", "SEC-013" })
        {
            Assert.Contains(reader.ReadRuleExecutions().Executions, rule => rule.RuleId == id);
            Assert.IsType<DelegationConfigurationEvidence>(Assert.Single(reader.Read().Findings, finding => finding.RuleId == id).Evidence);
        }
    }

    private static DelegationConfigurationAccount RemoveDescriptor(DelegationConfigurationAccount account) => account with
    {
        Attributes = account.Attributes.Where(attribute => attribute.LdapDisplayName != DelegationConfigurationRules.ResourceAttribute).ToArray(),
    };

    private static void ChangeProof(string directory, Func<DelegationConfigurationEvidence, DelegationConfigurationEvidence> change)
    {
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT finding_id,generation,proof FROM finding_delegation_configuration";
            long id;
            string generation;
            DelegationConfigurationEvidence evidence;
            using (var row = command.ExecuteReader())
            {
                Assert.True(row.Read());
                id = row.GetInt64(0);
                generation = row.GetString(1);
                evidence = JsonSerializer.Deserialize<DelegationConfigurationEvidence>(row.GetString(2), ProofSerialization.Options)!;
            }
            var json = JsonSerializer.Serialize(change(evidence), ProofSerialization.Options);
            command.CommandText = "UPDATE finding_delegation_configuration SET proof=$proof,fingerprint=$hash WHERE finding_id=$id";
            command.Parameters.AddWithValue("$proof", json);
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation + "\0" + json));
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
    }

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        using var reader = Published([Constrained, Rbcd], Front(["LDAP/service.contoso.com"]),
            Back(["LDAP/service.contoso.com"], Descriptor((false, 0x100, SidValue, AceFlags.None))));
        return reader.Read().Findings;
    }

    private static Fixture.Source Front(string[] names) => Fixture.With(Fixture.Account(dn: Account, sid: "S-1-5-21-1-2-3-1100", spns: []),
        DelegationConfigurationRules.ConstrainedAttribute, names.Select(EvidenceValue.OfText).ToArray());
    private static Fixture.Source Back(string[] names, byte[]? descriptor = null)
    {
        var account = Fixture.With(Fixture.Account(dn: Resource, sid: "S-1-5-21-1-2-3-500", spns: names),
            DelegationConfigurationRules.ConstrainedAttribute, []);
        return Fixture.With(account, DelegationConfigurationRules.ResourceAttribute,
            descriptor is null ? [] : [EvidenceValue.OfBytes(descriptor)]);
    }
    private static byte[] Descriptor(params (bool Deny, int Mask, string Sid, AceFlags Flags)[] entries)
    {
        var acl = new RawAcl(2, entries.Length);
        foreach (var entry in entries)
            acl.InsertAce(acl.Count, new CommonAce(entry.Flags, entry.Deny ? AceQualifier.AccessDenied : AceQualifier.AccessAllowed,
                entry.Mask, new System.Security.Principal.SecurityIdentifier(entry.Sid), false, null));
        var descriptor = new RawSecurityDescriptor(ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent, null, null, null, acl);
        var result = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(result, 0);
        return result;
    }
    private static byte[] NullDescriptor()
    {
        var descriptor = new RawSecurityDescriptor(ControlFlags.SelfRelative, null, null, null, null);
        var result = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(result, 0);
        return result;
    }
    private static string Prepared(IReadOnlyList<IRule> rules, params Fixture.Source[] sources)
    {
        var directory = Fixture.Capture(sources);
        Derive(directory);
        var result = JudgingRun.Judge(directory, rules, Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }
    private static JudgementReader Published(IReadOnlyList<IRule> rules, params Fixture.Source[] sources) => Open(Prepared(rules, sources));
    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
