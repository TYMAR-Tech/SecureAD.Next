using System.Globalization;
using System.Security.AccessControl;
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
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class AttributeWriteRuleTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Child = "DC=child," + Root;
    private const string Configuration = "CN=Configuration," + Root;
    private const string Schema = "CN=Schema," + Configuration;
    private const string DomainSid = "S-1-5-21-1-2-3";
    private const string ChildSid = "S-1-5-21-4-5-6";
    private const string TargetDn = "CN=Service target," + Root;
    private const string TargetSid = DomainSid + "-1100";
    private const string HolderSid = DomainSid + "-1200";
    private const string HolderDn = "CN=Permission holder," + Root;
    private const string SetGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static readonly IReadOnlyList<IRule> Trio = [new UnexpectedResourceBasedDelegationWrite(),
        new UnexpectedServicePrincipalNameWrite(), new UnexpectedKeyCredentialLinkWrite()];

    // Microsoft Learn: the SPN attribute and its validated write share a GUID, not an access-mask meaning.
    [Theory]
    [InlineData("SEC-014", "msDS-AllowedToActOnBehalfOfOtherIdentity", "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")]
    [InlineData("SEC-024", "servicePrincipalName", "f3a64788-5306-11d1-a9c5-0000f80367c1")]
    [InlineData("SEC-025", "msDS-KeyCredentialLink", "5b47d60f-6090-40b2-9f37-2a4de88f3063")]
    public void AttributeWriteRulesMatchMicrosoftAttributeIdentityAndSpecificWriteMask(string rule, string attribute, string guid)
    {
        var verdict = Assess(rule, [Write(guid)]);
        var finding = Assert.Single(verdict.Findings);
        var proof = Evidence(finding);
        Assert.Equal(attribute, proof.Attribute.LdapName);
        Assert.Equal(guid, proof.Attribute.Guid);
        Assert.Equal((SchemaGuidKind.Attribute, SchemaGuidSource.Captured), (proof.Attribute.Kind, proof.Attribute.Source));
        Assert.Equal(0x20, Assert.Single(proof.Entries).AccessMask);
        Assert.True(verdict.IsComplete);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal((Id(TargetDn), TargetDn, "contoso.com", "user"), (finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass));
        Assert.Equal(new FindingSubject(FindingSubjectKind.Account, HolderSid + ":"), finding.Subject);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesKeepValidatedWritesAndPermissionPivotsSeparate(string rule)
    {
        var guid = GuidFor(rule);
        foreach (var mask in new[] { 0x08, 0x100, 0x40000, 0x80000 })
        {
            var verdict = Assess(rule, [Write(guid) with { AccessMask = mask }]);
            Assert.Empty(verdict.Findings);
            Assert.True(verdict.IsComplete);
        }
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesDistinguishOrderedAllowsAndDeniesForTheSameProperty(string rule)
    {
        var guid = GuidFor(rule);
        var denied = Assess(rule, [Write(guid, 0, deny: true), Write(guid, 1)]);
        Assert.Empty(denied.Findings);
        Assert.True(denied.IsComplete);
        var allowed = Assess(rule, [Write(guid, 0), Write(guid, 1, deny: true)]);
        var proof = Evidence(Assert.Single(allowed.Findings));
        Assert.Equal(new[] { 0, 1 }, proof.Entries.Select(entry => entry.Ordinal));
        Assert.True(allowed.IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesUseCapturedContainingPropertySetsAndRejectDifferentSets(string rule)
    {
        var attribute = AttributeFor(rule);
        var contains = Catalogue(new Dictionary<string, IReadOnlyList<string>> { [SetGuid] = [attribute] });
        var finding = Assert.Single(Assess(rule, [Write(SetGuid)], catalogue: contains).Findings);
        Assert.Equal(attribute, Assert.Single(Evidence(finding).PropertySetMembers[SetGuid]));
        var unrelated = Catalogue(new Dictionary<string, IReadOnlyList<string>> { [SetGuid] = ["description"],
            ["11111111-2222-3333-4444-555555555555"] = [attribute] });
        var verdict = Assess(rule, [Write(SetGuid)], catalogue: unrelated);
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
        var unknown = Assess(rule, [Write(SetGuid)]);
        Assert.Empty(unknown.Findings);
        Assert.False(unknown.IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesDoNotLetBroadPropertyGrantsEscapeSpecificDenies(string rule)
    {
        var deny = Write(GuidFor(rule), 0, deny: true);
        var broad = Write(null, 1);
        var verdict = Assess(rule, [deny, broad]);
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
        var grant = Assess(rule, [broad with { Ordinal = 0 }, deny with { Ordinal = 1 }]);
        Assert.Single(grant.Findings);
        Assert.True(grant.IsComplete);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    [InlineData("customAccount")]
    [InlineData("inetOrgPerson")]
    public void AttributeWriteRulesIncludeCapturedAccountAncestryWithoutServiceOrSpnPrerequisites(string kind)
    {
        var subject = Account(TargetDn, TargetSid, kind);
        foreach (var rule in new[] { "SEC-014", "SEC-024", "SEC-025" })
        {
            var verdict = Assess(rule, [Write(GuidFor(rule))], subject);
            Assert.Single(verdict.Findings);
        }
    }

    [Theory]
    [InlineData("group")]
    [InlineData("organizationalUnit")]
    [InlineData("container")]
    [InlineData("domainDNS")]
    public void AttributeWriteRulesDoNotAttributeAccountPermissionsToKnownNonAccounts(string kind)
    {
        var subject = Account(TargetDn, TargetSid) with { Attributes = [Text("objectClass", "top", kind)] };
        foreach (var rule in Trio.OfType<IObjectRule>())
        {
            var verdict = rule.Judge(subject, JudgingContext.At(Started));
            Assert.Empty(verdict.Findings);
            Assert.True(verdict.IsComplete);
        }
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesRetainDisabledTargetsAsDormantPermissionExposure(string rule)
    {
        var subject = Account(TargetDn, TargetSid, control: 514);
        var finding = Assert.Single(Assess(rule, [Write(GuidFor(rule))], subject).Findings);
        Assert.Equal(514u, ServiceAccountReading.ReadControl(Evidence(finding).AccountControl));
        Assert.Contains("currently disabled", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("dormant exposure", finding.Detail, StringComparison.Ordinal);
        Assert.Equal(Severity.High, finding.Severity);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesMissingAccountStateDoesNotEraseAnEstablishedPermission(string rule)
    {
        var subject = Account(TargetDn, TargetSid) with { Attributes = Account(TargetDn, TargetSid).Attributes
            .Where(attribute => attribute.LdapDisplayName != "userAccountControl").ToArray() };
        var verdict = Assess(rule, [Write(GuidFor(rule))], subject);
        var finding = Assert.Single(verdict.Findings);
        Assert.Contains("userAccountControl", verdict.InputsNotCaptured);
        Assert.False(Evidence(finding).IsComplete);
        Assert.Contains("state could not be read", finding.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesRequireCapturedAttributeIdentityNotOnlyTheShippedCatalogue(string rule)
    {
        var verdict = Assess(rule, [Write(GuidFor(rule))], catalogue: SchemaGuidCatalog.Embedded);
        Assert.Empty(verdict.Findings);
        Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.AttributeWriteSchemaUnavailable);
        var wrong = Catalogue() ;
        wrong = new SchemaGuidCatalog(wrong.Entries.Select(entry => entry.LdapName == AttributeFor(rule)
            ? entry with { Guid = SetGuid } : entry));
        Assert.Empty(Assess(rule, [Write(GuidFor(rule))], catalogue: wrong).Findings);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteSchemaSupportKeepsEveryScopeMeaningAndTargetClassWithoutUnrelatedDefinitions(string rule)
    {
        var attribute = AttributeFor(rule);
        var guid = GuidFor(rule);
        var alias = new SchemaGuidEntry(guid, "capturedScopeAlias", SchemaGuidKind.ValidatedWrite, SchemaGuidSource.Captured);
        var targetClass = new SchemaGuidEntry("11111111-2222-3333-4444-555555555555", "customAccount",
            SchemaGuidKind.ObjectClass, SchemaGuidSource.Captured);
        var irrelevant = Enumerable.Range(0, 1000).Select(index => new SchemaGuidEntry(
            new Guid(index, 0, 0, new byte[8]).ToString("D"), "unrelated" + index.ToString(CultureInfo.InvariantCulture),
            SchemaGuidKind.Attribute, SchemaGuidSource.Captured)).ToArray();
        var entries = Catalogue().Entries.Concat([alias, targetClass]).Concat(irrelevant).ToArray();
        var catalogue = new SchemaGuidCatalog(entries);
        var finding = Assert.Single(Assess(rule, [Write(guid)], Account(TargetDn, TargetSid, "customAccount"), catalogue).Findings);
        var proof = Evidence(finding);
        Assert.Contains(alias, proof.SchemaEntries);
        Assert.Contains(targetClass, proof.SchemaEntries);
        Assert.Contains(proof.SchemaEntries, definition => definition.LdapName == attribute && definition.Guid == guid);
        Assert.DoesNotContain(proof.SchemaEntries, definition => definition.LdapName.StartsWith("unrelated", StringComparison.Ordinal));
        var expected = entries.Where(definition => string.Equals(definition.Guid, guid, StringComparison.OrdinalIgnoreCase)
            || string.Equals(definition.LdapName, attribute, StringComparison.OrdinalIgnoreCase)
            || string.Equals(definition.LdapName, "customAccount", StringComparison.OrdinalIgnoreCase))
            .OrderBy(definition => definition.LdapName, StringComparer.Ordinal).ThenBy(definition => definition.Guid, StringComparer.Ordinal).ToArray();
        Assert.Equal(expected, proof.SchemaEntries);
    }

    [Theory]
    [InlineData("guid")]
    [InlineData("sid")]
    [InlineData("domain")]
    [InlineData("class")]
    public void AttributeWriteRulesCannotRelabelACapturedTargetOrTreatMissingIdentityAsClean(string variant)
    {
        var original = Account(TargetDn, TargetSid);
        var subject = variant switch
        {
            "guid" => original with { ObjectGuid = null },
            "domain" => original with { DomainFqdn = "child.contoso.com" },
            "sid" => original with { Attributes = original.Attributes.Select(attribute => attribute.LdapDisplayName != "objectSid"
                ? attribute : Binary("objectSid", Sid.ToBytes(ChildSid + "-1100")!)).ToArray() },
            _ => original with { Attributes = [Text("objectClass")] },
        };
        var verdict = Assess("SEC-024", [Write(GuidFor("SEC-024"))], subject, source: original);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesUnparsedConditionalAndCrossTrusteeDeniesAreNotEstablishedPermissions(string rule)
    {
        var guid = GuidFor(rule);
        var cross = Assess(rule, [Write(guid, 0, sid: DomainSid + "-1201", deny: true), Write(guid, 1)]);
        Assert.Empty(cross.Findings);
        Assert.False(cross.IsComplete);
        var callback = Assess(rule, [Write(guid) with { AceType = "AccessAllowedCallbackObject", ApplicationData = [1] }]);
        Assert.Empty(callback.Findings);
        Assert.False(callback.IsComplete);
        var incomplete = Assess(rule, [Write(guid)], incompleteDescriptor: true);
        Assert.Empty(incomplete.Findings);
        Assert.False(incomplete.IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesUnknownHolderAndPlaceholderAreExplicitlyUnassessed(string rule)
    {
        var unknown = Write(GuidFor(rule)) with { Trustee = new(DomainSid + "-9999", null, null, null, null, null, null) };
        var verdict = Assess(rule, [unknown]);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        var placeholder = Write(GuidFor(rule)) with { Trustee = new("S-1-3-0", "CREATOR OWNER", null, null, null, WellKnownSidRole.Placeholder, null) };
        verdict = Assess(rule, [placeholder]);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesKeepRestrictedValidatedSpnAndRawGenericMasksOutOfPositiveFindings(string rule)
    {
        var validated = Assess(rule, [Write("f3a64788-5306-11d1-a9c5-0000f80367c1") with { AccessMask = 0x08 }]);
        Assert.Empty(validated.Findings);
        Assert.True(validated.IsComplete);
        var generic = Assess(rule, [Write(null) with { AccessMask = unchecked((int)0x10000000) }], unsupportedMask: true);
        Assert.Empty(generic.Findings);
        Assert.False(generic.IsComplete);
    }

    [Fact]
    public void AttributeWriteRulesKeepIndependentPropertiesSeparate()
    {
        var rbcd = GuidFor("SEC-014");
        var spn = GuidFor("SEC-024");
        var entries = new[] { Write(rbcd, deny: true), Write(rbcd, 1), Write(spn, 2) };
        Assert.Empty(Assess("SEC-014", entries).Findings);
        var spnFinding = Assert.Single(Assess("SEC-024", entries).Findings);
        Assert.Equal(new[] { 2 }, Evidence(spnFinding).Entries.Select(entry => entry.Ordinal));
        Assert.True(Evidence(spnFinding).IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesUseExistingExpectednessWithoutProtectedOrKeyAdminExemptions(string rule)
    {
        var expected = Assess(rule, [Write(GuidFor(rule), sid: DomainSid + "-512")]);
        Assert.Empty(expected.Findings);
        Assert.True(expected.IsComplete);
        foreach (var sid in new[] { DomainSid + "-526", DomainSid + "-527", DomainSid + "-518", "S-1-1-0" })
        {
            var finding = Assert.Single(Assess(rule, [Write(GuidFor(rule), sid: sid)]).Findings);
            Assert.Equal(sid, Evidence(finding).HolderSid);
        }
        Assert.Empty(Assess(rule, [Write(GuidFor(rule), sid: "S-1-5-18")]).Findings);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesDoNotMakeForeignDomainAdminsExpectedOverThisTarget(string rule)
    {
        var entry = Write(GuidFor(rule), sid: ChildSid + "-512") with
        {
            Trustee = new(ChildSid + "-512", "Child Domain Admins", "CN=Domain Admins," + Child, "child.contoso.com", null, null, null),
        };
        var finding = Assert.Single(Assess(rule, [entry]).Findings);
        Assert.Equal(nameof(ControlExpectednessReason.UnexpectedOutsideAuthorityScope), Evidence(finding).ExpectednessReason);
    }

    [Fact]
    public void AttributeWriteRulesDoNotExpandGroupHeldPermissionsIntoMemberFindings()
    {
        var source = Group(HolderDn, HolderSid, -2147483646, TargetDn, "CN=Another member," + Root);
        var verdict = Assess("SEC-024", [Write(GuidFor("SEC-024"))], additional: [source]);
        var finding = Assert.Single(verdict.Findings);
        Assert.Equal(HolderSid, Evidence(finding).HolderSid);
        Assert.Equal(HolderSid + ":", finding.Subject.Key);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesPreserveInheritedEntriesWithoutApplyingInheritOnlyEntriesToThisTarget(string rule)
    {
        var inherited = Write(GuidFor(rule)) with { IsInherited = true, InheritanceFlags = 1 };
        var finding = Assert.Single(Assess(rule, [inherited]).Findings);
        Assert.True(Assert.Single(Evidence(finding).Entries).IsInherited);
        var inheritOnly = inherited with { PropagationFlags = 0x08 };
        var verdict = Assess(rule, [inheritOnly]);
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesCountOneFindingPerHolderAndTargetWhileKeepingEveryOriginalGrant(string rule)
    {
        var finding = Assert.Single(Assess(rule, [Write(GuidFor(rule), 0), Write(GuidFor(rule), 1)]).Findings);
        var proof = Evidence(finding);
        Assert.Equal(new[] { 0, 1 }, proof.Entries.Select(entry => entry.Ordinal));
        Assert.Equal(new[] { 0, 1 }, proof.Scopes.Select(scope => scope.Ordinal));
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesKeepBuiltinBroadHolderScopeBoundToTheResourceDomain(string rule)
    {
        var finding = Assert.Single(Assess(rule, [Write(GuidFor(rule), sid: "S-1-5-32-545")]).Findings);
        Assert.Equal(("S-1-5-32-545", "contoso.com"), (Evidence(finding).HolderSid, Evidence(finding).HolderScope));
        Assert.Equal("S-1-5-32-545:CONTOSO.COM", finding.Subject.Key);
    }

    [Fact]
    public void AttributeWriteFullControlRetainsTheNewPrimitivePermissionsUnderItsAggregate()
    {
        var subject = Account(TargetDn, TargetSid);
        var entry = Write(null) with { AccessMask = 0x000f01ff };
        var (_, context) = Prepare(subject, [entry], Catalogue(), [], false, false);
        var permissions = new ObjectPermissions(TargetDn, DescriptorAvailability.Read, null, null, DaclState.Present,
            DaclCompleteness.Complete, true, false, [entry], []);
        var result = ControlEdgeDeriver.Derive(subject, permissions, context, Guid.NewGuid(), Guid.NewGuid(), DomainSidOf);
        var summary = Assert.Single(result.FullControlAssessments);
        Assert.Contains(ControlCapability.CanWriteServicePrincipalName, summary.SupportingCapabilities);
        Assert.Contains(ControlCapability.CanWriteResourceBasedConstrainedDelegation, summary.SupportingCapabilities);
        Assert.Contains(result.Edges, edge => edge.Capability == ControlCapability.CanWriteKeyCredentialLink);
    }

    [Theory]
    [InlineData("SEC-014")]
    [InlineData("SEC-024")]
    [InlineData("SEC-025")]
    public void AttributeWriteRulesKeepKnownPositivePermissionsBesideIncompleteOtherHolders(string rule)
    {
        var guid = GuidFor(rule);
        var unknown = Write(guid, 1) with { Trustee = new(DomainSid + "-9999", null, null, null, null, null, null) };
        var verdict = Assess(rule, [Write(guid), unknown]);
        var finding = Assert.Single(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.False(Evidence(finding).IsComplete);
        var row = new FindingRowViewModel(finding);
        Assert.Equal("May be incomplete", row.Coverage);
        Assert.Equal(FactState.NotEstablished, row.State);
        Assert.False(row.HasTier0Routes);
    }

    [Fact]
    public void AttributeWriteRulesRequireTheExactPreparedObjectAndGeneration()
    {
        var subject = Account(TargetDn, TargetSid);
        var (assessment, context) = Prepare(subject, [Write(GuidFor("SEC-024"))], Catalogue(), [], false, false);
        Assert.Throws<InvalidOperationException>(() => assessment.For(subject with { DistinguishedName = "CN=Another," + Root }, Definition("SEC-024")));
        Assert.Throws<InvalidOperationException>(() => new UnexpectedServicePrincipalNameWrite().Judge(subject));
        var notPrepared = new UnexpectedServicePrincipalNameWrite().Judge(subject, JudgingContext.At(Started));
        Assert.False(notPrepared.IsComplete);
        var (wrongGeneration, _) = Prepare(subject, [Write(GuidFor("SEC-024"))], Catalogue(), [], false, false,
            changeEvaluation: value => value with { Edges = value.Edges.Select(edge => edge with { GenerationId = Guid.NewGuid() }).ToArray() });
        Assert.Throws<InvalidDataException>(() => wrongGeneration.For(subject, Definition("SEC-024")));
    }

    [Fact]
    public void AttributeWriteRulesNullDaclRemainsBroadWithoutInventingPermissionEntries()
    {
        var directory = Published("O:SYG:SY");
        using var reader = Open(directory);
        Assert.All(reader.Read().Findings, finding =>
        {
            var proof = Evidence(finding);
            Assert.Equal("S-1-1-0", proof.HolderSid);
            Assert.Equal(nameof(EffectiveAccessOutcome.GrantsEveryoneEverything), proof.DescriptorOutcome);
            Assert.Empty(proof.Entries);
            Assert.Empty(proof.Scopes);
        });
    }

    [Fact]
    public void AttributeWriteRulesUnknownClassDoesNotBecomeNotApplicableInTheRealScheduler()
    {
        var directory = Capture(AllPropertyDescriptor(), omitTargetClass: true);
        Derive(directory);
        var result = JudgingRun.Judge(directory, Trio, Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);
        Assert.Empty(reader.Read().Findings);
        Assert.All(reader.ReadRuleExecutions().Executions, execution =>
        {
            Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
            Assert.Contains(execution.MissingInputs, input => input.Attribute == "objectClass");
            Assert.True(execution.ObjectsNotJudged > 0);
        });
    }

    [Fact]
    public void AttributeWriteRulesPersistAllThreeTypedAnswersAndSharedOriginalEntryReferences()
    {
        var directory = Published(AllPropertyDescriptor());
        using var reader = Open(directory);
        var findings = reader.Read().Findings;
        Assert.Equal(3, findings.Count);
        var page = reader.ReadPage(FindingsQuery.About(TargetDn));
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(findings.Select(finding => JsonSerializer.Serialize(Evidence(finding), ProofSerialization.Options)),
            page.Value.Findings.Select(finding => JsonSerializer.Serialize(Evidence(finding), ProofSerialization.Options)));
        Assert.All(findings, finding =>
        {
            var evidence = Evidence(finding);
            Assert.Equal(reader.Description.GenerationId, evidence.GenerationId);
            Assert.Equal(reader.Description.DerivationGenerationId, evidence.DerivationGenerationId);
            Assert.Equal(0, Assert.Single(evidence.Entries).Ordinal);
            Assert.Equal(HolderSid, Assert.Single(evidence.Entries).Trustee.Sid);
        });
        using var connection = ReadConnection(directory, reader);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*),COUNT(DISTINCT entry_id) FROM finding_attribute_write_entry";
        using var rows = command.ExecuteReader();
        Assert.True(rows.Read());
        Assert.Equal((3L, 1L), (rows.GetInt64(0), rows.GetInt64(1)));
    }

    [Theory]
    [InlineData("cli")]
    [InlineData("shell")]
    public async Task AttributeWriteRulesRunInBothOfflineHostsWithoutCaptureOrCompletedPathClaims(string host)
    {
        var directory = Capture(AllPropertyDescriptor());
        Derive(directory);
        var before = Hash(directory);
        if (host == "cli")
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--judge", directory])!, CancellationToken.None,
                null, (_, _) => throw new InvalidOperationException("The property rules must never recapture.")));
        else
            Assert.True((await new JudgingLauncher(null).RunAsync(directory, new Progress<JudgingRun.JudgingProgress>(), CancellationToken.None)).IsSuccess);
        using var reader = Open(directory);
        var findings = reader.Read().Findings.Where(finding => finding.RuleId is "SEC-014" or "SEC-024" or "SEC-025").ToArray();
        Assert.Equal(3, findings.Length);
        Assert.All(findings, finding => Assert.Contains("does not prove", finding.Detail, StringComparison.Ordinal));
        Assert.Equal(before, Hash(directory));
    }

    [Theory]
    [InlineData("$.GenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.EvidenceSeal", "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")]
    [InlineData("$.DerivationGenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.DerivationSeal", "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")]
    [InlineData("$.PermissionKind", "'KeyCredentialLink'")]
    [InlineData("$.Attribute.Guid", "'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'")]
    [InlineData("$.Target.ObjectGuid", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.HolderSid", "'S-1-5-21-1-2-3-9999'")]
    [InlineData("$.Scopes[0].State", "'Unknown'")]
    [InlineData("$.ControlEngineVersion", "999")]
    public void AttributeWriteSavedReadRejectsRehashedSourceAndMeaningCorruption(string path, string value)
    {
        var directory = Published(AllPropertyDescriptor());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding_attribute_write SET proof=json_set(proof,$path,{value}) WHERE finding_id="
                + "(SELECT finding_id FROM finding WHERE rule_id='SEC-014')";
            command.Parameters.AddWithValue("$path", path);
            Assert.Equal(1, command.ExecuteNonQuery());
            Rehash(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(TargetDn)));
    }

    [Theory]
    [InlineData("ordinal")]
    [InlineData("fingerprint")]
    [InlineData("missing-entry")]
    [InlineData("missing-body")]
    [InlineData("relabel-row")]
    public void AttributeWriteSavedReadCannotLoseOrRelabelOriginalPermissionOccurrences(string variant)
    {
        var directory = Published(AllPropertyDescriptor());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = variant switch
            {
                "ordinal" => "UPDATE finding_attribute_write_entry SET ordinal=7",
                "fingerprint" => "UPDATE finding_attribute_write_entry SET fingerprint=zeroblob(32)",
                "missing-entry" => "DELETE FROM finding_attribute_write_entry",
                "missing-body" => "DELETE FROM finding_attribute_write_entry; DELETE FROM finding_attribute_write",
                _ => "UPDATE finding SET subject_key='wrong holder' WHERE rule_id='SEC-014'",
            };
            command.ExecuteNonQuery();
            Rehash(connection);
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Theory]
    [InlineData("severity", "'Critical'")]
    [InlineData("domain_fqdn", "'child.contoso.com'")]
    [InlineData("object_class", "'computer'")]
    [InlineData("subject_kind", "'DirectoryObject'")]
    public void AttributeWriteSavedReadRejectsRelabelledSeverityResourceAndSubject(string column, string value)
    {
        var directory = Published(AllPropertyDescriptor());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding SET {column}={value} WHERE rule_id='SEC-014'";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.About(TargetDn)));
    }

    [Fact]
    public void AttributeWritePublicationRefusesMissingTypedProofsOrBrokenFingerprints()
    {
        var directory = Published(AllPropertyDescriptor());
        using var reader = Open(directory);
        var seal = Evidence(reader.Read().Findings[0]).DerivationSeal;
        var working = TestSealing.CopyJudgement(directory, reader.Description.GenerationId, "attribute-write-publication");
        var copy = BundleLayout.AnalysisGenerationDataPath(working, AnalysisStoreKind.Judgement, reader.Description.GenerationId);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = copy, Pooling = false }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, working, reader.Description.GenerationId);
        AttributeWriteFindingStorage.RequirePublishable(connection, seal, CancellationToken.None);
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE finding_attribute_write SET fingerprint=zeroblob(32)";
        Assert.Equal(3, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => AttributeWriteFindingStorage.RequirePublishable(connection, seal, CancellationToken.None));
        Rehash(connection);
        command.CommandText = "DELETE FROM finding_attribute_write_entry; DELETE FROM finding_attribute_write";
        command.ExecuteNonQuery();
        Assert.Throws<InvalidDataException>(() => AttributeWriteFindingStorage.RequirePublishable(connection, seal, CancellationToken.None));
    }

    [Fact]
    public void AttributeWriteRollbackDoesNotLeaveSharedEntryIdsForAnotherRule()
    {
        var directory = Published(AllPropertyDescriptor());
        Finding[] originals;
        JudgementDescription description;
        using (var reader = Open(directory))
        {
            originals = reader.Read().Findings.ToArray();
            description = reader.Description;
        }
        using (var writer = JudgementWriter.Create(directory, description.EvidenceSeal, description.DerivationGenerationId, Started, Started))
        {
            Finding Rebind(string rule)
            {
                var finding = originals.Single(value => value.RuleId == rule);
                return finding with { Evidence = Evidence(finding) with { GenerationId = writer.GenerationId } };
            }
            var first = Rebind("SEC-014");
            var broken = first with { Subject = new(FindingSubjectKind.Account, "invalid-holder:"), Evidence = Evidence(first) with { HolderSid = "invalid-sid" } };
            Assert.Throws<InvalidDataException>(() => writer.Write(RuleExecution.Judged(Definition("SEC-014"), 1, 0, [first, broken])));
            var second = Rebind("SEC-024");
            var error = Record.Exception(() => writer.Write(RuleExecution.Judged(Definition("SEC-024"), 1, 0, [second])));
            Assert.Null(error);
            writer.Complete(Started.AddMinutes(1));
        }
        using var saved = Open(directory);
        var survived = Assert.Single(saved.Read().Findings);
        Assert.Equal("SEC-024", survived.RuleId);
        Assert.Single(Evidence(survived).Entries);
        Assert.Equal(HolderSid, Assert.Single(Evidence(survived).Entries).Trustee.Sid);
    }

    [Fact]
    public void AttributeWriteRulesUseApprovedLabelsFixedHighSeverityAndPermissionOnlyGuidance()
    {
        Assert.Equal(new[] { "Unexpected RBCD-configuration write permission", "Unexpected service-principal-name write permission",
            "Unexpected key-credential-link write permission" }, Trio.Select(rule => rule.Definition.Name));
        Assert.All(Trio, rule =>
        {
            Assert.Equal(Severity.High, rule.Definition.Severity);
            Assert.Single(RuleCatalogue.All, scheduled => scheduled.Definition.Id == rule.Definition.Id);
            Assert.Contains("does not prove", RuleGuidanceCatalogue.For(rule.Definition.Id)!.WhyItMatters, StringComparison.Ordinal);
            Assert.Contains("Remove only", RuleGuidanceCatalogue.For(rule.Definition.Id)!.WhatToDo, StringComparison.Ordinal);
        });
        Assert.DoesNotContain(RuleCatalogue.All, rule => rule.Definition.Id == "SEC-083");
        Assert.Equal("Service-principal-name write permission", ControlEdgeRowViewModel.CapabilityText(ControlCapability.CanWriteServicePrincipalName));
        Assert.Equal("RBCD-configuration write permission", ControlEdgeRowViewModel.CapabilityText(ControlCapability.CanWriteResourceBasedConstrainedDelegation));
    }

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        using var reader = Open(FindingsRun());
        return reader.ReadPage(FindingsQuery.About(TargetDn)).Value.Findings;
    }

    internal static string FindingsRun() => Published(AllPropertyDescriptor());

    private static RuleVerdict Assess(string rule, IReadOnlyList<PermissionEntry> entries, ObjectAttributes? subject = null,
        SchemaGuidCatalog? catalogue = null, IReadOnlyList<ObjectAttributes>? additional = null, bool incompleteDescriptor = false,
        ObjectAttributes? source = null, bool unsupportedMask = false)
    {
        subject ??= Account(TargetDn, TargetSid);
        var (assessment, context) = Prepare(subject, entries, catalogue ?? Catalogue(), additional ?? [], incompleteDescriptor, unsupportedMask, source);
        return ((IObjectRule)Trio.Single(value => value.Definition.Id == rule)).Judge(subject, context with { AttributeWrites = assessment });
    }

    private static (AttributeWriteAssessment Assessment, JudgingContext Context) Prepare(ObjectAttributes subject, IReadOnlyList<PermissionEntry> entries,
        SchemaGuidCatalog catalogue, IReadOnlyList<ObjectAttributes> additional, bool incompleteDescriptor, bool unsupportedMask,
        ObjectAttributes? source = null, Func<ControlObjectEvaluation, ControlObjectEvaluation>? changeEvaluation = null)
    {
        var generation = Guid.NewGuid();
        var derived = Guid.NewGuid();
        var seal = new string('a', 64);
        var binding = new Tier0InputBinding(seal, derived, new string('b', 64), PrincipalClassificationRegistry.Version, 2, 2, Root, Configuration);
        var objects = new List<ObjectAttributes> { Domain(Root, DomainSid), Domain(Child, ChildSid), source ?? subject };
        objects.AddRange(DefaultGroups());
        objects.AddRange(additional);
        if (objects.All(value => value.DistinguishedName != HolderDn)) objects.Add(Group(HolderDn, HolderSid, -2147483646));
        var input = new CapturedMembershipInput(derived, true, objects).Prepare(CancellationToken.None);
        var facts = new StoredProtectedPrincipalDerivation(1, DirectoryHeuristics.AdminSdExclusions("0000000001000000"), [], entries.Select(entry => entry.Trustee)
            .Append(new PermissionTrustee(HolderSid, "Permission holder", HolderDn, "contoso.com", null, null, null))
            .DistinctBy(holder => holder.Sid).Select((holder, index) => new StoredProtectedPrincipalFact(index, holder.Sid,
                Sid.IsBuiltinDomain(holder.Sid) ? "contoso.com" : null, ProtectedPrincipalEvaluation.NotProtected, null, ProtectionUnknownReason.None, [],
                OwnerAcceptance.NotAccepted) { MembershipRoutes = new([], MembershipRouteIncompleteReason.None) }).ToArray(), ProtectionUnknownReason.None);
        var context = JudgingContext.At(Started) with
        {
            ProtectedPrincipals = facts, SchemaGuids = catalogue, ForestFqdn = "contoso.com",
            NamingContexts = new Dictionary<string, NamingContextKind>(StringComparer.OrdinalIgnoreCase) { [Root] = NamingContextKind.Domain, [Child] = NamingContextKind.Domain },
            AdministrativeMembership = CapturedGroupMembershipIndex.Create(input, binding,
                new Dictionary<string, NamingContextKind>(StringComparer.OrdinalIgnoreCase) { [Root] = NamingContextKind.Domain, [Child] = NamingContextKind.Domain }, CancellationToken.None),
        };
        var permissions = new ObjectPermissions(subject.DistinguishedName, DescriptorAvailability.Read, null, null, DaclState.Present,
            incompleteDescriptor ? DaclCompleteness.Incomplete : DaclCompleteness.Complete, true, false, entries, []);
        var evaluated = ControlEdgeDeriver.DeriveAttributeWrites(subject, permissions, context, generation, derived, DomainSidOf);
        return (new(subject, changeEvaluation?.Invoke(evaluated) ?? evaluated, context, binding, true, unsupportedMask, generation), context);
    }

    private static RuleDefinition Definition(string rule) => Trio.Single(value => value.Definition.Id == rule).Definition;
    private static string AttributeFor(string rule) => rule switch
    {
        "SEC-014" => "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "SEC-024" => "servicePrincipalName",
        _ => "msDS-KeyCredentialLink",
    };
    private static string GuidFor(string rule) => rule switch
    {
        "SEC-014" => "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
        "SEC-024" => "f3a64788-5306-11d1-a9c5-0000f80367c1",
        _ => "5b47d60f-6090-40b2-9f37-2a4de88f3063",
    };
    private static AttributeWritePermissionEvidence Evidence(Finding finding) => Assert.IsType<AttributeWritePermissionEvidence>(finding.Evidence);
    private static Guid Id(string dn) => new(SHA256.HashData(Encoding.UTF8.GetBytes(dn)).AsSpan(0, 16));
    private static string? DomainSidOf(string domain) => domain == "contoso.com" ? DomainSid : domain == "child.contoso.com" ? ChildSid : null;
    private static PermissionEntry Write(string? guid, int ordinal = 0, string? sid = null, bool deny = false)
    {
        sid ??= HolderSid;
        var holder = new PermissionTrustee(sid, sid == HolderSid ? "Permission holder" : sid,
            sid.StartsWith(DomainSid, StringComparison.Ordinal) ? HolderDn : null, "contoso.com", null, null, null);
        return new(ordinal, guid is null ? deny ? "AccessDenied" : "AccessAllowed" : deny ? "AccessDeniedObject" : "AccessAllowedObject",
            holder, 0x20, guid, null, false, 0, 0, guid is not null, false, []);
    }
    private static ObjectAttribute Text(string name, params string[] values) => new(name, AttributeCardinality.MultiValued,
        values.Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray());
    private static ObjectAttribute Binary(string name, byte[] value) => new(name, AttributeCardinality.SingleValued, [new(0, null, value)]);
    private static ObjectAttributes Account(string dn, string sid, string kind = "user", uint control = 512)
    {
        var classes = new List<string> { "top", "person", "organizationalPerson", "user" };
        if (kind == "inetOrgPerson") classes.Remove("user");
        if (kind is "computer" or "msDS-ManagedServiceAccount" or "msDS-GroupManagedServiceAccount") classes.Add("computer");
        if (kind != "user" && kind != "computer") classes.Add(kind);
        return new(dn, Id(dn), Started, EvidenceCompleteness.Complete, [Text("objectClass", classes.ToArray()), Binary("objectSid", Sid.ToBytes(sid)!),
            Text("userAccountControl", control.ToString(CultureInfo.InvariantCulture)), Text("primaryGroupID", "513")],
            dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase) ? "child.contoso.com" : "contoso.com");
    }
    private static ObjectAttributes Domain(string dn, string sid) => new(dn, Id(dn), Started, EvidenceCompleteness.Complete,
        [Text("objectClass", "top", "domainDNS"), Binary("objectSid", Sid.ToBytes(sid)!)], dn == Root ? "contoso.com" : "child.contoso.com");
    private static ObjectAttributes Group(string dn, string sid, long type, params string[] members) => new(dn, Id(dn), Started, EvidenceCompleteness.Complete,
        [Text("objectClass", "top", "group"), Binary("objectSid", Sid.ToBytes(sid)!), Text("groupType", type.ToString(CultureInfo.InvariantCulture)),
            Text("member", members)], dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase) ? "child.contoso.com" : "contoso.com");
    private static IReadOnlyList<ObjectAttributes> DefaultGroups() => new[] { Root, Child }.SelectMany(context =>
    {
        var sid = context == Root ? DomainSid : ChildSid;
        var result = new List<ObjectAttributes> { Group("CN=Domain Admins," + context, sid + "-512", -2147483646),
            Group("CN=Administrators,CN=Builtin," + context, "S-1-5-32-544", -2147483643), Group("CN=Domain Users," + context, sid + "-513", -2147483646) };
        if (context == Root) result.AddRange([Group("CN=Enterprise Admins," + context, sid + "-519", -2147483640),
            Group("CN=Schema Admins," + context, sid + "-518", -2147483640)]);
        return result;
    }).ToArray();
    private static SchemaGuidCatalog Catalogue(IReadOnlyDictionary<string, IReadOnlyList<string>>? sets = null) =>
        SchemaGuidCatalog.CapturedOver(Trio.Select(rule => new SchemaGuidEntry(GuidFor(rule.Definition.Id), AttributeFor(rule.Definition.Id),
            SchemaGuidKind.Attribute, SchemaGuidSource.Captured)), SchemaGuidCatalog.Embedded,
            sets ?? new Dictionary<string, IReadOnlyList<string>>());
    private static string AllPropertyDescriptor() => $"O:SYG:SYD:(A;;WP;;;{HolderSid})";
    internal static string Published(string descriptor)
    {
        var directory = Capture(descriptor);
        Derive(directory);
        var result = JudgingRun.Judge(directory, Trio, Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);
        Assert.Equal(3, reader.Read().Findings.Count);
        return directory;
    }
    private static string Capture(string descriptor, bool omitTargetClass = false)
    {
        var directory = TempDirectories.Create("attribute-write-trio");
        using var writer = BundleWriter.Create(directory, Started);
        var objects = new List<ObjectAttributes> { Domain(Root, DomainSid), Domain(Child, ChildSid), Account(TargetDn, TargetSid), Group(HolderDn, HolderSid, -2147483646) };
        objects.AddRange(DefaultGroups());
        var configuration = new ObjectAttributes("CN=Directory Service,CN=Windows NT,CN=Services," + Configuration,
            Id("Directory Service"), Started, EvidenceCompleteness.Complete, [Text("objectClass", "top", "nTDSService"), Text("dSHeuristics", "0000000001000000")], "contoso.com");
        objects.Add(configuration);
        foreach (var (context, kind) in new[] { (Root, NamingContextKind.Domain), (Child, NamingContextKind.Domain),
            (Configuration, NamingContextKind.Configuration), (Schema, NamingContextKind.Schema) })
        {
            var partition = new PartitionCoverage(context, kind, "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(partition);
            foreach (var source in objects.Where(source => Context(source.DistinguishedName) == context))
            {
                var attributes = source.Attributes.Where(attribute => !omitTargetClass || source.DistinguishedName != TargetDn || attribute.LdapDisplayName != "objectClass")
                    .Select(attribute => new EvidenceAttribute(attribute.LdapDisplayName, StoredAttributeCompleteness.Complete,
                    attribute.Values.Select(value => value.Bytes is { } bytes ? EvidenceValue.OfBytes(bytes) : EvidenceValue.OfText(value.Text!)).ToArray())).ToList();
                var objectId = writer.WriteObject(new(partition, source.DistinguishedName, source.ObjectGuid, attributes, Started));
                if (source.DistinguishedName == TargetDn)
                {
                    var security = new RawSecurityDescriptor(descriptor);
                    var bytes = new byte[security.BinaryLength];
                    security.GetBinaryForm(bytes, 0);
                    writer.WriteSecurityDescriptor(objectId, bytes,
                        AceNormalizer.Normalize(source.ObjectGuid ?? throw new InvalidOperationException("The target fixture requires a GUID."),
                            SecurityDescriptorParser.Parse(bytes)));
                }
            }
            if (kind == NamingContextKind.Schema)
                foreach (var rule in Trio)
                {
                    var name = AttributeFor(rule.Definition.Id);
                    writer.WriteObject(new(partition, "CN=" + name + "," + Schema, Id(name),
                        [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("attributeSchema")]),
                            new("lDAPDisplayName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(name)]),
                            new("schemaIDGUID", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Guid.Parse(GuidFor(rule.Definition.Id)).ToByteArray())]),
                            new("isSingleValued", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("FALSE")])], Started));
                }
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com", "child.contoso.com"]),
            [DomainCoverage.Read("contoso.com"), DomainCoverage.Read("child.contoso.com")],
            [ForestPartitionCoverage.Read(Configuration, NamingContextKind.Configuration), ForestPartitionCoverage.Read(Schema, NamingContextKind.Schema)],
            SysvolCoverage.Of([])), Started.AddMinutes(1));
        return directory;
    }
    private static string Context(string dn) => dn.EndsWith(Schema, StringComparison.OrdinalIgnoreCase) ? Schema
        : dn.EndsWith(Configuration, StringComparison.OrdinalIgnoreCase) ? Configuration : dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase) ? Child : Root;
    private static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }
    private static SqliteConnection ReadConnection(string directory, JudgementReader reader)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = BundleLayout.AnalysisGenerationDataPath(directory,
            AnalysisStoreKind.Judgement, reader.Description.GenerationId), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, directory, reader.Description.GenerationId);
        return connection;
    }
    private static void Rehash(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT finding_id,generation,proof FROM finding_attribute_write";
        var rows = new List<(long Id, string Generation, string Proof)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read()) rows.Add((reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
        foreach (var row in rows)
        {
            command.CommandText = "SELECT ordinal,entry_id,fingerprint FROM finding_attribute_write_entry WHERE finding_id=$id ORDER BY ordinal";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$id", row.Id);
            var references = new List<AttributeWriteFindingStorage.Reference>();
            using (var reader = command.ExecuteReader())
                while (reader.Read()) references.Add(new(reader.GetInt32(0), reader.GetInt64(1), (byte[])reader.GetValue(2)));
            command.CommandText = "UPDATE finding_attribute_write SET fingerprint=$hash WHERE finding_id=$id";
            command.Parameters.AddWithValue("$hash", AttributeWriteFindingStorage.Fingerprint(row.Generation, row.Proof, references));
            Assert.Equal(1, command.ExecuteNonQuery());
        }
    }
}
