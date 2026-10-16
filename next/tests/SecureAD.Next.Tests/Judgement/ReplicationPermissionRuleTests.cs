using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Nodes;
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
using Fixture = SecureAD.Next.Tests.Judgement.ServiceAccountRuleTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ReplicationPermissionRuleTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Child = "DC=child," + Root;
    private const string Configuration = "CN=Configuration," + Root;
    private const string Domain = "S-1-5-21-1-2-3";
    private const string ChildDomain = "S-1-5-21-4-5-6";
    private const string HolderDn = "CN=Replication holder," + Root;
    private const string Other = Domain + "-1300";
    private const string Changes = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    private const string All = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    private const string Filtered = "89e95b76-444d-4c62-991a-0facbeda640c";
    private static readonly UnexpectedDomainSecretReplication Rule = new();

    // MS-DRSR IsGetNCChangesPermissionGranted checks the two CARs at ncRoot; the filtered and EXOP routes are distinct.
    [Theory]
    [InlineData(false, false, false, 0)]
    [InlineData(true, false, false, 0)]
    [InlineData(false, true, false, 0)]
    [InlineData(true, false, true, 0)]
    [InlineData(true, true, false, 1)]
    [InlineData(true, true, true, 1)]
    public void Sec002ConsumesOnlyTheFullSecretDomainCompound(bool changes, bool all, bool filtered, int count)
    {
        var rights = new[] { (changes, Changes), (all, All), (filtered, Filtered) };
        var verdict = Assess(rights.Where(value => value.Item1).Select((value, ordinal) => Right(ordinal, value.Item2)).ToArray());
        Assert.Equal(count, verdict.Findings.Count);
        Assert.True(verdict.IsComplete);
        if (count != 0)
        {
            var proof = Evidence(Assert.Single(verdict.Findings));
            Assert.Equal("PartitionRoot", proof.Tier0Basis);
            Assert.Equal(new[] { "Established", "Established" }, proof.Checks.Take(2).Select(check => check.State));
            Assert.Equal((Root, "contoso.com", Fixture.Id(Root)), (proof.NamingContextRoot, proof.DomainFqdn, proof.RootGuid));
        }
    }

    [Theory]
    [InlineData(Changes)]
    [InlineData(All)]
    public void Sec002PreservesTheOrderOfBroadAndScopedDenies(string denied)
    {
        var first = Assess([Right(0, denied, deny: true), Right(1, Changes), Right(2, All)]);
        Assert.Empty(first.Findings);
        Assert.True(first.IsComplete);
        var last = Assess([Right(0, Changes), Right(1, All), Right(2, denied, deny: true)]);
        var proof = Evidence(Assert.Single(last.Findings));
        Assert.Equal(new[] { 0, 1, 2 }, proof.Entries.Select(entry => entry.Ordinal));
        Assert.Contains(proof.Entries, entry => entry.AceType == "AccessDeniedObject");
        Assert.True(last.IsComplete);
        var broad = Ace(2, Holder, 0x100);
        Assert.Empty(Assess([Right(0, denied, deny: true), broad]).Findings);
    }

    [Fact]
    public void Sec002DoesNotCombineDifferentHoldersOrUsePermissionPivots()
    {
        Assert.Empty(Assess([Right(0, Changes), Right(1, All, sid: Other)]).Findings);
        foreach (var mask in new[] { 0x08, 0x10, 0x20, 0x40000, 0x80000 })
            Assert.Empty(Assess([Right(0, Changes) with { AccessMask = mask }, Right(1, All)]).Findings);
        Assert.Empty(Assess([Right(0, Changes) with { PropagationFlags = 8 }, Right(1, All)]).Findings);
    }

    [Fact]
    public void Sec002ReusesPartitionRootTier0QualificationWithoutInventingARootSid()
    {
        var root = SubjectAt(Root);
        root = root with { Attributes = root.Attributes.Where(attribute => attribute.LdapDisplayName != "objectSid").ToArray() };
        var finding = Assert.Single(Assess([Right(0, Changes), Right(1, All)], subject: root).Findings);
        Assert.Equal(Fixture.Id(Root), finding.ObjectGuid);
        Assert.Equal("PartitionRoot", Evidence(finding).Tier0Basis);
        Assert.Equal(FindingSubjectKind.DirectoryObject, finding.Subject.Kind);
    }

    [Theory]
    [InlineData("CN=Child,DC=contoso,DC=com", NamingContextKind.Domain, "domainDNS", false)]
    [InlineData("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration, "configuration", true)]
    [InlineData("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema, "dMD", true)]
    public void Sec002DoesNotRelabelDescendantsOrOtherPartitionsAsDomainSecrets(string dn, NamingContextKind kind, string objectClass, bool recorded)
    {
        var subject = SubjectAt(dn, objectClass);
        var roots = new Dictionary<string, NamingContextKind>(StringComparer.OrdinalIgnoreCase) { [Root] = NamingContextKind.Domain };
        if (recorded) roots[dn] = kind;
        var verdict = Assess([Right(0, Changes), Right(1, All)], subject: subject, roots: roots);
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Theory]
    [InlineData("classes")]
    [InlineData("mismatch")]
    [InlineData("guid")]
    [InlineData("root-metadata")]
    [InlineData("domain")]
    public void Sec002DoesNotTreatUnverifiedRootIdentityAsClean(string defect)
    {
        var subject = SubjectAt(Root);
        subject = defect switch
        {
            "classes" => subject with { Attributes = subject.Attributes.Where(attribute => attribute.LdapDisplayName != "objectClass").ToArray() },
            "mismatch" => subject with { Attributes = [Text("objectClass", "top", "container")] },
            "guid" => subject with { ObjectGuid = null },
            "domain" => subject with { DomainFqdn = "child.contoso.com" },
            _ => subject,
        };
        var verdict = Assess([Right(0, Changes), Right(1, All)], subject: subject, missingRoots: defect == "root-metadata");
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-512", 0)]
    [InlineData("S-1-5-21-1-2-3-519", 0)]
    [InlineData("S-1-5-32-544", 0)]
    [InlineData("S-1-5-18", 0)]
    [InlineData("S-1-5-21-1-2-3-518", 1)]
    [InlineData("S-1-5-21-1-2-3-548", 1)]
    [InlineData("S-1-5-21-1-2-3-513", 1)]
    [InlineData("S-1-5-11", 1)]
    [InlineData("S-1-5-21-4-5-6-512", 1)]
    public void Sec002UsesScopedExpectednessNotTier0MembershipOrADomainControllerExemption(string sid, int count)
    {
        var entries = new[] { Right(0, Changes, sid: sid), Right(1, All, sid: sid) };
        var verdict = Assess(entries);
        Assert.Equal(count, verdict.Findings.Count);
        Assert.True(verdict.IsComplete);
        if (sid.StartsWith(ChildDomain, StringComparison.Ordinal))
            Assert.Equal("UnexpectedOutsideAuthorityScope", Evidence(Assert.Single(verdict.Findings)).ExpectednessReason);
    }

    [Fact]
    public void Sec002RetainsDomainControllerClassificationWithoutSuppressingItsPermission()
    {
        var holder = SubjectAt("CN=DC01,OU=Domain Controllers," + Root, "computer") with
        {
            Attributes = [Text("objectClass", "top", "user", "computer"), Binary("objectSid", Holder),
                Text("userAccountControl", "8192"), Text("primaryGroupID", "516")],
        };
        var entries = new[] { Right(0, Changes), Right(1, All) }.Select(entry => entry with
            { Trustee = entry.Trustee with { DistinguishedName = holder.DistinguishedName } }).ToArray();
        var proof = Evidence(Assert.Single(Assess(entries, holder: holder).Findings));
        Assert.Equal("Established", proof.Checks.Single(check => check.Name == "HolderDomainControllerAsset").State);
        Assert.Equal("UnexpectedNotControlPlane", proof.ExpectednessReason);
    }

    [Fact]
    public void Sec002KeepsUnknownExpectednessUnassessed()
    {
        var verdict = Assess([Right(0, Changes), Right(1, All)], missingMembership: true);
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.ReplicationPermissionIncomplete);
    }

    [Theory]
    [InlineData("descriptor")]
    [InlineData("incomplete")]
    [InlineData("callback")]
    [InlineData("cross-deny")]
    [InlineData("scope")]
    [InlineData("generic")]
    public void Sec002DoesNotTurnMissingOrUnsupportedPermissionInputsIntoCleanAnswers(string defect)
    {
        var entries = new List<PermissionEntry> { Right(0, Changes), Right(1, All) };
        if (defect == "callback") entries.Insert(0, Right(2, All) with { AceType = "AccessDeniedCallbackObject" });
        if (defect == "cross-deny") entries.Insert(0, Right(2, All, deny: true, sid: Other));
        if (defect == "scope") entries[0] = entries[0] with { ObjectTypeGuid = null };
        if (defect == "generic") entries = [Ace(0, Holder, unchecked((int)0x10000000))];
        entries = entries.Select((entry, ordinal) => entry with { Ordinal = ordinal }).ToList();
        var verdict = Assess(entries, unread: defect == "descriptor", incomplete: defect == "incomplete");
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    [Fact]
    public void Sec002NullDaclAndEmptyDaclRemainDifferent()
    {
        var nullDacl = Evidence(Assert.Single(Assess([], nullDacl: true).Findings));
        Assert.Equal("S-1-1-0", nullDacl.HolderSid);
        Assert.Equal("GrantsEveryoneEverything", nullDacl.DescriptorOutcome);
        Assert.Empty(nullDacl.Entries);
        var empty = Assess([]);
        Assert.Empty(empty.Findings);
        Assert.True(empty.IsComplete);
    }

    [Fact]
    public void Sec002KnownPermissionSurvivesOtherUnassessedHoldersAndCaptureGaps()
    {
        var verdict = Assess([Right(0, Changes), Right(1, All), Right(2, Changes, sid: Other),
            Right(3, All, sid: Other) with { AceType = "AccessAllowedCallbackObject" }], captureComplete: false);
        var proof = Evidence(Assert.Single(verdict.Findings));
        Assert.Equal(Holder, proof.HolderSid);
        Assert.False(proof.IsComplete);
        Assert.Contains("CaptureIncomplete", proof.Limitations);
        Assert.False(verdict.IsComplete);
        Assert.Equal(new[] { 0, 1 }, proof.Entries.Select(entry => entry.Ordinal));
        var row = new FindingRowViewModel(verdict.Findings[0]);
        Assert.Equal("May be incomplete", row.Coverage);
    }

    [Theory]
    [InlineData("object")]
    [InlineData("generation")]
    [InlineData("derivation")]
    [InlineData("input")]
    public void Sec002RequiresTheExactPreparedObjectAndGeneration(string defect)
    {
        var prepared = Prepare([Right(0, Changes), Right(1, All)], change: evaluation => defect switch
        {
            "generation" => evaluation with { Edges = evaluation.Edges.Select(edge => edge with { GenerationId = Guid.NewGuid() }).ToArray() },
            "derivation" => evaluation with { Edges = evaluation.Edges.Select(edge => edge with { DerivationGenerationId = Guid.NewGuid() }).ToArray() },
            _ => evaluation,
        }, inputMismatch: defect == "input");
        Assert.ThrowsAny<Exception>(() => Rule.Judge(defect == "object" ? prepared.Subject with { } : prepared.Subject, prepared.Context));
    }

    [Fact]
    public void Sec002OneGroupHeldFindingKeepsDuplicatesAndInheritedOriginalOccurrencesWithoutExpandingMembers()
    {
        var descriptor = Grants(Holder) + $"(OA;;CR;{All};;{Holder})(OA;ID;CR;{Changes};;{Holder})";
        var members = Enumerable.Range(0, 4).Select(index => "CN=Member " + index + "," + Root).ToArray();
        var sources = new List<Fixture.Source> { Fixture.Group(HolderDn, Holder, -2147483646, members) };
        sources.AddRange(members.Select((dn, index) => Fixture.Account(dn: dn, sid: Domain + "-" + (2000 + index), spns: [])));
        var directory = Published(descriptor, sources.ToArray());
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings);
        var proof = Evidence(finding);
        Assert.Equal(new FindingSubject(FindingSubjectKind.DirectoryObject, Holder + ":"), finding.Subject);
        Assert.Equal(new[] { 0, 1, 2, 3 }, proof.Entries.Select(entry => entry.Ordinal));
        Assert.True(proof.Entries[^1].IsInherited);
        Assert.Equal(new[] { Changes, All, All, Changes }, proof.Entries.Select(entry => entry.ObjectTypeGuid));
        Assert.Equal(2, reader.ReadControlEdges(Root, null, null, true, 0).Edges.Count(edge => edge.EdgeClass == ControlEdgeClass.ReplicationControl));
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()!.Verdict);
        using var connection = Connection(directory, reader, readOnly: true);
        Assert.Equal(1L, Scalar(connection, "SELECT COUNT(*) FROM finding_replication_permission"));
        Assert.Equal(0L, Scalar(connection, "SELECT COUNT(*) FROM sqlite_schema WHERE name='finding_replication_permission_entry'"));
    }

    [Fact]
    public void Sec002WholeAndSelectedReadsKeepTheSameGenerationBoundProofAndSharedSource()
    {
        var directory = Published(Grants(Holder));
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings);
        var page = reader.ReadPage(FindingsQuery.About(Root));
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(JsonSerializer.Serialize(finding.Evidence, ProofSerialization.Options),
            JsonSerializer.Serialize(Assert.Single(page.Value.Findings).Evidence, ProofSerialization.Options));
        Assert.Equal(reader.Description.GenerationId, Evidence(finding).GenerationId);
        Assert.Equal(reader.Description.EvidenceSeal, Evidence(finding).EvidenceSeal);
        Assert.Equal(reader.Description.DerivationGenerationId, Evidence(finding).DerivationGenerationId);
        var noChildFindings = reader.ReadPage(FindingsQuery.About(HolderDn));
        Assert.True(noChildFindings.IsSuccess);
        Assert.Empty(noChildFindings.Value.Findings);
    }

    [Fact]
    public void Sec002KeepsTheSameBuiltinSidSeparateAtEachCapturedDomainRoot()
    {
        const string builtin = "S-1-5-32-545";
        var child = Fixture.With(RootSource(Grants(builtin)) with { Dn = Child, Guid = Fixture.Id(Child) },
            "objectSid", [EvidenceValue.OfBytes(Sid.ToBytes(ChildDomain)!)]);
        var directory = Published(Grants(builtin), child);
        using var reader = Open(directory);
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        Assert.Equal(new[] { Child, Root }, findings.Select(finding => finding.DistinguishedName).Order(StringComparer.Ordinal));
        Assert.Equal(new[] { "child.contoso.com", "contoso.com" }, findings.Select(finding => Evidence(finding).HolderScope).Order(StringComparer.Ordinal));
        Assert.Equal(2, findings.Select(finding => finding.Subject.Key).Distinct().Count());
        foreach (var finding in findings)
        {
            Assert.Equal(finding.DomainFqdn, Evidence(finding).HolderScope);
            Assert.Equal(finding.ObjectGuid, Evidence(finding).RootGuid);
        }
    }

    [Theory]
    [InlineData("cli")]
    [InlineData("shell")]
    public async Task Sec002RunsThroughBothOfflineHostsWithoutCaptureOrChangingEvidence(string host)
    {
        var directory = Capture(Grants(Holder));
        Derive(directory);
        var before = Hash(directory);
        if (host == "cli")
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--judge", directory])!, CancellationToken.None,
                null, (_, _) => throw new InvalidOperationException("SEC-002 must not contact a forest.")));
        else
        {
            var result = await new JudgingLauncher(null).RunAsync(directory, new Progress<JudgingRun.JudgingProgress>(), CancellationToken.None);
            Assert.True(result.IsSuccess, result.Error?.Description);
        }
        using var reader = Open(directory);
        Assert.Single(reader.Read().Findings.Where(finding => finding.RuleId == "SEC-002"));
        Assert.Equal(before, Hash(directory));
        Assert.Equal(RuleCatalogue.All.Count, reader.ReadRuleExecutions().Executions.Count);
    }

    [Theory]
    [InlineData("root")]
    [InlineData("class")]
    [InlineData("guid")]
    public void Sec002RealSchedulerRecordsMissingOrConflictingRootsAsUnassessed(string defect)
    {
        var root = RootSource(Grants(Holder));
        root = defect switch
        {
            "class" => root with { Attributes = root.Attributes.Where(attribute => attribute.LdapDisplayName != "objectClass").Append(
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("container")])).ToArray() },
            "guid" => root with { Guid = null },
            _ => root,
        };
        var child = Fixture.With(RootSource("O:SYG:SYD:") with { Dn = Child, Guid = Fixture.Id(Child) },
            "objectSid", [EvidenceValue.OfBytes(Sid.ToBytes(ChildDomain)!)]);
        var directory = Fixture.Capture([root, child, Fixture.Group(HolderDn, Holder, -2147483646)],
            omit: defect == "root" ? [Root] : null);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var execution = Assert.Single(reader.ReadRuleExecutions().Executions);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(1, execution.ObjectsNotJudged);
        Assert.Equal(1, execution.ObjectsJudged);
        Assert.Empty(reader.Read().Findings);
    }

    [Fact]
    public void Sec002RealSchedulerDoesNotOfferDomainDnsDescendantsAsNamingContextRoots()
    {
        var dn = "DC=lookalike," + Root;
        var source = RootSource(Grants(Holder));
        var child = source with { Dn = dn, Guid = Fixture.Id(dn),
            Attributes = source.Attributes.Where(attribute => attribute.LdapDisplayName != "objectSid").ToArray() };
        var directory = Capture("O:SYG:SYD:", child);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Empty(reader.Read().Findings);
        var execution = Assert.Single(reader.ReadRuleExecutions().Executions);
        Assert.Equal(1, execution.ObjectsJudged);
        Assert.Equal(1, execution.ObjectsNotJudged);
        Assert.True(execution.ObjectsNotApplicable > 0);
    }

    [Theory]
    [InlineData("RootGuid", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    [InlineData("NamingContextRoot", "CN=Descendant,DC=contoso,DC=com")]
    [InlineData("DomainFqdn", "other.contoso.com")]
    [InlineData("RootClass", "configuration")]
    [InlineData("Tier0Basis", "Core")]
    [InlineData("HolderSid", "S-1-5-21-1-2-3-1300")]
    [InlineData("HolderScope", "other.contoso.com")]
    [InlineData("HolderName", "Relabelled holder")]
    [InlineData("ExpectednessReason", "ExpectedSameDomainControlPlane")]
    [InlineData("DescriptorOutcome", "GrantsEveryoneEverything")]
    [InlineData("EvidenceSeal", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    [InlineData("DerivationSeal", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    [InlineData("GenerationId", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    [InlineData("DerivationGenerationId", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    public void Sec002ReadRefusesRehashedFindingBodiesThatRelabelSourceScopeOrGeneration(string field, string value)
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var json = JsonNode.Parse((string)ScalarObject(connection, "SELECT proof FROM finding_replication_permission")!)!.AsObject();
            json[field] = value;
            SaveRehashedBody(connection, json);
        });
        AssertRefused(directory);
    }

    [Theory]
    [InlineData("PrincipalCatalogueVersion")]
    [InlineData("ControlEngineVersion")]
    [InlineData("TierPolicyVersion")]
    [InlineData("TierContractVersion")]
    public void Sec002ReadRefusesRehashedUnsupportedSemanticVersions(string field)
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var json = JsonNode.Parse((string)ScalarObject(connection, "SELECT proof FROM finding_replication_permission")!)!.AsObject();
            json[field] = 999;
            SaveRehashedBody(connection, json);
        });
        AssertRefused(directory);
    }

    [Theory]
    [InlineData("Checks")]
    [InlineData("Limitations")]
    [InlineData("Entries")]
    [InlineData("invalid-json")]
    public void Sec002MalformedTypedProofsAreExplicitRefusalsOnExistingFindingScreens(string defect)
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var json = JsonNode.Parse((string)ScalarObject(connection, "SELECT proof FROM finding_replication_permission")!)!.AsObject();
            if (defect == "invalid-json") SaveRehashedJson(connection, "{bad");
            else
            {
                json[defect] = null;
                SaveRehashedBody(connection, json);
            }
        });
        AssertRefused(directory);
    }

    [Fact]
    public void Sec002CoordinatedBodyAndHeaderEditsCannotRelabelTheRecordedResourceDomain()
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var json = JsonNode.Parse((string)ScalarObject(connection, "SELECT proof FROM finding_replication_permission")!)!.AsObject();
            json["DomainFqdn"] = "child.contoso.com";
            SaveRehashedBody(connection, json);
            Execute(connection, "UPDATE finding SET domain_fqdn='child.contoso.com' WHERE rule_id='SEC-002'");
        });
        AssertRefused(directory);
    }

    [Fact]
    public void Sec002RehashingTheBodyCannotEraseRecordedIncompleteCapture()
    {
        var directory = Fixture.Capture([RootSource(Grants("S-1-1-0"))], partial: true);
        Derive(directory);
        Judge(directory);
        using (var reader = Open(directory))
        {
            var proof = Evidence(Assert.Single(reader.Read().Findings));
            Assert.Contains("CaptureIncomplete", proof.Limitations);
            Assert.False(proof.IsComplete);
        }
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var json = JsonNode.Parse((string)ScalarObject(connection, "SELECT proof FROM finding_replication_permission")!)!.AsObject();
            json["Limitations"] = new JsonArray();
            SaveRehashedBody(connection, json);
        });
        AssertRefused(directory);
    }

    [Theory]
    [InlineData("DELETE FROM control_ace WHERE edge_id IN (SELECT edge_id FROM finding_replication_permission)")]
    [InlineData("UPDATE control_ace SET ordinal=ordinal+10 WHERE edge_id IN (SELECT edge_id FROM finding_replication_permission)")]
    [InlineData("UPDATE permission_entry SET mask=16 WHERE id IN (SELECT entry_id FROM control_ace)")]
    [InlineData("UPDATE control_precondition SET state='NotEstablished' WHERE name='DS-Replication-Get-Changes-All'")]
    [InlineData("UPDATE control_precondition SET evidence='Configuration' WHERE name='NamingContextKind'")]
    [InlineData("DELETE FROM control_precondition WHERE name='NamingContextRoot'")]
    [InlineData("UPDATE control_edge SET generation='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'")]
    [InlineData("UPDATE control_edge SET expectedness='Expected'")]
    [InlineData("UPDATE control_edge SET target_guid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'")]
    public void Sec002ReadRefusesChangedOrLostOriginalPermissionProofs(string sql)
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection => Execute(connection, sql));
        AssertRefused(directory);
    }

    [Theory]
    [InlineData("severity", "High")]
    [InlineData("subject_kind", "Account")]
    [InlineData("subject_key", "S-1-5-21-1-2-3-1300:")]
    [InlineData("object_guid", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    [InlineData("distinguished_name", "CN=Descendant,DC=contoso,DC=com")]
    [InlineData("domain_fqdn", "child.contoso.com")]
    public void Sec002ReadCannotRelabelTheFindingHeader(string column, string value)
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection => Execute(connection,
            "UPDATE finding SET " + column + "=$value WHERE rule_id='SEC-002'", ("$value", value)));
        AssertRefused(directory);
    }

    [Theory]
    [InlineData("DELETE FROM finding_replication_permission")]
    [InlineData("UPDATE finding_replication_permission SET fingerprint=zeroblob(32)")]
    [InlineData("UPDATE finding_replication_permission SET source_hash=zeroblob(32)")]
    public void Sec002PublicationAndReadbackRequireTypedProofAndBothBindings(string sql)
    {
        var directory = Published(Grants(Holder));
        SelfMembershipCoverageTests.Mutate(directory, connection => Execute(connection, sql));
        using var reader = Open(directory);
        using var connection = Connection(directory, reader);
        var seal = FindingInputBinding.DerivationSeal(directory, reader.Description.DerivationGenerationId);
        Assert.ThrowsAny<Exception>(() => ReplicationPermissionFindingStorage.RequirePublishable(connection, seal, CancellationToken.None));
        Assert.ThrowsAny<Exception>(() => reader.Read());
    }

    [Fact]
    public void Sec002SharedProofReferenceCannotBeRepointedEvenWithARehashedBody()
    {
        var directory = Published(Grants(Holder) + Grants(Other), Fixture.Group("CN=Other holder," + Root, Other, -2147483646));
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var rows = new List<(long Finding, long Edge, string Json, byte[] Source)>();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT finding_id,edge_id,proof,source_hash FROM finding_replication_permission ORDER BY finding_id";
                using var read = command.ExecuteReader();
                while (read.Read()) rows.Add((read.GetInt64(0), read.GetInt64(1), read.GetString(2), (byte[])read.GetValue(3)));
            }
            var first = rows[0];
            var second = rows[1];
            Execute(connection, "DELETE FROM finding_replication_permission WHERE finding_id=$id", ("$id", second.Finding));
            Execute(connection, "DELETE FROM finding WHERE finding_id=$id", ("$id", second.Finding));
            var generation = JsonSerializer.Deserialize<ReplicationPermissionEvidence>(first.Json, ProofSerialization.Options)!.GenerationId.ToString("D");
            Execute(connection, "UPDATE finding_replication_permission SET edge_id=$edge,fingerprint=$hash WHERE finding_id=$id",
                ("$edge", second.Edge), ("$hash", ReplicationPermissionFindingStorage.Fingerprint(generation, second.Edge, first.Json, first.Source)),
                ("$id", first.Finding));
        });
        AssertRefused(directory);
    }

    [Fact]
    public void Sec002RulesAndFindingsUseTheApprovedCriticalPermissionOnlyCopy()
    {
        Assert.Same(RuleCatalogue.All.Single(rule => rule.Definition.Id == "SEC-002").GetType(), typeof(UnexpectedDomainSecretReplication));
        Assert.Equal(Severity.Critical, Rule.Definition.Severity);
        Assert.Equal("Unexpected domain-secret replication permission", Rule.Definition.Name);
        var guidance = Assert.IsType<RuleGuidance>(RuleGuidanceCatalogue.For("SEC-002"));
        Assert.Null(guidance.MitreTechnique);
        var explanation = "The captured permissions establish Get-Changes and Get-Changes-All for this permission holder on the domain naming-context root. "
            + "These permissions can expose secret domain data.";
        var limits = "This finding does not establish authorization for an individual group member, that replication occurred, credential extraction or a completed path to Tier 0. "
            + "Filtered-attribute replication and constrained individual-secret replication are separate assessments.";
        var review = "Review the recorded permission holder and original granting entries. Confirm whether this replication permission is required before removing an unintended grant; "
            + "removing legitimate replication permissions can disrupt directory replication or dependent services.";
        var ruleRow = new RuleRowViewModel("SEC-002", Rule.Definition, null);
        Assert.Equal(explanation, ruleRow.LooksFor);
        Assert.Equal(explanation, ruleRow.WhyItMatters);
        Assert.Equal(limits, Assert.Single(ruleRow.ScopeNotes).Text);
        Assert.Equal(review, ruleRow.WhatToDo);
        var finding = Assert.Single(Assess([Right(0, Changes), Right(1, All)]).Findings);
        Assert.Contains(explanation, finding.Detail);
        Assert.Contains(limits, finding.Detail);
        var findingRow = new FindingRowViewModel(finding);
        Assert.Equal(review, findingRow.WhatToDo);
        Assert.Equal("Critical", findingRow.Severity);
        Assert.Equal("Replication permissions or scoped expectedness could not be fully assessed from the captured evidence. "
            + "Established findings remain evidence of the permissions shown.",
            UnresolvedWording.For("AdministrativeMembership.ReplicationPermissionIncomplete"));
    }

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        var directory = FindingsRun();
        using var reader = Open(directory);
        var page = reader.ReadPage(FindingsQuery.About(Root));
        Assert.True(page.IsSuccess, page.Error?.Description);
        return page.Value.Findings;
    }

    internal static string FindingsRun() => Published(Grants(Holder));

    private static RuleVerdict Assess(IReadOnlyList<PermissionEntry> entries, ObjectAttributes? subject = null,
        IReadOnlyDictionary<string, NamingContextKind>? roots = null, bool missingRoots = false, bool missingMembership = false,
        bool unread = false, bool incomplete = false, bool nullDacl = false, bool captureComplete = true, ObjectAttributes? holder = null)
    {
        var prepared = Prepare(entries, subject, roots, missingRoots, missingMembership, unread, incomplete, nullDacl, captureComplete, holder);
        return Rule.Judge(prepared.Subject, prepared.Context);
    }

    private static (ObjectAttributes Subject, JudgingContext Context) Prepare(IReadOnlyList<PermissionEntry> entries,
        ObjectAttributes? subject = null, IReadOnlyDictionary<string, NamingContextKind>? roots = null, bool missingRoots = false,
        bool missingMembership = false, bool unread = false, bool incomplete = false, bool nullDacl = false,
        bool captureComplete = true, ObjectAttributes? holder = null, Func<ControlObjectEvaluation, ControlObjectEvaluation>? change = null,
        bool inputMismatch = false)
    {
        subject ??= SubjectAt(Root);
        roots ??= new Dictionary<string, NamingContextKind>(StringComparer.OrdinalIgnoreCase) { [Root] = NamingContextKind.Domain };
        var generation = Guid.NewGuid();
        var derived = Guid.NewGuid();
        var binding = new Tier0InputBinding(new string('a', 64), derived, new string('b', 64), PrincipalClassificationRegistry.Version,
            2, 2, Root, Configuration);
        var input = new CapturedMembershipInput(inputMismatch ? Guid.NewGuid() : derived, true, [subject]).Prepare(CancellationToken.None);
        var facts = new StoredProtectedPrincipalDerivation(1, DirectoryHeuristics.AdminSdExclusions(null), [], entries.Select(entry => entry.Trustee)
            .DistinctBy(trustee => trustee.Sid).Select((trustee, ordinal) => new StoredProtectedPrincipalFact(ordinal, trustee.Sid,
                Sid.IsBuiltinDomain(trustee.Sid) ? subject.DomainFqdn : null, ProtectedPrincipalEvaluation.NotProtected,
                null, ProtectionUnknownReason.None, [], OwnerAcceptance.NotAccepted)
                { MembershipRoutes = new([], MembershipRouteIncompleteReason.None) }).ToArray(), ProtectionUnknownReason.None);
        var context = JudgingContext.At(Started) with
        {
            ForestFqdn = "contoso.com", SchemaGuids = SecureAD.Kernel.Schema.SchemaGuidCatalog.Embedded,
            NamingContexts = missingRoots ? null : roots, ProtectedPrincipals = missingMembership ? null : facts,
            ControlPrincipals = _ => holder,
        };
        var permissions = unread ? null : new ObjectPermissions(subject.DistinguishedName, DescriptorAvailability.Read, null, null,
            nullDacl ? DaclState.Null : DaclState.Present, incomplete ? DaclCompleteness.Incomplete : DaclCompleteness.Complete, true, false, entries, []);
        var evaluated = ControlEdgeDeriver.Derive(subject, permissions, context, generation, derived, domain =>
            domain == "contoso.com" ? Domain : domain == "child.contoso.com" ? ChildDomain : null);
        var assessment = new ReplicationPermissionAssessment(subject, change?.Invoke(evaluated) ?? evaluated, context, binding, input, captureComplete,
            entries.Any(entry => (entry.AccessMask & unchecked((int)0xf0000000)) != 0), generation);
        return (subject, context with { ReplicationPermissions = assessment });
    }

    private static ObjectAttributes SubjectAt(string dn, string objectClass = "domainDNS") => new(dn, Fixture.Id(dn), Started,
        EvidenceCompleteness.Complete, [Text("objectClass", "top", objectClass), Binary("objectSid", Domain)], "contoso.com");
    private static ObjectAttribute Text(string name, params string[] values) => new(name,
        CapturedAttributeCatalog.All.Single(attribute => attribute.LdapDisplayName == name).Cardinality,
        values.Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray());
    private static ObjectAttribute Binary(string name, string sid) => new(name, AttributeCardinality.SingleValued, [new(0, null, Sid.ToBytes(sid)!)]);
    private static PermissionEntry Right(int ordinal, string guid, bool deny = false, string sid = Holder) =>
        Ace(ordinal, sid, 0x100, deny ? "AccessDeniedObject" : "AccessAllowedObject") with
        {
            HasObjectType = true, ObjectTypeGuid = guid,
            Trustee = Ace(ordinal, sid, 0x100).Trustee with
            {
                DistinguishedName = HolderDn, DomainFqdn = sid.StartsWith(ChildDomain, StringComparison.Ordinal) ? "child.contoso.com" : "contoso.com",
            },
        };
    private static string Grants(string sid) => $"(OA;;CR;{Changes};;{sid})(OA;;CR;{All};;{sid})";
    private static Fixture.Source RootSource(string descriptor)
    {
        if (!descriptor.StartsWith("O:", StringComparison.Ordinal)) descriptor = "O:SYG:SYD:" + descriptor;
        var raw = new RawSecurityDescriptor(descriptor);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        return new(Root, Fixture.Id(Root),
            [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("domainDNS")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(Domain)!)]),
                new("nTSecurityDescriptor", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)])]);
    }
    private static string Capture(string descriptor, params Fixture.Source[] extra)
    {
        var sources = new List<Fixture.Source> { RootSource(descriptor) };
        sources.AddRange(extra);
        if (sources.All(source => source.Dn != HolderDn)) sources.Add(Fixture.Group(HolderDn, Holder, -2147483646));
        sources.Add(new("CN=Directory Service,CN=Windows NT,CN=Services," + Configuration, Fixture.Id("Directory Service"),
            [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("nTDSService")]),
                new("dSHeuristics", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("0000000001000000")])]));
        sources.Add(Fixture.Group("CN=Domain Users," + Root, Domain + "-513", -2147483646));
        sources.Add(Fixture.Group("CN=Domain Users," + Child, ChildDomain + "-513", -2147483646));
        return Fixture.Capture(sources);
    }
    private static string Published(string descriptor, params Fixture.Source[] extra)
    {
        var directory = Capture(descriptor, extra);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var findings = reader.Read().Findings;
        Assert.True(findings.Any(finding => finding.RuleId == "SEC-002"),
            "The positive captured fixture did not establish SEC-002: " + JsonSerializer.Serialize(new
            {
                Executions = reader.ReadRuleExecutions().Executions,
                Edges = reader.ReadControlEdges(Root, null, null, true, 0).Edges.Select(edge =>
                    new { edge.Capability, edge.EvaluationState, edge.Expectedness, edge.ExpectednessReason, edge.Uncertainty }),
                Root = findings.Count == 0 ? CapturedRootDiagnosis(directory) : null,
            }, ProofSerialization.Options));
        return directory;
    }
    private static object CapturedRootDiagnosis(string directory)
    {
        using var inputs = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(inputs.OpenDerivation().IsSuccess);
        var root = inputs.Bundle.ReadObjectAttributes(Root)!;
        var input = inputs.ReadMembershipInput();
        var classification = Tier0Classifier.Qualify(inputs.Binding(), Tier0Target.From(root, Root), input, null);
        return new
        {
            Captured = root, Saved = input.FindUnique(Root, CancellationToken.None), Classification = classification,
            CaptureComplete = inputs.Bundle.ReadScope().Value.AllDeclaredDomainsAreComplete,
        };
    }
    private static void Judge(string directory)
    {
        var result = JudgingRun.Judge(directory, [Rule], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }
    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
    private static ReplicationPermissionEvidence Evidence(Finding finding) => Assert.IsType<ReplicationPermissionEvidence>(finding.Evidence);
    private static SqliteConnection Connection(string directory, JudgementReader reader, bool readOnly = false)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite, Pooling = false, ForeignKeys = false,
        }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, directory, reader.Description.GenerationId);
        return connection;
    }
    private static void AssertRefused(string directory)
    {
        using var reader = Open(directory);
        Assert.ThrowsAny<Exception>(() => reader.Read());
        var query = FindingsQuery.About(Root) with { Object = null };
        Assert.ThrowsAny<Exception>(() => reader.ReadPage(query));
        using var source = new BundleAssetSource();
        var page = source.ReadFindings(directory, query);
        Assert.False(page.IsSuccess);
        Assert.False(string.IsNullOrWhiteSpace(page.Error?.Description));
    }
    private static object? ScalarObject(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
    private static long Scalar(SqliteConnection connection, string sql) => (long)ScalarObject(connection, sql)!;
    private static void Execute(SqliteConnection connection, string sql, params (string Name, object Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        command.ExecuteNonQuery();
    }
    private static void SaveRehashedBody(SqliteConnection connection, JsonObject body)
    {
        var json = body.ToJsonString(ProofSerialization.Options);
        SaveRehashedJson(connection, json);
    }
    private static void SaveRehashedJson(SqliteConnection connection, string json)
    {
        var generation = (string)ScalarObject(connection, "SELECT generation FROM finding_replication_permission")!;
        var edge = Scalar(connection, "SELECT edge_id FROM finding_replication_permission");
        var source = (byte[])ScalarObject(connection, "SELECT source_hash FROM finding_replication_permission")!;
        Execute(connection, "UPDATE finding_replication_permission SET proof=$proof,fingerprint=$hash",
            ("$proof", json), ("$hash", ReplicationPermissionFindingStorage.Fingerprint(generation, edge, json, source)));
    }
}
