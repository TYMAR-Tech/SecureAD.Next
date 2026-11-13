using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoDirectoryPermissionTests
{
    internal const string Root = "DC=contoso,DC=com";
    internal const string Domain = "contoso.com";
    internal const string DomainSid = "S-1-5-21-1-2-3";
    internal const string HolderSid = DomainSid + "-1200";
    internal const string GpoDn = "CN=Captured policy,CN=Policies,CN=System," + Root;
    internal const string OuDn = "OU=Captured scope," + Root;
    internal const string SiteDn = "CN=Captured site,CN=Sites,CN=Configuration," + Root;
    internal const string SetGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    internal static readonly DateTimeOffset When = SelfMembershipDiscoveryTests.Started;
    internal static readonly Guid Generation = Guid.Parse("00000000-0000-0000-0000-000000000801");
    internal static readonly Guid DerivationGeneration = Guid.Parse("00000000-0000-0000-0000-000000000802");
    internal static readonly (string Name, string Guid)[] Attributes =
    [
        ("gPCFileSysPath", "f30e3bc1-9ff0-11d1-b603-0000f80367c1"),
        ("gPCFunctionalityVersion", "f30e3bc0-9ff0-11d1-b603-0000f80367c1"),
        ("flags", "bf967976-0de6-11d0-a285-00aa003049e2"),
        ("versionNumber", "bf967a76-0de6-11d0-a285-00aa003049e2"),
        ("gPCMachineExtensionNames", "32ff8ecc-783f-11d2-9916-0000f87a57d4"),
        ("gPCUserExtensionNames", "42a75fc6-783f-11d2-9916-0000f87a57d4"),
        ("gPCWQLFilter", "7bd4c7a6-1add-4436-8c04-3999a880154c"),
        ("gPLink", "f30e3bbe-9ff0-11d1-b603-0000f80367c1"),
        ("gPOptions", "f30e3bbf-9ff0-11d1-b603-0000f80367c1"),
    ];

    [Theory]
    [InlineData("gPCFileSysPath", GpoDirectoryOperation.PolicyFilePath)]
    [InlineData("gPCFunctionalityVersion", GpoDirectoryOperation.FunctionalityVersion)]
    [InlineData("flags", GpoDirectoryOperation.EnablementFlags)]
    [InlineData("versionNumber", GpoDirectoryOperation.PolicyVersion)]
    [InlineData("gPCMachineExtensionNames", GpoDirectoryOperation.ComputerExtensions)]
    [InlineData("gPCUserExtensionNames", GpoDirectoryOperation.UserExtensions)]
    [InlineData("gPCWQLFilter", GpoDirectoryOperation.WmiFilter)]
    public void MicrosoftPolicyAttributeIdentityQualifiesOnlyItsSpecificWrite(string attribute, GpoDirectoryOperation operation)
    {
        var verdict = Assess("SEC-080", [Entry(0, 0x20, GuidFor(attribute))]);
        var finding = Assert.Single(verdict.Findings);
        var proof = Evidence(finding);
        Assert.True(verdict.IsComplete);
        Assert.Equal(operation, Assert.Single(proof.Rights, right => right.State == GpoDirectoryPermissionState.Established).Operation);
        Assert.Equal(GuidFor(attribute), Assert.Single(proof.Permissions.Entries).ObjectTypeGuid);
        Assert.Equal(0x20, Assert.Single(proof.Permissions.Entries).AccessMask);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("groupPolicyContainer", finding.ObjectClass);
        Assert.Equal(HolderSid + ":", finding.Subject.Key);
    }

    [Theory]
    [InlineData("domainDNS")]
    [InlineData("organizationalUnit")]
    [InlineData("site")]
    public void LinkWriteIsScopedToCapturedLinkHoldersWithoutNeedingAnExistingLink(string kind)
    {
        var verdict = Assess("SEC-081", [Entry(0, 0x20, GuidFor("gPLink"))], kind);
        Assert.True(verdict.IsComplete);
        var proof = Evidence(Assert.Single(verdict.Findings));
        Assert.Equal(kind, proof.Target.ObjectClass);
        Assert.Equal(GpoDirectoryOperation.Links, Assert.Single(proof.Rights).Operation);
        Assert.Equal(GpoDirectoryPermissionState.Established, Assert.Single(proof.Rights).State);
    }

    [Theory]
    [InlineData("SEC-080", 0x80000)]
    [InlineData("SEC-080", 0x10000)]
    [InlineData("SEC-080", 0x10)]
    [InlineData("SEC-080", 0x100)]
    [InlineData("SEC-080", 0x10000000)]
    [InlineData("SEC-081", 0x40000)]
    [InlineData("SEC-081", 0x80000)]
    [InlineData("SEC-081", 0x10000000)]
    public void OtherRightsAndStoredGenericBitsAreNotPromotedIntoTheseOperations(string rule, int mask)
    {
        var verdict = Assess(rule, [Entry(0, mask)], rule == "SEC-080" ? "groupPolicyContainer" : "organizationalUnit");
        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    [Fact]
    public void PermissionListControlIsADirectoryOperationNotOwnershipOrSysvolControl()
    {
        var verdict = Assess("SEC-080", [Entry(0, 0x40000)]);
        var proof = Evidence(Assert.Single(verdict.Findings));
        Assert.Equal(GpoDirectoryOperation.PermissionList, Assert.Single(proof.Rights, right => right.State == GpoDirectoryPermissionState.Established).Operation);
        Assert.Equal(0x40000, Assert.Single(proof.Permissions.Entries).AccessMask);
        Assert.Contains("SYSVOL file modification", GpoDirectoryPermissionRules.Caution, StringComparison.Ordinal);
        Assert.Contains("completed path to Tier 0", GpoDirectoryPermissionRules.Caution, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SEC-080", "displayName")]
    [InlineData("SEC-080", "gPLink")]
    [InlineData("SEC-081", "gPOptions")]
    [InlineData("SEC-081", "gPCFileSysPath")]
    public void RenameAndSeparatePolicyOperationsDoNotBecomeFindings(string rule, string attribute)
    {
        var guid = attribute == "displayName" ? "bf967953-0de6-11d0-a285-00aa003049e2" : GuidFor(attribute);
        var verdict = Assess(rule, [Entry(0, 0x20, guid)], rule == "SEC-080" ? "groupPolicyContainer" : "organizationalUnit");
        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OrderedDenialsDoNotSubtractAnEarlierAllow(bool denyFirst)
    {
        var verdict = Assess("SEC-081", [Entry(0, 0x20, GuidFor("gPLink"), deny: denyFirst),
            Entry(1, 0x20, GuidFor("gPLink"), deny: !denyFirst)], "organizationalUnit");
        Assert.True(verdict.IsComplete);
        Assert.Equal(denyFirst ? 0 : 1, verdict.Findings.Count);
        if (!denyFirst) Assert.Equal(new[] { 0, 1 }, Evidence(Assert.Single(verdict.Findings)).Permissions.Entries.Select(entry => entry.Ordinal));
    }

    [Theory]
    [InlineData("SEC-080")]
    [InlineData("SEC-081")]
    public void OriginalDuplicatesAndGroupHeldPermissionsDoNotMultiplyFindings(string rule)
    {
        var verdict = Assess(rule, [Entry(0, 0x20), Entry(1, 0x20)], rule == "SEC-080" ? "groupPolicyContainer" : "organizationalUnit");
        var proof = Evidence(Assert.Single(verdict.Findings));
        Assert.Equal(2, proof.Permissions.Entries.Count);
        Assert.All(proof.Rights.Where(right => right.State == GpoDirectoryPermissionState.Established),
            right => Assert.Equal(new[] { 0, 1 }, right.GrantOrdinals));
        Assert.Equal(HolderSid, proof.Holder.Sid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CapturedPropertySetsQualifyOnlyTheirRecordedMembers(bool containsLink)
    {
        var assignments = new Dictionary<string, IReadOnlyList<string>> { [SetGuid] = containsLink ? ["gPLink"] : ["gPOptions"] };
        if (!containsLink) assignments["11111111-2222-3333-4444-555555555555"] = ["gPLink"];
        var catalogue = Catalogue(assignments);
        var verdict = Assess("SEC-081", [Entry(0, 0x20, SetGuid)], "organizationalUnit", catalogue);
        Assert.True(verdict.IsComplete);
        Assert.Equal(containsLink ? 1 : 0, verdict.Findings.Count);
        if (containsLink) Assert.Equal(new[] { "gPLink" }, Evidence(Assert.Single(verdict.Findings)).PropertySets[SetGuid]);
    }

    [Fact]
    public void SavedSchemaKeepsOutsideSetAssignmentsNeededToReplayExclusions()
    {
        const string other = "11111111-2222-3333-4444-555555555555";
        var assignments = new Dictionary<string, IReadOnlyList<string>>
        {
            [SetGuid] = ["gPCWQLFilter"],
            [other] = Attributes.Where(attribute => attribute.Name != "gPCWQLFilter").Select(attribute => attribute.Name).ToArray(),
        };
        var verdict = Assess("SEC-080", [Entry(0, 0x20, SetGuid, deny: true), Entry(1, 0x20)], catalogue: Catalogue(assignments));
        Assert.True(verdict.IsComplete);
        var proof = Evidence(Assert.Single(verdict.Findings));
        Assert.Contains(other, proof.PropertySets.Keys);
        Assert.Equal(assignments[other], proof.PropertySets[other]);
        Assert.Equal(GpoDirectoryPermissionState.NotEstablished, proof.Rights.Single(right => right.Operation == GpoDirectoryOperation.WmiFilter).State);
        Assert.Equal(GpoDirectoryPermissionState.Established, proof.Rights.Single(right => right.Operation == GpoDirectoryOperation.PolicyFilePath).State);
        GpoDirectoryPermissionStorage.Validate(proof);
    }

    [Theory]
    [InlineData("missing-schema")]
    [InlineData("conditional")]
    [InlineData("other-denial")]
    [InlineData("descriptor")]
    [InlineData("membership")]
    public void MissingOrUnsupportedAnalysisIsUnassessedRatherThanSafeOrEstablished(string issue)
    {
        var entries = issue switch
        {
            "conditional" => new[] { Entry(0, 0x20) with { AceType = "AccessAllowedCallback" } },
            "other-denial" => [Entry(0, 0x20, deny: true, sid: DomainSid + "-1500"), Entry(1, 0x20)],
            _ => [Entry(0, 0x20)],
        };
        var context = Context(Subject("organizationalUnit"), entries);
        if (issue == "missing-schema") context = context with { SchemaGuids = SchemaGuidCatalog.Embedded };
        if (issue == "descriptor") context = context with { Permissions = _ => null };
        if (issue == "membership") context = context with { MembershipRoutes = (_, _) => MembershipRouteSummary.NotDerived };
        var verdict = new UnexpectedGroupPolicyLinkWrite().Judge(Subject("organizationalUnit"), context);
        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    [Fact]
    public void UnavailablePropertySchemaDoesNotEraseIndependentlyEstablishedDaclControl()
    {
        var verdict = Assess("SEC-080", [Entry(0, 0x40000)], catalogue: SchemaGuidCatalog.Embedded);
        Assert.False(verdict.IsComplete);
        var proof = Evidence(Assert.Single(verdict.Findings));
        Assert.False(proof.IsComplete);
        Assert.Contains(proof.Rights, right => right.Operation == GpoDirectoryOperation.PermissionList && right.State == GpoDirectoryPermissionState.Established);
    }

    [Theory]
    [InlineData(DomainSid + "-512", Domain, 0)]
    [InlineData("S-1-5-21-4-5-6-512", "child.contoso.com", 1)]
    [InlineData(DomainSid + "-518", Domain, 1)]
    [InlineData(DomainSid + "-520", Domain, 1)]
    [InlineData("S-1-5-11", null, 1)]
    [InlineData("S-1-5-18", null, 0)]
    public void ExistingExpectednessIsTargetScopedWithoutNewGpoExemptions(string sid, string? holderDomain, int count)
    {
        var verdict = Assess("SEC-080", [Entry(0, 0x20, sid: sid, holderDomain: holderDomain)]);
        Assert.True(verdict.IsComplete);
        Assert.Equal(count, verdict.Findings.Count);
    }

    [Fact]
    public void BuiltinSitePermissionKeepsTheExistingForestPartitionScopeLimit()
    {
        var verdict = Assess("SEC-081", [Entry(0, 0x20, sid: "S-1-5-32-544")], "site");
        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NullAndEmptyDaclsRemainDistinctWithoutInventedEntries(bool nullDacl)
    {
        var subject = Subject("organizationalUnit");
        var context = Context(subject, []) with { Permissions = _ => new(subject.DistinguishedName, DescriptorAvailability.Read,
            null, null, nullDacl ? DaclState.Null : DaclState.Empty, DaclCompleteness.Complete, true, false, [], []) };
        var verdict = new UnexpectedGroupPolicyLinkWrite().Judge(subject, context);
        Assert.True(verdict.IsComplete);
        Assert.Equal(nullDacl ? 1 : 0, verdict.Findings.Count);
        if (nullDacl)
        {
            var proof = Evidence(Assert.Single(verdict.Findings));
            Assert.Equal("S-1-1-0", proof.Holder.Sid);
            Assert.Empty(proof.Permissions.Entries);
        }
    }

    [Fact]
    public void ADescriptorFromAnotherObjectCannotBeUsedAsThisTargetsProof()
    {
        var subject = Subject("groupPolicyContainer");
        var context = Context(subject, [Entry(0, 0x20)]) with { Permissions = _ => new("CN=Another," + Root,
            DescriptorAvailability.Read, null, null, DaclState.Present, DaclCompleteness.Complete, true, false, [Entry(0, 0x20)], []) };
        Assert.Throws<InvalidDataException>(() => new UnexpectedGpoDirectoryControl().Judge(subject, context));
    }

    internal static string GuidFor(string name) => Attributes.Single(value => value.Name == name).Guid;
    internal static GpoDirectoryPermissionEvidence Evidence(Finding finding) => Assert.IsType<GpoDirectoryPermissionEvidence>(finding.Evidence);
    internal static RuleVerdict Assess(string rule, IReadOnlyList<PermissionEntry> entries, string kind = "groupPolicyContainer",
        SchemaGuidCatalog? catalogue = null)
    {
        var subject = Subject(kind);
        var context = Context(subject, entries) with { SchemaGuids = catalogue ?? Catalogue() };
        return rule == "SEC-080" ? new UnexpectedGpoDirectoryControl().Judge(subject, context) : new UnexpectedGroupPolicyLinkWrite().Judge(subject, context);
    }
    internal static ObjectAttributes Subject(string kind) => new(kind switch
        { "groupPolicyContainer" => GpoDn, "site" => SiteDn, "domainDNS" => Root, _ => OuDn },
        Guid.Parse("00000000-0000-0000-0000-000000000811"), When, EvidenceCompleteness.Complete,
        [new("objectClass", AttributeCardinality.MultiValued, [new(0, "top", null), new(1, kind, null)]),
         new("displayName", AttributeCardinality.SingleValued, [new(0, "Captured GPO", null)])], Domain);
    internal static JudgingContext Context(ObjectAttributes subject, IReadOnlyList<PermissionEntry> entries) =>
        JudgingContext.At(When) with
        {
            SchemaGuids = Catalogue(), ForestFqdn = Domain,
            MembershipRoutes = (_, _) => new([], MembershipRouteIncompleteReason.None),
            NamingContexts = new Dictionary<string, NamingContextKind> { [Root] = NamingContextKind.Domain },
            Permissions = _ => new(subject.DistinguishedName, DescriptorAvailability.Read, null, null, entries.Count == 0 ? DaclState.Empty : DaclState.Present,
                DaclCompleteness.Complete, true, false, entries, []),
            GpoDirectoryPermissions = new(Generation, new(new string('a', 64), DerivationGeneration, new string('b', 64),
                PrincipalClassificationRegistry.Version, 2, 2, Root, "CN=Configuration," + Root),
                domain => domain == Domain ? DomainSid : domain == "child.contoso.com" ? "S-1-5-21-4-5-6" : null, true, CancellationToken.None),
        };
    internal static SchemaGuidCatalog Catalogue(IReadOnlyDictionary<string, IReadOnlyList<string>>? sets = null) =>
        SchemaGuidCatalog.CapturedOver(Attributes.Select(value => new SchemaGuidEntry(value.Guid, value.Name, SchemaGuidKind.Attribute, SchemaGuidSource.Captured))
            .Concat(new[] { ("groupPolicyContainer", "f30e3bc2-9ff0-11d1-b603-0000f80367c1"), ("organizationalUnit", "bf967aa5-0de6-11d0-a285-00aa003049e2"),
                ("domainDNS", "19195a5b-6da0-11d0-afd3-00c04fd930c9"), ("site", "bf967ab3-0de6-11d0-a285-00aa003049e2") }
                .Select(value => new SchemaGuidEntry(value.Item2, value.Item1, SchemaGuidKind.ObjectClass, SchemaGuidSource.Captured)))
            .Concat(sets is null ? [] : sets.Keys.Select(value => new SchemaGuidEntry(value, "Captured policy property set", SchemaGuidKind.PropertySet, SchemaGuidSource.Captured))),
            SchemaGuidCatalog.Embedded, sets ?? new Dictionary<string, IReadOnlyList<string>>());
    internal static PermissionEntry Entry(int ordinal, int mask, string? guid = null, bool deny = false,
        string sid = HolderSid, string? holderDomain = Domain) =>
        new(ordinal, deny ? guid is null ? "AccessDenied" : "AccessDeniedObject" : guid is null ? "AccessAllowed" : "AccessAllowedObject",
            new(sid, "Captured holder", "CN=Captured holder," + Root, holderDomain, null,
                WellKnownSidCatalog.FindBySid(sid)?.Role, null),
            mask, guid, null, false, 0, 0, guid is not null, false, []);
}
