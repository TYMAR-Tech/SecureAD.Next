using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class AttributeWritePermissionReadTests
{
    internal const string TargetDn = "CN=Captured target,DC=contoso,DC=com";
    internal const string HolderSid = "S-1-5-21-1-2-3-1200";
    internal const string AttributeGuid = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
    internal const string AttributeName = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    internal const string SetGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    [Theory]
    [InlineData(1)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(127)]
    public void SavedOriginalEntriesKeepTheirOrdinalOrderAndFindingGrainAcrossPages(int count)
    {
        var (evidence, selected, sources) = Fixture(count);
        var all = new List<int>();
        AttributeWritePermissionMark? after = null;
        do
        {
            var start = after?.Ordinal ?? -1;
            var entries = sources.Where(entry => entry.Ordinal > start).Take(50).ToArray();
            var next = sources.Count(entry => entry.Ordinal > start) > 50
                ? new AttributeWritePermissionMark(evidence.GenerationId, 17, selected.ObjectGuid, entries[^1].Ordinal) : (AttributeWritePermissionMark?)null;
            var page = Project(evidence, selected, entries, sources.Length, after, next);
            Assert.True(page.Context.Matches(selected));
            Assert.True(page.Context.EvidenceIsComplete);
            Assert.Equal(Math.Min(50, count - all.Count), page.Entries.Count);
            Assert.Equal(entries.Select(entry => entry.Ordinal), page.Entries.Select(entry => entry.Ordinal));
            all.AddRange(page.Entries.Select(entry => entry.Ordinal));
            after = page.Next;
        } while (after is not null);
        Assert.Equal(Enumerable.Range(0, count), all);
        Assert.Equal(HolderSid + ":", selected.Subject.Key);
        Assert.Equal(Severity.High, selected.Severity);
    }

    [Theory]
    [InlineData(SavedPropertyWriteScope.Attribute, false, false)]
    [InlineData(SavedPropertyWriteScope.PropertySet, true, false)]
    [InlineData(SavedPropertyWriteScope.ObjectClass, false, true)]
    [InlineData(SavedPropertyWriteScope.AllProperties, true, true)]
    public void EntryTypeBreadthAndInheritanceAreSavedFactsNotNewPermissionCalculations(
        SavedPropertyWriteScope scope, bool deny, bool inherited)
    {
        var (evidence, selected, sources) = Fixture(1, scope);
        sources = [sources[0] with { IsDeny = deny, IsInherited = inherited }];
        var page = Project(evidence, selected, sources, 1);
        var entry = Assert.Single(page.Entries);
        Assert.Equal(scope, entry.Scope);
        Assert.Equal(deny ? "Deny" : "Allow", entry.EntryType);
        Assert.Equal(inherited ? "Inherited" : "Explicit", entry.Assignment);
        Assert.Equal(inherited, entry.IsInherited);
        Assert.Equal(scope switch
        {
            SavedPropertyWriteScope.Attribute => "RBCD attribute",
            SavedPropertyWriteScope.PropertySet => "Property set: Captured property set",
            SavedPropertyWriteScope.ObjectClass => "Object class: user",
            _ => "All properties",
        }, entry.PermissionScope);
        Assert.Contains("not established by this finding", entry.InheritanceNote, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SavedPropertyWriteScope.PropertySet)]
    [InlineData(SavedPropertyWriteScope.ObjectClass)]
    public void UncapturedScopeNamesDoNotBecomeInventedCapturedNames(SavedPropertyWriteScope scope)
    {
        var (evidence, selected, sources) = Fixture(1, scope);
        evidence = evidence with { SchemaEntries = evidence.SchemaEntries.Select(entry =>
            entry.Guid == SetGuid ? entry with { Source = SchemaGuidSource.Embedded } : entry).ToArray() };
        var row = Assert.Single(Project(evidence, selected, sources, 1).Entries);
        Assert.Null(row.ScopeName);
        Assert.Contains("captured name unavailable", row.PermissionScope, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NullObjectDaclIsNotAnInventedEveryoneEntry(bool complete)
    {
        var (evidence, selected, sources) = Fixture(0, nullDacl: true);
        if (!complete)
        {
            evidence = evidence with { Limitations = ["CaptureIncomplete"] };
            selected = Selected(evidence);
        }
        var page = Project(evidence, selected, sources, 0);
        Assert.True(page.Context.HasNullDacl);
        Assert.Empty(page.Entries);
        Assert.Null(page.Next);
        Assert.Equal(complete, page.Context.EvidenceIsComplete);
    }

    [Theory]
    [InlineData(0u, "Enabled")]
    [InlineData(2u, "Disabled")]
    public void AccountStateUsesTheOriginalFlagsAtCapture(uint flags, string expected)
    {
        var (evidence, _, sources) = Fixture(1);
        evidence = evidence with { AccountControl = [new(0, flags.ToString(System.Globalization.CultureInfo.InvariantCulture), null)] };
        var page = Project(evidence, Selected(evidence), sources, 1);
        Assert.Equal(expected, page.Context.AccountState);
    }

    [Fact]
    public void MissingAccountStateRequiresItsSavedLimitationRatherThanAssumingEnabled()
    {
        var (evidence, _, sources) = Fixture(1);
        evidence = evidence with { AccountControl = [], Limitations = ["AccountStateUnreadable"] };
        var page = Project(evidence, Selected(evidence), sources, 1);
        Assert.Equal("Not established from captured evidence.", page.Context.AccountState);
        Assert.False(page.Context.EvidenceIsComplete);
        Assert.Single(page.Context.DescribeLimitations());
        var invalid = evidence with { Limitations = [] };
        Assert.Throws<InvalidDataException>(() => Project(invalid, Selected(invalid), sources, 1));
    }

    [Theory]
    [InlineData("UnexpectedBroadPrincipal", "broadly applicable identity")]
    [InlineData("UnexpectedNotControlPlane", "expected administrator for this target")]
    [InlineData("UnexpectedOutsideAuthorityScope", "expected administrative authority")]
    public void UnexpectednessReasonsRemainSavedAndDistinct(string reason, string wording)
    {
        var (evidence, _, sources) = Fixture(1);
        evidence = evidence with { ExpectednessReason = reason };
        var page = Project(evidence, Selected(evidence), sources, 1);
        Assert.Contains(wording, page.Context.Unexpectedness, StringComparison.Ordinal);
    }

    [Fact]
    public void UnrequestedSchemaAndDomainCollectionsAreNotReconstructed()
    {
        var (evidence, selected, sources) = Fixture(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Domains"] = JsonNode.Parse("[{\"Unrequested\":\"" + new string('x', 160_000) + "\"}]");
        json["PropertySetMembers"] = JsonNode.Parse("{\"unrequested\":[\"" + new string('x', 160_000) + "\"]}");
        Assert.Single(Project(json.ToJsonString(), evidence, selected, sources, 1).Entries);
    }

    public static IEnumerable<object[]> InvalidMetadata()
    {
        const string differentGuid = "\"00000000-0000-0000-0000-000000000001\"";
        yield return ["GenerationId", differentGuid];
        yield return ["EvidenceSeal", "\"different source\""];
        yield return ["DerivationGenerationId", differentGuid];
        yield return ["DerivationSeal", "\"different derivation\""];
        yield return ["PrincipalCatalogueVersion", "-1"];
        yield return ["ControlEngineVersion", "-1"];
        yield return ["PermissionKind", "\"ServicePrincipalName\""];
        yield return ["Target.ObjectGuid", differentGuid];
        yield return ["Target.DistinguishedName", "\"CN=Another target,DC=contoso,DC=com\""];
        yield return ["Target.DomainFqdn", "\"another.example\""];
        yield return ["HolderSid", "\"S-1-5-21-1-2-3-9999\""];
        yield return ["HolderScope", "\"invented.example\""];
        yield return ["ExpectednessReason", "\"ExpectedDomainAdministrator\""];
        yield return ["Attribute.Guid", differentGuid];
        yield return ["Attribute.Source", "\"Embedded\""];
        yield return ["DescriptorOutcome", "\"NotComputed\""];
        yield return ["Scopes", "[]"];
        yield return ["IsComplete", "false"];
    }

    [Theory]
    [MemberData(nameof(InvalidMetadata))]
    public void MalformedMisboundOrWrongFamilyMetadataCannotBecomeAReadback(string path, string replacement)
    {
        var (evidence, selected, sources) = Fixture(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        var names = path.Split('.');
        var parent = names.Take(names.Length - 1).Aggregate(json, (node, name) => node[name]!);
        parent[names[^1]] = JsonNode.Parse(replacement);
        Assert.Equal(SavedAttributeWritePermission.InvalidDetailsForRule("SEC-014"),
            Assert.Throws<InvalidDataException>(() => Project(json.ToJsonString(), evidence, selected, sources, 1)).Message);
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("duplicate")]
    public void PermissionMetadataRequiresOneCompleteJsonObject(string defect)
    {
        var (evidence, selected, sources) = Fixture(1);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        json = defect switch { "truncated" => json[..^1], "trailing" => json + "{}", _ => json.Insert(1, "\"HolderSid\":\"duplicate\",") };
        Assert.Throws<InvalidDataException>(() => Project(json, evidence, selected, sources, 1));
    }

    internal static (AttributeWritePermissionEvidence Evidence, FindingListItem Selected, SavedWriteEntrySource[] Sources) Fixture(
        int count, SavedPropertyWriteScope scope = SavedPropertyWriteScope.AllProperties, bool nullDacl = false,
        AttributeWritePermissionKind permissionKind = AttributeWritePermissionKind.ResourceBasedConstrainedDelegation)
    {
        var family = Family(permissionKind);
        var generation = Guid.NewGuid();
        var target = new AdministrativeMembershipIdentity(Guid.NewGuid(), TargetDn, "DC=contoso,DC=com", "contoso.com",
            "S-1-5-21-1-2-3-1100", null, "user", null, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete,
            [new("objectClass", 0, "top"), new("objectClass", 1, "person"), new("objectClass", 2, "user")]);
        var attribute = new SchemaGuidEntry(family.Guid, family.Attribute, SchemaGuidKind.Attribute, SchemaGuidSource.Captured);
        var definitions = new List<SchemaGuidEntry> { attribute };
        if (scope is SavedPropertyWriteScope.PropertySet or SavedPropertyWriteScope.ObjectClass)
            definitions.Add(new(SetGuid, scope == SavedPropertyWriteScope.PropertySet ? "Captured property set" : "user",
                scope == SavedPropertyWriteScope.PropertySet ? SchemaGuidKind.PropertySet : SchemaGuidKind.ObjectClass, SchemaGuidSource.Captured));
        var sources = Enumerable.Range(0, count).Select(ordinal => new SavedWriteEntrySource(ordinal, false, HolderSid,
            scope == SavedPropertyWriteScope.AllProperties ? null : scope == SavedPropertyWriteScope.Attribute ? family.Guid : SetGuid,
            scope != SavedPropertyWriteScope.AllProperties, false)).ToArray();
        var evidence = new AttributeWritePermissionEvidence(generation, new string('a', 64), Guid.NewGuid(), new string('b', 64),
            PrincipalClassificationRegistry.Version, ControlEdgeStorage.EngineVersion, permissionKind,
            target, [], [new(0, "512", null)], nullDacl ? "S-1-1-0" : HolderSid, null, nullDacl ? "Everyone" : "Captured holder",
            nullDacl ? "UnexpectedBroadPrincipal" : "UnexpectedNotControlPlane", attribute, definitions,
            new Dictionary<string, IReadOnlyList<string>>(),
            sources.Select(entry => new AttributeWritePermissionScope(entry.Ordinal, "Established", "Original saved scope")).ToArray(), [],
            nullDacl ? "GrantsEveryoneEverything" : "Computed", []);
        return (evidence, Selected(evidence), sources);
    }

    internal static (string Rule, string Attribute, string Guid) Family(AttributeWritePermissionKind kind) => kind switch
    {
        AttributeWritePermissionKind.ResourceBasedConstrainedDelegation => ("SEC-014", AttributeName, AttributeGuid),
        AttributeWritePermissionKind.ServicePrincipalName => ("SEC-024", "servicePrincipalName", "f3a64788-5306-11d1-a9c5-0000f80367c1"),
        AttributeWritePermissionKind.KeyCredentialLink => ("SEC-025", "msDS-KeyCredentialLink", "5b47d60f-6090-40b2-9f37-2a4de88f3063"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    internal static Finding Finding(AttributeWritePermissionEvidence evidence) => new(Family(evidence.PermissionKind).Rule, 1, Severity.High,
        new(FindingSubjectKind.Account, AttributeWriteRules.Key(evidence.HolderSid, evidence.HolderScope)), evidence.Target.ObjectGuid,
        evidence.Target.DistinguishedName, evidence.Target.DomainFqdn!, "user", "Original full proof prose must not be used.",
        EvidenceCompleteness.Complete, evidence) { PrincipalName = evidence.HolderName ?? evidence.HolderSid };
    internal static FindingListItem Selected(AttributeWritePermissionEvidence evidence) =>
        FindingListItem.FromFinding(Finding(evidence)) with { Reference = new(evidence.GenerationId, 17) };

    internal static SavedAttributeWritePermission Project(AttributeWritePermissionEvidence evidence, FindingListItem selected,
        IReadOnlyList<SavedWriteEntrySource> sources, long total, AttributeWritePermissionMark? after = null, AttributeWritePermissionMark? next = null) =>
        Project(JsonSerializer.Serialize(evidence, ProofSerialization.Options), evidence, selected, sources, total, after, next);

    internal static SavedAttributeWritePermission Project(string json, AttributeWritePermissionEvidence evidence, FindingListItem selected,
        IReadOnlyList<SavedWriteEntrySource> sources, long total, AttributeWritePermissionMark? after = null, AttributeWritePermissionMark? next = null)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var description = new JudgementDescription(evidence.EvidenceSeal, evidence.GenerationId, evidence.DerivationGenerationId,
            JudgementRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        return AttributeWritePermissionProjection.Read(stream, selected, description, evidence.DerivationSeal, sources, total, after, next, CancellationToken.None);
    }
}
