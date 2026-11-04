using System.Text.Json;
using System.Text.Json.Nodes;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using Xunit;
using static SecureAD.Next.Tests.Judgement.AttributeWritePermissionReadTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class AttributeWritePermissionFamilyReadTests
{
    internal static readonly AttributeWritePermissionKind[] Kinds =
        [AttributeWritePermissionKind.ServicePrincipalName, AttributeWritePermissionKind.KeyCredentialLink];

    public static IEnumerable<object[]> Families() => Kinds.Select(kind => new object[] { kind });
    public static IEnumerable<object[]> PageCases() => Kinds.SelectMany(kind => new[] { 1, 50, 51, 127 }
        .Select(count => new object[] { kind, count }));
    public static IEnumerable<object[]> ScopeCases() => Kinds.SelectMany(kind => new[]
        { SavedPropertyWriteScope.PropertySet, SavedPropertyWriteScope.ObjectClass, SavedPropertyWriteScope.AllProperties }
        .Select(scope => new object[] { kind, scope }));
    public static IEnumerable<object[]> UncapturedCases() => Kinds.SelectMany(kind => new[]
        { SavedPropertyWriteScope.PropertySet, SavedPropertyWriteScope.ObjectClass }.Select(scope => new object[] { kind, scope }));
    public static IEnumerable<object[]> NullDaclCases() => Kinds.SelectMany(kind => new[] { false, true }
        .Select(complete => new object[] { kind, complete }));
    public static IEnumerable<object[]> MisboundCases() => Kinds.SelectMany(kind => new[]
        { "kind", "attribute-name", "attribute-guid", "selected-rule" }.Select(defect => new object[] { kind, defect }));

    [Theory]
    [MemberData(nameof(Families))]
    public void SavedRuleKindAttributeAndOriginalAttributeScopeStayTogether(AttributeWritePermissionKind kind)
    {
        var (evidence, selected, sources) = Fixture(1, SavedPropertyWriteScope.Attribute, permissionKind: kind);
        var page = Project(evidence, selected, sources, 1);
        var family = Family(kind);
        Assert.True(page.Context.Matches(selected));
        Assert.Equal(family.Rule, page.Context.RuleId);
        Assert.Equal(family.Attribute, page.Context.AttributeName);
        Assert.Equal(kind, page.Context.PermissionKind);
        Assert.Equal(kind == AttributeWritePermissionKind.ServicePrincipalName
            ? "The selected finding's saved SPN-write permission details are missing, invalid or inconsistent."
            : "The selected finding's saved key-credential-write permission details are missing, invalid or inconsistent.",
            page.Context.InvalidDetails);
        Assert.Equal(Severity.High, selected.Severity);
        Assert.Equal(HolderSid + ":", selected.Subject.Key);
        var entry = Assert.Single(page.Entries);
        Assert.Equal(kind, entry.PermissionKind);
        Assert.Equal(AttributeLabel(kind), entry.PermissionScope);
        Assert.Equal("Allow", entry.EntryType);
        Assert.Equal("Explicit", entry.Assignment);
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void OtherSchemaMeaningsOfTheSameGuidDoNotReplaceAnAttributeWrite(AttributeWritePermissionKind kind)
    {
        var (evidence, _, sources) = Fixture(1, SavedPropertyWriteScope.Attribute, permissionKind: kind);
        evidence = evidence with { SchemaEntries = [.. evidence.SchemaEntries,
            new(Family(kind).Guid, "Other saved meaning", SchemaGuidKind.ValidatedWrite, SchemaGuidSource.Embedded)] };
        var entry = Assert.Single(Project(evidence, Selected(evidence), sources, 1).Entries);
        Assert.Equal(SavedPropertyWriteScope.Attribute, entry.Scope);
        Assert.Equal(AttributeLabel(kind), entry.PermissionScope);
    }

    [Theory]
    [MemberData(nameof(PageCases))]
    public void EveryOriginalOccurrenceKeepsItsPositionAcrossFamilyPages(AttributeWritePermissionKind kind, int count)
    {
        var (evidence, selected, sources) = Fixture(count, permissionKind: kind);
        var observed = new List<int>();
        AttributeWritePermissionMark? after = null;
        do
        {
            var start = after?.Ordinal ?? -1;
            var entries = sources.Where(entry => entry.Ordinal > start).Take(50).ToArray();
            var next = sources.Count(entry => entry.Ordinal > start) > 50
                ? new AttributeWritePermissionMark(evidence.GenerationId, 17, selected.ObjectGuid, entries[^1].Ordinal)
                : (AttributeWritePermissionMark?)null;
            var page = Project(evidence, selected, entries, count, after, next);
            Assert.Equal(Math.Min(50, count - observed.Count), page.Entries.Count);
            Assert.True(page.Context.Matches(selected));
            Assert.All(page.Entries, entry => Assert.Equal(kind, entry.PermissionKind));
            observed.AddRange(page.Entries.Select(entry => entry.Ordinal));
            after = page.Next;
        } while (after is not null);
        Assert.Equal(Enumerable.Range(0, count), observed);
    }

    [Theory]
    [MemberData(nameof(ScopeCases))]
    public void BroadScopeDenyAndInheritanceAreNotRelabelledAsAnAttributeGrant(
        AttributeWritePermissionKind kind, SavedPropertyWriteScope scope)
    {
        var (evidence, selected, sources) = Fixture(1, scope, permissionKind: kind);
        sources = [sources[0] with { IsDeny = true, IsInherited = true }];
        var entry = Assert.Single(Project(evidence, selected, sources, 1).Entries);
        Assert.Equal(scope, entry.Scope);
        Assert.Equal("Deny", entry.EntryType);
        Assert.Equal("Inherited", entry.Assignment);
        Assert.Equal(scope switch
        {
            SavedPropertyWriteScope.PropertySet => "Property set: Captured property set",
            SavedPropertyWriteScope.ObjectClass => "Object class: user",
            _ => "All properties",
        }, entry.PermissionScope);
        Assert.Contains("not established by this finding", entry.InheritanceNote, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(UncapturedCases))]
    public void EmbeddedScopeNamesAreNotPresentedAsCapturedNames(AttributeWritePermissionKind kind, SavedPropertyWriteScope scope)
    {
        var (evidence, _, sources) = Fixture(1, scope, permissionKind: kind);
        evidence = evidence with { SchemaEntries = evidence.SchemaEntries.Select(entry =>
            entry.Guid == SetGuid ? entry with { Source = SchemaGuidSource.Embedded } : entry).ToArray() };
        var entry = Assert.Single(Project(evidence, Selected(evidence), sources, 1).Entries);
        Assert.Null(entry.ScopeName);
        Assert.Contains("captured name unavailable", entry.PermissionScope, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(MisboundCases))]
    public void SavedKindAndAttributeCannotBeSubstitutedFromAnotherRule(AttributeWritePermissionKind kind, string defect)
    {
        var (evidence, selected, sources) = Fixture(1, permissionKind: kind);
        var other = Family(Other(kind));
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        switch (defect)
        {
            case "kind": json["PermissionKind"] = Other(kind).ToString(); break;
            case "attribute-name": json["Attribute"]!["LdapName"] = other.Attribute; break;
            case "attribute-guid": json["Attribute"]!["Guid"] = other.Guid; break;
            default: selected = selected with { RuleId = other.Rule }; break;
        }
        var error = Assert.Throws<InvalidDataException>(() => Project(json.ToJsonString(), evidence, selected, sources, 1));
        Assert.Equal(SavedAttributeWritePermission.InvalidDetailsForRule(selected.RuleId), error.Message);
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void APageCannotContainAnotherRulesOriginalEntryOrContext(AttributeWritePermissionKind kind)
    {
        var (evidence, selected, sources) = Fixture(1, SavedPropertyWriteScope.Attribute, permissionKind: kind);
        var page = Project(evidence, selected, sources, 1);
        Assert.False((page.Context with { PermissionKind = Other(kind) }).Matches(selected));
        Assert.False((page with { Entries = [page.Entries[0] with { PermissionKind = Other(kind) }] }).IsExpectedPage(-1));
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void UnrequestedSchemaAndDomainCollectionsRemainUnloaded(AttributeWritePermissionKind kind)
    {
        var (evidence, selected, sources) = Fixture(1, permissionKind: kind);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Domains"] = JsonNode.Parse("[{\"Unrequested\":\"" + new string('x', 160_000) + "\"}]");
        json["PropertySetMembers"] = JsonNode.Parse("{\"unrequested\":[\"" + new string('x', 160_000) + "\"]}");
        Assert.Single(Project(json.ToJsonString(), evidence, selected, sources, 1).Entries);
    }

    [Theory]
    [MemberData(nameof(NullDaclCases))]
    public void NullObjectDaclDoesNotInventAKeyOrSpnPermissionEntry(AttributeWritePermissionKind kind, bool complete)
    {
        var (evidence, _, sources) = Fixture(0, nullDacl: true, permissionKind: kind);
        if (!complete) evidence = evidence with { Limitations = ["CaptureIncomplete"] };
        var selected = Selected(evidence);
        var page = Project(evidence, selected, sources, 0);
        Assert.True(page.Context.Matches(selected));
        Assert.True(page.Context.HasNullDacl);
        Assert.Equal(complete, page.Context.EvidenceIsComplete);
        Assert.Empty(page.Entries);
        Assert.Null(page.Next);
        Assert.Equal(kind, page.Context.PermissionKind);
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void UnknownCapturedStateIsNotInventedEnabledState(AttributeWritePermissionKind kind)
    {
        var (evidence, _, sources) = Fixture(1, permissionKind: kind);
        evidence = evidence with { AccountControl = [], Limitations = ["AccountStateUnreadable"] };
        var page = Project(evidence, Selected(evidence), sources, 1);
        Assert.Equal("Not established from captured evidence.", page.Context.AccountState);
        Assert.False(page.Context.EvidenceIsComplete);
        Assert.Single(page.Context.DescribeLimitations());
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void SupportedPermissionRemainsDistinctFromOtherIncompleteEvidence(AttributeWritePermissionKind kind)
    {
        var (evidence, _, sources) = Fixture(1, permissionKind: kind);
        evidence = evidence with { Limitations = ["CaptureIncomplete", "OtherCapturedInput"] };
        var page = Project(evidence, Selected(evidence), sources, 1);
        Assert.Single(page.Entries);
        Assert.False(page.Context.EvidenceIsComplete);
        Assert.Equal(2, page.Context.DescribeLimitations().Count);
        Assert.Contains("supported permission shown here remains a finding", page.Context.DescribeLimitations()[0], StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Families))]
    public void GuidanceDoesNotReplacePermissionRepairWithSpnOrKeyRemoval(AttributeWritePermissionKind kind)
    {
        var guidance = RuleGuidanceCatalogue.For(Family(kind).Rule)!;
        Assert.Contains("It does not show", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("A group-held permission does not establish authorization for each member.", guidance.WhyItMatters, StringComparison.Ordinal);
        Assert.Contains("remove or narrow only that permission on the target account", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.Contains("verify its original source and wider impact", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.Contains(kind == AttributeWritePermissionKind.ServicePrincipalName
            ? "Do not remove legitimate service principal names or reset passwords"
            : "Do not delete existing key credentials or reset passwords", guidance.WhatToDo, StringComparison.Ordinal);
    }

    internal static AttributeWritePermissionKind Other(AttributeWritePermissionKind kind) =>
        kind == AttributeWritePermissionKind.ServicePrincipalName
            ? AttributeWritePermissionKind.KeyCredentialLink : AttributeWritePermissionKind.ServicePrincipalName;

    internal static string AttributeLabel(AttributeWritePermissionKind kind) =>
        kind == AttributeWritePermissionKind.ServicePrincipalName ? "SPN attribute" : "Key-credential-link attribute";
}
