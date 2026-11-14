using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.AttributeWritePermissionFamilyReadTests;

namespace SecureAD.Next.Tests.Shell;

[Collection("Finding window resources")]
public sealed class AttributeWritePermissionFamilyDetailTests
{
    public static IEnumerable<object[]> FamilyCases() => Families();
    public static IEnumerable<object[]> InvalidCases() => Kinds.SelectMany(kind => new[] { "context", "entry" }
        .Select(defect => new object[] { kind, defect }));
    public static IEnumerable<object[]> ViewCases() => Kinds.SelectMany(kind => new[] { 900, 1300 }
        .SelectMany(width => new[] { false, true }.Select(nullDacl => new object[] { kind, width, nullDacl })));
    public static IEnumerable<object[]> LifetimeCases() => Kinds.SelectMany(kind => new[] { false, true }
        .Select(expire => new object[] { kind, expire }));

    [Theory]
    [MemberData(nameof(FamilyCases))]
    public void SharedPanelShowsTheSelectedAttributeAndRulesGuidance(AttributeWritePermissionKind kind)
    {
        var (model, source, _) = AttributeWritePermissionDetailTests.Model(2, kind: kind, scope: SavedPropertyWriteScope.Attribute);
        var row = Assert.Single(model.Findings);
        Assert.Empty(source.AttributeWritePermissionReads);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<AttributeWritePermissionViewModel>(details.AttributeWritePermission);
        var family = AttributeWritePermissionReadTests.Family(kind);
        Assert.Equal(family.Rule, details.Finding!.Rule);
        Assert.Equal(family.Attribute, panel.Attribute);
        Assert.Equal("Captured holder", panel.Holder);
        Assert.Equal("Captured target", panel.TargetName);
        Assert.Equal("High", details.Finding.Severity);
        Assert.All(panel.Entries, entry => Assert.Equal(AttributeLabel(kind), entry.PermissionScope));
        Assert.Equal("Deny", panel.Entries[1].EntryType);
        Assert.Equal("Inherited", panel.Entries[1].Assignment);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        var guidance = RuleGuidanceCatalogue.For(family.Rule)!;
        var rules = new RuleRowViewModel(family.Rule, RuleCatalogue.All.Single(rule => rule.Definition.Id == family.Rule).Definition, null);
        Assert.Equal(guidance.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(rules.WhatToDo, details.Finding.WhatToDo);
        Assert.Contains(kind == AttributeWritePermissionKind.ServicePrincipalName
            ? "Validated write to service principal names is a separate permission."
            : "The SELF-only validated computer-account operation is separate.", panel.ScopeNote, StringComparison.Ordinal);
        Assert.Empty(source.AccountSettingReads);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Single(source.AttributeWritePermissionReads);
    }

    [Theory]
    [MemberData(nameof(InvalidCases))]
    public void AnotherRulesContextOrEntryCannotBeShownUnderThisFinding(AttributeWritePermissionKind kind, string defect)
    {
        var (model, source, _) = AttributeWritePermissionDetailTests.Model(1, kind: kind);
        var read = source.AttributeWritePermissionRead!;
        source.AttributeWritePermissionRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedAttributeWritePermission>.Success(defect == "context"
                ? page with { Context = page.Context with { PermissionKind = Other(kind) } }
                : page with { Entries = [page.Entries[0] with { PermissionKind = Other(kind) }] });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Equal(SavedAttributeWritePermission.InvalidDetailsForRule(AttributeWritePermissionReadTests.Family(kind).Rule),
            model.FindingDetails.Refusal);
        Assert.Null(model.FindingDetails.AttributeWritePermission);
        Assert.False(model.FindingDetails.HasFinding);
    }

    [Theory]
    [MemberData(nameof(FamilyCases))]
    public void AnotherRulesContinuationKeepsTheOriginalPageAndAllowsRetry(AttributeWritePermissionKind kind) => OneThread.Run(async () =>
    {
        var (model, source, _) = AttributeWritePermissionDetailTests.Model(51, kind: kind);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.AttributeWritePermission!;
        var original = panel.Entries.ToArray();
        var read = source.AttributeWritePermissionRead!;
        source.AttributeWritePermissionRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedAttributeWritePermission>.Success(page with { Context = page.Context with { PermissionKind = Other(kind) } });
        };
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.True(panel.HasRefusal);
        Assert.Equal("Page 1", panel.PageLabel);
        Assert.Equal(original, panel.Entries);
        source.AttributeWritePermissionRead = read;
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.False(panel.HasRefusal);
        Assert.Equal("Page 2", panel.PageLabel);
        Assert.Equal(50, Assert.Single(panel.Entries).Ordinal);
    });

    [Theory]
    [MemberData(nameof(FamilyCases))]
    public void MainAndObjectFindingsOpenTheSameSavedAttributePermission(AttributeWritePermissionKind kind) => OneThread.Run(async () =>
    {
        var (model, source, _) = AttributeWritePermissionDetailTests.Model(1, kind: kind);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, row.ObjectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        model.CloseFindingDetails();
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(AttributeWritePermissionReadTests.Family(kind).Attribute, model.FindingDetails!.AttributeWritePermission!.Attribute);
        Assert.Equal(row.Saved.Reference, model.FindingDetails.Finding!.Saved.Reference);
        Assert.Equal(2, source.AttributeWritePermissionReads.Count);
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    });

    [Theory]
    [MemberData(nameof(ViewCases))]
    public void RealSharedWindowDisplaysTheSelectedFamilyAtBothWidths(AttributeWritePermissionKind kind, int width, bool nullDacl) =>
        AttributeWritePermissionDetailTests.CheckRealPermissionPanel(width, nullDacl, kind);

    [Theory]
    [MemberData(nameof(LifetimeCases))]
    public void ClosedAndExpiredFamilyPagesCannotPublishLateAnswers(AttributeWritePermissionKind kind, bool expire) =>
        AttributeWritePermissionDetailTests.CheckClosedOrExpiredPermissionPages(expire, kind);
}
