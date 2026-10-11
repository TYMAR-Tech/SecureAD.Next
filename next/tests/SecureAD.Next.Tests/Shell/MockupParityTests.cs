using System.Xml.Linq;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class MockupParityTests
{
    private static readonly string Shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");

    [Fact]
    public void ObjectOverviewUsesTheApprovedTwoPanelGrouping()
    {
        var template = ObjectTemplate("OverviewSectionViewModel");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Text") == "Identity & ownership");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Text") == "Account state & activity");
        Assert.Contains(template.Descendants(), element =>
            (string?)element.Attribute("Text") == "{Binding EntryCount,StringFormat={}{0} captured permission entries}");
    }

    [Fact]
    public void PermissionsKeepBothApprovedLayoutsAndSharedFilters()
    {
        var template = ObjectTemplate("PermissionsSectionViewModel");
        Assert.Equal(new[] { "A - Principal reading pane", "B - Expandable principal groups" },
            template.Descendants().Where(element => element.Name.LocalName == "TabItem")
                .Select(element => (string?)element.Attribute("Header")));
        Assert.Contains(template.Descendants().Attributes(),
            attribute => attribute.Value.Contains("PermissionSearchText", StringComparison.Ordinal));
        Assert.Contains(template.Descendants().Attributes(),
            attribute => attribute.Value.Contains("PermissionTypeChoices", StringComparison.Ordinal));
        Assert.Contains(template.Descendants().Attributes(),
            attribute => attribute.Value.Contains("VisiblePrincipals", StringComparison.Ordinal));
    }

    [Fact]
    public void ControlEdgesUseDirectionAndSelectedDetailTabs()
    {
        var template = ObjectTemplate("ControlEdgesSectionViewModel");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Content") == "{Binding OnObjectQuestion}");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Content") == "{Binding HeldByObjectQuestion}");
        Assert.Equal(new[] { "Evidence", "Requester check", "Membership" },
            template.Descendants().Where(element => element.Name.LocalName == "RadioButton"
                && (string?)element.Attribute("GroupName") == "ControlDetails")
                .Select(element => (string?)element.Attribute("Content")));
        Assert.Contains(template.Descendants().Attributes(),
            attribute => attribute.Value.Contains("EdgeSearchText", StringComparison.Ordinal));
        Assert.DoesNotContain(template.Descendants(),
            element => (string?)element.Attribute("Header") == "How control edges are counted");
        Assert.DoesNotContain(template.Descendants(),
            element => ((string?)element.Attribute("Text"))?.Contains(
                "Principals with supported control", StringComparison.Ordinal) == true);
        Assert.Contains(template.Descendants(),
            element => (string?)element.Attribute("Text") == "Why this control relationship exists");
    }

    [Fact]
    public void ObjectWindowUsesCompactIdentityStrongSelectionAndDedicatedHelp()
    {
        var header = View("ObjectSectionList.xaml");
        Assert.Contains(header.Descendants().Attributes(),
            attribute => attribute.Value == "{Binding Opened.Heading}");
        Assert.Contains(header.Descendants().Attributes(),
            attribute => attribute.Value == "{Binding Opened.DistinguishedName, Mode=OneWay}");
        Assert.DoesNotContain(header.Descendants().Attributes(),
            attribute => attribute.Value.Contains("Opened.Domain", StringComparison.Ordinal)
                || attribute.Value.Contains("Opened.RunContext", StringComparison.Ordinal));
        Assert.Contains(header.Descendants(), element => element.Name.LocalName == "Setter"
            && (string?)element.Attribute("Property") == "Background"
            && (string?)element.Attribute("Value") == "{DynamicResource AccentBrush}");

        var host = View("ObjectView.xaml");
        Assert.DoesNotContain(host.Descendants().Attributes(),
            attribute => attribute.Value.Contains("Opened.Selected.Title", StringComparison.Ordinal));
        Assert.Equal(ObjectSectionCatalog.Help, ObjectSectionCatalog.For("computer")[^1].Key);

        var help = Assert.Single(XDocument.Load(Path.Combine(Shell, "Views", "Sections", "ObjectSectionTemplates.xaml"))
            .Descendants(), element => element.Name.LocalName == "DataTemplate"
                && (string?)element.Attribute("DataType") == "{x:Type vm:ObjectHelpSectionViewModel}");
        Assert.Contains(help.Descendants(),
            element => (string?)element.Attribute("Text") == "What Control edges answers");
        Assert.Contains(help.Descendants(),
            element => (string?)element.Attribute("Header") == "How control relationships are counted");
    }

    [Fact]
    public void ObjectTier0UsesTheApprovedWarningAndRouteCards()
    {
        var template = ObjectTemplate("SavedTier0PathSectionViewModel");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Text") == "Shortest supported distance");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Text") == "Best-supported route");
        Assert.Contains(template.Descendants().Attributes(),
            attribute => attribute.Value == "{DynamicResource FaultSubtleBrush}");
        Assert.Contains(template.Descendants(), element => (string?)element.Attribute("Text") == "Existing assessed results");
    }

    [Fact]
    public void RulesUseTheApprovedResultTableFiltersAndReadingTabs()
    {
        var view = View("RulesView.xaml");
        Assert.DoesNotContain(view.Descendants(),
            element => (string?)element.Attribute("Text") == "Rules and their results");
        Assert.DoesNotContain(view.Descendants().Attributes(),
            attribute => attribute.Value.Contains("RunName", StringComparison.Ordinal)
                || attribute.Value.Contains("BundlePath", StringComparison.Ordinal));
        Assert.Contains(view.Descendants(), element => element.Name.LocalName == "DataGrid"
            && (string?)element.Attribute(XName.Get("Name", "http://schemas.microsoft.com/winfx/2006/xaml")) == "RulesTable");
        Assert.Contains(view.Descendants().Attributes(), attribute => attribute.Value.Contains("RuleSearchText", StringComparison.Ordinal));
        Assert.Contains(view.Descendants().Attributes(), attribute => attribute.Value.Contains("RuleAssessmentChoices", StringComparison.Ordinal));
        Assert.Equal(new[] { "Summary", "Evidence used", "Scope & limitations", "Reference" },
            view.Descendants().Where(element => element.Name.LocalName == "TabItem")
                .Select(element => (string?)element.Attribute("Header")));
    }

    [Fact]
    public void ObjectBrowserDoesNotRepeatItsTabTitleScopeOrTreeToggle()
    {
        var view = View("AssetsView.xaml");
        Assert.DoesNotContain(view.Descendants(), element => (string?)element.Attribute("Text") == "Objects");
        Assert.DoesNotContain(view.Descendants().Attributes(), attribute => attribute.Value == "{Binding ScopeTreeAction}");
        Assert.DoesNotContain(view.Descendants().Attributes(),
            attribute => attribute.Value == "{Binding NavigationLocation,Mode=OneWay}");
        Assert.Contains(view.Descendants().Attributes(), attribute => attribute.Value == "{Binding NavigationLocation}");
    }

    [Fact]
    public void GroupsAndLapsUseTableFirstSelectedItemPanels()
    {
        var groups = View("GroupsView.xaml");
        Assert.DoesNotContain(groups.Descendants(), element => element.Name.LocalName == "GroupSummaryVisibility");
        Assert.Contains(groups.Descendants(), element => (string?)element.Attribute("Content") == "Open object window");
        Assert.Contains(groups.Descendants().Attributes(), attribute => attribute.Value.Contains("SelectedGroup.MembershipDetail", StringComparison.Ordinal));

        var laps = View("LapsInventoryView.xaml");
        Assert.Contains(laps.Descendants(), element => (string?)element.Attribute("Text") == "LAPS coverage");
        Assert.Contains(laps.Descendants().Attributes(), attribute => attribute.Value == "{Binding SelectedLapsComputer,Mode=TwoWay}");
        Assert.Contains(laps.Descendants().Attributes(), attribute => attribute.Value.Contains("LapsSearchText", StringComparison.Ordinal));
        Assert.Contains(laps.Descendants().Attributes(), attribute => attribute.Value.Contains("LapsStateChoices", StringComparison.Ordinal));
        Assert.Contains(laps.Descendants(), element => (string?)element.Attribute("Content") == "Open object window");
    }

    [Fact]
    public void Tier0OverviewUsesRunCardsWarningAndAllIdentitiesView()
    {
        var view = View("Tier0OverviewView.xaml");
        foreach (var binding in new[] { "Tier0ClassifiedCount", "Tier0OtherSupportedCount", "Tier0UnresolvedCount", "Tier0UnassessedCount" })
            Assert.Contains(view.Descendants().Attributes(), attribute => attribute.Value.Contains(binding, StringComparison.Ordinal));
        Assert.Contains(view.Descendants(), element => (string?)element.Attribute("Content") == "All identities");
        Assert.Contains(view.Descendants(), element => (string?)element.Attribute("Header") == "Domain");
    }

    [Fact]
    public void DelegationsUseCompactSearchAndSelectedEvidencePanels()
    {
        var view = View("DelegationsView.xaml");
        Assert.Contains(view.Descendants(), element => (string?)element.Attribute("Content") == "{x:Static vm:DelegationText.EditSearch}");
        Assert.Contains(view.Descendants(), element => (string?)element.Attribute("Header") == "Membership and original evidence");
        Assert.Contains(view.Descendants().Attributes(), attribute => attribute.Value.Contains("DelegationSearchSummary", StringComparison.Ordinal));
        Assert.Contains(view.Descendants().Attributes(), attribute => attribute.Value.Contains("DelegationResultSearch", StringComparison.Ordinal));
    }

    private static XElement ObjectTemplate(string type)
    {
        var document = XDocument.Load(Path.Combine(Shell, "Views", "Sections", "ObjectSectionTemplates.xaml"));
        return Assert.Single(document.Descendants(), element => element.Name.LocalName == "DataTemplate"
            && (string?)element.Attribute("DataType") == "{x:Type vm:" + type + "}");
    }

    private static XDocument View(string name) => XDocument.Load(Path.Combine(Shell, "Views", name));
}
