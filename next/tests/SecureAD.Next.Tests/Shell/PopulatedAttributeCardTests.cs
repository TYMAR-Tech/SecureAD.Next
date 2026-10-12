using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class PopulatedAttributeCardTests
{
    private const string Dn = "CN=Example,DC=contoso,DC=com";

    [Fact]
    public void FilterPreservesAllCapturedOccurrencesIncludingEmptyStringsAndZeroBytes()
    {
        var rows = new[]
        {
            Row("missing", null),
            Row("zero", new("zero", AttributeCardinality.SingleValued, [new(0, "0", null)])),
            Row("emptyString", new("emptyString", AttributeCardinality.SingleValued, [new(0, "", null)])),
            Row("emptyBytes", new("emptyBytes", AttributeCardinality.SingleValued, [new(0, null, [])])),
            Row("multi", new("multi", AttributeCardinality.MultiValued, [new(0, "b", null), new(1, "b", null), new(2, "a", null)])),
            new AttributeValueViewModel("unread", null, false, DateTimeOffset.UnixEpoch),
        };
        var cards = new AttributeCardsViewModel(rows);
        var notifications = new List<string?>();
        cards.PropertyChanged += (_, args) => notifications.Add(args.PropertyName);

        Assert.False(cards.ShowMissingAttributes);
        Assert.True(cards.HasMissingAttributes);
        Assert.Equal(rows.Skip(1), cards.VisibleValues);
        Assert.Equal("b, b, a", cards.VisibleValues[3].Stored);
        cards.ShowMissingAttributes = true;
        Assert.Equal(rows, cards.VisibleValues);
        Assert.Contains(nameof(cards.VisibleValues), notifications);
        cards.ShowMissingAttributes = false;
        Assert.Equal(rows.Skip(1), cards.VisibleValues);
    }

    [Theory]
    [InlineData("Delegation")]
    [InlineData("PolicyLinks")]
    [InlineData("OtherValues")]
    public void EveryCardTemplateUsesTheSharedFilterAndKeepsUnreadEvidence(string key) => OnSta(() =>
    {
        var section = Section(key, wasRead: true);
        var (host, _, _) = AssetCardViewTests.Present(section);
        Layout(host, 850, 800);
        var cards = Cards(section);
        var shown = Descendants<Border>(host).Where(item => item.Name == "AttributeCardSurface").ToArray();
        Assert.Single(shown);
        var toggle = Assert.Single(Descendants<CheckBox>(host), item => Equals(item.Content, "Show missing attributes"));
        Assert.Equal(key != "OtherValues", toggle.Visibility == Visibility.Visible);
        if (key != "OtherValues")
        {
            var outline = Assert.IsType<Border>(toggle.Template.FindName("MissingToggleOutline", toggle));
            Assert.Equal(16, outline.ActualWidth);
            Assert.Equal(1, outline.BorderThickness.Left);
            ((IToggleProvider)new CheckBoxAutomationPeer(toggle).GetPattern(PatternInterface.Toggle)!).Toggle();
            Layout(host, 850, 800);
            Assert.True(cards.ShowMissingAttributes);
            Assert.Equal(2, Descendants<Border>(host).Count(item => item.Name == "AttributeCardSurface"));
            ((IToggleProvider)new CheckBoxAutomationPeer(toggle).GetPattern(PatternInterface.Toggle)!).Toggle();
            Layout(host, 850, 800);
            Assert.Single(Descendants<Border>(host), item => item.Name == "AttributeCardSurface");
        }
        var unread = Section(key, wasRead: false);
        var (unreadHost, _, _) = AssetCardViewTests.Present(unread);
        Layout(unreadHost, 850, 800);
        Assert.False(Cards(unread).HasMissingAttributes);
        if (key == "OtherValues")
            Assert.Contains(Descendants<TextBlock>(unreadHost), text => text.Text == "Not read");
        else
        {
            Assert.Equal(2, Descendants<TextBox>(unreadHost).Count(text => text.Name == "AttributeValue" && text.Text == "Not read"));
            Assert.Equal(2, Cards(unread).VisibleValues.Count);
        }
    });

    [Fact]
    public void AllAttributeCardSurfacesUseTheSharedPresentation()
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var path = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Views", "Sections", "ObjectSectionTemplates.xaml");
        var root = XDocument.Load(path).Root!;
        var shared = Assert.Single(root.Elements(wpf + "DataTemplate"), template => (string?)template.Attribute(xaml + "Key") == "AttributeCards");
        Assert.Single(shared.Descendants(wpf + "ItemsControl"), item => (string?)item.Attribute("ItemsSource") == "{Binding VisibleValues}");
        Assert.DoesNotContain(root.Descendants(wpf + "ItemsControl"), item => (string?)item.Attribute("ItemsSource") == "{Binding Values}");
        var consumers = root.Descendants(wpf + "ContentControl")
            .Where(control => (string?)control.Attribute("ContentTemplate") == "{StaticResource AttributeCards}")
            .Select(control => (string?)control.Ancestors(wpf + "DataTemplate").First().Attribute("DataType")).ToArray();
        Assert.Equal(new[]
        {
            "{x:Type vm:OverviewSectionViewModel}", "{x:Type vm:OverviewSectionViewModel}",
            "{x:Type vm:AttributeSectionViewModel}", "{x:Type vm:PolicyLinksSectionViewModel}",
            "{x:Type vm:OtherValuesSectionViewModel}",
        }, consumers);
    }

    [Fact]
    public void SupportedClassesAndUnknownClassesUseValuesRatherThanSchemaGuesses()
    {
        foreach (var objectClass in CapturedAttributeCatalog.ObjectClasses.Concat(new[] { "customClass" }))
        {
            foreach (var definition in ObjectSectionCatalog.For(objectClass))
            {
                if (definition.Attributes.Count == 0 || definition.Key == ObjectSectionCatalog.Permissions) continue;
                var rows = definition.Rows(new(Dn, Guid.Empty, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete,
                    [new(definition.Attributes[0], AttributeCardinality.SingleValued, [new(0, "present", null)])], "contoso.com"));
                var cards = new AttributeCardsViewModel(rows);
                Assert.Same(rows[0], Assert.Single(cards.VisibleValues));
                cards.ShowMissingAttributes = true;
                Assert.Equal(rows, cards.VisibleValues);
            }
        }
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    public void OptionalUpnIsShownOnlyWhenCapturedAndCanBeRevealedWhenMissing(string objectClass)
    {
        // Microsoft's Computer class explicitly inherits optional User-Principal-Name from User:
        // https://learn.microsoft.com/windows/win32/adschema/c-computer
        var definition = ObjectSectionCatalog.For(objectClass).Single(item => item.Key == ObjectSectionCatalog.Overview);
        var data = new ObjectAttributes(Dn, Guid.Empty, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete, [], "contoso.com");
        var missing = new OverviewSectionViewModel(definition, Judgement.ControlEdgeDeriverTests.Permissions(), data, objectClass);
        Assert.DoesNotContain(missing.IdentityCards.VisibleValues, row => row.Attribute == "userPrincipalName");
        missing.IdentityCards.ShowMissingAttributes = true;
        Assert.Equal("No captured value", Assert.Single(missing.IdentityCards.VisibleValues, row => row.Attribute == "userPrincipalName").Worded);
        var populated = new OverviewSectionViewModel(definition, Judgement.ControlEdgeDeriverTests.Permissions(),
            data with { Attributes = [new("userPrincipalName", AttributeCardinality.SingleValued, [new(0, "example@contoso.com", null)])] }, objectClass);
        Assert.Equal("example@contoso.com", Assert.Single(populated.IdentityCards.VisibleValues).Worded);
    }

    [Fact]
    public void MissingFilterDoesNotChangeSecurityQualificationsOrEmptySectionExplanations() => OnSta(() =>
    {
        var definition = ObjectSectionCatalog.For("user").Single(section => section.Key == ObjectSectionCatalog.Overview);
        var overview = new OverviewSectionViewModel(definition, Judgement.ControlEdgeDeriverTests.Permissions(),
            new(Dn, Guid.Empty, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete, [], "contoso.com"), "user");
        var account = Assert.IsType<AccountSectionViewModel>(overview.Account);
        var before = account.Emptiness;
        var (host, _, _) = AssetCardViewTests.Present(overview);
        Layout(host, 850, 800);
        Assert.DoesNotContain(Descendants<Border>(host), border => border.Name == "AttributeCardSurface");
        Assert.NotNull(before);
        Assert.Contains(Descendants<TextBlock>(host), text => text.Text == before.Detail && text.ActualHeight > 0);
        overview.ActivityCards.ShowMissingAttributes = true;
        Assert.Equal(before, account.Emptiness);
        Assert.False(account.HasFlags);
        overview = new OverviewSectionViewModel(new("Overview", "Overview", ["description"]),
            Judgement.ControlEdgeDeriverTests.Permissions() with
            {
                Entries = [new(0, "AccessAllowed",
                    new("S-1-3-4", "Owner Rights", null, null, null, WellKnownSidRole.OwnerRightsQualifier, ""),
                    0, null, null, false, 0, 0, false, false, [])],
            },
            new(Dn, Guid.Empty, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete, [], "contoso.com"), "user");
        var (ownerHost, _, _) = AssetCardViewTests.Present(overview);
        Layout(ownerHost, 850, 800);
        Assert.Contains(Descendants<TextBlock>(ownerHost), text => text.Text == overview.OwnerQualification && text.ActualHeight > 0);
        Assert.Empty(overview.IdentityCards.VisibleValues);
        overview.IdentityCards.ShowMissingAttributes = true;
        Assert.True(overview.HasOwnerQualification);
        Assert.Single(overview.IdentityCards.VisibleValues);
    });

    [Fact]
    public void TogglingMissingAttributesDoesNotReadOrReviveARefusedSection()
    {
        var (screen, source) = ObjectNavigationTests.Model();
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions();
        source.Attributes = new(Dn, Guid.Empty, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete,
            [new("objectClass", AttributeCardinality.SingleValued, [new(0, "computer", null)])], "contoso.com");
        screen.OpenObject(new(new(Dn, "Example", Guid.Empty, "computer", "DC=contoso,DC=com")));
        var overview = Assert.IsType<OverviewSectionViewModel>(screen.Opened!.Content);
        var account = Assert.IsType<AccountSectionViewModel>(overview.Account);
        source.Reads.Clear();
        overview.ActivityCards.ShowMissingAttributes = true;
        Assert.NotEmpty(overview.ActivityCards.VisibleValues);
        overview.ActivityCards.ShowMissingAttributes = false;
        Assert.Empty(overview.ActivityCards.VisibleValues);
        Assert.Empty(source.Reads);
        screen.Opened.Show(ObjectSectionCatalog.Permissions);
        Assert.IsType<UnloadedObjectSectionViewModel>(screen.Opened.Section(ObjectSectionCatalog.Overview));
        screen.Opened.Show(ObjectSectionCatalog.Overview);
        overview = Assert.IsType<OverviewSectionViewModel>(screen.Opened.Content);
        Assert.False(overview.ActivityCards.ShowMissingAttributes);
        source.IsCurrent = false;
        screen.Opened.Show(ObjectSectionCatalog.Permissions);
        Assert.True(screen.Opened.HasRefusal);
        overview.ActivityCards.ShowMissingAttributes = true;
        Assert.Null(screen.Opened.Content);
    }

    private static AttributeValueViewModel Row(string name, ObjectAttribute? attribute) =>
        new(name, attribute, true, DateTimeOffset.UnixEpoch);

    private static ObjectSectionViewModel Section(string key, bool wasRead, bool empty = false)
    {
        var definition = new ObjectSectionDefinition(key, key, ["description", "userPrincipalName"]);
        ObjectAttributes? data = wasRead ? new(Dn, Guid.Empty, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete,
            empty ? [] : [new("description", AttributeCardinality.SingleValued, [new(0, "Example", null)])], "contoso.com") : null;
        return key switch
        {
            "Overview" => new OverviewSectionViewModel(definition, Judgement.ControlEdgeDeriverTests.Permissions(), data, "user"),
            "Delegation" => new AttributeSectionViewModel(definition, data),
            "PolicyLinks" => new PolicyLinksSectionViewModel(definition, data),
            "OtherValues" => new OtherValuesSectionViewModel(definition,
                data is null ? null : data with { Attributes = [new("custom", AttributeCardinality.SingleValued, [new(0, "Example", null)])] }, "user"),
            _ => throw new ArgumentOutOfRangeException(nameof(key)),
        };
    }

    private static AttributeCardsViewModel Cards(ObjectSectionViewModel section) => section switch
    {
        AttributeSectionViewModel value => value.Cards,
        PolicyLinksSectionViewModel value => value.Cards,
        OtherValuesSectionViewModel value => value.Cards,
        _ => throw new ArgumentOutOfRangeException(nameof(section)),
    };
}
