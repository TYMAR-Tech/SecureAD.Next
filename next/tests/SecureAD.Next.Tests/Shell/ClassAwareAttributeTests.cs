using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class ClassAwareAttributeTests
{
    private const string Dn = "CN=Alice,DC=contoso,DC=com";
    private static readonly DateTimeOffset CapturedUtc = new(2026, 10, 5, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void FriendlyTitlesKeepTheirExactLdapCaption()
    {
        var row = new AttributeValueViewModel("description", Text("description", "Example"), true, CapturedUtc);
        Assert.Equal("Description", row.Label);
        Assert.Equal(" (description)", row.AttributeCaption);
    }

    [Theory]
    [InlineData("user", false)]
    [InlineData("USER", false)]
    [InlineData("inetOrgPerson", false)]
    [InlineData("msDS-ManagedServiceAccount", false)]
    [InlineData("msDS-GroupManagedServiceAccount", false)]
    [InlineData("computer", true)]
    [InlineData("CoMpUtEr", true)]
    public void AccountFieldsFollowCapturedClassRatherThanMissingValues(string objectClass, bool hasOs)
    {
        var definition = Definition(objectClass, ObjectSectionCatalog.Overview);
        var captured = Data(objectClass);
        var empty = Assert.IsType<AccountSectionViewModel>(new OverviewSectionViewModel(definition,
            Judgement.ControlEdgeDeriverTests.Permissions(), captured, objectClass).Account);
        var populated = Assert.IsType<AccountSectionViewModel>(new OverviewSectionViewModel(definition,
            Judgement.ControlEdgeDeriverTests.Permissions(), Data(objectClass,
                Text("operatingSystem", "Example OS"), Text("operatingSystemVersion", "10.0")), objectClass).Account);
        string[] common = ["userAccountControl", "adminCount", "pwdLastSet", "accountExpires", "lastLogonTimestamp", "primaryGroupID"];
        var expected = hasOs ? [.. common, "operatingSystem", "operatingSystemVersion"] : common;

        Assert.Equal(expected, empty.Values.Select(row => row.Attribute));
        Assert.Equal(expected, populated.Values.Select(row => row.Attribute));
        Assert.All(empty.Values, row => Assert.Equal("No captured value", row.Worded));
        var unread = Assert.IsType<AccountSectionViewModel>(new OverviewSectionViewModel(definition,
            Judgement.ControlEdgeDeriverTests.Permissions(), null, objectClass).Account);
        Assert.All(unread.Values, row => Assert.Equal("Not read", row.Worded));
    }

    [Fact]
    public void OtherValuesPreserveUnclaimedDataAndOriginalValueOrder()
    {
        var captured = Data("user",
            Text("SAMACCOUNTNAME", "alice"),
            Text("DISTINGUISHEDNAME", Dn),
            Text("OPERATINGSYSTEM", "Example OS"),
            Text("operatingSystemVersion", "10.0"),
            Text("managedBy", "CN=First,DC=contoso,DC=com", "CN=First,DC=contoso,DC=com", "CN=Second,DC=contoso,DC=com"),
            Text("dNSHostName", "example.contoso.com"),
            Text("dSHeuristics", "000000000100000f"),
            Text("objectCategory", "CN=Person,CN=Schema,CN=Configuration,DC=contoso,DC=com"),
            new("customBinary", AttributeCardinality.SingleValued, [new(0, null, [1, 2, 160])]),
            Text("capturedEmptyString", ""),
            Text("noValues"));
        var other = Other("user", captured);

        Assert.Equal(new[] { "OPERATINGSYSTEM", "operatingSystemVersion", "managedBy", "dNSHostName",
            "dSHeuristics", "objectCategory", "customBinary", "capturedEmptyString" }, other.Values.Select(row => row.Attribute));
        Assert.All(other.Values, row =>
        {
            Assert.Equal(row.Attribute, row.Label);
            Assert.Equal("", row.AttributeCaption);
        });
        Assert.Equal("CN=First,DC=contoso,DC=com, CN=First,DC=contoso,DC=com, CN=Second,DC=contoso,DC=com",
            other.Values.Single(row => row.Attribute == "managedBy").Stored);
        Assert.Equal("0102A0", other.Values.Single(row => row.Attribute == "customBinary").Stored);
        Assert.Equal("", other.Values.Single(row => row.Attribute == "capturedEmptyString").Stored);
        Assert.Null(other.Emptiness);
        Assert.Contains("does not establish the security owner", other.Values.Single(row => row.Attribute == "managedBy").Caveat);
        Assert.Contains("No interpretation", other.Values.Single(row => row.Attribute == "dSHeuristics").Caveat);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("customDirectoryClass")]
    public void UnknownClassesRetainPopulatedValuesWithoutGuessingTheirApplicability(string? objectClass)
    {
        var other = Other(objectClass, Data(objectClass, Text("operatingSystem", "Unexpected value"), Text("customValue", "kept")));
        Assert.Equal(new[] { "operatingSystem", "customValue" }, other.Values.Select(row => row.Attribute));
    }

    [Theory]
    [InlineData(true, "No additional captured values")]
    [InlineData(false, "Not read")]
    public void OtherValuesKeepEmptyAndUnreadStatesDistinct(bool wasRead, string title)
    {
        var other = Other("user", wasRead ? Data("user", Text("sAMAccountName", "alice"), Text("empty")) : null);
        Assert.Empty(other.Values);
        Assert.False(other.HasAnyValue);
        Assert.True(other.HasEmptiness);
        Assert.Equal(title, other.Emptiness!.Title);
    }

    [Fact]
    public void MissingValueExplanationDoesNotReplaceUnreadOrExistingTimeCaveats() => OnSta(() =>
    {
        var missing = new AttributeValueViewModel("adminCount", null, true, CapturedUtc);
        var unread = new AttributeValueViewModel("adminCount", null, false, CapturedUtc);
        var present = new AttributeValueViewModel("adminCount", Text("adminCount", "1"), true, CapturedUtc);
        Assert.Equal("The attribute may be unset or unavailable to the capture account.", missing.Caveat);
        Assert.Null(unread.Caveat);
        Assert.Null(present.Caveat);
        var (host, presenter, template) = AssetCardViewTests.Present(missing);
        Layout(host, 420, 300);
        var caveat = Assert.IsType<TextBlock>(template.FindName("AttributeCaveat", presenter));
        Assert.Equal(missing.Caveat, caveat.Text);
        Assert.Equal(Visibility.Visible, Assert.IsType<Border>(caveat.Parent).Visibility);
        Assert.Equal("No captured value", Assert.IsType<TextBox>(template.FindName("AttributeValue", presenter)).Text);
    });

    [Theory]
    [InlineData(420)]
    [InlineData(1200)]
    public void OtherValuesTemplateShowsLdapNamesCopyableValuesAndQualifications(int width) => OnSta(() =>
    {
        var other = Other("computer", Data("computer",
            Text("dNSHostName", "lab-dc01.contoso.example"),
            Text("managedBy", "CN=Server Operations,OU=Groups,DC=contoso,DC=example")));
        var (host, _, _) = AssetCardViewTests.Present(other);
        Layout(host, width, 320);
        var titles = Descendants<TextBlock>(host).Where(text => text.Name == "AttributeTitle")
            .Select(text => new TextRange(text.ContentStart, text.ContentEnd).Text).ToArray();
        Assert.Equal(new[] { "dNSHostName", "managedBy" }, titles);
        var values = Descendants<TextBox>(host).Where(text => text.Name == "AttributeValue").ToArray();
        Assert.Equal(other.Values.Select(row => row.Worded), values.Select(text => text.Text));
        Assert.All(values, value =>
        {
            Assert.True(value.IsReadOnly);
            value.SelectAll();
            Assert.Equal(value.Text, value.SelectedText);
        });
        Assert.Contains(Descendants<TextBlock>(host), text => text.Name == "AttributeCaveat" &&
            text.Text.Contains("does not establish the security owner", StringComparison.Ordinal));
    });

    [Theory]
    [InlineData(true, "No additional captured values")]
    [InlineData(false, "Not read")]
    public void OtherValuesTemplateDisplaysItsEmptyOrUnreadState(bool wasRead, string title) => OnSta(() =>
    {
        var (host, _, _) = AssetCardViewTests.Present(Other("user", wasRead ? Data("user") : null));
        Layout(host, 650, 300);
        Assert.Contains(Descendants<TextBlock>(host), text => text.Text == title && text.ActualHeight > 0);
        Assert.DoesNotContain(Descendants<Border>(host), border => border.Name == "AttributeCardSurface");
    });

    [Fact]
    public void SelectedOtherValuesUseCapturedClassAndProtectedObjectLifetime()
    {
        var (screen, source) = ObjectNavigationTests.Model();
        source.Attributes = Data("user", Text("operatingSystem", "Unexpected OS"), Text("managedBy", "CN=Contact,DC=contoso,DC=com"));
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions(Dn);
        screen.OpenObject(new(new(Dn, "Alice", Guid.NewGuid(), "computer", "DC=contoso,DC=com")));
        var overview = Assert.IsType<OverviewSectionViewModel>(screen.Opened!.Content);
        Assert.DoesNotContain(Assert.IsType<AccountSectionViewModel>(overview.Account).Values,
            row => row.Attribute == "operatingSystem");
        Assert.IsType<UnloadedObjectSectionViewModel>(screen.Opened!.Section(ObjectSectionCatalog.OtherValues));
        source.Reads.Clear();
        screen.Opened.Show(ObjectSectionCatalog.OtherValues);
        var other = Assert.IsType<OtherValuesSectionViewModel>(screen.Opened.Content);
        Assert.Equal(new[] { "operatingSystem", "managedBy" }, other.Values.Select(row => row.Attribute));
        Assert.Equal(new[] { "Attributes" }, source.Reads);
        source.IsCurrent = false;
        screen.Opened.Show(ObjectSectionCatalog.Overview);
        Assert.True(screen.Opened.HasRefusal);
        Assert.Null(screen.Opened.Content);
    }

    private static ObjectSectionDefinition Definition(string? objectClass, string key) =>
        ObjectSectionCatalog.For(objectClass).Single(section => section.Key == key);

    private static OtherValuesSectionViewModel Other(string? objectClass, ObjectAttributes? data) =>
        new(Definition(objectClass, ObjectSectionCatalog.OtherValues), data, objectClass);

    private static ObjectAttributes Data(string? objectClass, params ObjectAttribute[] values) =>
        new(Dn, Guid.Parse("3f08c7d4-221e-4c7c-86bd-2be97a2e8d14"), CapturedUtc, EvidenceCompleteness.Complete,
            [Text("objectClass", objectClass is null ? [] : [objectClass]), .. values], "contoso.com");

    private static ObjectAttribute Text(string name, params string[] values) =>
        new(name, AttributeCardinality.MultiValued, [.. values.Select((value, ordinal) => new AttributeValue(ordinal, value, null))]);
}
