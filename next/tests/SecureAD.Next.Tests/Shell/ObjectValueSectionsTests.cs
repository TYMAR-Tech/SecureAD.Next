using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The two sections that read what an object is: Overview and Account.
/// </summary>
/// <remarks>
/// The subject throughout is what the screen says when there is nothing to say. An attribute with
/// no value, an object whose values were never read, and a value this build cannot interpret are
/// three different statements, and a section that rendered them alike would be telling an operator
/// something nobody knows.
/// </remarks>
public sealed class ObjectValueSectionsTests
{
    private const string DomainDn = "DC=contoso,DC=com";
    private const string AliceDn = "CN=Alice," + DomainDn;
    private const string AdminsDn = "CN=Domain Admins," + DomainDn;
    private const string AliceSid = "S-1-5-21-1111111111-2222222222-3333333333-1104";

    // ---------------------------------------------------------------------------------------
    // A row
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ACapturedValueIsShownAsTheDirectorySentIt()
    {
        var overview = Overview(Text("sAMAccountName", "alice"));

        Assert.Equal("alice", Row(overview.Values, "sAMAccountName").Worded);
    }

    /// <summary>
    /// The label is prose, and the attribute's own name is beside it: an operator checking this
    /// product against ldp.exe needs the name the directory uses.
    /// </summary>
    [Fact]
    public void ARowCarriesBothTheLabelAndTheAttributeName()
    {
        var row = Row(Overview().Values, "sAMAccountName");

        Assert.Equal("Account name", row.Label);
        Assert.Equal("sAMAccountName", row.Attribute);
    }

    /// <summary>
    /// A section shows every attribute it is answerable for, in the order it claims them, whether
    /// or not a value arrived. Choosing rows by what arrived would hide the ones that did not.
    /// </summary>
    [Fact]
    public void EveryAttributeTheSectionClaimsGetsARow()
    {
        var overview = Overview();

        Assert.Equal(
            [
                "objectClass",
                "objectGUID",
                "objectSid",
                "sAMAccountName",
                "userPrincipalName",
                "description",
                "whenCreated",
                "sIDHistory",
            ],
            overview.Values.Select(v => v.Attribute));
    }

    /// <summary>
    /// The distinguished name is the object's heading rather than a row of its overview. Showing it
    /// twice on one screen reads as two facts, and it is the fact every section depends on.
    /// </summary>
    [Fact]
    public void TheDistinguishedNameIsNotRepeatedAsARow()
    {
        Assert.DoesNotContain(
            Overview().Values,
            v => string.Equals(
                v.Attribute, "distinguishedName", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// An absent attribute is a statement about the bundle, never about the object: Active
    /// Directory omits an attribute it will not disclose exactly as it omits one that is not there.
    /// </summary>
    [Fact]
    public void AnAttributeWithNoValueSaysSoAboutTheBundleAndNotTheObject()
    {
        var row = Row(Overview().Values, "sAMAccountName");

        Assert.False(row.HasValue);
        Assert.Equal(AttributeValueViewModel.NothingStored, row.Worded);
    }

    /// <summary>
    /// An object whose values were never read is the fourth silence, and it is not the same
    /// statement as an attribute the bundle holds nothing for.
    /// </summary>
    [Fact]
    public void AnObjectWhoseValuesWereNotReadSaysThatInstead()
    {
        var overview = new OverviewSectionViewModel(
            Definition(ObjectSectionCatalog.Overview), Permissions(), null, "User");

        Assert.Equal(
            AttributeValueViewModel.NothingRead,
            Row(overview.Values, "sAMAccountName").Worded);
    }

    // ---------------------------------------------------------------------------------------
    // Bytes
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A SID is bytes on the wire and text everywhere a person deals with it, including the
    /// permission list on the next section of the same screen.
    /// </summary>
    [Fact]
    public void ASidIsShownAsASidRatherThanAsBytes()
    {
        var overview = Overview(Bytes("objectSid", Sid.ToBytes(AliceSid)!));

        Assert.Equal(AliceSid, Row(overview.Values, "objectSid").Worded);
    }

    /// <summary>
    /// The stored form stays within reach of the worded one, because a wrong reading does not look
    /// wrong.
    /// </summary>
    [Fact]
    public void AnInterpretedValueKeepsTheStoredFormBesideIt()
    {
        var bytes = Sid.ToBytes(AliceSid)!;

        var row = Row(Overview(Bytes("objectSid", bytes)).Values, "objectSid");

        Assert.True(row.IsInterpreted);
        Assert.Equal(Convert.ToHexString(bytes), row.Stored);
    }

    /// <summary>
    /// Bytes that are not a SID are shown as they were stored. Reading them as one would put a
    /// principal on screen that the directory does not hold.
    /// </summary>
    [Fact]
    public void BytesThatAreNotASidAreShownAsStored()
    {
        var row = Row(Overview(Bytes("objectSid", [0x01, 0x02, 0xAB])).Values, "objectSid");

        Assert.Equal("0102AB", row.Worded);
    }

    /// <summary>
    /// A value shown as it was stored has nothing to reveal, and revealing it twice would suggest
    /// this build had done something to it.
    /// </summary>
    [Fact]
    public void AValueThatWasNotInterpretedSaysThereIsNothingToReveal()
    {
        var overview = Overview(Text("sAMAccountName", "alice"));

        Assert.False(Row(overview.Values, "sAMAccountName").IsInterpreted);
    }

    [Fact]
    public void AMultiValuedAttributeShowsEveryValue()
    {
        var overview = Overview(Text("objectClass", "top", "person", "user"));

        Assert.Equal("top, person, user", Row(overview.Values, "objectClass").Worded);
    }

    // ---------------------------------------------------------------------------------------
    // The account state
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void TheAccountStateIsWordedFromTheValueTheDirectorySent()
    {
        var account = Account(Text("userAccountControl", "514"));

        Assert.Equal(
            ["The account is disabled.", "This is a typical user account."],
            account.Flags);
    }

    /// <summary>
    /// The number the sentences were read from stays on screen. It is the only thing that makes a
    /// wrong reading detectable.
    /// </summary>
    [Fact]
    public void TheAccountStateKeepsTheNumberItWasReadFrom()
    {
        var account = Account(Text("userAccountControl", "514"));

        Assert.Equal("514", Row(account.Values, "userAccountControl").Stored);
    }

    [Fact]
    public void AWordedAccountStateHasNothingToExplain()
    {
        Assert.Null(Account(Text("userAccountControl", "514")).Emptiness);
    }

    /// <summary>
    /// A bit this build has no word for is named. A list of flags that looks complete and is not is
    /// worse than no list at all.
    /// </summary>
    [Fact]
    public void ABitWithNoWordingIsNamedOnScreen()
    {
        var account = Account(Text("userAccountControl", "16896"));

        Assert.Equal("0x00004000", account.UnwordedBits);
    }

    [Fact]
    public void AnAccountStateWhoseBitsAreAllWordedNamesNone()
    {
        Assert.False(Account(Text("userAccountControl", "514")).HasUnwordedBits);
    }

    // ---------------------------------------------------------------------------------------
    // The four silences
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnAccountWithNoCapturedStateSaysTheAttributeIsNotInTheBundle()
    {
        var account = Account();

        Assert.False(account.HasFlags);
        Assert.Equal("The account state was not captured", account.Emptiness!.Title);
    }

    [Fact]
    public void AnObjectWhoseValuesWereNotReadSaysTheStateWasNotRead()
    {
        var account = new AccountSectionViewModel(Definition(ObjectSectionCatalog.Account), null);

        Assert.Equal("The account state was not read", account.Emptiness!.Title);
    }

    /// <summary>
    /// A value this build cannot read is shown as stored rather than worded into something it may
    /// not mean.
    /// </summary>
    [Fact]
    public void AnAccountStateThatIsNotANumberIsNotWordedIntoAnything()
    {
        var account = Account(Text("userAccountControl", "NORMAL_ACCOUNT"));

        Assert.False(account.HasFlags);
        Assert.Equal("The account state could not be read", account.Emptiness!.Title);
    }

    /// <summary>
    /// Zero is a real answer and the only one of the four that is a fact about the account.
    /// </summary>
    [Fact]
    public void AnAccountStateOfZeroIsSaidToBeTheAccountsOwnDoing()
    {
        var account = Account(Text("userAccountControl", "0"));

        Assert.Equal("This account sets no state flags", account.Emptiness!.Title);
    }

    // ---------------------------------------------------------------------------------------

    // ---------------------------------------------------------------------------------------
    // The sections that are their attributes
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ASectionBuiltFromAttributesShowsTheOnesItClaims()
    {
        var membership = Section(ObjectSectionCatalog.Membership, Text("memberOf", AdminsDn));

        Assert.Equal(
            ["memberOf", "member", "primaryGroupID"],
            membership.Values.Select(v => v.Attribute));
    }

    [Fact]
    public void ASectionWithAValueHasNothingToExplain()
    {
        var membership = Section(ObjectSectionCatalog.Membership, Text("memberOf", AdminsDn));

        Assert.True(membership.HasAnyValue);
        Assert.Null(membership.Emptiness);
    }

    /// <summary>
    /// A section that shows nothing says which silence it is, and says it about the bundle. The
    /// object may hold these values and the run may have been refused them, and the directory does
    /// not tell those apart.
    /// </summary>
    [Fact]
    public void ASectionWithNoValuesSaysSoAboutTheBundle()
    {
        var membership = Section(ObjectSectionCatalog.Membership);

        Assert.False(membership.HasAnyValue);
        Assert.Equal("This bundle holds none of these values", membership.Emptiness!.Title);
    }

    [Fact]
    public void ASectionOnAnObjectWhoseValuesWereNotReadSaysThatInstead()
    {
        var membership = new AttributeSectionViewModel(
            Definition(ObjectSectionCatalog.Membership), null);

        Assert.Equal("These values were not read", membership.Emptiness!.Title);
    }

    // ---------------------------------------------------------------------------------------
    // A group's type
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The scope and whether the group can hold permissions at all, from a value that is stored
    /// negative.
    /// </summary>
    [Fact]
    public void AGroupTypeIsWordedRatherThanShownAsANumber()
    {
        var group = Section(ObjectSectionCatalog.Group, Text("groupType", "-2147483646"));

        Assert.Equal("Global security group", Row(group.Values, "groupType").Worded);
    }

    [Fact]
    public void AGroupTypeKeepsTheNumberItWasReadFrom()
    {
        var group = Section(ObjectSectionCatalog.Group, Text("groupType", "-2147483646"));

        Assert.Equal("-2147483646", Row(group.Values, "groupType").Stored);
    }

    // ---------------------------------------------------------------------------------------
    // A security descriptor is not shown as bytes
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Several hundred bytes of hexadecimal in a field row tells a reader nothing and buries the
    /// rest of the section. The row says what the value is instead.
    /// </summary>
    [Fact]
    public void ASecurityDescriptorIsNotPrintedAsHexadecimal()
    {
        var readers = Section(
            ObjectSectionCatalog.PasswordReaders,
            Bytes("msDS-GroupMSAMembership", [1, 2, 3, 4, 5]));

        var row = Row(readers.Values, "msDS-GroupMSAMembership");

        Assert.Equal(AttributeValueViewModel.DescriptorNotRead, row.Worded);
    }

    /// <summary>
    /// The size is the one legible thing about it: an unusually large descriptor is an object with
    /// an unusually long access list.
    /// </summary>
    [Fact]
    public void ASecurityDescriptorShowsItsSize()
    {
        var readers = Section(
            ObjectSectionCatalog.PasswordReaders,
            Bytes("msDS-GroupMSAMembership", [1, 2, 3, 4, 5]));

        Assert.Equal("5 bytes", Row(readers.Values, "msDS-GroupMSAMembership").Stored);
    }

    // ---------------------------------------------------------------------------------------

    private static AttributeSectionViewModel Section(
        string key, params ObjectAttribute[] attributes) =>
        new(Definition(key), Attributes(attributes));

    private static AttributeValueViewModel Row(
        IReadOnlyList<AttributeValueViewModel> values, string attribute) =>
        values.Single(v =>
            string.Equals(v.Attribute, attribute, StringComparison.OrdinalIgnoreCase));

    private static OverviewSectionViewModel Overview(params ObjectAttribute[] attributes) =>
        new(
            Definition(ObjectSectionCatalog.Overview),
            Permissions(),
            Attributes(attributes),
            "User");

    // ---------------------------------------------------------------------------------------
    // What qualifies the owner's control
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An object carrying an <c>OWNER RIGHTS</c> entry says so beside its owner.
    /// </summary>
    /// <remarks>
    /// The entry is written with an empty access mask because that is what a real one looks like:
    /// on 2026-08-20 an administrator added one to <c>OU=test01</c> in the lab with every
    /// permission unticked, and the directory stored <c>access_mask=0</c>. Active Directory Users
    /// and Computers then stopped displaying it, while the directory continued to honour it.
    /// </remarks>
    [Fact]
    public void WhenAnOwnerRightsEntryIsPresent_ThenTheOverviewSaysWhatQualifiesTheOwner()
    {
        var overview = new OverviewSectionViewModel(
            Definition(ObjectSectionCatalog.Overview),
            PermissionsWithOwnerRights(),
            null,
            "organizationalUnit");

        Assert.NotNull(overview.OwnerQualification);
        Assert.Contains("OWNER RIGHTS", overview.OwnerQualification, StringComparison.Ordinal);
        Assert.True(overview.HasOwnerQualification);
    }

    /// <summary>
    /// The ordinary object says nothing, rather than showing an empty line where an assurance
    /// would go.
    /// </summary>
    [Fact]
    public void WhenNoOwnerRightsEntryIsPresent_ThenTheOverviewSaysNothingAboutIt()
    {
        Assert.Null(Overview().OwnerQualification);
        Assert.False(Overview().HasOwnerQualification);
    }

    private static ObjectPermissions PermissionsWithOwnerRights() => new(
        AliceDn,
        DescriptorAvailability.Read,
        UnreadableReason: null,
        Owner: null,
        DaclState.Present,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        [OwnerRightsEntry()],
        []);

    private static PermissionEntry OwnerRightsEntry() => new(
        Ordinal: 0,
        AceType: "AccessAllowed",
        Trustee: new PermissionTrustee(
            "S-1-3-4",
            "Owner Rights",
            DistinguishedName: null,
            DomainFqdn: null,
            UnresolvedReason: null,
            WellKnownSidRole.OwnerRightsQualifier,
            "Represents the object's current owner."),
        AccessMask: 0,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        HasObjectType: false,
        HasInheritedObjectType: false,
        ApplicationData: []);

    private static AccountSectionViewModel Account(params ObjectAttribute[] attributes) =>
        new(Definition(ObjectSectionCatalog.Account), Attributes(attributes));

    /// <summary>The catalogue's own definition, so a test cannot invent a section.</summary>
    private static ObjectSectionDefinition Definition(string key) =>
        ObjectSectionCatalog.For("group").Concat(ObjectSectionCatalog.For("computer"))
            .Concat(ObjectSectionCatalog.For("msDS-GroupManagedServiceAccount"))
            .Concat(ObjectSectionCatalog.For("organizationalUnit"))
            .Concat(ObjectSectionCatalog.For("groupPolicyContainer"))
            .Concat(ObjectSectionCatalog.For("user"))
            .First(s => s.Key == key);

    private static ObjectAttributes Attributes(params ObjectAttribute[] attributes) =>
        new(AliceDn, Captured, EvidenceCompleteness.Complete, attributes);

    /// <summary>When the run read the object. Ages on screen are measured from here.</summary>
    private static readonly DateTimeOffset Captured =
        new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);

    private static ObjectAttribute Text(string ldapDisplayName, params string[] values) =>
        new(
            ldapDisplayName,
            AttributeCardinality.MultiValued,
            [.. values.Select((v, i) => new AttributeValue(i, v, null))]);

    private static ObjectAttribute Bytes(string ldapDisplayName, byte[] value) =>
        new(
            ldapDisplayName,
            AttributeCardinality.SingleValued,
            [new AttributeValue(0, null, value)]);

    private static ObjectPermissions Permissions() => new(
        AliceDn,
        DescriptorAvailability.Read,
        UnreadableReason: null,
        Owner: null,
        DaclState.Present,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        [],
        []);
}
