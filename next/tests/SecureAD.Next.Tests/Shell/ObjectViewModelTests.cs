using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// Opening an object from the listing, and what its permissions say once it is open.
/// </summary>
public sealed class ObjectViewModelTests
{
    private const string BundlePath = @"C:\runs\contoso-2026-08-18";
    private const string DomainDn = "DC=contoso,DC=com";
    private const string AliceDn = "CN=Alice," + DomainDn;
    private const string AdminsSid = "S-1-5-21-1111111111-2222222222-3333333333-512";
    private const string OrphanSid = "S-1-5-21-1111111111-2222222222-3333333333-25601";

    // ---------------------------------------------------------------------------------------
    // Opening and coming back
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void TheListingShowsUntilAnObjectIsOpened()
    {
        var screen = Listing();

        Assert.True(screen.ShowsListing);
        Assert.False(screen.HasOpenObject);
    }

    [Fact]
    public void OpeningAnObjectReplacesTheListing()
    {
        var screen = Opened(Permissions());

        Assert.True(screen.HasOpenObject);
        Assert.False(screen.ShowsListing);
    }

    /// <summary>
    /// An operator reading one object's permissions is still somewhere in the directory, and needs
    /// to get back to where they were.
    /// </summary>
    [Fact]
    public void ClosingAnObjectReturnsToTheListing()
    {
        var screen = Opened(Permissions());

        screen.CloseObjectCommand.Execute(null);

        Assert.True(screen.ShowsListing);
    }

    /// <summary>
    /// A new listing answers a different question. Leaving the object up would show one container's
    /// object over another container's list.
    /// </summary>
    [Fact]
    public void ChangingTheLevelClosesTheObjectThatWasOpen()
    {
        var screen = Opened(Permissions());

        screen.ShowsEverythingBeneath = true;

        Assert.False(screen.HasOpenObject);
    }

    [Fact]
    public void AnObjectOpensOnItsOverviewRatherThanOnItsPermissions()
    {
        var screen = Opened(Permissions());

        Assert.Equal(ObjectSectionCatalog.Overview, screen.Opened!.Selected!.Key);
    }

    /// <summary>
    /// A listing and an evidence file that disagree is a fault worth stating, not an object with
    /// no permissions.
    /// </summary>
    [Fact]
    public void AnObjectTheEvidenceDoesNotHoldIsRefusedRatherThanShownEmpty()
    {
        var screen = Listing(permissions: null);

        screen.OpenObjectCommand.Execute(screen.Objects[0]);

        Assert.False(screen.HasOpenObject);
        Assert.True(screen.HasRefusal);
    }

    // ---------------------------------------------------------------------------------------
    // The four silences
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A null DACL grants everyone full control. Rendering it as an empty table would show the most
    /// open object in the forest as the most closed.
    /// </summary>
    [Fact]
    public void ANullPermissionListIsNotShownAsAnEmptyOne()
    {
        var opened = Opened(Permissions(daclState: DaclState.Null)).Permissions();

        Assert.True(opened.IsEmpty);
        Assert.Contains(
            "grants everyone full control", opened.Emptiness!.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyPermissionListSaysItGrantsNobodyAnything()
    {
        var opened = Opened(Permissions(daclState: DaclState.Empty)).Permissions();

        Assert.Contains(
            "grants nobody anything", opened.Emptiness!.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A fifth of a production domain returned no readable descriptor. Those objects are unknown,
    /// and saying so is the difference between an audit and a reassurance.
    /// </summary>
    [Fact]
    public void AnObjectWhosePermissionsCouldNotBeReadSaysWhy()
    {
        var opened = Opened(new ObjectPermissions(
            AliceDn,
            DescriptorAvailability.Unreadable,
            "The controller refused the attribute.",
            Owner: null,
            DaclState.Unreadable,
            DaclCompleteness.Unknown,
            DaclWasCanonical: false,
            IsDaclProtected: false,
            [],
            [])).Permissions();

        Assert.Contains(
            "The controller refused the attribute.",
            opened.Emptiness!.Detail,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AnObjectWhosePermissionsWereNeverReadSaysThatInstead()
    {
        var opened = Opened(new ObjectPermissions(
            AliceDn,
            DescriptorAvailability.NotAttempted,
            UnreadableReason: null,
            Owner: null,
            DaclState.Unreadable,
            DaclCompleteness.Unknown,
            DaclWasCanonical: false,
            IsDaclProtected: false,
            [],
            [])).Permissions();

        Assert.Equal("The permissions on this object were not read", opened.Emptiness!.Title);
    }

    /// <summary>
    /// The silence is only ever said when there is one. A list with entries in it must not carry a
    /// notice claiming it has none.
    /// </summary>
    [Fact]
    public void AnObjectWithEntriesSaysNothingAboutBeingEmpty()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x000F01FF))).Permissions();

        Assert.Null(opened.Emptiness);
        Assert.False(opened.IsEmpty);
    }

    // ---------------------------------------------------------------------------------------
    // What the list as a whole says
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnObjectRefusingInheritanceSaysSoWhereTheShortListIsSeen()
    {
        var opened = Opened(
            Permissions(Allowing(AdminsSid, 0x00000010)) with { IsDaclProtected = true }).Permissions();

        Assert.Contains(
            opened.Statements, s => s.Title == "This object refuses inheritance");
    }

    /// <summary>
    /// AD works through the whole DACL and will not deny a right already granted earlier in it, so
    /// an allow before a deny keeps the deny from applying. These entries are shown sorted, so
    /// without this an object reads safer than it is.
    /// </summary>
    [Fact]
    public void AListTheDirectoryHoldsInAnotherOrderSaysSo()
    {
        var opened = Opened(
            Permissions(Allowing(AdminsSid, 0x00000010)) with { DaclWasCanonical = false }).Permissions();

        Assert.Contains(
            opened.Statements,
            s => s.Title == "The directory holds these entries in a different order");
    }

    [Fact]
    public void ATruncatedListSaysTheObjectMayGrantMoreThanIsShown()
    {
        var opened = Opened(
            Permissions(Allowing(AdminsSid, 0x00000010)) with
            {
                DaclCompleteness = DaclCompleteness.Incomplete,
            }).Permissions();

        Assert.Contains(opened.Statements, s => s.Title == "This list is not everything");
    }

    /// <summary>
    /// An ordinary list carries no statements at all, so that when one appears it means something.
    /// </summary>
    [Fact]
    public void AnOrdinaryListCarriesNoStatements()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x00000010))).Permissions();

        Assert.False(opened.HasStatements);
    }

    // ---------------------------------------------------------------------------------------
    // Grouped by principal
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The entry table sits beside the principal list, so arriving with nothing selected shows an
    /// empty table next to a full list - which reads as though the first principal holds nothing.
    /// </summary>
    [Fact]
    public void APrincipalIsSelectedOnArrivalSoTheEntryTableIsNotEmptyBesideAFullList()
    {
        var opened = Opened(Permissions(
            Allowing(AdminsSid, 0x000F01FF),
            Allowing(OrphanSid, 0x00000010))).Permissions();

        Assert.Same(opened.Principals[0], opened.SelectedPrincipal);
    }

    /// <summary>
    /// An object nobody has a permission on has no principal to select, and must not be asked to
    /// produce one.
    /// </summary>
    [Fact]
    public void AnObjectWithNoEntriesSelectsNoPrincipal()
    {
        var opened = Opened(Permissions()).Permissions();

        Assert.Null(opened.SelectedPrincipal);
        Assert.False(opened.HasPrincipals);
    }

    [Fact]
    public void EntriesArePutTogetherUnderThePrincipalTheyName()
    {
        var opened = Opened(Permissions(
            Allowing(AdminsSid, 0x00000010),
            Allowing(AdminsSid, 0x00000020),
            Allowing(OrphanSid, 0x00000010))).Permissions();

        Assert.Equal(2, opened.Principals.Count);
        Assert.Equal("2 entries", opened.Principals[0].EntryCount);
    }

    [Fact]
    public void AGroupIsHeadedByThePrincipalsNameWhenThisRunCapturedThem()
    {
        var opened = Opened(Permissions(
            Allowing(AdminsSid, 0x00000010) with
            {
                Trustee = Named(AdminsSid, "Domain Admins"),
            })).Permissions();

        Assert.Equal("Domain Admins", opened.Principals[0].Principal);
        Assert.Equal("contoso.com", opened.Principals[0].Domain);
    }

    /// <summary>
    /// The predecessor's screen showed a bare identifier holding Full Control with no explanation.
    /// The identifier is shown, and so is the reason it has no name.
    /// </summary>
    [Fact]
    public void APrincipalWithNoNameShowsItsIdentifierAndWhyItHasNone()
    {
        var opened = Opened(Permissions(Allowing(OrphanSid, 0x000F01FF))).Permissions();

        Assert.Equal(OrphanSid, opened.Principals[0].Principal);
        Assert.Contains(
            "no longer exists", opened.Principals[0].Unresolved!, StringComparison.Ordinal);
    }

    /// <summary>
    /// A collapsed group is one line, and it has to be worth reading. Naming a few rights and
    /// stopping would let a reader conclude those are all there is, so what is left out is counted.
    /// </summary>
    [Fact]
    public void AGroupSummarisesWhatThePrincipalHoldsAndSaysWhenItIsASummary()
    {
        var opened = Opened(Permissions(
            Allowing(AdminsSid, 0x00000001 | 0x00000002 | 0x00000010 | 0x00000020 | 0x00010000)))
            .Permissions();

        Assert.Contains(
            "and 2 more", opened.Principals[0].RightsSummary, StringComparison.Ordinal);
    }

    [Fact]
    public void APrincipalHoldingEverythingIsSummarisedAsFullControl()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x000F01FF))).Permissions();

        Assert.Equal("Full control", opened.Principals[0].RightsSummary);
    }

    // ---------------------------------------------------------------------------------------
    // The four columns
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnEntryIsShownInTheWordsAnAdministratorReads()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x00080000))).Permissions();

        Assert.Equal("Modify owner", opened.Principals[0].Entries[0].Right);
    }

    /// <summary>
    /// A denial and a grant are opposite facts. Folding an unrecognised type into <i>Allow</i>
    /// would state the opposite of a denial.
    /// </summary>
    [Fact]
    public void ADenialIsShownAsADenial()
    {
        var opened = Opened(Permissions(
            Ace(nameof(AceType.AccessDenied), OrphanSid, 0x00000010))).Permissions();

        Assert.Equal("Deny", opened.Principals[0].Entries[0].Type);
        Assert.True(opened.Principals[0].HasDenials);
    }

    [Fact]
    public void AnEntryTypeThisBuildDoesNotKnowIsShownAsItWasStored()
    {
        var opened = Opened(Permissions(Ace("SomethingNew", OrphanSid, 0x00000010))).Permissions();

        Assert.Equal("SomethingNew", opened.Principals[0].Entries[0].Type);
    }

    [Fact]
    public void AnEntryStatesHowFarItReaches()
    {
        var opened = Opened(Permissions(
            Allowing(AdminsSid, 0x00000010) with { InheritanceFlags = 0x02 })).Permissions();

        Assert.Equal(
            "This object and all descendant objects", opened.Principals[0].Entries[0].Scope);
    }

    [Fact]
    public void AnInheritedEntryStatesThatItCameFromAbove()
    {
        var opened = Opened(Permissions(
            Allowing(AdminsSid, 0x00000010) with { IsInherited = true })).Permissions();

        Assert.Equal("Inherited", opened.Principals[0].Entries[0].Inheritance);
    }

    /// <summary>
    /// A mask carrying bits this build has no word for is not established, because part of what it
    /// grants genuinely is not known here.
    /// </summary>
    [Fact]
    public void AnEntryCarryingRightsThisBuildCannotNameIsNotEstablished()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x00000010 | 0x00000200))).Permissions();

        Assert.Equal(FactState.NotEstablished, opened.Principals[0].Entries[0].State);
    }

    // ---------------------------------------------------------------------------------------
    // The overview
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An owner is not an entry and outranks every entry below it: an owner can rewrite the list.
    /// </summary>
    [Fact]
    public void TheOwnerIsShownOnTheOverview()
    {
        var opened = Opened(
            Permissions(Allowing(AdminsSid, 0x00000010)) with
            {
                Owner = Named(AdminsSid, "Domain Admins"),
            }).Overview();

        Assert.Equal("Domain Admins", opened.Owner);
    }

    [Fact]
    public void AnObjectWithNoRecordedOwnerSaysSoRatherThanShowingNothing()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x00000010))).Overview();

        Assert.Equal("not recorded", opened.Owner);
    }

    /// <summary>
    /// The type comes from the row that was clicked, so a listing and the object opened from it
    /// cannot disagree about what the object is.
    /// </summary>
    [Fact]
    public void TheObjectKeepsTheTypeTheListingShowed()
    {
        var opened = Opened(Permissions(Allowing(AdminsSid, 0x00000010))).Overview();

        Assert.Equal("user", opened.ObjectType);
    }

    // ---------------------------------------------------------------------------------------

    private static AssetsViewModel Opened(ObjectPermissions permissions)
    {
        var screen = Listing(permissions);
        screen.OpenObjectCommand.Execute(screen.Objects[0]);
        return screen;
    }
    private static AssetsViewModel Listing(ObjectPermissions? permissions = null)
    {
        var assets = new FakeAssetSource
        {
            Tree = TreeOfOneDomain(),
            Page = new ObjectPage(
                [new ListedObject(AliceDn, "Alice", Guid.NewGuid(), "user", DomainDn)],
                1,
                true,
                null),
            Permissions = permissions,
        };

        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);
        return screen;
    }

    private static ObjectPermissions Permissions(
        params PermissionEntry[] entries) =>
        Permissions(DaclState.Present, entries);

    private static ObjectPermissions Permissions(
        DaclState daclState, params PermissionEntry[] entries) => new(
        AliceDn,
        DescriptorAvailability.Read,
        UnreadableReason: null,
        Owner: null,
        daclState,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        entries,
        []);

    private static PermissionEntry Allowing(string sid, int mask) =>
        Ace(nameof(AceType.AccessAllowed), sid, mask);

    private static PermissionEntry Ace(string type, string sid, int mask) => new(
        Ordinal: 0,
        type,
        Unnamed(sid),
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        HasObjectType: false,
        HasInheritedObjectType: false,
        ApplicationData: []);

    /// <summary>A principal nothing in the bundle holds, with the run's reason for that.</summary>
    private static PermissionTrustee Unnamed(string sid) => new(
        sid, null, null, null, UnresolvedReferenceReason.OrphanedIdentifier);

    private static PermissionTrustee Named(string sid, string name) =>
        new(sid, name, $"CN={name},{DomainDn}", "contoso.com", null);

    private static DirectoryTree TreeOfOneDomain() => new(
        [
            new TreeNode(
                DomainDn,
                "contoso",
                Guid.Parse("11111111-2222-3333-4444-555555555555"),
                TreeNodeOrigin.Partition,
                []),
        ],
        []);
}

/// <summary>
/// Reaching the two sections this build fills, so a test can say what it is about rather than
/// walking the section list.
/// </summary>
internal static class OpenedObjectSections
{
    /// <summary>The permissions section of the object this screen has open.</summary>
    /// <param name="screen">The assets screen, with an object open.</param>
    public static PermissionsSectionViewModel Permissions(this AssetsViewModel screen) =>
        (PermissionsSectionViewModel)screen.Opened!.Section(ObjectSectionCatalog.Permissions)!;

    /// <summary>The overview section of the object this screen has open.</summary>
    /// <param name="screen">The assets screen, with an object open.</param>
    public static OverviewSectionViewModel Overview(this AssetsViewModel screen) =>
        (OverviewSectionViewModel)screen.Opened!.Section(ObjectSectionCatalog.Overview)!;
}
