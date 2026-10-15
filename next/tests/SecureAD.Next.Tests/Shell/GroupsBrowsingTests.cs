using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class GroupsBrowsingTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Group = "CN=Administrators,CN=Builtin," + Root;

    [Theory]
    [InlineData(GroupMembershipLimitations.None, "Recorded values")]
    [InlineData(GroupMembershipLimitations.UnresolvedReferences, "Incomplete membership evidence")]
    [InlineData(GroupMembershipLimitations.CaptureIncomplete, "Incomplete membership evidence")]
    public void GroupsSavedTotalsAndLimitationsAreSeparateFromDirectCounts(GroupMembershipLimitations limitation, string text)
    {
        var unresolved = limitation == GroupMembershipLimitations.UnresolvedReferences ? 2 : 0;
        var row = new GroupRowViewModel(new(Guid.NewGuid(), Group, "Administrators", null, "contoso.com",
            -2147483643, 4, 0, false, null, new(17, unresolved, 0, limitation)));
        Assert.Equal("17", row.KnownTotal);
        Assert.Equal(4, row.DirectMembers);
        Assert.Equal(text, row.MembershipData);
        Assert.Equal($"{text}. Unresolved references: {unresolved}; unreadable references: 0.", row.MembershipDetail);
    }

    [Fact]
    public async Task GroupsViewReadsOnlyWhenSelectedAndOpensTheCapturedGroup()
    {
        var (model, source) = Model();
        Assert.Empty(source.GroupQueries);
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        Assert.Single(source.GroupQueries);
        Assert.True(model.ShowsGroupsListing);
        var selected = Assert.Single(model.Groups);
        Assert.Equal("17", selected.KnownTotal);
        model.OpenGroupCommand.Execute(selected);
        await model.ReadCompletion;
        Assert.Equal(Group, model.Opened!.DistinguishedName);
        Assert.Equal(ObjectSectionCatalog.Membership, model.Opened.SelectedKey);
        Assert.True(model.HasOpenObject);
        model.CloseObject();
        Assert.Same(selected, model.SelectedGroup);
        Assert.Single(source.GroupQueries);
        Assert.True(model.ShowsGroupsListing);
    }

    [Fact]
    public async Task GroupsFiltersAndPagingAreRetainedWhenReturningFromObject()
    {
        var (model, source) = Model();
        model.Pane = AssetsPane.Groups;
        model.GroupSearchText = "Administrators";
        model.SearchGroupsCommand.Execute(null);
        await model.ReadCompletion;
        Assert.Equal("Administrators", source.GroupQueries[^1].Query.Search);
        var count = source.GroupQueries.Count;
        model.OpenGroupCommand.Execute(model.SelectedGroup);
        await model.ReadCompletion;
        model.CloseObject();
        Assert.Equal(count, source.GroupQueries.Count);
        Assert.Equal("Administrators", model.GroupSearchText);
    }

    [Fact]
    public async Task GroupsLocationCanWidenExplicitlyWithoutChangingGroupScopeMeaning()
    {
        var (model, source) = Model();
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        Assert.Equal(Root, source.GroupQueries[^1].Query.Container);
        model.BrowseAllGroupsCommand.Execute(null);
        await model.ReadCompletion;
        Assert.Null(source.GroupQueries[^1].Query.Container);
        Assert.True(model.GroupsWholeCapture);
        Assert.False(model.CanChangeBrowsingScope);
        model.GroupScope = GroupInventoryScope.DomainLocal;
        await model.ReadCompletion;
        Assert.Equal(GroupInventoryScope.DomainLocal, source.GroupQueries[^1].Query.GroupScope);
    }

    [Fact]
    public async Task GroupsScopeTreeStartsCompactAndTogglesWithoutChangingTheQuestion()
    {
        var (model, source) = Model();
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        var selected = model.Selected;
        var queries = source.GroupQueries.Count;

        Assert.False(model.ShowsScopeTree);
        Assert.Equal("Show scope tree", model.ScopeTreeAction);

        model.ToggleScopeTreeCommand.Execute(null);

        Assert.True(model.ShowsScopeTree);
        Assert.Equal("Hide scope tree", model.ScopeTreeAction);
        Assert.Same(selected, model.Selected);
        Assert.Equal(queries, source.GroupQueries.Count);
        Assert.Contains(Root, model.GroupLocation, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GroupsCycleButtonUsesItsRowRatherThanAnUnrelatedSelection()
    {
        var (model, source) = Model();
        var other = new GroupInventoryRow(Guid.NewGuid(), "CN=Second," + Root, "Second", "Second",
            "contoso.com", -2147483646, 1, 0, true, null, new(1, 0, 0, GroupMembershipLimitations.None));
        source.GroupPage = source.GroupPage with { Groups = [.. source.GroupPage.Groups, other], Total = 2 };
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        source.Attributes = FakeAssetSource.CapturedObject(other.DistinguishedName, "group");
        model.OpenGroupFindingsCommand.Execute(model.Groups[1]);
        await model.ReadCompletion;
        Assert.Equal(other.DistinguishedName, model.Opened!.DistinguishedName);
        Assert.Equal(ObjectSectionCatalog.Findings, model.Opened.SelectedKey);
    }

    [Fact]
    public async Task GroupsDirectMemberNavigationReturnsThroughTheGroupWithoutLosingTheList()
    {
        var (model, source) = Model();
        var attributes = FakeAssetSource.CapturedObject(Group, "group");
        source.Attributes = attributes with { Attributes = [.. attributes.Attributes,
            new("member", SecureAD.Kernel.Capture.AttributeCardinality.MultiValued,
                [new(0, "CN=Nested," + Root, null)])] };
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        var selected = model.SelectedGroup;
        model.OpenGroupCommand.Execute(selected);
        await model.ReadCompletion;
        var members = Assert.IsType<GroupMembershipSectionViewModel>(model.Opened!.Content);
        Assert.Equal(new[] { "CN=Nested," + Root }, Assert.Single(source.MemberReferenceQueries));
        var row = Assert.Single(members.Members);
        source.Attributes = FakeAssetSource.CapturedObject(row.RecordedName, "group");
        members.OpenMemberCommand.Execute(row);
        await model.ReadCompletion;
        Assert.Equal(row.RecordedName, model.Opened!.DistinguishedName);
        source.Attributes = attributes;
        model.CloseObject();
        await model.ReadCompletion;
        Assert.NotNull(model.Opened);
        Assert.Equal(Group, model.Opened!.DistinguishedName);
        model.CloseObject();
        Assert.Same(selected, model.SelectedGroup);
        Assert.Single(source.GroupQueries);
    }

    [Fact]
    public async Task GroupsUnresolvedMemberIsVisibleButCannotOpen()
    {
        var attributes = FakeAssetSource.CapturedObject(Group, "group") with { Attributes =
            [new("member", SecureAD.Kernel.Capture.AttributeCardinality.MultiValued, [new(0, "CN=Missing," + Root, null)])] };
        var definition = new ObjectSectionDefinition("Membership", "Membership", ["member"]);
        var opens = new List<string>();
        var section = new GroupMembershipSectionViewModel(definition, MembershipReader(attributes,
            (names, _) => Task.FromResult(SecureAD.Kernel.Result<CapturedMemberReferences>.Success(new(
                names.Select(name => new CapturedMemberReference(name, null, null, null, null, null)).ToArray())))),
            opens.Add, () => true);
        await section.ReadCompletion;
        var row = Assert.Single(section.Members);
        Assert.Equal("Unresolved reference", row.Kind);
        Assert.False(section.OpenMemberCommand.CanExecute(row));
        Assert.Empty(opens);
    }

    [Fact]
    public async Task GroupsStaleObjectReturnDoesNotReuseTheOldListing()
    {
        var (model, source) = Model();
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        model.OpenGroupCommand.Execute(model.SelectedGroup);
        await model.ReadCompletion;
        source.IsCurrent = false;
        model.CloseObject();
        await model.ReadCompletion;
        Assert.False(model.HasListingResult);
        Assert.True(model.HasViewRefusal);
    }

    [Fact]
    public async Task GroupsCannotOpenARowFromAnEarlierPage()
    {
        var (model, source) = Model();
        model.Pane = AssetsPane.Groups;
        await model.ReadCompletion;
        var old = model.SelectedGroup;
        source.GroupPage = source.GroupPage with { Groups = [], Total = 0 };
        model.GroupSearchText = "none";
        model.SearchGroupsCommand.Execute(null);
        await model.ReadCompletion;
        Assert.False(model.OpenGroupCommand.CanExecute(old));
        Assert.Null(model.SelectedGroup);
    }

    [Fact]
    public async Task GroupsCancelledLateReadCannotRepopulateAnInactiveView()
    {
        var (model, source) = Model();
        var release = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? result = null;
        source.CompleteRead = (value, _) => { result = value; return release.Task; };
        model.Pane = AssetsPane.Groups;
        var pending = model.ReadCompletion;
        Assert.True(model.IsLoading);
        model.Suspend();
        release.SetResult(result!);
        await pending;
        Assert.Empty(model.Groups);
        Assert.False(model.ShowsGroupsListing);
    }

    [Fact]
    public async Task GroupsMemberListResolvesOnlyTheRequestedPage()
    {
        var attributes = FakeAssetSource.CapturedObject(Group, "group") with { Attributes =
            [new("member", SecureAD.Kernel.Capture.AttributeCardinality.MultiValued,
                Enumerable.Range(0, 123).Select(i => new AttributeValue(i, $"CN=Member{i}," + Root, null)).ToArray())] };
        var calls = new List<IReadOnlyList<string>>();
        var section = new GroupMembershipSectionViewModel(new("Membership", "Membership", ["member"]), MembershipReader(attributes,
            (names, _) =>
            {
                calls.Add(names);
                return Task.FromResult(SecureAD.Kernel.Result<CapturedMemberReferences>.Success(new(
                    names.Select(name => new CapturedMemberReference(name, null, null, null, null, null)).ToArray())));
            }), _ => throw new InvalidOperationException("Unresolved members must not open."), () => true);
        await section.ReadCompletion;
        Assert.Equal(50, Assert.Single(calls).Count);
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal("CN=Member50," + Root, calls[1][0]);
        Assert.Equal(50, calls[1].Count);
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal(23, calls[2].Count);
        Assert.False(section.NextCommand.CanExecute(null));
        section.PreviousCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal("CN=Member50," + Root, calls[3][0]);
    }

    [Fact]
    public async Task GroupsStaleMemberCannotNavigateAndShowsTheRefusal()
    {
        var current = true;
        var opened = false;
        var attributes = FakeAssetSource.CapturedObject(Group, "group") with { Attributes =
            [new("member", SecureAD.Kernel.Capture.AttributeCardinality.MultiValued, [new(0, "CN=Member," + Root, null)])] };
        var section = new GroupMembershipSectionViewModel(new("Membership", "Membership", ["member"]), MembershipReader(attributes,
            (names, _) => Task.FromResult(SecureAD.Kernel.Result<CapturedMemberReferences>.Success(new(
                names.Select(name => new CapturedMemberReference(name, Guid.NewGuid(), name, "Member", "user", "contoso.com")).ToArray())))),
            _ => opened = true, () => current);
        await section.ReadCompletion;
        current = false;
        section.OpenMemberCommand.Execute(Assert.Single(section.Members));
        Assert.False(opened);
        Assert.True(section.HasError);
    }

    private static Func<bool, CapturedMembershipMark?, CancellationToken,
        Task<SecureAD.Kernel.Result<(CapturedMembershipPage, CapturedMemberReferences)>>> MembershipReader(
        ObjectAttributes attributes,
        Func<IReadOnlyList<string>, CancellationToken, Task<SecureAD.Kernel.Result<CapturedMemberReferences>>> resolve)
    {
        var source = new FakeAssetSource { Attributes = attributes };
        return async (parents, after, token) =>
        {
            var page = source.ReadCapturedMembership("test", attributes.DistinguishedName, parents, after).Value!;
            var members = await resolve(page.Values.Select(value => value.Stored).ToArray(), token);
            return members.IsSuccess
                ? SecureAD.Kernel.Result<(CapturedMembershipPage, CapturedMemberReferences)>.Success((page, members.Value))
                : SecureAD.Kernel.Result<(CapturedMembershipPage, CapturedMemberReferences)>.Failure(members.Error);
        };
    }

    private static (AssetsViewModel, FakeAssetSource) Model()
    {
        var source = new FakeAssetSource
        {
            Tree = new([new(Root, "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []),
            Attributes = FakeAssetSource.CapturedObject(Group, "group"),
            GroupPage = new(Guid.NewGuid(), new string('a', 64),
                [new(Guid.NewGuid(), Group, "Administrators", "Administrators", "contoso.com", -2147483643, 4, 0, true, null,
                    new(17, 0, 0, GroupMembershipLimitations.None))],
                1, null, new(true, null), null),
        };
        var model = new AssetsViewModel(source);
        model.Show(@"C:\synthetic-runs\groups", false);
        return (model, source);
    }
}
