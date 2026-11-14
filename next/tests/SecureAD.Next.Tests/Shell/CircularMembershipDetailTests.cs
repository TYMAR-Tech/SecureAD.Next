using System.Windows;
using System.Windows.Controls;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

[Collection("Finding window resources")]
public sealed class CircularMembershipDetailTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void GridsDeferCycleInventoryWhileDetailsUseTheOriginalSavedFlag(bool complete)
    {
        var (model, source) = Model(complete);
        var row = Assert.Single(model.Findings);
        Assert.Null(row.Saved.CircularInventoryComplete);
        Assert.Equal(FactState.NotEstablished, row.State);
        Assert.Equal(complete ? "Cycle inventory: open details" : "May be incomplete; cycle inventory: open details", row.Coverage);
        Assert.Empty(source.CircularReads);
        Assert.Equal(CircularGroupMembership.Explanation, row.Detail);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<CircularMembershipViewModel>(details.CircularMembership);
        Assert.Equal("Medium", details.Finding!.Severity);
        Assert.Equal(complete, details.Finding.Saved.CircularInventoryComplete);
        Assert.Equal(complete ? "Complete" : "May be incomplete", details.Finding.Coverage);
        Assert.Equal(complete ? "Saved cycle inventory: Complete" : "Saved cycle inventory: Incomplete", panel.InventoryLabel);
        Assert.Equal(!complete, panel.IsIncomplete);
        Assert.Equal(new[] { "loop" }, source.CircularReads);
        Assert.False(details.ShowsSavedDescription); Assert.False(details.ShowsStandardIdentity);
        Assert.Equal(50, panel.Loop.Rows.Count); Assert.Null(panel.Groups); Assert.Null(panel.Links); Assert.Null(panel.Witnesses);
        Assert.Null(row.Saved.CircularInventoryComplete);
        Assert.Empty(source.ControlQueries); Assert.Empty(source.PathQueries);
    }

    [Theory]
    [InlineData("loop")]
    [InlineData("groups")]
    [InlineData("links")]
    [InlineData("witnesses")]
    public void EachRequestedPageIsBoundedAndPreviousRestoresTheSameOriginalRows(string level)
    {
        var (model, source) = Model(); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.CircularMembership!;
        if (level == "loop")
        {
            var first = panel.Loop.Rows.Select(value => value.Saved).ToArray();
            var held = panel.Loop.Rows[0].ReviewCommand;
            var announced = new List<string?>();
            panel.PropertyChanged += (_, change) => announced.Add(change.PropertyName);
            panel.Loop.NextPageCommand.Execute(null);
            Assert.Equal(5, panel.Loop.Rows.Count);
            Assert.Equal(50, panel.Loop.Rows[0].Saved.Position);
            Assert.False(held.CanExecute(null));
            Assert.Contains(nameof(panel.Chain), announced);
            Assert.StartsWith("Group 50 (contoso.com)", panel.Chain, StringComparison.Ordinal);
            Assert.Equal("Arrow means contains.", panel.ArrowNote);
            panel.Loop.PreviousPageCommand.Execute(null);
            Assert.Equal(first, panel.Loop.Rows.Select(value => value.Saved));
            Assert.Equal(new[] { "loop", "loop", "loop" }, source.CircularReads);
            Assert.Null(panel.Groups); Assert.Null(panel.Links); Assert.Null(panel.Witnesses);
            return;
        }
        panel.ViewDetailsCommand.Execute(null);
        if (level == "groups")
        {
            var first = panel.Groups!.Rows.Select(value => value.Saved).ToArray();
            panel.Groups.NextPageCommand.Execute(null); Assert.Equal(5, panel.Groups.Rows.Count);
            panel.Groups.PreviousPageCommand.Execute(null); Assert.Equal(first, panel.Groups.Rows.Select(value => value.Saved));
            Assert.Equal(new[] { "loop", "groups", "groups", "groups" }, source.CircularReads);
        }
        else
        {
            panel.ViewLinksCommand.Execute(null);
            Assert.Null(panel.Witnesses);
            if (level == "links")
            {
                var first = panel.Links!.Rows.Select(value => value.Saved).ToArray();
                panel.Links.NextPageCommand.Execute(null); Assert.Equal(5, panel.Links.Rows.Count);
                panel.Links.PreviousPageCommand.Execute(null); Assert.Equal(first, panel.Links.Rows.Select(value => value.Saved));
            }
            else
            {
                panel.Links!.Rows[0].ViewCommand.Execute(null);
                var first = panel.Witnesses!.Rows.Select(value => value.Saved).ToArray();
                panel.Witnesses.NextPageCommand.Execute(null); Assert.Equal(5, panel.Witnesses.Rows.Count);
                panel.Witnesses.PreviousPageCommand.Execute(null); Assert.Equal(first, panel.Witnesses.Rows.Select(value => value.Saved));
                Assert.True(panel.HasMemberOf);
                panel.Links.NextPageCommand.Execute(null); Assert.Null(panel.Witnesses);
            }
        }
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("group")]
    [InlineData("page")]
    public void InvalidInitialSavedGroupPagesCannotBecomeGenericOrRawProseSuccess(string defect)
    {
        var (model, source) = Model(); var read = source.CircularLoopRead!;
        source.CircularLoopRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedCircularMembershipLoop>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingCircularDetails", ErrorSeverity.Failed, SavedCircularMembershipContext.InvalidDetails, null));
            var page = read(reference, after).Value;
            return Result<SavedCircularMembershipLoop>.Success(defect switch
            {
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "group" => page with { Context = page.Context with { Anchor = page.Context.Anchor with { ObjectGuid = Guid.NewGuid() } } },
                _ => page with { Next = null },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding); Assert.Null(model.FindingDetails.CircularMembership);
        Assert.Equal(SavedCircularMembershipContext.InvalidDetails, model.FindingDetails.Refusal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InvalidRequestedLinkPagesRemainExplicitRefusals(bool context)
    {
        var (model, source) = Model(); var read = source.CircularLinksRead!;
        source.CircularLinksRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedCircularMembershipLinks>.Success(context
                ? page with { Context = page.Context with { InventoryComplete = false } }
                : page with { Links = page.Links.Take(49).ToArray() });
        };
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.CircularMembership!;
        panel.ViewLinksCommand.Execute(null);
        Assert.Null(panel.Links); Assert.Equal(SavedCircularMembershipContext.InvalidDetails, panel.Refusal);
    }

    [Theory]
    [InlineData("link")]
    [InlineData("position")]
    [InlineData("context")]
    public void SupportingValuesCannotComeFromAnotherRelationshipOrPage(string defect)
    {
        var (model, source) = Model(); var read = source.CircularWitnessesRead!;
        source.CircularWitnessesRead = (reference, group, member, after) =>
        {
            var page = read(reference, group, member, after).Value;
            return Result<SavedCircularMembershipWitnesses>.Success(defect switch
            {
                "link" => page with { Link = page.Link with { Member = page.Link.ContainingGroup } },
                "position" => page with { Witnesses = page.Witnesses.Select(value => value with { Position = value.Position + 1 }).ToArray() },
                _ => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.CircularMembership!;
        panel.ViewLinksCommand.Execute(null); panel.Links!.Rows[0].ViewCommand.Execute(null);
        Assert.Null(panel.Witnesses); Assert.Equal(SavedCircularMembershipContext.InvalidDetails, panel.Refusal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CloseAndExpiryClearEveryLoadedPageAndDisableHeldCommands(bool expire)
    {
        var (model, source) = Model(); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.CircularMembership!;
        panel.ViewDetailsCommand.Execute(null);
        panel.ViewLinksCommand.Execute(null); panel.Links!.Rows[0].ViewCommand.Execute(null);
        var groups = panel.Groups!; var group = groups.Rows[1]; var links = panel.Links; var values = panel.Witnesses!;
        if (expire) { source.IsCurrent = false; Assert.False(model.FindingDetails.CheckCurrent()); } else model.CloseFindingDetails();
        Assert.Empty(groups.Rows); Assert.Empty(links.Rows); Assert.Empty(values.Rows);
        Assert.False(group.OpenCommand.CanExecute(null)); Assert.False(panel.ViewLinksCommand.CanExecute(null));
        Assert.False(values.NextPageCommand.CanExecute(null));
    }

    [Fact]
    public void OpenGroupUsesItsActualIdentityAndBothFindingEntryPointsPreserveContext() => OneThread.Run(async () =>
    {
        var (model, source) = Model(); var selected = Assert.Single(model.Findings); model.SelectedFinding = selected;
        model.OpenFinding(selected); var panel = model.FindingDetails!.CircularMembership!;
        panel.ViewDetailsCommand.Execute(null);
        var child = panel.Groups!.Rows[1];
        source.Attributes = FakeAssetSource.CapturedObject(child.Location, "group") with { ObjectGuid = child.Saved.Group.ObjectGuid };
        child.OpenCommand.Execute(null); await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        Assert.Equal(child.Location, opened.DistinguishedName); Assert.Equal(child.Saved.Group.ObjectGuid, opened.ObjectGuid);
        Assert.Same(panel, model.FindingDetails!.CircularMembership); Assert.Same(selected, model.SelectedFinding);
        opened.Show(ObjectSectionCatalog.Findings); await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        var objectRow = Assert.Single(section.Findings); section.SelectedFinding = objectRow;
        model.CloseFindingDetails(); model.OpenFinding(objectRow);
        Assert.Equal(selected.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.Same(section, opened.Content); Assert.Same(objectRow, section.SelectedFinding);
        Assert.Equal(new[] { "loop", "groups", "loop" }, source.CircularReads);
    });

    [Fact]
    public void SelfMembershipAndMemberOfAreShownWithoutInventingAPath()
    {
        var (model, _) = Model(self: true); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.CircularMembership!; panel.ViewLinksCommand.Execute(null);
        var link = Assert.Single(panel.Links!.Rows);
        Assert.True(link.IsSelfMembership); Assert.Equal("This group is recorded as a member of itself.", link.SelfMembershipNote);
        link.ViewCommand.Execute(null);
        Assert.True(panel.HasMemberOf); Assert.Contains("same relationship", panel.MemberOfNote, StringComparison.Ordinal);
        Assert.Contains("not one ordered path", panel.LinksNote, StringComparison.Ordinal);
        Assert.Contains("does not establish a route to Tier 0", model.FindingDetails.Finding!.WhyItMatters, StringComparison.Ordinal);
    }

    [Fact]
    public void ALinkAnswerCompletingAfterSuspendCannotRestoreThePanel() => OneThread.Run(async () =>
    {
        var (model, source) = Model(); var reference = Assert.Single(model.Findings).Saved.Reference!.Value;
        var pending = new TaskCompletionSource<Result<SavedCircularMembershipLinks>>();
        var panel = new CircularMembershipViewModel(source.CircularLoopRead!(reference, null).Value,
            new((after, _) => Task.FromResult(source.CircularLoopRead(reference, after)),
                (after, _) => Task.FromResult(source.CircularGroupsRead!(reference, after)), (_, _) => pending.Task,
                (group, member, after, _) => Task.FromResult(source.CircularWitnessesRead!(reference, group, member, after)), _ => { }, _ => { }), () => true);
        panel.ViewLinksCommand.Execute(null); var work = panel.ReadCompletion;
        panel.Suspend(); pending.SetResult(source.CircularLinksRead!(reference, null)); await work;
        Assert.Null(panel.Links); Assert.Empty(panel.Loop.Rows); Assert.False(panel.ViewLinksCommand.CanExecute(null));
    });

    [Fact]
    public void LoopFirstReviewOpensTheContainingGroupsCapturedMembershipWithoutLoadingEvidence() => OneThread.Run(async () =>
    {
        var (model, source) = Model(size: 3); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.CircularMembership!;
        var choice = panel.Loop.Rows[0];
        source.Attributes = FakeAssetSource.CapturedObject(choice.Saved.Link.ContainingGroup.DistinguishedName, "group")
            with { ObjectGuid = choice.Saved.Link.ContainingGroup.ObjectGuid };
        choice.ReviewCommand.Execute(null); await model.ObjectReadCompletion;
        Assert.Equal(choice.Saved.Link.ContainingGroup.DistinguishedName, source.OpenedObject);
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        Assert.Equal(choice.Saved.Link.ContainingGroup.ObjectGuid, opened.ObjectGuid);
        Assert.Equal(ObjectSectionCatalog.Membership, opened.SelectedKey);
        Assert.Equal(new[] { "loop" }, source.CircularReads);
        Assert.Null(panel.Groups); Assert.Null(panel.Links); Assert.Null(panel.Witnesses);
        Assert.Contains("breaks the loop shown", panel.BreakNote, StringComparison.Ordinal);
    });

    [Theory]
    [InlineData(900, true)]
    [InlineData(1300, true)]
    [InlineData(900, false)]
    [InlineData(1300, false)]
    public void RealWindowShowsSavedCoverageAndRequestedRelationshipsWithoutRawProof(int width, bool complete) => OnSta(() =>
    {
        var (model, _) = Model(complete, size: 3, otherLoops: !complete); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.CircularMembership!;
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "The circular nesting");
            var how = Assert.Single(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "How to break the loop shown");
            var bounds = how.TransformToAncestor(view).TransformBounds(new Rect(how.RenderSize));
            Assert.InRange(bounds.Top, 0, 700 - how.ActualHeight);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text ==
                "Anchor (contoso.com) \u2192 Child nested (child.contoso.com) \u2192 Group 2 (contoso.com) \u2192 Anchor (contoso.com)");
            Assert.Equal(!complete, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == panel.IncompleteNote));
            Assert.Equal(!complete, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == panel.OtherLoopsNote));
            var choices = Descendants<Button>(view).Where(value => value.IsVisible && Equals(value.Content, "Review membership")).ToArray();
            Assert.Equal(3, choices.Length);
            var viewport = Assert.Single(Descendants<ScrollViewer>(view), value => value.Name == "FindingDetailsScroll");
            var visible = viewport.TransformToAncestor(view).TransformBounds(new Rect(viewport.RenderSize));
            Assert.All(choices, choice =>
            {
                var choiceBounds = choice.TransformToAncestor(view).TransformBounds(new Rect(choice.RenderSize));
                Assert.InRange(choiceBounds.Top, visible.Top, visible.Bottom - choice.ActualHeight);
            });
            var details = Assert.Single(Descendants<Button>(view), value => Equals(value.Content, "Group details and original evidence"));
            details.Command.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == (complete ? "Saved cycle inventory: Complete" : "Saved cycle inventory: Incomplete"));
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Recorded nesting links");
            var button = Assert.Single(Descendants<Button>(view), value => Equals(value.Content, "View recorded nesting links"));
            button.Command.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Recorded nesting links");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Child nested (child.contoso.com) is a member of Anchor (contoso.com).");
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text.Contains("Raw cycle proof", StringComparison.Ordinal));
        }
        finally { host.Close(); }
    });

    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(bool complete = true, bool self = false, int size = 55, bool otherLoops = false)
    {
        var count = self ? 1 : size;
        var groups = Enumerable.Range(0, count).Select(index =>
        {
            var domain = index == 1 ? "child.contoso.com" : "contoso.com";
            var name = index == 0 ? "Anchor" : index == 1 ? "Child nested" : "Group " + index;
            var dn = "CN=" + name + "," + (index == 1 ? "DC=child," : "") + "DC=contoso,DC=com";
            return new CircularMembershipGroup(new Guid(index + 1, 0, 0, new byte[8]), dn, domain, "S-1-5-21-1-2-3-" + (2000 + index), null);
        }).ToArray();
        var originals = groups.Select((group, index) => new CircularMembershipLink(group.ObjectGuid, groups[(index + 1) % count].ObjectGuid,
            Enumerable.Range(0, 55).Select(ordinal => ordinal % 2 == 0
                ? new CircularMembershipWitness(group.ObjectGuid, "member", ordinal, groups[(index + 1) % count].DistinguishedName)
                : new CircularMembershipWitness(groups[(index + 1) % count].ObjectGuid, "memberOf", ordinal, group.DistinguishedName)).ToArray())).ToArray();
        CircularMembershipLink[] allLinks = otherLoops
            ? [.. originals, new(groups[0].ObjectGuid, groups[^1].ObjectGuid,
                [new(groups[0].ObjectGuid, "member", 55, groups[^1].DistinguishedName)])]
            : originals;
        var subject = new FindingSubject(FindingSubjectKind.DirectoryObject, CircularMembershipIndex.Key(groups));
        var evidence = new CircularMembershipEvidence(new string('a', 64), Guid.NewGuid(), subject.Key, groups, allLinks, complete);
        var finding = new Finding("SEC-052", 1, Severity.Medium, subject, groups[0].ObjectGuid, groups[0].DistinguishedName,
            groups[0].DomainFqdn, "group", "Raw cycle proof must not be displayed", EvidenceCompleteness.Complete, evidence);
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([Severity.Medium], ["SEC-052"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings }; model.Show(@"C:\offline-fixture\circular-membership", false);
        SavedCircularMembershipContext Context(FindingReference reference) => new(reference, subject, groups[0], count, allLinks.Length, complete, EvidenceCompleteness.Complete);
        var loopKey = Tier0PathCalculation.Fingerprint(originals.Select(link => link.GroupGuid.ToString("D") + ":" + link.MemberGuid.ToString("D")));
        source.CircularLoopRead = (reference, after) =>
        {
            var start = after?.Offset ?? 0;
            var steps = originals.Skip((int)start).Take(50).Select((link, index) => new SavedCircularMembershipLoopStep(start + index,
                new(start + index, groups.Single(group => group.ObjectGuid == link.GroupGuid),
                    groups.Single(group => group.ObjectGuid == link.MemberGuid), 55))).ToArray();
            return Result<SavedCircularMembershipLoop>.Success(new(Context(reference), loopKey, groups[0].ObjectGuid, count, otherLoops,
                steps, start + steps.Length < count ? new(reference.GenerationId, reference.FindingId, subject.Key, loopKey, start + steps.Length) : null));
        };
        source.CircularGroupsRead = (reference, after) =>
        {
            var start = after?.Offset ?? 0;
            var rows = groups.Skip((int)start).Take(50).Select((group, index) => new SavedCircularMembershipGroup(start + index, group)).ToArray();
            return Result<SavedCircularMembershipGroups>.Success(new(Context(reference), rows, start + rows.Length < count
                ? new(reference.GenerationId, reference.FindingId, subject.Key, start + rows.Length) : null));
        };
        source.CircularLinksRead = (reference, after) =>
        {
            var start = after?.Offset ?? 0;
            var rows = allLinks.Skip((int)start).Take(50).Select((link, index) => new SavedCircularMembershipLink(start + index,
                groups.Single(group => group.ObjectGuid == link.GroupGuid), groups.Single(group => group.ObjectGuid == link.MemberGuid), link.Witnesses.Count)).ToArray();
            return Result<SavedCircularMembershipLinks>.Success(new(Context(reference), rows, start + rows.Length < allLinks.Length
                ? new(reference.GenerationId, reference.FindingId, subject.Key, start + rows.Length) : null));
        };
        source.CircularWitnessesRead = (reference, group, member, after) =>
        {
            var position = Array.FindIndex(allLinks, link => link.GroupGuid == group && link.MemberGuid == member);
            var original = allLinks[position];
            var saved = new SavedCircularMembershipLink(position, groups.Single(value => value.ObjectGuid == group), groups.Single(value => value.ObjectGuid == member), original.Witnesses.Count);
            var start = after?.Offset ?? 0;
            var rows = original.Witnesses.Skip((int)start).Take(50).Select((value, index) => new SavedCircularMembershipWitness(start + index,
                groups.Single(identity => identity.ObjectGuid == value.SourceObjectGuid), value.Attribute, value.Ordinal, value.Value)).ToArray();
            return Result<SavedCircularMembershipWitnesses>.Success(new(Context(reference), saved, rows, start + rows.Length < original.Witnesses.Count
                ? new(reference.GenerationId, reference.FindingId, subject.Key, group, member, start + rows.Length) : null));
        };
        return (model, source);
    }
}
