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
public sealed class BroadMembershipDetailTests
{
    [Theory]
    [InlineData("SEC-061", false)]
    [InlineData("SEC-061", true)]
    [InlineData("SEC-062", false)]
    [InlineData("SEC-062", true)]
    public void SelectedSavedBroadAnswerKeepsRuleCoverageAndDoesNotReadLinksOrValues(string rule, bool partial)
    {
        var (model, source) = Model(rule, partial);
        Assert.Empty(source.BroadReads);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        var panel = Assert.IsType<BroadMembershipViewModel>(details.BroadMembership);
        Assert.Equal(rule == "SEC-061" ? "Medium" : "High", details.Finding!.Severity);
        Assert.Equal(partial, panel.HasLimitations);
        Assert.Equal(partial ? new[] { "sources", "limitations" } : ["sources"], source.BroadReads);
        Assert.Equal(50, panel.Sources.Rows.Count); Assert.Null(panel.Links); Assert.Null(panel.Values);
        Assert.False(details.ShowsSavedDescription); Assert.False(details.ShowsStandardIdentity);
        Assert.Contains("not expanded into accounts", panel.SourcesNote, StringComparison.Ordinal);
        Assert.Empty(source.ControlQueries); Assert.Empty(source.PathQueries);
    }

    [Theory]
    [InlineData("sources")]
    [InlineData("links")]
    [InlineData("values")]
    [InlineData("limitations")]
    public void EveryRequestedLevelKeepsFiftyRowsAndOriginalPreviousPage(string level)
    {
        var (model, _) = Model("SEC-062", true); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.BroadMembership!;
        if (level == "sources") CheckPages(panel.Sources, row => row.Saved);
        else if (level == "limitations") CheckPages(panel.Limitations!, row => row.Saved);
        else
        {
            panel.ViewLinksCommand.Execute(null);
            if (level == "links") CheckPages(panel.Links!, row => row.Saved);
            else
            {
                var link = panel.Links!.Rows[0]; link.ViewCommand.Execute(null);
                CheckPages(panel.Values!, row => row.Saved);
                Assert.True(panel.HasMemberOf);
                panel.Links.NextPageCommand.Execute(null);
                Assert.Null(panel.Values); Assert.False(link.ViewCommand.CanExecute(null));
            }
        }
    }
    private static void CheckPages<T, TRow, TValue>(BroadMembershipPageViewModel<T, TRow> page, Func<TRow, TValue> saved)
    {
        var first = page.Rows.Select(saved).ToArray(); Assert.Equal(50, first.Length);
        page.NextPageCommand.Execute(null); Assert.Equal(5, page.Rows.Count);
        page.PreviousPageCommand.Execute(null); Assert.Equal(first, page.Rows.Select(saved));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("target")]
    [InlineData("page")]
    public void InvalidInitialBroadAnswersCannotBecomeGenericFindingSuccess(string defect)
    {
        var (model, source) = Model("SEC-061"); var read = source.BroadSourcesRead!;
        source.BroadSourcesRead = (reference, after) =>
        {
            if (defect == "missing") return Result<SavedBroadMembershipPage<SavedBroadIdentity>>.Failure(
                AuditError.Create(ErrorCategory.Evidence, "MissingBroadMembership", ErrorSeverity.Failed, SavedBroadMembershipContext.InvalidDetails, null));
            var page = read(reference, after).Value;
            return Result<SavedBroadMembershipPage<SavedBroadIdentity>>.Success(defect switch
            {
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "target" => page with { Context = page.Context with { Target = page.Context.Target with { ObjectGuid = Guid.NewGuid() } } },
                _ => page with { Next = null },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding); Assert.Null(model.FindingDetails.BroadMembership);
        Assert.Equal(SavedBroadMembershipContext.InvalidDetails, model.FindingDetails.Refusal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CloseAndExpiryClearLoadedBroadPagesAndDisableHeldValueActions(bool expire)
    {
        var (model, source) = Model("SEC-062", true); model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.BroadMembership!;
        panel.ViewLinksCommand.Execute(null); var held = panel.Links!.Rows[0]; held.ViewCommand.Execute(null);
        var values = panel.Values!;
        if (expire) { source.IsCurrent = false; Assert.False(model.FindingDetails.CheckCurrent()); } else model.CloseFindingDetails();
        Assert.Empty(panel.Sources.Rows); Assert.Empty(panel.Limitations!.Rows); Assert.Empty(panel.Links.Rows); Assert.Empty(values.Rows);
        Assert.False(held.ViewCommand.CanExecute(null)); Assert.False(panel.ViewLinksCommand.CanExecute(null));
        Assert.False(values.NextPageCommand.CanExecute(null));
    }

    [Fact]
    public void LateBroadLinkAnswersCannotRestoreASuspendedPanel() => OneThread.Run(async () =>
    {
        var (model, source) = Model("SEC-062"); var reference = Assert.Single(model.Findings).Saved.Reference!.Value;
        var pending = new TaskCompletionSource<Result<SavedBroadMembershipPage<SavedBroadMembershipLink>>>();
        var panel = new BroadMembershipViewModel(source.BroadSourcesRead!(reference, null).Value, null,
            new((after, _) => Task.FromResult(source.BroadSourcesRead(reference, after)),
                (_, _) => pending.Task,
                (link, after, _) => Task.FromResult(source.BroadValuesRead!(reference, link, after)),
                (after, _) => Task.FromResult(source.BroadLimitationsRead!(reference, after))), () => true);
        panel.ViewLinksCommand.Execute(null); var work = panel.ReadCompletion;
        panel.Suspend(); pending.SetResult(source.BroadLinksRead!(reference, null)); await work;
        Assert.Null(panel.Links); Assert.Empty(panel.Sources.Rows); Assert.False(panel.ViewLinksCommand.CanExecute(null));
    });

    [Theory]
    [InlineData("context")]
    [InlineData("link")]
    [InlineData("source")]
    [InlineData("value")]
    [InlineData("position")]
    public void RequestedValuesRefuseAnotherSavedSourceRelationshipOrPage(string defect)
    {
        var (model, source) = Model("SEC-061"); var read = source.BroadValuesRead!;
        source.BroadValuesRead = (reference, link, after) =>
        {
            var page = read(reference, link, after).Value;
            return Result<SavedBroadMembershipPage<SavedBroadMembershipWitness>>.Success(defect switch
            {
                "context" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "link" => page with { SelectedLink = page.SelectedLink! with { Position = link + 1 } },
                "source" => page with { Rows = page.Rows.Select(row => row with { Value = row.Value with { Source = page.SelectedLink!.Member } }).ToArray() },
                "value" => page with { Rows = page.Rows.Select(row => row with { Value = row.Value with { Value = "CN=Other,DC=contoso,DC=com" } }).ToArray() },
                _ => page with { Rows = page.Rows.Select(row => row with { Position = row.Position + 1 }).ToArray() },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.BroadMembership!; panel.ViewLinksCommand.Execute(null); panel.Links!.Rows[0].ViewCommand.Execute(null);
        Assert.Null(panel.Values); Assert.Equal(SavedBroadMembershipContext.InvalidDetails, panel.Refusal);
    }

    [Theory]
    [InlineData("SEC-061")]
    [InlineData("SEC-062")]
    public void BothFindingEntryPointsKeepTheSameBroadAnswerAndReturnSelection(string rule) => OneThread.Run(async () =>
    {
        var (model, source) = Model(rule); var selected = Assert.Single(model.Findings); model.SelectedFinding = selected;
        model.OpenFinding(selected); var panel = model.FindingDetails!.BroadMembership!;
        source.Attributes = FakeAssetSource.CapturedObject(panel.Location, "group") with { ObjectGuid = selected.Saved.ObjectGuid };
        model.OpenAffectedObjectCommand.Execute(null); await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings); await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        var objectRow = Assert.Single(section.Findings); section.SelectedFinding = objectRow;
        model.CloseFindingDetails(); model.OpenFinding(objectRow);
        Assert.NotSame(panel, model.FindingDetails!.BroadMembership);
        Assert.Equal(new[] { "sources", "sources" }, source.BroadReads);
        Assert.Equal(selected.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.IsType<BroadMembershipViewModel>(model.FindingDetails.BroadMembership);
        Assert.Same(section, opened.Content); Assert.Same(objectRow, section.SelectedFinding); Assert.Same(selected, model.SelectedFinding);
    });

    [Theory]
    [InlineData("SEC-061", 900, false)]
    [InlineData("SEC-061", 1300, false)]
    [InlineData("SEC-061", 900, true)]
    [InlineData("SEC-061", 1300, true)]
    [InlineData("SEC-062", 900, false)]
    [InlineData("SEC-062", 1300, false)]
    [InlineData("SEC-062", 900, true)]
    [InlineData("SEC-062", 1300, true)]
    public void RealWindowShowsSymbolicSourcesAndRequestedForeignLinksWithoutRawProof(string rule, int width, bool partial) => OnSta(() =>
    {
        var (model, _) = Model(rule, partial, 1); model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved broad group membership");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Broad identities");
            Assert.Equal(partial, Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == "Incomplete membership evidence"));
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Recorded membership links");
            var action = Assert.Single(Descendants<Button>(view), value => Equals(value.Content, "View recorded membership links"));
            var viewport = Assert.Single(Descendants<ScrollViewer>(view), value => value.Name == "FindingDetailsScroll");
            var visible = viewport.TransformToAncestor(view).TransformBounds(new Rect(viewport.RenderSize));
            var bounds = action.TransformToAncestor(view).TransformBounds(new Rect(action.RenderSize));
            Assert.InRange(bounds.Top, visible.Top, visible.Bottom - action.ActualHeight);
            action.Command.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Member 0 is a member of Target.");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Recorded through");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Domain: child.contoso.com");
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text.Contains("Raw broad proof", StringComparison.Ordinal));
            Assert.Single(Descendants<Button>(view), value => Equals(value.Content, "View saved supporting values")).Command.Execute(null);
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Saved supporting values");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Recorded attribute: member");
        }
        finally { host.Close(); }
    });

    internal static (AssetsViewModel Model, FakeAssetSource Source) Model(string rule, bool partial = false, int count = 55)
    {
        const string root = "DC=contoso,DC=com";
        static Guid Id(int value) => new(value, 0, 0, new byte[8]);
        var target = new SavedBroadMembershipIdentity(Id(1), "CN=Target,CN=Builtin," + root, root, "contoso.com",
            rule == "SEC-061" ? "S-1-5-32-554" : "S-1-5-32-544", "contoso.com", "group", -2147483643);
        var links = Enumerable.Range(0, count).Select(index =>
        {
            var member = new SavedBroadMembershipIdentity(Id(index + 2), "CN=Member " + index + ",DC=child," + root,
                "DC=child," + root, "child.contoso.com", "S-1-5-21-4-5-" + (6 + index) + "-513", null, "group", -2147483646);
            var reference = new SavedBroadMembershipIdentity(Id(index + 1000), "CN=Reference " + index + ",CN=ForeignSecurityPrincipals," + root,
                root, "contoso.com", member.Sid, null, "foreignSecurityPrincipal", null);
            return new SavedBroadMembershipLink(index, target, member, reference, 55);
        }).ToArray();
        var broad = links.Select(link => new SavedBroadIdentity(link.Member.Sid, null, "Domain Users")).ToArray();
        var gaps = partial ? Enumerable.Range(0, count).Select(index => new AdministrativeMembershipLimitation(
            "CN=Missing " + index + "," + root, AdministrativeMembershipReason.MemberUncaptured)).ToArray() : [];
        var subject = new FindingSubject(FindingSubjectKind.DirectoryObject, target.ObjectGuid.ToString("D"));
        var evidence = new BroadGroupMembershipEvidence(new string('a', 64), Guid.NewGuid(), new string('b', 64), 1, 1,
            root, "CN=Configuration," + root, target.ObjectGuid, [], [], [], [], true, gaps,
            rule == "SEC-061" ? BroadMembershipTarget.PreWindows2000CompatibleAccess : BroadMembershipTarget.AdministrativeGroup);
        var finding = new Finding(rule, 1, rule == "SEC-061" ? Severity.Medium : Severity.High, subject, target.ObjectGuid,
            target.DistinguishedName, target.DomainFqdn!, "group", "Raw broad proof must not be shown", EvidenceCompleteness.Complete, evidence);
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([finding.Severity], [rule], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings }; model.Show(@"C:\offline-fixture\broad-membership", false);
        SavedBroadMembershipContext Context(FindingReference reference) => new(reference, rule, subject, target, count, count, gaps.Length, true, !partial);
        SavedBroadMembershipPage<T> Page<T>(FindingReference reference, BroadMembershipPageKind kind, IReadOnlyList<T> rows,
            BroadMembershipMark? after, SavedBroadMembershipLink? link = null)
        {
            var start = after?.Offset ?? 0;
            var values = rows.Skip((int)start).Take(50).Select((value, index) => new SavedBroadMembershipRow<T>(start + index, value)).ToArray();
            return new(Context(reference), kind, link, values, start + values.Length < rows.Count
                ? new(reference.GenerationId, reference.FindingId, target.ObjectGuid, kind, link?.Position ?? -1, start + values.Length) : null);
        }
        source.BroadSourcesRead = (reference, after) => Result<SavedBroadMembershipPage<SavedBroadIdentity>>.Success(Page(reference, BroadMembershipPageKind.Sources, broad, after));
        source.BroadLinksRead = (reference, after) => Result<SavedBroadMembershipPage<SavedBroadMembershipLink>>.Success(Page(reference, BroadMembershipPageKind.Links, links, after));
        source.BroadLimitationsRead = (reference, after) => Result<SavedBroadMembershipPage<AdministrativeMembershipLimitation>>.Success(Page(reference, BroadMembershipPageKind.Limitations, gaps, after));
        source.BroadValuesRead = (reference, position, after) =>
        {
            var link = links[(int)position];
            var values = Enumerable.Range(0, 55).Select(index => index % 2 == 0
                ? new SavedBroadMembershipWitness(target, "member", index, link.RecordedThrough.DistinguishedName)
                : new SavedBroadMembershipWitness(link.RecordedThrough, "memberOf", index, target.DistinguishedName)).ToArray();
            return Result<SavedBroadMembershipPage<SavedBroadMembershipWitness>>.Success(Page(reference, BroadMembershipPageKind.Values, values, after, link));
        };
        return (model, source);
    }
}
