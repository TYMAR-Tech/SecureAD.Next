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
public sealed class ServiceAccountDetailTests
{
    [Theory]
    [InlineData("SEC-100", "user", 66048u)]
    [InlineData("SEC-100", "user", 66050u)]
    [InlineData("SEC-100", "user", null)]
    [InlineData("SEC-100", "msDS-ManagedServiceAccount", 66048u)]
    [InlineData("SEC-100", "msDS-GroupManagedServiceAccount", 66050u)]
    [InlineData("SEC-101", "user", 66048u)]
    [InlineData("SEC-101", "user", 66050u)]
    public void SelectedServiceAccountShowsSavedKindAndStateWithoutEagerSupportingReads(string rule, string kind, uint? control)
    {
        var (model, source) = Model(rule, kind: kind, control: control);
        Assert.Empty(source.ServiceAccountReads);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        var panel = Assert.IsType<ServiceAccountViewModel>(details.ServiceAccount);
        Assert.Equal(new[] { "header" }, source.ServiceAccountReads);
        Assert.Null(panel.Names); Assert.Null(panel.Links); Assert.Null(panel.Values); Assert.Null(panel.Limitations);
        Assert.Equal(rule == "SEC-100", panel.Entries is not null);
        Assert.Equal(control is null ? "Not established from captured evidence." : (control & 2) != 0 ? "Disabled" : "Enabled", panel.AccountState);
        Assert.Equal(kind, panel.Account.ObjectClass);
        Assert.Contains(kind == "user" ? "Ordinary user" : kind == "msDS-ManagedServiceAccount" ? "(sMSA)" : "(gMSA)", panel.Association, StringComparison.Ordinal);
        Assert.Equal(rule == "SEC-100" ? "High" : "Medium", details.Finding!.Severity);
        Assert.False(details.ShowsSavedDescription); Assert.False(details.ShowsStandardIdentity);
        Assert.Contains("not observed service use", panel.AssociationNote, StringComparison.Ordinal);
        Assert.Empty(source.ControlQueries); Assert.Empty(source.PathQueries);
    }

    [Theory]
    [InlineData("names")]
    [InlineData("entries")]
    [InlineData("links")]
    [InlineData("values")]
    [InlineData("limitations")]
    public void RequestedServiceAccountLevelsKeepFiftyRowsAndOriginalPreviousPages(string level)
    {
        var (model, _) = Model("SEC-100", partial: true);
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.ServiceAccount!;
        if (level == "entries") CheckPages(panel.Entries!, row => row.Saved);
        else if (level == "names") { panel.ViewNamesCommand.Execute(null); CheckPages(panel.Names!, row => row.Saved); }
        else if (level == "links") { panel.ViewLinksCommand.Execute(null); CheckPages(panel.Links!, row => row.Saved); }
        else if (level == "limitations") { panel.ViewLimitationsCommand.Execute(null); CheckPages(panel.Limitations!, row => row.Saved); }
        else
        {
            var held = panel.Entries!.Rows[0]; held.ViewCommand.Execute(null);
            CheckPages(panel.Values!, row => row.Saved);
            panel.Entries.NextPageCommand.Execute(null);
            Assert.Null(panel.Values); Assert.False(held.ViewCommand.CanExecute(null));
        }
    }
    private static void CheckPages<T, TRow, TValue>(ServiceAccountPageViewModel<T, TRow> page, Func<TRow, TValue> saved)
    {
        var first = page.Rows.Select(saved).ToArray(); Assert.Equal(50, first.Length);
        page.NextPageCommand.Execute(null); Assert.InRange(page.Rows.Count, 1, 50);
        Assert.NotEqual(first, page.Rows.Select(saved));
        page.PreviousPageCommand.Execute(null); Assert.Equal(first, page.Rows.Select(saved));
        while (page.NextPageCommand.CanExecute(null)) page.NextPageCommand.Execute(null);
        Assert.InRange(page.Rows.Count, 1, 50); Assert.False(page.NextPageCommand.CanExecute(null));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("account")]
    [InlineData("target")]
    [InlineData("complete")]
    [InlineData("entries")]
    public void InvalidServiceAccountHeadersRefuseInsteadOfShowingGenericFindingSuccess(string defect)
    {
        var (model, source) = Model("SEC-100"); var read = source.ServiceAccountRead!;
        source.ServiceAccountRead = reference =>
        {
            if (defect == "missing") return Result<SavedServiceAccountDetails>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingServiceAccount", ErrorSeverity.Failed, SavedServiceAccountContext.InvalidDetails, null));
            var details = read(reference).Value;
            return Result<SavedServiceAccountDetails>.Success(defect switch
            {
                "generation" => details with { Context = details.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "account" => details with { Context = details.Context with { Account = details.Context.Account with { ObjectGuid = Guid.NewGuid() } } },
                "target" => details with { Context = details.Context with { Target = details.Context.Target! with { ObjectGuid = Guid.NewGuid() } } },
                "complete" => details with { Context = details.Context with { IsComplete = false } },
                _ => details with { EntryMemberships = null },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding); Assert.Null(model.FindingDetails.ServiceAccount);
        Assert.Equal(SavedServiceAccountContext.InvalidDetails, model.FindingDetails.Refusal);
    }

    [Theory]
    [InlineData("kind")]
    [InlineData("context")]
    [InlineData("page")]
    public void RequestedNamesRefuseWrongLevelContextOrContinuationShape(string defect)
    {
        var (model, source) = Model("SEC-101"); var read = source.ServiceAccountNamesRead!;
        source.ServiceAccountNamesRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedServiceAccountPage<SavedServiceAccountName>>.Success(defect switch
            {
                "kind" => page with { Kind = ServiceAccountPageKind.Links },
                "context" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                _ => page with { Next = null },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.ServiceAccount!;
        panel.ViewNamesCommand.Execute(null);
        Assert.Null(panel.Names); Assert.Equal(SavedServiceAccountContext.InvalidDetails, panel.Refusal);
        Assert.Equal(new[] { "header", "names" }, source.ServiceAccountReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ServiceAccountCloseAndExpiryClearLoadedPagesAndHeldActions(bool expire)
    {
        var (model, source) = Model("SEC-100", partial: true);
        model.OpenFinding(Assert.Single(model.Findings)); var panel = model.FindingDetails!.ServiceAccount!;
        panel.ViewNamesCommand.Execute(null); panel.ViewLinksCommand.Execute(null); panel.ViewLimitationsCommand.Execute(null);
        var held = panel.Entries!.Rows[0]; held.ViewCommand.Execute(null); var values = panel.Values!;
        if (expire) { source.IsCurrent = false; Assert.False(model.FindingDetails.CheckCurrent()); } else model.CloseFindingDetails();
        Assert.Empty(panel.Entries.Rows); Assert.Empty(panel.Names!.Rows); Assert.Empty(panel.Links!.Rows);
        Assert.Empty(panel.Limitations!.Rows); Assert.Empty(values.Rows);
        Assert.False(held.ViewCommand.CanExecute(null)); Assert.False(panel.ViewNamesCommand.CanExecute(null));
        Assert.False(panel.ViewLinksCommand.CanExecute(null)); Assert.False(values.NextPageCommand.CanExecute(null));
    }

    [Fact]
    public void LateServiceAccountNamesCannotRestoreASuspendedPanel() => OneThread.Run(async () =>
    {
        var (model, source) = Model("SEC-101"); var reference = Assert.Single(model.Findings).Saved.Reference!.Value;
        var pending = new TaskCompletionSource<Result<SavedServiceAccountPage<SavedServiceAccountName>>>();
        var reads = Reads(source, reference) with { Names = (_, _) => pending.Task };
        var panel = new ServiceAccountViewModel(source.ServiceAccountRead!(reference).Value, reads, () => true);
        panel.ViewNamesCommand.Execute(null); var work = panel.ReadCompletion;
        panel.Suspend(); pending.SetResult(source.ServiceAccountNamesRead!(reference, null)); await work;
        Assert.Null(panel.Names); Assert.False(panel.ViewNamesCommand.CanExecute(null));
    });

    [Theory]
    [InlineData("SEC-100")]
    [InlineData("SEC-101")]
    public void BothFindingEntryPointsKeepFreshServiceAccountReadsAndReturnContext(string rule) => OneThread.Run(async () =>
    {
        var (model, source) = Model(rule); var selected = Assert.Single(model.Findings); model.SelectedFinding = selected;
        model.OpenFinding(selected); var panel = model.FindingDetails!.ServiceAccount!;
        source.Attributes = FakeAssetSource.CapturedObject(panel.Account.DistinguishedName, panel.Account.ObjectClass)
            with { ObjectGuid = selected.Saved.ObjectGuid };
        model.OpenAffectedObjectCommand.Execute(null); await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings); await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        var objectRow = Assert.Single(section.Findings); section.SelectedFinding = objectRow;
        model.CloseFindingDetails(); model.OpenFinding(objectRow);
        Assert.NotSame(panel, model.FindingDetails!.ServiceAccount);
        Assert.Equal(new[] { "header", "header" }, source.ServiceAccountReads);
        Assert.Equal(selected.Saved.Reference, model.FindingDetails.Finding!.Saved.Reference);
        Assert.Same(section, opened.Content); Assert.Same(objectRow, section.SelectedFinding); Assert.Same(selected, model.SelectedFinding);
    });

    [Theory]
    [InlineData("SEC-100", 900)]
    [InlineData("SEC-100", 1300)]
    [InlineData("SEC-101", 900)]
    [InlineData("SEC-101", 1300)]
    public void RealServiceAccountWindowDrawsRequestedFullValuesAndOnlyItsOwnMembershipPanel(string rule, int width) => OnSta(() =>
    {
        var (model, _) = Model(rule, count: 1); model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000, ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text
                == (rule == "SEC-100" ? "Saved administrative membership" : "Captured password setting"));
            Assert.Equal(rule == "SEC-100", Descendants<TextBlock>(view).Any(value => value.IsVisible && value.Text == "Entry memberships"));
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("Raw service proof", StringComparison.Ordinal));
            var names = Assert.Single(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View captured service names"));
            names.BringIntoView(); Layout(view, width, 700); AssertActionVisible(view, names);
            names.Command.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "HTTP/service0.contoso.com:8443/instance");
            if (rule == "SEC-100")
            {
                var links = Assert.Single(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View recorded membership links"));
                links.BringIntoView(); Layout(view, width, 700); AssertActionVisible(view, links);
                links.Command.Execute(null); Layout(view, width, 700);
                Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Service is a member of Bridge 0.");
            }
            else Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Password never expires: Enabled");
        }
        finally { host.Close(); }
    });
    private static void AssertActionVisible(FrameworkElement view, Button action)
    {
        var viewport = Assert.Single(Descendants<ScrollViewer>(view), value => value.Name == "FindingDetailsScroll");
        var visible = viewport.TransformToAncestor(view).TransformBounds(new Rect(viewport.RenderSize));
        var bounds = action.TransformToAncestor(view).TransformBounds(new Rect(action.RenderSize));
        Assert.True(action.ActualHeight > 0);
        Assert.InRange(bounds.Top, visible.Top, visible.Bottom - action.ActualHeight);
    }

    private static ServiceAccountReads Reads(FakeAssetSource source, FindingReference reference) => new(
        (after, _) => Task.FromResult(source.ServiceAccountNamesRead!(reference, after)),
        (after, _) => Task.FromResult(source.ServiceAccountEntriesRead!(reference, after)),
        (after, _) => Task.FromResult(source.ServiceAccountLinksRead!(reference, after)),
        (link, after, _) => Task.FromResult(source.ServiceAccountValuesRead!(reference, link, after)),
        (after, _) => Task.FromResult(source.ServiceAccountLimitationsRead!(reference, after)));
    private static (AssetsViewModel Model, FakeAssetSource Source) Model(string rule, bool partial = false,
        string kind = "user", uint? control = 66048, int count = 55)
    {
        const string root = "DC=contoso,DC=com", domain = "contoso.com", sid = "S-1-5-21-1-2-3";
        static Guid Id(int value) => new(value, 0, 0, new byte[8]);
        var accountClass = kind == "user" ? "user" : "computer";
        var account = new SavedServiceAccountIdentity(Id(1), "CN=Service," + root, root, domain, sid + "-1100", null,
            accountClass, null, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete);
        var target = new SavedServiceAccountIdentity(Id(2), "CN=Target,CN=Builtin," + root, root, domain,
            "S-1-5-32-544", domain, "group", -2147483643, DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete);
        var names = kind == "user" ? Enumerable.Range(0, count)
            .Select(index => new SavedServiceAccountName(index, "HTTP/service" + index + ".contoso.com:8443/instance", false)).ToArray() : [];
        var missing = control is null ? new[] { "userAccountControl" } : partial && rule == "SEC-101" ? ["servicePrincipalName"] : [];
        var facts = new SavedServiceAccountFacts(account.ObjectGuid, account.DistinguishedName, domain, kind, "Service",
            account.CapturedUtc, account.Coverage, kind == "user" ? ServiceAccountKind.SpnBearingUser : kind == "msDS-ManagedServiceAccount"
                ? ServiceAccountKind.StandaloneManagedServiceAccount : ServiceAccountKind.GroupManagedServiceAccount, control,
            string.Join(", ", missing), names.Length);
        var entries = Enumerable.Range(0, count).Select(index =>
        {
            var bridge = target with { ObjectGuid = Id(index + 10), DistinguishedName = "CN=Bridge " + index + "," + root,
                Sid = sid + "-" + (1200 + index), SidScope = null, GroupType = -2147483646 };
            return new SavedServiceAccountLink(index, bridge, account, account, count, false);
        }).ToArray();
        var links = entries.Concat(entries.Select((entry, index) =>
            new SavedServiceAccountLink(count + index, target, entry.ContainingGroup, entry.ContainingGroup, count, false))).ToArray();
        var gaps = partial && rule == "SEC-100" ? Enumerable.Range(0, count).Select(index =>
            new AdministrativeMembershipLimitation("CN=Missing " + index + "," + root, AdministrativeMembershipReason.MemberUncaptured)).ToArray() : [];
        var association = new ServiceAccountAssociation(account.ObjectGuid, account.DistinguishedName, domain, account.CapturedUtc,
            account.Coverage, facts.Kind, [new(0, kind, null)],
            names.Select(value => new AttributeValue(value.OriginalOrdinal, value.Text, null)).ToArray(),
            control is { } number ? [new(0, number.ToString(System.Globalization.CultureInfo.InvariantCulture), null)] : [], control, missing);
        var membership = rule == "SEC-100" ? new ServiceAdministrativeMembership(new string('a', 64), Guid.NewGuid(), new string('b', 64),
            1, 1, root, account.ObjectGuid, target.ObjectGuid, [], [], [], true, MembershipRouteIncompleteReason.None, gaps) : null;
        var subject = new FindingSubject(FindingSubjectKind.Account, rule == "SEC-100"
            ? account.ObjectGuid.ToString("D") + ":" + target.ObjectGuid.ToString("D") : account.ObjectGuid.ToString("D"));
        var finding = new Finding(rule, 1, rule == "SEC-100" ? Severity.High : Severity.Medium, subject, account.ObjectGuid,
            account.DistinguishedName, domain, kind, "Raw service proof must not be shown", EvidenceCompleteness.Complete,
            new ServiceAccountFindingEvidence(association, membership)) { PrincipalName = "Service" };
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1), FilterValues = new([finding.Severity], [rule], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings }; model.Show(@"C:\offline-fixture\service-account", false);
        SavedServiceAccountContext Context(FindingReference reference) => new(reference, rule, subject, facts,
            rule == "SEC-100" ? account : null, rule == "SEC-100" ? target : null,
            rule == "SEC-100" ? count : 0, rule == "SEC-100" ? links.Length : 0, gaps.Length, true, MembershipRouteIncompleteReason.None,
            missing.Length == 0 && gaps.Length == 0);
        SavedServiceAccountPage<T> Page<T>(FindingReference reference, ServiceAccountPageKind pageKind, IReadOnlyList<T> rows,
            ServiceAccountMark? after, SavedServiceAccountLink? link = null)
        {
            var start = after?.Offset ?? 0;
            var values = rows.Skip((int)start).Take(50).Select((value, index) => new SavedServiceAccountRow<T>(start + index, value)).ToArray();
            return new(Context(reference), pageKind, link, values, start + values.Length < rows.Count
                ? new(reference.GenerationId, reference.FindingId, account.ObjectGuid, rule == "SEC-100" ? target.ObjectGuid : null,
                    pageKind, link?.Position ?? -1, start + values.Length) : null);
        }
        source.ServiceAccountRead = reference => Result<SavedServiceAccountDetails>.Success(new(Context(reference),
            rule == "SEC-100" ? Page(reference, ServiceAccountPageKind.EntryMemberships, entries, null) : null));
        source.ServiceAccountNamesRead = (reference, after) => Result<SavedServiceAccountPage<SavedServiceAccountName>>.Success(
            Page(reference, ServiceAccountPageKind.Names, names, after));
        source.ServiceAccountEntriesRead = (reference, after) => Result<SavedServiceAccountPage<SavedServiceAccountLink>>.Success(
            Page(reference, ServiceAccountPageKind.EntryMemberships, entries, after));
        source.ServiceAccountLinksRead = (reference, after) => Result<SavedServiceAccountPage<SavedServiceAccountLink>>.Success(
            Page(reference, ServiceAccountPageKind.Links, links, after));
        source.ServiceAccountLimitationsRead = (reference, after) => Result<SavedServiceAccountPage<AdministrativeMembershipLimitation>>.Success(
            Page(reference, ServiceAccountPageKind.Limitations, gaps, after));
        source.ServiceAccountValuesRead = (reference, position, after) =>
        {
            var link = links[(int)position];
            var values = Enumerable.Range(0, count).Select(index =>
                new SavedServiceAccountWitness(link.ContainingGroup, "member", index, link.RecordedThrough.DistinguishedName)).ToArray();
            return Result<SavedServiceAccountPage<SavedServiceAccountWitness>>.Success(Page(reference, ServiceAccountPageKind.Values, values, after, link));
        };
        return (model, source);
    }
}
