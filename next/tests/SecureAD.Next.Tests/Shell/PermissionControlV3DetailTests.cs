using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

[Collection("Finding window resources")]
public sealed class PermissionControlV3DetailTests
{
    [Theory]
    [InlineData(PermissionControlState.Established, PermissionControlState.NotEstablished, PermissionControlState.NotEstablished)]
    [InlineData(PermissionControlState.Unknown, PermissionControlState.Established, PermissionControlState.Unknown)]
    [InlineData(PermissionControlState.Established, PermissionControlState.Unknown, PermissionControlState.NotEstablished)]
    [InlineData(PermissionControlState.Established, PermissionControlState.Established, PermissionControlState.Established)]
    public void VersionThreeShowsSeparateSavedStatesAndNeverLegacyWarnings(PermissionControlState modify,
        PermissionControlState owner, PermissionControlState full)
    {
        var (model, source) = Model(modify, owner, full);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = Assert.IsType<PermissionControlViewModel>(model.FindingDetails!.PermissionControl);
        Assert.Equal(new[] { "header" }, source.PermissionControlReads);
        Assert.True(panel.HasCurrentAssessment);
        Assert.Equal(Text(modify), panel.ModifyPermissions);
        Assert.Equal(Text(owner), panel.ChangeOwner);
        Assert.Equal(Text(full), panel.FullControl);
        Assert.Equal(owner != PermissionControlState.NotEstablished, panel.IsOwnership);
        Assert.False(panel.IsFullControlCategory);
        Assert.Equal("Saved assessment limits", panel.CalculationLimitsHeading);
        Assert.Equal(modify == PermissionControlState.Unknown || owner == PermissionControlState.Unknown
            || full == PermissionControlState.Unknown, panel.HasCalculationLimits);
        Assert.Equal("Complete", panel.Expansion);
        Assert.Equal("Complete", panel.CapturedPermissions);
        Assert.Equal(SavedPermissionControl.CurrentScopeNote, panel.ScopeNote);
        Assert.Equal(SavedPermissionControl.CurrentOwnerRoute, panel.OwnerRoute);
        Assert.Null(panel.Chain);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
    }

    [Fact]
    public void NullDaclDoesNotInventAnExplicitEntryOrAnInheritedSource()
    {
        var (model, _) = Model(PermissionControlState.Established, PermissionControlState.Established,
            PermissionControlState.Established, nullDacl: true);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.PermissionControl!;
        Assert.True(panel.HasNullDacl);
        Assert.Equal("No entry (NULL DACL)", panel.EntryContext);
        Assert.Equal("No permission list (NULL DACL)", panel.CapturedPermissions);
        Assert.Equal(SavedPermissionControl.NullDaclNote, panel.EntryNote);
        Assert.Equal("Full control", panel.ReportedRight);
    }

    [Fact]
    public void InheritedVersionThreeContextUsesTheActualSupportingFlagWithoutInventingAContainer()
    {
        var (model, source) = Model();
        var read = source.PermissionControlRead!;
        source.PermissionControlRead = reference =>
        {
            var value = read(reference).Value;
            return Result<SavedPermissionControl>.Success(value with
            {
                InheritedContext = true,
                Assessment = value.Assessment! with { SupportingEntryIsInherited = true },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.PermissionControl!;
        Assert.Equal("Inherited", panel.EntryContext);
        Assert.Equal(SavedPermissionControl.CurrentEntryNote, panel.EntryNote);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("object")]
    [InlineData("holder")]
    [InlineData("right")]
    [InlineData("complete")]
    [InlineData("version")]
    public void VersionThreeInitialUiContextCannotFallBackToLegacyFacts(string defect)
    {
        var (model, source) = Model();
        var read = source.PermissionControlRead!;
        source.PermissionControlRead = reference =>
        {
            var value = read(reference).Value;
            return Result<SavedPermissionControl>.Success(defect switch
            {
                "missing" => value with { Assessment = null },
                "generation" => value with { Assessment = value.Assessment! with { GenerationId = Guid.NewGuid() } },
                "object" => value with { Assessment = value.Assessment! with { ObjectGuid = Guid.NewGuid() } },
                "holder" => value with { Assessment = value.Assessment! with { HolderSid = "S-1-5-21-1-2-3-999" } },
                "right" => value with { Assessment = value.Assessment! with { ModifyPermissions = PermissionControlState.NotEstablished } },
                "complete" => value with { Assessment = value.Assessment! with { HasLimitations = true } },
                _ => value with { RuleVersion = 2 },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.False(model.FindingDetails!.HasFinding);
        Assert.Null(model.FindingDetails.PermissionControl);
        Assert.Equal(SavedPermissionControl.InvalidDetails, model.FindingDetails.Refusal);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void MembershipAndCalculationCompletenessRemainIndependent(bool membershipComplete, bool calculationComplete)
    {
        var (model, _) = Model(calculationComplete ? PermissionControlState.Established : PermissionControlState.Unknown,
            PermissionControlState.Established, PermissionControlState.NotEstablished, membershipComplete: membershipComplete);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.PermissionControl!;
        Assert.Equal(membershipComplete ? "Complete" : "May be incomplete", panel.Expansion);
        Assert.Equal(!calculationComplete, panel.HasCalculationLimits);
        Assert.Equal(SavedPermissionControl.CurrentExpansionNote, panel.ExpansionNote);
    }

    [Fact]
    public void VersionThreeChainUsesFiftyRowsAndRefusesAForeignPreparedAssessment()
    {
        var (model, source) = Model();
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.PermissionControl!;
        panel.ViewChainCommand.Execute(null);
        var chain = Assert.IsType<PermissionControlChainViewModel>(panel.Chain);
        var first = chain.Steps.ToArray();
        Assert.Equal(50, first.Length);
        chain.NextPageCommand.Execute(null);
        Assert.Equal(5, chain.Steps.Count);
        chain.PreviousPageCommand.Execute(null);
        Assert.Equal(first, chain.Steps);
        var read = source.PermissionControlChainRead!;
        source.PermissionControlChainRead = (reference, after) =>
        {
            var page = read(reference, after).Value;
            return Result<SavedPermissionControlChain>.Success(page with
            {
                Context = page.Context with { Assessment = page.Context.Assessment! with { GenerationId = Guid.NewGuid() } },
            });
        };
        chain.NextPageCommand.Execute(null);
        Assert.Equal(SavedPermissionControl.InvalidDetails, chain.Refusal);
    }

    [Fact]
    public void BothVersionThreeEntryPointsRetainObjectAndMainGridSelections() => OneThread.Run(async () =>
    {
        var (model, source) = Model();
        var selected = Assert.Single(model.Findings);
        model.SelectedFinding = selected;
        model.OpenFinding(selected);
        var panel = model.FindingDetails!.PermissionControl!;
        source.Attributes = FakeAssetSource.CapturedObject(panel.Object.DistinguishedName, panel.Object.ObjectClass)
            with { ObjectGuid = panel.Object.ObjectGuid };
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        var row = Assert.Single(section.Findings);
        section.SelectedFinding = row;
        model.CloseFindingDetails();
        model.OpenFinding(row);
        Assert.NotSame(panel, model.FindingDetails!.PermissionControl);
        Assert.Same(selected, model.SelectedFinding);
        Assert.Same(row, section.SelectedFinding);
        Assert.Equal(new[] { "header", "header" }, source.PermissionControlReads);
    });

    [Fact]
    public void SuspendedVersionThreePanelCannotBeRestoredByALateChain() => OneThread.Run(async () =>
    {
        var (model, source) = Model();
        var reference = Assert.Single(model.Findings).Saved.Reference!.Value;
        var pending = new TaskCompletionSource<Result<SavedPermissionControlChain>>();
        var panel = new PermissionControlViewModel(source.PermissionControlRead!(reference).Value, (_, _) => pending.Task, () => true);
        panel.ViewChainCommand.Execute(null);
        var work = panel.ReadCompletion;
        panel.Suspend();
        pending.SetResult(source.PermissionControlChainRead!(reference, null));
        await work;
        Assert.Null(panel.Chain);
        Assert.False(panel.ViewChainCommand.CanExecute(null));
    });

    [Theory]
    [InlineData(900, "full")]
    [InlineData(1300, "full")]
    [InlineData(900, "null")]
    [InlineData(1300, "null")]
    [InlineData(900, "unresolved")]
    [InlineData(1300, "unresolved")]
    [InlineData(900, "direct")]
    [InlineData(1300, "direct")]
    public void RealWindowDrawsVersionThreeClaimsAndActualChainAction(int width, string mode) => OnSta(() =>
    {
        var owner = mode == "direct" ? PermissionControlState.NotEstablished
            : mode == "unresolved" ? PermissionControlState.Unknown : PermissionControlState.Established;
        var full = mode == "direct" ? PermissionControlState.NotEstablished
            : mode == "unresolved" ? PermissionControlState.Unknown : PermissionControlState.Established;
        var (model, _) = Model(PermissionControlState.Established, owner, full, nullDacl: mode == "null");
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            var text = Descendants<TextBlock>(view).Where(value => value.IsVisible).Select(value => value.Text).ToArray();
            Assert.Equal("Established", Named<TextBlock>(view, "PermissionControlModifyState").Text);
            Assert.Equal(Text(owner), Named<TextBlock>(view, "PermissionControlOwnerState").Text);
            Assert.Equal(Text(full), Named<TextBlock>(view, "PermissionControlFullState").Text);
            Assert.Equal(owner != PermissionControlState.NotEstablished, text.Contains(SavedPermissionControl.CurrentOwnerRoute));
            Assert.Equal(mode == "unresolved", text.Contains(SavedPermissionControl.CurrentCalculationLimits));
            Assert.Contains(SavedPermissionControl.CurrentScopeNote, text);
            Assert.DoesNotContain(SavedPermissionControl.CalculationLimits, text);
            Assert.DoesNotContain(SavedPermissionControl.FullControlNote, text);
            if (mode == "null") Assert.Contains(SavedPermissionControl.NullDaclNote, text);
            else Assert.DoesNotContain(SavedPermissionControl.CurrentEntryNote, text);
            var context = Named<Expander>(view, "PermissionControlAssessmentContext");
            Assert.False(context.IsExpanded);
            context.IsExpanded = true; Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(context), value => value.IsVisible && value.Text ==
                (mode == "null" ? SavedPermissionControl.NullDaclNote : SavedPermissionControl.CurrentEntryNote));
            var action = Assert.Single(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View saved supporting chain"));
            action.BringIntoView(); Layout(view, width, 700);
            var viewport = Assert.Single(Descendants<ScrollViewer>(view), value => value.Name == "FindingDetailsScroll");
            var visible = viewport.TransformToAncestor(view).TransformBounds(new Rect(viewport.RenderSize));
            var bounds = action.TransformToAncestor(view).TransformBounds(new Rect(action.RenderSize));
            Assert.True(action.ActualHeight > 0);
            Assert.InRange(bounds.Top, visible.Top, visible.Bottom - action.ActualHeight);
            action.Command.Execute(null); Layout(view, width, 700);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Saved step 0");
            Assert.Equal(50, model.FindingDetails!.PermissionControl!.Chain!.Steps.Count);
        }
        finally { host.Close(); }
    });

    [Theory]
    [InlineData(900, true)]
    [InlineData(1300, true)]
    [InlineData(900, false)]
    [InlineData(1300, false)]
    public void ModernPresentationSeparatesConclusionsAndOpensTechnicalDetailOnlyOnRequest(int width, bool dark) => OnSta(() =>
    {
        var (model, source) = Model(PermissionControlState.Established, PermissionControlState.Established);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var theme = dark ? ThemeVariant.Dark : ThemeVariant.Light;
        new WpfThemeApplier(view.Resources).Apply(theme);
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, width, 700);
            Assert.False(model.FindingDetails!.ShowsStandardPresentation);
            Assert.Equal(3, Descendants<Expander>(view).Count());
            Assert.All(Descendants<Expander>(view), value => Assert.False(value.IsExpanded));
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Recorded holder");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Authenticated Users");
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Target");
            var modify = Named<TextBlock>(view, "PermissionControlModifyState");
            var full = Named<TextBlock>(view, "PermissionControlFullState");
            Assert.Equal("Established", modify.Text);
            Assert.Equal("Not established", full.Text);
            Assert.Equal(((SolidColorBrush)view.FindResource("AccentBrush")).Color, ((SolidColorBrush)modify.Foreground).Color);
            Assert.Equal(((SolidColorBrush)view.FindResource("NotEstablishedBrush")).Color, ((SolidColorBrush)full.Foreground).Color);
            var cards = new[] { "Modify", "Owner", "Full" }.Select(name => Named<Border>(view, $"PermissionControl{name}Card")).ToArray();
            Assert.All(cards, value => Assert.True(value.ActualWidth > 150 && value.ActualHeight > 70));
            Assert.True(cards[0].TransformToAncestor(view).Transform(new Point()).X
                < cards[1].TransformToAncestor(view).Transform(new Point()).X);
            Assert.True(cards[1].TransformToAncestor(view).Transform(new Point()).X
                < cards[2].TransformToAncestor(view).Transform(new Point()).X);
            var action = Assert.Single(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, "View saved supporting chain"));
            var viewport = Named<ScrollViewer>(view, "FindingDetailsScroll");
            var visible = viewport.TransformToAncestor(view).TransformBounds(new Rect(viewport.RenderSize));
            var bounds = action.TransformToAncestor(view).TransformBounds(new Rect(action.RenderSize));
            Assert.InRange(bounds.Top, visible.Top, visible.Bottom - action.ActualHeight);
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.StartsWith("Holder SID:", StringComparison.Ordinal));
            RenderIfRequested(view, width, $"permission-control-{theme}-{width}");
            Named<Expander>(view, "PermissionControlIdentifiers").IsExpanded = true; Layout(view, width, 700);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Holder SID: " + model.FindingDetails.PermissionControl!.HolderSid);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Broad identity SID: " + model.FindingDetails.PermissionControl!.BroadSid);
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Location: " + model.FindingDetails.PermissionControl!.Object.DistinguishedName);
            Named<Expander>(view, "PermissionControlAssessmentContext").IsExpanded = true; Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == SavedPermissionControl.CurrentStateNote);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == SavedPermissionControl.CurrentOwnerNote);
            Named<Expander>(view, "PermissionControlGuidance").IsExpanded = true; Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == SavedPermissionControl.Risk);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == SavedPermissionControl.Action);
            Assert.Equal(new[] { "header" }, source.PermissionControlReads);
            Assert.Null(model.FindingDetails.PermissionControl!.Chain);
        }
        finally { host.Close(); }
    });

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ModernPresentationKeepsCaptureMembershipAndUnsettledRightsVisiblySeparate(bool captureComplete, bool membershipComplete) => OnSta(() =>
    {
        var (model, source) = Model(PermissionControlState.NotEstablished, PermissionControlState.Established,
            PermissionControlState.Unknown, membershipComplete: membershipComplete,
            descriptorCompleteness: captureComplete ? DaclCompleteness.Complete : DaclCompleteness.Incomplete);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = 900, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, 900, 700);
            Assert.Equal(!captureComplete, Named<Border>(view, "PermissionControlCaptureLimit").IsVisible);
            Assert.Equal(!membershipComplete, Named<Border>(view, "PermissionControlMembershipLimit").IsVisible);
            Assert.All(Descendants<Expander>(view), value => Assert.False(value.IsExpanded));
            var text = Descendants<TextBlock>(view).Where(value => value.IsVisible).Select(value => value.Text).ToArray();
            Assert.Contains(SavedPermissionControl.CurrentCalculationLimits, text);
            Assert.Contains(SavedPermissionControl.CurrentOwnerRoute, text);
            Assert.Contains("Captured permission list: " + (captureComplete ? "Complete" : "May be incomplete"), text);
            Assert.Contains("Saved membership expansion: " + (membershipComplete ? "Complete" : "May be incomplete"), text);
            Assert.Equal("Not established", Named<TextBlock>(view, "PermissionControlModifyState").Text);
            Assert.Equal("Other access is not ruled out.", Named<TextBlock>(view, "PermissionControlModifyNote").Text);
            var unresolved = Named<TextBlock>(view, "PermissionControlFullState");
            Assert.Equal("Unresolved", unresolved.Text);
            Assert.Equal("This assessment could not settle that right.", Named<TextBlock>(view, "PermissionControlFullNote").Text);
            Assert.Equal(((SolidColorBrush)view.FindResource("EstablishedBadBrush")).Color, ((SolidColorBrush)unresolved.Foreground).Color);
            Assert.Equal(new[] { "header" }, source.PermissionControlReads);
            Assert.Null(model.FindingDetails!.PermissionControl!.Chain);
        }
        finally { host.Close(); }
    });

    private static T Named<T>(DependencyObject root, string name) where T : FrameworkElement =>
        Assert.Single(Descendants<T>(root), value => value.Name == name);

    [Theory]
    [InlineData("group", "Group")]
    [InlineData("user", "User")]
    [InlineData("computer", "Computer")]
    [InlineData("msDS-ManagedServiceAccount", "Managed service account")]
    [InlineData("msDS-GroupManagedServiceAccount", "Group managed service account")]
    [InlineData("foreignSecurityPrincipal", "Foreign principal reference")]
    [InlineData(null, "Type unavailable")]
    [InlineData(" ", "Type unavailable")]
    public void HolderTypeBadgeUsesCapturedClassWithoutGuessingFromTheHolderName(string? objectClass, string expected) => OnSta(() =>
    {
        var (model, source) = Model(holderObjectClass: objectClass);
        model.OpenFinding(Assert.Single(model.Findings));
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = 900, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show(); Layout(view, 900, 700);
            var badge = Named<TextBlock>(view, "PermissionControlHolderType");
            Assert.True(badge.IsVisible && badge.ActualWidth > 0 && badge.ActualHeight > 0);
            Assert.Equal(expected, badge.Text);
            Assert.Equal("Recorded holder", model.FindingDetails!.PermissionControl!.Holder);
            Assert.Equal(new[] { "header" }, source.PermissionControlReads);
            Assert.Null(model.FindingDetails.PermissionControl.Chain);
            if (objectClass == "group") RenderIfRequested(view, 900, "permission-holder-Group-900");
        }
        finally { host.Close(); }
    });

    private static void RenderIfRequested(FrameworkElement view, int width, string name)
    {
        if (Environment.GetEnvironmentVariable("SECUREAD_PERMISSION_CONTROL_RENDER") is not { } directory) return;
        var image = new RenderTargetBitmap(width, 700, 96, 96, PixelFormats.Pbgra32);
        image.Render(view);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(image));
        using var output = System.IO.File.Create(System.IO.Path.Combine(directory, name + ".png"));
        encoder.Save(output);
    }

    private static string Text(PermissionControlState state) => state switch
    {
        PermissionControlState.Established => "Established",
        PermissionControlState.NotEstablished => "Not established",
        _ => "Unresolved",
    };

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(
        PermissionControlState modify = PermissionControlState.Established,
        PermissionControlState owner = PermissionControlState.NotEstablished,
        PermissionControlState full = PermissionControlState.NotEstablished, bool membershipComplete = true, bool nullDacl = false,
        DaclCompleteness descriptorCompleteness = DaclCompleteness.Complete, string? holderObjectClass = null)
    {
        const string dn = "CN=Target,DC=contoso,DC=com", domain = "contoso.com", broad = "S-1-5-11", holder = "S-1-5-21-1-2-3-1200";
        var guid = Guid.NewGuid();
        var derivation = Guid.NewGuid();
        var steps = Enumerable.Range(0, 55).Select(index => new PathStep(index == 54 ? broad : "S-1-5-21-1-2-3-" + (1200 + index),
            "Saved step " + index)).ToArray();
        PermissionControlRightAssessment Right(PermissionControlState state) => new(state, state == PermissionControlState.Established ? [0] : [],
            [], state == PermissionControlState.Unknown ? ["ConditionalOrUnsupportedAce"] : []);
        var calculation = new PermissionControlCalculation(Guid.NewGuid(), new string('a', 64), derivation, new string('b', 64),
            guid, dn, domain, holder, null, broad, nullDacl ? DaclState.Null : DaclState.Present, descriptorCompleteness, true,
            Right(modify), Right(owner), Right(full), PermissionControlState.Unknown,
            owner == PermissionControlState.NotEstablished ? PermissionControlState.NotEstablished : PermissionControlState.Unknown,
            [], [], false);
        var right = full == PermissionControlState.Established ? ObjectTakeoverRight.GenericAll
            : modify == PermissionControlState.Established ? ObjectTakeoverRight.WriteDacl : ObjectTakeoverRight.WriteOwner;
        var subject = new FindingSubject(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(broad));
        var finding = new Finding("SEC-060", 3, Severity.High, subject, guid, dn, domain, "group",
            "Original takeover prose must not be loaded.", EvidenceCompleteness.Complete,
            new ObjectTakeoverEvidence(holder, "Recorded holder", broad, "Authenticated Users", steps, right, null, membershipComplete)
            { Calculation = calculation }) { PrincipalName = "Authenticated Users" };
        var source = new FakeAssetSource { FindingsPage = new([finding], null, 1),
            FilterValues = new([Severity.High], ["SEC-060"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\permission-control-v3", false);
        SavedPermissionControl Header(FindingReference reference) => new(reference, subject, new(guid, dn, domain, "group"),
            finding.PrincipalName, holder, "Recorded holder", broad, "Authenticated Users", right, false, membershipComplete,
            EvidenceCompleteness.Complete, steps.Length)
        {
            RuleVersion = 3,
            HolderObjectClass = holderObjectClass,
            Assessment = SavedPermissionControlAssessment.From(calculation with { GenerationId = reference.GenerationId }, steps.Length),
        };
        source.PermissionControlRead = reference => Result<SavedPermissionControl>.Success(Header(reference));
        source.PermissionControlChainRead = (reference, after) =>
        {
            var start = after?.Ordinal + 1 ?? 0;
            var page = steps.Skip((int)start).Take(50).Select((step, index) => new SavedPermissionControlStep(start + index, step.Sid, step.Name)).ToArray();
            return Result<SavedPermissionControlChain>.Success(new(Header(reference), page, start + page.Length < steps.Length
                ? new(reference.GenerationId, reference.FindingId, guid, page[^1].Ordinal) : null));
        };
        return (model, source);
    }
}
