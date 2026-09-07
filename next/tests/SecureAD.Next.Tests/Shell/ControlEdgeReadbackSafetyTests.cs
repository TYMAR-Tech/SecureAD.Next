using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ControlEdgeReadbackSafetyTests
{
    private const string Target = "CN=Target,DC=contoso,DC=com";
    private const string Requester = "CN=Alice,DC=contoso,DC=com";
    private const string Bundle = @"C:\synthetic-runs\first";
    private static readonly AuditError Failure = AuditError.Create(ErrorCategory.Shell, "SyntheticReadFailure",
        ErrorSeverity.Failed, "The stored product could not be read.", null);

    public static IEnumerable<object[]> FailureTransitions()
    {
        foreach (var user in new[] { false, true })
            foreach (var transition in new[] { "next", "first", "filter", "direction", "configure" })
                yield return [user, transition];
    }

    [Theory]
    [MemberData(nameof(FailureTransitions))]
    public void FailedControlReadCannotLeavePreviousRequesterAnswers(bool user, string transition)
    {
        var generation = Guid.NewGuid();
        var fail = false;
        var vm = Section();
        Result<ControlEdgePage> Read(bool holder, bool expected, long after) => fail
            ? Result<ControlEdgePage>.Failure(Failure) : Result<ControlEdgePage>.Success(Page(generation));
        vm.Configure(true, user, Read, _ => Result<SelfMembershipAssessmentSet>.Success(Assessments(generation)));
        Assert.Single(vm.RequesterAssessments);
        Assert.Single(vm.Rows);
        fail = true;

        switch (transition)
        {
            case "next": vm.NextPageCommand.Execute(null); break;
            case "first": vm.FirstPageCommand.Execute(null); break;
            case "filter": vm.IncludeExpected = true; break;
            case "direction": vm.ByHolder = !user; break;
            case "configure": vm.Configure(true, !user, Read, _ => Result<SelfMembershipAssessmentSet>.Success(Assessments(generation))); break;
        }

        Assert.Empty(vm.RequesterAssessments);
        Assert.Empty(vm.Rows);
        Assert.Null(vm.SelectedEdge);
        Assert.False(vm.HasMore);
        Assert.Contains("unreadable", vm.Counts);
        Assert.Equal(Failure.Description, vm.Coverage);
        Assert.DoesNotContain("stored concrete requester assessment(s)", vm.RequesterCoverage);
        Assert.Contains("not read", vm.RequesterCoverage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void DifferentGenerationsBetweenReadsWithholdBothProductsUntilFirstPage(bool user, bool empty)
    {
        var controlGeneration = Guid.NewGuid();
        var requesterGeneration = Guid.NewGuid();
        var vm = Section();
        vm.Configure(true, user, (_, _, _) => Result<ControlEdgePage>.Success(Page(controlGeneration)),
            _ => Result<SelfMembershipAssessmentSet>.Success(Assessments(requesterGeneration, empty)));

        AssertWithheld(vm);
        Assert.Contains("first page", vm.RequesterCoverage, StringComparison.OrdinalIgnoreCase);
        controlGeneration = requesterGeneration;
        vm.FirstPageCommand.Execute(null);
        Assert.Single(vm.Rows);
        Assert.NotNull(vm.SelectedEdge);
        Assert.True(vm.HasMore);
        Assert.Equal(empty ? 0 : 1, vm.RequesterAssessments.Count);
        Assert.DoesNotContain("changed", vm.RequesterCoverage);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GenerationChangeWhilePagingAlsoClearsRequesterRows(bool user)
    {
        var generation = Guid.NewGuid();
        var requesterReads = 0;
        var vm = Section();
        vm.Configure(true, user, (_, _, _) => Result<ControlEdgePage>.Success(Page(generation)), _ =>
        {
            requesterReads++;
            return Result<SelfMembershipAssessmentSet>.Success(Assessments(generation));
        });
        Assert.Single(vm.RequesterAssessments);
        var initialReads = requesterReads;
        generation = Guid.NewGuid();
        vm.NextPageCommand.Execute(null);
        AssertWithheld(vm);
        Assert.Equal(initialReads, requesterReads);
        vm.FirstPageCommand.Execute(null);
        Assert.Single(vm.RequesterAssessments);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void DerivedProductsWithoutGenerationCannotSupplyRowsOrCompleteEmptyAnswers(bool controlMissing, bool empty)
    {
        var generation = Guid.NewGuid();
        var vm = Section();
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(Page(controlMissing ? null : generation)),
            _ => Result<SelfMembershipAssessmentSet>.Success(Assessments(generation, empty) with
            {
                GenerationId = controlMissing ? generation : null,
            }));
        Assert.Empty(vm.Rows);
        Assert.Empty(vm.RequesterAssessments);
        Assert.Null(vm.SelectedEdge);
        Assert.False(vm.HasMore);
        Assert.Contains("generation", vm.Coverage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("generation", vm.RequesterCoverage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("withheld", vm.Counts, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ConfigureReadsEachApplicableProductOnce(bool user)
    {
        var generation = Guid.NewGuid();
        var controlReads = 0;
        var requesterReads = 0;
        var vm = Section();
        vm.Configure(true, user, (_, _, after) =>
        {
            controlReads++;
            Assert.Equal(0, after);
            return Result<ControlEdgePage>.Success(Page(generation));
        }, _ =>
        {
            requesterReads++;
            return Result<SelfMembershipAssessmentSet>.Success(Assessments(generation));
        });
        Assert.Equal(1, controlReads);
        Assert.Equal(1, requesterReads);
    }

    [Fact]
    public void ControlRowsAreNotPublishedBeforeRequesterGenerationIsChecked()
    {
        var generation = Guid.NewGuid();
        var vm = Section();
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(Page(generation)), _ =>
        {
            Assert.Empty(vm.Rows);
            Assert.Empty(vm.RequesterAssessments);
            Assert.Null(vm.SelectedEdge);
            Assert.False(vm.HasMore);
            return Result<SelfMembershipAssessmentSet>.Success(Assessments(generation));
        });
        Assert.Single(vm.Rows);
        Assert.Single(vm.RequesterAssessments);
    }

    [Fact]
    public void RequesterFailureRemovesItsOldRowsButKeepsTheSuccessfullyReadControlPage()
    {
        var generation = Guid.NewGuid();
        var fail = false;
        var vm = Section();
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(Page(generation)), _ => fail
            ? Result<SelfMembershipAssessmentSet>.Failure(Failure)
            : Result<SelfMembershipAssessmentSet>.Success(Assessments(generation)));
        Assert.Single(vm.RequesterAssessments);
        fail = true;
        vm.NextPageCommand.Execute(null);
        Assert.Empty(vm.RequesterAssessments);
        Assert.Equal(Failure.Description, vm.RequesterCoverage);
        Assert.Single(vm.Rows);
        Assert.NotNull(vm.SelectedEdge);
        Assert.True(vm.HasMore);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void AbsentAndEmptyProductsRetainTheirDifferentMeanings(bool controlDerived, bool requesterDerived)
    {
        var generation = Guid.NewGuid();
        var vm = Section();
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0,
            controlDerived, true, false, 0) { GenerationId = generation }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], requesterDerived, requesterDerived ? generation : null)));
        Assert.Empty(vm.Rows);
        Assert.Empty(vm.RequesterAssessments);
        Assert.Contains(requesterDerived ? "No concrete requester request was scheduled" : "not derived", vm.RequesterCoverage);
        Assert.DoesNotContain("withheld", vm.Counts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InapplicableDirectionDoesNotReuseOrReadRequesterAnswers(bool user)
    {
        var generation = Guid.NewGuid();
        var reads = 0;
        var vm = Section();
        vm.Configure(true, user, (_, _, _) => Result<ControlEdgePage>.Success(Page(generation)), _ =>
        {
            reads++;
            return Result<SelfMembershipAssessmentSet>.Success(Assessments(generation));
        });
        Assert.Single(vm.RequesterAssessments);
        var initialReads = reads;
        vm.ByHolder = !user;
        Assert.Empty(vm.RequesterAssessments);
        Assert.Equal(initialReads, reads);
        Assert.Contains("shown when", vm.RequesterCoverage);
    }

    [Theory]
    [InlineData("reload")]
    [InlineData("switch")]
    [InlineData("capture")]
    [InlineData("refusal")]
    [InlineData("clear")]
    public void ChangingOrReloadingRunClosesOldDetailEvenWithoutATreeSelection(string transition)
    {
        var source = Source();
        var screen = OpenScreen(source);
        Assert.Null(screen.Selected);
        Assert.NotNull(screen.Opened);
        switch (transition)
        {
            case "reload": screen.Read(); break;
            case "switch": screen.Show(@"C:\synthetic-runs\second", false); break;
            case "capture": screen.Show(Bundle, true); break;
            case "refusal": source.Fails = Failure; screen.Show(@"C:\synthetic-runs\second", false); break;
            case "clear": screen.Clear(); break;
        }
        Assert.Null(screen.Opened);
        Assert.False(screen.HasOpenObject);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedOrMissingNewObjectCannotLeaveOldObjectOnScreen(bool missing)
    {
        var source = Source();
        var screen = OpenScreen(source);
        if (missing) source.Permissions = null;
        else source.PermissionsFail = Failure;
        screen.OpenObject(new(new("CN=Other,DC=contoso,DC=com", "Other", Guid.NewGuid(), "group", "DC=contoso,DC=com")));
        Assert.Null(screen.Opened);
        Assert.False(screen.HasOpenObject);
        Assert.NotNull(screen.Refusal);
    }

    [Fact]
    public void ObjectCallbacksStayBoundToTheBundleThatOpenedTheObject()
    {
        var source = Source();
        var screen = OpenScreen(source);
        var controls = Assert.IsType<ControlEdgesSectionViewModel>(screen.Opened!.Section(ObjectSectionCatalog.ControlEdges));
        Assert.Single(controls.RequesterAssessments);
        screen.Show(@"C:\synthetic-runs\second", false);
        controls.FirstPageCommand.Execute(null);
        Assert.Equal((Bundle, (string?)Target, (string?)null), source.ControlQueries[^1]);
        Assert.Equal((Bundle, (string?)Target, (string?)null), source.RequesterQueries[^1]);
    }

    private static ControlEdgesSectionViewModel Section() => new(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));

    private static ControlEdgePage Page(Guid? generation)
    {
        var evaluation = Judgement.GroupMembershipControlTests.Membership(Judgement.ControlEdgeDeriverTests.Permissions(
            Judgement.GroupMembershipControlTests.Scoped(0, 0x08)));
        return new([Assert.Single(evaluation.Edges) with { Id = 9, GenerationId = generation ?? Guid.Empty }],
            0, 1, 0, 1, true, true, true, 9) { GenerationId = generation };
    }

    private static SelfMembershipAssessmentSet Assessments(Guid generation, bool empty = false) => new(empty ? [] :
        [new(new(Requester, Target, SelfMembershipOperation.Add, null), generation, null, new('a', 64),
            null, null, null, null, null, null, ControlEvaluationState.Unknown, ControlEvaluationState.Unknown,
            ControlEvaluationState.Unknown, "DescriptorNotRead", null, null, null,
            [SelfMembershipIssue.DescriptorUnreadable], [], [])], true, generation);

    private static void AssertWithheld(ControlEdgesSectionViewModel vm)
    {
        Assert.Empty(vm.Rows);
        Assert.Empty(vm.RequesterAssessments);
        Assert.Null(vm.SelectedEdge);
        Assert.False(vm.HasMore);
        Assert.Contains("changed", vm.Coverage);
        Assert.Contains("changed", vm.RequesterCoverage);
        Assert.Contains("withheld", vm.Counts, StringComparison.OrdinalIgnoreCase);
    }

    private static FakeAssetSource Source()
    {
        var generation = Guid.NewGuid();
        return new()
        {
            Permissions = new(Target, DescriptorAvailability.Read, null, null, DaclState.Present,
                DaclCompleteness.Complete, true, false, [], []),
            ControlEdges = Page(generation),
            SelfMembershipAssessments = Assessments(generation),
        };
    }

    private static AssetsViewModel OpenScreen(FakeAssetSource source)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        screen.OpenObject(new(new(Target, "Target", Guid.NewGuid(), "group", "DC=contoso,DC=com")));
        Assert.NotNull(screen.Opened);
        return screen;
    }
}
