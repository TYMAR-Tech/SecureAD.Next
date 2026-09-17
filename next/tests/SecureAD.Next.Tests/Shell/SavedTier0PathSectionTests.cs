using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    private const string UserDn = "CN=User,DC=contoso,DC=com";
    private const string CoreDn = "CN=Domain Admins,DC=contoso,DC=com";
    private const string Bundle = @"C:\synthetic-runs\saved-path";

    [Fact]
    public void SavedPathDisplaysASupportedRoute()
    {
        var section = Read(Saved());

        Assert.Equal("Supported route recorded", section.Result);
    }

    [Fact]
    public void SavedPathShowsAFixedTargetWithoutInventingAHop()
    {
        var saved = Saved();
        var section = Section();
        section.Configure(CoreDn, () => Result<SavedTier0Path?>.Success(saved with
        { Path = saved.Path with { Subject = saved.Path.Inputs.FixedTargets[0], ShortestProvenDistance = 0, Steps = [] } }));
        section.Read();

        Assert.Equal(("This object is a Tier 0 target", 0,
            "Shortest proven route: 0 steps. The object is already a fixed Tier 0 target; no extra hop is added."),
            (section.Result, section.Steps.Count, section.Distance));
    }

    [Fact]
    public void SavedPathDoesNotShowUncertainStepsAsAProvenRoute()
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with { Reachability = Tier0Reachability.Unknown, ShortestProvenDistance = null } });

        Assert.Equal(("Not determined", 0, ""), (section.Result, section.Steps.Count, section.Distance));
    }

    [Fact]
    public void SavedPathShowsUnproducedAnalysisAsNoSavedResult()
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with
        { Inputs = saved.Path.Inputs with { Availability = PathInputAvailability.NotProduced }, Reachability = Tier0Reachability.Unknown } });

        Assert.Equal("No saved path result", section.Result);
    }

    [Fact]
    public void SavedPathMissingJudgementIsNotASafeAnswer()
    {
        var section = Read(null);

        Assert.Equal("This run has no saved path result to display. This does not establish that no route exists.", section.Detail);
    }

    [Fact]
    public void SavedPathRetainsUnavailableRequiredInputs()
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with
        { Inputs = saved.Path.Inputs with { Availability = PathInputAvailability.RequiredInputsUnavailable }, Reachability = Tier0Reachability.Unknown } });

        Assert.Contains("Required inputs unavailable", section.Limitations);
    }

    [Theory]
    [InlineData(null, false, "Not requested")]
    [InlineData(1, false, "Required inputs unavailable")]
    [InlineData(1, true, "Supported questions evaluated")]
    public void SavedPathUsesTypedExecutionCoverageEvenWithNoQuestions(int? version, bool completed, string expected)
    {
        var saved = Saved();
        var section = Read(saved with { Requesters = saved.Requesters with { SelectionVersion = version, InputScanCompleted = completed } });

        Assert.Equal(expected, section.AutomaticChecks);
    }

    [Theory]
    [InlineData("Missing captured evidence: required directory evidence is incomplete.")]
    [InlineData("Unsupported analysis: this build does not evaluate every possible relationship or operation.")]
    [InlineData("Unfinished processing: the saved input work did not complete.")]
    public void SavedPathKeepsCoverageBoundariesSeparateOnPositiveRoutes(string expected)
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with
        { Inputs = saved.Path.Inputs with { Coverage = new(false, false, false, Tier0Limitations.None) } } });

        Assert.Contains(expected, section.Limitations);
    }

    [Fact]
    public void SavedPathPositiveRouteSurvivesIndependentCoverageGaps()
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with
        { Inputs = saved.Path.Inputs with { Coverage = new(false, false, false, Tier0Limitations.None) } } });

        Assert.Equal("Supported route recorded", section.Result);
    }

    [Theory]
    [InlineData(PathRequesterSelectionReason.IdentityUnresolved, "Unresolved identity")]
    [InlineData(PathRequesterSelectionReason.DescriptorUnavailable, "Missing captured evidence: descriptor unavailable")]
    [InlineData(PathRequesterSelectionReason.ResourceContextUnsupported, "Unsupported analysis: resource authorization context")]
    [InlineData(PathRequesterSelectionReason.BroadIdentityNotExpanded, "Work not performed: broad identity was not expanded")]
    public void SavedPathNamesSelectionLimitationsWithoutLosingTheirResource(PathRequesterSelectionReason reason, string expected)
    {
        var saved = Saved();
        var section = Read(saved with { Requesters = saved.Requesters with
        { Limitations = [new(reason, CoreDn, 7, "S-1-5-11", UserDn)] } });

        Assert.Contains(section.Limitations, text => text.StartsWith(expected, StringComparison.Ordinal)
            && text.Contains(CoreDn, StringComparison.Ordinal) && text.Contains("\"PermissionOrdinal\": 7", StringComparison.Ordinal));
    }

    [Fact]
    public void SavedPathDoesNotEquateFinishedQuestionsWithEstablishedAnswers()
    {
        var saved = Saved();
        var section = Read(saved with { Requesters = saved.Requesters with
        { SelectionVersion = 1, InputScanCompleted = true, Families = [new(PathRequesterFamily.MembershipDacl, 1, 1, 1, 1, 1)] } });

        Assert.Contains("Some saved supported questions remain unresolved; completing their evaluation did not establish their authorization or membership outcome.", section.Limitations);
    }

    [Theory]
    [InlineData(PathUncertaintyCause.CapturedEvidenceIncomplete, "Missing captured evidence")]
    [InlineData(PathUncertaintyCause.AnalysisUnsupported, "Unsupported analysis")]
    [InlineData(PathUncertaintyCause.IdentityUnresolved, "Unresolved identity")]
    [InlineData(PathUncertaintyCause.BroadPrincipalNotExpanded, "Work not performed: broad-principal expansion")]
    public void SavedPathRetainsSymbolicUncertaintyWithoutInventingSubjects(PathUncertaintyCause cause, string expected)
    {
        var saved = Saved();
        var region = new PathUncertaintyRegion(new(Tier0DiscoveryReason.UnresolvedTrustee, CoreDn, 9, "S-1-5-11"), cause,
            PathSubjectScope.UnknownWithinForest, PathTargetScope.Object, saved.Path.Inputs.FixedTargets[0]);
        var section = Read(saved with { Path = saved.Path with { Inputs = saved.Path.Inputs with { UncertaintyRegions = [region] } } });

        Assert.Contains(section.Limitations, text => text.StartsWith(expected, StringComparison.Ordinal)
            && text.Contains("\"Subjects\": \"UnknownWithinForest\"", StringComparison.Ordinal)
            && text.Contains(CoreDn, StringComparison.Ordinal));
    }

    [Fact]
    public void SavedPathShowsItsExactGenerationRatherThanLatestAttemptStatus()
    {
        var saved = Saved();
        var section = Read(saved);

        Assert.Contains("Saved judgement generation: " + saved.Description.GenerationId, section.Provenance);
    }

    [Fact]
    public void SavedPathQualifiesShortestProvenLength()
    {
        var section = Read(Saved());

        Assert.Equal("Shortest proven route: 1 step\nUnsupported alternatives might be shorter. This is one recorded supported route, not all routes or a remediation recommendation.", section.Distance);
    }

    [Fact]
    public void SavedPathKeepsTheOrderedMembershipStepAndOriginalWitness()
    {
        var section = Read(Saved());
        var step = Assert.Single(section.Steps);

        Assert.Contains("Attribute: member; value ordinal: 3; value: " + UserDn, step.Evidence);
    }

    [Fact]
    public void SavedPathKeepsTheDestinationResourceScope()
    {
        var section = Read(Saved());

        Assert.Contains("naming context: DC=contoso,DC=com; captured domain: contoso.com", section.Destination);
    }

    [Fact]
    public void SavedPathRefusesMixedPathGenerations()
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with { Inputs = saved.Path.Inputs with { JudgementGenerationId = Guid.NewGuid() } } });

        Assert.Equal("Saved result unavailable", section.Result);
    }

    [Fact]
    public void SavedPathRefusesMixedCoverageGenerations()
    {
        var saved = Saved();
        var section = Read(saved with { Requesters = saved.Requesters with { Inputs = saved.Requesters.Inputs with { JudgementGenerationId = Guid.NewGuid() } } });

        Assert.Equal("Saved result unavailable", section.Result);
    }

    [Fact]
    public void SavedPathRefusesMixedEvidenceSeals()
    {
        var saved = Saved();
        var section = Read(saved with { Requesters = saved.Requesters with { EvidenceSeal = new('b', 64) } });

        Assert.Equal("Saved result unavailable", section.Result);
    }

    [Fact]
    public void SavedPathRefusesMixedDerivationGenerations()
    {
        var saved = Saved();
        var section = Read(saved with { Requesters = saved.Requesters with { DerivationGenerationId = Guid.NewGuid() } });

        Assert.Equal("Saved result unavailable", section.Result);
    }

    [Theory]
    [InlineData(JudgementRunState.Running)]
    [InlineData(JudgementRunState.Failed)]
    public void SavedPathRefusesUnfinishedJudgement(JudgementRunState state)
    {
        var saved = Saved();
        var section = Read(saved with { Description = saved.Description with { State = state } });

        Assert.Equal("Saved result unavailable", section.Result);
    }

    [Fact]
    public void SavedPathRefusesADifferentObject()
    {
        var saved = Saved();
        var section = Read(saved with { Path = saved.Path with { Subject = saved.Path.Inputs.FixedTargets[0] } });

        Assert.Equal("Saved result unavailable", section.Result);
    }

    [Fact]
    public void SavedPathDegradedJudgementRetainsItsWarning()
    {
        var saved = Saved();
        var section = Read(saved with { Description = saved.Description with { State = JudgementRunState.CompletedDegraded } });

        Assert.Contains("The saved judging completed with limitations. This is not a clean-forest result.", section.Limitations);
    }

    [Fact]
    public void SavedPathFailureClearsThePreviouslySuccessfulDisplay()
    {
        var section = Read(Saved());
        section.Configure(UserDn, () => Result<SavedTier0Path?>.Failure(Failure()));
        section.Read();

        Assert.Equal(("Saved result unavailable", "Synthetic saved-path proof failure", 0, "", "", ""),
            (section.Result, section.Detail, section.Steps.Count, section.Distance, section.Destination, section.Provenance));
    }

    [Fact]
    public void SavedPathConfigurationDoesNotRead()
    {
        var source = new FakeAssetSource();
        var section = Section();
        section.Configure(UserDn, () => source.ReadSavedTier0Path(Bundle, UserDn));

        Assert.Empty(source.PathQueries);
    }

    [Fact]
    public void SavedPathOpeningAnObjectDoesNotRead()
    {
        var source = Source();
        OpenScreen(source);

        Assert.Empty(source.PathQueries);
    }

    [Fact]
    public void SavedPathSelectingTheSectionReadsTheOpeningObject()
    {
        var source = Source();
        var screen = OpenScreen(source);
        screen.Opened!.Show(ObjectSectionCatalog.SavedTier0Path);

        Assert.Equal((Bundle, UserDn), Assert.Single(source.PathQueries));
    }

    [Fact]
    public void SavedPathCallbackKeepsItsOriginalBundleAfterNavigation()
    {
        var source = Source();
        var screen = OpenScreen(source);
        var old = screen.Opened!;
        screen.Show(@"C:\synthetic-runs\another", false);
        old.Show(ObjectSectionCatalog.SavedTier0Path);

        Assert.Equal((Bundle, UserDn), Assert.Single(source.PathQueries));
    }

    [Theory]
    [InlineData("user")]
    [InlineData("group")]
    [InlineData("computer")]
    [InlineData(null)]
    public void SavedPathFollowsControlEdgesForEveryObject(string? objectClass)
    {
        var sections = ObjectSectionCatalog.For(objectClass).ToList();
        var controls = sections.FindIndex(value => value.Key == ObjectSectionCatalog.ControlEdges);

        Assert.Equal("Saved Tier 0 path", sections[controls + 1].Title);
    }

    private static FakeAssetSource Source() => new()
    {
        Permissions = new(UserDn, SecureAD.Evidence.DescriptorAvailability.Read, null, null,
            SecureAD.Kernel.Security.DaclState.Present, SecureAD.Kernel.Security.DaclCompleteness.Complete, true, false, [], []),
        SavedPath = Result<SavedTier0Path?>.Success(Saved()),
    };

    private static AssetsViewModel OpenScreen(FakeAssetSource source)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        screen.OpenObject(new(new(UserDn, "User", Guid.NewGuid(), "user", "DC=contoso,DC=com")));
        return screen;
    }

    private static SavedTier0Path Saved()
    {
        var generation = Guid.NewGuid();
        var user = new Tier0Target(Guid.NewGuid(), UserDn, "DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-1100", null);
        var core = new Tier0Target(Guid.NewGuid(), CoreDn, "DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-512", null);
        var coverage = new Tier0Coverage(true, false, true, Tier0Limitations.None);
        var inputs = new PathInputs(generation, PathInputAvailability.Recorded, null, coverage, [core], [], [], [], [], null);
        var path = new Tier0PathResult(inputs, user, Tier0Reachability.Reachable, 1,
            [new(user, core, Tier0PathStepKind.Membership, UserDn, 0, new(core, "member", 3, UserDn), null)]);
        var time = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var description = new JudgementDescription(new('a', 64), generation, null, JudgementRunState.Completed, time, time, time);
        return new(description, path, new(description.EvidenceSeal, null, inputs, null, false, [], []), []);
    }

    private static SavedTier0PathSectionViewModel Section() => new(new(ObjectSectionCatalog.SavedTier0Path, "Saved Tier 0 path", []));

    private static SavedTier0PathSectionViewModel Read(SavedTier0Path? value)
    {
        var section = Section();
        section.Configure(UserDn, () => Result<SavedTier0Path?>.Success(value));
        section.Read();
        return section;
    }

    private static AuditError Failure() => AuditError.Create(ErrorCategory.Shell, "SyntheticSavedPathFailure",
        ErrorSeverity.Failed, "Synthetic saved-path proof failure", Bundle);
}
