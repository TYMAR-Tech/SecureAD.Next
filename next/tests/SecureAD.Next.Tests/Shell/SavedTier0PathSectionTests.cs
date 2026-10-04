using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
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
        Assert.Equal(("SEC-071 — Unexpected route to Tier 0", "High"), (section.Result, section.Severity));
    }

    [Fact]
    public void SavedPathShowsAFixedTargetWithoutInventingAHop()
    {
        var saved = NoFinding(Saved(CoreDn));
        var section = Section();
        section.ConfigureAsync(CoreDn, (_, _, _) => Task.FromResult(Result<SavedTier0Path?>.Success(
            saved with { Page = saved.Page with { IsFixedTarget = true } })));
        section.Read();
        Assert.Equal(("This object is a Tier 0 target", 0), (section.Result, Steps(section).Count));
    }

    [Fact]
    public void SavedPathDoesNotShowUncertainStepsAsAProvenRoute()
    {
        var section = Read(NoFinding(Saved(), unresolved: true));
        Assert.Contains("No SEC-071 finding was established", section.Result);
        Assert.Empty(Steps(section));
        Assert.Equal("", section.Severity);
    }

    [Fact]
    public void SavedPathShowsUnproducedAnalysisAsNoSavedResult()
    {
        var section = Read(Availability(Saved(), PathRiskAvailability.NotRequested));
        Assert.Equal("Not requested", section.Result);
    }

    [Fact]
    public void SavedPathMissingJudgementIsNotASafeAnswer() =>
        Assert.Equal("This run has no saved path result to display. This does not establish that no route exists.", Read(null).Detail);

    [Fact]
    public void SavedPathRetainsUnavailableRequiredInputs() =>
        Assert.Contains("Required inputs unavailable", Read(Availability(Saved(), PathRiskAvailability.InputsUnavailable)).Limitations);

    [Theory]
    [InlineData(null, false, "Not requested")]
    [InlineData(1, false, "Required inputs unavailable")]
    [InlineData(1, true, "Supported questions evaluated")]
    public void SavedPathUsesTypedExecutionCoverageEvenWithNoQuestions(int? version, bool completed, string expected)
    {
        var availability = version is null ? PathRiskAvailability.NotRequested
            : completed ? PathRiskAvailability.Recorded : PathRiskAvailability.InputsUnavailable;
        Assert.Equal(expected, Read(Availability(Saved(), availability)).AutomaticChecks);
    }

    [Theory]
    [InlineData("Missing captured evidence: required directory evidence is incomplete.")]
    [InlineData("Unsupported analysis: this build does not evaluate every possible relationship or operation.")]
    [InlineData("Unfinished processing: the saved input work did not complete.")]
    public void SavedPathKeepsCoverageBoundariesSeparateOnPositiveRoutes(string expected) =>
        Assert.Contains(expected, Read(WithGaps(Saved())).Limitations);

    [Fact]
    public void SavedPathPositiveRouteSurvivesIndependentCoverageGaps() =>
        Assert.Equal("SEC-071 — Unexpected route to Tier 0", Read(WithGaps(Saved())).Result);

    [Theory]
    [InlineData(PathRiskIssue.RequesterUnresolved, "requester identity")]
    [InlineData(PathRiskIssue.InputsUnavailable, "Required saved inputs")]
    [InlineData(PathRiskIssue.AuthorizationUnknown, "could not settle")]
    [InlineData(PathRiskIssue.ContinuationUnavailable, "No supported saved continuation")]
    public void SavedPathNamesQuestionLimitationsWithoutLosingTheirResource(PathRiskIssue issue, string expected)
    {
        var question = Saved().Page.Questions[0];
        var row = new SavedPathQuestionViewModel(question with
        {
            Risk = question.Risk with { Verdict = PathRiskVerdict.Unknown, ExpectednessReason = null,
                Issue = issue, Authorization = ControlEvaluationState.Unknown },
        }, Saved());
        Assert.Contains(expected, row.Explanation);
        Assert.Contains(row.RecordDetails, value => value.Label == "Target distinguished name" && value.Value == CoreDn);
        Assert.Empty(row.Steps);
    }

    [Fact]
    public void SavedPathDoesNotEquateFinishedQuestionsWithEstablishedAnswers() =>
        Assert.Contains("Unresolved access checks: 1", Read(NoFinding(Saved(), unresolved: true)).Limitations);

    [Fact]
    public void SavedQuestionsUsePagesWithoutDroppingAny()
    {
        var saved = Saved();
        var source = saved.Page.Questions[0];
        var questions = Enumerable.Range(1, 205).Select(index =>
        {
            var target = source.Risk.ReachedTarget! with { ObjectGuid = Guid.NewGuid(), DistinguishedName = $"CN=Target{index},DC=contoso,DC=com" };
            var steps = source.Steps.Select(step => step with { To = target }).ToArray();
            var proof = source.Requester! with { Request = new(UserDn, target.DistinguishedName), Target = target, Steps = steps };
            return source with { Id = index, Steps = steps, Requester = proof,
                Risk = source.Risk with { TargetDn = target.DistinguishedName, ReachedTarget = target,
                    SourceProofFingerprint = Tier0PathCalculation.Fingerprint(new SavedRequesterDaclProof(proof, source.SourceFingerprint)) } };
        }).ToArray();
        var evidence = Assert.IsType<Tier0RouteFindingEvidence>(saved.Finding!.Evidence);
        saved = saved with
        {
            Finding = saved.Finding with { Evidence = evidence with { UnexpectedChecks = questions.Length } },
            Page = saved.Page with { Counts = new(questions.Length, 0, 0, 0) },
        };
        var section = Section();
        section.ConfigureAsync(UserDn, (_, after, _) =>
        {
            var skip = checked((int)(after?.AfterId ?? 0));
            var page = questions.Skip(skip).Take(PathRiskPage.PageSize).ToArray();
            return Task.FromResult(Result<SavedTier0Path?>.Success(saved with { Page = saved.Page with
            {
                Questions = page,
                Next = skip + page.Length < questions.Length
                    ? new(saved.Description.GenerationId, UserDn, PathRiskVerdict.UnexpectedRoute, page[^1].Id) : null,
            } }));
        });
        section.Read();
        var group = Assert.Single(section.Groups);
        var destinations = new List<string>();
        do
        {
            destinations.AddRange(group.Questions.Select(value => value.Target));
            if (!group.HasNext) break;
            group.NextCommand.Execute(null);
        } while (true);
        Assert.Equal((205, 205, 5, 5, false), (destinations.Count, destinations.Distinct().Count(),
            group.PageNumber, group.Questions.Count, group.HasNext));
        group.PreviousCommand.Execute(null);
        Assert.Equal((4, 50, true), (group.PageNumber, group.Questions.Count, group.HasNext));
        Assert.Equal("Target205 (object)", destinations[^1]);
    }

    [Theory]
    [InlineData(PathUncertaintyCause.CapturedEvidenceIncomplete)]
    [InlineData(PathUncertaintyCause.AnalysisUnsupported)]
    [InlineData(PathUncertaintyCause.IdentityUnresolved)]
    [InlineData(PathUncertaintyCause.BroadPrincipalNotExpanded)]
    public void SavedPathDoesNotAttributeRunWideUncertaintyToThisAccount(PathUncertaintyCause cause)
    {
        var saved = Saved();
        var coverage = saved.Page.Coverage.PathCoverage with
        {
            InputsComplete = cause != PathUncertaintyCause.CapturedEvidenceIncomplete,
            AnalysisComplete = cause != PathUncertaintyCause.AnalysisUnsupported,
            ProcessingComplete = cause is not (PathUncertaintyCause.IdentityUnresolved or PathUncertaintyCause.BroadPrincipalNotExpanded),
        };
        var section = Read(saved with { Page = saved.Page with { Coverage = saved.Page.Coverage with { PathCoverage = coverage } } });
        Assert.Contains("not necessarily a gap affecting this object", section.Scope);
        Assert.All(section.Limitations, value => Assert.DoesNotContain(CoreDn, value));
    }

    [Fact]
    public void SavedPathShowsItsExactGenerationRatherThanLatestAttemptStatus()
    {
        var saved = Saved();
        Assert.Contains("Saved judgement generation: " + saved.Description.GenerationId, Read(saved).Provenance);
    }

    [Fact]
    public void SavedPathDoesNotClaimTheDisplayedRouteIsBestOrShortest() =>
        Assert.Equal("User can change permissions on the Domain Admins object", Assert.Single(Questions(Read(Saved()))).Heading);

    [Fact]
    public void SavedPathKeepsTheOrderedMembershipStepAndOriginalWitness()
    {
        var row = Assert.Single(Questions(Read(Saved())));
        Assert.Contains("ordinal 3", Assert.Single(row.Steps).Evidence);
        Assert.Contains(row.RecordDetails, value => value.Label == "Relationship 1 — Captured attribute" && value.Value == "member");
        Assert.Contains(row.RecordDetails, value => value.Label == "Relationship 1 — Captured value ordinal" && value.Value == "3");
        Assert.Contains(row.RecordDetails, value => value.Label == "Relationship 1 — Captured value" && value.Value == UserDn);
    }

    [Fact]
    public void SavedPathKeepsTheDestinationResourceScope()
    {
        var row = Assert.Single(Questions(Read(Saved())));
        Assert.Contains(row.RecordDetails, value => value.Label == "Reached Tier 0 target — Naming context" && value.Value == "DC=contoso,DC=com");
        Assert.Contains(row.RecordDetails, value => value.Label == "Reached Tier 0 target — Captured domain" && value.Value == "contoso.com");
    }

    [Fact]
    public void SavedPathRefusesMixedPathGenerations()
    {
        var saved = Saved();
        Assert.Equal("Saved result unavailable", Read(saved with { Page = saved.Page with
        { Coverage = saved.Page.Coverage with { GenerationId = Guid.NewGuid() } } }).Result);
    }

    [Fact]
    public void SavedPathRefusesMixedCoverageGenerations()
    {
        var saved = Saved();
        Assert.Equal("Saved result unavailable", Read(saved with { Summary = saved.Summary! with { GenerationId = Guid.NewGuid() } }).Result);
    }

    [Fact]
    public void SavedPathRefusesMixedEvidenceSeals()
    {
        var saved = Saved();
        Assert.Equal("Saved result unavailable", Read(saved with { Page = saved.Page with
        { Coverage = saved.Page.Coverage with { EvidenceSeal = new('b', 64) } } }).Result);
    }

    [Fact]
    public void SavedPathRefusesMixedDerivationGenerations()
    {
        var saved = Saved();
        Assert.Equal("Saved result unavailable", Read(saved with { Page = saved.Page with
        { Coverage = saved.Page.Coverage with { DerivationGenerationId = Guid.NewGuid() } } }).Result);
    }

    [Theory]
    [InlineData(JudgementRunState.Running)]
    [InlineData(JudgementRunState.Failed)]
    public void SavedPathRefusesUnfinishedJudgement(JudgementRunState state)
    {
        var saved = Saved();
        Assert.Equal("Saved result unavailable", Read(saved with { Description = saved.Description with { State = state } }).Result);
    }

    [Fact]
    public void SavedPathRefusesADifferentObject() =>
        Assert.Equal("Saved result unavailable", Read(Saved("CN=Other,DC=contoso,DC=com")).Result);

    [Fact]
    public void SavedPathDegradedJudgementRetainsItsWarning()
    {
        var saved = Saved();
        Assert.Contains("The saved judging completed with limitations. This is not a clean-forest result.",
            Read(saved with { Description = saved.Description with { State = JudgementRunState.CompletedDegraded } }).Limitations);
    }

    [Fact]
    public void SavedPathFailureClearsThePreviouslySuccessfulDisplay()
    {
        var section = Read(Saved());
        section.ConfigureAsync(UserDn, (_, _, _) => Task.FromResult(Result<SavedTier0Path?>.Failure(Failure())));
        section.Read();
        Assert.Equal(("Saved result unavailable", "Synthetic saved-path proof failure", 0, "", ""),
            (section.Result, section.Detail, Steps(section).Count, section.Severity, section.Provenance));
    }

    [Fact]
    public void SavedPathConfigurationDoesNotRead()
    {
        var source = new FakeAssetSource();
        var section = Section();
        section.ConfigureAsync(UserDn, (group, after, _) => Task.FromResult(source.ReadSavedTier0Path(Bundle, UserDn, group, after)));
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
        Assert.Empty(source.PathQueries);
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
        Assert.Equal("Tier 0 findings and routes", sections[controls + 1].Title);
    }

    private static SavedTier0Path WithGaps(SavedTier0Path saved) => saved with
    { Page = saved.Page with { Coverage = saved.Page.Coverage with { PathCoverage = new(false, false, false, Tier0Limitations.None) } } };

    private static SavedTier0Path NoFinding(SavedTier0Path saved, bool unresolved = false) => saved with
    {
        Finding = null,
        Summary = saved.Summary! with { AccountsWithFindings = 0, UnresolvedAccessChecks = unresolved ? 1 : 0,
            Outcome = unresolved ? RuleExecutionOutcome.Indeterminate : RuleExecutionOutcome.Succeeded },
        Page = saved.Page with { Questions = [], Counts = new(0, 0, unresolved ? 0 : 1, unresolved ? 1 : 0) },
    };

    private static SavedTier0Path Availability(SavedTier0Path saved, PathRiskAvailability availability) =>
        availability == PathRiskAvailability.Recorded ? saved : NoFinding(saved) with
        {
            Summary = saved.Summary! with { Availability = availability, Outcome = RuleExecutionOutcome.DidNotRun,
                AssessedAccounts = 0, AccountsWithFindings = 0, UnresolvedAccessChecks = 0 },
            Page = saved.Page with { Coverage = saved.Page.Coverage with { Availability = availability },
                Questions = [], Counts = new(0, 0, 0, 0) },
        };

    private static FakeAssetSource Source() => new()
    {
        Attributes = FakeAssetSource.CapturedObject(UserDn, "user"),
        Permissions = new(UserDn, DescriptorAvailability.Read, null, null,
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

    private static SavedTier0Path Saved(string requesterDn = UserDn)
    {
        var generation = Guid.NewGuid();
        var derivation = Guid.NewGuid();
        var user = new Tier0Target(Guid.NewGuid(), requesterDn, "DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-1100", null);
        var core = new Tier0Target(Guid.NewGuid(), CoreDn, "DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-512", null);
        var seal = new string('a', 64);
        var calculation = new string('c', 64);
        var time = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var description = new JudgementDescription(seal, generation, derivation, JudgementRunState.Completed, time, time, time);
        var coverage = new PathRiskCoverage(1, generation, derivation, seal, new('d', 64), calculation, PrincipalClassificationRegistry.Version,
            PathRiskAvailability.Recorded, true, new(true, false, true, Tier0Limitations.None),
            [new(PathRequesterFamily.RequesterDacl, 1, 1, 0, 0, 0),
             new(PathRequesterFamily.OwnAccountMembership, 0, 0, 0, 0, 0), new(PathRequesterFamily.MembershipDacl, 0, 0, 0, 0, 0)]);
        var risk = new PathRequesterRiskAssessment(generation, derivation, seal, calculation, new('e', 64),
            PathRequesterFamily.RequesterDacl, requesterDn, CoreDn, null, null, core, ControlEvaluationState.Established,
            PathRiskVerdict.UnexpectedRoute, null, ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane,
            new(user, derivation, new('d', 64), 4, true, new('f', 64), MembershipRouteIncompleteReason.None, []), null, null);
        Tier0PathStep[] steps = [new(user, core, Tier0PathStepKind.Membership, requesterDn, 0, new(core, "member", 3, requesterDn), null)];
        var proof = new RequesterDaclAssessment(new(requesterDn, CoreDn), generation, derivation, seal,
            user, core, ControlEvaluationState.Established, [], [], [], steps);
        var question = new PathRiskQuestion(1, risk, new('f', 64), steps, proof, null, null);
        var finding = new Finding("SEC-071", 1, Severity.High, new(FindingSubjectKind.Account, user.ObjectGuid!.Value.ToString("D")),
            user.ObjectGuid.Value, requesterDn, "contoso.com", "user", "Unexpected route", EvidenceCompleteness.Complete,
            new Tier0RouteFindingEvidence(generation, derivation, seal, calculation, "Tier0ControlPlane",
                user.ObjectGuid.Value, user.Sid!, requesterDn, 1, new('f', 64))) { PrincipalName = "User" };
        return new(description, new(1, generation, derivation, seal, calculation, 1, PathRiskAvailability.Recorded,
            RuleExecutionOutcome.Succeeded, 1, 1, 0), finding,
            new(coverage, requesterDn, PathRiskVerdict.UnexpectedRoute, new(1, 0, 0, 0), [question], null, false), []);
    }

    private static SavedTier0PathSectionViewModel Section() => new(new(ObjectSectionCatalog.SavedTier0Path, "Tier 0 findings and routes", []));
    private static IReadOnlyList<SavedPathQuestionViewModel> Questions(SavedTier0PathSectionViewModel section) =>
        section.Groups.SelectMany(group => group.Questions).ToArray();
    private static IReadOnlyList<SavedPathStepViewModel> Steps(SavedTier0PathSectionViewModel section) =>
        Questions(section).SelectMany(question => question.Steps).ToArray();

    private static SavedTier0PathSectionViewModel Read(SavedTier0Path? value)
    {
        var section = Section();
        section.ConfigureAsync(UserDn, (_, _, _) => Task.FromResult(Result<SavedTier0Path?>.Success(value)));
        section.Read();
        return section;
    }

    private static AuditError Failure() => AuditError.Create(ErrorCategory.Shell, "SyntheticSavedPathFailure",
        ErrorSeverity.Failed, "Synthetic saved-path proof failure", Bundle);
}
