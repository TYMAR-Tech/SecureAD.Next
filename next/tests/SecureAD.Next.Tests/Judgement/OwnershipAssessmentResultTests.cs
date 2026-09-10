using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class OwnershipAssessmentResultTests
{
    [Fact]
    public void AMatchingExplicitCompletedEmptyAssessmentIsAvailable()
    {
        var result = Result();
        Assert.Equal(OwnershipAssessmentAvailability.Available, result.CheckBinding(result.Binding));
    }

    [Fact]
    public void AnExplicitRequestDoesNotChangeTheRecordedAutomaticScope()
    {
        var result = Result();
        Assert.Equal(OwnershipScopeState.OutsideComputedScope, result.Scope.State);
    }

    [Fact]
    public void AChangedEvidenceSealMakesTheResultStale()
    {
        var result = Result();
        var expected = result.Binding with { Input = result.Binding.Input with { EvidenceSeal = new string('E', 64) } };
        Assert.Equal(OwnershipAssessmentAvailability.Stale, result.CheckBinding(expected));
    }

    [Fact]
    public void AChangedDerivationGenerationMakesTheResultStale()
    {
        var result = Result();
        var expected = result.Binding with { Input = result.Binding.Input with { DerivationGenerationId = Guid.NewGuid() } };
        Assert.Equal(OwnershipAssessmentAvailability.Stale, result.CheckBinding(expected));
    }

    [Fact]
    public void AChangedJudgementGenerationMakesTheResultStale()
    {
        var result = Result();
        Assert.Equal(OwnershipAssessmentAvailability.Stale,
            result.CheckBinding(result.Binding with { JudgementGenerationId = Guid.NewGuid() }));
    }

    [Fact]
    public void AChangedTargetGuidMakesTheResultStale()
    {
        var result = Result();
        Assert.Equal(OwnershipAssessmentAvailability.Stale,
            result.CheckBinding(result.Binding with { Target = result.Binding.Target with { ObjectGuid = Guid.NewGuid() } }));
    }

    [Fact]
    public void AChangedOwnerRightsContextMakesTheResultStale()
    {
        var result = Result();
        Assert.Equal(OwnershipAssessmentAvailability.Stale,
            result.CheckBinding(result.Binding with { OwnerRightsContextHash = new string('F', 64) }));
    }

    [Fact]
    public void AChangedForestContextMakesTheResultStale()
    {
        var result = Result();
        Assert.Equal(OwnershipAssessmentAvailability.Stale, result.CheckBinding(result.Binding with
        { Input = result.Binding.Input with { ForestRootNamingContext = "DC=another,DC=com" } }));
    }

    [Fact]
    public void AChangedEvaluationTimeMakesTheResultStale()
    {
        var result = Result();
        Assert.Equal(OwnershipAssessmentAvailability.Stale, result.CheckBinding(result.Binding with
        { EvaluationAsOf = result.Binding.EvaluationAsOf.AddMinutes(1) }));
    }

    [Fact]
    public void UnsupportedEvaluatorVersionIsNotAnUnknownDirectoryConclusion()
    {
        var result = Result();
        var changed = result with { Binding = result.Binding with { EvaluatorVersion = 2 } };
        Assert.Equal(OwnershipAssessmentAvailability.UnsupportedVersion, changed.CheckBinding(result.Binding));
    }

    [Fact]
    public void UnsupportedClassificationVersionCannotBeReused()
    {
        var result = Result();
        var changed = result with { Binding = result.Binding with { Input = result.Binding.Input with { PolicyVersion = 2 } } };
        Assert.Equal(OwnershipAssessmentAvailability.UnsupportedVersion, changed.CheckBinding(result.Binding));
    }

    [Fact]
    public void MalformedSourceSealIsInvalidRatherThanStale()
    {
        var result = Result();
        var changed = result with { Binding = result.Binding with { Input = result.Binding.Input with { EvidenceSeal = "not-a-seal" } } };
        Assert.Equal(OwnershipAssessmentAvailability.InvalidProof, changed.CheckBinding(result.Binding));
    }

    [Fact]
    public void ScopeCannotBeAttachedToAnotherTarget()
    {
        var result = Result();
        var changed = result with { Scope = result.Scope with { Target = result.Scope.Target with { ObjectGuid = Guid.NewGuid() } } };
        Assert.Equal(OwnershipAssessmentAvailability.InvalidProof, changed.CheckBinding(result.Binding));
    }

    [Fact]
    public void IncompleteScopeCannotClaimOutsideComputedScope()
    {
        var result = Result();
        var changed = result with { Scope = result.Scope with { Coverage = new(false, false, true, Tier0Limitations.InputIncomplete) } };
        Assert.Equal(OwnershipAssessmentAvailability.InvalidProof, changed.CheckBinding(result.Binding));
    }

    [Fact]
    public void AnAutomaticAssessmentCannotRunOutsideItsSelectedScope()
    {
        var result = Result();
        var changed = result with { Origin = OwnershipAssessmentOrigin.AutomaticAudit, Binding = result.Binding with { JudgementSeal = null } };
        Assert.False(changed.CanPublish);
    }

    [Fact]
    public void NotAssessedIsAvailableAsAStatusButNotAPublishableAssessment()
    {
        var result = Result();
        var changed = result with { Origin = OwnershipAssessmentOrigin.AutomaticAudit,
            Binding = result.Binding with { JudgementSeal = null }, Execution = OwnershipAssessmentExecution.NotAssessed };
        Assert.Equal((OwnershipAssessmentAvailability.Available, false), (changed.CheckBinding(changed.Binding), changed.CanPublish));
    }

    [Theory]
    [InlineData(OwnershipAssessmentExecution.Cancelled)]
    [InlineData(OwnershipAssessmentExecution.Failed)]
    public void FailedOrCancelledAttemptsCannotReplaceAPublishedResult(OwnershipAssessmentExecution execution)
    {
        var result = Result() with { Execution = execution };
        Assert.False(result.CanPublish);
    }

    [Fact]
    public void UnknownCandidatesRequireTheOpenOwnerAssignmentGate()
    {
        var result = Result() with { Execution = OwnershipAssessmentExecution.CompletedWithLimitations, Candidates = [Candidate()] };
        Assert.Equal(OwnershipAssessmentAvailability.Available, result.CheckBinding(result.Binding));
    }

    [Fact]
    public void AClickCannotPromoteAnOwnerTransitionToEstablished()
    {
        var result = Result() with { Execution = OwnershipAssessmentExecution.CompletedWithLimitations,
            Candidates = [Candidate() with { State = ControlEvaluationState.Established }] };
        Assert.Equal(OwnershipAssessmentAvailability.InvalidProof, result.CheckBinding(result.Binding));
    }

    [Fact]
    public void OmittingTheOwnerAssignmentGateIsNotAValidProof()
    {
        var result = Result() with { Execution = OwnershipAssessmentExecution.CompletedWithLimitations,
            Candidates = [Candidate() with { Preconditions = [] }] };
        Assert.Equal(OwnershipAssessmentAvailability.InvalidProof, result.CheckBinding(result.Binding));
    }

    [Fact]
    public void UnknownCandidateCannotClaimUnqualifiedCompletion()
    {
        var result = Result() with { Candidates = [Candidate()] };
        Assert.False(result.CanPublish);
    }

    [Fact]
    public void DuplicateSourceCandidatesCannotMultiplyResults()
    {
        var result = Result() with { Execution = OwnershipAssessmentExecution.CompletedWithLimitations,
            Candidates = [Candidate(), Candidate()] };
        Assert.False(result.CanPublish);
    }

    [Fact]
    public void AnExplicitResultRequiresTheSourceAuditSeal()
    {
        var result = Result();
        result = result with { Binding = result.Binding with { JudgementSeal = null } };
        Assert.False(result.CanPublish);
    }

    [Fact]
    public void ARelationFromAnotherAuditCannotJustifyAutomaticScope()
    {
        var (input, controller, affected, edge) = Tier0RelevanceRelationTests.Source();
        var relation = Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge);
        var binding = new OwnershipAssessmentBinding(input, controller, Guid.NewGuid(), null, DateTimeOffset.UnixEpoch, new string('D', 64));
        var scope = new OwnershipScopeDecision(input, controller, OwnershipScopeState.Included,
            new(true, false, true, Tier0Limitations.ControlQualificationUnsupported), null, [relation]);
        var result = new OwnershipAssessmentResult(Guid.NewGuid(), binding, OwnershipAssessmentOrigin.AutomaticAudit,
            scope, OwnershipAssessmentExecution.Completed, []);
        Assert.Equal(OwnershipAssessmentAvailability.InvalidProof, result.CheckBinding(binding));
    }

    private static OwnershipCandidateAssessment Candidate() => new(1, "S-1-5-21-1-2-3-1200", null,
        ControlEvaluationState.Unknown, [new("CanSetTakeoverOwnerSid", ControlEvaluationState.Unknown, "0103;0112")]);

    private static OwnershipAssessmentResult Result()
    {
        var evidence = new Tier0TestEvidence();
        var target = evidence.Target(evidence.Principal("Ordinary", "S-1-5-21-1-2-3-1300", "user"));
        var input = evidence.Binding;
        var binding = new OwnershipAssessmentBinding(input, target, Guid.NewGuid(), new string('C', 64), DateTimeOffset.UnixEpoch, new string('D', 64));
        var scope = new OwnershipScopeDecision(input, target, OwnershipScopeState.OutsideComputedScope,
            new(true, true, true, Tier0Limitations.None), null, []);
        return new(Guid.NewGuid(), binding, OwnershipAssessmentOrigin.ExplicitObjectRequest, scope, OwnershipAssessmentExecution.Completed, []);
    }
}
