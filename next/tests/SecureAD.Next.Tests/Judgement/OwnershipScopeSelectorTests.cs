using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class OwnershipScopeSelectorTests
{
    [Fact]
    public void IncomingControllerIsIncludedWithoutIncludingEverythingTheRootManages()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.Root, graph.Ordinary, 2));
        Assert.Equal((OwnershipScopeState.Included, OwnershipScopeState.Included, OwnershipScopeState.Undetermined),
            (result.For(graph.Target(graph.Root)).State, result.For(graph.Target(graph.A)).State, result.For(graph.Target(graph.Ordinary)).State));
    }

    [Fact]
    public void SelectionRecordsItsOwnSemanticVersion()
    {
        var graph = new Graph();
        Assert.Equal(1, graph.Select().SelectorVersion);
    }

    [Fact]
    public void ControllersOfControllersAreSelectedWithoutBeingRelabelledTier0()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.A, 2));
        var decision = result.For(graph.Target(graph.B));
        Assert.Equal((OwnershipScopeState.Included, Tier0State.Unknown), (decision.State, decision.Classification?.State));
    }

    [Fact]
    public void AnchoredCyclesTerminateAfterOneVisitPerTarget()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.A, 2), graph.Link(graph.A, graph.B, 3));
        Assert.Equal((3, 3), (result.VisitedTargets, result.ExaminedRelations));
    }

    [Fact]
    public void AnUnanchoredCycleDoesNotCreateImportance()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.B, 1), graph.Link(graph.B, graph.A, 2));
        Assert.Equal(new[] { graph.Target(graph.Root) }, result.Decisions.Where(item => item.State == OwnershipScopeState.Included).Select(item => item.Target));
    }

    [Fact]
    public void IndependentOwnerAndDaclGrantsRemainSeparateReasons()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.A, graph.Root, 2, ControlCapability.CanWriteDacl));
        Assert.Equal(new long?[] { 1, 2 }, result.For(graph.Target(graph.A)).Reasons.Select(item => item.ControlEdgeId));
    }

    [Fact]
    public void RepeatedSourceRelationsDoNotMultiplyWork()
    {
        var graph = new Graph();
        var link = graph.Link(graph.A, graph.Root, 1);
        var result = graph.Select(link, link);
        Assert.Equal((1, 1), (result.Relations.Length, result.ExaminedRelations));
    }

    [Fact]
    public void ASharedControllerRetainsBothRoutesWithoutRepeatedVisits()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.Root, 2),
            graph.Link(graph.Ordinary, graph.A, 3), graph.Link(graph.Ordinary, graph.B, 4));
        Assert.Equal((4, 4, 2), (result.VisitedTargets, result.ExaminedRelations, result.For(graph.Target(graph.Ordinary)).Reasons.Length));
    }

    [Fact]
    public void DisprovenIncomingRelationIsCountedAsExaminedWithoutSelectingItsHolder()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1, state: ControlEvaluationState.NotEstablished));
        Assert.Equal(1, result.ExaminedRelations);
    }

    [Fact]
    public void ADisprovenGrantDoesNotHideAnIndependentPossibleGrant()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1, state: ControlEvaluationState.NotEstablished),
            graph.Link(graph.A, graph.Root, 2, ControlCapability.CanWriteDacl));
        Assert.Equal(new long?[] { 2 }, result.For(graph.Target(graph.A)).Reasons.Select(item => item.ControlEdgeId));
    }

    [Fact]
    public void AnUnverifiedOwnerTransitionRemainsASelectionCandidate()
    {
        var graph = new Graph();
        var relation = graph.Link(graph.A, graph.Root, 1, ControlCapability.CanBecomeOwnerAndRewriteDacl,
            ControlEvaluationState.Unknown, ControlUncertainty.OwnerTransitionLabRequired);
        var result = graph.Select(relation);
        Assert.Equal((OwnershipScopeState.Included, Tier0State.Unknown), (result.For(graph.Target(graph.A)).State, relation.State));
    }

    [Theory]
    [InlineData(ControlUncertainty.HolderUnresolved)]
    [InlineData(ControlUncertainty.HolderIsPlaceholder)]
    [InlineData(ControlUncertainty.ResourceContextUnverified)]
    public void UnresolvedIdentityOrResourceContextDoesNotPropagateSelection(ControlUncertainty uncertainty)
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1, uncertainty: uncertainty));
        Assert.Equal((OwnershipScopeState.Undetermined, true),
            (result.For(graph.Target(graph.A)).State, result.Coverage.Limitations.HasFlag(Tier0Limitations.IdentityUnverified)));
    }

    [Fact]
    public void AConflictingGuidBlocksTheAffectedSeedInsteadOfPickingAnAlias()
    {
        var graph = new Graph();
        var alias = graph.Target(graph.A) with { ObjectGuid = graph.Root.ObjectGuid };
        var result = graph.Select(graph.Link(alias, graph.Target(graph.Root), 1));
        Assert.Empty(result.Decisions.Where(item => item.State == OwnershipScopeState.Included));
    }

    [Fact]
    public void ConflictingSidIdentitiesStayUnresolved()
    {
        var graph = new Graph();
        var alias = graph.Target(graph.A) with { ObjectGuid = Guid.NewGuid(), DistinguishedName = "CN=Alias," + graph.Evidence.Domain.DistinguishedName };
        var result = graph.Select(graph.Link(alias, graph.Target(graph.Root), 1));
        Assert.Equal(OwnershipScopeState.Undetermined, result.For(alias).State);
    }

    [Fact]
    public void BuiltinPrincipalsInDifferentDomainsAreNotMerged()
    {
        var graph = new Graph();
        var first = new Tier0Target(Guid.NewGuid(), "CN=Administrators,CN=Builtin,DC=one,DC=com", "DC=one,DC=com",
            "one.com", "S-1-5-32-544", "one.com");
        var second = new Tier0Target(Guid.NewGuid(), "CN=Administrators,CN=Builtin,DC=two,DC=com", "DC=two,DC=com",
            "two.com", "S-1-5-32-544", "two.com");
        var result = graph.Select(graph.Link(first, graph.Target(graph.Root), 1), graph.Link(second, graph.Target(graph.Root), 2));
        Assert.Equal((OwnershipScopeState.Included, OwnershipScopeState.Included), (result.For(first).State, result.For(second).State));
    }

    [Fact]
    public void ARelationFromAnotherAuditIsRejected()
    {
        var graph = new Graph();
        var relation = graph.Link(graph.Target(graph.A), graph.Target(graph.Root), 1, audit: Guid.NewGuid());
        Assert.Throws<ArgumentException>(() => graph.Select(relation));
    }

    [Fact]
    public void ARelationFromAnotherCaptureIsRejected()
    {
        var graph = new Graph();
        var relation = graph.Link(graph.Target(graph.A), graph.Target(graph.Root), 1,
            input: graph.Input with { EvidenceSeal = new string('C', 64) });
        Assert.Throws<ArgumentException>(() => graph.Select(relation));
    }

    [Fact]
    public void AClassificationFromAnotherCaptureIsRejected()
    {
        var graph = new Graph();
        var classification = Tier0Classifier.Qualify(graph.Input with { EvidenceSeal = new string('C', 64) },
            graph.Target(graph.Root), graph.Evidence.Input(graph.Objects), routes: null);
        Assert.Throws<ArgumentException>(() => OwnershipScopeSelector.Select(graph.Input, graph.Audit, [classification], [], graph.Coverage, CancellationToken.None, progress: null));
    }

    [Fact]
    public void ConflictingPayloadsForOneSourceEdgeAreRejected()
    {
        var graph = new Graph();
        Assert.Throws<ArgumentException>(() => graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.Root, 1)));
    }

    [Fact]
    public void EquivalentRepeatedClassificationsAreNotTreatedAsAmbiguous()
    {
        var graph = new Graph();
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, graph.Classifications.Concat(graph.Classifications), [], graph.Coverage, CancellationToken.None, progress: null);
        Assert.Equal((4, OwnershipScopeState.Included), (result.Classifications.Length, result.For(graph.Target(graph.Root)).State));
    }

    [Fact]
    public void ConflictingClassificationsCannotSupplyASeed()
    {
        var graph = new Graph();
        var incomplete = Tier0Classifier.Qualify(graph.Input, graph.Target(graph.Root), graph.Evidence.Input(graph.Objects) with { IsComplete = false }, routes: null);
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, [.. graph.Classifications, incomplete], [], graph.Coverage, CancellationToken.None, progress: null);
        Assert.Equal(OwnershipScopeState.Undetermined, result.For(graph.Target(graph.Root)).State);
    }

    [Fact]
    public void CompletingTraversalDoesNotEraseUnsupportedDependencyCoverage()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1));
        Assert.Equal((true, false, true), (result.Coverage.ProcessingComplete, result.Coverage.IsComplete,
            result.Coverage.Limitations.HasFlag(Tier0Limitations.DependencyQualificationUnsupported)));
    }

    [Fact]
    public void AnUnlistedObjectDoesNotBecomeAnOutsideScopeAnswer()
    {
        var graph = new Graph();
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, [], [], graph.Coverage, CancellationToken.None, progress: null);
        Assert.Equal(OwnershipScopeState.Undetermined, result.For(graph.Target(graph.A)).State);
    }

    [Fact]
    public void AMissingClassificationCanRetainACapturedControllerWithIncompleteCoverage()
    {
        var graph = new Graph();
        var root = graph.Classifications.Single(item => item.Target == graph.Target(graph.Root));
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, [root], [graph.Link(graph.A, graph.Root, 1)], graph.Coverage, CancellationToken.None, progress: null);
        Assert.Equal((OwnershipScopeState.Included, false), (result.For(graph.Target(graph.A)).State, result.Coverage.InputsComplete));
    }

    [Fact]
    public void PreCancellationDoesNotInventAnOutsideScopeResult()
    {
        var graph = new Graph();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, graph.Classifications, [], graph.Coverage, cancellation.Token, progress: null);
        Assert.Equal((true, false, OwnershipScopeState.Undetermined),
            (result.WasCancelled, result.Coverage.ProcessingComplete, result.For(graph.Target(graph.Root)).State));
    }

    [Fact]
    public void MidTraversalCancellationRetainsDiscoveredInclusionsAndTheirReasons()
    {
        var graph = new Graph();
        using var cancellation = new CancellationTokenSource();
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, graph.Classifications,
            [graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.A, 2)], graph.Coverage, cancellation.Token,
            new InlineProgress(_ => cancellation.Cancel()));
        Assert.Equal((true, OwnershipScopeState.Included, 1, OwnershipScopeState.Undetermined),
            (result.WasCancelled, result.For(graph.Target(graph.A)).State, result.For(graph.Target(graph.A)).Reasons.Length,
                result.For(graph.Target(graph.B)).State));
    }

    [Fact]
    public void CancellationDuringInputReadRetainsConsumedWitnessesButNoFalseCompleteScope()
    {
        var graph = new Graph();
        using var cancellation = new CancellationTokenSource();
        var root = graph.Classifications.Single(item => item.Target == graph.Target(graph.Root));
        var result = OwnershipScopeSelector.Select(graph.Input, graph.Audit, CancelInput(root, cancellation), [], graph.Coverage, cancellation.Token, progress: null);
        Assert.Equal((1, true, false), (result.Classifications.Length, result.WasCancelled, result.Coverage.InputsComplete));
    }

    [Fact]
    public void AnUnrelatedProgressFailureIsNotReportedAsCallerCancellation()
    {
        var graph = new Graph();
        using var other = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => OwnershipScopeSelector.Select(graph.Input, graph.Audit,
            graph.Classifications, [], graph.Coverage, CancellationToken.None,
            progress: new InlineProgress(_ => throw new OperationCanceledException(other.Token))));
    }

    [Fact]
    public void InputOrderDoesNotChangeDecisionsOrIndependentReasons()
    {
        var graph = new Graph();
        var links = new[] { graph.Link(graph.A, graph.Root, 2), graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.A, 3) };
        var first = graph.Select(links);
        var second = OwnershipScopeSelector.Select(graph.Input, graph.Audit, graph.Classifications.Reverse(), links.Reverse(), graph.Coverage, CancellationToken.None, progress: null);
        Assert.Equal(Signature(first), Signature(second));
    }

    [Fact]
    public void QualifiedMembershipWitnessesAreReusedWithoutANewExpansion()
    {
        var evidence = new Tier0TestEvidence();
        var member = evidence.Principal("Member", "S-1-5-21-1-2-3-1200", "user");
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512", "group",
            Tier0TestEvidence.Attribute("groupType", "-2147483646"), Tier0TestEvidence.Attribute("member", member.DistinguishedName));
        var input = evidence.Input(member, root);
        var rootFact = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(root), input, routes: null);
        var memberFact = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), input, evidence.Routes(member, root));
        var relation = Tier0RelevanceRelation.FromMembership(memberFact, 0);
        var result = OwnershipScopeSelector.Select(evidence.Binding, Guid.NewGuid(), [rootFact, memberFact], [relation, relation],
            new(true, true, true, Tier0Limitations.None), CancellationToken.None, progress: null);
        Assert.Equal((2, 1, Tier0Basis.EffectiveMembership),
            (result.VisitedTargets, result.Relations.Length, result.For(evidence.Target(member)).Classification?.Supports[0].Basis));
    }

    [Fact]
    public void EveryProducedDecisionSatisfiesTheExistingOwnershipContract()
    {
        var graph = new Graph();
        var result = graph.Select(graph.Link(graph.A, graph.Root, 1), graph.Link(graph.B, graph.A, 2));
        Assert.All(result.Decisions, decision => Assert.True(decision.IsValid));
    }

    [Fact]
    public void UnknownCoverageFlagsCannotClaimARecognizedScope()
    {
        var graph = new Graph();
        Assert.Throws<ArgumentException>(() => OwnershipScopeSelector.Select(graph.Input, graph.Audit, [], [],
            graph.Coverage with { Limitations = (Tier0Limitations)(1 << 30) }, CancellationToken.None, progress: null));
    }

    private static IEnumerable<Tier0Classification> CancelInput(Tier0Classification first, CancellationTokenSource cancellation)
    {
        yield return first;
        cancellation.Cancel();
        yield return first;
    }

    private static IEnumerable<string> Signature(OwnershipScopeSelection selection) => selection.Decisions.Select(item =>
        $"{item.Target.DistinguishedName}:{item.State}:{string.Join(',', item.Reasons.Select(reason => reason.ControlEdgeId))}");

    private sealed class InlineProgress(Action<OwnershipScopeProgress> action) : IProgress<OwnershipScopeProgress>
    {
        public void Report(OwnershipScopeProgress value) => action(value);
    }

    private sealed class Graph
    {
        internal Tier0TestEvidence Evidence { get; } = new();
        internal Guid Audit { get; } = Guid.NewGuid();
        internal ObjectAttributes Root { get; }
        internal ObjectAttributes A { get; }
        internal ObjectAttributes B { get; }
        internal ObjectAttributes Ordinary { get; }
        internal Tier0InputBinding Input => Evidence.Binding;
        internal Tier0Coverage Coverage => new(true, true, true, Tier0Limitations.None);
        internal ObjectAttributes[] Objects => [Root, A, B, Ordinary];
        internal Tier0Classification[] Classifications => Objects.Select(item => Tier0Classifier.Qualify(Input,
            Target(item), Evidence.Input(Objects), routes: null)).ToArray();

        internal Graph()
        {
            Root = Evidence.Principal("Root", "S-1-5-21-1-2-3-512");
            A = Evidence.Principal("A", "S-1-5-21-1-2-3-1201", "user");
            B = Evidence.Principal("B", "S-1-5-21-1-2-3-1202", "user");
            Ordinary = Evidence.Principal("Ordinary", "S-1-5-21-1-2-3-1203", "user");
        }

        internal Tier0Target Target(ObjectAttributes item) => Evidence.Target(item);
        internal OwnershipScopeSelection Select(params Tier0RelevanceRelation[] relations) =>
            OwnershipScopeSelector.Select(Input, Audit, Classifications, relations, Coverage, CancellationToken.None, progress: null);
        internal Tier0RelevanceRelation Link(ObjectAttributes controller, ObjectAttributes affected, long id,
            ControlCapability capability = ControlCapability.CanSetOwner, ControlEvaluationState state = ControlEvaluationState.Established,
            ControlUncertainty uncertainty = ControlUncertainty.None) =>
            Link(Target(controller), Target(affected), id, capability, state, uncertainty);
        internal Tier0RelevanceRelation Link(Tier0Target controller, Tier0Target affected, long id,
            ControlCapability capability = ControlCapability.CanSetOwner, ControlEvaluationState state = ControlEvaluationState.Established,
            ControlUncertainty uncertainty = ControlUncertainty.None, Guid? audit = null, Tier0InputBinding? input = null)
        {
            var edge = new ControlEdge(id, affected.ObjectGuid, affected.DistinguishedName, "group",
                controller.Sid ?? throw new InvalidOperationException(), null, controller.SidScope, capability,
                state, uncertainty, ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane,
                3, audit ?? Audit, Evidence.Generation, true, [], [], MembershipRouteSummary.NotDerived);
            return Tier0RelevanceRelation.FromControlEdge(input ?? Input, controller, affected, edge);
        }
    }
}
