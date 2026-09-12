using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// The acceptance cases of decision 0116, covering discovery admission from captured facts.
/// </summary>
/// <remarks>
/// <para>
/// <b>Expectations here are stated from the fixtures and the decision, not produced by the code
/// under test.</b> Each test builds a small capture whose correct answer is arguable from the ACEs
/// alone, then asserts that answer. Running discovery to obtain the expected result would make the
/// suite agree with itself regardless of whether it is right.
/// </para>
/// <para>
/// New identifiers, per 0116: the old all-object control counts are history rather than oracles, and
/// nothing here edits a frozen expectation to accommodate the reduced products.
/// </para>
/// </remarks>
public sealed class Tier0DiscoveryAdmissionTests
{
    [Fact]
    public void AnUnrelatedOrdinaryAccountProducesNoCandidateAtAll()
    {
        var lab = new Lab();
        Assert.DoesNotContain(lab.Run().Candidates(),
            relation => relation.Controller.DistinguishedName == lab.Jimmy.DistinguishedName);
    }

    [Fact]
    public void AnUnrelatedOrdinaryAccountIsStillRecordedAsCaptured()
    {
        var lab = new Lab();
        Assert.True(lab.Run().Observed.ContainsKey(lab.Jimmy.DistinguishedName));
    }

    [Fact]
    public void AnUnrelatedOrdinaryAccountIsNotAdmittedForAssessment()
    {
        var lab = new Lab();
        Assert.Equal(OwnershipScopeState.Undetermined, lab.Select().For(lab.Target(lab.Jimmy)).State);
    }

    [Fact]
    public void AnAccountGrantedWriteDaclOnATierZeroGroupIsAdmitted()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        Assert.Equal(OwnershipScopeState.Included, lab.Select().For(lab.Target(lab.Helpdesk)).State);
    }

    [Fact]
    public void AnAdmittedAccountIsNotRelabelledTierZero()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        Assert.NotEqual(Tier0State.Established, lab.Select().For(lab.Target(lab.Helpdesk)).Classification?.State);
    }

    [Fact]
    public void JimmyReachedThroughASupportedRouteIsAdmittedWithASourceLinkedReason()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        lab.Describe(lab.Helpdesk, entries: [lab.Allow(3, lab.Jimmy, Lab.WriteDacl)]);
        var decision = lab.Select().For(lab.Target(lab.Jimmy));
        Assert.Equal((OwnershipScopeState.Included, lab.Helpdesk.DistinguishedName, (int?)3),
            (decision.State, decision.Reasons.Single().Witness?.TargetDn, decision.Reasons.Single().Witness?.PermissionOrdinal));
    }

    [Fact]
    public void ATierZeroAdministratorManagingAnOrdinaryUserDoesNotAdmitThatUser()
    {
        var lab = new Lab();

        // The outgoing direction: the Tier-0 group controls Jimmy, which is what an administrator is
        // supposed to be able to do. Only incoming control admits a target.
        lab.Describe(lab.Jimmy, entries: [lab.Allow(0, lab.DomainAdmins, Lab.WriteDacl)]);
        Assert.Equal(OwnershipScopeState.Undetermined, lab.Select().For(lab.Target(lab.Jimmy)).State);
    }

    [Fact]
    public void ADirectWriteDaclRouteNeedsNoOwnershipTransitionToBeDiscovered()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, ownerSid: null, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        var candidate = lab.Run().Candidates().Single(item => item.Controller.DistinguishedName == lab.Helpdesk.DistinguishedName);
        Assert.Equal(ControlCapability.CanWriteDacl, candidate.Capability);
    }

    [Fact]
    public void AConditionalOwnerRouteIsRetainedWithoutClaimingTakeover()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteOwner)]);
        var candidate = lab.Run().Candidates().Single(item => item.Controller.DistinguishedName == lab.Helpdesk.DistinguishedName);
        Assert.Equal((ControlCapability.CanSetOwner, Tier0State.Unknown, true),
            (candidate.Capability, candidate.State, candidate.Limitations.HasFlag(Tier0Limitations.ConditionalOperation)));
    }

    [Fact]
    public void TheCapturedOwnerIsRetainedAsAPossibleControllerWithoutAnAceOrdinal()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, ownerSid: lab.SidOf(lab.Helpdesk));
        var candidate = lab.Run().Candidates().Single(item => item.Controller.DistinguishedName == lab.Helpdesk.DistinguishedName);
        Assert.Equal((ControlCapability.IsOwnerAndCanRewriteDacl, true, (int?)null),
            (candidate.Capability, candidate.Witness!.IsOwner, candidate.Witness.PermissionOrdinal));
    }

    [Fact]
    public void ADenyEntryDoesNotAdmitItsTrusteeAsAController()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [Tier0DiscoveryEvidence.Deny(0, lab.Helpdesk, Lab.WriteDacl)]);
        Assert.Empty(lab.Run().Candidates());
    }

    [Fact]
    public void DiamondRoutesRetainBothWitnessesWithOneAssessmentPerTarget()
    {
        var lab = new Lab();
        var second = lab.Evidence.Principal("SecondRoute", "1450", "user");
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl), lab.Allow(1, second, Lab.WriteDacl)]);
        lab.Describe(lab.Helpdesk, entries: [lab.Allow(0, lab.Jimmy, Lab.WriteDacl)]);
        lab.Describe(second, entries: [lab.Allow(0, lab.Jimmy, Lab.WriteDacl)]);
        var result = lab.Select();
        Assert.Equal((2, OwnershipScopeState.Included),
            (result.For(lab.Target(lab.Jimmy)).Reasons.Length, result.For(lab.Target(lab.Jimmy)).State));
    }

    [Fact]
    public void ACycleTerminatesRatherThanTraversingForever()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        lab.Describe(lab.Helpdesk, entries: [lab.Allow(0, lab.Jimmy, Lab.WriteDacl)]);
        lab.Describe(lab.Jimmy, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        Assert.Equal(OwnershipScopeState.Included, lab.Select().For(lab.Target(lab.Jimmy)).State);
    }

    [Fact]
    public void AnUnreadableDescriptorIsRecordedAsUnavailableRatherThanEmpty()
    {
        var lab = new Lab();
        lab.Evidence.Unreadable(lab.DomainAdmins);
        Assert.Contains(lab.Run().Coverage().Limitations,
            item => item.Reason == Tier0DiscoveryReason.DescriptorUnavailable && item.TargetDn == lab.DomainAdmins.DistinguishedName);
    }

    [Fact]
    public void AnIncompleteDaclIsRecordedRatherThanTreatedAsWhollySeen()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, completeness: DaclCompleteness.Incomplete, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        Assert.Contains(lab.Run().Coverage().Limitations, item => item.Reason == Tier0DiscoveryReason.DescriptorIncomplete);
    }

    [Fact]
    public void ABroadPrincipalIsOneWitnessedCandidateAndNotAnExpansion()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries:
            [Tier0DiscoveryEvidence.AllowSid(2, Tier0DiscoveryEvidence.Everyone, Lab.WriteDacl, "Everyone")]);
        var coverage = lab.Run().Coverage();
        Assert.Equal((1, (int?)2, Tier0DiscoveryEvidence.Everyone),
            (coverage.Limitations.Count(item => item.Reason == Tier0DiscoveryReason.BroadTrustee),
             coverage.Limitations.First(item => item.Reason == Tier0DiscoveryReason.BroadTrustee).PermissionOrdinal,
             coverage.Limitations.First(item => item.Reason == Tier0DiscoveryReason.BroadTrustee).TrusteeSid));
    }

    [Fact]
    public void ABroadPrincipalDoesNotBecomeACandidateForEveryAccount()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries:
            [Tier0DiscoveryEvidence.AllowSid(0, Tier0DiscoveryEvidence.Everyone, Lab.WriteDacl, "Everyone")]);
        Assert.Empty(lab.Run().Candidates());
    }

    [Fact]
    public void ANullDaclIsRecordedAsBroadRatherThanAsNoPermissions()
    {
        var lab = new Lab();
        lab.Evidence.NullDacl(lab.DomainAdmins);
        var reasons = lab.Run().Coverage().Limitations.Select(item => item.Reason).ToArray();
        Assert.Contains(Tier0DiscoveryReason.NullDacl, reasons);
    }

    [Fact]
    public void AnUnresolvedTrusteeIsRetainedAsIncompleteCoverage()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries:
            [Tier0DiscoveryEvidence.AllowSid(5, "S-1-5-21-9-9-9-1234", Lab.WriteDacl)]);
        Assert.Contains(lab.Run().Coverage().Limitations,
            item => item.Reason == Tier0DiscoveryReason.UnresolvedTrustee && item.TrusteeSid == "S-1-5-21-9-9-9-1234");
    }

    [Fact]
    public void AnIncompleteCaptureNeverReportsCompleteCoverage()
    {
        var lab = new Lab(captureComplete: false);
        Assert.False(lab.Run().Coverage().IsComplete);
    }

    /// <summary>
    /// The scan has no work ceiling, so a capture it can read is a capture it reads all of.
    /// </summary>
    /// <remarks>
    /// Replaces an earlier pair asserting that an exhausted budget stopped the scan and that a null
    /// budget started nothing. Both described a configured limit that no longer exists; the limit was
    /// removed because the only value ever defined exceeded the recorded production forest several
    /// times over, so it stopped nothing while implying the product would stop somewhere.
    /// </remarks>
    [Fact]
    public void AScanWithNoCeilingReadsEveryCapturedObject()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        var scheduler = lab.Run();
        var coverage = scheduler.Coverage();
        Assert.Equal(("CapturedInputScanFinished", true, true),
            (coverage.Verdict, coverage.ObjectsVisited == scheduler.Observed.Count, coverage.CandidatesDiscovered > 0));
    }

    /// <summary>
    /// A cancelled scan throws rather than returning coverage that reads as a finished one.
    /// </summary>
    /// <remarks>
    /// <b>This is what makes the single verdict honest.</b> Cancellation is now the only thing that
    /// stops discovery early. Were it to return quietly instead of throwing, the one reachable verdict
    /// would claim a completed scan for a run the operator abandoned - the exact false statement the
    /// removed <c>ProcessingStopped</c> verdict used to carry.
    /// </remarks>
    [Fact]
    public void ACancelledScanThrowsRatherThanClaimingItFinished()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries: [lab.Allow(0, lab.Helpdesk, Lab.WriteDacl)]);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => lab.Run(cancellation.Token));
    }

    [Fact]
    public void AnObjectControllingItselfIsNotARouteToAnywhere()
    {
        var lab = new Lab();
        lab.Describe(lab.DomainAdmins, entries:
            [Tier0DiscoveryEvidence.AllowSid(0, Tier0DiscoveryEvidence.Self, Lab.WriteDacl, "SELF")]);
        Assert.Empty(lab.Run().Candidates());
    }

    [Fact]
    public void AnInheritOnlyEntryGrantsNothingOnTheObjectItIsAttachedTo()
    {
        var lab = new Lab();
        var inheritOnly = lab.Allow(0, lab.Helpdesk, Lab.WriteDacl) with { PropagationFlags = 0x08 };
        lab.Describe(lab.DomainAdmins, entries: [inheritOnly]);
        Assert.Empty(lab.Run().Candidates());
    }

    /// <summary>
    /// THE NEGATIVE CONTROL required by decision 0116. Every assertion above rests on the claim that
    /// counting candidates detects unwanted evaluation. If a scheduler that deliberately admitted an
    /// unrelated account still satisfied those assertions, they would be measuring nothing.
    /// </summary>
    [Fact]
    public void TheCandidateCountDetectsDeliberateEvaluationOfAnUnrelatedObject()
    {
        var lab = new Lab();

        // Exactly what the acceptance case forbids: Jimmy named on a Tier-0 object with no route.
        var leaked = new Lab();
        leaked.Describe(leaked.DomainAdmins, entries: [leaked.Allow(0, leaked.Jimmy, Lab.WriteDacl)]);

        var clean = lab.Run().Candidates()
            .Any(item => item.Controller.DistinguishedName == lab.Jimmy.DistinguishedName);
        var leakedResult = leaked.Run().Candidates()
            .Any(item => item.Controller.DistinguishedName == leaked.Jimmy.DistinguishedName);
        Assert.Equal((false, true), (clean, leakedResult));
    }

    /// <summary>
    /// The second half of the negative control: admission, not merely candidate collection, must also
    /// distinguish the two cases.
    /// </summary>
    [Fact]
    public void AdmissionDetectsDeliberateInclusionOfAnUnrelatedObject()
    {
        var clean = new Lab();
        var leaked = new Lab();
        leaked.Describe(leaked.DomainAdmins, entries: [leaked.Allow(0, leaked.Jimmy, Lab.WriteDacl)]);
        Assert.Equal((OwnershipScopeState.Undetermined, OwnershipScopeState.Included),
            (clean.Select().For(clean.Target(clean.Jimmy)).State,
             leaked.Select().For(leaked.Target(leaked.Jimmy)).State));
    }

    /// <summary>
    /// Coverage is resolved before it is read, so it cannot report fewer limitations to a caller who
    /// asks about completeness before asking for the candidates.
    /// </summary>
    [Fact]
    public void CoverageDoesNotDependOnWhetherCandidatesWereReadFirst()
    {
        var first = new Lab();
        first.Describe(first.DomainAdmins, entries:
            [Tier0DiscoveryEvidence.AllowSid(5, "S-1-5-21-9-9-9-1234", Lab.WriteDacl)]);
        var second = new Lab();
        second.Describe(second.DomainAdmins, entries:
            [Tier0DiscoveryEvidence.AllowSid(5, "S-1-5-21-9-9-9-1234", Lab.WriteDacl)]);

        var coverageFirst = first.Run().Coverage().Limitations.Count;
        var afterCandidates = second.Run();
        afterCandidates.Candidates();
        Assert.Equal(coverageFirst, afterCandidates.Coverage().Limitations.Count);
    }

    [Fact]
    public void ObservingAfterResolutionIsRefusedRatherThanSilentlyIgnored()
    {
        var lab = new Lab();
        var scheduler = lab.Run();
        scheduler.Candidates();
        Assert.Throws<InvalidOperationException>(() =>
            scheduler.Observe(lab.Jimmy, lab.Evidence.Permissions(lab.Jimmy.DistinguishedName)));
    }

    /// <summary>A bounded offline capture with one Tier-0 seed and unrelated ordinary accounts.</summary>
    private sealed class Lab
    {
        internal const int WriteDacl = 0x40000;
        internal const int WriteOwner = 0x80000;

        private readonly bool _captureComplete;

        internal Tier0DiscoveryEvidence Evidence { get; }
        internal ObjectAttributes DomainAdmins { get; }
        internal ObjectAttributes Helpdesk { get; }
        internal ObjectAttributes Jimmy { get; }

        internal Lab(bool captureComplete = true)
        {
            _captureComplete = captureComplete;
            Evidence = new();

            // RID 512 is Domain Admins, which the shared classifier recognises as a Tier-0 seed.
            DomainAdmins = Evidence.Principal("Domain Admins", "512");
            Helpdesk = Evidence.Principal("Helpdesk", "1401", "user");
            Jimmy = Evidence.Principal("jimmy.strand", "1402", "user");
            Evidence.Describe(DomainAdmins);
            Evidence.Describe(Helpdesk);
            Evidence.Describe(Jimmy);
        }

        internal string SidOf(ObjectAttributes subject) => subject.Find("objectSid")!.OnlyValue!.Text!;
        internal Tier0Target Target(ObjectAttributes subject) => Evidence.Target(subject);
        internal PermissionEntry Allow(int ordinal, ObjectAttributes holder, int mask) => Evidence.Allow(ordinal, holder, mask);

        internal void Describe(ObjectAttributes subject, string? ownerSid = null,
            DaclCompleteness completeness = DaclCompleteness.Complete, params PermissionEntry[] entries) =>
            Evidence.Describe(subject, ownerSid, DaclState.Present, completeness, entries);

        internal Tier0DiscoveryScheduler Run() => Run(CancellationToken.None);

        internal Tier0DiscoveryScheduler Run(CancellationToken cancellationToken)
        {
            var scheduler = new Tier0DiscoveryScheduler(Evidence.Binding, _captureComplete,
                Evidence.Find, Evidence.Target, cancellationToken);
            foreach (var subject in Evidence.Stream())
                scheduler.Observe(subject, Evidence.Permissions(subject.DistinguishedName));
            return scheduler;
        }

        internal OwnershipScopeSelection Select()
        {
            var scheduler = Run();
            var input = Evidence.Input();
            var classifications = scheduler.Observed.Values
                .Select(target => Tier0Classifier.Qualify(Evidence.Binding, target, input, routes: null)).ToArray();
            return OwnershipScopeSelector.Select(Evidence.Binding, Guid.NewGuid(), classifications,
                scheduler.Candidates(), new(true, true, true, Tier0Limitations.None), CancellationToken.None, progress: null);
        }
    }
}
