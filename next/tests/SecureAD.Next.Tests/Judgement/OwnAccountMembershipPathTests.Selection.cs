using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void SelectionAutomaticallyChecksADirectDaclRequester()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Established, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void SelectionChecksARecordedMemberOfTheDaclGrantingGroup()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Equal(2, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Theory]
    [InlineData("SW", UserSid, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("SW", HolderSid, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("WP", UserSid, OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("WP", HolderSid, OwnAccountMembershipPermissionKind.WriteMembers)]
    public void SelectionFindsOwnAccountMembershipContinuations(string right, string sid, OwnAccountMembershipPermissionKind kind)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{sid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);
        var path = reader.ReadTier0Path(UserDn);

        Assert.Equal((kind, 2), (Assert.Single(path.OwnAccountAssessments).Request.PermissionKind, path.ShortestProvenDistance));
    }

    [Theory]
    [InlineData("SW", UserSid, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("SW", HolderSid, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("WP", UserSid, OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("WP", HolderSid, OwnAccountMembershipPermissionKind.WriteMembers)]
    public void SelectionIncludesANonTierZeroIntermediateGroup(string right, string sid, OwnAccountMembershipPermissionKind kind)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{sid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);
        var path = reader.ReadTier0Path(UserDn);

        Assert.Equal((kind, 2, false), (Assert.Single(path.MembershipDaclAssessments).Request.PermissionKind,
            path.ShortestProvenDistance, path.Inputs.FixedTargets.Any(value => value.DistinguishedName == TargetDn)));
    }

    [Theory]
    [InlineData("(D;;WD;;;S-1-5-21-1-2-3-1100)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(D;;WD;;;S-1-5-21-1-2-3-1200)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(A;;WD;;;S-1-5-21-1-2-3-1200)(D;;WD;;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.Established)]
    public void SelectionDoesNotReplaceTheOrderedRequesterCheck(string entries, ControlEvaluationState expected)
    {
        var directory = Capture(membershipTail: false, coreDescriptor: "O:SYG:SYD:" + entries);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Equal(expected, Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments).Authorization);
    }

    [Fact]
    public void SelectionRetainsBothPermissionMechanismsAsDifferentQuestions()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SWWP;{MemberGuid};;{UserSid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Equal(new[] { OwnAccountMembershipPermissionKind.SelfMembership, OwnAccountMembershipPermissionKind.WriteMembers },
            reader.ReadTier0Path(UserDn).MembershipDaclAssessments.Select(value => value.Request.PermissionKind).Order());
    }

    [Fact]
    public void SelectionCoalescesDuplicateQuestionsButRetainsTheirPermissionWitnesses()
    {
        var entry = $"(OA;;SW;{MemberGuid};;{UserSid})";
        var directory = Capture("O:SYG:SYD:" + entry + entry, membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Equal(3, Assert.Single(reader.ReadTier0Path(UserDn).RequesterSelection!.Candidates).Witnesses.Count);
    }

    [Fact]
    public void SelectionDoesNotMultiplyHolderPermissionCounts()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, []);
        long[] before;
        using (var reader = Open(directory)) before = reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Select(value => value.Id).ToArray();
        JudgeSelection(directory);
        using var after = Open(directory);

        Assert.Equal(before, after.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Select(value => value.Id).ToArray());
    }

    [Fact]
    public void SelectionPreservesUnknownCurrentMembershipAndOrdinaryAddReadiness()
    {
        var directory = SelectionPrepared();
        using var reader = Open(directory);
        var membership = Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments).Membership;

        Assert.Equal(((bool?)null, ControlEvaluationState.Unknown), (membership.Permission.MemberPresent, membership.Permission.Readiness));
    }

    [Fact]
    public void SelectionKeepsADisabledRequesterAsAnUnprovenQuestion()
    {
        var directory = Capture(membershipTail: false, daclTail: true, userAttributes: Account("514", "513"));
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);
        var path = reader.ReadTier0Path(UserDn);

        Assert.Equal((PathRequesterFamily.MembershipDacl, Tier0Reachability.Unknown),
            (Assert.Single(path.RequesterSelection!.Candidates).Family, path.Reachability));
    }

    [Fact]
    public void SelectionDoesNotSupplyMissingOperationSchema()
    {
        var directory = Capture(membershipTail: false, daclTail: true, schema: false);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(OwnAccountMembershipIssue.SchemaEvidenceMissing,
            Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments).Membership.Issues);
    }

    [Theory]
    [InlineData("AU")]
    [InlineData("WD")]
    public void SelectionRetainsBroadTrusteesWithoutInventingRequesters(string sid)
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{sid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations,
            value => value.Reason == PathRequesterSelectionReason.BroadIdentityNotExpanded && value.ResourceDn == CoreDn);
    }

    [Fact]
    public void SelectionKeepsAnUnreadableFixedTargetAsMissingEvidence()
    {
        var directory = Capture(membershipTail: false, missingCoreDescriptor: true);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations,
            value => value.Reason == PathRequesterSelectionReason.DescriptorUnavailable && value.ResourceDn == CoreDn);
    }

    [Fact]
    public void SelectionKeepsAnUnresolvedTrusteeAndItsPermissionLocation()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: "O:SYG:SYD:(A;;WD;;;S-1-5-21-1-2-3-1999)");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(new(PathRequesterSelectionReason.IdentityUnresolved, CoreDn, 0, "S-1-5-21-1-2-3-1999", null),
            reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations);
    }

    [Fact]
    public void SelectionDoesNotTreatAnEmptyNestedGroupAsAConcreteRequester()
    {
        var directory = Capture(membershipTail: false, holderMembers: [TargetDn], coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        var selection = reader.ReadTier0Path(UserDn).RequesterSelection!;
        Assert.DoesNotContain(selection.Candidates, value => value.Family == PathRequesterFamily.RequesterDacl);
        Assert.Contains(new(PathRequesterSelectionReason.MembershipVisibilityUnknown, CoreDn, 0, HolderSid, null), selection.Limitations);
    }

    [Fact]
    public void SelectionKeepsKnownMembersWithoutClaimingFullMembershipVisibility()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);
        var path = reader.ReadTier0Path(UserDn);

        Assert.Equal((Tier0Reachability.Reachable, true), (path.Reachability,
            path.RequesterSelection!.Limitations.Contains(new(PathRequesterSelectionReason.MembershipVisibilityUnknown, CoreDn, 0, HolderSid, null))));
    }

    [Fact]
    public void SelectionDoesNotTreatAComputerAsAnOrdinaryRequester()
    {
        var directory = Capture(membershipTail: false, userClasses: ["top", "user", "computer"], coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(new(PathRequesterSelectionReason.RequesterKindUnsupported, CoreDn, 0, UserSid, null),
            reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations);
    }

    [Theory]
    [InlineData(-2147483644L)]
    [InlineData(2L)]
    public void SelectionDoesNotExpandAnUnsupportedGrantingGroup(long type)
    {
        var directory = Capture(membershipTail: false, groupType: type, members: [UserDn], daclTail: true);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(new(PathRequesterSelectionReason.GlobalGroupRequired, CoreDn, 0, TargetSid, null),
            reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations);
    }

    [Fact]
    public void SelectionNamesUnsupportedCrossDomainContext()
    {
        var directory = Capture(membershipTail: false, crossDomainRequester: true,
            coreDescriptor: "O:SYG:SYD:(A;;WD;;;S-1-5-21-4-5-6-1100)");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(new(PathRequesterSelectionReason.ResourceContextUnsupported, CoreDn, 0, "S-1-5-21-4-5-6-1100", null),
            reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations);
    }

    [Fact]
    public void SelectionDoesNotExpandRawGenericMasks()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(A;;GA;;;{UserSid})");
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Contains(new(PathRequesterSelectionReason.PermissionUnsupported, CoreDn, 0, UserSid, null),
            reader.ReadTier0Path(UserDn).RequesterSelection!.Limitations);
    }

    [Fact]
    public void SelectionCannotInventARequesterFromTheMembershipItProposes()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SW;{MemberGuid};;{TargetSid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Empty(reader.ReadTier0Path(UserDn).RequesterSelection!.Candidates);
    }

    [Fact]
    public void SelectionEmptyScanDoesNotMeanNotReachable()
    {
        var directory = Capture("O:SYG:SYD:", membershipTail: false);
        Derive(directory);
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void SelectionDeclaresItsUnsupportedPathFamiliesEvenAfterFinishing()
    {
        var directory = SelectionPrepared();
        using var reader = Open(directory);
        var selection = reader.ReadTier0Path(UserDn).RequesterSelection!;

        Assert.Equal((true, true), (selection.InputScanCompleted,
            selection.Limitations.Contains(new(PathRequesterSelectionReason.OtherPathFamiliesNotSelected, null, null, null, null))));
    }

    [Fact]
    public void SelectionDoesNotRunThroughTheExistingEntryPoint()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, []);
        using var reader = Open(directory);

        Assert.Null(reader.ReadTier0Path(UserDn).RequesterSelection);
    }

    [Fact]
    public void SelectionDoesNotActivateTheSeparateProductionDiscoveryScan()
    {
        var directory = SelectionPrepared();
        using var reader = Open(directory);

        Assert.Equal("NotStarted", reader.ReadTier0Path(UserDn).Inputs.RequesterDiscovery!.Verdict);
    }

    [Fact]
    public void SelectionIsBoundToThePublishedJudgementGeneration()
    {
        var directory = SelectionPrepared();
        using var reader = Open(directory);
        var path = reader.ReadTier0Path(UserDn);

        Assert.Equal(path.Inputs.JudgementGenerationId, path.RequesterSelection!.JudgementGenerationId);
    }

    [Theory]
    [InlineData("$.Selection.InputFingerprint", "changed")]
    [InlineData("$.Selection.JudgementGenerationId", "11111111-1111-1111-1111-111111111111")]
    [InlineData("$.Selection.Sources[0].Fingerprint", "changed")]
    [InlineData("$.Selection.Candidates[0].RequesterFingerprint", "changed")]
    [InlineData("$.Selection.Candidates[0].GroupDn", HolderDn)]
    [InlineData("$.Selection.Candidates[0].Family", "RequesterDacl")]
    [InlineData("$.Selection.Candidates[0].PermissionKind", "WriteMembers")]
    [InlineData("$.Selection.Candidates[0].Witnesses[0].HolderDn", HolderDn)]
    public void SelectionRejectsAlteredProvenanceEvenWithARefreshedHash(string path, string value)
    {
        var directory = SelectionPrepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "','" + value + "')");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Theory]
    [InlineData("$.Selection.Candidates[0].Witnesses[0].PermissionOrdinal", 99)]
    [InlineData("$.Selection.Candidates[0].Witnesses[0].RequiredMask", 32)]
    [InlineData("$.Selection.Version", 99)]
    public void SelectionRejectsAlteredTypedWitnessValues(string path, int value)
    {
        var directory = SelectionPrepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "'," + value + ")");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void SelectionRejectsOmittedQuestionsEvenWhenTheirProofsRemain()
    {
        var directory = SelectionPrepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'$.Selection.Candidates',json('[]'))");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void SelectionCannotDisappearFromASelectionEnabledGeneration()
    {
        var directory = SelectionPrepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'$.Selection',NULL)");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Theory]
    [InlineData("$.Selection.Candidates[0]")]
    [InlineData("$.Selection.Sources[0]")]
    [InlineData("$.Selection.Limitations[0]")]
    [InlineData("$.Selection.Candidates[0].Witnesses[0]")]
    public void SelectionRejectsNullRecordsAsInvalidStoredProof(string path)
    {
        var directory = SelectionPrepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "',NULL)");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void SelectionWithoutDerivationDoesNotClaimAFinishedScan()
    {
        var directory = Capture();
        JudgeSelection(directory);
        using var reader = Open(directory);

        Assert.False(reader.ReadTier0Path(UserDn).RequesterSelection!.InputScanCompleted);
    }

    [Fact]
    public void SelectionFailedPublicationPreservesThePreviousGeneration()
    {
        var directory = SelectionPrepared();
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        Assert.Throws<InvalidOperationException>(() => JudgingRun.JudgeWithOfflinePathRequesterSelection(directory, [], Started, Started,
            new RejectSelectionPublication(), RunLog.Discarded, CancellationToken.None));
        using var reader = Open(directory);

        Assert.Equal(previous, reader.ReadTier0Path(UserDn).RequesterSelection!.JudgementGenerationId);
    }

    private sealed class RejectSelectionPublication : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.PublishingJudgement) throw new InvalidOperationException("Synthetic publication failure.");
        }
    }

    [Fact]
    public void SelectionReopeningDoesNotWriteOrReplaceTheSavedGeneration()
    {
        var directory = SelectionPrepared();
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        var before = Snapshot(directory);

        reader.ReadTier0Path(UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void SelectionCancellationPreservesThePreviousValidGeneration()
    {
        var directory = SelectionPrepared();
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithOfflinePathRequesterSelection(directory, [], Started, Started,
            new CancelBeforePublication(stopping), RunLog.Discarded, stopping.Token));
        using var reader = Open(directory);

        Assert.Equal(previous, reader.ReadTier0Path(UserDn).RequesterSelection!.JudgementGenerationId);
    }

    [Fact]
    public void SelectionSourceStatusNamesRecordedReferencesWithoutClaimingAccess()
    {
        var candidate = new PathRequesterCandidate(PathRequesterFamily.RequesterDacl, UserDn, CoreDn, null, null,
            "recorded-requester", [new(CoreDn, 0, 0x40000, UserDn, null)]);

        Assert.Equal(PathRequesterSourceState.Recorded, candidate.Verdict);
    }

    [Fact]
    public void SelectionSourceStatusDoesNotCallMissingReferencesRecorded()
    {
        var candidate = new PathRequesterCandidate(PathRequesterFamily.RequesterDacl, UserDn, CoreDn, null, null,
            "recorded-requester", []);

        Assert.Equal(PathRequesterSourceState.Unrecorded, candidate.Verdict);
    }

    private string SelectionPrepared()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeSelection(directory);
        return directory;
    }

    private static void JudgeSelection(string directory)
    {
        var result = JudgingRun.JudgeWithOfflinePathRequesterSelection(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }
}
