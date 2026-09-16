using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void MembershipDaclConnectsOneObtainedMembershipToTheFixedTarget()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(2, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Theory]
    [InlineData("SW", UserSid, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("SW", HolderSid, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("WP", UserSid, OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("WP", HolderSid, OwnAccountMembershipPermissionKind.WriteMembers)]
    public void MembershipDaclUsesTheSelectedPreChangePermission(string right, string sid, OwnAccountMembershipPermissionKind kind)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{sid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn) { PermissionKind = kind }]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Established, Combined(reader).Authorization);
    }

    [Fact]
    public void MembershipDaclKeepsOrdinaryWriteSeparateFromSelfMembership()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;WP;{MemberGuid};;{UserSid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers }]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Combined(reader).Membership.Permission.Authorization);
    }

    // Microsoft's AccessCheck rule terminates on the first applicable decision for this one bit;
    // SID Attributes in an Access Token applies enabled group SIDs to both allows and denies.
    [Theory]
    [InlineData("(D;;WD;;;S-1-5-21-1-2-3-1100)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(D;;WD;;;S-1-5-21-1-2-3-1200)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(D;;WD;;;S-1-5-21-1-2-3-1300)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(D;;WD;;;AU)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(D;;WD;;;WD)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("(A;;WD;;;S-1-5-21-1-2-3-1200)(D;;WD;;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.Established)]
    [InlineData("(A;;WD;;;S-1-5-21-1-2-3-1200)(D;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Established)]
    [InlineData("(D;;WD;;;S-1-5-21-1-2-3-1999)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Unknown)]
    [InlineData("(A;;WD;;;S-1-5-21-1-2-3-1200)(D;;WD;;;S-1-5-21-1-2-3-1999)", ControlEvaluationState.Established)]
    [InlineData("(D;IO;WD;;;S-1-5-21-1-2-3-1200)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Established)]
    [InlineData("(XD;;WD;;;WD;(@User.department == \"Finance\"))(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Unknown)]
    [InlineData("(OD;;WD;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1200)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Unknown)]
    public void MembershipDaclChecksAllApplicableEntriesInCapturedOrder(string entries, ControlEvaluationState expected)
    {
        var directory = Capture(membershipTail: true, coreDescriptor: "O:SYG:SYD:" + entries);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(expected, Combined(reader).Dacl!.Authorization);
    }

    [Fact]
    public void MembershipDaclDoesNotExcludeACurrentUserSidFromTheObtainedGroupsUnresolvedHistory()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1999)(A;;WD;;;{TargetSid})",
            additional: (writer, coverage) => Write(writer, coverage, "CN=Other,DC=contoso,DC=com",
                ["top", "user"], "S-1-5-21-1-2-3-1999", [], "O:SYG:SYD:"));
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(RequesterTrusteeState.Unknown, Combined(reader).Dacl!.Evidence[0].Trustee.State);
    }

    [Fact]
    public void MembershipDaclDoesNotExcludeADistributionSidFromTheObtainedGroupsUnresolvedHistory()
    {
        var directory = Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1999)(A;;WD;;;{TargetSid})",
            additional: (writer, coverage) => Write(writer, coverage, "CN=Distribution,DC=contoso,DC=com",
                ["top", "group"], "S-1-5-21-1-2-3-1999", [Text("groupType", "2")], "O:SYG:SYD:"));
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Combined(reader).Authorization);
    }

    [Fact]
    public void MembershipDaclKeepsANestedDenyPossibleRatherThanIgnoringIt()
    {
        var directory = Capture(membershipTail: false, holderMembers: [TargetDn],
            coreDescriptor: $"O:SYG:SYD:(D;;WD;;;{HolderSid})(A;;WD;;;{TargetSid})");
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Combined(reader).Authorization);
    }

    [Theory]
    [InlineData("SW", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("WP", OwnAccountMembershipPermissionKind.WriteMembers)]
    public void MembershipDaclNeverUsesTheNewMembershipToAuthorizeItself(string right, OwnAccountMembershipPermissionKind kind)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{TargetSid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn) { PermissionKind = kind }]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Combined(reader).Membership.Obtainability);
    }

    [Fact]
    public void MembershipDaclDoesNotChainAnUnprovedNestedGrant()
    {
        var directory = Capture(membershipTail: true, holderMembers: [TargetDn], coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Combined(reader).Dacl!.Authorization);
    }

    [Theory]
    [InlineData("0x10000000")]
    [InlineData("0x40000000")]
    [InlineData("WO")]
    [InlineData("WP")]
    public void MembershipDaclRequiresConcreteWriteDaclRatherThanOtherRights(string right)
    {
        var directory = Capture(membershipTail: true, coreDescriptor: $"O:SYG:SYD:(A;;{right};;;{TargetSid})");
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Combined(reader).Dacl!.Authorization);
    }

    [Fact]
    public void MembershipDaclRequiresTheGrantToBeHeldByTheObtainedGroup()
    {
        var directory = Capture(membershipTail: true, coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.GrantNotHeldByObtainedGroup, Combined(reader).Dacl!.Issues);
    }

    [Fact]
    public void MembershipDaclDoesNotPromoteNullDaclToAGroupHeldGrant()
    {
        var directory = Capture(membershipTail: true, coreDescriptor: "O:SYG:SYD:NO_ACCESS_CONTROL");
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.GrantRouteUnsupported, Combined(reader).Dacl!.Issues);
    }

    [Fact]
    public void MembershipDaclKeepsMissingDescriptorEvidenceDistinct()
    {
        var directory = Capture(membershipTail: true, missingCoreDescriptor: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.DescriptorUnreadable, Combined(reader).Dacl!.Issues);
    }

    [Fact]
    public void MembershipDaclRequiresAFixedTargetRatherThanAssessmentAdmission()
    {
        var directory = Capture(membershipTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.TargetNotFixed, Combined(reader).Dacl!.Issues);
    }

    [Fact]
    public void MembershipDaclUsesTheAuthoritativeDomainRootTarget()
    {
        var directory = Capture(membershipTail: false, rootDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, "DC=contoso,DC=com")]);
        using var reader = Open(directory);

        Assert.Equal("DC=contoso,DC=com", reader.ReadTier0Path(UserDn).Steps.Last().To.DistinguishedName);
    }

    [Fact]
    public void MembershipDaclDoesNotAuthorizeTheConfigurationPartition()
    {
        var directory = Capture(membershipTail: true, additional: (writer, coverage) =>
        {
            var partition = new PartitionCoverage("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration,
                "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(partition);
            Write(writer, partition, "CN=Configuration,DC=contoso,DC=com", ["top", "configuration"], null, [], $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        });
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, "CN=Configuration,DC=contoso,DC=com")]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.ResourceContextUnsupported, Combined(reader).Dacl!.Issues);
    }

    [Fact]
    public void MembershipDaclKeepsUnknownCurrentMembership()
    {
        using var reader = Open(PreparedMembershipDacl());

        Assert.Null(Combined(reader).Membership.Permission.MemberPresent);
    }

    [Fact]
    public void MembershipDaclKeepsUnknownOrdinaryAddReadiness()
    {
        using var reader = Open(PreparedMembershipDacl());

        Assert.Equal(ControlEvaluationState.Unknown, Combined(reader).Membership.Permission.Readiness);
    }

    [Fact]
    public void MembershipDaclDoesNotInventAnAddForCapturedMembership()
    {
        var directory = Capture(members: [UserDn], membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(Tier0PathStepKind.Membership, Combined(reader).Steps[0].Kind);
    }

    [Fact]
    public void MembershipDaclDoesNotWidenThePrimaryGroupRequesterModel()
    {
        var directory = Capture(userAttributes: Account("512", "1200"), membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Combined(reader).Dacl!.Authorization);
    }

    [Fact]
    public void MembershipDaclDisabledAccountCannotObtainTheNewMembership()
    {
        var directory = Capture(userAttributes: Account("514", "513"), membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(OwnAccountMembershipIssue.AccountDisabled, Combined(reader).Membership.Issues);
    }

    [Fact]
    public void MembershipDaclMissingSchemaCannotProveTheOperation()
    {
        var directory = Capture(schema: false, membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(OwnAccountMembershipIssue.SchemaEvidenceMissing, Combined(reader).Membership.Issues);
    }

    [Fact]
    public void MembershipDaclUncertaintyDoesNotBecomeNotReachable()
    {
        var directory = Capture(schema: false, membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void MembershipDaclDoesNotEraseAnIndependentShorterRoute()
    {
        var directory = Capture(existingUserRoute: true, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(1, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void MembershipDaclDoesNotClaimTheShortestProvenRouteIsTheAbsoluteMinimum()
    {
        using var reader = Open(PreparedMembershipDacl());

        Assert.False(reader.ReadTier0Path(UserDn).IsMinimumEstablished);
    }

    [Fact]
    public void MembershipDaclStepsKeepBothOriginalPermissionReferences()
    {
        using var reader = Open(PreparedMembershipDacl());
        var assessment = Combined(reader);

        Assert.Equal(new long?[] { assessment.Membership.Permissions.Single().Id, assessment.Dacl!.Permissions.Single().Id },
            assessment.Steps.Select(step => step.PermissionId));
    }

    [Fact]
    public void MembershipDaclIdentifiesTheObtainedMembershipWithoutCapturedMemberEvidence()
    {
        using var reader = Open(PreparedMembershipDacl());
        var trustee = Combined(reader).Dacl!.Evidence.Single().Trustee;

        Assert.Equal((RequesterTrusteeReason.ObtainedGlobalMembership, (string?)null), (trustee.Reason, trustee.DirectMemberDn));
    }

    [Fact]
    public void MembershipDaclStoresItsAuthorizationAssumption()
    {
        using var reader = Open(PreparedMembershipDacl());

        Assert.Equal(MembershipDaclAssessment.Context, Combined(reader).AuthorizationContext);
    }

    [Fact]
    public void MembershipDaclDoesNotRelabelTheCapturedRequesterAssessment()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], [new(UserDn, CoreDn)], [], [new(UserDn, TargetDn, CoreDn)],
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void MembershipDaclRequestsDoNotMultiplyHolderCounts()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, []);
        string[] before;
        using (var reader = Open(directory)) before = HeldPermissions(reader);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn), new(UserDn, TargetDn, CoreDn)]);
        using var after = Open(directory);

        Assert.Equal(before, HeldPermissions(after));
    }

    [Fact]
    public void MembershipDaclDuplicateQuestionsAreStoredOnce()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn), new(UserDn.ToUpperInvariant(), TargetDn.ToUpperInvariant(), CoreDn.ToUpperInvariant())]);
        using var reader = Open(directory);

        Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments);
    }

    [Fact]
    public void MembershipDaclExistingEntryPointsDoNotScheduleCombinedQuestions()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Empty(reader.ReadTier0Path(UserDn).MembershipDaclAssessments);
    }

    [Theory]
    [InlineData("", TargetDn, CoreDn, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(UserDn, " ", CoreDn, OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(UserDn, TargetDn, "", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(UserDn, TargetDn, CoreDn, (OwnAccountMembershipPermissionKind)99)]
    public void MembershipDaclRejectsInvalidQuestionsBeforeOpeningEvidence(string user, string group, string target, OwnAccountMembershipPermissionKind kind)
    {
        Assert.Throws<ArgumentException>(() => JudgingRun.JudgeWithTier0Discovery("not-opened", [], [], [],
            [new(user, group, target) { PermissionKind = kind }], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None));
    }

    [Fact]
    public void MembershipDaclRejectsANullQuestionList()
    {
        Assert.Throws<ArgumentNullException>(() => JudgingRun.JudgeWithTier0Discovery("not-opened", [], [], [], null!,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None));
    }

    [Theory]
    [InlineData("$.MembershipDacls[0].SourceFingerprint", "changed")]
    [InlineData("$.MembershipDacls[0].Assessment.AuthorizationContext", "changed")]
    [InlineData("$.MembershipDacls[0].Assessment.Membership.EvidenceSeal", "changed")]
    [InlineData("$.MembershipDacls[0].Assessment.Membership.GenerationId", "11111111-1111-1111-1111-111111111111")]
    [InlineData("$.MembershipDacls[0].Assessment.Membership.DerivationGenerationId", "11111111-1111-1111-1111-111111111111")]
    [InlineData("$.MembershipDacls[0].Assessment.Dacl.Authorization", "Unknown")]
    [InlineData("$.MembershipDacls[0].Assessment.Dacl.Evidence[0].Trustee.Reason", "DirectIdentity")]
    [InlineData("$.MembershipDacls[0].Assessment.Dacl.Permissions[0].Fingerprint", "changed")]
    [InlineData("$.MembershipDacls[0].Assessment.Membership.Permissions[0].Fingerprint", "changed")]
    [InlineData("$.MembershipDacls[0].Assessment.Membership.Permission.Readiness", "Established")]
    [InlineData("$.MembershipDacls[0].Assessment.Steps[0].Kind", "Membership")]
    [InlineData("$.MembershipDacls[0].Assessment.Steps[1].To.DistinguishedName", "CN=Wrong,DC=contoso,DC=com")]
    public void MembershipDaclRejectsChangedProofEvenWithRefreshedJsonHash(string path, string value)
    {
        var directory = PreparedMembershipDacl();
        using (var before = Open(directory)) Assert.Equal(ControlEvaluationState.Established, Combined(before).Authorization);
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "','" + value + "')");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void MembershipDaclRejectsAnOmittedProvenRoute()
    {
        var directory = PreparedMembershipDacl();
        Mutate(directory, "UPDATE tier0_path_node SET proof=json_set(proof,'$.MembershipDaclRoute',NULL),outcome='Unknown' WHERE target LIKE 'CN=Alice,%'");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void MembershipDaclReadbackDoesNotWriteEvidenceOrAnalysis()
    {
        var directory = PreparedMembershipDacl();
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        var before = Snapshot(directory);

        reader.ReadTier0Path(UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void MembershipDaclCancellationPreservesThePreviousGeneration()
    {
        var directory = PreparedMembershipDacl();
        Guid generation;
        using (var before = Open(directory)) generation = Combined(before).GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], [], [],
            [new(UserDn, TargetDn, CoreDn)], Started, Started, new CancelBeforePublication(stopping), RunLog.Discarded, null, stopping.Token));
        using var after = Open(directory);

        Assert.Equal(generation, Combined(after).GenerationId);
    }

    [Fact]
    public void MembershipDaclInvalidRejudgingPreservesThePreviousGeneration()
    {
        var directory = PreparedMembershipDacl();
        Guid generation;
        using (var before = Open(directory)) generation = Combined(before).GenerationId;
        Assert.Throws<ArgumentException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], [], [],
            [new(UserDn, "", CoreDn)], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None));
        using var after = Open(directory);

        Assert.Equal(generation, Combined(after).GenerationId);
    }

    private string PreparedMembershipDacl()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        return directory;
    }

    private static string[] HeldPermissions(JudgementReader reader) => new[] { TargetDn, CoreDn }
        .SelectMany(target => reader.ReadControlEdges(target, null, null, true, 0).Edges)
        .Select(edge => edge.Id + ":" + edge.HolderSid + ":" + edge.Capability + ":" + edge.Target).ToArray();

    private static void JudgeMembershipDacl(string directory, IReadOnlyList<MembershipDaclRequest> requests)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], [], [], requests, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static MembershipDaclAssessment Combined(JudgementReader reader) =>
        Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments);
}
