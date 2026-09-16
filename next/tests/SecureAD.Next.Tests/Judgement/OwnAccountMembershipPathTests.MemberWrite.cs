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
    public void OrdinaryWriteReachesTier0ThroughExistingMemberships()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;WP;{MemberGuid};;{UserSid})");
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Reachable, reader.ReadTier0Path(UserDn).Reachability);
    }

    private const string MemberWriteGrant = "(OA;;WP;" + MemberGuid + ";;" + UserSid + ")";
    private const string MembershipSet = "11111111-1111-1111-1111-111111111111";
    private const string GroupGuid = "bf967a9c-0de6-11d0-a285-00aa003049e2";

    [Theory]
    [InlineData("0x40000000", 0x40000000)]
    [InlineData("0x10000000", 0x10000000)]
    [InlineData("0x80000000", unchecked((int)0x80000000))]
    [InlineData("0x20000000", 0x20000000)]
    [InlineData("0x40000020", 0x40000020)]
    [InlineData("0x20028", 0x20028)]
    [InlineData("WP", 0x20)]
    public void OrdinaryWritePermissionReadbackPreservesTheStoredMask(string right, int expected)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{UserSid})");
        using var bundle = BundleReader.Open(directory).Value;

        Assert.Equal(expected, Assert.Single(bundle.ReadPermissions(TargetDn)!.Entries).AccessMask);
    }

    [Theory]
    [InlineData("0x40000000")]
    [InlineData("0x10000000")]
    public void OrdinaryWriteRawGenericBitsDoNotManufactureHolderCapabilities(string right)
    {
        var directory = PrepareOrdinary($"(A;;{right};;;{UserSid})");
        using var reader = Open(directory);

        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Where(edge => edge.HolderSid == UserSid));
    }

    [Theory]
    [InlineData("(A;;WP;;;" + UserSid + ")")]
    [InlineData("(OA;;WP;" + GroupGuid + ";;" + UserSid + ")")]
    [InlineData("(OA;;WP;" + MemberGuid + ";;" + HolderSid + ")")]
    [InlineData("(OA;;WP;" + MembershipSet + ";;" + UserSid + ")")]
    public void OrdinaryWriteSupportedScopesAndGrantRoutesEstablishMembership(string entries)
    {
        var directory = PrepareOrdinary(entries);
        using var reader = Open(directory);

        Assert.Equal(OwnAccountMembershipBasis.ExistingOrAuthorizedAdd, Assessment(reader).Basis);
    }

    [Theory]
    [InlineData("(D;;WP;;;WD)" + MemberWriteGrant, ControlEvaluationState.NotEstablished)]
    [InlineData("(OD;;WP;" + MemberGuid + ";;WD)(A;;WP;;;" + UserSid + ")", ControlEvaluationState.NotEstablished)]
    [InlineData("(OD;;WP;" + MembershipSet + ";;WD)" + MemberWriteGrant, ControlEvaluationState.NotEstablished)]
    [InlineData(MemberWriteGrant + "(D;;WP;;;WD)", ControlEvaluationState.Established)]
    [InlineData("(D;;WP;;;S-1-5-21-1-2-3-1999)" + MemberWriteGrant, ControlEvaluationState.Unknown)]
    [InlineData(MemberWriteGrant + "(D;;WP;;;S-1-5-21-1-2-3-1999)", ControlEvaluationState.Established)]
    [InlineData("(XD;;WP;;;WD;(@User.department == \"Finance\"))" + MemberWriteGrant, ControlEvaluationState.Unknown)]
    [InlineData("(D;;SW;;;WD)" + MemberWriteGrant, ControlEvaluationState.Established)]
    [InlineData("(D;IO;WP;;;WD)" + MemberWriteGrant, ControlEvaluationState.Established)]
    public void OrdinaryWriteChecksApplicableDeniesInCapturedOrder(string entries, ControlEvaluationState expected)
    {
        var directory = PrepareOrdinary(entries);
        using var reader = Open(directory);

        Assert.Equal(expected, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Authorization);
    }

    [Theory]
    [InlineData("SW", ControlEvaluationState.NotEstablished)]
    [InlineData("WD", ControlEvaluationState.NotEstablished)]
    [InlineData("WO", ControlEvaluationState.NotEstablished)]
    [InlineData("CR", ControlEvaluationState.NotEstablished)]
    [InlineData("0x40000000", ControlEvaluationState.Unknown)]
    public void OrdinaryWriteDoesNotSubstituteOtherRights(string right, ControlEvaluationState expected)
    {
        var directory = PrepareOrdinary($"(OA;;{right};{MemberGuid};;{UserSid})");
        using var reader = Open(directory);

        Assert.Equal(expected, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Authorization);
    }

    [Theory]
    [InlineData("WD")]
    [InlineData("AU")]
    [InlineData("PS")]
    [InlineData("S-1-5-21-1-2-3-1999")]
    public void OrdinaryWriteUnsupportedGrantRoutesRemainUnknown(string trustee)
    {
        var directory = PrepareOrdinary($"(OA;;WP;{MemberGuid};;{trustee})");
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Authorization);
    }

    [Fact]
    public void OrdinaryWriteCannotInventItsGrantingMembership()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;WP;{MemberGuid};;{HolderSid})", holderMembers: []);
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Authorization);
    }

    [Fact]
    public void OrdinaryWriteUnknownPropertySetCannotBeSkippedBeforeAnAllow()
    {
        var directory = Capture($"O:SYG:SYD:(OD;;WP;{MembershipSet};;WD){MemberWriteGrant}");
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Contains(MemberWriteIssue.ScopeUnknown, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Issues);
    }

    [Fact]
    public void OrdinaryWritePropertySetProofRetainsTheCapturedAssignment()
    {
        var directory = PrepareOrdinary($"(OA;;WP;{MembershipSet};;{UserSid})");
        using var reader = Open(directory);

        Assert.Contains(MembershipSet, Assert.Single(Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Evidence).ScopeEvidence);
    }

    [Fact]
    public void OrdinaryWriteMissingSchemaDoesNotBecomeEmbeddedPermissionProof()
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant, schema: false);
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Authorization);
    }

    [Fact]
    public void OrdinaryWriteKeepsUnknownCurrentMembership()
    {
        var directory = PrepareOrdinary(MemberWriteGrant);
        using var reader = Open(directory);

        Assert.Null(Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).MemberPresent);
    }

    [Fact]
    public void OrdinaryWriteKeepsUnknownAddReadiness()
    {
        var directory = PrepareOrdinary(MemberWriteGrant);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Readiness);
    }

    [Fact]
    public void OrdinaryWriteDoesNotRelabelSelfMembershipAuthorization()
    {
        var directory = PrepareOrdinary(MemberWriteGrant);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Assessment(reader).Permission.Authorization);
    }

    [Fact]
    public void OrdinaryWriteAndSelfMembershipQuestionsRemainSeparate()
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn), WriteMembersRequest(), WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(new[] { (OwnAccountMembershipPermissionKind.SelfMembership, ControlEvaluationState.Unknown),
            (OwnAccountMembershipPermissionKind.WriteMembers, ControlEvaluationState.Established) }, reader.ReadTier0Path(UserDn)
            .OwnAccountAssessments.Select(value => (value.Request.PermissionKind, value.Obtainability)));
    }

    [Fact]
    public void OrdinaryWriteDenialDoesNotEraseAnIndependentSelfMembershipRoute()
    {
        var directory = Capture($"O:SYG:SYD:(D;;WP;;;WD)(OA;;SW;{MemberGuid};;{UserSid})");
        Derive(directory);
        Judge(directory, [WriteMembersRequest(), new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(new[] { OwnAccountMembershipPermissionKind.SelfMembership },
            reader.ReadTier0Path(UserDn).Steps.Where(step => step.Kind == Tier0PathStepKind.OwnAccountMembership)
                .Select(step => step.OwnAccountRequest!.PermissionKind));
    }

    [Theory]
    [InlineData("514", "513", OwnAccountMembershipIssue.AccountDisabled, ControlEvaluationState.NotEstablished)]
    [InlineData(null, "513", OwnAccountMembershipIssue.AccountStatusMissing, ControlEvaluationState.Unknown)]
    [InlineData("512", null, OwnAccountMembershipIssue.PrimaryGroupMissing, ControlEvaluationState.Unknown)]
    [InlineData("4096", "513", OwnAccountMembershipIssue.RequesterUnsupported, ControlEvaluationState.Unknown)]
    public void OrdinaryWriteKeepsOperationBlockers(string? uac, string? primary, OwnAccountMembershipIssue issue, ControlEvaluationState state)
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant, userAttributes: Account(uac, primary));
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), issue, state);
    }

    [Fact]
    public void OrdinaryWriteDisabledAccountRetainsPermissionEvidence()
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant, userAttributes: Account("514", "513"));
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Established, Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Authorization);
    }

    [Fact]
    public void OrdinaryWriteExistingMembershipDoesNotInventAnAdd()
    {
        var directory = Capture("O:SYG:SYD:", members: [UserDn], userAttributes: Account("514", "513"));
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(OwnAccountMembershipBasis.ExistingMembership, Assessment(reader).Basis);
    }

    [Theory]
    [InlineData("systemFlags", "19")]
    [InlineData("searchFlags", "4096")]
    public void OrdinaryWriteRequiresSupportedOperationSchema(string field, string value)
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant, memberSchema: MemberSchema(field, value));
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), OwnAccountMembershipIssue.SchemaUnsupported);
    }

    [Fact]
    public void OrdinaryWriteDoesNotCrossTheRequesterDomainBoundary()
    {
        const string requester = "CN=CrossDomain,DC=child,DC=contoso,DC=com";
        var directory = Capture(crossDomainRequester: true);
        Derive(directory);
        Judge(directory, [new(requester, TargetDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers }]);
        using var reader = Open(directory);

        AssertIssue(Assert.Single(reader.ReadTier0Path(requester).OwnAccountAssessments), OwnAccountMembershipIssue.ResourceContextUnsupported);
    }

    [Fact]
    public void OrdinaryWriteSavesTheMatchingOriginalHolderPermission()
    {
        var directory = PrepareOrdinary($"(OA;;WP;{MemberGuid};;{HolderSid})");
        using var reader = Open(directory);
        var proof = Assessment(reader);

        Assert.Equal(new[] { (HolderSid, ControlCapability.CanModifyGroupMembership) }, reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges
            .Where(edge => edge.Id == Assert.Single(proof.Permissions).Id).Select(edge => (edge.HolderSid, edge.Capability)));
    }

    [Fact]
    public void OrdinaryWriteSavesTheGrantingMembershipWitness()
    {
        var directory = PrepareOrdinary($"(OA;;WP;{MemberGuid};;{HolderSid})");
        using var reader = Open(directory);

        Assert.Equal((HolderDn, UserDn), Assert.IsType<MemberWriteAssessment>(Assessment(reader).MemberWrite).Evidence
            .Select(item => (item.Trustee.HolderDn, item.Trustee.DirectMemberDn)).Single());
    }

    [Fact]
    public void OrdinaryWriteCountsOneOperationAndTheActualMembershipSuffix()
    {
        var directory = PrepareOrdinary(MemberWriteGrant);
        using var reader = Open(directory);

        Assert.Equal(new[] { (Tier0PathStepKind.OwnAccountMembership, UserDn, TargetDn), (Tier0PathStepKind.Membership, TargetDn, CoreDn) },
            reader.ReadTier0Path(UserDn).Steps.Select(step => (step.Kind, step.From.DistinguishedName, step.To.DistinguishedName)));
    }

    [Fact]
    public void OrdinaryWriteCanAddToAFixedTargetWithoutASuffix()
    {
        var directory = Capture(coreDescriptor: "O:SYG:SYD:" + MemberWriteGrant);
        Derive(directory);
        Judge(directory, [WriteMembersRequest(CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(1, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void OrdinaryWriteDoesNotTransferTheNewGroupsDaclAuthority()
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant, membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void OrdinaryWriteDoesNotMultiplyHolderCounts()
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant);
        Derive(directory);
        Judge(directory, []);
        (string, ControlCapability, bool)[] counts;
        using (var before = Open(directory)) counts = before.ReadControlEdges(TargetDn, null, null, true, 0).Edges
            .Select(edge => (edge.HolderSid, edge.Capability, edge.IsCounted)).ToArray();
        Judge(directory, [WriteMembersRequest()]);
        using var after = Open(directory);

        Assert.Equal(counts, after.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Select(edge => (edge.HolderSid, edge.Capability, edge.IsCounted)));
    }

    [Theory]
    [InlineData("$.OwnAccounts[0].Assessment.MemberWrite.Authorization", "NotEstablished")]
    [InlineData("$.OwnAccounts[0].Assessment.MemberWrite.Readiness", "Established")]
    [InlineData("$.OwnAccounts[0].Assessment.MemberWrite.Evidence[0].ScopeEvidence", "changed")]
    [InlineData("$.OwnAccounts[0].Assessment.Request.PermissionKind", "SelfMembership")]
    [InlineData("$.OwnAccounts[0].Assessment.Permissions[0].Fingerprint", "changed")]
    [InlineData("$.OwnAccounts[0].SourceFingerprint", "changed")]
    public void OrdinaryWriteRejectsChangedSavedProofWithRefreshedHash(string path, string value)
    {
        // DACL admission supplies the holder proof without a selected membership route
        // masking a broken assessment validator. A missing reference would only test JSON shape.
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant, membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using (var intact = Open(directory)) Assert.Single(Assessment(intact).Permissions);
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "','" + value + "')");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void OrdinaryWriteReadbackRemainsPassive()
    {
        var directory = PrepareOrdinary(MemberWriteGrant);
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        var before = Snapshot(directory);

        reader.ReadTier0Path(UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void OrdinaryWriteCancellationKeepsThePreviousGeneration()
    {
        var directory = PrepareOrdinary(MemberWriteGrant);
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], [], [WriteMembersRequest()], Started, Started,
            new CancelBeforePublication(stopping), RunLog.Discarded, null, stopping.Token));
        using var reader = Open(directory);

        Assert.Equal(previous, Assessment(reader).GenerationId);
    }

    [Fact]
    public void OrdinaryWriteUnrequestedPairsRemainUnassessed()
    {
        var directory = Capture("O:SYG:SYD:" + MemberWriteGrant);
        Derive(directory);
        Judge(directory, []);
        using var reader = Open(directory);

        Assert.Empty(reader.ReadTier0Path(UserDn).OwnAccountAssessments);
    }

    [Fact]
    public void OrdinaryWriteRejectsUndefinedRequestKinds()
    {
        var directory = Capture();
        Derive(directory);

        Assert.Throws<ArgumentException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], [],
            [new(UserDn, TargetDn) { PermissionKind = (OwnAccountMembershipPermissionKind)99 }], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None));
    }

    private string PrepareOrdinary(string entries)
    {
        var directory = Capture("O:SYG:SYD:" + entries, memberSchema:
            [.. MemberSchema("searchFlags", "0"), Binary("attributeSecurityGUID", Guid.Parse(MembershipSet).ToByteArray())]);
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        return directory;
    }

    private static OwnAccountMembershipRequest WriteMembersRequest(string target = TargetDn) =>
        new(UserDn, target) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers };
}
