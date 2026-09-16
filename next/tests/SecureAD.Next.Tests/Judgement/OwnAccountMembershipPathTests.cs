using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests(ITestOutputHelper output)
{
    private const string SchemaDn = "CN=Schema,CN=Configuration,DC=contoso,DC=com";
    private const string HolderDn = "CN=Holder,DC=contoso,DC=com";
    private const string HolderSid = "S-1-5-21-1-2-3-1300";
    private const string MemberGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2";

    [Fact]
    public void AnAuthorizedOwnAccountOperationCanContinueThroughExistingMemberships()
    {
        var directory = Capture();
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Reachable, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void UnknownCurrentMembershipIsNotRewrittenAsAbsence()
    {
        var directory = Prepared();
        using var reader = Open(directory);

        Assert.Null(Assessment(reader).Permission.MemberPresent);
    }

    [Fact]
    public void OrdinaryAddReadinessRemainsUnknown()
    {
        var directory = Prepared();
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assessment(reader).Permission.Readiness);
    }

    [Fact]
    public void ObtainabilityRecordsTheTwoCaseProofRatherThanAnObservedAdd()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(OwnAccountMembershipBasis.ExistingOrAuthorizedAdd, Assessment(reader).Basis);
    }

    [Fact]
    public void TheInferredStepKeepsTheConcreteRequesterAndOriginalPermission()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SW;{MemberGuid};;{HolderSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);
        var assessment = Assessment(reader);

        Assert.Equal((UserDn, TargetDn, Tier0PathStepKind.OwnAccountMembership, (long?)Assert.Single(assessment.Permissions).Id),
            reader.ReadTier0Path(UserDn).Steps.Select(step => (step.From.DistinguishedName, step.To.DistinguishedName, step.Kind, step.PermissionId)).First());
    }

    [Fact]
    public void TheGrantingMembershipIsRetainedAsAuthorizationEvidence()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SW;{MemberGuid};;{HolderSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal((HolderDn, UserDn), Assessment(reader).Permission.Evidence
            .Select(item => (item.Trustee.HolderDn, item.Trustee.DirectMemberDn)).Single());
    }

    [Fact]
    public void TheSavedRouteRetainsItsExistingMembershipSuffix()
    {
        var directory = Prepared();
        using var reader = Open(directory);

        Assert.Equal((TargetDn, CoreDn, Tier0PathStepKind.Membership, "member", TargetDn), reader.ReadTier0Path(UserDn).Steps
            .Skip(1).Select(step => (step.From.DistinguishedName, step.To.DistinguishedName, step.Kind,
                step.MembershipWitness!.Attribute, step.MembershipWitness.Value)).Single());
    }

    [Fact]
    public void TheSavedLengthCountsOneOperationAndTheActualMembershipLink()
    {
        var directory = Prepared();
        using var reader = Open(directory);

        Assert.Equal(2, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void AFixedTargetGroupNeedsNoFurtherMembershipStep()
    {
        var directory = Capture(coreDescriptor: $"O:SYG:SYD:(OA;;SW;{MemberGuid};;{UserSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(1, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Theory]
    [InlineData("(OD;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1100)(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1300)", ControlEvaluationState.NotEstablished)]
    [InlineData("(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1300)(OD;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.Established)]
    [InlineData("(OD;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;AU)(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.NotEstablished)]
    [InlineData("(OD;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1999)(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.Unknown)]
    [InlineData("(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1100)(OD;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1999)", ControlEvaluationState.Established)]
    [InlineData("(OD;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;PS)(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.Unknown)]
    public void OrderedAuthorizationAndItsUncertaintyArePreserved(string aces, ControlEvaluationState expected)
    {
        var directory = Capture("O:SYG:SYD:" + aces);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(expected, Assessment(reader).Permission.Authorization);
    }

    [Theory]
    [InlineData("WP")]
    [InlineData("WD")]
    [InlineData("WO")]
    [InlineData("CR")]
    public void OtherPermissionsDoNotAuthorizeThisOperation(string right)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{UserSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Assessment(reader).Permission.Authorization);
    }

    [Theory]
    [InlineData("AU")]
    [InlineData("WD")]
    public void BroadAuthorizationDoesNotWidenTheApprovedGrantRoutes(string trustee)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SW;{MemberGuid};;{trustee})");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), OwnAccountMembershipIssue.GrantRouteUnsupported);
    }

    [Theory]
    [InlineData("PS")]
    [InlineData("S-1-5-21-1-2-3-1300")]
    public void MissingGrantingMembershipCannotBeFilledByTheProposedAddition(string trustee)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SW;{MemberGuid};;{trustee})", holderMembers: []);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assessment(reader).Permission.Authorization);
    }

    [Theory]
    [InlineData("514", OwnAccountMembershipIssue.AccountDisabled, ControlEvaluationState.NotEstablished)]
    [InlineData(null, OwnAccountMembershipIssue.AccountStatusMissing, ControlEvaluationState.Unknown)]
    [InlineData("4096", OwnAccountMembershipIssue.RequesterUnsupported, ControlEvaluationState.Unknown)]
    public void AccountOperationBlockersPreserveThePermission(string? uac, OwnAccountMembershipIssue expected, ControlEvaluationState state)
    {
        var directory = Capture(userAttributes: Account(uac, "513"));
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), expected, state);
    }

    [Fact]
    public void ADisabledAccountRetainsAuthorizationWithoutAnOperationRoute()
    {
        var directory = Capture(userAttributes: Account("514", "513"));
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal((ControlEvaluationState.Established, ControlEvaluationState.NotEstablished, Tier0Reachability.Unknown),
            (Assessment(reader).Permission.Authorization, Assessment(reader).Obtainability, reader.ReadTier0Path(UserDn).Reachability));
    }

    [Fact]
    public void MissingPrimaryGroupEvidenceIsNotInvented()
    {
        var directory = Capture(userAttributes: Account("512", null));
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), OwnAccountMembershipIssue.PrimaryGroupMissing);
    }

    [Theory]
    [InlineData(null, OwnAccountMembershipIssue.GroupTypeMissing)]
    [InlineData(2L, OwnAccountMembershipIssue.GroupScopeUnsupported)]
    [InlineData(-2147483644L, OwnAccountMembershipIssue.GroupScopeUnsupported)]
    [InlineData(-2147483640L, OwnAccountMembershipIssue.GroupScopeUnsupported)]
    public void UnsupportedTargetGroupsAreNotPromoted(long? type, OwnAccountMembershipIssue expected)
    {
        var directory = Capture(groupType: type);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), expected);
    }

    [Fact]
    public void ComputersDoNotEnterTheOrdinaryUserOperationModel()
    {
        var directory = Capture(userClasses: ["top", "user", "computer"]);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), OwnAccountMembershipIssue.RequesterUnsupported);
    }

    [Theory]
    [InlineData(HolderSid, OwnAccountMembershipIssue.IdentityUnresolved)]
    public void UnqualifiedRequesterIdentitiesRemainExplicit(string sid, OwnAccountMembershipIssue expected)
    {
        var directory = Capture(userSid: sid);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), expected);
    }

    [Fact]
    public void ARequesterInAnotherCapturedDomainCannotUseTheSameDomainOperation()
    {
        const string requester = "CN=CrossDomain,DC=child,DC=contoso,DC=com";
        var directory = Capture(crossDomainRequester: true);
        Derive(directory);
        Judge(directory, [new(requester, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assert.Single(reader.ReadTier0Path(requester).OwnAccountAssessments), OwnAccountMembershipIssue.ResourceContextUnsupported);
    }

    [Fact]
    public void AChangedRightNameCannotRedefineTheValidatedOperation()
    {
        const string otherGuid = "11111111-1111-1111-1111-111111111111";
        var directory = Capture(descriptor: $"O:SYG:SYD:(OA;;SW;{otherGuid};;{UserSid})", selfGuidOverride: otherGuid);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Assessment(reader).Permission.Authorization);
    }

    [Theory]
    [InlineData(MemberGuid, ControlEvaluationState.Established)]
    [InlineData("11111111-1111-1111-1111-111111111111", ControlEvaluationState.NotEstablished)]
    public void ExistingRequesterAuthorizationUsesTheMicrosoftIdentifier(string guid, ControlEvaluationState expected)
    {
        var directory = Capture(descriptor: $"O:SYG:SYD:(OA;;SW;{guid};;{UserSid})",
            selfGuidOverride: "11111111-1111-1111-1111-111111111111");
        Derive(directory);
        var result = JudgingRun.Judge(directory, [], [new SelfMembershipRequest(UserDn, TargetDn, SelfMembershipOperation.Add, null)],
            SelfMembershipBudget.Default, Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Equal(expected, Assert.Single(reader.ReadSelfMembershipAssessments(TargetDn, UserDn).Assessments).Authorization);
    }

    [Fact]
    public void AnArbitraryNamedRightDoesNotCreateASelfMembershipHolderEdge()
    {
        const string otherGuid = "11111111-1111-1111-1111-111111111111";
        var directory = Capture(descriptor: $"O:SYG:SYD:(OA;;SW;{otherGuid};;{UserSid})", selfGuidOverride: otherGuid);
        Derive(directory);
        Judge(directory, []);
        using var reader = Open(directory);

        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Where(edge => edge.Capability == ControlCapability.CanAddSelfToGroup));
    }

    [Fact]
    public void GenuineSelfMembershipSurvivesMisleadingCapturedNameMetadata()
    {
        var directory = Capture(selfGuidOverride: "11111111-1111-1111-1111-111111111111");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Reachable, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Theory]
    [InlineData(MemberGuid, 2)]
    [InlineData("11111111-1111-1111-1111-111111111111", 0)]
    public void TheOfflineDiscoveryFilterUsesTheSameFixedIdentifier(string guid, int expected)
    {
        var directory = Capture(descriptor: $"O:SYG:SYD:(OA;;SW;{guid};;{UserSid})",
            selfGuidOverride: "11111111-1111-1111-1111-111111111111");
        Derive(directory);
        var result = JudgingRun.Judge(directory, [], TestBudget, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Equal(expected, reader.ReadSelfMembershipAssessments(TargetDn, UserDn).Assessments.Count);
    }

    [Fact]
    public void AGroupAddCannotUseOnlyPublishedSchemaDefaults()
    {
        var directory = Capture(schema: false);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), OwnAccountMembershipIssue.SchemaEvidenceMissing);
    }

    [Theory]
    [InlineData("searchFlags", null, OwnAccountMembershipIssue.SchemaEvidenceMissing)]
    [InlineData("systemFlags", null, OwnAccountMembershipIssue.SchemaEvidenceMissing)]
    [InlineData("isSingleValued", null, OwnAccountMembershipIssue.SchemaEvidenceMissing)]
    [InlineData("isSingleValued", "TRUE", OwnAccountMembershipIssue.SchemaUnsupported)]
    [InlineData("systemFlags", "0", OwnAccountMembershipIssue.SchemaUnsupported)]
    [InlineData("systemFlags", "22", OwnAccountMembershipIssue.SchemaUnsupported)]
    [InlineData("searchFlags", "4096", OwnAccountMembershipIssue.SchemaUnsupported)]
    [InlineData("schemaIDGUID", "11111111-1111-1111-1111-111111111111", OwnAccountMembershipIssue.SchemaUnsupported)]
    public void MissingAndUnsupportedSchemaPrerequisitesStayDistinct(string field, string? value, OwnAccountMembershipIssue expected)
    {
        var directory = Capture(memberSchema: MemberSchema(field, value));
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        AssertIssue(Assessment(reader), expected);
    }

    [Fact]
    public void ARecordedMemberKeepsItsExistingRouteWithoutAnAdd()
    {
        var directory = Capture(members: [UserDn], schema: false, userAttributes: Account("514", "513"));
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(new[] { Tier0PathStepKind.Membership, Tier0PathStepKind.Membership }, reader.ReadTier0Path(UserDn).Steps.Select(step => step.Kind));
    }

    [Fact]
    public void ExistingMembershipHasItsOwnProofBasis()
    {
        var directory = Capture(members: [UserDn], schema: false, membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(OwnAccountMembershipBasis.ExistingMembership, Assessment(reader).Basis);
    }

    [Fact]
    public void PrimaryGroupMembershipDoesNotRequireOrInventAnAdd()
    {
        var directory = Capture(userAttributes: Account("512", "1200"), schema: false);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal("primaryGroupID", Assert.Single(Assessment(reader).MembershipEvidence).Attribute);
    }

    [Fact]
    public void TerminalGroupDaclAuthorityIsNotAMembershipContinuation()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal((ControlEvaluationState.Established, Tier0Reachability.Unknown),
            (Assessment(reader).Obtainability, reader.ReadTier0Path(UserDn).Reachability));
    }

    [Fact]
    public void AnUnresolvedContinuationIsRecordedWithoutErasingTheOperationProof()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Contains(OwnAccountMembershipIssue.MembershipContinuationUnresolved, Assessment(reader).Issues);
    }

    [Fact]
    public void AnUncertainNewOperationDoesNotEraseAnIndependentProvenRoute()
    {
        var directory = Capture(existingUserRoute: true, schema: false);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Equal(1, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void RequestsDoNotMultiplyNamedHolderEdges()
    {
        var directory = Capture($"O:SYG:SYD:(OA;;SW;{MemberGuid};;{HolderSid})");
        Derive(directory);
        Judge(directory, []);
        long[] before;
        using (var reader = Open(directory)) before = reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Select(edge => edge.Id).ToArray();
        Assert.Single(before);
        Judge(directory, [new(UserDn, TargetDn), new(UserDn, TargetDn)]);
        using var after = Open(directory);

        Assert.Equal(before, after.ReadControlEdges(TargetDn, null, null, true, 0).Edges.Select(edge => edge.Id).ToArray());
    }

    [Fact]
    public void DuplicateExplicitQuestionsAreStoredOnce()
    {
        var directory = Capture();
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn), new(UserDn.ToUpperInvariant(), TargetDn.ToUpperInvariant())]);
        using var reader = Open(directory);

        Assert.Single(reader.ReadTier0Path(UserDn).OwnAccountAssessments);
    }

    [Fact]
    public void TheExistingEntryPointSchedulesNoOwnAccountOperations()
    {
        var directory = Capture();
        Derive(directory);
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Empty(reader.ReadTier0Path(UserDn).OwnAccountAssessments);
    }

    [Fact]
    public void OperationWitnessesKeepTheCapturedAccountAndGroupValues()
    {
        var directory = Prepared();
        using var reader = Open(directory);

        Assert.Equal(new[] { "userAccountControl:512", "primaryGroupID:513", "groupType:-2147483646" }, Assessment(reader).OperationEvidence
            .Where(item => item.Attribute is "userAccountControl" or "primaryGroupID" or "groupType").Select(item => item.Attribute + ":" + item.Value));
    }

    [Theory]
    [InlineData("$.OwnAccounts[0].SourceFingerprint", "changed")]
    [InlineData("$.OwnAccounts[0].Assessment.Permission.Readiness", "Established")]
    [InlineData("$.OwnAccounts[0].Assessment.EvidenceSeal", "changed")]
    [InlineData("$.OwnAccounts[0].Assessment.GenerationId", "11111111-1111-1111-1111-111111111111")]
    [InlineData("$.OwnAccounts[0].Assessment.OperationEvidence[0].Value", "changed")]
    [InlineData("$.OwnAccounts[0].Steps[0].Kind", "Membership")]
    public void AlteredOwnAccountProofIsRejectedEvenWithARefreshedHash(string path, string value)
    {
        var directory = Prepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "','" + value + "')");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void AnOmittedProvenOperationRouteIsRejected()
    {
        var directory = Prepared();
        Mutate(directory, "UPDATE tier0_path_node SET proof=json_set(proof,'$.OwnAccountRoute',NULL),outcome='Unknown' WHERE target LIKE 'CN=Alice,%'");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void OwnAccountReadbackDoesNotModifyEvidenceOrAnalysis()
    {
        var directory = Prepared();
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        var before = Snapshot(directory);

        reader.ReadTier0Path(UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void CancelledOwnAccountJudgingPreservesThePreviousGeneration()
    {
        var directory = Prepared();
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], [], [new(UserDn, TargetDn)], Started, Started,
            new CancelBeforePublication(stopping), RunLog.Discarded, null, stopping.Token));
        using var reader = Open(directory);

        Assert.Equal(previous, Assessment(reader).GenerationId);
    }

    private string Prepared()
    {
        var directory = Capture();
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        return directory;
    }

    private static OwnAccountMembershipAssessment Assessment(JudgementReader reader) => Assert.Single(reader.ReadTier0Path(UserDn).OwnAccountAssessments);

    private static void AssertIssue(OwnAccountMembershipAssessment assessment, OwnAccountMembershipIssue issue,
        ControlEvaluationState state = ControlEvaluationState.Unknown) =>
        Assert.Equal((state, true), (assessment.Obtainability, assessment.Issues.Contains(issue)));

    private static EvidenceAttribute[] Account(string? uac, string? primary) =>
        [.. uac is null ? Array.Empty<EvidenceAttribute>() : [Text("userAccountControl", uac)],
         .. primary is null ? Array.Empty<EvidenceAttribute>() : [Text("primaryGroupID", primary)]];

    private static EvidenceAttribute[] MemberSchema(string field, string? value)
    {
        var values = new[] { Text("lDAPDisplayName", "member"), Binary("schemaIDGUID", Guid.Parse(MemberGuid).ToByteArray()),
            Text("isSingleValued", "FALSE"), Text("systemFlags", "18"), Text("searchFlags", "0") };
        return [.. values.Where(item => item.LdapDisplayName != field), .. value is null ? Array.Empty<EvidenceAttribute>()
            : [field == "schemaIDGUID" ? Binary(field, Guid.Parse(value).ToByteArray()) : Text(field, value)]];
    }

    private sealed class CancelBeforePublication(CancellationTokenSource stopping) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.PublishingJudgement) stopping.Cancel();
        }
    }

    private static string[] Snapshot(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    private static void Mutate(string directory, string sql) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        using var change = connection.CreateCommand();
        change.CommandText = sql;
        change.ExecuteNonQuery();
        foreach (var table in new[] { "tier0_path_calculation", "tier0_path_node" })
        {
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT rowid,proof FROM " + table;
            var proofs = new List<(long Id, string Proof)>();
            using (var read = query.ExecuteReader()) while (read.Read()) proofs.Add((read.GetInt64(0), read.GetString(1)));
            foreach (var proof in proofs)
            {
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE " + table + " SET fingerprint=$hash WHERE rowid=$id";
                update.Parameters.AddWithValue("$hash", SHA256.HashData(Encoding.UTF8.GetBytes(proof.Proof)));
                update.Parameters.AddWithValue("$id", proof.Id);
                update.ExecuteNonQuery();
            }
        }
    });

    private string Capture(string? descriptor = null, string[]? members = null, long? groupType = -2147483646,
        EvidenceAttribute[]? userAttributes = null, string[]? userClasses = null, bool schema = true,
        EvidenceAttribute[]? memberSchema = null, bool membershipTail = true, bool daclTail = false,
        bool existingUserRoute = false, string[]? holderMembers = null, string? coreDescriptor = null, string userSid = UserSid,
        bool crossDomainRequester = false, string? selfGuidOverride = null)
    {
        var directory = Bundle(users: 0, members: members ?? [], groupType: groupType,
            sddl: descriptor ?? $"O:SYG:SYD:(OA;;SW;{MemberGuid};;{UserSid})",
            writeAdditional: (writer, coverage) =>
            {
                Write(writer, coverage, UserDn, userClasses ?? ["top", "person", "organizationalPerson", "user"], userSid,
                    userAttributes ?? [Text("userAccountControl", "512"), Text("primaryGroupID", "513")], "O:SYG:SYD:");
                Write(writer, coverage, HolderDn, ["top", "group"], HolderSid,
                    [Text("groupType", "-2147483646"), Values("member", holderMembers ?? [UserDn])], "O:SYG:SYD:");
                Write(writer, coverage, CoreDn, ["top", "group"], "S-1-5-21-1-2-3-512",
                    [Text("groupType", "-2147483646"), Values("member", existingUserRoute ? [UserDn] : membershipTail ? [TargetDn] : [])],
                    coreDescriptor ?? (daclTail ? $"O:SYG:SYD:(A;;WD;;;{TargetSid})" : "O:SYG:SYD:"));
                if (crossDomainRequester)
                {
                    var child = new PartitionCoverage("DC=child,DC=contoso,DC=com", NamingContextKind.Domain, "dc01.child.contoso.com",
                        ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                    writer.WriteCoverage(child);
                    Write(writer, child, "DC=child,DC=contoso,DC=com", ["top", "domainDNS"], "S-1-5-21-4-5-6", [], "O:SYG:SYD:");
                    Write(writer, child, "CN=CrossDomain,DC=child,DC=contoso,DC=com", ["top", "user"], "S-1-5-21-4-5-6-1100",
                        [Text("userAccountControl", "512")], "O:SYG:SYD:");
                }
                if (selfGuidOverride is not null)
                {
                    var configuration = new PartitionCoverage("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration,
                        "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                    writer.WriteCoverage(configuration);
                    Write(writer, configuration, "CN=Self-Membership,CN=Extended-Rights,CN=Configuration,DC=contoso,DC=com",
                        ["top", "controlAccessRight"], null,
                        [Text("cn", "Self-Membership"), Text("rightsGuid", selfGuidOverride), Text("validAccesses", "8")], null);
                }
                if (!schema) return;
                var partition = new PartitionCoverage(SchemaDn, NamingContextKind.Schema, "dc01.contoso.com",
                    ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
                writer.WriteCoverage(partition);
                Write(writer, partition, "CN=Member," + SchemaDn, ["top", "attributeSchema"], null,
                    memberSchema ?? [Text("lDAPDisplayName", "member"), Binary("schemaIDGUID", Guid.Parse(MemberGuid).ToByteArray()),
                        Text("isSingleValued", "FALSE"), Text("systemFlags", "18"), Text("searchFlags", "0")], null);
                Write(writer, partition, "CN=Group," + SchemaDn, ["top", "classSchema"], null,
                    [Text("lDAPDisplayName", "group"), Binary("schemaIDGUID", Guid.Parse("bf967a9c-0de6-11d0-a285-00aa003049e2").ToByteArray()), Text("systemFlags", "16")], null);
                Write(writer, partition, "CN=User," + SchemaDn, ["top", "classSchema"], null,
                    [Text("lDAPDisplayName", "user"), Binary("schemaIDGUID", Guid.Parse("bf967aba-0de6-11d0-a285-00aa003049e2").ToByteArray()), Text("systemFlags", "16")], null);
            });
        output.WriteLine(directory);
        return directory;
    }

    private static EvidenceAttribute Text(string name, string value) => Values(name, [value]);
    private static EvidenceAttribute Values(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Binary(string name, byte[] bytes) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)]);

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string[] classes, string? sid,
        EvidenceAttribute[] extra, string? descriptor)
    {
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(coverage, dn, guid,
            [Values("objectClass", classes), .. sid is null ? Array.Empty<EvidenceAttribute>() : [Binary("objectSid", Sid.ToBytes(sid)!)], .. extra], Started));
        if (descriptor is null) return;
        var raw = new RawSecurityDescriptor(descriptor);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static void Judge(string directory, IReadOnlyList<OwnAccountMembershipRequest> requests,
        IReadOnlyList<RequesterDaclRequest>? daclRequests = null)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], daclRequests ?? [], requests, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, selfMembershipDiscoveryBudget: null, cancellationToken: CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
