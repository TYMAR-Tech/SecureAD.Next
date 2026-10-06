using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    private const string ObtainedMiddle = "CN=Middle,DC=contoso,DC=com";
    private const string ObtainedMiddleSid = "S-1-5-21-1-2-3-1400";
    private const string ObtainedDeny = "CN=Deny,DC=contoso,DC=com";
    private const string ObtainedDenySid = "S-1-5-21-1-2-3-1500";

    [Theory]
    [InlineData("shell", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("cli-offline", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("cli-capture", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("shell", OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("cli-offline", OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("cli-capture", OwnAccountMembershipPermissionKind.WriteMembers)]
    public async Task ObtainedNestingHostsSelectProveAndPublishTheWholeChain(string host, OwnAccountMembershipPermissionKind kind)
    {
        var directory = ObtainedCapture("nested", kind);
        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        var combined = Assert.IsType<MembershipDaclAssessment>(question.Membership);
        Assert.Equal((ControlEvaluationState.Established, kind, 4),
            (combined.Authorization, combined.Request.PermissionKind, combined.Steps.Count));
        Assert.Equal(new[] { TargetDn, ObtainedMiddle, HolderDn, CoreDn }, combined.Steps.Select(value => value.To.DistinguishedName));
        Assert.Equal(Tier0PathStepKind.OwnAccountMembership, combined.Steps[0].Kind);
        Assert.Equal(new[] { 0, 0, 1 }, reader.ReadPathRequesterCoverage().Families.Select(value => value.SelectedQuestions));
        var finding = Assert.Single(reader.Read().Findings, value => value.RuleId == "SEC-071");
        Assert.Equal((Severity.High, 1), (finding.Severity, Assert.IsType<Tier0RouteFindingEvidence>(finding.Evidence).UnexpectedChecks));
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
        Assert.DoesNotContain(reader.ReadPathInputs().FixedTargets, value => value.DistinguishedName == TargetDn);
    }

    [Fact]
    public void ObtainedNestingRetainsBothPermissionsDirectWitnessesAndExactBindings()
    {
        using var reader = Open(ObtainedPrepared("ordinals"));
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        var combined = question.Membership!;
        var dacl = combined.Dacl!;
        var entry = Assert.Single(dacl.Evidence);
        var nesting = Assert.IsType<RequesterMembershipEvidence>(entry.ObtainedGroupMembership);
        Assert.Null(entry.Membership);
        Assert.Equal(RequesterTrusteeReason.ObtainedGlobalMembership, entry.Trustee.Reason);
        Assert.Equal(new[] { (TargetDn, ObtainedMiddle, 1), (ObtainedMiddle, HolderDn, 0) },
            nesting.Links.Select(link => (link.Member.DistinguishedName, link.Group.DistinguishedName, link.Witness.Ordinal)));
        Assert.Null(combined.Membership.Permission.MemberPresent);
        Assert.Equal(ControlEvaluationState.Unknown, combined.Membership.Permission.Readiness);
        Assert.Equal((reader.Description.GenerationId, reader.Description.DerivationGenerationId, reader.Description.EvidenceSeal),
            (combined.GenerationId, dacl.DerivationGenerationId, dacl.EvidenceSeal));
        Assert.Equal(new long?[] { combined.Membership.Permissions.Single().Id, null, null, dacl.Permissions.Single().Id },
            combined.Steps.Select(step => step.PermissionId));
        Assert.Equal((UserSid, ControlCapability.CanAddSelfToGroup),
            (reader.ReadControlEdge(TargetDn, combined.Steps[0].PermissionId!.Value).HolderSid,
                reader.ReadControlEdge(TargetDn, combined.Steps[0].PermissionId!.Value).Capability));
        Assert.Equal((HolderSid, CoreDn), (reader.ReadControlEdge(CoreDn, combined.Steps[^1].PermissionId!.Value).HolderSid,
            combined.Steps[^1].To.DistinguishedName));
        using var sources = ControlProofVerification.OpenSources(reader);
        RequesterMembershipContext.RequireGroupSources(nesting, combined.Membership.Target!, dacl.Target!, HolderSid,
            sources.Bundle.ReadObjectAttributes, CancellationToken.None);
        var relation = Assert.Single(reader.ReadPathInputs().AdmissionRelationships,
            value => value.Controller.DistinguishedName == TargetDn && value.Witness?.GroupMembership is not null);
        Assert.Equal(Tier0State.Unknown, relation.State);
        Assert.Equal(Tier0PathCalculation.Fingerprint(nesting), Tier0PathCalculation.Fingerprint(relation.Witness!.GroupMembership));
        var terminal = Assert.Single(reader.ReadTier0Path(UserDn).RequesterSelection!.Candidates).Witnesses.Single(value => value.ResourceDn == CoreDn);
        Assert.Equal((HolderDn, 2), (terminal.HolderDn, terminal.Membership!.Links.Count));
    }

    [Theory]
    [InlineData("new-deny", ControlEvaluationState.NotEstablished)]
    [InlineData("existing-deny", ControlEvaluationState.NotEstablished)]
    [InlineData("allow-first", ControlEvaluationState.Established)]
    [InlineData("unknown-deny", ControlEvaluationState.Unknown)]
    [InlineData("scoped-deny", ControlEvaluationState.Unknown)]
    [InlineData("inherit-only-deny", ControlEvaluationState.Established)]
    public void ObtainedNestingChecksExistingAndNewlyApplicableDeniesInOrder(string variant, ControlEvaluationState expected)
    {
        var allow = $"(A;;WD;;;{HolderSid})";
        var deny = variant switch
        {
            "unknown-deny" => "(D;;WD;;;S-1-5-21-1-2-3-1999)",
            "scoped-deny" => $"(OD;;WD;{MemberGuid};;{ObtainedDenySid})",
            "inherit-only-deny" => $"(D;CIIO;WD;;;{ObtainedDenySid})",
            _ => $"(D;;WD;;;{ObtainedDenySid})",
        };
        using var reader = Open(ObtainedPrepared(variant, descriptor: "O:SYG:SYD:" + (variant == "allow-first" ? allow + deny : deny + allow)));
        var combined = Combined(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Membership.Obtainability);
        Assert.Equal(expected, combined.Authorization);
        if (variant == "new-deny")
            Assert.Equal(TargetDn, combined.Dacl!.Evidence[0].ObtainedGroupMembership!.Links[0].Member.DistinguishedName);
        if (variant == "existing-deny")
            Assert.Equal(UserDn, combined.Dacl!.Evidence[0].Membership!.Links[0].Member.DistinguishedName);
        if (variant == "allow-first") Assert.Single(combined.Dacl!.Evidence);
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers)]
    public void ObtainedNestingNeverUsesTheProposedMembershipToAuthorizeItsOwnAdd(OwnAccountMembershipPermissionKind kind)
    {
        using var reader = Open(ObtainedPrepared("self-authorized", kind, explicitQuestion: true));
        var combined = Combined(reader);
        Assert.Equal(ControlEvaluationState.Unknown, combined.Membership.Obtainability);
        Assert.Null(combined.Dacl);
        Assert.Empty(combined.Steps);
    }

    [Theory]
    [InlineData("distribution")]
    [InlineData("universal")]
    [InlineData("domain-local")]
    [InlineData("cross-domain")]
    [InlineData("missing-type")]
    [InlineData("middle-history")]
    [InlineData("missing-link")]
    [InlineData("second-operation")]
    [InlineData("primary")]
    [InlineData("member-of-only")]
    public void ObtainedNestingDoesNotPromoteUnsupportedContinuations(string variant)
    {
        using var reader = Open(ObtainedPrepared(variant, explicitQuestion: true));
        var combined = Combined(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Membership.Obtainability);
        Assert.Equal(ControlEvaluationState.Unknown, combined.Authorization);
        Assert.Empty(combined.Steps);
        Assert.NotEmpty(combined.Dacl!.Issues);
    }

    [Fact]
    public void ObtainedNestingPreservesCapturedMembershipWithoutInventingAnOperation()
    {
        using var reader = Open(ObtainedPrepared("already-member"));
        var combined = Combined(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Authorization);
        Assert.Equal(OwnAccountMembershipBasis.ExistingMembership, combined.Membership.Basis);
        Assert.All(combined.Steps.Take(3), step => Assert.Equal(Tier0PathStepKind.Membership, step.Kind));
        Assert.Empty(combined.Membership.Permissions);
        Assert.Equal("member", combined.Steps[0].MembershipWitness!.Attribute);
    }

    [Fact]
    public void ObtainedNestingCyclesRemainFiniteAndDoNotMultiplyHolderPermissions()
    {
        using var reader = Open(ObtainedPrepared("cycle"));
        var combined = Combined(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Authorization);
        Assert.Equal(new[] { TargetDn, ObtainedMiddle, HolderDn, CoreDn }, combined.Steps.Select(step => step.To.DistinguishedName));
        Assert.Single(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges.Where(value => value.IsCounted));
        Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
    }

    [Fact]
    public void ObtainedNestingCurrentAdministratorsRemainExpected()
    {
        using var reader = Open(ObtainedPrepared("administrator"));
        var combined = Combined(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Authorization);
        Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.ExpectedRoute, null, CancellationToken.None).Questions
            .Where(question => question.Risk.Family == PathRequesterFamily.MembershipDacl));
        Assert.DoesNotContain(reader.Read().Findings, value => value.RuleId == "SEC-071");
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers)]
    public void ObtainedNestingSavedPresentationNamesTheActualGrantingGroupAndAllSteps(OwnAccountMembershipPermissionKind kind)
    {
        var directory = ObtainedPrepared("nested", kind);
        var before = Snapshot(directory);
        using var source = new BundleAssetSource();
        var read = source.ReadSavedTier0Path(directory, UserDn);
        Assert.True(read.IsSuccess, read.Error?.Description);
        var saved = read.Value!;
        var row = new SavedPathQuestionViewModel(Assert.Single(saved.Page.Questions), saved);
        Assert.Equal(4, row.Steps.Count);
        Assert.Contains("Target (group)", row.Heading);
        Assert.Contains(row.PermissionDetails, value => value.Value.Contains("Holder (group);", StringComparison.Ordinal));
        Assert.Contains("no Add was performed", row.Steps[0].Description);
        Assert.Contains(row.Entries, value => value.Value.Contains(kind == OwnAccountMembershipPermissionKind.SelfMembership
            ? "Self-Membership" : "Write members", StringComparison.Ordinal));
        Assert.Contains(row.Entries, value => value.Value.Contains("obtainable-membership assumption", StringComparison.Ordinal));
        Assert.Equal(before, Snapshot(directory));
    }

    private string ObtainedPrepared(string variant, OwnAccountMembershipPermissionKind kind = OwnAccountMembershipPermissionKind.SelfMembership,
        string? descriptor = null, bool explicitQuestion = false)
    {
        var directory = ObtainedCapture(variant, kind, descriptor, explicitQuestion);
        Derive(directory);
        if (explicitQuestion) JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn) { PermissionKind = kind }]);
        else JudgeCoverage(directory);
        return directory;
    }

    private string ObtainedCapture(string variant, OwnAccountMembershipPermissionKind kind, string? descriptor = null,
        bool independentAdmission = false)
    {
        var right = kind == OwnAccountMembershipPermissionKind.SelfMembership ? "SW" : "WP";
        var middle = variant == "cross-domain" ? "CN=Middle,DC=child,DC=contoso,DC=com" : ObtainedMiddle;
        var middleType = variant switch { "distribution" => "2", "universal" => "-2147483640", "domain-local" => "-2147483644", "missing-type" => null, _ => "-2147483646" };
        return Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{(variant == "self-authorized" ? TargetSid : UserSid)})",
            members: variant == "already-member" ? [UserDn] : variant == "cycle" ? [HolderDn] : [],
            membershipTail: independentAdmission, existingUserRoute: variant == "administrator", holderMembers: [middle],
            coreDescriptor: descriptor ?? $"O:SYG:SYD:(A;;WD;;;{HolderSid})",
            userAttributes: variant == "primary" ? Account("512", "1200") : variant == "member-of-only"
                ? [.. Account("512", "513"), Text("memberOf", TargetDn)] : null,
            additional: (writer, domain) =>
            {
                var members = variant is "missing-link" or "second-operation" ? Array.Empty<string>()
                    : variant == "ordinals" ? new[] { ObtainedDeny, TargetDn } : new[] { TargetDn };
                var middleDomain = domain;
                if (variant == "cross-domain")
                {
                    middleDomain = new("DC=child,DC=contoso,DC=com", NamingContextKind.Domain, "dc01.child.contoso.com",
                        ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                    writer.WriteCoverage(middleDomain);
                    Write(writer, middleDomain, "DC=child,DC=contoso,DC=com", ["top", "domainDNS"], "S-1-5-21-4-5-6", [], "O:SYG:SYD:");
                }
                Write(writer, middleDomain, middle, ["top", "group"],
                    variant == "cross-domain" ? "S-1-5-21-4-5-6-1400" : ObtainedMiddleSid,
                    [Values("member", members), .. middleType is null ? [] : new[] { Text("groupType", middleType) },
                        .. variant == "middle-history" ? new[] { Binary("sIDHistory", Sid.ToBytes("S-1-5-21-9-8-7-1400")!) } : []],
                    variant == "second-operation" ? $"O:SYG:SYD:(OA;;WP;{MemberGuid};;{TargetSid})" : "O:SYG:SYD:");
                Write(writer, domain, ObtainedDeny, ["top", "group"], ObtainedDenySid,
                    [Text("groupType", "-2147483646"), Text("member", variant == "existing-deny" ? "CN=Existing,DC=contoso,DC=com" : TargetDn)],
                    "O:SYG:SYD:");
                if (variant == "existing-deny")
                    Write(writer, domain, "CN=Existing,DC=contoso,DC=com", ["top", "group"], "S-1-5-21-1-2-3-1600",
                        [Text("groupType", "-2147483646"), Text("member", UserDn)], "O:SYG:SYD:");
                Write(writer, domain, "CN=Domain Users,DC=contoso,DC=com", ["top", "group"], "S-1-5-21-1-2-3-513",
                    [Text("groupType", "-2147483646")], "O:SYG:SYD:");
                var configuration = new PartitionCoverage("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration,
                    "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                writer.WriteCoverage(configuration);
                Write(writer, configuration, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com",
                    ["top", "nTDSService"], null, [Text("dSHeuristics", "0")], "O:SYG:SYD:");
            });
    }
}
