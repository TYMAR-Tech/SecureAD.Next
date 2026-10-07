using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class SameForestRequesterTests
{
    [Theory]
    [InlineData("shell", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("cli-offline", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("cli-capture", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("shell", OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("cli-offline", OwnAccountMembershipPermissionKind.WriteMembers)]
    [InlineData("cli-capture", OwnAccountMembershipPermissionKind.WriteMembers)]
    public async Task ForestContinuationHostsSelectAndSaveBothPermissionFamilies(string host, OwnAccountMembershipPermissionKind kind)
    {
        var directory = Capture("nested", obtained: kind);
        await OwnAccountMembershipPathTests.RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        var combined = Continuation(reader);
        Assert.Equal((ControlEvaluationState.Established, kind, 4),
            (combined.Authorization, combined.Request.PermissionKind, combined.Steps.Count));
        Assert.Equal(new[] { Global, Universal, Local, Target }, combined.Steps.Select(step => step.To.DistinguishedName));
        Assert.Equal(Tier0PathStepKind.OwnAccountMembership, combined.Steps[0].Kind);
        Assert.Equal(RootB, combined.Dacl!.ResourceContext!.ResourceDomain.NamingContext);
        Assert.Equal(new[] { 0, 0, 1 }, reader.ReadPathRequesterCoverage().Families.Select(value => value.SelectedQuestions));
        Assert.Equal(Severity.High, Assert.Single(reader.Read().Findings, value => value.RuleId == "SEC-071").Severity);
        Assert.DoesNotContain(reader.ReadPathInputs().FixedTargets, value => value.DistinguishedName == Global);
        Assert.Single(reader.ReadControlEdges(Target, null, null, true, 0).Edges.Where(value => value.IsCounted));
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
    }

    [Theory]
    [InlineData("global", 2)]
    [InlineData("universal", 3)]
    [InlineData("nested", 4)]
    [InlineData("builtin", 3)]
    public void ForestContinuationUsesTheActualResourceDomainAndGrantingGroup(string variant, int steps)
    {
        using var reader = Open(ContinuationPrepared(variant));
        var combined = Continuation(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Authorization);
        Assert.Equal(steps, combined.Steps.Count);
        Assert.Equal(RootB, combined.Dacl!.ResourceContext!.ResourceDomain.NamingContext);
        Assert.Equal(variant == "builtin" ? BuiltinB : variant == "global" ? Global : variant == "universal" ? Universal : Local,
            combined.Steps[^1].From.DistinguishedName);
    }

    [Theory]
    [InlineData("new-deny", ControlEvaluationState.NotEstablished)]
    [InlineData("existing-deny", ControlEvaluationState.NotEstablished)]
    [InlineData("allow-first", ControlEvaluationState.Established)]
    [InlineData("unknown-deny", ControlEvaluationState.Unknown)]
    [InlineData("scoped-deny", ControlEvaluationState.Unknown)]
    [InlineData("inherit-only", ControlEvaluationState.Established)]
    public void ForestContinuationChecksExistingAndObtainedDeniesInOrder(string variant, ControlEvaluationState expected)
    {
        var allow = $"(A;;WD;;;{SidB}-1400)";
        var deny = variant switch
        {
            "unknown-deny" => "(D;;WD;;;S-1-5-21-7-8-9-1700)",
            "scoped-deny" => $"(OD;;WD;bf9679c0-0de6-11d0-a285-00aa003049e2;;{SidB}-1500)",
            "inherit-only" => $"(D;CIIO;WD;;;{SidB}-1500)",
            _ => $"(D;;WD;;;{SidB}-1500)",
        };
        using var reader = Open(ContinuationPrepared(variant, descriptor: "O:SYG:SYD:" + (variant == "allow-first" ? allow + deny : deny + allow)));
        var combined = Continuation(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Membership.Obtainability);
        Assert.Equal(expected, combined.Authorization);
        if (variant == "new-deny")
            Assert.Equal(Global, combined.Dacl!.Evidence[0].ObtainedGroupMembership!.Links[0].Member.DistinguishedName);
        if (variant == "existing-deny")
            Assert.Equal(RequesterTrusteeReason.DirectSecurityMembership, combined.Dacl!.Evidence[0].Trustee.Reason);
    }

    [Theory]
    [InlineData("self-authorized")]
    [InlineData("initial-universal")]
    [InlineData("no-schema")]
    public void ForestContinuationDoesNotWidenOrSelfAuthorizeTheFirstMembership(string variant)
    {
        foreach (var kind in Enum.GetValues<OwnAccountMembershipPermissionKind>())
        {
            using var reader = Open(ContinuationPrepared(variant, kind, explicitQuestion: true));
            var combined = Continuation(reader);
            Assert.Equal(ControlEvaluationState.Unknown, combined.Membership.Obtainability);
            Assert.Null(combined.Dacl);
            Assert.Empty(combined.Steps);
        }
    }

    [Theory]
    [InlineData("illegal-global")]
    [InlineData("illegal-universal")]
    [InlineData("missing-type")]
    [InlineData("missing-link")]
    [InlineData("group-history")]
    [InlineData("undeclared")]
    [InlineData("excluded")]
    public void ForestContinuationUnsupportedEvidenceIsNotAProvenRoute(string variant)
    {
        using var reader = Open(ContinuationPrepared(variant, explicitQuestion: true));
        var combined = Continuation(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Membership.Obtainability);
        Assert.Equal(ControlEvaluationState.Unknown, combined.Authorization);
        Assert.Empty(combined.Steps);
        Assert.NotEmpty(combined.Dacl!.Issues);
    }

    [Fact]
    public void ForestContinuationDomainLocalOutsideTheResourceCannotGrant()
    {
        var directory = Capture("outside-domain", obtained: OwnAccountMembershipPermissionKind.SelfMembership, independentAdmission: true);
        Derive(directory);
        JudgeContinuation(directory, RootA);
        using var reader = Open(directory);
        var combined = Continuation(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Membership.Obtainability);
        Assert.Equal(ControlEvaluationState.NotEstablished, combined.Authorization);
        Assert.Equal(RequesterTrusteeReason.DomainLocalOutsideResource, Assert.Single(combined.Dacl!.Evidence).Trustee.Reason);
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers)]
    public void ForestContinuationObtainedHistoryCannotExcludeAnOtherwiseOutOfDomainDeny(OwnAccountMembershipPermissionKind kind)
    {
        using var reader = Open(ContinuationPrepared("origin-history", kind,
            descriptor: $"O:SYG:SYD:(D;;WD;;;{SidA}-1600)(A;;WD;;;{SidA}-1200)"));
        var combined = Continuation(reader);
        Assert.Equal(ControlEvaluationState.Established, combined.Membership.Obtainability);
        Assert.Equal(ControlEvaluationState.Unknown, combined.Authorization);
        Assert.Equal(RequesterTrusteeReason.UnsupportedIdentity, combined.Dacl!.Evidence[0].Trustee.Reason);
        Assert.Empty(combined.Steps);
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers)]
    public void ForestContinuationSavedReadKeepsConditionalWordingDomainsAndOriginalProof(OwnAccountMembershipPermissionKind kind)
    {
        var directory = ContinuationPrepared("nested", kind);
        using var reader = Open(directory);
        var combined = Continuation(reader);
        using (var sources = ControlProofVerification.OpenSources(reader))
        {
            var evidence = Assert.Single(combined.Dacl!.Evidence);
            Assert.Equal(Tier0PathCalculation.Fingerprint(Assert.Single(sources.Bundle.ReadPermissions(Target)!.Entries)),
                Tier0PathCalculation.Fingerprint(evidence.Entry));
            Assert.Equal(new[] { (Global, Universal), (Universal, Local) },
                evidence.ObtainedGroupMembership!.Links.Select(link => (link.Member.DistinguishedName, link.Group.DistinguishedName)));
            foreach (var link in evidence.ObtainedGroupMembership.Links)
                Assert.Contains(sources.Bundle.ReadObjectAttributes(link.Group.DistinguishedName)!.Find("member")!.Values,
                    value => value.Ordinal == link.Witness.Ordinal && value.Stored == link.Witness.Value);
            PathProofVerification.ReadInputs(reader);
        }
        var before = Snapshot(directory);
        using var source = new BundleAssetSource();
        var saved = source.ReadSavedTier0Path(directory, Actor).Value!;
        var row = new SavedPathQuestionViewModel(Assert.Single(saved.Page.Questions), saved);
        Assert.Contains("Alice (contoso.com)", row.Heading);
        Assert.Contains("Access (contoso.com)", row.Heading);
        Assert.Contains("Domain Admins (branch.example)", row.Heading);
        Assert.Contains(row.PermissionDetails, value => value.Value.Contains("Access (branch.example) (group)", StringComparison.Ordinal));
        Assert.Contains(row.Entries, value => value.Value.Contains("obtainable-membership assumption", StringComparison.Ordinal));
        Assert.Equal(before, Snapshot(directory));
    }

    [Theory]
    [InlineData("$.Dacl.ResourceContext.ResourceDomain.DomainFqdn", "'contoso.com'")]
    [InlineData("$.Dacl.ResourceContext.ReadDomains", "json('[\"branch.example\"]')")]
    [InlineData("$.Dacl.ObtainedMembership.TargetDn", "'CN=Wrong,DC=contoso,DC=com'")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.Links[0].GroupType", "-2147483646")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.Links[1].Group.DomainFqdn", "'contoso.com'")]
    [InlineData("$.Dacl.Steps[0].PermissionId", "987654321")]
    [InlineData("$.Dacl.EvidenceSeal", "'changed'")]
    public void ForestContinuationSavedReaderRefusesBrokenBindings(string path, string value)
    {
        var directory = ContinuationPrepared("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.MembershipDacls[0].Assessment" + path[1..], value);
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadPathRiskPage(Actor, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None));
    }

    private static MembershipDaclAssessment Continuation(JudgementReader reader) =>
        Assert.Single(reader.ReadTier0Path(Actor).MembershipDaclAssessments);

    private static string ContinuationPrepared(string variant,
        OwnAccountMembershipPermissionKind kind = OwnAccountMembershipPermissionKind.SelfMembership,
        string? descriptor = null, bool explicitQuestion = false)
    {
        var directory = Capture(variant, descriptor, kind, explicitQuestion);
        Derive(directory);
        if (explicitQuestion) JudgeContinuation(directory, Target, kind);
        else
        {
            var result = JudgingRun.JudgeAudit(directory, [new UnexpectedTier0Route()], PathRequesterPolicy.SupportedCapturedQuestions,
                Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
            Assert.True(result.IsSuccess, result.Error?.Description);
        }
        return directory;
    }

    private static void JudgeContinuation(string directory, string target,
        OwnAccountMembershipPermissionKind kind = OwnAccountMembershipPermissionKind.SelfMembership)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], [], [],
            new[] { new MembershipDaclRequest(Actor, Global, target) { PermissionKind = kind } },
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }
}
