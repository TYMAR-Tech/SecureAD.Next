using SecureAD.Audit.Capture;
using SecureAD.Cli;
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
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task SameForestHostsProveGlobalUniversalLocalRoutesAcrossDifferentDnsTrees(string host)
    {
        var directory = Capture("nested");
        if (host == "shell")
        {
            Derive(directory);
            var result = await new JudgingLauncher(discoveryBudget: null).RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);
            Assert.True(result.IsSuccess, result.Error?.Description);
        }
        else if (host == "cli-offline")
        {
            Derive(directory);
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--judge", directory])!, CancellationToken.None, discoveryBudget: null,
                capture: _ => throw new InvalidOperationException("Offline judging must not capture.")));
        }
        else Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--library", System.IO.Path.GetDirectoryName(directory)!])!, CancellationToken.None,
            discoveryBudget: null, capture: _ => Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null)))));
        using var reader = Open(directory);
        var assessment = Assessment(reader);
        Assert.Equal(ControlEvaluationState.Established, assessment.Authorization);
        Assert.Equal(new[] { Global, Universal, Local, Target }, assessment.Steps.Select(step => step.To.DistinguishedName));
        Assert.Equal(RootB, assessment.ResourceContext!.ResourceDomain.DistinguishedName);
        Assert.Equal(new[] { B, A }, assessment.ResourceContext.ReadDomains);
        var finding = Assert.Single(reader.Read().Findings, value => value.RuleId == "SEC-071");
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
    }

    [Theory]
    [InlineData("global", 2)]
    [InlineData("universal", 3)]
    [InlineData("nested", 4)]
    public void SameForestGroupScopesCanGrantInTheVerifiedResourceDomain(string variant, int steps)
    {
        using var reader = Open(Prepared(variant));
        Assert.Equal((ControlEvaluationState.Established, steps), (Assessment(reader).Authorization, Assessment(reader).Steps.Count));
        var edge = Assert.Single(reader.ReadControlEdges(Target, null, null, true, 0).Edges.Where(value => value.IsCounted));
        Assert.Equal(edge.Id, Assessment(reader).Permissions.Single().Id);
    }

    [Theory]
    [InlineData("deny-first", ControlEvaluationState.NotEstablished)]
    [InlineData("allow-first", ControlEvaluationState.Established)]
    [InlineData("unknown-first", ControlEvaluationState.Unknown)]
    [InlineData("scoped-deny", ControlEvaluationState.Unknown)]
    public void SameForestChecksAllRelevantDeniesInCapturedOrder(string order, ControlEvaluationState expected)
    {
        var allow = $"(A;;WD;;;{SidB}-1400)";
        var deny = order == "unknown-first" ? "(D;;WD;;;S-1-5-21-7-8-9-1700)"
            : order == "scoped-deny" ? $"(OD;;WD;bf9679c0-0de6-11d0-a285-00aa003049e2;;{SidB}-1500)"
            : $"(D;;WD;;;{SidB}-1500)";
        using var reader = Open(Prepared("nested", "O:SYG:SYD:" + (order == "allow-first" ? allow + deny : deny + allow)));
        Assert.Equal(expected, Assessment(reader).Authorization);
        if (order == "deny-first")
            Assert.Equal(new[] { Global, Universal, Denying }, Assessment(reader).Evidence[0].Membership!.Links.Select(link => link.Group.DistinguishedName));
    }

    [Theory]
    [InlineData("illegal-global")]
    [InlineData("illegal-universal")]
    [InlineData("missing-type")]
    [InlineData("primary")]
    [InlineData("history")]
    [InlineData("group-history")]
    [InlineData("undeclared")]
    [InlineData("excluded")]
    [InlineData("computer")]
    public void SameForestUnsupportedOrUnboundContextsRemainExplicit(string variant)
    {
        using var reader = Open(Prepared(variant, automatic: false));
        var assessment = Assessment(reader);
        Assert.Equal(ControlEvaluationState.Unknown, assessment.Authorization);
        Assert.Empty(assessment.Steps);
        Assert.NotEmpty(assessment.Issues);
    }

    [Fact]
    public void SameForestDomainLocalPermissionDoesNotApplyInAnotherResourceDomain()
    {
        using var reader = Open(Prepared("outside-domain", automatic: false, target: RootA));
        var answer = Assert.Single(Assessment(reader).Evidence).Trustee;
        Assert.Equal((RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.DomainLocalOutsideResource), (answer.State, answer.Reason));
        Assert.Equal(ControlEvaluationState.NotEstablished, Assessment(reader).Authorization);
    }

    [Fact]
    public void SameForestBuiltinSidsBindToTheResourcesDomainRatherThanTheRequestersDomain()
    {
        using var reader = Open(Prepared("builtin"));
        var assessment = Assessment(reader);
        Assert.Equal((ControlEvaluationState.Established, ""), (assessment.Authorization, string.Join(", ", assessment.Issues)));
        Assert.Equal(BuiltinB, assessment.Steps[^1].From.DistinguishedName);
        var edge = reader.ReadControlEdge(Target, assessment.Permissions.Single().Id);
        Assert.Equal(("S-1-5-32-544", B), (edge.HolderSid, edge.HolderScope));
        Assert.Equal(B, assessment.Steps[^1].From.SidScope);
        Assert.Empty(reader.ReadTier0Path(Other).RequesterAssessments);
    }

    [Fact]
    public void SameForestConfigurationDoesNotBorrowAResourceDomain()
    {
        using var reader = Open(Prepared("nested", automatic: false, target: "CN=Configuration," + RootA));
        Assert.Equal(ControlEvaluationState.Unknown, Assessment(reader).Authorization);
        Assert.Contains(RequesterDaclIssue.ResourceContextUnsupported, Assessment(reader).Issues);
        Assert.Null(Assessment(reader).ResourceContext);
    }

    [Fact]
    public void SameForestCyclesDoNotMultiplyPermissionsOrInventSteps()
    {
        using var reader = Open(Prepared("cycle"));
        var assessment = Assessment(reader);
        Assert.Equal(ControlEvaluationState.Established, assessment.Authorization);
        Assert.Equal(4, assessment.Steps.Count);
        Assert.Single(reader.ReadControlEdges(Target, null, null, true, 0).Edges.Where(edge => edge.IsCounted));
    }

    [Fact]
    public void SameForestExpectedForestAdministrationRemainsExpected()
    {
        using var reader = Open(Prepared("expected"));
        Assert.Equal(ControlEvaluationState.Established, Assessment(reader).Authorization);
        Assert.Single(reader.ReadPathRiskPage(Actor, PathRiskVerdict.ExpectedRoute, null, CancellationToken.None).Questions);
        Assert.DoesNotContain(reader.Read().Findings, value => value.RuleId == "SEC-071");
    }

    [Fact]
    public void SameForestCrossDomainLabelsDisambiguateAccountTargetAndBothAccessGroups()
    {
        var directory = Prepared("nested");
        using var source = new BundleAssetSource();
        var saved = source.ReadSavedTier0Path(directory, Actor).Value!;
        var question = Assert.Single(saved.Page.Questions);
        var row = new SavedPathQuestionViewModel(question, saved);
        Assert.Contains("Alice (contoso.com)", row.Heading);
        Assert.Contains("Domain Admins (branch.example)", row.Heading);
        Assert.Contains(row.PermissionDetails, field => field.Value.Contains("Access (branch.example) (group)", StringComparison.Ordinal));
        Assert.Equal("Alice (contoso.com) is a member of Access (contoso.com) (group).", row.Steps[0].Description);
        Assert.Equal("Universal (branch.example) is a member of Access (branch.example) (group).", row.Steps[2].Description);
        Assert.Contains("Access (branch.example)", row.RecommendedChange);
        Assert.Contains("Domain Admins (branch.example)", row.WhereToChange);
    }
}
