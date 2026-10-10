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

public sealed partial class NestedRequesterPathTests
{
    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task NestedPermissionIsAutomaticallySelectedQualifiedAndPublishedByEveryHost(string host)
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
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--judge", directory])!, CancellationToken.None,
                discoveryBudget: null, capture: _ => throw new InvalidOperationException("This check must not capture.")));
        }
        else
            Assert.Equal(0, await Program.RunAsync(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!])!, CancellationToken.None,
                discoveryBudget: null, capture: _ => Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null)))));
        using var reader = Open(directory);
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        var finding = Assert.Single(reader.Read().Findings, value => value.RuleId == "SEC-071");
        Assert.Equal((ControlEvaluationState.Established, PathRequesterFamily.RequesterDacl, 3),
            (question.Risk.Authorization, question.Risk.Family, question.Steps.Count));
        Assert.Equal((Severity.High, 1), (finding.Severity, Assert.IsType<Tier0RouteFindingEvidence>(finding.Evidence).UnexpectedChecks));
        Assert.Equal(new[] { 1, 0, 0 }, reader.ReadPathRequesterCoverage().Families.Select(value => value.SelectedQuestions));
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
    }

    [Fact]
    public void NestedProofRetainsDirectOrdinalsCompleteIdentitiesAndOriginalGrant()
    {
        using var reader = Open(Prepare("ordinals"));
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        var assessment = Assert.IsType<RequesterDaclAssessment>(question.Requester);
        var evidence = Assert.Single(assessment.Evidence);
        var membership = Assert.IsType<RequesterMembershipEvidence>(evidence.Membership);
        Assert.Equal(RequesterTrusteeReason.NestedGlobalMembership, evidence.Trustee.Reason);
        Assert.Null(evidence.Trustee.DirectMemberDn);
        Assert.Equal(new[] { (UserDn, EntryDn, 1), (EntryDn, TargetDn, 1) },
            membership.Links.Select(link => (link.Member.DistinguishedName, link.Group.DistinguishedName, link.Witness.Ordinal)));
        using var sources = ControlProofVerification.OpenSources(reader);
        foreach (var link in membership.Links)
        {
            var member = sources.Bundle.ReadObjectAttributes(link.Member.DistinguishedName)!;
            var group = sources.Bundle.ReadObjectAttributes(link.Group.DistinguishedName)!;
            Assert.Equal(Tier0Target.From(member, Root), link.Member);
            Assert.Equal(Tier0Target.From(group, Root), link.Group);
            Assert.Equal((-2147483646L, group.CapturedUtc, "member", link.Member.DistinguishedName),
                (link.GroupType, link.CapturedUtc, link.Witness.Attribute, link.Witness.Value));
            Assert.Equal(Tier0PathCalculation.Fingerprint(new
            {
                Member = Tier0PathCalculation.Fingerprint(member), Group = Tier0PathCalculation.Fingerprint(group),
            }), link.SourceFingerprint);
        }
        var original = Assert.Single(sources.Bundle.ReadPermissions(CoreDn)!.Entries);
        Assert.Equal(Tier0PathCalculation.Fingerprint(original), Tier0PathCalculation.Fingerprint(evidence.Entry));
        var permission = Assert.Single(assessment.Permissions);
        var edge = reader.ReadControlEdge(CoreDn, permission.Id);
        Assert.Equal((TargetSid, CoreDn, true), (edge.HolderSid, edge.Target, edge.IsCounted));
        Assert.Equal(Tier0PathCalculation.Fingerprint(edge), permission.Fingerprint);
        Assert.Equal((TargetDn, CoreDn, (long?)permission.Id), (assessment.Steps[^1].From.DistinguishedName,
            assessment.Steps[^1].To.DistinguishedName, assessment.Steps[^1].PermissionId));
        Assert.Equal((reader.Description.GenerationId, reader.Description.DerivationGenerationId, reader.Description.EvidenceSeal),
            (assessment.GenerationId, assessment.DerivationGenerationId, assessment.EvidenceSeal));
        Assert.Equal(assessment.Steps, question.Steps);
    }

    [Theory]
    [InlineData("deny-first", ControlEvaluationState.NotEstablished)]
    [InlineData("allow-first", ControlEvaluationState.Established)]
    [InlineData("unknown-first", ControlEvaluationState.Unknown)]
    [InlineData("other-user", ControlEvaluationState.Established)]
    public void NestedAllowsAndDeniesKeepCapturedOrderAndRequesterContext(string order, ControlEvaluationState expected)
    {
        var allow = $"(A;;WD;;;{TargetSid})";
        var deny = $"(D;;WD;;;{DenySid})";
        var descriptor = "O:SYG:SYD:" + (order switch
        {
            "deny-first" => deny + allow,
            "allow-first" => allow + deny,
            "unknown-first" => "(D;;WD;;;S-1-5-21-1-2-3-1999)" + allow,
            _ => $"(D;;WD;;;{OtherSid})" + allow,
        });
        var assessment = Assess("nested", descriptor);
        Assert.Equal(expected, assessment.Authorization);
        if (order == "deny-first")
        {
            var entry = Assert.Single(assessment.Evidence);
            Assert.Equal(DenySid, entry.Entry.Trustee.Sid);
            Assert.Equal(new[] { EntryDn, DenyDn }, entry.Membership!.Links.Select(link => link.Group.DistinguishedName));
            Assert.Empty(assessment.Permissions);
        }
        if (order == "allow-first") Assert.Single(assessment.Evidence);
    }

    [Theory]
    [InlineData("distribution")]
    [InlineData("universal")]
    [InlineData("domain-local")]
    [InlineData("missing-type")]
    [InlineData("cross-domain")]
    [InlineData("primary")]
    [InlineData("member-of-only")]
    [InlineData("history")]
    [InlineData("group-history")]
    [InlineData("duplicate")]
    [InlineData("deleted")]
    public void NestedProofDoesNotBroadenUnsupportedMembershipContexts(string variant)
    {
        var assessment = Assess(variant);
        Assert.Equal(ControlEvaluationState.Unknown, assessment.Authorization);
        Assert.Empty(assessment.Steps);
        Assert.Empty(assessment.Permissions);
    }

    [Fact]
    public void NestedMissingCaptureAndUnsupportedAnalysisRemainDifferentAnswers()
    {
        var missing = Assert.Single(Assess("missing-member").Evidence).Membership!;
        var unsupported = Assert.Single(Assess("universal").Evidence).Membership!;
        Assert.Equal(PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember, missing.Verdict);
        Assert.Contains(PathRequesterSelectionReason.IdentityUnresolved, missing.Limitations);
        Assert.Contains(PathRequesterSelectionReason.GlobalGroupRequired, unsupported.Limitations);
        Assert.DoesNotContain(PathRequesterSelectionReason.IdentityUnresolved, unsupported.Limitations);
    }

    [Fact]
    public void NestedCyclesTerminateWithoutInventingMembershipOrExtraPermissions()
    {
        using var reader = Open(Prepare("cycle"));
        var page = reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None);
        var question = Assert.Single(page.Questions);
        Assert.Equal(new[] { (UserDn, EntryDn), (EntryDn, TargetDn), (TargetDn, CoreDn) },
            question.Steps.Select(step => (step.From.DistinguishedName, step.To.DistinguishedName)));
        Assert.Single(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges.Where(edge => edge.IsCounted));
        Assert.Equal(1, page.Counts.Unexpected);
        var outsider = Assess("cycle", $"O:SYG:SYD:(A;;WD;;;{OtherSid})");
        Assert.Equal(ControlEvaluationState.NotEstablished, outsider.Authorization);
    }

    [Fact]
    public void NestedUnsupportedShortcutDoesNotHideALongerSupportedRoute()
    {
        var assessment = Assess("shortcut");
        Assert.Equal(ControlEvaluationState.Established, assessment.Authorization);
        Assert.Equal(new[] { DeeperDn, EntryDn, TargetDn, CoreDn }, assessment.Steps.Select(step => step.To.DistinguishedName));
        Assert.Contains(PathRequesterSelectionReason.GlobalGroupRequired, assessment.Evidence.Single().Membership!.Limitations);
    }

    [Fact]
    public void NestedUnrelatedCaptureGapDoesNotEraseTheCapturedGrantRoute()
    {
        var assessment = Assess("partial");
        Assert.Equal(ControlEvaluationState.Established, assessment.Authorization);
        var membership = Assert.Single(assessment.Evidence).Membership!;
        Assert.Equal(PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember, membership.Verdict);
        Assert.Contains(PathRequesterSelectionReason.IdentityUnresolved, membership.Limitations);
        Assert.Equal(new[] { EntryDn, TargetDn, CoreDn }, assessment.Steps.Select(step => step.To.DistinguishedName));
    }

    [Theory]
    [InlineData("A", ControlEvaluationState.Established)]
    [InlineData("D", ControlEvaluationState.NotEstablished)]
    public void NestedSelfTrusteeKeepsTargetIdentityAndExactPermissionBinding(string kind, ControlEvaluationState expected)
    {
        var assessment = Assess("self", $"O:SYG:SYD:({kind};;WD;;;S-1-5-10)");
        Assert.Equal(expected, assessment.Authorization);
        var entry = Assert.Single(assessment.Evidence);
        var membership = Assert.IsType<RequesterMembershipEvidence>(entry.Membership);
        Assert.Equal(("S-1-5-10", CoreDn, "S-1-5-21-1-2-3-512"),
            (entry.Entry.Trustee.Sid, membership.Links[^1].Group.DistinguishedName, membership.Links[^1].Group.Sid));
        if (kind == "A")
        {
            Assert.DoesNotContain(RequesterDaclIssue.PermissionReferenceUnavailable, assessment.Issues);
            Assert.Equal(Assert.Single(assessment.Permissions).Id, assessment.Steps[^1].PermissionId);
        }
        else Assert.Empty(assessment.Steps);
    }

    [Fact]
    public void NestedExpectedAdministrationRemainsExpectedRatherThanSec071()
    {
        using var reader = Open(Prepare("administrator"));
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.ExpectedRoute, null, CancellationToken.None).Questions);
        Assert.Equal((ControlEvaluationState.Established, ControlExpectednessReason.ExpectedSameDomainControlPlane),
            (question.Risk.Authorization, question.Risk.ExpectednessReason));
        Assert.DoesNotContain(reader.Read().Findings, value => value.RuleId == "SEC-071");
    }

    [Fact]
    public void NestedPermissionSelectionDoesNotExtendPreChangeMembershipOperationAuthorization()
    {
        using var reader = Open(Prepare("operations"));
        Assert.Equal(new[] { 1, 0, 0 }, reader.ReadPathRequesterCoverage().Families.Select(value => value.StoredAssessments));
    }

    [Fact]
    public void NestedPermissionSelectionDoesNotIncludeComputerActors()
    {
        using var computer = Open(Prepare("computer"));
        Assert.Equal(0, computer.ReadPathRequesterCoverage().Families.Sum(value => value.SelectedQuestions));
        Assert.Contains(computer.ReadPathRequesterCoverage().Limitations,
            value => value.Reason == PathRequesterSelectionReason.RequesterKindUnsupported);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    public void NestedGroupPermissionCountsDoNotGrowWithMembers(int users)
    {
        var directory = Capture("nested", users: users);
        Derive(directory);
        Judge(directory, automatic: false);
        using var before = Open(directory);
        var permissions = before.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Select(edge => (edge.HolderSid, edge.Capability, edge.EvaluationState, edge.IsCounted)).ToArray();
        Judge(directory, automatic: true);
        using var after = Open(directory);
        Assert.Equal(permissions, after.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Select(edge => (edge.HolderSid, edge.Capability, edge.EvaluationState, edge.IsCounted)));
        Assert.Single(permissions.Where(value => value.IsCounted));
        Assert.Equal(users, after.ReadPathRequesterCoverage().Families.Single(value => value.Family == PathRequesterFamily.RequesterDacl).StoredAssessments);
    }

    [Fact]
    public void NestedMembershipWalkAndSourceReadsAreReusedAcrossRequesters()
    {
        var directory = Capture("nested", users: 16);
        Derive(directory);
        Judge(directory, automatic: false);
        using var reader = Open(directory);
        using var connection = Connection(reader);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        var reads = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var memberValues = new Dictionary<string, RequesterReuseTests.CountingList<AttributeValue>>(StringComparer.OrdinalIgnoreCase);
        ObjectAttributes? Read(string dn)
        {
            reads[dn] = reads.GetValueOrDefault(dn) + 1;
            var value = sources.Bundle.ReadObjectAttributes(dn);
            if (value?.Find("member") is not { HasValue: true } members) return value;
            var counted = new RequesterReuseTests.CountingList<AttributeValue>(members.Values);
            memberValues[dn] = counted;
            return value with { Attributes = value.Attributes.Select(attribute => attribute == members
                ? attribute with { Values = counted } : attribute).ToArray() };
        }
        var memberships = new RequesterMembershipContext(sources.OpenDerivation().Value, reader.ReadPathInputs().Input!,
            Read, identities, sources.ReadNamingContexts().Value, CancellationToken.None);
        var first = memberships.Read(UserDn, TargetDn);
        Assert.Equal(2, first.Links.Count);
        for (var index = 1; index < 16; index++)
        {
            var route = memberships.Read(UserName(index), TargetDn);
            Assert.Equal(2, route.Links.Count);
            Assert.Same(first.Links[1], route.Links[1]);
        }
        Assert.Same(first, memberships.Read(UserDn, TargetDn));
        Assert.Equal(18, reads.Count);
        Assert.All(reads.Values, count => Assert.Equal(1, count));
        Assert.Equal(2, memberValues.Count);
        Assert.All(memberValues.Values, values => Assert.Equal(values.Count, values.Visits));
    }

    [Fact]
    public void NestedMembershipTraversalHonorsCancellationBeforeReturningProof()
    {
        using var reader = Open(Prepare("nested", automatic: false));
        using var connection = Connection(reader);
        using var sources = ControlProofVerification.OpenSources(reader);
        using var stopping = new CancellationTokenSource();
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        ObjectAttributes? Read(string dn)
        {
            if (dn == EntryDn) stopping.Cancel();
            return sources.Bundle.ReadObjectAttributes(dn);
        }
        var memberships = new RequesterMembershipContext(sources.OpenDerivation().Value, reader.ReadPathInputs().Input!,
            Read, identities, sources.ReadNamingContexts().Value, stopping.Token);
        Assert.Throws<OperationCanceledException>(() => memberships.Read(UserDn, TargetDn));
    }

    [Theory]
    [InlineData("$.Evidence[0].Membership.Links[0].Witness.Ordinal", "-1")]
    [InlineData("$.Evidence[0].Membership.Links[0].Witness.Value", "'CN=Other,DC=contoso,DC=com'")]
    [InlineData("$.Evidence[0].Membership.Links[1].Member.DistinguishedName", "'CN=Other,DC=contoso,DC=com'")]
    [InlineData("$.Evidence[0].Membership.Links[0].Group.NamingContext", "'DC=child,DC=contoso,DC=com'")]
    [InlineData("$.Evidence[0].Membership.Links[0].GroupType", "2")]
    [InlineData("$.Evidence[0].Membership.Links[0].SourceFingerprint", "'bad'")]
    [InlineData("$.Evidence[0].Membership.SourceFingerprint", "'bad'")]
    [InlineData("$.Evidence[0].Membership.Links[0]", "NULL")]
    [InlineData("$.Steps[0].MembershipWitness.Ordinal", "99")]
    public void NestedSelectedReadRefusesBrokenSavedWitnessesWithoutReplaying(string path, string value)
    {
        var directory = Prepare("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.Requesters[0].Assessment" + path[1..], value);
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() =>
            reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None));
    }

    [Fact]
    public void NestedSelectedReadDoesNotLoadAnotherRequestersProof()
    {
        var directory = Prepare("nested", users: 2);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT source_proof FROM path_requester_risk WHERE requester=$requester";
            command.Parameters.AddWithValue("$requester", UserName(1));
            PathProofVerification.ReplaceJson(connection, Assert.IsType<long>(command.ExecuteScalar()), "unreadable other account proof");
        });
        using var source = new BundleAssetSource();
        var selected = source.ReadSavedTier0Path(directory, UserDn);
        var other = source.ReadSavedTier0Path(directory, UserName(1));
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        Assert.Equal(3, Assert.Single(selected.Value!.Page.Questions).Steps.Count);
        Assert.False(other.IsSuccess);
    }

    [Fact]
    public void NestedPassiveReadKeepsTheSavedMembershipSourceWithoutAnalysisReplay()
    {
        var directory = Prepare("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.Requesters[0].Assessment.Evidence[0].Membership.SourceFingerprint",
            "'" + new string('f', 64) + "'");
        using var reader = Open(directory);
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        Assert.Equal(new string('f', 64), question.Requester!.Evidence.Single().Membership!.SourceFingerprint);
        Assert.Equal(new[] { EntryDn, TargetDn, CoreDn }, question.Steps.Select(step => step.To.DistinguishedName));
    }

    [Fact]
    public void NestedSavedWitnessValidationHonorsCancellation()
    {
        var assessment = Assess("nested");
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.Throws<OperationCanceledException>(() => RequesterDaclProofs.RequireMembershipEvidence(assessment, stopping.Token));
    }

    [Fact]
    public void NestedSavedWitnessValidationRefusesAMissingWitness()
    {
        var assessment = Assess("nested");
        var entry = Assert.Single(assessment.Evidence);
        var membership = entry.Membership!;
        var broken = membership with { Links = [membership.Links[0] with { Witness = null! }, membership.Links[1]] };
        assessment = assessment with { Evidence = [entry with { Membership = broken }] };
        Assert.Throws<InvalidDataException>(() => RequesterDaclProofs.RequireMembershipEvidence(assessment, CancellationToken.None));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("evidence")]
    public void NestedMembershipContextRefusesADifferentSourceBinding(string changed)
    {
        using var reader = Open(Prepare("nested", automatic: false));
        using var connection = Connection(reader);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        var binding = reader.ReadPathInputs().Input!;
        binding = changed == "generation" ? binding with { DerivationGenerationId = Guid.NewGuid() }
            : binding with { EvidenceSeal = new string('f', 64) };
        Assert.Throws<InvalidDataException>(() => new RequesterMembershipContext(sources.OpenDerivation().Value, binding,
            sources.Bundle.ReadObjectAttributes, identities, sources.ReadNamingContexts().Value, CancellationToken.None));
    }

    [Fact]
    public void NestedSelectedPassiveReadbackUsesTheExistingRelationshipsAndGrantWording()
    {
        var directory = Prepare("nested");
        var before = Snapshot(directory);
        using var source = new BundleAssetSource();
        var result = source.ReadSavedTier0Path(directory, UserDn);
        Assert.True(result.IsSuccess, result.Error?.Description);
        var saved = Assert.IsType<SavedTier0Path>(result.Value);
        var question = Assert.Single(saved.Page.Questions);
        var view = new SavedPathQuestionViewModel(question, saved);
        Assert.Equal(3, view.Steps.Count);
        Assert.Equal(new[] { "Alice is a member of Entry (group).", "Entry is a member of Target (group)." },
            view.Steps.Take(2).Select(step => step.Description));
        Assert.Contains(view.PermissionDetails, field => field.Value.Contains("Target (group); Alice's access is through this group", StringComparison.Ordinal));
        Assert.Equal(before, Snapshot(directory));
    }
}
