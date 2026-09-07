using System.Xml.Linq;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ControlEdgePresentationTests
{
    [Fact]
    public void EstablishedRequesterPermissionUsesPlainLanguage()
    {
        var value = new SelfMembershipAssessment(new("CN=Alice", "CN=Target", SelfMembershipOperation.Remove, null),
            Guid.Empty, null, new('a', 64), Guid.NewGuid(), "S-1-5-21-1-2-3-1", Guid.NewGuid(),
            "S-1-5-21-1-2-3-2", Guid.NewGuid(), "S-1-5-21-1-2-3-1", ControlEvaluationState.Established,
            ControlEvaluationState.Established, ControlEvaluationState.Unknown, "Computed", DateTimeOffset.UnixEpoch,
            512, true, [SelfMembershipIssue.LiveOperationNotEvaluated], [], [9]);

        var row = new SelfMembershipAssessmentRowViewModel(value);

        Assert.Equal("Authorized", row.Authorization);
    }

    [Fact]
    public void BothViewsKeepGeneralAndSelfMembershipSeparateAndShowTheirLimits()
    {
        var evaluation = Judgement.GroupMembershipControlTests.Membership(Judgement.ControlEdgeDeriverTests.Permissions(
            Judgement.GroupMembershipControlTests.Scoped(0, 0x28)));
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(new(evaluation.Edges, 0, 2, 0, 1, true, true, false, 2) { GenerationId = Guid.Empty }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, Guid.Empty)));
        foreach (var byHolder in new[] { false, true })
        {
            vm.ByHolder = byHolder;
            Assert.Equal(2, vm.Rows.Count);
            Assert.Contains(vm.Rows, row => row.Capability.Contains("no own-account restriction") && row.Evaluation == "Established");
            var self = Assert.Single(vm.Rows.Where(row => row.Capability.Contains("Self-Membership")));
            Assert.Contains("own account only", self.Capability);
            Assert.Equal("Unknown", self.Evaluation);
            Assert.Contains("MembershipEscalation", self.Evidence);
            Assert.Contains("AddedMemberSid == RequesterSid: Unknown", self.Evidence);
            Assert.Contains("named-holder requester operations remain unknown", vm.SupportedScope);
            Assert.Contains("Counts include unknown candidates", vm.Coverage);
        }
    }

    [Fact]
    public void RequesterRowsUseOneStoredAnswerInBothDirections()
    {
        var value = new SelfMembershipAssessment(new("CN=Alice", "CN=Target", SelfMembershipOperation.Remove, null),
            Guid.Empty, null, new('a', 64), Guid.NewGuid(), "S-1-5-21-1-2-3-1", Guid.NewGuid(),
            "S-1-5-21-1-2-3-2", Guid.NewGuid(), "S-1-5-21-1-2-3-1", ControlEvaluationState.Established,
            ControlEvaluationState.Established, ControlEvaluationState.Established, "Computed", DateTimeOffset.UnixEpoch,
            512, true, [SelfMembershipIssue.LiveOperationNotEvaluated], [], [9]);
        foreach (var selectedIsUser in new[] { false, true })
        {
            var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
            vm.Configure(true, selectedIsUser,
                (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, true, true, false, 0) { GenerationId = Guid.Empty }),
                _ => Result<SelfMembershipAssessmentSet>.Success(new([value], true, Guid.Empty)));
            var row = Assert.Single(vm.RequesterAssessments);
            Assert.Equal("Authorized", row.Authorization);
            Assert.Same(row, vm.SelectedRequesterAssessment);
            Assert.Contains("do not add to holder-edge counts", vm.RequesterCoverage);
        }
    }

    [Theory]
    [InlineData("Counts")]
    [InlineData("Coverage")]
    [InlineData("Rows")]
    [InlineData("SelectedEdge.Evidence, Mode=OneWay")]
    [InlineData("SelectedRequesterAssessment, Mode=TwoWay")]
    [InlineData("SelectedRequesterAssessment.Evidence, Mode=OneWay")]
    public void RealControlTemplateKeepsTheAnswerAndItsEvidence(string binding)
    {
        var path = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Views", "Sections", "ObjectSectionTemplates.xaml");
        var document = System.Xml.Linq.XDocument.Load(path);
        var template = document.Descendants().Single(element => element.Name.LocalName == "DataTemplate"
            && element.Attributes().Any(attribute => attribute.Name.LocalName == "DataType" && attribute.Value == "{x:Type vm:ControlEdgesSectionViewModel}"));
        Assert.Contains(template.Descendants().Attributes(), attribute => attribute.Value == "{Binding " + binding + "}");
    }

    [Fact]
    public void BothDirectionsResetPagingAndAlwaysStateTheExpectedHiddenCount()
    {
        var queries = new List<(bool Holder, bool Expected, long After)>();
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        var generation = Guid.NewGuid();
        vm.Configure(true, false, (holder, expected, after) =>
        {
            queries.Add((holder, expected, after));
            return Result<ControlEdgePage>.Success(new([], 2, 3, 7, 1, true, false, true, 100) { GenerationId = generation });
        }, _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, generation)));
        Assert.Contains("7 expected (hidden)", vm.Counts);
        Assert.Contains("incomplete", vm.Coverage);
        vm.NextPageCommand.Execute(null);
        Assert.Equal(100, queries[^1].After);
        vm.ByHolder = true;
        Assert.Equal((true, false, 0L), queries[^1]);
        Assert.Contains("whole capture", vm.Coverage);
        vm.IncludeExpected = true;
        Assert.Equal((true, true, 0L), queries[^1]);
        Assert.Contains("7 expected (shown)", vm.Counts);
    }

    [Fact]
    public void UnrunAndChangedGenerationAreNotEmptyCompleteAnswers()
    {
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        vm.Configure(false, false, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, false, false, false, 0)),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], false, null)));
        Assert.Contains("not derived", vm.Coverage);
        Assert.Contains("unknown", vm.Counts);
        var generation = Guid.NewGuid();
        vm.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(new([], 0, 0, 0, 0, true, true, true, 100) { GenerationId = generation }),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, generation)));
        Assert.True(vm.HasMore);
        generation = Guid.NewGuid();
        vm.NextPageCommand.Execute(null);
        Assert.Contains("changed", vm.Coverage);
        Assert.False(vm.HasMore);
    }

    [Fact]
    public void EveryObjectHasAReachableControlSection()
    {
        Assert.Contains(ObjectSectionCatalog.For("user"), section => section.Key == ObjectSectionCatalog.ControlEdges);
        Assert.Contains(ObjectSectionCatalog.For(null), section => section.Key == ObjectSectionCatalog.ControlEdges);
    }

    [Theory]
    [InlineData(ControlEvaluationState.Established, "Authorized")]
    [InlineData(ControlEvaluationState.NotEstablished, "Not authorized")]
    [InlineData(ControlEvaluationState.Unknown, "Unknown")]
    public void AuthorizationDoesNotBorrowTheReadinessAnswer(ControlEvaluationState state, string expected)
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment() with { Authorization = state });
        Assert.Equal(expected, row.Authorization);
    }

    [Theory]
    [InlineData(ControlEvaluationState.Established, "Own account only")]
    [InlineData(ControlEvaluationState.NotEstablished, "Different account")]
    [InlineData(ControlEvaluationState.Unknown, "Not confirmed")]
    public void OwnAccountDoesNotBorrowThePermissionAnswer(ControlEvaluationState state, string expected)
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment() with { OwnAccount = state });
        Assert.Equal(expected, row.OwnAccount);
    }

    [Theory]
    [InlineData(ControlEvaluationState.Established, "Ready from capture")]
    [InlineData(ControlEvaluationState.NotEstablished, "Not ready")]
    [InlineData(ControlEvaluationState.Unknown, "Unknown")]
    public void ReadinessDoesNotPromiseLiveSuccess(ControlEvaluationState state, string expected)
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment() with { Readiness = state });
        Assert.Equal(expected, row.Readiness);
    }

    [Theory]
    [InlineData(SelfMembershipOperation.Add, "Add to group")]
    [InlineData(SelfMembershipOperation.Remove, "Remove from group")]
    public void OperationNamesTheStoredMembershipChange(SelfMembershipOperation operation, string expected)
    {
        var value = Assessment();
        var row = new SelfMembershipAssessmentRowViewModel(value with { Request = value.Request with { Operation = operation } });
        Assert.Equal(expected, row.Operation);
    }

    [Theory]
    [InlineData(SelfMembershipIssue.RequesterMissing, "Missing captured evidence: requester account was not found.")]
    [InlineData(SelfMembershipIssue.RequesterNotUser, "Unsupported analysis: requester is not a user account.")]
    [InlineData(SelfMembershipIssue.TargetMissing, "Missing captured evidence: target was not found.")]
    [InlineData(SelfMembershipIssue.TargetNotGroup, "Unsupported analysis: target is not a group.")]
    [InlineData(SelfMembershipIssue.MemberMissing, "Missing captured evidence: the account to add or remove was not found.")]
    [InlineData(SelfMembershipIssue.DescriptorUnreadable, "Missing captured evidence: the target's permissions could not be read.")]
    [InlineData(SelfMembershipIssue.DescriptorIncomplete, "Incomplete captured evidence: some permission entries are missing.")]
    [InlineData(SelfMembershipIssue.PermissionBudgetExceeded, "Processing stopped: this answer's permission-entry allowance was exceeded.")]
    [InlineData(SelfMembershipIssue.ScopeUnknown, "Unresolved permission scope: whether an entry applies to this right is unknown.")]
    [InlineData(SelfMembershipIssue.TrusteeUnknown, "Unresolved permission holder: whether an entry applies to this requester is unknown.")]
    [InlineData(SelfMembershipIssue.UnsupportedAce, "Unsupported analysis: a relevant permission-entry type cannot be fully evaluated.")]
    [InlineData(SelfMembershipIssue.AccountStatusMissing, "Missing captured evidence: account enabled/disabled status is unknown.")]
    [InlineData(SelfMembershipIssue.AccountDisabled, "Not ready: the requester account was disabled when captured.")]
    [InlineData(SelfMembershipIssue.AlreadyMember, "Not ready to add: the account is already a captured member.")]
    [InlineData(SelfMembershipIssue.MembershipStateUnknown, "Missing captured evidence: current membership is not established; absence is not proof of non-membership.")]
    [InlineData(SelfMembershipIssue.LiveOperationNotEvaluated, "Live operation not checked.")]
    public void IndividualLimitationsKeepTheirSpecificMeaning(SelfMembershipIssue issue, string expected)
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment() with { Issues = [issue] });
        Assert.Equal(expected, row.Limits);
    }

    [Theory]
    [InlineData("Requester: CN=Alice,DC=example,DC=invalid")]
    [InlineData("Requester object identifier (GUID): 11111111-1111-1111-1111-111111111111; security identifier (SID): S-1-5-21-1-2-3-101")]
    [InlineData("Target GUID: 22222222-2222-2222-2222-222222222222; SID: S-1-5-21-1-2-3-202")]
    [InlineData("Member GUID: 11111111-1111-1111-1111-111111111111; SID: S-1-5-21-1-2-3-101")]
    [InlineData("Judgement generation: 33333333-3333-3333-3333-333333333333")]
    [InlineData("Derivation generation (if recorded): 44444444-4444-4444-4444-444444444444")]
    [InlineData("Evidence fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("Requester captured at: 1970-01-01T00:00:00.0000000+00:00")]
    [InlineData("Stored account flags (userAccountControl): 512")]
    [InlineData("Stored membership state: Member present")]
    [InlineData("Supporting holder-edge identifiers: 9, 12")]
    [InlineData("Permission entry (ACE) 7: AccessDeniedObject")]
    [InlineData("Original trustee SID: S-1-5-10; access mask: 0x00000008")]
    [InlineData("Inherited: Yes; inheritance flags: 0x02; propagation flags: 0x01")]
    [InlineData("Object-type field present: Yes; GUID: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    [InlineData("Inherited-object-type field present: Yes; GUID: cccccccc-cccc-cccc-cccc-cccccccccccc")]
    [InlineData("Application data (hex): 012AFF")]
    [InlineData("Permission scope: Applicability is unknown")]
    [InlineData("Requester applicability: Applies to this requester")]
    [InlineData("same-domain global security group with the requester explicitly listed as a member")]
    [InlineData("Resolved holder: CN=Target,DC=example,DC=invalid; GUID: 22222222-2222-2222-2222-222222222222; domain: example.invalid")]
    [InlineData("Stored group type: -2147483646; holder captured at: 1970-01-01T00:00:00.0000000+00:00")]
    [InlineData("Explicit member in this route: CN=Alice,DC=example,DC=invalid")]
    [InlineData("Capture-wide discovery coverage is reported separately.")]
    [InlineData("This requester answer does not add to holder-edge counts.")]
    [InlineData("No chain to Tier 0 is established by this assessment.")]
    public void EvidenceShowsStoredIdentityPermissionRouteAndLimits(string expected)
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment());
        Assert.Contains(expected, row.Evidence);
    }

    [Theory]
    [InlineData(RequesterTrusteeReason.DirectIdentity, "The permission names the requester's current identity directly.")]
    [InlineData(RequesterTrusteeReason.AuthenticatedIdentity, "The permission covers this assumed authenticated user through a broad identity.")]
    [InlineData(RequesterTrusteeReason.DirectGlobalMembership, "The permission is held by a same-domain global security group with the requester explicitly listed as a member.")]
    [InlineData(RequesterTrusteeReason.DistributionGroup, "A distribution group does not supply this authorization route.")]
    [InlineData(RequesterTrusteeReason.OtherCurrentUser, "The permission names a different user's current identity.")]
    [InlineData(RequesterTrusteeReason.NonUserIdentity, "The permission names an identity that does not match this ordinary authenticated user.")]
    [InlineData(RequesterTrusteeReason.IdentityMissing, "Captured identity evidence is missing or cannot be matched.")]
    [InlineData(RequesterTrusteeReason.UnsupportedIdentity, "This identity route is outside the supported analysis.")]
    [InlineData(RequesterTrusteeReason.ResourceContextUnknown, "The required same-domain context could not be verified.")]
    [InlineData(RequesterTrusteeReason.GroupTypeMissing, "The captured group type is missing.")]
    [InlineData(RequesterTrusteeReason.UnsupportedGroupScope, "The group's scope is outside the supported analysis.")]
    [InlineData(RequesterTrusteeReason.MembershipNotEstablished, "Direct membership was not established; nested and other membership routes are not expanded.")]
    public void RouteReasonsExplainTheStoredAnswer(RequesterTrusteeReason reason, string expected)
    {
        var value = Assessment();
        var evidence = Assert.Single(value.Evidence);
        var row = new SelfMembershipAssessmentRowViewModel(value with
        {
            Evidence = [evidence with { Trustee = evidence.Trustee with { Reason = reason } }],
        });
        Assert.Contains(expected, row.Evidence);
    }

    [Fact]
    public void MissingMembershipIsNotPresentedAsNonMembership()
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment() with { MemberPresent = null });
        Assert.Contains("Stored membership state: Unknown; not proof of non-membership", row.Evidence);
    }

    [Fact]
    public void NoStoredEntriesAreNotPresentedAsARefusal()
    {
        var row = new SelfMembershipAssessmentRowViewModel(Assessment() with { Evidence = [] });
        Assert.Contains("No supporting permission entries were stored for this answer. This alone is not an authorization result.", row.Evidence);
    }

    [Fact]
    public void ExplicitDifferentMemberIsNotReplacedByTheRequester()
    {
        var value = Assessment();
        var row = new SelfMembershipAssessmentRowViewModel(value with
        {
            Request = value.Request with { MemberDn = "CN=Bob" },
            OwnAccount = ControlEvaluationState.NotEstablished,
        });
        Assert.Contains("Account to add or remove: CN=Bob", row.Evidence);
    }

    private static SelfMembershipAssessment Assessment()
    {
        var requester = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var target = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var entry = Judgement.GroupMembershipControlTests.Scoped(7, 8, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "AccessDeniedObject") with
        {
            Trustee = new("S-1-5-10", null, null, null, null, null, null), IsInherited = true, InheritanceFlags = 2, PropagationFlags = 1,
            HasInheritedObjectType = true, InheritedObjectTypeGuid = "cccccccc-cccc-cccc-cccc-cccccccccccc", ApplicationData = [1, 42, 255],
        };
        var route = new RequesterTrusteeEvidence("S-1-5-10", RequesterTrusteeState.Matches,
            RequesterTrusteeReason.DirectGlobalMembership, target, "CN=Target,DC=example,DC=invalid", "example.invalid",
            -2147483646, DateTimeOffset.UnixEpoch, "CN=Alice,DC=example,DC=invalid");
        return new(new("CN=Alice,DC=example,DC=invalid", "CN=Target,DC=example,DC=invalid", SelfMembershipOperation.Remove, null),
            Guid.Parse("33333333-3333-3333-3333-333333333333"), Guid.Parse("44444444-4444-4444-4444-444444444444"), new('a', 64),
            requester, "S-1-5-21-1-2-3-101", target, "S-1-5-21-1-2-3-202", requester, "S-1-5-21-1-2-3-101",
            ControlEvaluationState.Established, ControlEvaluationState.NotEstablished, ControlEvaluationState.Unknown,
            "Computed", DateTimeOffset.UnixEpoch, 512, true, [SelfMembershipIssue.LiveOperationNotEvaluated],
            [new(entry, ControlEvaluationState.Unknown, route)], [9, 12]);
    }
}
