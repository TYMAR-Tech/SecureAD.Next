using System.Windows.Controls;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    [Fact]
    public void Sec071AdminDirectGuidancePreservesTheOtherRights()
    {
        var saved = PresentationSaved();
        var row = PresentationRow(saved);
        Assert.Equal("Barbara Hernandez can change permissions on the ba.ad.lab domain", row.Heading);
        Assert.Equal("Remove Modify permissions from Barbara Hernandez's explicit permissions on ba.ad.lab (domain). "
            + "Keep the entry's other permissions unchanged unless they are separately reviewed.", row.RecommendedChange);
        Assert.Equal("Active Directory Users and Computers → ba.ad.lab → Properties → Security → Advanced → Barbara Hernandez's entry → Edit → clear Modify permissions.",
            row.WhereToChange);
        Assert.Equal("The captured permissions allow Barbara to change this domain object's permissions, but the captured evidence does not establish "
            + "an expected administrative role for this account on this domain.", row.Explanation);
        Assert.Equal("This addresses the permission shown, not every possible route. A new capture is needed to verify the change.", row.RecommendationBoundary);
        Assert.Equal(new[] { "Barbara Hernandez (bhernandez)", "ba.ad.lab — Domain", "Modify permissions (WRITE_DAC)",
            "Barbara Hernandez directly", "Explicit; not inherited", "This object only", "Allowed" }, row.PermissionDetails.Select(value => value.Value));
        Assert.Contains("Read permissions", Assert.Single(row.Entries).Value);
        Assert.Contains("Write all properties", Assert.Single(row.Entries).Value);
        Assert.Equal(393268, saved.Permissions[0].Evidence[0].AccessMask);
        Assert.Equal(("SEC-071", Severity.High), (saved.Finding!.RuleId, saved.Finding.Severity));
    }

    [Theory]
    [InlineData(PresentationDomain, "domainDNS", "ba.ad.lab — Domain", "ba.ad.lab domain")]
    [InlineData(PresentationComputer, "computer", "DC01 — Computer", "DC01 computer")]
    [InlineData(PresentationComputer, null, "DC01 — Object; kind not recorded in this proof", "DC01 object")]
    public void Sec071AdminLabelsTheObjectKindRatherThanInterpretingDcText(string dn, string? kind, string target, string headline)
    {
        var row = PresentationRow(PresentationSaved(targetDn: dn, targetClass: kind));
        Assert.Equal(target, Detail(row, "Target"));
        Assert.EndsWith(headline, row.Heading);
        Assert.DoesNotContain("domain controller", row.Heading, StringComparison.OrdinalIgnoreCase);
        if (kind is null)
            Assert.Equal("DC01 — Directory object (serviceConnectionPoint)",
                Detail(PresentationRow(PresentationSaved(targetDn: dn, targetClass: "serviceConnectionPoint")), "Target"));
    }

    [Fact]
    public void Sec071AdminUsesCapturedNamesWithoutGuessingAGivenName()
    {
        var saved = PresentationSaved();
        var account = saved.Account! with { Name = "Alex Morgan", AccountName = "amorgan", GivenName = null };
        var row = PresentationRow(saved with { Account = account });
        Assert.StartsWith("Alex Morgan can change permissions", row.Heading);
        Assert.Equal("Alex Morgan (amorgan)", Detail(row, "Account"));
        Assert.StartsWith("The captured permissions allow Alex Morgan to change", row.Explanation);
    }

    [Fact]
    public void Sec071AdminAccountProjectionRetainsCapturedNamingFields()
    {
        var captured = FakeAssetSource.CapturedObject(PresentationUser, "user") with
        {
            Attributes =
            [
                new("displayName", AttributeCardinality.SingleValued, [new(0, "Captured display name", null)]),
                new("sAMAccountName", AttributeCardinality.SingleValued, [new(0, "captured-account", null)]),
                new("givenName", AttributeCardinality.SingleValued, [new(0, "Captured given name", null)]),
            ],
        };
        var account = SavedPathAccount.From(captured);
        Assert.Equal((captured.ObjectGuid, PresentationUser, "Captured display name", "captured-account", "Captured given name"),
            (account.ObjectGuid, account.DistinguishedName, account.Name, account.AccountName, account.GivenName));
    }

    [Fact]
    public void Sec071AdminBlankOptionalNamesDoNotProduceAnEmptyAccountDescription()
    {
        var captured = FakeAssetSource.CapturedObject(PresentationUser, "user") with
        {
            Attributes = new[] { "displayName", "sAMAccountName", "givenName" }.Select(attribute =>
                new ObjectAttribute(attribute, AttributeCardinality.SingleValued, [new(0, " ", null)])).ToArray(),
        };
        var account = SavedPathAccount.From(captured);
        Assert.Equal(("Barbara Hernandez", (string?)null, (string?)null), (account.Name, account.AccountName, account.GivenName));
    }

    [Fact]
    public void Sec071AdminGroupHeldGrantNamesTheActualGroup()
    {
        var row = PresentationRow(PresentationSaved(group: true));
        Assert.StartsWith("Remove Modify permissions from Tier 0 Delegation's explicit permissions on ba.ad.lab (domain).", row.RecommendedChange);
        Assert.Contains("affect other members", row.RecommendedChange);
        Assert.DoesNotContain("Barbara Hernandez's explicit permissions", row.RecommendedChange);
        Assert.Contains("Tier 0 Delegation's entry", row.WhereToChange);
        Assert.Equal("Tier 0 Delegation (group); Barbara Hernandez's access is through this group", Detail(row, "Granted to"));
        Assert.Equal("Barbara Hernandez is a member of Tier 0 Delegation (group).", row.Steps[0].Description);
        Assert.StartsWith("Tier 0 Delegation holds Modify permissions on ba.ad.lab (domain).", row.Steps[1].Description);
    }

    [Theory]
    [InlineData(false, "Barbara Hernandez")]
    [InlineData(true, "Tier 0 Delegation")]
    public void Sec071AdminInheritedGrantDoesNotInventTheOriginalLocation(bool group, string holder)
    {
        var row = PresentationRow(PresentationSaved(group: group, inherited: true, inheritance: 2));
        Assert.StartsWith($"Locate the original inherited grant of Modify permissions to {holder}", row.RecommendedChange);
        Assert.Contains("does not establish the original grant location", row.RecommendedChange);
        Assert.Contains("descendant objects", row.RecommendedChange);
        Assert.DoesNotContain("explicit permissions", row.RecommendedChange);
        Assert.Contains("inspect Inherited from", row.WhereToChange);
        Assert.Equal("Inherited; original grant location is not established by the saved evidence", Detail(row, "Assignment"));
        Assert.Equal("This object and all descendant objects", Detail(row, "Applies to"));
    }

    [Fact]
    public void Sec071AdminExplicitGrantRetainsItsDescendantScope()
    {
        var row = PresentationRow(PresentationSaved(inheritance: 2));
        Assert.Equal("Explicit; not inherited", Detail(row, "Assignment"));
        Assert.Equal("This object and all descendant objects", Detail(row, "Applies to"));
        Assert.Contains("descendant objects", row.RecommendedChange);
        Assert.DoesNotContain("inherited grant of", row.RecommendedChange);
    }

    [Fact]
    public void Sec071AdminUnknownClassRestrictionAndApplicationDataRemainLabelledRecords()
    {
        const string guid = "fedcba98-7654-4321-9876-0123456789ab";
        var saved = PresentationSaved(inheritance: 2);
        var question = saved.Page.Questions[0];
        var original = question.Requester!.Evidence[0];
        var entry = original.Entry with { InheritedObjectTypeGuid = guid, HasInheritedObjectType = true, ApplicationData = [0x12, 0xab] };
        var edge = saved.Permissions[0] with { Evidence = [entry] };
        var row = new SavedPathQuestionViewModel(question with { Requester = question.Requester with
        {
            Evidence = [original with { Entry = entry }],
            Permissions = [new(edge.Id, Tier0PathCalculation.Fingerprint(edge))],
        } }, saved with { Permissions = [edge] });
        Assert.Contains("recorded class", Detail(row, "Applies to"));
        Assert.DoesNotContain(guid, Assert.Single(row.Entries).Value);
        Assert.Contains(row.RecordDetails, value => value.Label.EndsWith("Inherited class identifier", StringComparison.Ordinal) && value.Value == guid);
        Assert.Contains(row.RecordDetails, value => value.Label.EndsWith("Application data (hexadecimal)", StringComparison.Ordinal) && value.Value == "12AB");
    }

    [Fact]
    public void Sec071AdminUnidentifiedGrantDoesNotBecomeADirectUserRemoval()
    {
        var saved = PresentationSaved();
        var original = saved.Page.Questions[0];
        var question = original with { Steps = [], Requester = original.Requester! with { Permissions = [], Steps = [] } };
        var row = new SavedPathQuestionViewModel(question, saved with { Permissions = [] });
        Assert.Equal("No granting entry identified by this saved check", Detail(row, "Granted to"));
        Assert.Contains("does not identify an editable granting entry", row.RecommendedChange);
        Assert.Contains("Do not remove a direct user grant", row.RecommendedChange);
        Assert.DoesNotContain("clear Modify permissions", row.WhereToChange);
    }

    [Theory]
    [InlineData(ControlEvaluationState.NotEstablished, "Not established by this permission check")]
    [InlineData(ControlEvaluationState.Unknown, "Could not be determined")]
    public void Sec071AdminDenyAndUnresolvedChecksAreNotAllowed(ControlEvaluationState state, string expected)
    {
        var saved = PresentationSaved();
        var original = saved.Page.Questions[0];
        var entry = original.Requester!.Evidence[0] with { Entry = original.Requester.Evidence[0].Entry with { AceType = "AccessDenied" },
            Scope = state == ControlEvaluationState.Unknown ? state : ControlEvaluationState.Established };
        var question = original with
        {
            Risk = original.Risk with { Authorization = state, Verdict = state == ControlEvaluationState.Unknown ? PathRiskVerdict.Unknown : PathRiskVerdict.NotEstablished,
                Expectedness = null, ExpectednessReason = null, Issue = state == ControlEvaluationState.Unknown
                    ? PathRiskIssue.AuthorizationUnknown : PathRiskIssue.AuthorizationNotEstablished },
            Requester = original.Requester with { Authorization = state, Evidence = [entry], Permissions = [], Steps = [] }, Steps = [],
        };
        var row = new SavedPathQuestionViewModel(question, saved with { Permissions = [] });
        Assert.StartsWith(expected, Detail(row, "Permission check"));
        Assert.StartsWith("Deny entry 36", Assert.Single(row.Entries).Label);
        Assert.Contains("Account or group named by this entry:", Assert.Single(row.Entries).Value);
        Assert.DoesNotContain("Granted to:", Assert.Single(row.Entries).Value);
        Assert.False(row.HasRecommendation);
        Assert.Empty(row.RecommendedChange);
        Assert.Empty(row.Steps);
    }

    [Fact]
    public void Sec071AdminOnlyTheSupportingAllowDeterminesWhatToRemove()
    {
        var saved = PresentationSaved();
        var original = saved.Page.Questions[0];
        var deny = original.Requester!.Evidence[0] with
        {
            Entry = original.Requester.Evidence[0].Entry with { Ordinal = 10, AceType = "AccessDenied",
                Trustee = original.Requester.Evidence[0].Entry.Trustee with { Name = "Another account", DistinguishedName = "CN=Another account," + PresentationDomain, Sid = "S-1-5-21-10-20-30-1200" } },
            Trustee = original.Requester.Evidence[0].Trustee with { State = RequesterTrusteeState.DoesNotMatch,
                Reason = RequesterTrusteeReason.OtherCurrentUser, HolderDn = "CN=Another account," + PresentationDomain },
        };
        var row = new SavedPathQuestionViewModel(original with { Requester = original.Requester with
        { Evidence = [deny, original.Requester.Evidence[0]] } }, saved);
        Assert.StartsWith("Deny entry 10", row.Entries[0].Label);
        Assert.Contains("does not match this account", row.Entries[0].Value);
        Assert.StartsWith("Allow entry 36", row.Entries[1].Label);
        Assert.StartsWith("Remove Modify permissions from Barbara Hernandez's explicit permissions", row.RecommendedChange);
        Assert.DoesNotContain("Another account", row.RecommendedChange);
    }

    [Fact]
    public void Sec071AdminUnresolvedTrusteeKeepsItsIdentifierWithoutInventingAName()
    {
        var saved = PresentationSaved();
        var question = saved.Page.Questions[0];
        var entry = question.Requester!.Evidence[0];
        entry = entry with { Entry = entry.Entry with { Trustee = entry.Entry.Trustee with { Name = null, DistinguishedName = null } },
            Trustee = entry.Trustee with { State = RequesterTrusteeState.Unknown, Reason = RequesterTrusteeReason.IdentityMissing, HolderDn = null } };
        var row = new SavedPathQuestionViewModel(question with
        {
            Risk = question.Risk with { Verdict = PathRiskVerdict.Unknown, Authorization = ControlEvaluationState.Unknown,
                ExpectednessReason = null, Issue = PathRiskIssue.AuthorizationUnknown },
            Requester = question.Requester with { Authorization = ControlEvaluationState.Unknown, Evidence = [entry], Permissions = [], Steps = [] }, Steps = [],
        }, saved with { Permissions = [] });
        Assert.Contains("Unresolved permission holder", Assert.Single(row.Entries).Value);
        Assert.Contains("could not determine", Assert.Single(row.Entries).Value);
        Assert.Contains(row.RecordDetails, value => value.Label.EndsWith("Security identifier (SID)", StringComparison.Ordinal) && value.Value == entry.Entry.Trustee.Sid);
        Assert.False(row.HasRecommendation);
    }

    [Fact]
    public void Sec071AdminRecordDetailsRetainExactSourceBindingsWithoutJson()
    {
        var saved = PresentationSaved();
        var row = PresentationRow(saved);
        var record = row.RecordDetails;
        Assert.Contains(record, value => value.Label == "Requester distinguished name" && value.Value == PresentationUser);
        Assert.Contains(record, value => value.Label == "Target distinguished name" && value.Value == PresentationDomain);
        Assert.Contains(record, value => value.Label == "Target — Naming context" && value.Value == PresentationDomain);
        Assert.Contains(record, value => value.Label == "Target — Captured domain" && value.Value == "ba.ad.lab");
        Assert.Contains(record, value => value.Label == "Judgement generation" && value.Value == saved.Description.GenerationId.ToString());
        Assert.Contains(record, value => value.Label == "Derivation generation" && value.Value == saved.Description.DerivationGenerationId!.Value.ToString());
        Assert.Contains(record, value => value.Label == "Evidence seal" && value.Value == saved.Description.EvidenceSeal);
        Assert.Contains(record, value => value.Label == "Calculation fingerprint" && value.Value == saved.Page.Coverage.CalculationFingerprint);
        Assert.Contains(record, value => value.Label == "Account — Object identifier (GUID)" && value.Value == saved.Finding!.ObjectGuid.ToString());
        Assert.Contains(record, value => value.Label == "Account — SID resource scope" && value.Value == "not used");
        Assert.Contains(record, value => value.Label == "Source proof fingerprint" && value.Value == saved.Page.Questions[0].Risk.SourceProofFingerprint);
        Assert.Contains(record, value => value.Label == "Source evidence fingerprint" && value.Value == saved.Page.Questions[0].SourceFingerprint);
        Assert.Contains(record, value => value.Label.EndsWith("Full recorded access mask", StringComparison.Ordinal) && value.Value == "393268 (0x00060034)");
        Assert.Contains(record, value => value.Label.Contains("captured ordinal 36", StringComparison.Ordinal)
            && value.Label.EndsWith("Original permission reference", StringComparison.Ordinal) && value.Value == "960");
        Assert.All(record, value => { Assert.DoesNotContain("{", value.Value); Assert.DoesNotContain("\"GenerationId\"", value.Value); });
        Assert.Contains(record, value => value.Value == "No captured authority roots");
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership, "Self-Membership")]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers, "Write members")]
    public void Sec071AdminOwnAccountGuidanceRetainsItsPermissionAndUnknownAdd(OwnAccountMembershipPermissionKind kind, string right)
    {
        var row = PresentationRow(OwnPresentation(PresentationSaved(), kind));
        Assert.Equal("Barbara Hernandez can obtain membership in Tier 0 Delegation (group)", row.Heading);
        Assert.Equal(right, Detail(row, "Relevant permission"));
        Assert.StartsWith($"Remove {right} from Barbara Hernandez's explicit permissions on Tier 0 Delegation (group).", row.RecommendedChange);
        Assert.EndsWith($"clear {right}.", row.WhereToChange);
        Assert.Contains("Captured membership: unresolved", row.Membership);
        Assert.Contains("Prerequisites for adding this account to the group: unresolved", row.Membership);
        Assert.Contains("No group change was performed", row.Membership);
        Assert.Equal("Allowed", Detail(row, "Permission check"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sec071AdminExistingMembershipNamesTheActualAssignment(bool primary)
    {
        var row = PresentationRow(OwnPresentation(PresentationSaved(), OwnAccountMembershipPermissionKind.SelfMembership, existing: true, primary: primary));
        Assert.Equal("Barbara Hernandez is a member of Tier 0 Delegation (group)", row.Heading);
        Assert.Equal("No Add permission is needed for the captured existing membership", Detail(row, "Permission check"));
        Assert.Equal("This addresses the membership shown, not every possible route. A new capture is needed to verify the change.", row.RecommendationBoundary);
        if (primary)
        {
            Assert.Contains("primary-group assignment must not be treated as one", row.RecommendedChange);
            Assert.DoesNotContain("→ Members", row.WhereToChange);
        }
        else
        {
            Assert.StartsWith("Remove Barbara Hernandez's recorded membership from Tier 0 Delegation (group)", row.RecommendedChange);
            Assert.EndsWith("→ Members → Barbara Hernandez → Remove.", row.WhereToChange);
        }
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership, "Self-Membership")]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers, "Write members")]
    public void Sec071AdminCombinedRouteKeepsBothPermissionsAndTheMembershipAssumption(OwnAccountMembershipPermissionKind kind, string membershipRight)
    {
        var row = PresentationRow(CombinedPresentation(kind));
        Assert.Equal("With membership in Tier 0 Delegation (group), Barbara Hernandez would have permission to change permissions on the ba.ad.lab domain", row.Heading);
        Assert.StartsWith("Remove Modify permissions from Tier 0 Delegation's explicit permissions on ba.ad.lab (domain).", row.RecommendedChange);
        Assert.Equal("Allowed under the saved membership assumption; not proof of current access or a completed Add", Detail(row, "Permission check"));
        Assert.Equal(2, row.Entries.Count);
        Assert.Contains(row.Entries, value => value.Value.Contains("Relevant permission: " + membershipRight, StringComparison.Ordinal));
        Assert.Contains(row.Entries, value => value.Value.Contains("Relevant permission: Modify permissions", StringComparison.Ordinal));
        Assert.Contains("Captured membership: unresolved", row.Membership);
        Assert.Contains("Prerequisites for adding this account to the group: unresolved", row.Membership);
        Assert.Contains(row.RecordDetails, value => value.Value == MembershipDaclAssessment.Context);
        Assert.Contains(row.RecordDetails, value => value.Label.EndsWith("Original permission reference", StringComparison.Ordinal) && value.Value == "961");
        Assert.Contains(row.RecordDetails, value => value.Label.EndsWith("Original permission reference", StringComparison.Ordinal) && value.Value == "960");
        if (kind == OwnAccountMembershipPermissionKind.WriteMembers)
            Assert.Contains(row.RecordDetails, value => value.Label == "Write members scope evidence on " + PresentationGroup + ", captured ordinal 36"
                && value.Value == "member");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sec071AdminCapturedNameMustMatchTheSavedAccount(bool changeName)
    {
        var saved = PresentationSaved();
        var account = changeName ? saved.Account! with { DistinguishedName = "CN=Another," + PresentationDomain }
            : saved.Account! with { ObjectGuid = Guid.NewGuid() };
        var section = ReadPresentation(saved with { Account = account });
        Assert.Equal("Saved result unavailable", section.Result);
        Assert.Empty(section.Groups);
        Assert.False(section.HasRecordDetails);
    }

    [Fact]
    public async Task Sec071AdminCancellationClearsAdviceAndRejectsLateNames()
    {
        var saved = PresentationSaved();
        var section = ReadPresentation(saved);
        Assert.NotEmpty(Assert.Single(Questions(section)).RecommendedChange);
        var pending = PendingPath();
        section.ConfigureAsync(PresentationUser, (_, _, _) => pending.Task);
        section.Read();
        var completed = section.ReadCompletion;
        section.CancelRead();
        pending.SetResult(Result<SavedTier0Path?>.Success(saved));
        await completed;
        Assert.Empty(section.Groups);
        Assert.False(section.HasRecordDetails);
        Assert.Equal("Saved results have not been read.", section.Result);
    }

    [Fact]
    public void Sec071AdminPagingReplacesAdviceAndRecordDetailsFromOnlyTheSelectedPage()
    {
        var first = PresentationSaved();
        var evidence = (Tier0RouteFindingEvidence)first.Finding!.Evidence;
        first = first with { Finding = first.Finding with { Evidence = evidence with { UnexpectedChecks = 2 } },
            Page = first.Page with { Counts = new(2, 0, 0, 0),
                Next = new(first.Description.GenerationId, PresentationUser, PathRiskVerdict.UnexpectedRoute, 1) } };
        var question = first.Page.Questions[0];
        var target = question.Requester!.Target! with { ObjectGuid = Guid.NewGuid(), DistinguishedName = PresentationComputer };
        var edge = first.Permissions[0] with { Id = 962, Target = PresentationComputer, TargetClass = "computer", TargetGuid = target.ObjectGuid };
        var steps = question.Steps.Select(value => value with { To = target, PermissionId = edge.Id }).ToArray();
        var proof = question.Requester with { Request = new(PresentationUser, PresentationComputer), Target = target, Steps = steps,
            Permissions = [new(edge.Id, Tier0PathCalculation.Fingerprint(edge))] };
        var second = first with { Permissions = [edge], Page = first.Page with { Next = null,
            Questions = [question with { Id = 2, Steps = steps, Requester = proof,
                Risk = question.Risk with { TargetDn = PresentationComputer, ReachedTarget = target,
                    SourceProofFingerprint = Tier0PathCalculation.Fingerprint(new SavedRequesterDaclProof(proof, question.SourceFingerprint)) } }] } };
        var requests = new List<PathRiskPageMark?>();
        var section = Section();
        section.ConfigureAsync(PresentationUser, (_, after, _) =>
        {
            requests.Add(after);
            return Task.FromResult(Result<SavedTier0Path?>.Success(after is null ? first : second));
        });
        section.Read();
        var group = Assert.Single(section.Groups);
        Assert.Single(requests);
        Assert.EndsWith("ba.ad.lab domain", Assert.Single(group.Questions).Heading);
        group.NextCommand.Execute(null);
        Assert.Equal(2, requests.Count);
        Assert.Equal(first.Page.Next, requests[1]);
        var displayed = Assert.Single(group.Questions);
        Assert.EndsWith("DC01 computer", displayed.Heading);
        Assert.Contains("on DC01 (computer)", displayed.RecommendedChange);
        Assert.Contains(displayed.RecordDetails, value => value.Label == "Target distinguished name" && value.Value == PresentationComputer);
        Assert.DoesNotContain(displayed.RecordDetails, value => value.Label == "Target distinguished name" && value.Value == PresentationDomain);
        Assert.Equal((2, false, true), (group.PageNumber, group.HasNext, group.HasPrevious));
    }

    [Fact]
    public void Sec071AdminFindingGuidanceDoesNotRecommendDeletingTheWholeEntry()
    {
        var row = new FindingRowViewModel(PresentationSaved().Finding!);
        Assert.Contains("Remove only the permission identified there", row.WhatToDo);
        Assert.Contains("other permissions unchanged", row.WhatToDo);
        Assert.Contains("Group-held and inherited grants", row.WhatToDo);
        Assert.Contains("new capture", row.WhatToDo);
    }

    [Theory]
    [InlineData(600, 430)]
    [InlineData(1200, 650)]
    public void Sec071AdminCompiledLayoutSeparatesReadableEvidenceFromCollapsedRecords(int width, int height) => OnPathSta(() =>
    {
        var saved = PresentationSaved();
        var section = ReadPresentation(saved);
        var (template, pane, presenter) = PathPane(section);
        LayoutPath(pane, width, height);
        var record = Assert.IsType<Expander>(template.FindName("SavedPathRecordDetails", presenter));
        Assert.False(record.IsExpanded);
        var headline = Assert.Single(PathDescendants<TextBlock>(pane), value => value.Name == "SavedPermissionHeadline");
        var change = Assert.Single(PathDescendants<TextBlock>(pane), value => value.Name == "SavedPermissionChange");
        Assert.Equal("Barbara Hernandez can change permissions on the ba.ad.lab domain", headline.Text);
        Assert.Equal(PresentationRow(saved).RecommendedChange, change.Text);
        Assert.True(change.TransformToAncestor(pane).Transform(new System.Windows.Point(0, change.ActualHeight)).Y <= height,
            "The headline and recommended change must remain visible together on the first screen.");
        var visibleText = string.Join("\n", PathDescendants<TextBlock>(pane).Select(value => value.Text));
        Assert.DoesNotContain(PresentationUser, visibleText);
        Assert.DoesNotContain(saved.Description.GenerationId.ToString(), visibleText);
        Assert.Equal(1, PathDescendants<TextBlock>(pane).Count(value => value.Text == "Permission details"));
        Assert.NotEmpty(Assert.Single(PathDescendants<ItemsControl>(pane), value => value.Name == "SavedPermissionEntries").Items);
        record.IsExpanded = true;
        LayoutPath(pane, width, height);
        var expandedText = string.Join("\n", PathDescendants<TextBlock>(pane).Select(value => value.Text));
        Assert.Contains(PresentationUser, expandedText);
        Assert.Contains(saved.Description.GenerationId.ToString(), expandedText);
        Assert.DoesNotContain("{", expandedText);
        Assert.DoesNotContain("}", expandedText);
        Assert.DoesNotContain("\"GenerationId\"", expandedText);
        Assert.DoesNotContain("From:", expandedText);
        Assert.DoesNotContain("To:", expandedText);
        Assert.DoesNotContain("Supporting evidence", expandedText);
        var scroll = AncestorScroll(headline)!;
        scroll.ScrollToEnd();
        LayoutPath(pane, width, height);
        Assert.True(scroll.VerticalOffset > 0);
        Assert.Equal(ScrollBarVisibility.Disabled, scroll.HorizontalScrollBarVisibility);
        Assert.All(PathDescendants<TextBlock>(pane), value =>
        {
            Assert.Equal(System.Windows.TextWrapping.Wrap, value.TextWrapping);
            Assert.True(value.ActualWidth <= width);
        });
    });
}
