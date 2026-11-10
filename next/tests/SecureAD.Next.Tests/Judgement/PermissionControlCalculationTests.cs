using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PermissionControlCalculationTests
{
    private const string Everyone = "S-1-1-0";
    private const string Authenticated = "S-1-5-11";
    private const string Holder = "S-1-5-21-1-2-3-1200";
    private const int Modify = 0x40000;
    private const int ChangeOwner = 0x80000;
    private const string Target = SelfMembershipDiscoveryTests.TargetDn;

    [Theory]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    public void EveryoneDenialAndAuthenticatedGrantRespectOriginalOrderThroughSavedOutput(bool denyFirst, int count)
    {
        var deny = "(D;;WD;;;WD)";
        var allow = "(A;;WD;;;AU)";
        var directory = Saved(denyFirst ? deny + allow : allow + deny);
        using var reader = Open(directory);
        var page = reader.ReadPage(FindingsQuery.About(Target));
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(1, page.Value.RulesRan);
        Assert.Equal(count, page.Value.Findings.Count);
        if (count == 0) return;
        var evidence = Assert.IsType<ObjectTakeoverEvidence>(Assert.Single(page.Value.Findings).Evidence);
        Assert.Equal(PermissionControlState.Established, evidence.Calculation!.ModifyPermissions.State);
        Assert.Equal(new[] { 0 }, evidence.Calculation.ModifyPermissions.GrantOrdinals);
    }

    [Theory]
    [InlineData("AccessAllowedCallback", false, false)]
    [InlineData("AccessDeniedCallback", false, false)]
    [InlineData("AccessDeniedCallback", true, true)]
    public void ConditionalEntriesDoNotBecomeUnconditionalRights(string type, bool ordinaryFirst, bool established)
    {
        var conditional = Ace(ordinaryFirst ? 1 : 0, Everyone, Modify, type);
        var entries = ordinaryFirst ? new[] { Ace(0, Everyone, Modify), conditional }
            : type == "AccessAllowedCallback" ? [conditional] : new[] { conditional, Ace(1, Everyone, Modify) };
        var verdict = Judge(entries);
        Assert.Equal(established ? 1 : 0, verdict.Findings.Count);
        if (established)
            Assert.Equal(PermissionControlState.Established, Calculation(verdict).ModifyPermissions.State);
        else Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.PermissionControlNotEvaluated);
    }

    [Fact]
    public void ConditionalEntriesAfterATerminalDenialCannotCreateUncertaintyOrAccess()
    {
        var verdict = Judge([Ace(0, Everyone, Modify, "AccessDenied"), Ace(1, Everyone, Modify, "AccessAllowedCallback")]);
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnUncertainEarlierAllowCannotWeakenALaterIndependentGrant(bool scoped)
    {
        var uncertain = Ace(0, Everyone, Modify, scoped ? "AccessAllowedObject" : "AccessAllowedCallback") with
        {
            HasObjectType = scoped, ObjectTypeGuid = scoped ? "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" : null,
        };
        var value = Calculation(Judge([uncertain, Ace(1, Everyone, Modify)]));
        Assert.Equal(PermissionControlState.Established, value.ModifyPermissions.State);
        Assert.Equal(new[] { 1 }, value.ModifyPermissions.GrantOrdinals);
    }

    [Fact]
    public void AnUnmatchedDenyRemainsUnknownWithoutInventingARequesterToken()
    {
        var verdict = Judge([Ace(0, Holder, Modify, "AccessDenied"), Ace(1, Authenticated, Modify)]);
        Assert.Empty(verdict.Findings);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.PermissionControlNotEvaluated);
    }

    [Fact]
    public void AScopedPropertyDenialBreaksFullControlWithoutErasingModifyPermissions()
    {
        var deny = Ace(0, Everyone, 0x20, "AccessDeniedObject") with
        {
            HasObjectType = true, ObjectTypeGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2",
        };
        var verdict = Judge([deny, Ace(1, Everyone, FullControlEvaluator.RequiredMask)]);
        var evidence = Assert.IsType<ObjectTakeoverEvidence>(Assert.Single(verdict.Findings).Evidence);
        Assert.Equal(ObjectTakeoverRight.WriteDacl, evidence.Right);
        Assert.Equal(PermissionControlState.NotEstablished, evidence.Calculation!.FullControl.State);
        Assert.Equal(PermissionControlState.Established, evidence.Calculation.ModifyPermissions.State);
    }

    [Fact]
    public void UnsupportedStandardRightScopeIsUnresolvedRatherThanAWholeObjectGrant()
    {
        var verdict = Judge([Ace(0, Everyone, Modify, "AccessAllowedObject") with
        {
            HasObjectType = true, ObjectTypeGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        }]);
        Assert.Empty(verdict.Findings);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.PermissionControlNotEvaluated);
    }

    [Fact]
    public void InheritOnlyGrantsNothingHereAndAnInheritedGrantDoesNotInventItsContainer()
    {
        var entry = Ace(7, Everyone, Modify) with { IsInherited = true, HasInheritedObjectType = true,
            InheritedObjectTypeGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" };
        Assert.Empty(Judge([entry with { PropagationFlags = 0x08 }]).Findings);
        var evidence = Assert.IsType<ObjectTakeoverEvidence>(Assert.Single(Judge([entry]).Findings).Evidence);
        Assert.Null(evidence.InheritedFrom);
        Assert.True(evidence.Calculation!.SupportingEntryIsInherited);
        Assert.Equal(new[] { 7 }, evidence.Calculation.ModifyPermissions.GrantOrdinals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ChangeOwnerAndItsUnverifiedTransitionDoNotWeakenIndependentModifyPermissions(bool computer)
    {
        var verdict = Judge([Ace(0, Everyone, ChangeOwner), Ace(1, "S-1-3-4", 0x10),
            Ace(2, Everyone, Modify)], computer ? "computer" : "group");
        var calculation = Calculation(verdict);
        Assert.Equal(PermissionControlState.Established, calculation.ModifyPermissions.State);
        Assert.Equal(PermissionControlState.Established, calculation.ChangeOwner.State);
        Assert.Equal(PermissionControlState.Unknown, calculation.OwnerTransition);
        Assert.Equal(ObjectTakeoverRight.WriteDacl, Assert.IsType<ObjectTakeoverEvidence>(Assert.Single(verdict.Findings).Evidence).Right);
        Assert.Contains(calculation.OwnerConditions, condition => condition.Name == "ControlledOwnerSidTransition"
            && condition.State == PermissionControlState.Unknown);
    }

    [Fact]
    public void AComputerHeuristicDoesNotInventRecordedDirectoryServerBehavior()
    {
        var calculation = Calculation(Judge([Ace(0, Everyone, ChangeOwner)], "computer"));
        Assert.Equal(PermissionControlState.Established, calculation.ChangeOwner.State);
        Assert.Equal(PermissionControlState.Unknown, calculation.OwnerRightsCondition);
        Assert.Contains(calculation.OwnerConditions, check => check.Name == "ServerBehaviourBaseline"
            && check.State == PermissionControlState.Unknown);
    }

    [Fact]
    public void MembershipCompletenessIsNotUsedAsPermissionCalculationCompleteness()
    {
        var verdict = Judge([Ace(0, Holder, Modify, "AccessDeniedCallback"), Ace(1, Everyone, Modify),
            Ace(2, Everyone, ChangeOwner)]);
        var evidence = Assert.IsType<ObjectTakeoverEvidence>(Assert.Single(verdict.Findings).Evidence);
        Assert.True(evidence.ExpansionWasComplete);
        Assert.False(evidence.Calculation!.IsComplete);
        Assert.Equal(PermissionControlState.Unknown, evidence.Calculation.ModifyPermissions.State);
        Assert.Equal(PermissionControlState.Established, evidence.Calculation.ChangeOwner.State);
    }

    [Fact]
    public void AllObjectScopeDoesNotRequireTierZeroAdmissionOrExpandReadOnlyHolders()
    {
        var expansions = 0;
        var entries = Enumerable.Range(0, 40).Select(index => Ace(index, Holder, 0x10)).Append(Ace(40, Everyone, Modify)).ToArray();
        var verdict = Judge(entries, "organizationalUnit", expand: (sid, _) =>
        {
            expansions++;
            Assert.Equal(Everyone, sid);
            return new(sid, PrincipalExpansionOutcome.Expanded, []);
        });
        Assert.Single(verdict.Findings);
        Assert.Equal(1, expansions);
        Assert.Empty(new BroadPrincipalCanTakeOverObject().Definition.SubjectClasses);
    }

    [Fact]
    public void FullControlPreparationIsSharedWithoutReadingUndeclaredRequesterRoutes()
    {
        var ownerReads = 0;
        var expansions = 0;
        PrincipalExpansion Expand(string sid, string _) { expansions++; return new(sid, PrincipalExpansionOutcome.Expanded,
            [new(Everyone, "contoso.com", [Holder, Everyone], true), new(Authenticated, "contoso.com", [Holder, Authenticated], true)]); }
        var verdict = Judge([Ace(0, Holder, FullControlEvaluator.RequiredMask)], expand: Expand, configure: context => context with
        {
            MembershipRoutes = (_, _) => { ownerReads++; return MembershipRouteSummary.NotDerived; },
        });
        var values = verdict.Findings.Select(finding => Assert.IsType<ObjectTakeoverEvidence>(finding.Evidence).Calculation!).ToArray();
        Assert.Equal(2, values.Length);
        Assert.Same(values[0].FullControl, values[1].FullControl);
        Assert.Equal(0, ownerReads);
        Assert.Equal(1, expansions);
    }

    [Fact]
    public void ADirectCapturedAdministratorIdentityQualifiesOnlyTheOwnerCondition()
    {
        const string administrator = "S-1-5-21-1-2-3-512";
        var value = Calculation(Judge([Ace(0, administrator, ChangeOwner)], "computer", (sid, _) =>
            new(sid, PrincipalExpansionOutcome.Expanded, [new(Everyone, "contoso.com", [sid, Everyone], true)])));
        Assert.Equal(PermissionControlState.Established, value.ChangeOwner.State);
        Assert.Equal(PermissionControlState.Established, value.OwnerRightsCondition);
        Assert.Contains(value.OwnerConditions, check => check.Name == "RequesterExemption"
            && check.State == PermissionControlState.Established);
        Assert.Equal(PermissionControlState.Unknown, value.OwnerTransition);
    }

    [Fact]
    public void BuiltinIdentityRequiresItsResourceDomainRatherThanAForestWideSidMatch()
    {
        var subject = Subject("group") with { DistinguishedName = "CN=Configuration,DC=contoso,DC=com" };
        var verdict = Judge([Ace(0, "S-1-5-32-545", Modify)], subject: subject);
        Assert.Empty(verdict.Findings);
        Assert.Contains(verdict.Unresolved, value => value.Reason == UnresolvedReason.PermissionControlNotEvaluated);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NullAndEmptyDaclsRemainOppositeAnswersWithoutInventedEntries(bool nullDacl)
    {
        var verdict = Judge([], configure: context => context with
        {
            Permissions = dn => ControlEdgeDeriverTests.Permissions(dn) with
            {
                DaclState = nullDacl ? DaclState.Null : DaclState.Empty,
            },
        });
        if (!nullDacl)
        {
            Assert.Empty(verdict.Findings);
            Assert.True(verdict.IsComplete);
            return;
        }
        var value = Calculation(verdict);
        Assert.Equal(PermissionControlState.Established, value.FullControl.State);
        Assert.Equal(DaclState.Null, value.DescriptorState);
        Assert.Empty(value.ModifyPermissions.GrantOrdinals);
    }

    [Fact]
    public void ForeignPermissionInputsAreRefusedEvenWhenTheyContainNoCandidateRights()
    {
        Assert.Throws<InvalidDataException>(() => Judge([], configure: context => context with
        {
            Permissions = _ => ControlEdgeDeriverTests.Permissions("CN=Other,DC=contoso,DC=com"),
        }));
    }

    [Fact]
    public void SavedCalculationRetainsExactBindingsAndUsesTheVersionThreeDisplay()
    {
        var directory = Saved("(A;;WD;;;WD)");
        using var reader = Open(directory);
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Target)).Value.Findings);
        var read = reader.ReadPermissionControlCalculation(row.Reference!.Value);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(3, row.RuleVersion);
        Assert.Equal(row.ObjectGuid, read.Value.Calculation.ObjectGuid);
        Assert.Equal(reader.Description.GenerationId, read.Value.Calculation.GenerationId);
        Assert.Equal(reader.Description.EvidenceSeal, read.Value.Calculation.EvidenceSeal);
        Assert.Equal(reader.Description.DerivationGenerationId, read.Value.Calculation.DerivationGenerationId);
        Assert.Equal(FindingInputBinding.DerivationSeal(directory, reader.Description.DerivationGenerationId), read.Value.Calculation.DerivationSeal);
        var display = reader.ReadPermissionControl(row.Reference.Value);
        Assert.True(display.IsSuccess, display.Error?.Description);
        Assert.True(display.Value.Matches(row));
        Assert.Equal(PermissionControlState.Established, display.Value.Assessment!.ModifyPermissions);
        Assert.False(reader.ReadPermissionControlCalculation(row.Reference.Value with { GenerationId = Guid.NewGuid() }).IsSuccess);
        Assert.False(reader.ReadPermissionControlCalculation(row.Reference.Value with { FindingId = long.MaxValue }).IsSuccess);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    [InlineData("derivation-seal")]
    [InlineData("object")]
    [InlineData("target")]
    [InlineData("domain")]
    [InlineData("holder")]
    [InlineData("broad")]
    [InlineData("modify-proof")]
    [InlineData("owner-transition")]
    [InlineData("owner-conditions")]
    public void SavedBindingRefusalsAreNotSubstitutedBySealFailures(string field)
    {
        var directory = Saved("(A;;WD;;;WD)");
        PermissionControlCalculation calculation;
        Finding finding;
        using (var reader = Open(directory))
        {
            finding = Assert.Single(reader.ReadPage(FindingsQuery.About(Target)).Value.Findings);
            calculation = Assert.IsType<ObjectTakeoverEvidence>(finding.Evidence).Calculation!;
        }
        using (var writer = JudgementWriter.Create(directory, calculation.EvidenceSeal, calculation.DerivationGenerationId,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch))
        {
            calculation = calculation with { GenerationId = writer.GenerationId };
            finding = finding with { Evidence = ((ObjectTakeoverEvidence)finding.Evidence) with { Calculation = calculation } };
            writer.Write(RuleExecution.Judged(new BroadPrincipalCanTakeOverObject().Definition, 1, 0, [finding]));
            var changed = field switch
            {
                "generation" => calculation with { GenerationId = Guid.NewGuid() },
                "evidence" => calculation with { EvidenceSeal = new string('c', 64) },
                "derivation" => calculation with { DerivationGenerationId = Guid.NewGuid() },
                "derivation-seal" => calculation with { DerivationSeal = new string('d', 64) },
                "object" => calculation with { ObjectGuid = Guid.NewGuid() },
                "target" => calculation with { Target = "CN=Other,DC=contoso,DC=com" },
                "domain" => calculation with { ResourceDomain = "other.com" },
                "holder" => calculation with { HolderSid = Holder },
                "modify-proof" => calculation with { ModifyPermissions = calculation.ModifyPermissions with { GrantOrdinals = [] } },
                "owner-transition" => calculation with { OwnerTransition = PermissionControlState.Established },
                "owner-conditions" => calculation with { OwnerRightsCondition = PermissionControlState.Established },
                _ => calculation with { BroadSid = Authenticated },
            };
            using (var connection = new SqliteConnection("Data Source=" + TestSealing.PendingJudgementPath(directory) + ";Pooling=False"))
            {
                connection.Open();
                TestSealing.AttachJudgementParts(connection, directory, writer.GenerationId, staged: true);
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE finding_object_takeover_calculation SET payload=$payload";
                update.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(changed, ProofSerialization.Options));
                Assert.Equal(1, update.ExecuteNonQuery());
            }
            writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        }
        using var reopened = Open(directory);
        var selected = Assert.Single(reopened.ReadListPage(FindingsQuery.About(Target)).Value.Findings);
        var error = Assert.Throws<InvalidDataException>(() => reopened.ReadPermissionControlCalculation(selected.Reference!.Value));
        Assert.Contains("saved SEC-060 calculation", error.Message, StringComparison.Ordinal);
    }

    internal static RuleVerdict Judge(PermissionEntry[] entries, string kind = "group",
        Func<string, string, PrincipalExpansion>? expand = null, Func<JudgingContext, JudgingContext>? configure = null,
        ObjectAttributes? subject = null)
    {
        subject ??= Subject(kind);
        var permissions = ControlEdgeDeriverTests.Permissions(subject.DistinguishedName, entries);
        var context = JudgingContext.At(DateTimeOffset.UnixEpoch) with
        {
            Permissions = _ => permissions,
            MembersOfPrincipal = expand ?? ((sid, _) => new(sid, PrincipalExpansionOutcome.Expanded, [])),
            ForestFqdn = "contoso.com",
            OwnerImplicitRights = DirectoryHeuristics.OwnerImplicitRights(""),
            PermissionControlInputs = new(Guid.NewGuid(),
                new(new string('a', 64), Guid.NewGuid(), new string('b', 64), PrincipalClassificationRegistry.Version, 2, 2,
                    "DC=contoso,DC=com", "CN=Configuration,DC=contoso,DC=com"), ControlEdgeDeriverTests.DomainSid),
        };
        return new BroadPrincipalCanTakeOverObject().Judge(subject, configure is null ? context : configure(context));
    }

    private static ObjectAttributes Subject(string kind) => ControlEdgeDeriverTests.Subject with
    {
        Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, "top", null), new(1, kind, null)])],
    };
    private static PermissionEntry Ace(int ordinal, string sid, int mask, string type = "AccessAllowed") =>
        ControlEdgeDeriverTests.Ace(ordinal, sid, mask, type);
    private static PermissionControlCalculation Calculation(RuleVerdict verdict) =>
        Assert.IsType<PermissionControlCalculation>(Assert.IsType<ObjectTakeoverEvidence>(Assert.Single(verdict.Findings).Evidence).Calculation);

    internal static string Saved(string? entries)
    {
        var directory = SelfMembershipDiscoveryTests.Bundle(entries is null ? "O:SYG:SY" : "O:SYG:SYD:" + entries,
            membership: false, users: 0);
        SelfMembershipDiscoveryTests.Derive(directory);
        var evidence = SelfMembershipDiscoveryTests.Hash(directory);
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [new BroadPrincipalCanTakeOverObject()],
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, JudgingRun.NobodyIsWatching, RunLog.Discarded,
            cancellationToken: CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(evidence, SelfMembershipDiscoveryTests.Hash(directory));
        return directory;
    }
    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
