using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SelfMembershipRequesterTests
{
    private const string RequesterSid = "S-1-5-21-1-2-3-1100";
    private const string HolderSid = "S-1-5-21-1-2-3-1200";
    private const string RequesterDn = "CN=Alice,DC=contoso,DC=com";
    private const string HolderDn = "CN=Helpdesk,DC=contoso,DC=com";
    private const string TargetDn = "CN=Target,DC=contoso,DC=com";
    private static readonly Guid RequesterGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TargetGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public void DirectAndOneGlobalGroupGrantEstablishAuthorization()
    {
        Assert.Equal(ControlEvaluationState.Established, Assess(Entry(0, RequesterSid, RequesterDn)).Authorization);
        Assert.Equal(ControlEvaluationState.Established, Assess(Entry(0, HolderSid, HolderDn), holder: Group(-2147483646, RequesterDn)).Authorization);
    }

    [Fact]
    public void GeneralMemberWriteMaskDoesNotBecomeSelfMembershipAuthorization()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished,
            Assess(Entry(0, RequesterSid, RequesterDn) with { AccessMask = 0x20 }).Authorization);
    }

    [Fact]
    public void ApplicableDenyThroughAnotherIdentityIsEvaluatedInStoredOrder()
    {
        var deny = Entry(0, HolderSid, HolderDn, "AccessDeniedObject");
        var allow = Entry(1, RequesterSid, RequesterDn);
        Assert.Equal(ControlEvaluationState.NotEstablished, Assess(deny, allow, holder: Group(-2147483646, RequesterDn)).Authorization);
        Assert.Equal(ControlEvaluationState.Established, Assess(allow with { Ordinal = 0 }, deny with { Ordinal = 1 }, holder: Group(-2147483646, RequesterDn)).Authorization);
    }

    [Fact]
    public void MissingMembershipStaysUnknownAndDistributionMembershipDoesNotAuthorize()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Assess(Entry(0, HolderSid, HolderDn), holder: Group(-2147483646)).Authorization);
        Assert.Equal(ControlEvaluationState.NotEstablished, Assess(Entry(0, HolderSid, HolderDn), holder: Group(2, RequesterDn)).Authorization);
    }

    [Fact]
    public void AnotherMemberFailsTheOwnAccountConstraintWithoutErasingThePermission()
    {
        var other = User("CN=Bob,DC=contoso,DC=com", "S-1-5-21-1-2-3-1101", Guid.Parse("33333333-3333-3333-3333-333333333333"), 512);
        var result = Assess(Entry(0, RequesterSid, RequesterDn), member: other);
        Assert.Equal(ControlEvaluationState.Established, result.Authorization);
        Assert.Equal(ControlEvaluationState.NotEstablished, result.OwnAccount);
    }

    [Fact]
    public void DisabledAccountIsAReadinessBlockerNotAPermissionDenial()
    {
        var result = Assess(Entry(0, RequesterSid, RequesterDn), requester: User(RequesterDn, RequesterSid, RequesterGuid, 514));
        Assert.Equal(ControlEvaluationState.Established, result.Authorization);
        Assert.Equal(ControlEvaluationState.NotEstablished, result.Readiness);
        Assert.Contains(SelfMembershipIssue.AccountDisabled, result.Issues);
    }

    [Fact]
    public void IncompleteDescriptorCannotProduceACompleteNegativeAnswer()
    {
        var permissions = Permissions() with { DaclCompleteness = DaclCompleteness.Incomplete };
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(permissions, User(RequesterDn, RequesterSid, RequesterGuid, 512), Target(), null).Authorization);
    }

    [Theory]
    [InlineData("trustee", true, false, ControlEvaluationState.Unknown)]
    [InlineData("trustee", false, true, ControlEvaluationState.Unknown)]
    [InlineData("trustee", true, true, ControlEvaluationState.NotEstablished)]
    [InlineData("trustee", false, false, ControlEvaluationState.Established)]
    [InlineData("scope", true, false, ControlEvaluationState.Unknown)]
    [InlineData("scope", false, true, ControlEvaluationState.Unknown)]
    [InlineData("scope", true, true, ControlEvaluationState.NotEstablished)]
    [InlineData("scope", false, false, ControlEvaluationState.Established)]
    [InlineData("callback", true, false, ControlEvaluationState.Unknown)]
    [InlineData("callback", false, true, ControlEvaluationState.Unknown)]
    [InlineData("callback", true, true, ControlEvaluationState.NotEstablished)]
    [InlineData("callback", false, false, ControlEvaluationState.Established)]
    public void EarlierUncertaintyOnlyChangesTheAnswerWhenItsOutcomeCanDiffer(string uncertainty,
        bool earlierDeny, bool laterDeny, ControlEvaluationState expected)
    {
        var earlier = UncertainEntry(uncertainty, earlierDeny);
        var later = Entry(1, RequesterSid, RequesterDn, laterDeny ? "AccessDeniedObject" : "AccessAllowedObject");
        var issue = uncertainty switch
        {
            "trustee" => SelfMembershipIssue.TrusteeUnknown,
            "scope" => SelfMembershipIssue.ScopeUnknown,
            _ => SelfMembershipIssue.UnsupportedAce,
        };
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
        {
            var result = Assess(earlier, later, operation: operation);
            Assert.Equal(expected, result.Authorization);
            Assert.Contains(issue, result.Issues);
            Assert.Equal(new[] { 0, 1 }, result.Evidence.Select(value => value.Entry.Ordinal));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnrecognizedAceBeforeEitherDecisionRemainsUnknown(bool laterDeny)
    {
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
        {
            var result = Assess(Entry(0, RequesterSid, RequesterDn, "UnrecognizedAce"),
                Entry(1, RequesterSid, RequesterDn, laterDeny ? "AccessDeniedObject" : "AccessAllowedObject"), operation: operation);
            Assert.Equal(ControlEvaluationState.Unknown, result.Authorization);
            Assert.Contains(SelfMembershipIssue.UnsupportedAce, result.Issues);
        }
    }

    [Theory]
    [InlineData(DaclCompleteness.Incomplete, "AccessAllowedObject")]
    [InlineData(DaclCompleteness.Incomplete, "AccessDeniedObject")]
    [InlineData(DaclCompleteness.Unknown, "AccessAllowedObject")]
    [InlineData(DaclCompleteness.Unknown, "AccessDeniedObject")]
    public void IncompleteDescriptorWithRelevantEntriesCannotJustifyEitherAnswer(DaclCompleteness completeness, string type)
    {
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
        {
            var permissions = Permissions(Entry(0, RequesterSid, RequesterDn, type)) with { DaclCompleteness = completeness };
            var result = Evaluate(permissions, User(RequesterDn, RequesterSid, RequesterGuid, 512), Target(), null, operation: operation);
            Assert.Equal(ControlEvaluationState.Unknown, result.Authorization);
            Assert.Contains(SelfMembershipIssue.DescriptorIncomplete, result.Issues);
            Assert.Single(result.Evidence);
        }
    }

    [Theory]
    [InlineData("trustee")]
    [InlineData("scope")]
    [InlineData("callback")]
    public void EndOfDaclImplicitDenialAgreesWithPossibleDenyButNotPossibleAllow(string uncertainty)
    {
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
        {
            Assert.Equal(ControlEvaluationState.NotEstablished, Assess(UncertainEntry(uncertainty, true), operation: operation).Authorization);
            Assert.Equal(ControlEvaluationState.Unknown, Assess(UncertainEntry(uncertainty, false), operation: operation).Authorization);
        }
    }

    [Theory]
    [InlineData(false, ControlEvaluationState.Established)]
    [InlineData(true, ControlEvaluationState.NotEstablished)]
    public void JustifiedDecisionIsNotChangedByALaterOppositeOrUncertainEntry(bool deny, ControlEvaluationState expected)
    {
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
        {
            var first = Entry(0, RequesterSid, RequesterDn, deny ? "AccessDeniedObject" : "AccessAllowedObject");
            var opposite = Entry(1, HolderSid, HolderDn, deny ? "AccessAllowedObject" : "AccessDeniedObject");
            Assert.Equal(expected, Assess(first, opposite, holder: Group(-2147483646, RequesterDn), operation: operation).Authorization);
            foreach (var uncertainty in new[] { "trustee", "scope", "callback" })
            {
                var result = Assess(first, UncertainEntry(uncertainty, !deny) with { Ordinal = 1 }, operation: operation);
                Assert.Equal(expected, result.Authorization);
                Assert.Single(result.Evidence);
            }
        }
    }

    [Theory]
    [InlineData(SelfMembershipOperation.Add)]
    [InlineData(SelfMembershipOperation.Remove)]
    public void BothOperationsKeepMembershipReadinessAccountStatusAndOwnAccountSeparate(SelfMembershipOperation operation)
    {
        var requester = User(RequesterDn, RequesterSid, RequesterGuid, 512);
        var target = Group(-2147483646, RequesterDn) with { DistinguishedName = TargetDn, ObjectGuid = TargetGuid };
        var permissions = Permissions(Entry(0, RequesterSid, RequesterDn));
        var result = Evaluate(permissions, requester, target, null, operation: operation);
        Assert.Equal(operation, result.Request.Operation);
        Assert.Equal(ControlEvaluationState.Established, result.Authorization);
        Assert.Equal(ControlEvaluationState.Established, result.OwnAccount);
        Assert.True(result.MemberPresent);
        Assert.Equal(operation == SelfMembershipOperation.Add ? ControlEvaluationState.NotEstablished : ControlEvaluationState.Established, result.Readiness);
        Assert.Equal(operation == SelfMembershipOperation.Add, result.Issues.Contains(SelfMembershipIssue.AlreadyMember));
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(permissions, requester, Target(), null, operation: operation).Readiness);
        var disabled = Evaluate(permissions, User(RequesterDn, RequesterSid, RequesterGuid, 514), target, null, operation: operation);
        Assert.Equal(ControlEvaluationState.Established, disabled.Authorization);
        Assert.Equal(ControlEvaluationState.NotEstablished, disabled.Readiness);
        Assert.Contains(SelfMembershipIssue.AccountDisabled, disabled.Issues);
        var other = User("CN=Bob,DC=contoso,DC=com", "S-1-5-21-1-2-3-1101", Guid.NewGuid(), 512);
        var otherMember = Evaluate(permissions, requester, target, null, other, operation);
        Assert.Equal(ControlEvaluationState.Established, otherMember.Authorization);
        Assert.Equal(ControlEvaluationState.NotEstablished, otherMember.OwnAccount);
        Assert.NotEqual(ControlEvaluationState.Established, otherMember.Readiness);
        Assert.Equal(ControlEvaluationState.NotEstablished, Assess(Entry(0, RequesterSid, RequesterDn) with { AccessMask = 0x20 }, operation: operation).Authorization);
        Assert.Equal(ControlEvaluationState.Established, Assess(Entry(0, HolderSid, HolderDn), holder: Group(-2147483646, RequesterDn), operation: operation).Authorization);
        Assert.Equal(ControlEvaluationState.Unknown, Assess(Entry(0, HolderSid, HolderDn), holder: Group(-2147483646), operation: operation).Authorization);
        Assert.Equal(ControlEvaluationState.NotEstablished, Assess(Entry(0, HolderSid, HolderDn), holder: Group(2, RequesterDn), operation: operation).Authorization);
    }

    [Theory]
    [InlineData("nested")]
    [InlineData("primary")]
    [InlineData("history")]
    [InlineData("foreign")]
    [InlineData("cross-domain")]
    [InlineData("domain-local")]
    [InlineData("universal")]
    [InlineData("builtin")]
    [InlineData("resource-context")]
    [InlineData("missing-group-type")]
    public void UnsupportedRoutesCannotBecomeSupportedAuthorization(string route)
    {
        var requester = User(RequesterDn, RequesterSid, RequesterGuid, 512);
        var target = Target();
        var holder = Group(-2147483646, RequesterDn);
        var sid = HolderSid;
        switch (route)
        {
            case "nested": holder = Group(-2147483646, "CN=Nested,DC=contoso,DC=com"); break;
            case "primary":
                holder = Group(-2147483646);
                requester = requester with { Attributes = [.. requester.Attributes, new("primaryGroupID", AttributeCardinality.SingleValued, [new(0, "1200", null)])] };
                break;
            case "history":
                holder = User(HolderDn, HolderSid, Guid.NewGuid(), 512);
                requester = requester with { Attributes = [.. requester.Attributes, new("sIDHistory", AttributeCardinality.MultiValued, [new(0, null, Sid.ToBytes(HolderSid)!)])] };
                break;
            case "foreign": holder = Object(HolderDn, HolderSid, Guid.NewGuid(), "foreignSecurityPrincipal", []); break;
            case "cross-domain": holder = holder with { DistinguishedName = "CN=Helpdesk,DC=other,DC=com", DomainFqdn = "other.com" }; break;
            case "domain-local": holder = Group(-2147483644, RequesterDn); break;
            case "universal": holder = Group(-2147483640, RequesterDn); break;
            case "builtin": sid = "S-1-5-32-544"; break;
            case "resource-context": target = target with { DomainFqdn = null }; break;
            case "missing-group-type": holder = holder with { Attributes = holder.Attributes.Where(value => value.LdapDisplayName != "groupType").ToArray() }; break;
        }
        foreach (var operation in Enum.GetValues<SelfMembershipOperation>())
        {
            Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Permissions(Entry(0, sid, HolderDn)), requester, target, holder, operation: operation).Authorization);
            Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Permissions(Entry(0, sid, HolderDn, "AccessDeniedObject"),
                Entry(1, RequesterSid, RequesterDn)), requester, target, holder, operation: operation).Authorization);
        }
    }

    [Theory]
    [InlineData(SelfMembershipOperation.Add)]
    [InlineData(SelfMembershipOperation.Remove)]
    public void BothPossibleOutcomesSurviveFurtherUncertainEntries(SelfMembershipOperation operation)
    {
        var permissions = Permissions(UncertainEntry("trustee", true), UncertainEntry("scope", false) with { Ordinal = 1 },
            Entry(2, RequesterSid, RequesterDn));
        var result = Evaluate(permissions, User(RequesterDn, RequesterSid, RequesterGuid, 512), Target(), null, operation: operation);
        Assert.Equal(ControlEvaluationState.Unknown, result.Authorization);
        Assert.Contains(SelfMembershipIssue.TrusteeUnknown, result.Issues);
        Assert.Contains(SelfMembershipIssue.ScopeUnknown, result.Issues);
    }

    private static PermissionEntry UncertainEntry(string uncertainty, bool deny)
    {
        var entry = Entry(0, RequesterSid, RequesterDn, deny ? "AccessDeniedObject" : "AccessAllowedObject");
        return uncertainty switch
        {
            "trustee" => entry with { Trustee = Entry(0, HolderSid, HolderDn).Trustee },
            "scope" => entry with { ObjectTypeGuid = null },
            "callback" => entry with { AceType = deny ? "AccessDeniedCallbackObject" : "AccessAllowedCallbackObject", ApplicationData = [0x61, 0x72, 0x74, 0x78] },
            _ => throw new ArgumentOutOfRangeException(nameof(uncertainty)),
        };
    }

    private static SelfMembershipAssessment Assess(PermissionEntry first, PermissionEntry? second = null,
        ObjectAttributes? requester = null, ObjectAttributes? holder = null, ObjectAttributes? member = null,
        SelfMembershipOperation operation = SelfMembershipOperation.Add) =>
        Evaluate(Permissions(second is null ? [first] : [first, second]), requester ?? User(RequesterDn, RequesterSid, RequesterGuid, 512),
            Target(), holder, member, operation);

    private static SelfMembershipAssessment Evaluate(ObjectPermissions permissions, ObjectAttributes requester,
        ObjectAttributes target, ObjectAttributes? holder, ObjectAttributes? member = null,
        SelfMembershipOperation operation = SelfMembershipOperation.Add) =>
        SelfMembershipEvaluator.Assess(new(RequesterDn, TargetDn, operation, member?.DistinguishedName),
            requester, target, member ?? requester, permissions, trustee => trustee.DistinguishedName == HolderDn ? holder : null,
            SchemaGuidCatalog.Embedded, "contoso.com", new('a', 64), Guid.Empty, null, SelfMembershipBudget.Default, []);

    private static PermissionEntry Entry(int ordinal, string sid, string? dn, string type = "AccessAllowedObject") =>
        new(ordinal, type, new(sid, sid, dn, "contoso.com", null, null, null), 0x08,
            SchemaGuidCatalog.Embedded.GuidFor("Self-Membership"), null, false, 0, 0, true, false, []);
    private static ObjectPermissions Permissions(params PermissionEntry[] entries) => new(TargetDn, DescriptorAvailability.Read,
        null, null, DaclState.Present, DaclCompleteness.Complete, true, false, entries, []);
    private static ObjectAttributes User(string dn, string sid, Guid guid, int uac) => Object(dn, sid, guid, "user",
        [new("userAccountControl", AttributeCardinality.SingleValued, [new(0, uac.ToString(), null)])]);
    private static ObjectAttributes Target() => Object(TargetDn, "S-1-5-21-1-2-3-1300", TargetGuid, "group", []);
    private static ObjectAttributes Group(long type, params string[] members) => Object(HolderDn, HolderSid,
        Guid.Parse("44444444-4444-4444-4444-444444444444"), "group",
        [new("groupType", AttributeCardinality.SingleValued, [new(0, type.ToString(), null)]),
         new("member", AttributeCardinality.MultiValued, members.Select((dn, i) => new AttributeValue(i, dn, null)).ToArray())]);
    private static ObjectAttributes Object(string dn, string sid, Guid guid, string @class, IReadOnlyList<ObjectAttribute> additional) =>
        new(dn, guid, DateTimeOffset.UnixEpoch, default,
            [new("objectClass", AttributeCardinality.MultiValued, [new(0, "top", null), new(1, @class, null)]),
             new("objectSid", AttributeCardinality.SingleValued, [new(0, null, Sid.ToBytes(sid)!)]), .. additional], "contoso.com");
}
