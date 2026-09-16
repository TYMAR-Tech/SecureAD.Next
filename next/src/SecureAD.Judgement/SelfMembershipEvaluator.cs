using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class SelfMembershipEvaluator
{
    private const int Self = 0x08;

    public static SelfMembershipAssessment Assess(SelfMembershipRequest request, ObjectAttributes? requester,
        ObjectAttributes? target, ObjectAttributes? member, ObjectPermissions? permissions,
        Func<PermissionTrustee, ObjectAttributes?> holder, string forest,
        string evidenceSeal, Guid generation, Guid? derivationGeneration, SelfMembershipBudget budget,
        IReadOnlyList<long> holderEdgeIds)
    {
        var issues = new List<SelfMembershipIssue>();
        if (requester is null) issues.Add(SelfMembershipIssue.RequesterMissing);
        else if (!RequesterTrusteeReading.HasClass(requester, "user")) issues.Add(SelfMembershipIssue.RequesterNotUser);
        if (target is null) issues.Add(SelfMembershipIssue.TargetMissing);
        else if (!RequesterTrusteeReading.HasClass(target, "group")) issues.Add(SelfMembershipIssue.TargetNotGroup);
        if (member is null) issues.Add(SelfMembershipIssue.MemberMissing);
        var requesterSid = RequesterTrusteeReading.SidOf(requester);
        var targetSid = RequesterTrusteeReading.SidOf(target);
        var memberSid = RequesterTrusteeReading.SidOf(member);
        var own = requester is null || member is null || requester.ObjectGuid is null || member.ObjectGuid is null
            ? ControlEvaluationState.Unknown
            : requester.ObjectGuid == member.ObjectGuid && Same(requesterSid, memberSid)
                ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
        if (requester is null || target is null || issues.Contains(SelfMembershipIssue.RequesterNotUser)
            || issues.Contains(SelfMembershipIssue.TargetNotGroup))
            return Result(ControlEvaluationState.Unknown, own, ControlEvaluationState.Unknown, "NotEvaluated", null, null, [], []);

        var (authorization, descriptor, evidence) = Authorization(requester, target, permissions, holder,
            forest, budget, issues);
        var (readiness, uac, present) = Readiness(requester, target, member, request.Operation, own, issues);
        issues.Add(SelfMembershipIssue.LiveOperationNotEvaluated);
        return Result(authorization, own, readiness, descriptor, uac, present, evidence, holderEdgeIds);

        SelfMembershipAssessment Result(ControlEvaluationState authorization, ControlEvaluationState ownAccount,
            ControlEvaluationState readiness, string descriptorOutcome, long? userAccountControl, bool? memberPresent,
            IReadOnlyList<SelfMembershipAceEvidence> aceEvidence, IReadOnlyList<long> edges) =>
            new(request, generation, derivationGeneration, evidenceSeal, requester?.ObjectGuid, requesterSid,
                target?.ObjectGuid, targetSid, member?.ObjectGuid, memberSid, authorization, ownAccount, readiness,
                descriptorOutcome, requester?.CapturedUtc, userAccountControl, memberPresent,
                issues.Distinct().Order().ToArray(), aceEvidence, edges.Distinct().Order().ToArray());
    }

    private static (ControlEvaluationState State, string Outcome, IReadOnlyList<SelfMembershipAceEvidence> Evidence)
        Authorization(ObjectAttributes requester, ObjectAttributes target, ObjectPermissions? permissions,
            Func<PermissionTrustee, ObjectAttributes?> holder, string forest,
            SelfMembershipBudget budget, List<SelfMembershipIssue> issues)
    {
        if (permissions is null || permissions.Availability != DescriptorAvailability.Read)
        {
            issues.Add(SelfMembershipIssue.DescriptorUnreadable);
            return (ControlEvaluationState.Unknown, "DescriptorNotRead", []);
        }
        if (permissions.DaclState == DaclState.Null)
            return (ControlEvaluationState.Established, EffectiveAccessOutcome.GrantsEveryoneEverything.ToString(), []);
        if (permissions.DaclState == DaclState.Unreadable)
        {
            issues.Add(SelfMembershipIssue.DescriptorUnreadable);
            return (ControlEvaluationState.Unknown, EffectiveAccessOutcome.EntriesUnparsed.ToString(), []);
        }
        if (permissions.DaclCompleteness != DaclCompleteness.Complete)
            issues.Add(SelfMembershipIssue.DescriptorIncomplete);
        var relevant = permissions.Entries.Where(Applies).Where(entry => (entry.AccessMask & Self) != 0).ToArray();
        if (relevant.Length > budget.PermissionEntries)
        {
            issues.Add(SelfMembershipIssue.PermissionBudgetExceeded);
            return (ControlEvaluationState.Unknown, EffectiveAccessOutcome.Computed.ToString(), []);
        }
        var evidence = new List<SelfMembershipAceEvidence>();
        // Missing entries have no trustworthy position or effect. For visible uncertain ACEs,
        // retain their possible terminal outcomes while the non-applying path continues in order.
        var possibleAllow = permissions.DaclCompleteness != DaclCompleteness.Complete;
        var possibleDeny = possibleAllow;
        foreach (var entry in relevant)
        {
            var scope = Scope(entry);
            var trustee = RequesterTrusteeReading.Read(requester, target, entry.Trustee, holder(entry.Trustee), forest);
            evidence.Add(new(entry, scope, trustee));
            if (scope == ControlEvaluationState.NotEstablished || trustee.State == RequesterTrusteeState.DoesNotMatch)
                continue;
            if (!Supported(entry.AceType))
                issues.Add(SelfMembershipIssue.UnsupportedAce);
            if (scope == ControlEvaluationState.Unknown)
                issues.Add(SelfMembershipIssue.ScopeUnknown);
            if (trustee.State == RequesterTrusteeState.Unknown)
                issues.Add(SelfMembershipIssue.TrusteeUnknown);

            var effect = entry.AceType switch
            {
                "AccessAllowed" or "AccessAllowedObject" or "AccessAllowedCallback" or "AccessAllowedCallbackObject"
                    => ControlEvaluationState.Established,
                "AccessDenied" or "AccessDeniedObject" or "AccessDeniedCallback" or "AccessDeniedCallbackObject"
                    => ControlEvaluationState.NotEstablished,
                _ => ControlEvaluationState.Unknown,
            };
            possibleAllow |= effect != ControlEvaluationState.NotEstablished;
            possibleDeny |= effect != ControlEvaluationState.Established;
            if (Supported(entry.AceType) && scope == ControlEvaluationState.Established
                && trustee.State == RequesterTrusteeState.Matches)
                return Decision();
        }
        // Any path still undecided at the end of the DACL is implicitly denied.
        possibleDeny = true;
        return Decision();

        (ControlEvaluationState, string, IReadOnlyList<SelfMembershipAceEvidence>) Decision() =>
            (possibleAllow ? possibleDeny ? ControlEvaluationState.Unknown : ControlEvaluationState.Established
                : ControlEvaluationState.NotEstablished, EffectiveAccessOutcome.Computed.ToString(), evidence);
    }

    private static (ControlEvaluationState State, long? Uac, bool? Present) Readiness(ObjectAttributes requester,
        ObjectAttributes target, ObjectAttributes? member, SelfMembershipOperation operation,
        ControlEvaluationState own, List<SelfMembershipIssue> issues)
    {
        var uac = RequesterTrusteeReading.Number(requester, "userAccountControl");
        if (uac is null) issues.Add(SelfMembershipIssue.AccountStatusMissing);
        else if ((uac.Value & 0x2) != 0) issues.Add(SelfMembershipIssue.AccountDisabled);
        var found = member is not null && target.Find("member")?.Values.Any(value => Same(value.Text, member.DistinguishedName)) == true;
        bool? present = found ? true : null;
        if (present is null)
            issues.Add(SelfMembershipIssue.MembershipStateUnknown);
        if (present == true && operation == SelfMembershipOperation.Add)
            issues.Add(SelfMembershipIssue.AlreadyMember);
        if (own != ControlEvaluationState.Established || uac is null)
            return (ControlEvaluationState.Unknown, uac, present);
        if ((uac.Value & 0x2) != 0)
            return (ControlEvaluationState.NotEstablished, uac, present);
        if (present is null)
            return (ControlEvaluationState.Unknown, uac, present);
        if (operation == SelfMembershipOperation.Add && present == true)
            return (ControlEvaluationState.NotEstablished, uac, present);
        return operation == SelfMembershipOperation.Remove && present == true
            ? (ControlEvaluationState.Established, uac, present)
            : (ControlEvaluationState.Unknown, uac, present);
    }

    private static ControlEvaluationState Scope(PermissionEntry entry)
    {
        if (!entry.HasObjectType) return ControlEvaluationState.Established;
        if (entry.ObjectTypeGuid is null) return ControlEvaluationState.Unknown;
        // The validated-write GUID is fixed by AD, not by mutable captured display-name metadata.
        return Same(entry.ObjectTypeGuid, SchemaGuidCatalog.Embedded.GuidFor("Self-Membership"))
            ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
    }
    private static bool Applies(PermissionEntry entry) =>
        EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject;
    private static bool Supported(string type) => type is "AccessAllowed" or "AccessAllowedObject" or "AccessDenied" or "AccessDeniedObject";
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
