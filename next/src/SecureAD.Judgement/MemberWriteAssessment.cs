using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>A limitation of the bounded ordinary member-write authorization, not a reachability verdict.</summary>
public enum MemberWriteIssue
{
    /// <summary>The enclosing operation did not establish the supported requester/resource context.</summary>
    ContextNotEstablished,
    /// <summary>The target descriptor could not be read or parsed.</summary>
    DescriptorUnreadable,
    /// <summary>Missing permission entries could change the answer.</summary>
    DescriptorIncomplete,
    /// <summary>A relevant entry requires unsupported interpretation.</summary>
    UnsupportedAce,
    /// <summary>Required captured attribute, class or property-set scope is unresolved.</summary>
    ScopeUnknown,
    /// <summary>A relevant trustee cannot be matched or excluded.</summary>
    TrusteeUnknown,
    /// <summary>No explicit direct-user or single-global-group grant supports this bounded route.</summary>
    GrantRouteUnsupported,
}

/// <summary>An original ordered member-write permission entry, with scope and requester evidence.</summary>
public sealed record MemberWriteAceEvidence(PermissionEntry Entry, ControlEvaluationState Scope,
    string ScopeEvidence, RequesterTrusteeEvidence Trustee);

/// <summary>
/// Ordinary Write Members authorization within a source-bound own-account assessment.
/// This is separate from Self-Membership, membership obtainability, authentication and live Add success.
/// </summary>
public sealed record MemberWriteAssessment(ControlEvaluationState Authorization, ControlEvaluationState Readiness,
    bool? MemberPresent, IReadOnlyList<MemberWriteIssue> Issues, IReadOnlyList<MemberWriteAceEvidence> Evidence);

internal static class MemberWriteEvaluator
{
    private const int WriteProperty = 0x20;
    private const int GenericShorthand = 0x50000000;

    internal static MemberWriteAssessment Assess(ObjectAttributes requester, ObjectAttributes target,
        ObjectPermissions? permissions, Func<PermissionTrustee, ObjectAttributes?> holder, string forest,
        SchemaGuidCatalog catalogue, ControlEvaluationState readiness, bool? memberPresent, CancellationToken cancellationToken)
    {
        var issues = new List<MemberWriteIssue>();
        var evidence = new List<MemberWriteAceEvidence>();
        if (permissions is null || permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
            return Unknown(MemberWriteIssue.DescriptorUnreadable);
        // A NULL DACL is broad access, but supplies no explicit user/group grant in this checkpoint.
        if (permissions.DaclState == DaclState.Null) return Unknown(MemberWriteIssue.GrantRouteUnsupported);
        var possibleAllow = permissions.DaclCompleteness != DaclCompleteness.Complete;
        var possibleDeny = possibleAllow;
        if (possibleAllow) issues.Add(MemberWriteIssue.DescriptorIncomplete);
        foreach (var entry in permissions.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if ((entry.AccessMask & (WriteProperty | GenericShorthand)) == 0
                || EntryReachReader.FromPropagationFlags(entry.PropagationFlags) != EntryReach.ThisObject) continue;
            var (scope, source) = ControlEdgeDeriver.OperationScope(entry, WriteProperty, "member", "group", catalogue);
            if (entry.HasObjectType && (catalogue.FindUnambiguousByLdapName("member")?.Source != SchemaGuidSource.Captured
                || catalogue.FindUnambiguousByLdapName("group")?.Source != SchemaGuidSource.Captured)) scope = ControlEvaluationState.Unknown;
            var concreteWrite = (entry.AccessMask & WriteProperty) != 0;
            if (!concreteWrite) scope = ControlEvaluationState.Unknown;
            var trustee = RequesterTrusteeReading.Read(requester, target, entry.Trustee, holder(entry.Trustee), forest);
            evidence.Add(new(entry, scope, source, trustee));
            if (scope == ControlEvaluationState.NotEstablished || trustee.State == RequesterTrusteeState.DoesNotMatch) continue;
            var allow = entry.AceType is "AccessAllowed" or "AccessAllowedObject";
            var deny = entry.AceType is "AccessDenied" or "AccessDeniedObject";
            if ((!allow && !deny) || !concreteWrite) issues.Add(MemberWriteIssue.UnsupportedAce);
            if (scope == ControlEvaluationState.Unknown) issues.Add(MemberWriteIssue.ScopeUnknown);
            if (trustee.State == RequesterTrusteeState.Unknown) issues.Add(MemberWriteIssue.TrusteeUnknown);
            var grantRoute = trustee.Reason is RequesterTrusteeReason.DirectIdentity or RequesterTrusteeReason.DirectGlobalMembership;
            if (allow && !grantRoute) issues.Add(MemberWriteIssue.GrantRouteUnsupported);
            // MS-ADTS 5.1.3.3.3: project the single member attribute, not independent
            // allow/deny totals. An uncertain earlier match retains both possible outcomes.
            possibleAllow |= !deny;
            possibleDeny |= !allow;
            if ((deny || allow && grantRoute) && concreteWrite && scope == ControlEvaluationState.Established
                && trustee.State == RequesterTrusteeState.Matches)
                return Result(possibleAllow ? possibleDeny ? ControlEvaluationState.Unknown : ControlEvaluationState.Established
                    : ControlEvaluationState.NotEstablished);
        }
        return Result(possibleAllow ? ControlEvaluationState.Unknown : ControlEvaluationState.NotEstablished);

        MemberWriteAssessment Unknown(MemberWriteIssue issue)
        {
            issues.Add(issue);
            return Result(ControlEvaluationState.Unknown);
        }

        MemberWriteAssessment Result(ControlEvaluationState state) =>
            new(state, readiness, memberPresent, issues.Distinct().Order().ToArray(), evidence);
    }
}
