using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>An explicit offline question about ACE-backed WRITE_DAC, not a discovery instruction.</summary>
public sealed record RequesterDaclRequest(string RequesterDn, string TargetDn);

/// <summary>Why the bounded permission question could not establish an answer.</summary>
public enum RequesterDaclIssue
{
    /// <summary>The source-bound path inputs were not produced or are unavailable.</summary>
    PathInputsUnavailable,
    /// <summary>The requested user was not found in the captured evidence.</summary>
    RequesterMissing,
    /// <summary>The captured requester is outside the ordinary-user model.</summary>
    RequesterNotUser,
    /// <summary>The requested resource is not one of the saved fixed Tier-0 targets.</summary>
    TargetNotFixed,
    /// <summary>A captured identity is missing, ambiguous or cannot be qualified.</summary>
    IdentityUnresolved,
    /// <summary>The operation is outside the verified same-domain resource context.</summary>
    ResourceContextUnsupported,
    /// <summary>The target's DACL could not be read or parsed.</summary>
    DescriptorUnreadable,
    /// <summary>Uncaptured DACL entries could change the authorization answer.</summary>
    DescriptorIncomplete,
    /// <summary>A relevant permission entry requires unsupported interpretation.</summary>
    UnsupportedAce,
    /// <summary>A relevant object-specific permission scope is not supported.</summary>
    ScopeUnsupported,
    /// <summary>A relevant trustee cannot be matched or excluded for this requester.</summary>
    TrusteeUnknown,
    /// <summary>The grant lacks a supported explicit user or captured global-group route.</summary>
    GrantRouteUnsupported,
    /// <summary>The granting entry cannot be bound to its original stored holder permission.</summary>
    PermissionReferenceUnavailable,
    /// <summary>The supplied membership context does not qualify this requester and resource.</summary>
    MembershipContextUnsupported,
    /// <summary>The successful grant does not name the group required by the combined route.</summary>
    GrantNotHeldByObtainedGroup,
}

/// <summary>An original ordered permission entry and its applicability to this requester.</summary>
public sealed record RequesterDaclAceEvidence(PermissionEntry Entry, ControlEvaluationState Scope,
    RequesterTrusteeEvidence Trustee)
{
    /// <summary>The separately qualified nested route, including the sources of a matching deny.</summary>
    public RequesterMembershipEvidence? Membership { get; init; }
    /// <summary>Captured nesting from the separately obtained group, never an invented user membership value.</summary>
    public RequesterMembershipEvidence? ObtainedGroupMembership { get; init; }
}

/// <summary>An unchanged named-holder permission supporting a separate requester proof.</summary>
public sealed record RequesterDaclPermission(long Id, string Fingerprint);

/// <summary>
/// Saved explicit WRITE_DAC authorization under the bounded ordinary-directory-user model.
/// NotEstablished answers only this ACE-backed operation, never all ownership rights or Tier-0 reachability.
/// This is not an authentication, live-token, account-takeover or LDAP-success prediction.
/// </summary>
public sealed record RequesterDaclAssessment(RequesterDaclRequest Request, Guid GenerationId,
    Guid? DerivationGenerationId, string EvidenceSeal, Tier0Target? Requester, Tier0Target? Target,
    ControlEvaluationState Authorization, IReadOnlyList<RequesterDaclIssue> Issues,
    IReadOnlyList<RequesterDaclAceEvidence> Evidence, IReadOnlyList<RequesterDaclPermission> Permissions,
    IReadOnlyList<Tier0PathStep> Steps)
{
    /// <summary>The separate membership context, when this answer belongs to a combined proof rather than captured membership alone.</summary>
    public OwnAccountMembershipRequest? ObtainedMembership { get; init; }
}

internal static class RequesterDaclEvaluator
{
    private const int WriteDacl = 0x40000;

    internal static RequesterDaclAssessment Assess(RequesterDaclRequest request, PathInputs inputs,
        JudgementDescription description, IReadOnlyDictionary<string, Tier0Target> identities,
        Func<string, ObjectAttributes?> attributes, ObjectPermissions? permissions,
        IReadOnlyDictionary<string, NamingContextKind> contexts, IReadOnlyList<ControlEdge> edges,
        string forest, CancellationToken cancellationToken, OwnAccountMembershipAssessment? obtainedMembership,
        RequesterMembershipContext? memberships)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var issues = new List<RequesterDaclIssue>();
        var evidence = new List<RequesterDaclAceEvidence>();
        var requester = identities.GetValueOrDefault(request.RequesterDn);
        var target = inputs.FixedTargets.SingleOrDefault(value => Same(value.DistinguishedName, request.TargetDn));
        var user = attributes(request.RequesterDn);
        var resource = attributes(request.TargetDn);
        if (inputs.Availability != PathInputAvailability.Recorded)
            return Unknown(RequesterDaclIssue.PathInputsUnavailable);
        if (user is null) return Unknown(RequesterDaclIssue.RequesterMissing);
        if (!RequesterTrusteeReading.HasClass(user, "user") || RequesterTrusteeReading.HasClass(user, "computer"))
            return Unknown(RequesterDaclIssue.RequesterNotUser);
        if (target is null) return Unknown(RequesterDaclIssue.TargetNotFixed);
        if (requester is null || resource is null || !Qualified(user, requester) || requester.Sid is null || !Qualified(resource, target))
            return Unknown(RequesterDaclIssue.IdentityUnresolved);
        if (!Domain(requester) || !Domain(target) || !Same(requester.DomainFqdn, target.DomainFqdn))
            return Unknown(RequesterDaclIssue.ResourceContextUnsupported);
        var obtainedGroup = obtainedMembership?.Target;
        var group = obtainedGroup is null ? null : attributes(obtainedGroup.DistinguishedName);
        if (obtainedMembership is not null && (obtainedMembership.Obtainability != ControlEvaluationState.Established
            || obtainedMembership.Requester != requester || obtainedGroup is null || !Qualified(group, obtainedGroup)
            || !Domain(obtainedGroup) || !Same(obtainedGroup.NamingContext, requester.NamingContext)
            || !Same(target.NamingContext, requester.NamingContext)
            || obtainedMembership.GenerationId != description.GenerationId
            || obtainedMembership.DerivationGenerationId != description.DerivationGenerationId
            || obtainedMembership.EvidenceSeal != description.EvidenceSeal))
            return Unknown(RequesterDaclIssue.MembershipContextUnsupported);
        if (permissions is null || permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
            return Unknown(RequesterDaclIssue.DescriptorUnreadable);
        // NULL DACL access has no explicit user/group grant to witness in this slice.
        if (permissions.DaclState == DaclState.Null) return Unknown(RequesterDaclIssue.GrantRouteUnsupported);
        var possibleAllow = permissions.DaclCompleteness != DaclCompleteness.Complete;
        var possibleDeny = possibleAllow;
        if (possibleAllow) issues.Add(RequesterDaclIssue.DescriptorIncomplete);
        foreach (var entry in permissions.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if ((entry.AccessMask & WriteDacl) == 0 || EntryReachReader.FromPropagationFlags(entry.PropagationFlags) != EntryReach.ThisObject)
                continue;
            var holder = entry.Trustee.DistinguishedName is { } dn ? attributes(dn) : null;
            var trustee = RequesterTrusteeReading.Read(user, resource, entry.Trustee, holder, forest);
            if (entry.Trustee.Sid == "S-1-5-10") holder = resource;
            RequesterMembershipEvidence? membership = null;
            if (memberships is not null && holder is not null
                && trustee.Reason == RequesterTrusteeReason.MembershipNotEstablished
                && Qualified(holder, identities.GetValueOrDefault(holder.DistinguishedName))
                && Domain(identities[holder.DistinguishedName]))
            {
                membership = memberships.Read(request.RequesterDn, holder.DistinguishedName);
                if (membership.Links.Count > 1)
                    trustee = trustee with { State = RequesterTrusteeState.Matches, Reason = RequesterTrusteeReason.NestedGlobalMembership };
            }
            if (obtainedMembership?.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd)
            {
                var sid = entry.Trustee.Sid == "S-1-5-10" ? target.Sid : entry.Trustee.Sid;
                if (Same(sid, obtainedGroup!.Sid))
                {
                    holder = group;
                    membership = null;
                    trustee = new(entry.Trustee.Sid, RequesterTrusteeState.Matches, RequesterTrusteeReason.ObtainedGlobalMembership,
                        obtainedGroup.ObjectGuid, obtainedGroup.DistinguishedName, obtainedGroup.DomainFqdn,
                        RequesterTrusteeReading.Number(group, "groupType"), group!.CapturedUtc, null);
                }
                else if (trustee.Reason is RequesterTrusteeReason.OtherCurrentUser or RequesterTrusteeReason.DistributionGroup)
                {
                    // The added group's carried identities are outside this bounded model. A current
                    // nonmatching identity cannot exclude a historical SID introduced by that group.
                    trustee = trustee with { State = RequesterTrusteeState.Unknown, Reason = RequesterTrusteeReason.UnsupportedIdentity };
                }
            }
            RequesterMembershipEvidence? obtainedNesting = null;
            if (obtainedMembership is not null && memberships is not null && holder is not null
                && trustee.Reason is RequesterTrusteeReason.MembershipNotEstablished or RequesterTrusteeReason.NestedGlobalMembership
                    or RequesterTrusteeReason.DirectGlobalMembership
                && Qualified(holder, identities.GetValueOrDefault(holder.DistinguishedName))
                && Domain(identities[holder.DistinguishedName])
                && (obtainedMembership.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd
                    || obtainedMembership.MembershipEvidence.Any(value => value.Attribute == "member"
                        && value.Object == obtainedGroup && Same(value.Value, requester.DistinguishedName))))
            {
                obtainedNesting = memberships.Read(obtainedGroup!.DistinguishedName, holder.DistinguishedName);
                if (obtainedNesting.Links.Count != 0)
                {
                    membership = null;
                    trustee = trustee with { State = RequesterTrusteeState.Matches, Reason =
                        obtainedMembership.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd
                            ? RequesterTrusteeReason.ObtainedGlobalMembership : RequesterTrusteeReason.NestedGlobalMembership };
                }
                else obtainedNesting = null;
            }
            if (trustee.Reason == RequesterTrusteeReason.DirectGlobalMembership
                && (holder is null || !Qualified(holder, identities.GetValueOrDefault(holder.DistinguishedName))
                    || !Domain(identities[holder.DistinguishedName])))
                trustee = trustee with { State = RequesterTrusteeState.Unknown, Reason = RequesterTrusteeReason.IdentityMissing };
            var scope = entry.HasObjectType ? ControlEvaluationState.Unknown : ControlEvaluationState.Established;
            evidence.Add(new(entry, scope, trustee) { Membership = membership, ObtainedGroupMembership = obtainedNesting });
            if (trustee.State == RequesterTrusteeState.DoesNotMatch) continue;
            var allow = entry.AceType is "AccessAllowed" or "AccessAllowedObject";
            var deny = entry.AceType is "AccessDenied" or "AccessDeniedObject";
            if (!allow && !deny) issues.Add(RequesterDaclIssue.UnsupportedAce);
            if (scope == ControlEvaluationState.Unknown) issues.Add(RequesterDaclIssue.ScopeUnsupported);
            if (trustee.State == RequesterTrusteeState.Unknown) issues.Add(RequesterDaclIssue.TrusteeUnknown);
            var grantRoute = trustee.Reason is RequesterTrusteeReason.DirectIdentity or RequesterTrusteeReason.DirectGlobalMembership
                or RequesterTrusteeReason.ObtainedGlobalMembership or RequesterTrusteeReason.NestedGlobalMembership;
            if (allow && !grantRoute) issues.Add(RequesterDaclIssue.GrantRouteUnsupported);
            possibleAllow |= !deny;
            possibleDeny |= !allow;
            if ((deny || allow && grantRoute) && scope == ControlEvaluationState.Established
                && trustee.State == RequesterTrusteeState.Matches)
                return Finish(possibleAllow ? possibleDeny ? ControlEvaluationState.Unknown : ControlEvaluationState.Established
                    : ControlEvaluationState.NotEstablished, allow ? entry : null, trustee, holder);
        }
        return Finish(possibleAllow ? ControlEvaluationState.Unknown : ControlEvaluationState.NotEstablished, null, null, null);

        RequesterDaclAssessment Unknown(RequesterDaclIssue issue)
        {
            issues.Add(issue);
            return Result(ControlEvaluationState.Unknown, [], []);
        }

        RequesterDaclAssessment Result(ControlEvaluationState state, IReadOnlyList<RequesterDaclPermission> references,
            IReadOnlyList<Tier0PathStep> steps) => new(request, description.GenerationId, description.DerivationGenerationId,
                description.EvidenceSeal, requester, target, state, issues.Distinct().Order().ToArray(), evidence, references, steps)
                { ObtainedMembership = obtainedMembership?.Request };

        RequesterDaclAssessment Finish(ControlEvaluationState state, PermissionEntry? grant,
            RequesterTrusteeEvidence? route, ObjectAttributes? holder)
        {
            if (state != ControlEvaluationState.Established) return Result(state, [], []);
            var resolvedSid = grant!.Trustee.Sid == "S-1-5-10" ? target!.Sid : grant.Trustee.Sid;
            var nesting = evidence[^1].ObtainedGroupMembership;
            if (obtainedMembership is not null && !Same(resolvedSid, obtainedGroup!.Sid) && nesting is null)
                return Unknown(RequesterDaclIssue.GrantNotHeldByObtainedGroup);
            var edge = edges.Where(value => value.Capability == ControlCapability.CanWriteDacl
                && Same(value.Target, target!.DistinguishedName) && value.TargetGuid == target.ObjectGuid
                && value.GenerationId == description.GenerationId && value.DerivationGenerationId == description.DerivationGenerationId
                && Same(value.HolderSid, resolvedSid) && value.HolderScope is null
                && value.Evidence.Any(original => Tier0PathCalculation.Fingerprint(original) == Tier0PathCalculation.Fingerprint(grant)))
                .OrderBy(value => value.Id).FirstOrDefault();
            if (edge is null) return Unknown(RequesterDaclIssue.PermissionReferenceUnavailable);
            var steps = new List<Tier0PathStep>();
            var from = requester!;
            if (nesting is not null)
            {
                steps.Add(OwnAccountMembershipProofs.InitialStep(obtainedMembership!));
                foreach (var link in nesting.Links)
                    steps.Add(new(link.Member, link.Group, Tier0PathStepKind.Membership, null, null, link.Witness, null)
                        { RequesterRequest = request });
                from = nesting.Links[^1].Group;
            }
            else if (route!.Reason == RequesterTrusteeReason.DirectGlobalMembership)
            {
                var membership = holder?.Find("member")?.Values.FirstOrDefault(value => Same(value.Text, requester!.DistinguishedName));
                if (holder is null || membership is null) return Unknown(RequesterDaclIssue.IdentityUnresolved);
                from = identities[holder.DistinguishedName];
                steps.Add(new(requester!, from, Tier0PathStepKind.Membership, null, null,
                    new Tier0Evidence(from, "member", membership.Ordinal, requester!.DistinguishedName), null) { RequesterRequest = request });
            }
            else if (route.Reason == RequesterTrusteeReason.NestedGlobalMembership)
            {
                var membership = evidence[^1].Membership ?? throw Tier0PathStorage.InvalidProof();
                foreach (var link in membership.Links)
                    steps.Add(new(link.Member, link.Group, Tier0PathStepKind.Membership, null, null, link.Witness, null)
                        { RequesterRequest = request });
                from = membership.Links[^1].Group;
            }
            else if (route.Reason == RequesterTrusteeReason.ObtainedGlobalMembership)
            {
                from = obtainedGroup!;
                steps.Add(new(requester!, from, Tier0PathStepKind.OwnAccountMembership, null, null, null,
                    obtainedMembership!.Permissions.Single().Id) { OwnAccountRequest = obtainedMembership.Request });
            }
            steps.Add(new(from, target!, Tier0PathStepKind.WriteDacl, null, null, null, edge.Id) { RequesterRequest = request });
            return Result(state, [new(edge.Id, Tier0PathCalculation.Fingerprint(edge))], steps);
        }

        bool Qualified(ObjectAttributes? value, Tier0Target? identity) => memberships is not null
            ? memberships.Qualified(value, identity) : value is not null && identity is { ObjectGuid: not null }
            && identity.IsValid && Tier0Target.From(value, identity.NamingContext) == identity
            && !RequesterTrusteeReading.HasClass(value, "foreignSecurityPrincipal")
            && !Same(value.Find("isDeleted")?.OnlyValue?.Text, "TRUE")
            && (identity.Sid is null || identities.Values.Count(other => Same(other.Sid, identity.Sid)
                && Same(other.SidScope, identity.SidScope)) == 1);

        bool Domain(Tier0Target value) => contexts.TryGetValue(value.NamingContext, out var kind) && kind == NamingContextKind.Domain
            && !string.IsNullOrWhiteSpace(value.DomainFqdn)
            && Same(SecureAD.Kernel.Naming.DnHelper.DnToFqdn(value.NamingContext), value.DomainFqdn);
    }

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
