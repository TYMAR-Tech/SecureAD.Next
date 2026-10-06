using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>The permission route requested for an own-account membership operation.</summary>
public enum OwnAccountMembershipPermissionKind
{
    /// <summary>The fixed Self-Membership validated write; ordinary member write is not substituted.</summary>
    SelfMembership,
    /// <summary>Ordinary write access to member; the operation still adds only the requester's own DN.</summary>
    WriteMembers,
}

/// <summary>An explicit offline question about obtaining membership with the requester's own account.</summary>
public sealed record OwnAccountMembershipRequest(string RequesterDn, string TargetDn)
{
    /// <summary>The separate permission proof to evaluate; no automatic requester discovery is implied.</summary>
    public OwnAccountMembershipPermissionKind PermissionKind { get; init; }
}

/// <summary>The proof used, not a claim that a directory modification was performed.</summary>
public enum OwnAccountMembershipBasis
{
    /// <summary>No supported membership outcome was established.</summary>
    Unresolved,
    /// <summary>A qualified captured membership already supplies the relationship.</summary>
    ExistingMembership,
    /// <summary>Membership is obtainable in both the already-present and authorized-absent-add cases.</summary>
    ExistingOrAuthorizedAdd,
}

/// <summary>Operation limitations, separate from the original permission and ordinary Add-readiness answers.</summary>
public enum OwnAccountMembershipIssue
{
    /// <summary>The path input product was not available.</summary>
    PathInputsUnavailable,
    /// <summary>A required captured requester or target was not available.</summary>
    ObjectMissing,
    /// <summary>A captured identity cannot be uniquely qualified.</summary>
    IdentityUnresolved,
    /// <summary>The requester is outside the ordinary user model.</summary>
    RequesterUnsupported,
    /// <summary>A required group-type value was not captured.</summary>
    GroupTypeMissing,
    /// <summary>The target is not a same-domain global security group.</summary>
    GroupScopeUnsupported,
    /// <summary>The resource cannot be tied to the same verified domain as the requester.</summary>
    ResourceContextUnsupported,
    /// <summary>The original permission calculation did not establish authorization.</summary>
    AuthorizationNotEstablished,
    /// <summary>The authorization lacks the supported direct-user or pre-existing single-global-group grant.</summary>
    GrantRouteUnsupported,
    /// <summary>The captured account status cannot support the operation.</summary>
    AccountStatusMissing,
    /// <summary>The account is disabled; permission evidence is retained.</summary>
    AccountDisabled,
    /// <summary>The captured primary-group identity was not available.</summary>
    PrimaryGroupMissing,
    /// <summary>Required operation-specific schema evidence was not captured.</summary>
    SchemaEvidenceMissing,
    /// <summary>The captured schema needs interpretation outside the supported base-schema operation.</summary>
    SchemaUnsupported,
    /// <summary>The permission cannot be tied to its original saved holder edge.</summary>
    PermissionReferenceUnavailable,
    /// <summary>No qualified existing-membership continuation to a fixed target was established.</summary>
    MembershipContinuationUnresolved,
}

/// <summary>An unchanged named-holder permission supporting this separate operation assessment.</summary>
public sealed record OwnAccountMembershipPermission(long Id, string Fingerprint);

/// <summary>
/// A saved membership-obtainability proof, not an authentication or LDAP-success prediction.
/// The original permission assessment retains Unknown current membership and ordinary Add readiness.
/// </summary>
public sealed record OwnAccountMembershipAssessment(OwnAccountMembershipRequest Request, Guid GenerationId,
    Guid? DerivationGenerationId, string EvidenceSeal, Tier0Target? Requester, Tier0Target? Target,
    SelfMembershipAssessment Permission, ControlEvaluationState Obtainability, OwnAccountMembershipBasis Basis,
    IReadOnlyList<OwnAccountMembershipIssue> Issues, IReadOnlyList<Tier0Evidence> MembershipEvidence,
    IReadOnlyList<ObjectAttributes> SchemaEvidence, IReadOnlyList<OwnAccountMembershipPermission> Permissions)
{
    /// <summary>The supported static-directory operation context; never an observed session or write.</summary>
    public const string Context = "Ordinary authenticated directory user on a writable AD DS domain replica; own-DN member value only; same-domain global security group and captured base-schema evidence. No live authentication, replication-convergence or LDAP-success prediction.";

    /// <summary>The captured account, group and domain values used by the operation check.</summary>
    public IReadOnlyList<Tier0Evidence> OperationEvidence { get; init; } = [];

    /// <summary>Ordinary member-write proof when requested, never a relabeled Self-Membership answer.</summary>
    public MemberWriteAssessment? MemberWrite { get; init; }

    /// <summary>The operation answer that vouches its evidence, not a negative reachability verdict.</summary>
    public string Verdict => Obtainability.ToString();
}

internal static class OwnAccountMembershipEvaluator
{
    internal static OwnAccountMembershipAssessment Assess(OwnAccountMembershipRequest request, PathInputs inputs,
        JudgementDescription description, IReadOnlyDictionary<string, Tier0Target> identities,
        Func<string, ObjectAttributes?> attributes, ObjectPermissions? permissions,
        IReadOnlyList<ObjectAttributes> schema, SchemaGuidCatalog catalogue, IReadOnlyDictionary<string, NamingContextKind> contexts,
        IReadOnlyList<ControlEdge> edges, string forest, CancellationToken cancellationToken, RequesterMembershipContext? memberships)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var requester = identities.GetValueOrDefault(request.RequesterDn);
        var target = identities.GetValueOrDefault(request.TargetDn);
        var user = attributes(request.RequesterDn);
        var group = attributes(request.TargetDn);
        var issues = new List<OwnAccountMembershipIssue>();
        var permission = SelfMembershipEvaluator.Assess(new(request.RequesterDn, request.TargetDn, SelfMembershipOperation.Add, null),
            user, group, user, permissions, trustee => trustee.DistinguishedName is { } dn
                && Qualified(attributes(dn), identities.GetValueOrDefault(dn)) && Domain(identities[dn]) ? attributes(dn) : null,
            forest, description.EvidenceSeal, description.GenerationId, description.DerivationGenerationId,
            SelfMembershipBudget.Default, []);
        MemberWriteAssessment? memberWrite = request.PermissionKind == OwnAccountMembershipPermissionKind.WriteMembers
            ? new(ControlEvaluationState.Unknown, permission.Readiness, permission.MemberPresent, [MemberWriteIssue.ContextNotEstablished], []) : null;
        if (inputs.Availability != PathInputAvailability.Recorded) return Unknown(OwnAccountMembershipIssue.PathInputsUnavailable);
        if (user is null || group is null) return Unknown(OwnAccountMembershipIssue.ObjectMissing);
        if (!Qualified(user, requester) || !Qualified(group, target)) return Unknown(OwnAccountMembershipIssue.IdentityUnresolved);
        if (!RequesterTrusteeReading.HasClass(user, "user") || user.Find("objectClass")!.Values.Any(value =>
            value.Text is not ("top" or "person" or "organizationalPerson" or "user")))
            return Unknown(OwnAccountMembershipIssue.RequesterUnsupported);
        if (!RequesterTrusteeReading.HasClass(group, "group")) return Unknown(OwnAccountMembershipIssue.GroupScopeUnsupported);
        var groupType = RequesterTrusteeReading.Number(group, "groupType");
        if (groupType is null) return Unknown(OwnAccountMembershipIssue.GroupTypeMissing);
        if (groupType is not (-2147483646L or 2147483650L)
            || group.Find("objectClass")!.Values.Any(value => value.Text is not ("top" or "group")))
            return Unknown(OwnAccountMembershipIssue.GroupScopeUnsupported);
        if (requester is null || target is null || !Domain(requester) || !Domain(target)
            || !Same(requester.NamingContext, target.NamingContext)) return Unknown(OwnAccountMembershipIssue.ResourceContextUnsupported);

        if (request.PermissionKind == OwnAccountMembershipPermissionKind.WriteMembers)
            memberWrite = MemberWriteEvaluator.Assess(user, group, permissions, trustee => trustee.DistinguishedName is { } dn
                && Qualified(attributes(dn), identities.GetValueOrDefault(dn)) && Domain(identities[dn]) ? attributes(dn) : null,
                forest, catalogue, permission.Readiness, permission.MemberPresent, cancellationToken);

        var current = new List<Tier0Evidence>();
        var member = group.Find("member")?.Values.FirstOrDefault(value => Same(value.Text, user.DistinguishedName));
        if (member is not null) current.Add(new(target, "member", member.Ordinal, user.DistinguishedName));
        var memberOf = user.Find("memberOf")?.Values.FirstOrDefault(value => Same(value.Text, group.DistinguishedName));
        if (memberOf is not null) current.Add(new(requester, "memberOf", memberOf.Ordinal, group.DistinguishedName));
        var primary = RequesterTrusteeReading.Number(user, "primaryGroupID");
        if (primary is > 0 and <= uint.MaxValue && Same(target.Sid, Sid.IssuingDomain(requester.Sid!) + "-"
            + primary.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)))
            current.Add(new(requester, "primaryGroupID", 0, primary.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        if (current.Count != 0) return Result(ControlEvaluationState.Established, OwnAccountMembershipBasis.ExistingMembership, current, []);

        // Self-Membership validates the requester's DN; ordinary Write Members is a separate
        // authorization route to the same bounded own-DN operation, not a validated-write grant.
        // Neither an omitted member value nor the hypothetical added membership may authorize this check.
        var authorization = memberWrite?.Authorization ?? permission.Authorization;
        if (authorization != ControlEvaluationState.Established || permission.OwnAccount != ControlEvaluationState.Established)
            return Unknown(OwnAccountMembershipIssue.AuthorizationNotEstablished);
        var grantEntry = memberWrite is not null ? memberWrite.Evidence.LastOrDefault()?.Entry : permission.Evidence.LastOrDefault()?.Entry;
        var grantTrustee = memberWrite is not null ? memberWrite.Evidence.LastOrDefault()?.Trustee : permission.Evidence.LastOrDefault()?.Trustee;
        if (grantEntry is null || grantTrustee is null || grantTrustee.Reason is not (RequesterTrusteeReason.DirectIdentity or RequesterTrusteeReason.DirectGlobalMembership))
            return Unknown(OwnAccountMembershipIssue.GrantRouteUnsupported);
        if (grantTrustee.Reason == RequesterTrusteeReason.DirectGlobalMembership
            && (grantTrustee.HolderDn is not { } holderDn || !identities.TryGetValue(holderDn, out var holder)
                || !Domain(holder) || !Same(holder.NamingContext, requester.NamingContext)))
            return Unknown(OwnAccountMembershipIssue.ResourceContextUnsupported);
        if (permission.UserAccountControl is not { } uac) return Unknown(OwnAccountMembershipIssue.AccountStatusMissing);
        if ((uac & 2) != 0)
        {
            issues.Add(OwnAccountMembershipIssue.AccountDisabled);
            return Result(ControlEvaluationState.NotEstablished, OwnAccountMembershipBasis.Unresolved, [], []);
        }
        if ((uac & 0x3A00) != 0x200) return Unknown(OwnAccountMembershipIssue.RequesterUnsupported);
        if (primary is null or <= 0 or > uint.MaxValue) return Unknown(OwnAccountMembershipIssue.PrimaryGroupMissing);

        foreach (var name in new[] { "user", "group", "member" })
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidates = schema.Where(value => Same(value.Find("lDAPDisplayName")?.OnlyValue?.Text, name)).ToArray();
            if (candidates.Length == 0) return Unknown(OwnAccountMembershipIssue.SchemaEvidenceMissing);
            var definition = candidates[0];
            if (definition.Find("schemaIDGUID")?.HasValue != true || definition.Find("systemFlags")?.HasValue != true
                || name == "member" && (definition.Find("isSingleValued")?.HasValue != true || definition.Find("searchFlags")?.HasValue != true))
                return Unknown(OwnAccountMembershipIssue.SchemaEvidenceMissing);
            if (candidates.Length != 1 || !identities.TryGetValue(definition.DistinguishedName, out var identity)
                || !contexts.TryGetValue(identity.NamingContext, out var kind) || kind != NamingContextKind.Schema
                || !QualifiedSchema(definition, name)) return Unknown(OwnAccountMembershipIssue.SchemaUnsupported);
        }

        var sid = grantEntry.Trustee.Sid == "S-1-5-10" ? target.Sid : grantEntry.Trustee.Sid;
        var capability = memberWrite is not null ? ControlCapability.CanModifyGroupMembership : ControlCapability.CanAddSelfToGroup;
        var edge = edges.Where(value => value.Capability == capability
            && Same(value.Target, target.DistinguishedName) && value.TargetGuid == target.ObjectGuid
            && value.GenerationId == description.GenerationId && value.DerivationGenerationId == description.DerivationGenerationId
            && Same(value.HolderSid, sid) && value.HolderScope is null
            && value.Evidence.Any(original => Tier0PathCalculation.Fingerprint(original) == Tier0PathCalculation.Fingerprint(grantEntry)))
            .OrderBy(value => value.Id).FirstOrDefault();
        if (edge is null) return Unknown(OwnAccountMembershipIssue.PermissionReferenceUnavailable);

        // The two cases prove the membership outcome, NOT absence, a successful ordinary Add,
        // or a completed live operation. MS-ADTS 3.1.1.5.3.2 rejects duplicate ordinary adds.
        return Result(ControlEvaluationState.Established, OwnAccountMembershipBasis.ExistingOrAuthorizedAdd, [],
            [new(edge.Id, Tier0PathCalculation.Fingerprint(edge))]);

        OwnAccountMembershipAssessment Unknown(OwnAccountMembershipIssue issue)
        {
            issues.Add(issue);
            return Result(ControlEvaluationState.Unknown, OwnAccountMembershipBasis.Unresolved, [], []);
        }

        OwnAccountMembershipAssessment Result(ControlEvaluationState state, OwnAccountMembershipBasis basis,
            IReadOnlyList<Tier0Evidence> membership, IReadOnlyList<OwnAccountMembershipPermission> references) =>
            new(request, description.GenerationId, description.DerivationGenerationId, description.EvidenceSeal,
                requester, target, permission, state, basis, issues.Distinct().Order().ToArray(), membership, schema, references)
            { OperationEvidence = Witnesses(), MemberWrite = memberWrite };

        IReadOnlyList<Tier0Evidence> Witnesses()
        {
            var result = new List<Tier0Evidence>();
            foreach (var (value, identity, names) in new[]
            {
                (user, requester, new[] { "objectClass", "userAccountControl", "primaryGroupID" }),
                (group, target, new[] { "objectClass", "groupType" }),
            })
            {
                if (value is null || identity is null) continue;
                foreach (var name in names)
                    foreach (var item in value.Find(name)?.Values ?? [])
                        result.Add(new(identity, name, item.Ordinal, item.Stored));
            }
            if (target is not null && identities.TryGetValue(target.NamingContext, out var root) && root.Sid is not null)
                result.Add(new(root, "objectSid", 0, root.Sid));
            return result;
        }

        bool Qualified(ObjectAttributes? value, Tier0Target? identity) => memberships is not null
            ? identity?.Sid is not null && memberships.Qualified(value, identity)
            : value is not null && identity is { ObjectGuid: not null, Sid: not null }
            && identity.IsValid && Tier0Target.From(value, identity.NamingContext) == identity
            && !RequesterTrusteeReading.HasClass(value, "foreignSecurityPrincipal")
            && !Same(value.Find("isDeleted")?.OnlyValue?.Text, "TRUE")
            && identities.Values.Count(other => Same(other.Sid, identity.Sid) && Same(other.SidScope, identity.SidScope)) == 1;

        bool Domain(Tier0Target identity) => contexts.TryGetValue(identity.NamingContext, out var kind) && kind == NamingContextKind.Domain
            && !string.IsNullOrWhiteSpace(identity.DomainFqdn) && Same(DnHelper.DnToFqdn(identity.NamingContext), identity.DomainFqdn)
            && identities.TryGetValue(identity.NamingContext, out var root) && root.Sid is not null
            && Same(Sid.IssuingDomain(identity.Sid!), root.Sid);
    }

    private static bool QualifiedSchema(ObjectAttributes value, string name)
    {
        var bytes = value.Find("schemaIDGUID")?.OnlyValue?.Bytes;
        if (value.ObjectGuid is null || bytes is not { Length: 16 }
            || !Same(new Guid(bytes).ToString("D"), SchemaGuidCatalog.Embedded.GuidFor(name))
            || RequesterTrusteeReading.Number(value, "systemFlags") is not { } flags || (flags & 0x10) == 0)
            return false;
        if (name != "member") return RequesterTrusteeReading.HasClass(value, "classSchema");
        // MS-ADTS 3.1.1.2.3: the base member syntax/link/cardinality are system-only;
        // rangeLower/rangeUpper do not constrain Object(DS-DN). Mutable partition-secret flags
        // do require additional write checks, so missing flags and that unsupported case stay unknown.
        return RequesterTrusteeReading.HasClass(value, "attributeSchema")
            && Same(value.Find("isSingleValued")?.OnlyValue?.Text, "FALSE")
            && (flags & 0x05) == 0 && RequesterTrusteeReading.Number(value, "searchFlags") is >= 0 and <= 0x0FFF;
    }

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
