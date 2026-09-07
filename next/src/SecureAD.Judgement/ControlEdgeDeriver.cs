using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class ControlEdgeDeriver
{
    private const int WriteDacl = 0x40000;
    private const int WriteOwner = 0x80000;
    private const int ControlAccess = 0x100;

    public static ControlObjectEvaluation Derive(ObjectAttributes subject, ObjectPermissions? permissions,
        JudgingContext context, Guid generation, Guid? derivationGeneration, Func<string, string?> domainSid)
    {
        var sidValue = subject.Find("objectSid")?.OnlyValue;
        var targetSid = sidValue?.Bytes is { } bytes ? Sid.ToText(bytes) : sidValue?.Text;
        var targetScope = targetSid is not null && Sid.IsBuiltinDomain(targetSid) ? subject.DomainFqdn : null;
        if (permissions is null)
            return new(subject.DistinguishedName, targetSid, targetScope, "DescriptorNotRead", ControlUncertainty.DescriptorUnreadable, []);

        // Resolve SELF for this target only. Preserve the original ACEs as evidence below.
        var normalized = permissions with
        {
            Entries = permissions.Entries.Select(entry => entry.Trustee.Sid == "S-1-5-10" && targetSid is not null
                ? entry with { Trustee = entry.Trustee with { Sid = targetSid, Name = subject.DistinguishedName,
                    DistinguishedName = subject.DistinguishedName, DomainFqdn = subject.DomainFqdn, WellKnownRole = null } }
                : entry).ToArray(),
        };
        var effective = EffectiveAccessCalculator.Over(normalized with
        {
            Entries = normalized.Entries.Where(entry => IsSupported(entry.AceType)).ToArray(),
        }, objectTypeGuid: null);
        var uncertainty = effective.Outcome is EffectiveAccessOutcome.DescriptorNotRead or EffectiveAccessOutcome.EntriesUnparsed
            ? ControlUncertainty.DescriptorUnreadable
            : permissions.DaclCompleteness != DaclCompleteness.Complete ? ControlUncertainty.DescriptorIncomplete : ControlUncertainty.None;
        if ((uncertainty & ControlUncertainty.DescriptorUnreadable) != 0)
            return new(subject.DistinguishedName, targetSid, targetScope, effective.Outcome.ToString(), uncertainty, []);

        var candidates = normalized.Entries.Where(Applies).Select(entry => entry.Trustee)
            .Where(trustee => trustee.Sid != "S-1-3-4")
            .DistinctBy(trustee => trustee.Sid, StringComparer.OrdinalIgnoreCase).ToList();
        if (effective.Outcome == EffectiveAccessOutcome.GrantsEveryoneEverything)
            candidates = [new PermissionTrustee("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null)];
        var edges = new List<ControlEdge>();
        foreach (var trustee in candidates.OrderBy(t => t.Sid, StringComparer.Ordinal))
        {
            var mask = effective.Outcome == EffectiveAccessOutcome.GrantsEveryoneEverything ? WriteDacl | WriteOwner
                : effective.Holders.FirstOrDefault(holder => Same(holder.Trustee.Sid, trustee.Sid))?.Mask ?? 0;
            var holderScope = Sid.IsBuiltinDomain(trustee.Sid) ? subject.DomainFqdn : null;
            var routes = context.ProtectedPrincipals?.Lookup(trustee.Sid, holderScope)?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
            foreach (var (right, capability) in new[] { (WriteDacl, ControlCapability.CanWriteDacl), (WriteOwner, ControlCapability.CanSetOwner) })
            {
                var relevant = normalized.Entries.Where(entry => Applies(entry) && (entry.AccessMask & right) != 0).ToArray();
                var unknown = uncertainty;
                if (relevant.Any(entry => entry.HasObjectType && (Same(entry.Trustee.Sid, trustee.Sid)
                    || entry.AceType.Contains("Denied", StringComparison.Ordinal)))) unknown |= ControlUncertainty.ObjectSpecificScopeNotEvaluated;
                if (relevant.Any(entry => !IsSupported(entry.AceType))) unknown |= ControlUncertainty.ConditionalOrUnsupportedAce;
                if (relevant.Any(entry => entry.AceType.Contains("Denied", StringComparison.Ordinal)
                    && !Same(entry.Trustee.Sid, trustee.Sid))) unknown |= ControlUncertainty.CrossTrusteeDeny;
                if (!trustee.HoldsThePermission) unknown |= ControlUncertainty.HolderIsPlaceholder;
                var classification = PrincipalClassificationRegistry.For(trustee.Sid);
                if (!classification.IdentityIsValid || trustee.DistinguishedName is null && classification.MicrosoftName is null)
                    unknown |= ControlUncertainty.HolderUnresolved;
                // P-90: the capturing controller's domain is not a proven resource context for a non-domain NC.
                if (Sid.IsBuiltinDomain(trustee.Sid) && !IsDomainTarget(subject, context.ForestFqdn))
                    unknown |= ControlUncertainty.ResourceContextUnverified;
                var granted = (mask & right) != 0;
                var possibleGrant = relevant.Any(entry => Same(entry.Trustee.Sid, trustee.Sid)
                    && !entry.AceType.Contains("Denied", StringComparison.Ordinal));
                if (!granted && !(possibleGrant && unknown != ControlUncertainty.None)) continue;
                var evaluation = unknown == ControlUncertainty.None ? ControlEvaluationState.Established : ControlEvaluationState.Unknown;
                var expected = Expected(trustee, subject, context.ForestFqdn, routes, permissions.DaclCompleteness == DaclCompleteness.Complete,
                    effective.Outcome != EffectiveAccessOutcome.GrantsEveryoneEverything && evaluation == ControlEvaluationState.Established && granted, domainSid);
                var evidence = permissions.Entries.Where(entry => Applies(entry) && (entry.AccessMask & right) != 0).ToArray();
                var edge = new ControlEdge(0, subject.ObjectGuid, subject.DistinguishedName,
                    subject.Find("objectClass")?.Values.LastOrDefault()?.Text, trustee.Sid, trustee.Name, holderScope,
                    capability, evaluation, unknown, expected.State, expected.Reason, PrincipalClassificationRegistry.Version,
                    generation, derivationGeneration, true, evidence, [], routes) { DescriptorOutcome = effective.Outcome.ToString() };
                edges.Add(edge);
                if (capability == ControlCapability.CanSetOwner)
                    edges.Add(edge with
                    {
                        Capability = ControlCapability.CanBecomeOwnerAndRewriteDacl,
                        EvaluationState = ControlEvaluationState.Unknown,
                        Expectedness = Same(trustee.Sid, "S-1-5-18") ? ControlExpectedness.Unknown : edge.Expectedness,
                        ExpectednessReason = Same(trustee.Sid, "S-1-5-18") ? ControlExpectednessReason.UnknownCapabilityScope : edge.ExpectednessReason,
                        Uncertainty = unknown | ControlUncertainty.OwnerTransitionLabRequired | ControlUncertainty.OwnerRightsOperationNotEvaluated,
                        IsCounted = false,
                        Preconditions = [new("CanSetOwner", evaluation, "MS-ADTS-5.1.3.3.2;stored descriptor"),
                            new("CanSetTakeoverOwnerSid", ControlEvaluationState.Unknown, "0103;SPEC-stage-6 section 13.1 laboratory gate"),
                            new("OwnerWouldReceiveWriteDacl", ControlEvaluationState.Unknown, "Specific owner/modification evaluation not yet implemented")],
                    });
            }
        }
        uncertainty |= AddScopedEdges(subject, permissions, normalized, context, generation, derivationGeneration,
            domainSid, effective.Outcome, uncertainty, edges);
        return new(subject.DistinguishedName, targetSid, targetScope, effective.Outcome.ToString(), uncertainty, edges);
    }

    private static ControlUncertainty AddScopedEdges(ObjectAttributes subject, ObjectPermissions original,
        ObjectPermissions normalized, JudgingContext context, Guid generation, Guid? derivationGeneration,
        Func<string, string?> domainSid, EffectiveAccessOutcome outcome, ControlUncertainty descriptorUncertainty,
        List<ControlEdge> edges)
    {
        var classes = subject.Find("objectClass")?.Values;
        var isGroup = classes?.Any(value => Same(value.Text, "group")) == true;
        var isAccount = classes?.Any(value => Same(value.Text, "user") || Same(value.Text, "computer")
            || Same(value.Text, "inetOrgPerson") || Same(value.Text, "msDS-ManagedServiceAccount")
            || Same(value.Text, "msDS-GroupManagedServiceAccount")) == true;
        var classKnown = classes?.Any(value => !string.IsNullOrWhiteSpace(value.Text)) == true;
        var targetUncertainty = classKnown ? ControlUncertainty.None : ControlUncertainty.TargetClassNotRead;
        var catalogue = context.SchemaGuids ?? SchemaGuidCatalog.Embedded;
        foreach (var (right, capability, operation) in new[] { (0x20, ControlCapability.CanModifyGroupMembership, "member"),
            (0x08, ControlCapability.CanAddSelfToGroup, "Self-Membership"),
            (ControlAccess, ControlCapability.CanResetPassword, "User-Force-Change-Password"),
            (0x20, ControlCapability.CanWriteKeyCredentialLink, "msDS-KeyCredentialLink") })
        {
            var accountOperation = capability is ControlCapability.CanResetPassword or ControlCapability.CanWriteKeyCredentialLink;
            if (classKnown && !(accountOperation ? isAccount : isGroup)) continue;
            var relevant = normalized.Entries.Select((entry, index) => (Entry: entry, Original: original.Entries[index],
                    Scope: OperationScope(entry, right, operation, classes?.LastOrDefault()?.Text, catalogue)))
                .Where(item => Applies(item.Entry) && (item.Entry.AccessMask & right) != 0
                    && item.Scope.State != ControlEvaluationState.NotEstablished).ToArray();
            // Project one operation, preserving DACL order. Never union separately evaluated property sets:
            // that would let a broad allow escape a member-specific deny (or the reverse).
            var effective = EffectiveAccessCalculator.Over(normalized with
            {
                Entries = relevant.Where(item => item.Scope.State == ControlEvaluationState.Established && IsSupported(item.Entry.AceType))
                    .Select(item => item.Entry with { HasObjectType = false, ObjectTypeGuid = null }).ToArray(),
            }, objectTypeGuid: null);
            var trustees = relevant.Select(item => item.Entry.Trustee).Where(trustee => trustee.Sid != "S-1-3-4")
                .DistinctBy(trustee => trustee.Sid, StringComparer.OrdinalIgnoreCase).ToList();
            if (outcome == EffectiveAccessOutcome.GrantsEveryoneEverything)
                trustees = [new PermissionTrustee("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null)];
            foreach (var trustee in trustees.OrderBy(item => item.Sid, StringComparer.Ordinal))
            {
                var evidence = relevant.Where(item => Same(item.Entry.Trustee.Sid, trustee.Sid)
                    || item.Entry.AceType.Contains("Denied", StringComparison.Ordinal)).ToArray();
                var unknown = descriptorUncertainty | targetUncertainty;
                if (evidence.Any(item => item.Scope.State == ControlEvaluationState.Unknown))
                    unknown |= capability switch
                    {
                        ControlCapability.CanResetPassword => ControlUncertainty.PasswordResetScopeNotEvaluated,
                        ControlCapability.CanWriteKeyCredentialLink => ControlUncertainty.KeyCredentialLinkScopeNotEvaluated,
                        _ => ControlUncertainty.MembershipScopeNotEvaluated,
                    };
                if (evidence.Any(item => !IsSupported(item.Entry.AceType))) unknown |= ControlUncertainty.ConditionalOrUnsupportedAce;
                if (evidence.Any(item => item.Entry.AceType.Contains("Denied", StringComparison.Ordinal)
                    && !Same(item.Entry.Trustee.Sid, trustee.Sid))) unknown |= ControlUncertainty.CrossTrusteeDeny;
                if (!trustee.HoldsThePermission) unknown |= ControlUncertainty.HolderIsPlaceholder;
                var classification = PrincipalClassificationRegistry.For(trustee.Sid);
                if (!classification.IdentityIsValid || trustee.DistinguishedName is null && classification.MicrosoftName is null)
                    unknown |= ControlUncertainty.HolderUnresolved;
                if (Sid.IsBuiltinDomain(trustee.Sid) && !IsDomainTarget(subject, context.ForestFqdn))
                    unknown |= ControlUncertainty.ResourceContextUnverified;
                var granted = outcome == EffectiveAccessOutcome.GrantsEveryoneEverything
                    || ((effective.Holders.FirstOrDefault(holder => Same(holder.Trustee.Sid, trustee.Sid))?.Mask ?? 0) & right) != 0;
                var possibleGrant = evidence.Any(item => Same(item.Entry.Trustee.Sid, trustee.Sid)
                    && !item.Entry.AceType.Contains("Denied", StringComparison.Ordinal));
                if (!granted && !(possibleGrant && unknown != ControlUncertainty.None)) continue;
                var conditions = evidence.Select(item => new ControlPrecondition(capability switch
                    {
                        ControlCapability.CanResetPassword => $"ResetPasswordRightScope[{item.Entry.Ordinal}]",
                        ControlCapability.CanWriteKeyCredentialLink => $"KeyCredentialLinkWriteScope[{item.Entry.Ordinal}]",
                        _ => $"ACE {item.Entry.Ordinal} reaches membership operation",
                    },
                    item.Scope.State, item.Scope.Source)).ToList();
                if (capability == ControlCapability.CanAddSelfToGroup)
                {
                    conditions.Add(new("HoldsSelfMembershipValidatedWrite", unknown == ControlUncertainty.None && granted
                        ? ControlEvaluationState.Established : ControlEvaluationState.Unknown, "Stored descriptor; ADS_RIGHT_DS_SELF (0x08)"));
                    conditions.Add(new("AddedMemberSid == RequesterSid", ControlEvaluationState.Unknown,
                        "Microsoft Self-Membership: only the caller's account may be added or removed. No concrete requester operation evaluated; group-held expansion remains gated by 0110."));
                    unknown |= ControlUncertainty.SelfMembershipRequesterNotEvaluated;
                }
                var holderScope = Sid.IsBuiltinDomain(trustee.Sid) ? subject.DomainFqdn : null;
                var routes = context.ProtectedPrincipals?.Lookup(trustee.Sid, holderScope)?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
                var expected = Expected(trustee, subject, context.ForestFqdn, routes, original.DaclCompleteness == DaclCompleteness.Complete,
                    outcome != EffectiveAccessOutcome.GrantsEveryoneEverything && granted && unknown == ControlUncertainty.None, domainSid);
                if (capability == ControlCapability.CanAddSelfToGroup && Same(trustee.Sid, "S-1-5-18"))
                    expected = (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownCapabilityScope);
                edges.Add(new ControlEdge(0, subject.ObjectGuid, subject.DistinguishedName, classes?.LastOrDefault()?.Text,
                    trustee.Sid, trustee.Name, holderScope, capability,
                    unknown == ControlUncertainty.None ? ControlEvaluationState.Established : ControlEvaluationState.Unknown,
                    unknown, expected.State, expected.Reason, PrincipalClassificationRegistry.Version, generation, derivationGeneration,
                    true, evidence.Select(item => item.Original).ToArray(), conditions, routes) { DescriptorOutcome = outcome.ToString() });
            }
        }
        return targetUncertainty;
    }

    private static (ControlEvaluationState State, string Source) OperationScope(PermissionEntry entry, int right,
        string name, string? targetClass, SchemaGuidCatalog catalogue)
    {
        if (!entry.HasObjectType) return (ControlEvaluationState.Established, "Unscoped entry reaches all operations of this access-mask kind.");
        if (!Guid.TryParse(catalogue.GuidFor(name), out _))
            return (ControlEvaluationState.Unknown, name);
        if (entry.ObjectTypeGuid is { } guid && Same(guid, catalogue.GuidFor(name)))
            return (ControlEvaluationState.Established, $"{name}: {guid}; {catalogue.FindByLdapName(name)!.Source} schema catalogue.");
        if (right == 0x20 && entry.ObjectTypeGuid is { } propertySet)
        {
            var meanings = catalogue.FindByGuid(propertySet);
            if (meanings.Any(item => item.Kind == SchemaGuidKind.ObjectClass))
            {
                if (targetClass is null || !Guid.TryParse(catalogue.GuidFor(targetClass), out _))
                    return (ControlEvaluationState.Unknown, propertySet);
                return (Same(propertySet, catalogue.GuidFor(targetClass)) ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished,
                    $"{targetClass}: {catalogue.GuidFor(targetClass)}; {catalogue.FindByLdapName(targetClass)!.Source} schema catalogue.");
            }
            var members = catalogue.MembersOfPropertySet(propertySet);
            if (members is not null || meanings.Count == 0 || meanings.Any(item => item.Kind is SchemaGuidKind.PropertySet or SchemaGuidKind.Unclassified))
            {
                if (catalogue.AttributeBelongsToPropertySet(name, propertySet) is { } belongs)
                    return (belongs ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished,
                        $"Captured property set {propertySet}; attributes: {string.Join(", ", members ?? [])}.");
                return (ControlEvaluationState.Unknown, $"Property/attribute scope {propertySet}: captured property-set membership unavailable.");
            }
        }
        if (entry.ObjectTypeGuid is null || !Guid.TryParse(entry.ObjectTypeGuid, out _))
            return (ControlEvaluationState.Unknown, "Object-type flag is present but its GUID is unavailable or invalid.");
        return (ControlEvaluationState.NotEstablished, "Entry is scoped to a different operation.");
    }

    internal static (ControlExpectedness State, ControlExpectednessReason Reason) Expected(PermissionTrustee holder,
        ObjectAttributes target, string? forest, MembershipRouteSummary routes, bool descriptorComplete, bool effectiveDirectAce,
        Func<string, string?> domainSid)
    {
        var definition = PrincipalClassificationRegistry.For(holder.Sid);
        if (definition.IsBroad) return (ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedBroadPrincipal);
        if (!holder.HoldsThePermission) return (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownHolderIsPlaceholder);
        if (Same(holder.Sid, "S-1-5-18"))
            return descriptorComplete && effectiveDirectAce
                ? (ControlExpectedness.Expected, ControlExpectednessReason.ExpectedPlatformIdentityDirectAce)
                : (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownDescriptorIncomplete);
        var holderDomain = holder.DomainFqdn;
        if (Sid.IsBuiltinDomain(holder.Sid) && definition.ControlPlaneScope == PrincipalAuthorityScope.Domain)
        {
            // A direct BUILTIN ACE names the resource domain's group, not a forest-wide SID match.
            // Membership roots below retain their own scope; P-90 still gates non-domain resources.
            if (!IsDomainTarget(target, forest) || string.IsNullOrWhiteSpace(domainSid(target.DomainFqdn!)))
                return (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownAuthorityScope);
            holderDomain = target.DomainFqdn;
        }
        var direct = VerifiedScopeAnswer(holder.Sid, definition.ControlPlaneScope, holderDomain, target, forest, domainSid);
        if (direct.State == ControlExpectedness.Expected) return direct;
        // These chains carry a separate authorization answer. Never consult protection, the selected basis,
        // or OwnerAcceptance. Positive current membership can establish scope; SID history cannot.
        foreach (var route in routes.Memberships.SelectMany(group => group.Routes)
            .Where(route => route.Authorization == MembershipRouteAuthorization.SecurityEnabled))
        {
            var root = route.Steps.LastOrDefault()?.Principal;
            if (root is null || !Same(route.Steps.First().Principal.Sid, holder.Sid)) continue;
            var rootDefinition = PrincipalClassificationRegistry.For(root.Sid);
            if (rootDefinition.ControlPlaneScope is PrincipalAuthorityScope.Descriptor or PrincipalAuthorityScope.RequiredDomainControllerOperations) continue;
            var domain = root.Scope ?? (root.DistinguishedName is { } dn ? DnHelper.DnToFqdn(dn) : null);
            var answer = VerifiedScopeAnswer(root.Sid, rootDefinition.ControlPlaneScope, domain, target, forest, domainSid);
            if (answer.State == ControlExpectedness.Expected) return answer;
        }
        if (!routes.IsComplete) return (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownMembershipIncomplete);
        return direct;
    }

    private static (ControlExpectedness State, ControlExpectednessReason Reason) VerifiedScopeAnswer(string sid, PrincipalAuthorityScope authority,
        string? holderDomain, ObjectAttributes target, string? forest, Func<string, string?> domainSid)
    {
        if (authority is PrincipalAuthorityScope.Domain or PrincipalAuthorityScope.Forest or PrincipalAuthorityScope.Schema
            && !Sid.IsBuiltinDomain(sid))
        {
            if (string.IsNullOrWhiteSpace(holderDomain) || domainSid(holderDomain) is not { } issued
                || !Same(sid[..sid.LastIndexOf('-')], issued))
                return (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownAuthorityScope);
        }
        return ScopeAnswer(authority, holderDomain, target, forest);
    }

    private static (ControlExpectedness State, ControlExpectednessReason Reason) ScopeAnswer(PrincipalAuthorityScope authority,
        string? holderDomain, ObjectAttributes target, string? forest)
    {
        if (authority == PrincipalAuthorityScope.None) return (ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane);
        if (authority == PrincipalAuthorityScope.RequiredDomainControllerOperations)
            return (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownCapabilityScope);
        if (string.IsNullOrWhiteSpace(holderDomain) || string.IsNullOrWhiteSpace(forest) || string.IsNullOrWhiteSpace(target.DomainFqdn))
            return (ControlExpectedness.Unknown, ControlExpectednessReason.UnknownAuthorityScope);
        if (authority == PrincipalAuthorityScope.Domain && IsDomainTarget(target, forest))
            return Same(holderDomain, target.DomainFqdn)
                ? (ControlExpectedness.Expected, ControlExpectednessReason.ExpectedSameDomainControlPlane)
                : (ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedOutsideAuthorityScope);
        if (authority == PrincipalAuthorityScope.Forest && Same(holderDomain, forest))
            return (ControlExpectedness.Expected, ControlExpectednessReason.ExpectedForestControlPlane);
        if (authority == PrincipalAuthorityScope.Schema && Same(holderDomain, forest)
            && IsWithin(target.DistinguishedName, "CN=Schema,CN=Configuration," + DomainDn(forest)))
            return (ControlExpectedness.Expected, ControlExpectednessReason.ExpectedSchemaControlPlane);
        return (ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedOutsideAuthorityScope);
    }

    private static bool IsSupported(string type) => type is "AccessAllowed" or "AccessAllowedObject" or "AccessDenied" or "AccessDeniedObject";
    private static bool Applies(PermissionEntry entry) => EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject;
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static string DomainDn(string domain) => string.Join(',', domain.Split('.').Select(part => "DC=" + part));
    private static bool IsConfiguration(string dn, string? forest) => !string.IsNullOrWhiteSpace(forest)
        && IsWithin(dn, "CN=Configuration," + DomainDn(forest));
    private static bool IsDomainTarget(ObjectAttributes target, string? forest) => !string.IsNullOrWhiteSpace(forest)
        && !string.IsNullOrWhiteSpace(target.DomainFqdn)
        && Same(DnHelper.DnToFqdn(target.DistinguishedName), target.DomainFqdn)
        && !IsConfiguration(target.DistinguishedName, forest);
    private static bool IsWithin(string dn, string root)
    {
        for (string? ancestor = dn; ancestor is not null; ancestor = DnHelper.GetParentDn(ancestor))
            if (Same(ancestor, root)) return true;
        return false;
    }
}
