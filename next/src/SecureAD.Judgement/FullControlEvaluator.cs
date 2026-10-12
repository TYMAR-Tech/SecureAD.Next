using System.Globalization;
using System.Resources;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class FullControlEvaluator
{
    // MS-ADTS 6.1.3 GENERIC_ALL_MAPPING. Stored generic bits are not mapped by an access check (MS-DTYP 2.4.3).
    internal const int RequiredMask = 0x000F01FF;
    private static readonly int[] RequiredRights = [1, 2, 4, 8, 16, 32, 64, 128, 256, 0x10000, 0x20000, 0x40000, 0x80000];
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.FullControl", typeof(FullControlEvaluator).Assembly);

    internal static FullControlAssessment AssessFullControl(FullControlSource source, Guid generation, Guid? derivationGeneration,
        ControlExpectedness expectedness, ControlExpectednessReason reason, IReadOnlyList<ControlEdge> edges)
    {
        var checks = new List<FullControlRight>();
        foreach (var right in RequiredRights)
        {
            checks.Add(Check(source, right, null, true));
            foreach (var scope in source.Entries.Where(entry => Applies(entry) && entry.HasObjectType
                && IsDeny(entry) && (entry.AccessMask & right) != 0)
                .Select(entry => entry.ObjectTypeGuid ?? "").Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal))
                checks.Add(Check(source, right, scope, KnownScope(source, right, scope)));
        }
        var uncertainty = checks.Aggregate(ControlUncertainty.None, (value, check) => value | check.Uncertainty);
        var state = checks.Any(check => check.State == ControlEvaluationState.NotEstablished) ? ControlEvaluationState.NotEstablished
            : checks.Any(check => !check.IsComplete) ? ControlEvaluationState.Unknown : ControlEvaluationState.Established;
        var supports = state == ControlEvaluationState.Established ? edges.Where(edge => Supports(source, edge))
            .Select(edge => edge.Capability).Distinct().Order().ToArray() : [];
        // A full-control label must not make a restricted or unresolved supporting classification disappear.
        var classifications = edges.Where(edge => supports.Contains(edge.Capability) && Supports(source, edge)).ToArray();
        if (expectedness == ControlExpectedness.Expected && classifications.Any(edge => edge.Expectedness != ControlExpectedness.Expected))
        {
            expectedness = ControlExpectedness.Unknown;
            reason = ControlExpectednessReason.UnknownCapabilityScope;
        }
        var firstRoute = checks.SelectMany(check => check.GrantOrdinals.Take(1)).ToHashSet();
        return new(0, source, generation, derivationGeneration, PrincipalClassificationRegistry.Version, state, uncertainty,
            expectedness, reason, checks, supports)
        {
            HasIndependentGrantRoutes = state == ControlEvaluationState.Established
                && checks.All(check => check.GrantOrdinals.Any(ordinal => !firstRoute.Contains(ordinal))),
        };
    }

    internal static bool Supports(FullControlSource source, ControlEdge edge) => edge.IsCounted
        && edge.EvaluationState == ControlEvaluationState.Established && edge.Uncertainty == ControlUncertainty.None
        && Same(source.Target, edge.Target) && source.TargetGuid == edge.TargetGuid
        && Same(source.Holder.Sid, edge.HolderSid) && Same(source.HolderScope, edge.HolderScope)
        && edge.Capability is ControlCapability.CanWriteDacl or ControlCapability.CanSetOwner
            or ControlCapability.CanModifyGroupMembership or ControlCapability.CanResetPassword
            or ControlCapability.CanWriteKeyCredentialLink or ControlCapability.CanReplicateSecretDomainData
            or ControlCapability.CanWriteServicePrincipalName or ControlCapability.CanWriteResourceBasedConstrainedDelegation
            or ControlCapability.CanReplicateFilteredAttributes;

    internal static void Validate(FullControlAssessment value, IReadOnlyList<ControlEdge> edges)
    {
        var source = value.Source;
        if (source is null || source.Holder is null || string.IsNullOrWhiteSpace(source.Target)
            || source.Classes is null || source.Entries is null || source.AuthorityDomainSids is null || source.MembershipRoutes is null
            || source.MembershipRoutes.Memberships is null || value.Rights is null || value.SupportingCapabilities is null
            || !Enum.IsDefined(source.Availability) || !Enum.IsDefined(source.Dacl) || !Enum.IsDefined(source.Completeness)
            || !Enum.IsDefined(value.Expectedness) || !Enum.IsDefined(value.ExpectednessReason)
            || value.Expectedness == ControlExpectedness.Expected && value.ExpectednessReason == ControlExpectednessReason.ExpectedSchemaControlPlane
            // Catalogue 3 changes only Tier-0 classification; catalogue-2 permission proof is still replayable.
            || value.PrincipalCatalogueVersion is not (2 or 3)
            || source.Entries.Any(entry => entry is null || entry.Trustee is null || entry.ApplicationData is null)
            || source.Entries.Select(entry => entry.Ordinal).Distinct().Count() != source.Entries.Count
            || !source.Entries.Select(entry => entry.Ordinal).SequenceEqual(source.Entries.Select(entry => entry.Ordinal).Order()))
            throw InvalidProof();
        if (source.Dacl is DaclState.Null or DaclState.Empty && source.Entries.Count != 0
            || edges.Where(edge => Supports(source, edge)).Any(edge => edge.TargetClass != source.Classes.LastOrDefault()
                || edge.Evidence.Any(entry => !source.Entries.Any(original => SamePermission(original, entry))))) throw InvalidProof();
        var rights = AssessFullControl(source, value.GenerationId, value.DerivationGenerationId,
            ControlExpectedness.Unknown, ControlExpectednessReason.UnknownCapabilityScope, edges);
        var target = new ObjectAttributes(source.Target, source.TargetGuid, DateTimeOffset.UnixEpoch, default, [], source.TargetDomain);
        string? DomainSid(string domain) => source.AuthorityDomainSids.FirstOrDefault(pair => Same(pair.Key, domain)).Value;
        var resourceContext = !Sid.IsBuiltinDomain(source.Holder.Sid) || ControlEdgeDeriver.IsDomainTarget(target, source.ForestFqdn)
            && source.TargetDomain is { } domain && !string.IsNullOrWhiteSpace(DomainSid(domain));
        if (source.ResourceContextEstablished != resourceContext
            || source.HolderScope != (Sid.IsBuiltinDomain(source.Holder.Sid) ? source.TargetDomain : null)) throw InvalidProof();
        var expected = ControlEdgeDeriver.Expected(source.Holder, target, source.ForestFqdn, source.MembershipRoutes,
            source.Completeness == DaclCompleteness.Complete, rights.IsCounted && source.Dacl != DaclState.Null, DomainSid, fullControl: true);
        var replay = AssessFullControl(source, value.GenerationId, value.DerivationGenerationId, expected.State, expected.Reason, edges);
        if (value.EvaluationState != replay.EvaluationState || value.Uncertainty != replay.Uncertainty
            || value.HasIndependentGrantRoutes != replay.HasIndependentGrantRoutes
            || value.Expectedness != replay.Expectedness || value.ExpectednessReason != replay.ExpectednessReason
            || JsonSerializer.Serialize(value.Rights, ProofSerialization.Options) != JsonSerializer.Serialize(replay.Rights, ProofSerialization.Options)
            || !value.SupportingCapabilities.SequenceEqual(replay.SupportingCapabilities)
            || edges.Where(edge => Supports(source, edge)).Any(edge => edge.GenerationId != value.GenerationId
                || edge.DerivationGenerationId != value.DerivationGenerationId)) throw InvalidProof();
    }

    private static FullControlRight Check(FullControlSource source, int right, string? scope, bool knownScope)
    {
        var unknown = source.Availability != DescriptorAvailability.Read || source.Dacl == DaclState.Unreadable
            ? ControlUncertainty.DescriptorUnreadable
            : source.Completeness != DaclCompleteness.Complete ? ControlUncertainty.DescriptorIncomplete : ControlUncertainty.None;
        var definition = PrincipalClassificationRegistry.For(source.Holder.Sid);
        if (!source.Holder.HoldsThePermission || definition.IdentityIsValid && definition.MicrosoftName is not null
            && source.Holder.Sid is "S-1-3-0" or "S-1-3-4") unknown |= ControlUncertainty.HolderIsPlaceholder;
        if (!definition.IdentityIsValid || source.Holder.DistinguishedName is null && definition.MicrosoftName is null)
            unknown |= ControlUncertainty.HolderUnresolved;
        if (!source.ResourceContextEstablished) unknown |= ControlUncertainty.ResourceContextUnverified;
        var grants = new List<int>();
        var blockers = new List<int>();
        if (source.Availability == DescriptorAvailability.Read && source.Dacl == DaclState.Null)
            return new(right, scope, unknown == ControlUncertainty.None && Same(source.Holder.Sid, "S-1-1-0")
                ? ControlEvaluationState.Established : ControlEvaluationState.Unknown, unknown, grants, blockers);
        var boundary = false;
        foreach (var entry in source.Entries)
        {
            if (!Applies(entry) || (entry.AccessMask & right) == 0) continue;
            var sameHolder = Same(entry.Trustee.Sid == "S-1-5-10" && source.TargetSid is not null
                ? source.TargetSid : entry.Trustee.Sid, source.Holder.Sid);
            if (!sameHolder && !IsDeny(entry)) continue;
            if (scope is null && entry.HasObjectType) continue;
            if (scope is not null && entry.HasObjectType && !Same(entry.ObjectTypeGuid ?? "", scope))
            {
                // Overlapping property sets and object-type scopes are not unioned into an authorization answer.
                if (IsDeny(entry) && grants.Count == 0) unknown |= ControlUncertainty.ObjectSpecificScopeNotEvaluated;
                continue;
            }
            var limit = !Supported(entry) ? ControlUncertainty.ConditionalOrUnsupportedAce
                : !sameHolder ? ControlUncertainty.CrossTrusteeDeny
                : scope is not null && entry.HasObjectType && !knownScope ? ControlUncertainty.ObjectSpecificScopeNotEvaluated
                : ControlUncertainty.None;
            if (limit != ControlUncertainty.None)
            {
                if (grants.Count == 0) unknown |= limit;
                blockers.Add(entry.Ordinal);
                boundary = true;
            }
            else if (IsDeny(entry))
            {
                blockers.Add(entry.Ordinal);
                boundary = true;
            }
            else if (!boundary) grants.Add(entry.Ordinal);
        }
        var state = unknown != ControlUncertainty.None ? ControlEvaluationState.Unknown
            : grants.Count != 0 ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
        return new(right, scope, state, unknown, grants, blockers);
    }

    private static bool KnownScope(FullControlSource source, int right, string scope)
    {
        var group = source.Classes.Any(value => Same(value, "group"));
        var account = source.Classes.Any(value => value is "user" or "computer" or "inetOrgPerson"
            or "msDS-ManagedServiceAccount" or "msDS-GroupManagedServiceAccount");
        var names = right switch
        {
            0x20 => (group ? new[] { "member" } : Array.Empty<string>()).Concat(account ? ["msDS-KeyCredentialLink"] : []),
            0x08 when group => ["Self-Membership"],
            0x100 => (account ? new[] { "User-Force-Change-Password" } : Array.Empty<string>()).Concat(source.NamingContextRootEstablished
                ? ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set"] : []),
            _ => Enumerable.Empty<string>(),
        };
        return names.Any(name => Same(SchemaGuidCatalog.Embedded.GuidFor(name), scope));
    }

    private static bool SamePermission(PermissionEntry left, PermissionEntry right) => left.Ordinal == right.Ordinal
        && left.AccessMask == right.AccessMask && left.AceType == right.AceType && Same(left.Trustee.Sid, right.Trustee.Sid)
        && Same(left.ObjectTypeGuid, right.ObjectTypeGuid) && Same(left.InheritedObjectTypeGuid, right.InheritedObjectTypeGuid)
        && left.HasObjectType == right.HasObjectType && left.HasInheritedObjectType == right.HasInheritedObjectType
        && left.IsInherited == right.IsInherited && left.InheritanceFlags == right.InheritanceFlags
        && left.PropagationFlags == right.PropagationFlags && left.ApplicationData.SequenceEqual(right.ApplicationData);

    internal static bool Applies(PermissionEntry entry) => EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject;
    internal static bool IsDeny(PermissionEntry entry) => entry.AceType.Contains("Denied", StringComparison.OrdinalIgnoreCase);
    private static bool Supported(PermissionEntry entry) => entry.AceType is "AccessAllowed" or "AccessAllowedObject" or "AccessDenied" or "AccessDeniedObject";
    internal static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    internal static InvalidOperationException InvalidProof() => new(Resources.GetString("InvalidProof", CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException("InvalidProof"));
}
