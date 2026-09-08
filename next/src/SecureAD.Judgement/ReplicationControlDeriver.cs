using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using System.Globalization;
using System.Resources;

namespace SecureAD.Judgement;

internal static class ReplicationControlDeriver
{
    internal const string Changes = "DS-Replication-Get-Changes";
    internal const string All = "DS-Replication-Get-Changes-All";
    internal const string Filtered = "DS-Replication-Get-Changes-In-Filtered-Set";
    private static readonly string[] Rights = [Changes, All, Filtered];
    private const int ControlAccess = 0x100;
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.ReplicationControl", typeof(ReplicationControlDeriver).Assembly);

    internal static void ValidateStored(ControlEdge edge)
    {
        if (edge.EdgeClass != ControlEdgeClass.ReplicationControl) return;
        var proof = edge.Preconditions;
        var required = Rights.Concat(["NamingContextRoot", "NamingContextKind", "HolderDomainControllerAsset"]).ToArray();
        if (proof.Count != required.Length || required.Any(name => proof.Count(item => item.Name == name) != 1)
            || proof.Any(item => !Enum.IsDefined(item.State)) || !edge.IsCounted)
            throw new InvalidOperationException(Text("InvalidProof"));
        var checks = Rights.Select(name => new Check(proof.Single(item => item.Name == name).State, ControlUncertainty.None)).ToArray();
        var combined = And(checks[0], edge.Capability == ControlCapability.CanReplicateSecretDomainData ? checks[1] : Or(checks[1], checks[2]));
        var root = proof.Single(item => item.Name == "NamingContextRoot");
        var kind = proof.Single(item => item.Name == "NamingContextKind");
        if (!Same(root.EvidenceSource, edge.Target)
            || root.State == ControlEvaluationState.NotEstablished || kind.State == ControlEvaluationState.NotEstablished
            || kind.State == ControlEvaluationState.Established && (!Enum.TryParse<NamingContextKind>(kind.EvidenceSource, out var parsed) || !Enum.IsDefined(parsed))
            || combined.State == ControlEvaluationState.NotEstablished
            || edge.EvaluationState is not (ControlEvaluationState.Established or ControlEvaluationState.Unknown)
            || edge.EvaluationState == ControlEvaluationState.Established && (combined.State != ControlEvaluationState.Established
                || root.State != ControlEvaluationState.Established || kind.State != ControlEvaluationState.Established || edge.Uncertainty != ControlUncertainty.None)
            || edge.DescriptorOutcome != EffectiveAccessOutcome.GrantsEveryoneEverything.ToString() && edge.Evidence.Count == 0)
            throw new InvalidOperationException(Text("InvalidProof"));
        var catalogue = new SchemaGuidCatalog(Rights.Select(name => new SchemaGuidEntry(
            proof.Single(item => item.Name == name).EvidenceSource, name, SchemaGuidKind.ExtendedRight, SchemaGuidSource.Captured)));
        var normalized = edge.Evidence.Select(entry => entry.Trustee.Sid == "S-1-5-10"
            ? entry with { Trustee = entry.Trustee with { Sid = edge.HolderSid, WellKnownRole = null } } : entry).ToArray();
        var permissions = new ObjectPermissions(edge.Target, DescriptorAvailability.Read, null, null,
            edge.DescriptorOutcome == EffectiveAccessOutcome.GrantsEveryoneEverything.ToString() ? DaclState.Null : DaclState.Present,
            DaclCompleteness.Complete, true, false, normalized, []);
        var holder = normalized.FirstOrDefault(entry => Same(entry.Trustee.Sid, edge.HolderSid))?.Trustee
            ?? new(edge.HolderSid, edge.HolderName, null, null, null, null, null);
        var descriptorUncertainty = edge.Uncertainty & (ControlUncertainty.DescriptorIncomplete | ControlUncertainty.DescriptorUnreadable);
        if (Rights.Where((right, index) => CheckRight(right, holder, permissions, catalogue, descriptorUncertainty).State != checks[index].State).Any())
            throw new InvalidOperationException(Text("InvalidProof"));
    }

    internal static ControlUncertainty Add(ObjectAttributes subject, ObjectPermissions original,
        ObjectPermissions normalized, JudgingContext context, Guid generation, Guid? derivationGeneration,
        Func<string, string?> domainSid, EffectiveAccessOutcome outcome, ControlUncertainty descriptorUncertainty,
        List<ControlEdge> edges)
    {
        var classes = subject.Find("objectClass")?.Values.Select(value => value.Text).ToArray() ?? [];
        var kind = context.NamingContexts?.TryGetValue(subject.DistinguishedName, out var capturedKind) == true
            ? capturedKind : (NamingContextKind?)null;
        // A known child is not a replication target, even if its class or name resembles a root.
        if (context.NamingContexts is not null && kind is null) return ControlUncertainty.None;
        if (kind is null && classes.Length != 0 && !classes.Any(value => value is "domainDNS" or "configuration" or "dMD"))
            return ControlUncertainty.None;
        var rootUnknown = kind is null || !classes.Any(value => Same(value, kind switch
        {
            NamingContextKind.Domain => "domainDNS",
            NamingContextKind.Configuration => "configuration",
            NamingContextKind.Schema => "dMD",
            _ => null,
        }));
        var rootUncertainty = rootUnknown ? ControlUncertainty.ReplicationRootNotEstablished : ControlUncertainty.None;
        var catalogue = context.SchemaGuids ?? SchemaGuidCatalog.Embedded;
        var relevant = normalized.Entries.Select((entry, index) => (Entry: entry, Original: original.Entries[index]))
            .Where(item => Applies(item.Entry) && (item.Entry.AccessMask & ControlAccess) != 0
                && Rights.Any(right => Scope(item.Entry, right, catalogue).State != ControlEvaluationState.NotEstablished)).ToArray();
        var trustees = relevant.Select(item => item.Entry.Trustee).Where(trustee => trustee.Sid != "S-1-3-4")
            .DistinctBy(trustee => trustee.Sid, StringComparer.OrdinalIgnoreCase).ToList();
        if (outcome == EffectiveAccessOutcome.GrantsEveryoneEverything)
            trustees = [new("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null)];
        foreach (var trustee in trustees.OrderBy(item => item.Sid, StringComparer.Ordinal))
        {
            var checks = Rights.Select(right => CheckRight(right, trustee, normalized, catalogue,
                descriptorUncertainty & (ControlUncertainty.DescriptorIncomplete | ControlUncertainty.DescriptorUnreadable))).ToArray();
            var holderUnknown = rootUncertainty;
            var classification = PrincipalClassificationRegistry.For(trustee.Sid);
            if (!trustee.HoldsThePermission) holderUnknown |= ControlUncertainty.HolderIsPlaceholder;
            if (!classification.IdentityIsValid || trustee.DistinguishedName is null && classification.MicrosoftName is null)
                holderUnknown |= ControlUncertainty.HolderUnresolved;
            // No servicing/token context is established for non-domain partitions in this bounded slice (P-90).
            if (kind != NamingContextKind.Domain && !Same(trustee.Sid, "S-1-1-0") && !Same(trustee.Sid, "S-1-5-18"))
                holderUnknown |= ControlUncertainty.ResourceContextUnverified;
            if (Sid.IsBuiltinDomain(trustee.Sid) && !ControlEdgeDeriver.IsDomainTarget(subject, context.ForestFqdn))
                holderUnknown |= ControlUncertainty.ResourceContextUnverified;
            var holderScope = Sid.IsBuiltinDomain(trustee.Sid) ? subject.DomainFqdn : null;
            var routes = context.ProtectedPrincipals?.Lookup(trustee.Sid, holderScope)?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
            var evidence = relevant.Where(item => Same(item.Entry.Trustee.Sid, trustee.Sid) || IsDeny(item.Entry))
                .Select(item => item.Original).ToArray();
            var holderObject = trustee.DistinguishedName is { } dn ? context.ControlPrincipals?.Invoke(dn) : null;
            foreach (var capability in new[] { ControlCapability.CanReplicateSecretDomainData, ControlCapability.CanReplicateFilteredAttributes })
            {
                var alternative = capability == ControlCapability.CanReplicateSecretDomainData
                    ? checks[1] : Or(checks[1], checks[2]);
                var combined = And(checks[0], alternative);
                if (combined.State == ControlEvaluationState.NotEstablished) continue;
                var unknown = combined.Uncertainty | holderUnknown;
                var state = unknown == ControlUncertainty.None ? combined.State : ControlEvaluationState.Unknown;
                var expected = ControlEdgeDeriver.Expected(trustee, subject, context.ForestFqdn, routes,
                    original.DaclCompleteness == DaclCompleteness.Complete,
                    outcome != EffectiveAccessOutcome.GrantsEveryoneEverything && state == ControlEvaluationState.Established,
                    domainSid, replication: true);
                var proof = Rights.Select((right, index) => new ControlPrecondition(right, checks[index].State,
                    catalogue.GuidFor(right) ?? right)).ToList();
                proof.Add(new("NamingContextRoot", rootUnknown ? ControlEvaluationState.Unknown : ControlEvaluationState.Established,
                    subject.DistinguishedName));
                proof.Add(new("NamingContextKind", kind is null ? ControlEvaluationState.Unknown : ControlEvaluationState.Established,
                    kind?.ToString() ?? "Unknown"));
                proof.Add(HolderClassification(trustee.Sid, holderObject));
                edges.Add(new(0, subject.ObjectGuid, subject.DistinguishedName, classes.LastOrDefault(), trustee.Sid,
                    trustee.Name, holderScope, capability, state, unknown, expected.State, expected.Reason,
                    PrincipalClassificationRegistry.Version, generation, derivationGeneration, true, evidence, proof, routes)
                    { DescriptorOutcome = outcome.ToString() });
            }
        }
        return rootUncertainty;
    }

    private static Check CheckRight(string right, PermissionTrustee trustee, ObjectPermissions permissions,
        SchemaGuidCatalog catalogue, ControlUncertainty descriptorUncertainty)
    {
        if (permissions.DaclState == DaclState.Null)
            return new(ControlEvaluationState.Established, ControlUncertainty.None);
        var relevant = permissions.Entries.Where(entry => Applies(entry) && (entry.AccessMask & ControlAccess) != 0)
            .Select(entry => (Entry: entry, Scope: Scope(entry, right, catalogue)))
            .Where(item => item.Scope.State != ControlEvaluationState.NotEstablished).ToArray();
        // One GUID-scoped operation includes broad entries in their original order; never union grant lists.
        var effective = EffectiveAccessCalculator.Over(permissions with
        {
            Entries = relevant.Where(item => item.Scope.State == ControlEvaluationState.Established && Supported(item.Entry))
                .Select(item => item.Entry with { HasObjectType = false, ObjectTypeGuid = null }).ToArray(),
        }, null);
        var granted = effective.Holders.Any(holder => Same(holder.Trustee.Sid, trustee.Sid) && (holder.Mask & ControlAccess) != 0);
        var unknown = descriptorUncertainty;
        if (!trustee.HoldsThePermission && relevant.Any(item => Same(item.Entry.Trustee.Sid, trustee.Sid) && !IsDeny(item.Entry)))
            unknown |= ControlUncertainty.HolderIsPlaceholder;
        foreach (var item in relevant)
        {
            var own = Same(item.Entry.Trustee.Sid, trustee.Sid);
            if (!own && !IsDeny(item.Entry)) continue;
            // A certain terminal entry makes later uncertain entries irrelevant for this right only.
            if (own && Supported(item.Entry) && item.Scope.State == ControlEvaluationState.Established) break;
            if (!own) unknown |= ControlUncertainty.CrossTrusteeDeny;
            if (!Supported(item.Entry)) unknown |= ControlUncertainty.ConditionalOrUnsupportedAce;
            if (item.Scope.State == ControlEvaluationState.Unknown) unknown |= ControlUncertainty.ReplicationRightNotEstablished;
        }
        return new(unknown != ControlUncertainty.None ? ControlEvaluationState.Unknown
            : granted ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished, unknown);
    }

    private static ControlPrecondition HolderClassification(string sid, ObjectAttributes? holder)
    {
        var value = holder?.Find("objectSid")?.OnlyValue;
        var capturedSid = value?.Bytes is { } bytes ? Sid.ToText(bytes) : value?.Text;
        if (holder is null || !Same(capturedSid, sid))
            return new("HolderDomainControllerAsset", ControlEvaluationState.Unknown, Text("HolderUnavailable"));
        var signals = DomainControllerSignals.Of(holder);
        var complete = AttributeReading.UnsignedInteger(holder, "userAccountControl") is not null
            && AttributeReading.SignedInteger(holder, "primaryGroupID") is not null;
        var computer = holder.Find("objectClass")?.Values.Any(item => Same(item.Text, "computer")) == true;
        var classKnown = holder.Find("objectClass")?.Values.Any(item => !string.IsNullOrWhiteSpace(item.Text)) == true;
        var state = !classKnown ? ControlEvaluationState.Unknown : !computer ? ControlEvaluationState.NotEstablished
            : !complete || signals.SignalsDisagree ? ControlEvaluationState.Unknown
            : signals.IsDomainController ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
        return new("HolderDomainControllerAsset", state, string.Format(CultureInfo.InvariantCulture, Text("HolderSignals"),
            holder.DistinguishedName, holder.ObjectGuid, signals.ServerTrustAccountBit,
            signals.PrimaryGroupIsDomainController, signals.UnderDomainControllersOu, complete));
    }

    private static string Text(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);

    private static (ControlEvaluationState State, string Source) Scope(PermissionEntry entry, string right, SchemaGuidCatalog catalogue) =>
        ControlEdgeDeriver.OperationScope(entry, ControlAccess, right, null, catalogue);
    private static bool Applies(PermissionEntry entry) => EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject;
    private static bool Supported(PermissionEntry entry) => entry.AceType is "AccessAllowed" or "AccessAllowedObject" or "AccessDenied" or "AccessDeniedObject";
    private static bool IsDeny(PermissionEntry entry) => entry.AceType.Contains("Denied", StringComparison.Ordinal);
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private sealed record Check(ControlEvaluationState State, ControlUncertainty Uncertainty);
    private static Check And(Check left, Check right) => left.State == ControlEvaluationState.NotEstablished || right.State == ControlEvaluationState.NotEstablished
        ? new(ControlEvaluationState.NotEstablished, ControlUncertainty.None)
        : new(left.State == ControlEvaluationState.Established && right.State == ControlEvaluationState.Established
            ? ControlEvaluationState.Established : ControlEvaluationState.Unknown, left.Uncertainty | right.Uncertainty);
    private static Check Or(Check left, Check right) => left.State == ControlEvaluationState.Established || right.State == ControlEvaluationState.Established
        ? new(ControlEvaluationState.Established, ControlUncertainty.None)
        : new(left.State == ControlEvaluationState.NotEstablished && right.State == ControlEvaluationState.NotEstablished
            ? ControlEvaluationState.NotEstablished : ControlEvaluationState.Unknown, left.Uncertainty | right.Uncertainty);
}
