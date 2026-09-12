using System.Globalization;
using System.Resources;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class OwnershipControlDeriver
{
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.OwnershipControl", typeof(OwnershipControlDeriver).Assembly);

    internal static ControlUncertainty Add(ObjectAttributes subject, ObjectPermissions permissions, JudgingContext context,
        Guid generation, Guid? derivationGeneration, Func<string, string?> domainSid, List<ControlEdge> edges)
    {
        var eligibility = ObjectOwnershipReading.Eligibility(subject, context with { Permissions = _ => permissions });
        if (eligibility.Outcome == ObjectOwnershipOutcome.OwnerIsAccepted || eligibility.Evidence?.IsOrphaned == true)
            return ControlUncertainty.None;
        if (permissions.Owner is not { } owner || string.IsNullOrWhiteSpace(owner.Sid))
            return ControlUncertainty.HolderUnresolved;
        var eligible = eligibility.Outcome == ObjectOwnershipOutcome.OwnerIsNotAccepted && eligibility.Evidence?.IsComplete == true
            ? ControlEvaluationState.Established : ControlEvaluationState.Unknown;
        var scope = Sid.IsBuiltinDomain(owner.Sid) ? subject.DomainFqdn : null;
        var routes = context.ProtectedPrincipals?.Lookup(owner.Sid, scope)?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
        var expected = ControlEdgeDeriver.Expected(owner, subject, context.ForestFqdn, routes,
            permissions.DaclCompleteness == DaclCompleteness.Complete, false, domainSid);
        var proof = Source(subject, permissions, context, owner, eligible,
            eligible == ControlEvaluationState.Established ? ControlEvaluationState.NotEstablished : ControlEvaluationState.Unknown,
            ControlEvaluationState.NotEstablished, ControlUncertainty.None);
        var edge = Rebuild(new(0, subject.ObjectGuid, subject.DistinguishedName,
            subject.Find("objectClass")?.Values.LastOrDefault()?.Text, owner.Sid, owner.Name, scope,
            ControlCapability.IsOwnerAndCanRewriteDacl, ControlEvaluationState.Unknown, ControlUncertainty.None,
            expected.State, expected.Reason, PrincipalClassificationRegistry.Version, generation, derivationGeneration,
            false, permissions.Entries, [], routes) { DescriptorOutcome = DescriptorOutcome(permissions) }, proof);
        edges.Add(edge);
        return edge.EvaluationState == ControlEvaluationState.Unknown ? edge.Uncertainty : ControlUncertainty.None;
    }

    internal static ControlEdge Transition(ControlEdge primitive, ObjectAttributes subject, ObjectPermissions permissions,
        JudgingContext context, PermissionTrustee holder, Func<string, string?> domainSid)
    {
        var proof = Source(subject, permissions, context, holder, ControlEvaluationState.Unknown,
            Exemption(holder.Sid, primitive.MembershipRoutes, subject, context.ForestFqdn, domainSid),
            primitive.EvaluationState, primitive.Uncertainty);
        return Rebuild(primitive with
        {
            Capability = ControlCapability.CanBecomeOwnerAndRewriteDacl,
            Evidence = permissions.Entries,
            Expectedness = holder.Sid == "S-1-5-18" ? ControlExpectedness.Unknown : primitive.Expectedness,
            ExpectednessReason = holder.Sid == "S-1-5-18" ? ControlExpectednessReason.UnknownCapabilityScope : primitive.ExpectednessReason,
        }, proof);
    }

    internal static void ValidateStored(ControlEdge edge)
    {
        if (edge.Capability is not (ControlCapability.IsOwnerAndCanRewriteDacl or ControlCapability.CanBecomeOwnerAndRewriteDacl)) return;
        var sources = edge.Preconditions.Where(item => item.Name == "OwnerSource").ToArray();
        if (sources.Length != 1 || sources[0].State != ControlEvaluationState.Established) throw InvalidProof();
        OwnerSource? source;
        try { source = JsonSerializer.Deserialize<OwnerSource>(sources[0].EvidenceSource); }
        catch (JsonException error) { throw new InvalidOperationException(Text("InvalidProof"), error); }
        if (source is null || source.Holder is null || source.Classes is null
            || source.Target != edge.Target || source.TargetGuid != edge.TargetGuid || source.Holder.Sid != edge.HolderSid
            || source.Classes.LastOrDefault() != edge.TargetClass
            || !Enum.IsDefined(source.Availability) || !Enum.IsDefined(source.Dacl) || !Enum.IsDefined(source.Completeness)
            || !Enum.IsDefined(source.Eligible) || !Enum.IsDefined(source.Exemption) || !Enum.IsDefined(source.CanSetOwner)
            || !ValidSetting(source.Setting)
            || edge.Capability == ControlCapability.IsOwnerAndCanRewriteDacl && source.CapturedOwnerSid != edge.HolderSid
            || edge.Evidence.Select(item => item.Ordinal).Distinct().Count() != edge.Evidence.Count)
            throw InvalidProof();
        if (edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl && source.CanSetOwner == ControlEvaluationState.Established)
        {
            var permissions = Permissions(edge, source);
            var access = EffectiveAccessCalculator.Over(permissions with
            {
                Entries = permissions.Entries.Select(entry => entry.Trustee.Sid == "S-1-5-10" && source.TargetSid is not null
                    ? entry with { Trustee = entry.Trustee with { Sid = source.TargetSid, WellKnownRole = null } } : entry).ToArray(),
            }, null);
            if (access.Outcome != EffectiveAccessOutcome.GrantsEveryoneEverything
                && !access.Holders.Any(item => item.Trustee.Sid == edge.HolderSid && (item.Mask & 0x80000) != 0)) throw InvalidProof();
        }
        var replayed = Rebuild(edge, source);
        if (edge.EvaluationState != replayed.EvaluationState || edge.Uncertainty != replayed.Uncertainty
            || edge.IsCounted != replayed.IsCounted || edge.DescriptorOutcome != DescriptorOutcome(Permissions(edge, source))
            || !edge.Preconditions.SequenceEqual(replayed.Preconditions)) throw InvalidProof();
    }

    private static ControlEdge Rebuild(ControlEdge edge, OwnerSource source)
    {
        var classes = source.Classes;
        var computer = classes.Length == 0 || classes.Any(string.IsNullOrWhiteSpace) ? ControlEvaluationState.Unknown
            : classes.Any(value => string.Equals(value, "computer", StringComparison.OrdinalIgnoreCase))
                ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
        var rights = OwnerRightsReading.Check(Permissions(edge, source), source.Holder, source.TargetSid,
            computer, source.Setting, source.Exemption);
        var transition = edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl;
        var uncertainty = rights.Uncertainty;
        var definition = PrincipalClassificationRegistry.For(source.Holder.Sid);
        if (!definition.IdentityIsValid || !source.Holder.HoldsThePermission) uncertainty |= ControlUncertainty.HolderUnresolved;
        if (!source.DomainContextVerified) uncertainty |= ControlUncertainty.ResourceContextUnverified;
        if (transition) uncertainty |= source.PrimitiveUncertainty | ControlUncertainty.OwnerTransitionLabRequired;
        else if (source.Eligible != ControlEvaluationState.Established) uncertainty |= ControlUncertainty.OwnerEligibilityNotEstablished;
        var state = transition || uncertainty != ControlUncertainty.None ? ControlEvaluationState.Unknown : rights.State;
        return edge with
        {
            EvaluationState = state,
            Uncertainty = uncertainty,
            IsCounted = !transition && state == ControlEvaluationState.Established,
            Preconditions =
            [
                new("OwnerSource", ControlEvaluationState.Established, JsonSerializer.Serialize(source)),
                new("OwnerEligibility", source.Eligible, transition ? "NotAnExistingOwnerClaim" : "0095;0107;0109;captured-owner-and-derived-acceptance"),
                .. transition ? new ControlPrecondition[]
                {
                    new("CanSetOwner", source.CanSetOwner, "stored-descriptor;independent-primitive"),
                    new("CanSetTakeoverOwnerSid", ControlEvaluationState.Unknown, "0103;SPEC-stage-6-13.1;laboratory-gate"),
                } : [],
                .. rights.Checks,
            ],
        };
    }

    private static ObjectPermissions Permissions(ControlEdge edge, OwnerSource source) => new(edge.Target, source.Availability, null,
        source.CapturedOwnerSid is { } sid ? source.Holder with { Sid = sid } : null,
        source.Dacl, source.Completeness, true, false, edge.Evidence, []);

    private static OwnerSource Source(ObjectAttributes subject, ObjectPermissions permissions, JudgingContext context,
        PermissionTrustee holder, ControlEvaluationState eligible, ControlEvaluationState exemption,
        ControlEvaluationState canSetOwner, ControlUncertainty primitiveUncertainty) => new(
            subject.DistinguishedName, subject.ObjectGuid, permissions.Owner?.Sid, OwnerRightsReading.TargetSid(subject),
            subject.Find("objectClass")?.Values.Select(value => value.Text).ToArray() ?? [], holder,
            permissions.Availability, permissions.DaclState, permissions.DaclCompleteness, context.OwnerImplicitRights,
            eligible, exemption, canSetOwner, primitiveUncertainty,
            !Sid.IsBuiltinDomain(holder.Sid) || ControlEdgeDeriver.IsDomainTarget(subject, context.ForestFqdn));

    private static ControlEvaluationState Exemption(string holder, MembershipRouteSummary routes, ObjectAttributes subject,
        string? forest, Func<string, string?> domainSid)
    {
        var domain = subject.DomainFqdn is { } targetDomain && ControlEdgeDeriver.IsDomainTarget(subject, forest) ? domainSid(targetDomain) : null;
        var root = forest is null ? null : domainSid(forest);
        bool Exempt(string sid) => domain is not null && sid == domain + "-512" || root is not null && sid == root + "-519";
        if (Exempt(holder) || routes.Memberships.SelectMany(group => group.Routes).Any(route =>
            route.Authorization == MembershipRouteAuthorization.SecurityEnabled && route.Steps.FirstOrDefault()?.Principal.Sid == holder
            && route.Steps.LastOrDefault()?.Principal.Sid is { } sid && Exempt(sid))) return ControlEvaluationState.Established;
        return ControlEvaluationState.Unknown;
    }

    private static string DescriptorOutcome(ObjectPermissions permissions) => EffectiveAccessCalculator.Over(permissions, null).Outcome.ToString();
    private static bool ValidSetting(OwnerImplicitRightsSetting? setting) => setting is null || (setting.Outcome switch
    {
        HeuristicReadOutcome.NotRead => setting.Value is null && setting.Character is null,
        HeuristicReadOutcome.DefaultedByAbsence => setting.Value == 0 && setting.Character == '0',
        HeuristicReadOutcome.Stated => setting.Character is >= '0' and <= '3' && setting.Value == setting.Character - '0',
        HeuristicReadOutcome.Malformed => setting.Value == 1 && setting.Character is { } character && character is not (>= '0' and <= '3'),
        _ => false,
    });
    private static InvalidOperationException InvalidProof() => new(Text("InvalidProof"));
    private static string Text(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(key);

    private sealed record OwnerSource(string Target, Guid? TargetGuid, string? CapturedOwnerSid, string? TargetSid,
        string?[] Classes, PermissionTrustee Holder, DescriptorAvailability Availability, DaclState Dacl,
        DaclCompleteness Completeness, OwnerImplicitRightsSetting? Setting, ControlEvaluationState Eligible,
        ControlEvaluationState Exemption, ControlEvaluationState CanSetOwner, ControlUncertainty PrimitiveUncertainty,
        bool DomainContextVerified);
}
