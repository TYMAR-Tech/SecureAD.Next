using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed record PermissionControlInputs(Guid GenerationId, Tier0InputBinding Binding,
    Func<string, string?> DomainSid)
{
    internal Guid RequireFor(ObjectAttributes subject, ObjectPermissions permissions)
    {
        if (GenerationId == Guid.Empty || !Binding.IsSupported || subject.ObjectGuid is not { } guid || guid == Guid.Empty
            || permissions.DistinguishedName != subject.DistinguishedName)
            throw new InvalidDataException("The permission-control inputs do not match their source or target.");
        return guid;
    }

    internal Func<string, bool, PermissionControlCalculation> Prepare(ObjectAttributes subject, ObjectPermissions permissions,
        JudgingContext context, PermissionTrustee holder, int candidateMask, IReadOnlyList<PermissionEntry> standardEntries)
    {
        var guid = RequireFor(subject, permissions);
        var holderScope = Sid.IsBuiltinDomain(holder.Sid) ? subject.DomainFqdn : null;
        var source = new FullControlSource(subject.DistinguishedName, guid, OwnerRightsReading.TargetSid(subject),
            subject.DomainFqdn, subject.Find("objectClass")?.Values.Select(value => value.Text).OfType<string>().ToArray() ?? [],
            holder, holderScope, !Sid.IsBuiltinDomain(holder.Sid)
                || ControlEdgeDeriver.IsDomainTarget(subject, context.ForestFqdn) && subject.DomainFqdn is { } domain
                    && !string.IsNullOrWhiteSpace(DomainSid(domain)),
            context.NamingContexts?.ContainsKey(subject.DistinguishedName) == true,
            permissions.Availability, permissions.DaclState, permissions.DaclCompleteness,
            permissions.DaclWasCanonical, permissions.Entries);
        var standard = source with { Entries = standardEntries };
        var fullRight = new Lazy<PermissionControlRightAssessment>(() =>
        {
            if ((candidateMask & FullControlEvaluator.RequiredMask) != FullControlEvaluator.RequiredMask)
                return new(PermissionControlState.NotEstablished, [], [], []);
            var full = FullControlEvaluator.AssessFullControl(source, GenerationId, Binding.DerivationGenerationId,
                ControlExpectedness.Unknown, ControlExpectednessReason.UnknownCapabilityScope, []);
            return new(State(full.EvaluationState),
                full.Rights.SelectMany(right => right.GrantOrdinals).Distinct().Order().ToArray(),
                full.Rights.SelectMany(right => right.BlockingOrdinals).Distinct().Order().ToArray(), Limits(full.Uncertainty));
        }, LazyThreadSafetyMode.None);
        var owner = new Lazy<(ControlEvaluationState State, ControlUncertainty Uncertainty, IReadOnlyList<ControlPrecondition> Checks)>(() =>
        {
            // This all-object rule must not load undeclared administrator routes for a hypothetical requester.
            var exemption = OwnershipControlDeriver.Exemption(holder.Sid, MembershipRouteSummary.NotDerived,
                subject, context.ForestFqdn, DomainSid);
            return OwnerRightsReading.Check(permissions, holder, source.TargetSid,
                OwnerRightsReading.ComputerClass(subject), context.OwnerImplicitRights, exemption);
        }, LazyThreadSafetyMode.None);
        return (broadSid, membershipQualified) =>
        {
            bool? MatchDeny(PermissionEntry entry)
            {
                var sid = entry.Trustee.Sid == "S-1-5-10" ? source.TargetSid : entry.Trustee.Sid;
                if (membershipQualified && Same(sid, broadSid)) return true;
                // This set inclusion does not construct an individual token or assume anonymous membership.
                if (Same(sid, "S-1-1-0") && Same(broadSid, "S-1-5-11")) return true;
                return null;
            }
            var modify = FullControlEvaluator.AssessStandardRight(standard, GenericRightsExpander.WriteDacl, MatchDeny);
            var changeOwner = FullControlEvaluator.AssessStandardRight(standard, GenericRightsExpander.WriteOwner, MatchDeny);
            var ownerState = PermissionControlState.NotEstablished;
            var transition = PermissionControlState.NotEstablished;
            PermissionControlCondition[] conditions = [];
            if (changeOwner.State != ControlEvaluationState.NotEstablished)
            {
                ownerState = State(owner.Value.State);
                transition = PermissionControlState.Unknown;
                conditions = [.. owner.Value.Checks.Select(check => new PermissionControlCondition(check.Name, State(check.State),
                    check.Name == "RequesterExemption" && check.State == ControlEvaluationState.Unknown
                        ? "NamedHolderIdentityOnly;indirect-requester-authorization-not-assessed" : check.EvidenceSource)),
                    new("ControlledOwnerSidTransition", PermissionControlState.Unknown, "OwnerTransitionLabRequired")];
            }
            var supporting = modify.State == ControlEvaluationState.Established ? modify.GrantOrdinals : changeOwner.GrantOrdinals;
            var inherited = supporting.Count != 0 && permissions.Entries.First(entry => entry.Ordinal == supporting[0]).IsInherited;
            return new(GenerationId, Binding.EvidenceSeal, Binding.DerivationGenerationId, Binding.DerivationSeal,
                guid, subject.DistinguishedName, subject.DomainFqdn, holder.Sid, holderScope, broadSid,
                permissions.DaclState, permissions.DaclCompleteness, permissions.DaclWasCanonical,
                Right(modify), Right(changeOwner), fullRight.Value, ownerState, transition, conditions, [], inherited);
        };
    }

    private static PermissionControlRightAssessment Right(FullControlRight right) =>
        new(State(right.State), right.GrantOrdinals, right.BlockingOrdinals, Limits(right.Uncertainty));

    private static string[] Limits(ControlUncertainty uncertainty) => Enum.GetValues<ControlUncertainty>()
        .Where(value => value != ControlUncertainty.None && (uncertainty & value) == value)
        .Select(value => value.ToString()).ToArray();

    private static PermissionControlState State(ControlEvaluationState state) => state switch
    {
        ControlEvaluationState.Established => PermissionControlState.Established,
        ControlEvaluationState.NotEstablished => PermissionControlState.NotEstablished,
        ControlEvaluationState.Unknown => PermissionControlState.Unknown,
        _ => throw new InvalidDataException("The permission-control conclusion is not supported."),
    };

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
