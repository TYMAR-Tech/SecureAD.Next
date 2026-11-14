using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-060: broad identity attribution behind separately evaluated permission-changing rights.</summary>
public sealed class BroadPrincipalCanTakeOverObject : IObjectRule
{
    private const string RuleId = "SEC-060";
    internal const int RuleVersion = 3;

    public RuleDefinition Definition { get; } = new(RuleId, SavedPermissionControl.Title, Severity.High, RuleVersion,
        SubjectClasses: [], RequiredAttributes: ["objectClass"],
        RequiredDerivedFacts: [nameof(DerivedFactKind.PrincipalExpansion)]);

    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-060 requires its declared permission and membership inputs.");

    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (context.MembersOfPrincipal is not { } expand || context.PermissionControlInputs is not { } inputs)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        if (context.Permissions?.Invoke(subject.DistinguishedName) is not { } permissions
            || permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.SecurityDescriptorUnreadable)]);
        if (subject.ObjectGuid is not { } guid || guid == Guid.Empty)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);
        inputs.RequireFor(subject, permissions);
        if (permissions.DaclState is DaclState.Null or DaclState.Empty && permissions.Entries.Count != 0)
            throw new InvalidDataException("The permission-control descriptor state contradicts its entries.");

        var targetSid = OwnerRightsReading.TargetSid(subject);
        var candidates = new Dictionary<string, Candidate>(StringComparer.OrdinalIgnoreCase);
        var standardEntries = new List<PermissionEntry>();
        var unresolved = new HashSet<UnresolvedInput>();
        foreach (var entry in permissions.Entries)
        {
            if (!FullControlEvaluator.Applies(entry)) continue;
            if ((entry.AccessMask & (GenericRightsExpander.WriteDacl | GenericRightsExpander.WriteOwner)) != 0)
                standardEntries.Add(entry);
            if (FullControlEvaluator.IsDeny(entry)) continue;
            if (entry.Trustee.Sid == "S-1-5-10" && targetSid is null
                && (entry.AccessMask & (GenericRightsExpander.WriteDacl | GenericRightsExpander.WriteOwner)) != 0)
            {
                unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.IdentityUnreadable));
                continue;
            }
            var holder = entry.Trustee.Sid == "S-1-5-10" && targetSid is not null
                ? entry.Trustee with { Sid = targetSid, DistinguishedName = subject.DistinguishedName, WellKnownRole = null }
                : entry.Trustee;
            if (!holder.HoldsThePermission || holder.Sid is "S-1-3-0" or "S-1-3-4") continue;
            if (candidates.TryGetValue(holder.Sid, out var candidate))
                candidates[holder.Sid] = candidate with { Mask = candidate.Mask | entry.AccessMask };
            else candidates.Add(holder.Sid, new(holder, entry.AccessMask));
        }
        if (permissions.DaclState == DaclState.Null)
            candidates.Add("S-1-1-0", new(new("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null),
                FullControlEvaluator.RequiredMask));

        var pending = new Dictionary<string, Pending>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates.Values)
        {
            if ((candidate.Mask & (GenericRightsExpander.WriteDacl | GenericRightsExpander.WriteOwner)) == 0) continue;
            var expansion = PrincipalExpansionReading.MembersOfTrustee(expand, candidate.Holder, subject.DomainFqdn);
            if (expansion.Outcome == PrincipalExpansionOutcome.PrincipalNotFound)
                unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived));
            else if (expansion.Outcome != PrincipalExpansionOutcome.PrincipalDoesNotExist && !expansion.IsComplete)
                unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.MembershipIncomplete));
            Func<string, bool, PermissionControlCalculation>? assess = null;
            if (BroadPrincipalCatalogue.IsBroad(candidate.Holder.Sid))
                Assess(candidate.Holder.Sid, [candidate.Holder.Sid], expansion.IsComplete);
            foreach (var member in expansion.BroadMembers)
                Assess(member.Sid, member.PathFromRoot, expansion.IsComplete && member.IsComplete);

            void Assess(string broad, IReadOnlyList<string> path, bool membershipComplete)
            {
                assess ??= inputs.Prepare(subject, permissions, context, candidate.Holder, candidate.Mask, standardEntries);
                var calculation = assess(broad, membershipComplete);
                var right = calculation.FullControl.State == PermissionControlState.Established ? ObjectTakeoverRight.GenericAll
                    : calculation.ModifyPermissions.State == PermissionControlState.Established ? ObjectTakeoverRight.WriteDacl
                    : calculation.ChangeOwner.State == PermissionControlState.Established ? ObjectTakeoverRight.WriteOwner
                    : (ObjectTakeoverRight?)null;
                if (!calculation.IsComplete)
                    unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.PermissionControlNotEvaluated));
                if (right is null) return;
                if (pending.TryGetValue(broad, out var existing)
                    && (right.Value > existing.Right || right == existing.Right && path.Count >= existing.Path.Count)) return;
                pending[broad] = new(candidate.Holder, broad, path, right.Value, membershipComplete, calculation);
            }
        }
        if (permissions.DaclCompleteness != DaclCompleteness.Complete)
            unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.SecurityDescriptorIncomplete));
        if (pending.Count == 0)
            return unresolved.Count == 0 ? RuleVerdict.Judged([]) : RuleVerdict.CouldNotResolve(unresolved.OrderBy(value => value.Reason).ToArray());
        var limitations = unresolved.Select(value => value.Reason.ToString()).Distinct().Order(StringComparer.Ordinal).ToArray();
        return RuleVerdict.Judged(pending.Values.Select(value =>
        {
            var evidence = new ObjectTakeoverEvidence(value.Holder.Sid, value.Holder.Name ?? Name(value.Holder.Sid),
                value.Broad, Name(value.Broad), value.Path.Select(sid => new PathStep(sid, Name(sid))).ToArray(),
                value.Right, InheritedFrom: null, value.MembershipComplete)
            {
                Calculation = value.Calculation with { Limitations = limitations },
            };
            return new Finding(RuleId, RuleVersion, Severity.High,
                new(FindingSubjectKind.Account, SubjectKeyFor(value.Broad)), guid, subject.DistinguishedName,
                subject.DomainFqdn ?? "", AttributeReading.LastText(subject, "objectClass") ?? "",
                SavedPermissionControl.Statement, subject.Completeness, evidence);
        }).ToArray());

        string? Name(string sid) => BroadPrincipalCatalogue.NameOf(sid) ?? context.PrincipalNames?.Invoke(sid);
    }

    internal static string SubjectKeyFor(string sid) =>
        BroadPrincipalCatalogue.NameOf(sid) is { } known ? $"{known} ({sid})" : sid;

    private sealed record Candidate(PermissionTrustee Holder, int Mask);
    private sealed record Pending(PermissionTrustee Holder, string Broad, IReadOnlyList<string> Path,
        ObjectTakeoverRight Right, bool MembershipComplete, PermissionControlCalculation Calculation);
}
