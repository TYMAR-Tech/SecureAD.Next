using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal enum OwnerServerBehavior
{
    NotRecorded,
    ClassicUpdated,
    ModificationRestricted,
}

internal static class OwnerRightsReading
{
    internal const string OwnerRightsSid = "S-1-3-4";
    internal const string Modification = "AddWholeObjectWriteDaclAllowForOwner";
    private const int WriteDacl = 0x40000;

    internal static UnresolvedReason Reason(ControlUncertainty uncertainty) =>
        (uncertainty & (ControlUncertainty.DescriptorUnreadable | ControlUncertainty.DescriptorIncomplete)) != 0 ? UnresolvedReason.SecurityDescriptorUnreadable
        : (uncertainty & ControlUncertainty.OwnerHeuristicNotRead) != 0 ? UnresolvedReason.OwnerHeuristicNotRead
        : (uncertainty & ControlUncertainty.OwnerServerBehaviorNotRecorded) != 0 ? UnresolvedReason.OwnerServerBehaviorNotRecorded
        : UnresolvedReason.OwnerRightsNotEvaluated;

    internal static string? TargetSid(ObjectAttributes subject)
    {
        var value = subject.Find("objectSid")?.OnlyValue;
        return value?.Bytes is { } bytes ? Sid.ToText(bytes) : value?.Text;
    }

    internal static ControlEvaluationState ComputerClass(ObjectAttributes subject)
    {
        var classes = subject.Find("objectClass")?.Values;
        return classes is null || classes.Count == 0 || classes.Any(value => string.IsNullOrWhiteSpace(value.Text))
            ? ControlEvaluationState.Unknown
            : classes.Any(value => Same(value.Text, "computer")) ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
    }

    internal static (ControlEvaluationState State, ControlUncertainty Uncertainty, IReadOnlyList<ControlPrecondition> Checks) Check(
        ObjectPermissions permissions, PermissionTrustee owner, string? targetSid,
        ControlEvaluationState computerClass, OwnerImplicitRightsSetting? setting,
        ControlEvaluationState requesterExemption, OwnerServerBehavior behavior = OwnerServerBehavior.NotRecorded)
    {
        var independent = Access(permissions, owner, targetSid, includeOwnerGrants: false);
        var ownerEntries = permissions.Entries.Where(entry => Applies(entry) && Same(entry.Trustee.Sid, OwnerRightsSid)).ToArray();
        var descriptorKnown = permissions.Availability == DescriptorAvailability.Read
            && permissions.DaclState != DaclState.Unreadable && permissions.DaclCompleteness == DaclCompleteness.Complete;
        var presence = !descriptorKnown ? ControlEvaluationState.Unknown
            : ownerEntries.Any(entry => !entry.HasObjectType && Supported(entry)) ? ControlEvaluationState.Established
            : ownerEntries.Length == 0 ? ControlEvaluationState.NotEstablished : ControlEvaluationState.Unknown;
        var ownerAccess = Access(permissions, owner, targetSid, includeOwnerGrants: true);
        var implicitAccess = Implicit(computerClass, setting, requesterExemption, behavior);
        var answer = independent.State == ControlEvaluationState.Established ? independent
            : presence == ControlEvaluationState.Established ? ownerAccess
            : presence == ControlEvaluationState.Unknown ? (ControlEvaluationState.Unknown, ControlUncertainty.OwnerRightsOperationNotEvaluated)
            : implicitAccess;
        if (!descriptorKnown)
            answer = (ControlEvaluationState.Unknown, permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable
                ? ControlUncertainty.DescriptorUnreadable : ControlUncertainty.DescriptorIncomplete);
        return (answer.Item1, answer.Item2,
        [
            new("RequestedModification", ControlEvaluationState.Established, Modification),
            new("IndependentWriteDaclOnOwner", independent.State, "MS-DTYP-2.5.3.2;ordered-descriptor"),
            new("OwnerRightsPresent", presence, OwnerRightsSid),
            new("OwnerRightsEvaluation", ownerAccess.State, "MS-DTYP-2.5.3.2;ordered-owner-substitution"),
            new("TargetComputerClass", computerClass, "captured-objectClass-ancestry"),
            new("BlockOwnerImplicitRights", setting?.Value is >= 0 and <= 3 ? ControlEvaluationState.Established : ControlEvaluationState.Unknown,
                setting is null ? "NotRead" : $"{setting.Outcome}:{setting.Character}:{setting.Value}"),
            new("RequesterExemption", requesterExemption, "Domain-Admins-or-Enterprise-Admins;current-authorization"),
            new("ServerBehaviourBaseline", behavior == OwnerServerBehavior.NotRecorded ? ControlEvaluationState.Unknown : ControlEvaluationState.Established, behavior.ToString()),
            new("ImplicitOwnerWriteDacl", implicitAccess.State, "MS-ADTS-6.1.3.4"),
            new("PrivilegeBasedTakeover", ControlEvaluationState.Unknown, "OutOfScope"),
            new("OwnerWouldReceiveWriteDacl", answer.Item1, Modification),
        ]);
    }

    private static (ControlEvaluationState State, ControlUncertainty Uncertainty) Implicit(
        ControlEvaluationState computerClass, OwnerImplicitRightsSetting? setting,
        ControlEvaluationState exemption, OwnerServerBehavior behavior)
    {
        if (computerClass == ControlEvaluationState.NotEstablished)
            return (ControlEvaluationState.Established, ControlUncertainty.None);
        if (computerClass == ControlEvaluationState.Unknown)
            return (ControlEvaluationState.Unknown, ControlUncertainty.TargetClassNotRead);
        if (exemption == ControlEvaluationState.Established)
            return (ControlEvaluationState.Established, ControlUncertainty.None);
        // Neither a heuristic nor an operating-system name proves the serving DC's installed behavior.
        if (behavior == OwnerServerBehavior.NotRecorded || setting?.Value is not (>= 0 and <= 3))
            return (ControlEvaluationState.Unknown,
                (behavior == OwnerServerBehavior.NotRecorded ? ControlUncertainty.OwnerServerBehaviorNotRecorded : ControlUncertainty.None)
                | (setting?.Value is not (>= 0 and <= 3) ? ControlUncertainty.OwnerHeuristicNotRead : ControlUncertainty.None));
        if (behavior == OwnerServerBehavior.ModificationRestricted)
            return (ControlEvaluationState.Unknown, ControlUncertainty.OwnerRightsOperationNotEvaluated);
        if (setting.Value == 1)
            return exemption == ControlEvaluationState.NotEstablished
                ? (ControlEvaluationState.NotEstablished, ControlUncertainty.None)
                : (ControlEvaluationState.Unknown, ControlUncertainty.OwnerRightsOperationNotEvaluated);
        return (ControlEvaluationState.Established, ControlUncertainty.None);
    }

    private static (ControlEvaluationState State, ControlUncertainty Uncertainty) Access(
        ObjectPermissions permissions, PermissionTrustee owner, string? targetSid, bool includeOwnerGrants)
    {
        if (permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
            return (ControlEvaluationState.Unknown, ControlUncertainty.DescriptorUnreadable);
        if (permissions.DaclState == DaclState.Null)
            return (ControlEvaluationState.Established, ControlUncertainty.None);
        var relevant = permissions.Entries.Where(entry => Applies(entry) && (entry.AccessMask & WriteDacl) != 0)
            .Select(entry => entry.Trustee.Sid == "S-1-5-10" && targetSid is not null
                ? entry with { Trustee = entry.Trustee with { Sid = targetSid, WellKnownRole = null } } : entry)
            .Where(entry => includeOwnerGrants || !Same(entry.Trustee.Sid, OwnerRightsSid) || IsDeny(entry)).ToArray();
        bool Own(PermissionEntry entry) => Same(entry.Trustee.Sid, owner.Sid)
            || Same(entry.Trustee.Sid, OwnerRightsSid) || Same(entry.Trustee.Sid, "S-1-1-0");
        var effective = EffectiveAccessCalculator.Over(permissions with
        {
            Entries = relevant.Where(entry => Own(entry) && Supported(entry) && !entry.HasObjectType)
                .Select(entry => entry with { Trustee = owner with { WellKnownRole = null } }).ToArray(),
        }, null);
        var unknown = permissions.DaclCompleteness == DaclCompleteness.Complete ? ControlUncertainty.None : ControlUncertainty.DescriptorIncomplete;
        foreach (var entry in relevant)
        {
            var own = Own(entry);
            if (!own && !IsDeny(entry)) continue;
            if (own && Supported(entry) && !entry.HasObjectType) break;
            if (!own) unknown |= ControlUncertainty.CrossTrusteeDeny;
            if (!Supported(entry)) unknown |= ControlUncertainty.ConditionalOrUnsupportedAce;
            if (entry.HasObjectType) unknown |= ControlUncertainty.ObjectSpecificScopeNotEvaluated;
        }
        var granted = effective.Holders.Any(holder => Same(holder.Trustee.Sid, owner.Sid) && (holder.Mask & WriteDacl) != 0);
        return (unknown != ControlUncertainty.None ? ControlEvaluationState.Unknown
            : granted ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished, unknown);
    }

    private static bool Applies(PermissionEntry entry) => EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject;
    private static bool Supported(PermissionEntry entry) => entry.AceType is "AccessAllowed" or "AccessDenied" or "AccessAllowedObject" or "AccessDeniedObject";
    private static bool IsDeny(PermissionEntry entry) => entry.AceType.Contains("Denied", StringComparison.Ordinal);
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
