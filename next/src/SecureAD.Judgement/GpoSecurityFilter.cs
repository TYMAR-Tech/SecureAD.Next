using System.Collections.Immutable;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal enum GpoSecurityDecision { Unresolved, Excluded, Included }

internal sealed record GpoMembershipWitness(CapturedObjectIdentity Member, CapturedObjectIdentity Group,
    string Attribute, int Ordinal, string Value, long GroupType);

internal sealed record GpoTrusteeCheck(string Sid, bool? Matches, string Reason,
    ImmutableArray<GpoMembershipWitness> Route);

/// <summary>Directory Read/Apply only, never WMI applicability, policy precedence or client execution.</summary>
internal sealed record GpoSecurityAssessment(Guid CaptureGenerationId, string EvidenceSeal, Guid? DerivationGenerationId,
    CapturedObjectIdentity Computer, CapturedObjectIdentity Policy, ObjectAttributes ComputerValues,
    ObjectAttributes PolicyValues, ObjectPermissions Permissions, FullControlRight ReadControl,
    FullControlRight ReadProperties, FullControlRight ApplyGroupPolicy, ControlEvaluationState Read,
    GpoSecurityDecision Decision, ImmutableArray<GpoTrusteeCheck> Trustees, ImmutableArray<AuditError> Limitations);

internal static class GpoCapturedIdentity
{
    internal static CapturedObjectIdentity Normalize(CapturedObjectIdentity identity, ObjectAttributes values) => identity with
    {
        DistinguishedName = values.DistinguishedName, ObjectGuid = values.ObjectGuid,
        DomainFqdn = values.DomainFqdn, ObjectClass = AttributeReading.LastText(values, "objectClass"),
        PrincipalSid = RequesterTrusteeReading.SidOf(values),
    };
}

internal sealed class GpoSecurityFilterReader : IDisposable
{
    private static readonly string ApplyRight = SchemaGuidCatalog.Embedded.GuidFor("Apply-Group-Policy")
        ?? throw new InvalidOperationException("The shared Apply Group Policy right is missing.");
    private readonly JudgingInputs _sources;
    private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
    private readonly IReadOnlySet<string> _readDomains;
    private readonly Dictionary<string, string?> _domainSids = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(long Computer, string Resource), GpoComputerMembership> _memberships = [];
    private long? _membershipComputer;
    private DerivationReader? _derivation;
    private bool _disposed;

    private GpoSecurityFilterReader(JudgingInputs sources, IReadOnlyDictionary<string, NamingContextKind> contexts,
        IReadOnlySet<string> readDomains) => (_sources, _contexts, _readDomains) = (sources, contexts, readDomains);

    internal BundleReader Bundle => _sources.Bundle;

    internal void RequireCurrent() => _sources.RequireCurrent();

    internal static Result<GpoSecurityFilterReader> Open(string directory, CancellationToken cancellationToken) =>
        Open(JudgingInputs.Open(directory, cancellationToken));

    internal static Result<GpoSecurityFilterReader> Open(ProtectedRunFiles files, CancellationToken cancellationToken) =>
        Open(JudgingInputs.Open(files, cancellationToken));

    private static Result<GpoSecurityFilterReader> Open(Result<JudgingInputs> opened)
    {
        if (!opened.IsSuccess) return Result<GpoSecurityFilterReader>.Failure(opened.Error);
        var accepted = false;
        try
        {
            var contexts = opened.Value.ReadNamingContexts();
            if (!contexts.IsSuccess) return Result<GpoSecurityFilterReader>.Failure(contexts.Error);
            var scope = opened.Value.Bundle.ReadScope();
            if (!scope.IsSuccess) return Result<GpoSecurityFilterReader>.Failure(scope.Error);
            var result = new GpoSecurityFilterReader(opened.Value, contexts.Value,
                scope.Value.Domains.Where(domain => domain.Outcome == DomainReadOutcome.Read)
                    .Select(domain => domain.DomainFqdn).ToImmutableHashSet(StringComparer.OrdinalIgnoreCase));
            accepted = true;
            return result;
        }
        finally { if (!accepted) opened.Value.Dispose(); }
    }

    internal GpoSecurityAssessment Assess(CapturedObjectIdentity computer, CapturedObjectIdentity policy,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        _sources.RequireCurrent();
        if (_membershipComputer != computer.ObjectId)
        {
            _memberships.Clear();
            _membershipComputer = computer.ObjectId;
        }
        if (_derivation is null) _memberships.Clear();
        var computerValues = Bundle.ReadObjectAttributesAt(computer,
            ["objectClass", "objectSid", "primaryGroupID", "sIDHistory", "userAccountControl"]).Snapshot();
        var policyValues = Bundle.ReadGpoPolicyValues(policy, ["objectClass", "objectSid"], cancellationToken);
        computer = GpoCapturedIdentity.Normalize(computer, computerValues);
        policy = GpoCapturedIdentity.Normalize(policy, policyValues);
        var permissions = Bundle.ReadPermissionsAt(policy);
        permissions = permissions with
        {
            Entries = permissions.Entries.Select(entry => entry with { ApplicationData = entry.ApplicationData.ToArray() }).ToImmutableArray(),
            Errors = permissions.Errors.ToImmutableArray(),
        };
        var limitations = new List<AuditError>();
        var trustees = new Dictionary<string, GpoTrusteeCheck>(StringComparer.OrdinalIgnoreCase);
        var unknown = new FullControlRight(0x20000, null, ControlEvaluationState.Unknown,
            ControlUncertainty.ResourceContextUnverified, [], []);
        var readControl = unknown;
        var readProperties = unknown with { Mask = 0x10 };
        var apply = unknown with { Mask = 0x100, ObjectType = ApplyRight };
        var sid = RequesterTrusteeReading.SidOf(computerValues);
        if (computer.ObjectGuid is null || computer.ObjectGuid == Guid.Empty || sid is null
            || PrincipalClassificationRegistry.DomainRid(sid) is null
            || !string.Equals(AttributeReading.LastText(computerValues, "objectClass"), "computer", StringComparison.OrdinalIgnoreCase))
            return Finish("GpoSecurityComputerIdentityUnavailable", "The captured requester is not a qualified current computer identity.");
        if (policy.ObjectGuid is null || policy.ObjectGuid == Guid.Empty
            || !string.Equals(AttributeReading.LastText(policyValues, "objectClass"), "groupPolicyContainer", StringComparison.OrdinalIgnoreCase))
            return Finish("GpoSecurityPolicyIdentityUnavailable", "The captured target is not an identifiable Group Policy object.");
        var computerDomainSid = DomainSid(computer.DomainFqdn);
        if (computerDomainSid is null || DomainSid(policy.DomainFqdn) is null
            || !Same(Sid.IssuingDomain(sid), computerDomainSid)
            || RequesterTrusteeReading.ReadSameForest(computerValues, policyValues,
                new("S-1-1-0", null, null, null, null, null, null), null,
                Bundle.Description.ForestFqdn, _readDomains).State != RequesterTrusteeState.Matches)
            return Finish("GpoSecurityResourceContextUnavailable", "The computer and policy do not have qualified captured same-forest domain context.");
        if (permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
            return Finish("GpoSecurityDescriptorUnavailable", permissions.UnreadableReason ?? "The captured GPO descriptor is unreadable.");
        if (permissions.DaclState == DaclState.Null)
            return Finish("GpoSecurityNullDaclUnqualified", "A NULL DACL on this maintained directory object is outside the qualified GPO profile.");
        if (permissions.DaclState == DaclState.Empty && permissions.Entries.Count != 0
            || permissions.Entries.Select(entry => entry.Ordinal).Distinct().Count() != permissions.Entries.Count
            || !permissions.Entries.Select(entry => entry.Ordinal).SequenceEqual(permissions.Entries.Select(entry => entry.Ordinal).Order()))
            return Finish("GpoSecurityDescriptorInvalid", "The descriptor state or original permission order is inconsistent.");
        var key = (computer.ObjectId, policy.DomainFqdn!.ToUpperInvariant());
        if (!_memberships.TryGetValue(key, out var membership))
            _memberships.Add(key, membership = new(Bundle, OpenMemberships, computer, computerValues, policyValues,
                Bundle.Description.ForestFqdn, _readDomains, DomainSid));
        var holder = new PermissionTrustee(sid, null, computer.DistinguishedName, computer.DomainFqdn, null, null, null);
        var source = new FullControlSource(policy.DistinguishedName, policy.ObjectGuid,
            RequesterTrusteeReading.SidOf(policyValues), policy.DomainFqdn,
            policyValues.Find("objectClass")!.Values.Select(value => value.Text).OfType<string>().ToArray(),
            holder, policy.DomainFqdn, true, false, permissions.Availability, permissions.DaclState,
            permissions.DaclCompleteness, permissions.DaclWasCanonical, permissions.Entries);
        bool? Match(PermissionEntry entry)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (trustees.TryGetValue(entry.Trustee.Sid, out var known)) return known.Matches;
            var answer = entry.Trustee.Sid == "S-1-3-4"
                ? permissions.Owner is { } owner ? membership.Match(owner, cancellationToken) with { Sid = entry.Trustee.Sid }
                    : new GpoTrusteeCheck(entry.Trustee.Sid, null, "Owner identity is unavailable.", [])
                : membership.Match(entry.Trustee, cancellationToken);
            trustees.Add(entry.Trustee.Sid, answer);
            return answer.Matches;
        }
        static ControlEvaluationState WholeRead(PermissionEntry entry) => entry.HasObjectType
            ? ControlEvaluationState.Unknown : ControlEvaluationState.Established;
        var applyGuid = Guid.Parse(ApplyRight);
        ControlEvaluationState ApplyScope(PermissionEntry entry) => !entry.HasObjectType ? ControlEvaluationState.Established
            : !Guid.TryParse(entry.ObjectTypeGuid, out var guid) || guid == Guid.Empty ? ControlEvaluationState.Unknown
            : guid == applyGuid ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished;
        readControl = FullControlEvaluator.AssessRequesterRight(source, 0x20000, WholeRead, Match);
        readProperties = FullControlEvaluator.AssessRequesterRight(source, 0x10, WholeRead, Match);
        apply = FullControlEvaluator.AssessRequesterRight(source, 0x100, ApplyScope, Match) with { ObjectType = ApplyRight };
        if (readControl.State != ControlEvaluationState.Established && permissions.Owner is { } recordedOwner
            && membership.Match(recordedOwner, cancellationToken).Matches != false)
        {
            readControl = readControl with
            {
                State = ControlEvaluationState.Unknown,
                Uncertainty = readControl.Uncertainty | ControlUncertainty.OwnerRightsOperationNotEvaluated,
            };
            limitations.Add(Error("GpoSecurityOwnerReadUnqualified",
                "The possible owner's implicit Read Control permission is outside this assessment."));
        }
        if (permissions.Entries.Any(entry => ((uint)entry.AccessMask & 0xf0000000U) != 0
            && FullControlEvaluator.Applies(entry) && Match(entry) != false))
        {
            readControl = Unqualified(readControl);
            readProperties = Unqualified(readProperties);
            apply = Unqualified(apply);
            limitations.Add(Error("GpoSecurityStoredGenericRightsUnsupported", "Stored generic bits were not remapped into established specific permissions."));
        }
        return Finish(null, null);

        GpoSecurityAssessment Finish(string? reason, string? description)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reason is not null) limitations.Add(Error(reason, description!));
            foreach (var proof in new[] { readControl, readProperties, apply })
                if (proof.State == ControlEvaluationState.Unknown)
                    limitations.Add(Error("GpoSecurityRightUnresolved", $"Directory right 0x{proof.Mask:X} is unresolved: {proof.Uncertainty}."));
            foreach (var trustee in trustees.Values.Where(value => value.Matches is null))
                limitations.Add(Error("GpoSecurityTrusteeUnresolved", $"{trustee.Sid}: {trustee.Reason}"));
            var read = Both(readControl.State, readProperties.State);
            var decision = read == ControlEvaluationState.NotEstablished || apply.State == ControlEvaluationState.NotEstablished
                ? GpoSecurityDecision.Excluded
                : read == ControlEvaluationState.Established && apply.State == ControlEvaluationState.Established
                    ? GpoSecurityDecision.Included : GpoSecurityDecision.Unresolved;
            _sources.RequireCurrent();
            return new(Bundle.Description.CaptureGenerationId, _sources.EvidenceSeal, _derivation?.Description.GenerationId,
                computer, policy, computerValues, policyValues, permissions, readControl, readProperties, apply,
                read, decision, trustees.Values.ToImmutableArray(), limitations.Distinct().ToImmutableArray());
        }
        AuditError Error(string reason, string description) => AuditError.Create(ErrorCategory.Evidence, reason,
            ErrorSeverity.Degraded, description, computer.DistinguishedName + " -> " + policy.DistinguishedName);
    }

    private Result<DerivationReader> OpenMemberships()
    {
        var opened = _sources.OpenMembershipDerivation();
        if (opened.IsSuccess) _derivation = opened.Value;
        return opened;
    }

    private string? DomainSid(string? domain)
    {
        if (domain is null || !_readDomains.Contains(domain)) return null;
        if (_domainSids.TryGetValue(domain, out var known)) return known;
        var roots = _contexts.Where(pair => pair.Value == NamingContextKind.Domain && Same(DnHelper.DnToFqdn(pair.Key), domain)).ToArray();
        string? value = null;
        if (roots.Length == 1 && Bundle.ReadObjectNameMatch(roots[0].Key) is { Ambiguous: false, ObjectId: not null })
        {
            var identity = Bundle.ReadObjectIdentity(roots[0].Key)!;
            var attributes = Bundle.ReadObjectAttributesAt(identity, ["objectClass", "objectSid"]);
            if (identity.ObjectGuid is not null && identity.ObjectGuid != Guid.Empty
                && Same(AttributeReading.LastText(attributes, "objectClass"), "domainDNS"))
                value = RequesterTrusteeReading.SidOf(attributes);
        }
        _domainSids.Add(domain, value);
        return value;
    }

    private static FullControlRight Unqualified(FullControlRight proof) => proof with
    {
        State = ControlEvaluationState.Unknown,
        Uncertainty = proof.Uncertainty | ControlUncertainty.ConditionalOrUnsupportedAce,
    };
    private static ControlEvaluationState Both(ControlEvaluationState left, ControlEvaluationState right) =>
        left == ControlEvaluationState.NotEstablished || right == ControlEvaluationState.NotEstablished
            ? ControlEvaluationState.NotEstablished
            : left == ControlEvaluationState.Established && right == ControlEvaluationState.Established
                ? ControlEvaluationState.Established : ControlEvaluationState.Unknown;
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _sources.Dispose();
    }
}
