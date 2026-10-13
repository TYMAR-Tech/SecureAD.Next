using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-002 reports established unexpected secret-domain-data replication permission on a domain root.</summary>
public sealed class UnexpectedDomainSecretReplication : IObjectRule
{
    internal const string Explanation = "The captured permissions establish Get-Changes and Get-Changes-All for this permission holder "
        + "on the domain naming-context root. These permissions can expose secret domain data.";
    internal const string ScopeNote = "This finding does not establish authorization for an individual group member, that replication occurred, "
        + "credential extraction or a completed path to Tier 0. Filtered-attribute replication and constrained individual-secret replication are separate assessments.";
    internal const string Guidance = "Review the recorded permission holder and original granting entries. "
        + "Confirm whether this replication permission is required before removing an unintended grant; "
        + "removing legitimate replication permissions can disrupt directory replication or dependent services.";
    /// <summary>The approved explanation for this rule's incomplete saved assessment.</summary>
    public static string IncompleteExplanation => "Replication permissions or scoped expectedness could not be fully assessed from the captured evidence. "
        + "Established findings remain evidence of the permissions shown.";

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new("SEC-002", "Unexpected domain-secret replication permission", Severity.Critical, 1,
        ["domainDNS"], ["objectClass", "objectGUID", "objectSid", "nTSecurityDescriptor"],
        [nameof(DerivedFactKind.ProtectedPrincipals), nameof(DerivedFactKind.AdministrativeMembership)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("The replication rule requires its declared prepared permission inputs.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!IsCandidate(subject, context)) return RuleVerdict.Judged([]);
        if (subject.Find("objectClass")?.Values.Any(value => !string.IsNullOrWhiteSpace(value.Text)) != true)
            return RuleVerdict.CouldNotJudge(["objectClass"]);
        if (subject.ObjectGuid is null || subject.ObjectGuid == Guid.Empty) return RuleVerdict.CouldNotJudge(["objectGUID"]);
        return context.ReplicationPermissions is { } assessment ? assessment.For(subject, Definition)
            : RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.ReplicationPermissionIncomplete)]);
    }

    internal static bool IsCandidate(ObjectAttributes subject, JudgingContext context) => context.NamingContexts is { } roots
        ? roots.TryGetValue(subject.DistinguishedName, out var kind) && kind == NamingContextKind.Domain
        : subject.Find("objectClass")?.Values.Any(value => string.Equals(value.Text, "domainDNS", StringComparison.OrdinalIgnoreCase)) != false;

    internal static string Key(string sid, string? scope) => sid.ToUpperInvariant() + ":" + (scope?.ToUpperInvariant() ?? "");
}

internal sealed class ReplicationPermissionAssessment(ObjectAttributes subject, ControlObjectEvaluation permissions,
    JudgingContext context, Tier0InputBinding binding, CapturedMembershipInput input, bool captureComplete,
    bool unsupportedMask, Guid generation)
{
    internal RuleVerdict For(ObjectAttributes offered, RuleDefinition rule)
    {
        if (!ReferenceEquals(offered, subject)) throw new InvalidOperationException("The replication assessment belongs to another captured object.");
        if (!binding.IsSupported || input.DerivationGenerationId != binding.DerivationGenerationId
            || permissions.Target != subject.DistinguishedName
            || permissions.Edges.Any(edge => edge.GenerationId != generation || edge.DerivationGenerationId != binding.DerivationGenerationId
                || edge.Target != subject.DistinguishedName || edge.TargetGuid != subject.ObjectGuid))
            throw new InvalidDataException("The replication assessment does not match its captured object and analysis generation.");
        if (context.NamingContexts is not { } roots || !roots.TryGetValue(subject.DistinguishedName, out var kind)
            || kind != NamingContextKind.Domain || !ControlEdgeDeriver.IsDomainTarget(subject, context.ForestFqdn))
            return Unassessed();
        var target = Tier0Target.From(subject, subject.DistinguishedName);
        var classification = Tier0Classifier.Qualify(binding, target, input, routes: null);
        if (!classification.Supports.Any(support => support.Basis == Tier0Basis.PartitionRoot)) return Unassessed();

        var candidates = permissions.Edges.Where(edge => edge.Capability == ControlCapability.CanReplicateSecretDomainData).ToArray();
        var limits = new HashSet<string>(StringComparer.Ordinal);
        if (!captureComplete) limits.Add("CaptureIncomplete");
        if (unsupportedMask) limits.Add("UnsupportedGenericMask");
        if ((permissions.Uncertainty & (ControlUncertainty.DescriptorIncomplete | ControlUncertainty.DescriptorUnreadable
            | ControlUncertainty.ReplicationRootNotEstablished)) != 0) limits.Add(permissions.Uncertainty.ToString());
        foreach (var edge in candidates)
        {
            if (!edge.IsComplete) limits.Add(edge.Uncertainty.ToString());
            if (edge.Expectedness == ControlExpectedness.Unknown) limits.Add(edge.ExpectednessReason.ToString());
        }
        var savedLimits = limits.Order(StringComparer.Ordinal).ToArray();
        var findings = candidates.Where(edge => edge.IsComplete && edge.Expectedness == ControlExpectedness.Unexpected
                && edge.ReplicationNamingContextKind == nameof(NamingContextKind.Domain))
            .OrderBy(edge => edge.HolderSid, StringComparer.Ordinal).ThenBy(edge => edge.HolderScope, StringComparer.Ordinal)
            .Select(edge =>
            {
                var proof = new ReplicationPermissionEvidence(generation, binding.EvidenceSeal, binding.DerivationGenerationId,
                    binding.DerivationSeal, binding.PrincipalCatalogueVersion, ControlEdgeStorage.EngineVersion,
                    binding.PolicyVersion, binding.ContractVersion, subject.ObjectGuid!.Value, subject.DistinguishedName,
                    subject.DomainFqdn!, edge.TargetClass!, nameof(Tier0Basis.PartitionRoot), edge.HolderSid, edge.HolderScope,
                    edge.HolderName, edge.ExpectednessReason.ToString(), edge.DescriptorOutcome,
                    edge.Preconditions.Select(check => new ReplicationPermissionCheck(check.Name, check.State.ToString(), check.EvidenceSource)).ToArray(),
                    edge.Evidence.Select(entry => entry with { ApplicationData = entry.ApplicationData.ToArray() }).ToArray(), savedLimits);
                var name = edge.HolderName ?? edge.HolderSid;
                var detail = name + " - " + subject.DistinguishedName + ". " + UnexpectedDomainSecretReplication.Explanation
                    + " " + UnexpectedDomainSecretReplication.ScopeNote
                    + "\n\nOriginal permission entries:\n" + string.Join("\n", proof.Entries.Select(entry => "Entry " + entry.Ordinal + ": "
                        + entry.AceType + "; " + entry.Trustee.Sid + "; mask 0x" + entry.AccessMask.ToString("X8")
                        + (entry.ObjectTypeGuid is null ? "; all extended rights" : "; scope " + entry.ObjectTypeGuid)
                        + (entry.IsInherited ? "; inherited" : "; explicit")));
                if (savedLimits.Length != 0) detail += "\n\n" + UnexpectedDomainSecretReplication.IncompleteExplanation;
                return new Finding(rule.Id, rule.Version, rule.Severity,
                    new(FindingSubjectKind.DirectoryObject, UnexpectedDomainSecretReplication.Key(edge.HolderSid, edge.HolderScope)),
                    subject.ObjectGuid.Value, subject.DistinguishedName, subject.DomainFqdn!, edge.TargetClass!, detail,
                    subject.Completeness, proof) { PrincipalName = name };
            }).ToArray();
        return new(findings, [], savedLimits.Length == 0 ? [] :
            [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.ReplicationPermissionIncomplete)]);
    }

    private static RuleVerdict Unassessed() => RuleVerdict.CouldNotResolve(
        [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.ReplicationPermissionIncomplete)]);
}
