using System.Buffers.Binary;
using System.Collections.Immutable;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal enum LapsPolicySetting
{
    BackupDirectory,
    ADPasswordEncryptionEnabled,
    ADPasswordEncryptionPrincipal,
    ADBackupDSRMPassword,
}

internal enum LapsRegistryState { Untouched, Deleted, Assigned, Unresolved }
internal enum LapsConfiguredValueState { Unresolved, PolicyValue, DocumentedDefault }

internal sealed record LapsSettingSource(GpoHierarchyLink Link, CapturedObjectIdentity? Policy,
    string? FileSysPath, int? EntryIndex, RegistryPolicyEntry? Instruction);

internal abstract record LapsSettingDecision;
internal sealed record LapsSettingLeaf(LapsRegistryState State, LapsSettingSource? Source, string? Reason,
    LapsSettingDecision? Previous = null) : LapsSettingDecision;
internal sealed record LapsSettingBranch(GpoWmiConditionKey Condition,
    LapsSettingDecision WhenMatches, LapsSettingDecision WhenDoesNotMatch) : LapsSettingDecision;

internal sealed record LapsDomainAdmins(string? DomainFqdn, string? Sid);
internal sealed record LapsConfiguredValue(LapsConfiguredValueState State, uint? Number, string? Principal,
    LapsDomainAdmins? DomainAdmins, LapsSettingSource? Source, string? Reason);

internal sealed record LapsSettingResult(LapsPolicySetting Setting, LapsSettingDecision Decision,
    LapsConfiguredValue? UniformOrderedProjectionValue, bool IsDefiniteForComputer,
    ImmutableArray<LapsSettingSource> PossibleSources, int DecisionNodeCount);

internal sealed record LapsDirectorySettingAssessment(LapsConfiguredValue? Value,
    ImmutableArray<GpoDirectoryWmiAssessment> UsedAssessments, GpoWmiConditionKey? UnresolvedCondition, string? Reason)
{
    internal string Assumption => GpoDirectoryWmiAssessment.Assumption;
    internal bool IsObservedWmiResult => false;
}

internal sealed record LapsRegistryPolicyInput(GpoComputerApplicability Applicability,
    GpoApplicabilityState RegistryExtension, ObjectAttributes ExtensionValues,
    GpoRegistrySettings? Registry, AuditError? ExtensionLimitation)
{
    internal required IReadOnlyList<RegistryPolicyInstruction> Instructions { get; init; }
}

internal sealed record LapsConfiguredPolicy(Guid CaptureGenerationId, string EvidenceSeal,
    Guid? DerivationGenerationId, CapturedObjectIdentity Computer, GpoComputerInputs Inputs,
    ImmutableArray<LapsRegistryPolicyInput> RegistryPolicies,
    ImmutableDictionary<LapsPolicySetting, LapsSettingResult> Settings,
    LapsDomainAdmins DsrMDecryptorWhenApplicable, bool HasOpenPolicyScope,
    ImmutableArray<AuditError> Limitations)
{
    internal bool IsGroupPolicyRootOnly => true;
    internal bool DefaultsRequireSelectionOfThisPolicyRoot => true;

    internal LapsDirectorySettingAssessment UnderDirectoryAssessment(LapsPolicySetting setting)
    {
        var known = new Dictionary<GpoWmiConditionKey, GpoDirectoryWmiAssessment>();
        foreach (var policy in RegistryPolicies)
        {
            var assessment = policy.Applicability.DirectoryAssessment;
            if (assessment.CaptureGenerationId != CaptureGenerationId || assessment.EvidenceSeal != EvidenceSeal
                || assessment.Computer != Computer || assessment.Condition != policy.Applicability.Conditional.Wmi?.Condition)
                throw new InvalidDataException("A directory-based assessment belongs to another captured computer or filter.");
            if (assessment.Condition is not { } key) continue;
            if (known.TryGetValue(key, out var previous) && previous.State != assessment.State)
                throw new InvalidDataException("Policies sharing one captured filter have inconsistent directory assessments.");
            known[key] = assessment;
        }
        var assumptions = new Dictionary<GpoWmiConditionKey, bool>();
        var used = ImmutableArray.CreateBuilder<GpoDirectoryWmiAssessment>();
        var current = Settings[setting].Decision;
        while (current is LapsSettingBranch branch)
        {
            if (!known.TryGetValue(branch.Condition, out var assessment) || assessment.State == GpoDirectoryWmiState.Unresolved)
                return new(null, used.ToImmutable(), branch.Condition,
                    "A required filter has no qualified directory-based outcome; both conditional alternatives remain retained.");
            assumptions[branch.Condition] = assessment.State == GpoDirectoryWmiState.MatchesRecordedPlatform;
            used.Add(assessment);
            current = assumptions[branch.Condition] ? branch.WhenMatches : branch.WhenDoesNotMatch;
        }
        return new(UnderAssumptions(setting, assumptions), used.ToImmutable(), null, null);
    }

    internal bool? RequestsAdEncryption(IReadOnlyDictionary<GpoWmiConditionKey, bool> assumptions)
    {
        var backup = UnderAssumptions(LapsPolicySetting.BackupDirectory, assumptions);
        if (backup.Number is 0 or 1) return false;
        var encryption = UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionEnabled, assumptions);
        return encryption.Number == 0 ? false : backup.Number == 2 && encryption.Number == 1 ? true : null;
    }

    internal bool? RequestsDsrMBackup(IReadOnlyDictionary<GpoWmiConditionKey, bool> assumptions)
    {
        var encryption = RequestsAdEncryption(assumptions);
        var recovery = UnderAssumptions(LapsPolicySetting.ADBackupDSRMPassword, assumptions);
        return encryption == false || recovery.Number == 0 ? false
            : encryption == true && recovery.Number == 1 ? true : null;
    }

    internal LapsConfiguredValue UnderAssumptions(LapsPolicySetting setting,
        IReadOnlyDictionary<GpoWmiConditionKey, bool> assumptions)
    {
        foreach (var key in assumptions.Keys)
            if (key.CaptureGenerationId != CaptureGenerationId || key.EvidenceSeal != EvidenceSeal
                || key.ComputerObjectId != Computer.ObjectId)
                throw new InvalidDataException("A WMI assumption belongs to another captured computer or evidence selection.");
        var current = Settings[setting].Decision;
        while (current is LapsSettingBranch branch)
        {
            if (!assumptions.TryGetValue(branch.Condition, out var matches))
                throw new InvalidDataException("The selected conditional setting requires an explicit matching/non-matching assumption.");
            current = matches ? branch.WhenMatches : branch.WhenDoesNotMatch;
        }
        return LapsConfiguredPolicyCalculator.Describe(setting, (LapsSettingLeaf)current, DsrMDecryptorWhenApplicable);
    }
}

internal static class LapsConfiguredPolicyCalculator
{
    internal static LapsConfiguredPolicy Calculate(GpoComputerInputs inputs,
        IReadOnlyDictionary<long, LapsRegistryPolicyInput> policies, CancellationToken token)
    {
        var hierarchy = inputs.Hierarchy;
        var domain = hierarchy.Computer.DomainFqdn;
        var issuingDomain = Sid.ToBytes(hierarchy.Computer.PrincipalSid ?? "") is not null
            ? Sid.IssuingDomain(hierarchy.Computer.PrincipalSid) : null;
        var capturedDomainSids = hierarchy.Containers.Where(container => container.Kind == GpoLinkContainerKind.Domain
            && string.Equals(container.Identity?.DomainFqdn, domain, StringComparison.OrdinalIgnoreCase)
            && container.Values is not null)
            .Select(container => RequesterTrusteeReading.SidOf(container.Values!)).Where(sid => sid is not null).Distinct().ToArray();
        var domainSid = capturedDomainSids.Length == 1 && capturedDomainSids[0] == issuingDomain ? issuingDomain : null;
        var domainAdmins = new LapsDomainAdmins(domain, domainSid is null ? null : domainSid + "-512");
        var errors = hierarchy.Limitations.ToList();
        var roots = Enum.GetValues<LapsPolicySetting>().ToDictionary(setting => setting,
            _ => (LapsSettingDecision)new LapsSettingLeaf(LapsRegistryState.Untouched, null, null));
        var generations = new HashSet<Guid>();
        foreach (var (rowId, policy) in policies)
        {
            token.ThrowIfCancellationRequested();
            var answer = policy.Applicability;
            if (answer.CaptureGenerationId != hierarchy.CaptureGenerationId || answer.EvidenceSeal != hierarchy.EvidenceSeal
                || answer.Computer != hierarchy.Computer || rowId != answer.Policy.ObjectId
                || answer.Policy.CaptureGenerationId != hierarchy.CaptureGenerationId
                || answer.Computer.CaptureGenerationId != hierarchy.CaptureGenerationId
                || policy.ExtensionValues.ObjectGuid != answer.Policy.ObjectGuid)
                throw new InvalidDataException("LAPS precedence inputs do not bind the same captured sources.");
            if (answer.DerivationGenerationId is { } generation) generations.Add(generation);
            errors.AddRange(answer.Limitations);
            if (policy.ExtensionLimitation is { } limitation) errors.Add(limitation);
            if (policy.Registry is { } registry)
            {
                if (!registry.IsComplete)
                    errors.Add(AuditError.Create(ErrorCategory.Evidence, "LapsPolicySettingsIncomplete",
                        ErrorSeverity.Degraded, registry.Reason ?? "The captured Machine registry policy has parse errors.",
                        answer.Policy.DistinguishedName));
                foreach (var error in registry.ParseErrors)
                    errors.Add(AuditError.Create(ErrorCategory.Evidence, "LapsPolicyParseError",
                        ErrorSeverity.Degraded, error, answer.Policy.DistinguishedName));
            }
        }
        if (generations.Count > 1)
            throw new InvalidDataException("LAPS precedence inputs contain different membership derivations.");
        foreach (var link in hierarchy.Links.Where(link => link.State != GpoLinkHierarchyState.Excluded
            && link.DomainOuProcessingOrder is not null).OrderBy(link => link.DomainOuProcessingOrder))
        {
            token.ThrowIfCancellationRequested();
            LapsCalculationDiagnostics.Count("ordered-links-visited", 1);
            policies.TryGetValue(link.Policy?.ObjectId ?? 0, out var policy);
            if (policy is not null && (link.Policy is not { } linked
                || linked.ObjectGuid != policy.Applicability.Policy.ObjectGuid
                || linked.CaptureGenerationId != policy.Applicability.CaptureGenerationId))
                throw new InvalidDataException("The selected registry policy does not bind the captured link occurrence.");
            if (policy is not null && (policy.Applicability.PolicyState == GpoApplicabilityState.DoesNotApply
                || policy.RegistryExtension == GpoApplicabilityState.DoesNotApply))
                continue;
            var source = new LapsSettingSource(link, link.Policy,
                policy?.Applicability.Protocol.Inputs.TemplateVersion.FileSysPath, null, null);
            var registry = policy?.Registry;
            var instructions = policy is { Registry: not null } ? policy.Instructions : [];
            var qualified = policy is not null && policy.RegistryExtension == GpoApplicabilityState.Applies
                && policy.Applicability.PolicyState == GpoApplicabilityState.Applies
                && link.State == GpoLinkHierarchyState.Included;
            foreach (var setting in roots.Keys.ToArray())
            {
                var previous = roots[setting];
                var relevant = instructions.Where(instruction => instruction.Affects(
                    LapsPolicySettingsEvidence.RegistryKey, setting.ToString())).ToArray();
                if (registry is { IsComplete: true } && relevant.Length == 0) continue;
                var condition = policy?.Applicability.Conditional.Wmi;
                LapsSettingDecision Include(LapsSettingDecision prior)
                {
                    if (!qualified || registry is null)
                        return Unknown(prior, source, "The captured policy's registry participation or required inputs remain unresolved.");
                    var current = prior;
                    foreach (var instruction in relevant)
                    {
                        LapsCalculationDiagnostics.Count("registry-setting-instructions-applied", 1);
                        var occurrence = source with { EntryIndex = instruction.EntryIndex, Instruction = instruction.Source };
                        current = Apply(current, instruction, occurrence);
                    }
                    return registry.IsComplete ? current
                        : Unknown(current, source, "Unread or unparsed policy settings may contain a later write or deletion.");
                }
                if (condition is not null)
                {
                    var included = Restrict(previous, condition.Condition, true);
                    roots[setting] = Choice(condition.Condition, Include(included),
                        Restrict(previous, condition.Condition, false));
                }
                else roots[setting] = Unknown(previous, source,
                    "The captured WMI input does not establish a qualified condition or an unfiltered policy.");
            }
        }
        var openScope = !hierarchy.SiteScopeResolved || !hierarchy.DomainOuEvidenceComplete;
        var results = ImmutableDictionary.CreateBuilder<LapsPolicySetting, LapsSettingResult>();
        foreach (var (setting, root) in roots)
        {
            token.ThrowIfCancellationRequested();
            var nodes = Nodes(root).ToArray();
            var values = nodes.OfType<LapsSettingLeaf>().Select(leaf => Describe(setting, leaf, domainAdmins)).ToArray();
            var first = values[0];
            var uniform = first.State != LapsConfiguredValueState.Unresolved
                && values.All(value => value.State != LapsConfiguredValueState.Unresolved && SameValue(first, value));
            results.Add(setting, new(setting, root, uniform ? first : null, uniform && !openScope,
                nodes.OfType<LapsSettingLeaf>().Where(leaf => leaf.Source is not null)
                    .Select(leaf => leaf.Source!).Distinct().ToImmutableArray(), nodes.Length));
        }
        return new(hierarchy.CaptureGenerationId, hierarchy.EvidenceSeal, generations.Count == 0 ? null : generations.Single(),
            hierarchy.Computer, inputs, policies.Values.ToImmutableArray(), results.ToImmutable(),
            domainAdmins, openScope, errors.Distinct().ToImmutableArray());
    }

    private static LapsSettingDecision Apply(LapsSettingDecision root, RegistryPolicyInstruction instruction,
        LapsSettingSource source)
    {
        var assigned = new LapsSettingLeaf(LapsRegistryState.Assigned, source, null);
        var deleted = new LapsSettingLeaf(LapsRegistryState.Deleted, source, null);
        var memo = new Dictionary<LapsSettingDecision, LapsSettingDecision>(ReferenceEqualityComparer.Instance);
        return Map(root);

        LapsSettingDecision Map(LapsSettingDecision node)
        {
            if (memo.TryGetValue(node, out var found)) return found;
            var result = node switch
            {
                LapsSettingBranch branch => Choice(branch.Condition, Map(branch.WhenMatches), Map(branch.WhenDoesNotMatch)),
                LapsSettingLeaf leaf => instruction.Kind switch
                {
                    RegistryPolicyInstructionKind.SetValue => assigned,
                    RegistryPolicyInstructionKind.DeleteValue or RegistryPolicyInstructionKind.ClearValues
                        or RegistryPolicyInstructionKind.DeleteKey => deleted,
                    RegistryPolicyInstructionKind.SetIfAbsent => leaf.State switch
                    {
                        LapsRegistryState.Deleted => assigned,
                        LapsRegistryState.Assigned => leaf,
                        _ => Unknown(leaf, source, "This conditional write depends on pre-existing client registry state."),
                    },
                    RegistryPolicyInstructionKind.Unsupported => Unknown(leaf, source, instruction.Reason!),
                    _ => throw new InvalidDataException("An unrelated registry instruction reached the setting replay."),
                },
                _ => throw new InvalidDataException("The conditional setting node is invalid."),
            };
            memo.Add(node, result);
            return result;
        }
    }

    private static LapsSettingLeaf Unknown(LapsSettingDecision previous, LapsSettingSource source, string reason) =>
        new(LapsRegistryState.Unresolved, source, reason, previous);

    private static LapsSettingDecision Choice(GpoWmiConditionKey condition, LapsSettingDecision yes, LapsSettingDecision no)
    {
        if (ReferenceEquals(yes, no)) return yes;
        LapsCalculationDiagnostics.Count("conditional-branches-created", 1);
        return new LapsSettingBranch(condition, yes, no);
    }

    private static LapsSettingDecision Restrict(LapsSettingDecision root, GpoWmiConditionKey condition, bool matches)
    {
        var memo = new Dictionary<LapsSettingDecision, LapsSettingDecision>(ReferenceEqualityComparer.Instance);
        return Visit(root);
        LapsSettingDecision Visit(LapsSettingDecision node)
        {
            if (memo.TryGetValue(node, out var known)) return known;
            var result = node is not LapsSettingBranch branch ? node
                : branch.Condition == condition ? Visit(matches ? branch.WhenMatches : branch.WhenDoesNotMatch)
                : Choice(branch.Condition, Visit(branch.WhenMatches), Visit(branch.WhenDoesNotMatch));
            memo.Add(node, result);
            return result;
        }
    }

    private static IEnumerable<LapsSettingDecision> Nodes(LapsSettingDecision root)
    {
        var seen = new HashSet<LapsSettingDecision>(ReferenceEqualityComparer.Instance);
        var pending = new Stack<LapsSettingDecision>();
        pending.Push(root);
        while (pending.TryPop(out var node))
        {
            if (!seen.Add(node)) continue;
            yield return node;
            if (node is LapsSettingBranch branch)
            {
                pending.Push(branch.WhenMatches);
                pending.Push(branch.WhenDoesNotMatch);
            }
        }
    }

    internal static LapsConfiguredValue Describe(LapsPolicySetting setting, LapsSettingLeaf leaf, LapsDomainAdmins domain)
    {
        if (leaf.State == LapsRegistryState.Unresolved)
            return new(LapsConfiguredValueState.Unresolved, null, null, null, leaf.Source, leaf.Reason);
        if (leaf.State is LapsRegistryState.Untouched or LapsRegistryState.Deleted) return Default(null);
        var entry = leaf.Source?.Instruction ?? throw new InvalidDataException("A configured setting has no source instruction.");
        if (setting == LapsPolicySetting.ADPasswordEncryptionPrincipal)
        {
            if (!RegistryPolicyInterpreter.TryReadString(entry, out var principal)
                || string.IsNullOrWhiteSpace(principal) || principal != principal.Trim())
                return new(LapsConfiguredValueState.Unresolved, null, null, null, leaf.Source,
                    "The captured decryptor value is not a qualified REG_SZ principal; its default cannot be assumed.");
            var sid = Sid.ToBytes(principal);
            var slash = principal.IndexOf('\\');
            var at = principal.IndexOf('@');
            if (sid is null && !(slash > 0 && slash < principal.Length - 1) && !(at > 0 && at < principal.Length - 1))
                return new(LapsConfiguredValueState.Unresolved, null, null, null, leaf.Source,
                    "The captured decryptor is not a qualified SID, qualified name or user principal name.");
            return new(LapsConfiguredValueState.PolicyValue, null, principal, null, leaf.Source,
                sid is null ? "The configured name is retained without claiming that the device can resolve it." : null);
        }
        if (entry.ValueType != RegistryValueType.Dword || entry.Data.Length != sizeof(uint))
            return new(LapsConfiguredValueState.Unresolved, null, null, null, leaf.Source,
                "The captured setting does not contain one qualified REG_DWORD.");
        var number = BinaryPrimitives.ReadUInt32LittleEndian(entry.Data);
        var maximum = setting == LapsPolicySetting.BackupDirectory ? 2U : 1U;
        return number <= maximum ? new(LapsConfiguredValueState.PolicyValue, number, null, null, leaf.Source, null)
            : Default("Microsoft documents the default for an unsupported numeric policy value.");

        LapsConfiguredValue Default(string? reason) => setting == LapsPolicySetting.ADPasswordEncryptionPrincipal
            && string.IsNullOrWhiteSpace(domain.DomainFqdn)
            ? new(LapsConfiguredValueState.Unresolved, null, null, null, leaf.Source,
                "The receiving computer's domain is unavailable; its Domain Admins default cannot be bound.")
            : setting == LapsPolicySetting.ADPasswordEncryptionPrincipal
            ? new(LapsConfiguredValueState.DocumentedDefault, null, null, domain, leaf.Source, reason)
            : new(LapsConfiguredValueState.DocumentedDefault,
                setting == LapsPolicySetting.ADPasswordEncryptionEnabled ? 1U : 0U, null, null, leaf.Source, reason);
    }

    private static bool SameValue(LapsConfiguredValue left, LapsConfiguredValue right)
    {
        if (left.Number != right.Number) return false;
        var leftSid = left.DomainAdmins?.Sid ?? left.Principal;
        var rightSid = right.DomainAdmins?.Sid ?? right.Principal;
        return leftSid is not null || rightSid is not null
            ? string.Equals(leftSid, rightSid, StringComparison.OrdinalIgnoreCase)
            : left.DomainAdmins == right.DomainAdmins;
    }
}
