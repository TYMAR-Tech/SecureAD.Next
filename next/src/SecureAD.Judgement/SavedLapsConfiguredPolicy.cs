using System.Collections.Immutable;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.GroupPolicy;

namespace SecureAD.Judgement;

internal sealed record SavedGpoProtocol(CapturedGpoProtocolInputs Inputs, uint? FunctionalityVersion,
    uint? Flags, uint? DirectoryVersion, ImmutableArray<AuditError> Limitations, GpoApplicabilityState State,
    bool? FunctionalitySupported, bool? ComputerHalfEnabled, bool? NonEmpty);
internal sealed record SavedGpoWmi(GpoWmiFilterReadingSource Source, bool DefinitionAvailable,
    ImmutableArray<CapturedWmiQuery> Queries, AuditError? Error);
internal sealed record GpoWmiFilterReadingSource(CapturedObjectIdentity Policy, ObjectAttributes PolicyValues,
    CapturedWmiReference? Reference, CapturedObjectIdentity? Filter, ObjectAttributes? FilterValues);
internal sealed record SavedGpoApplicability(CapturedObjectIdentity Policy, ImmutableArray<int> PolicyLinkIndices,
    GpoApplicabilityState DomainOuState, GpoSecurityAssessment Security, SavedGpoProtocol Protocol, SavedGpoWmi Wmi,
    GpoConditionalApplicability Conditional, GpoDirectoryWmiAssessment DirectoryAssessment,
    GpoApplicabilityState PolicyState, GpoApplicabilityState State, ImmutableArray<AuditError> Limitations);
internal sealed record SavedLapsRegistryInput(long PolicyRow, GpoApplicabilityState RegistryExtension,
    ObjectAttributes ExtensionValues, GpoRegistrySettings? Registry, AuditError? ExtensionLimitation);
internal sealed record SavedLapsSource(int LinkIndex, CapturedObjectIdentity? Policy, string? FileSysPath,
    int? EntryIndex, RegistryPolicyEntry? Instruction);
internal sealed record SavedLapsValue(LapsConfiguredValueState State, uint? Number, string? Principal,
    LapsDomainAdmins? DomainAdmins, int? Source, string? Reason);
internal sealed record SavedLapsNode(int Id, LapsPolicySetting Setting, LapsRegistryState? LeafState,
    int? Source, int? Previous, string? Reason, SavedLapsValue? Value,
    GpoWmiConditionKey? Condition, int? WhenMatches, int? WhenDoesNotMatch);
internal sealed record SavedLapsDirectoryValue(SavedLapsValue? Value,
    ImmutableArray<GpoWmiConditionKey> UsedConditions, GpoWmiConditionKey? UnresolvedCondition, string? Reason);
internal sealed record SavedLapsSetting(LapsPolicySetting Setting, int Root, SavedLapsValue? UniformOrderedProjectionValue,
    bool IsDefiniteForComputer, ImmutableArray<int> PossibleSources, int DecisionNodeCount,
    SavedLapsDirectoryValue DirectoryAssessment);

internal sealed record SavedLapsConfiguredPolicy(Guid JudgementGenerationId, Guid CaptureGenerationId, string EvidenceSeal,
    Guid? DerivationGenerationId, string? DerivationSeal, Guid? CalculationDerivationGenerationId, CapturedObjectIdentity Computer,
    GpoLinkHierarchy Hierarchy, ImmutableArray<SavedGpoApplicability> Policies,
    ImmutableArray<SavedLapsRegistryInput> RegistryPolicies, ImmutableArray<SavedLapsSource> Sources,
    ImmutableArray<SavedLapsNode> Nodes, ImmutableArray<SavedLapsSetting> Settings,
    LapsDomainAdmins DsrMDecryptorWhenApplicable, bool HasOpenPolicyScope,
    ImmutableArray<AuditError> Limitations, string RegistryPolicyRoot, bool DefaultsRequireSelectionOfThisPolicyRoot,
    string DirectoryAssumption, bool IsObservedWmiResult)
{
    internal SavedLapsValue UnderAssumptions(LapsPolicySetting setting,
        IReadOnlyDictionary<GpoWmiConditionKey, bool> assumptions)
    {
        var known = Policies.Where(policy => policy.Conditional.Wmi is not null)
            .Select(policy => policy.Conditional.Wmi!.Condition).ToHashSet();
        if (assumptions.Keys.Any(key => !known.Contains(key)))
            throw new InvalidDataException("A saved LAPS assumption belongs to another captured computer or filter.");
        var current = Nodes[Settings.Single(value => value.Setting == setting).Root];
        while (current.Condition is { } condition)
        {
            if (!assumptions.TryGetValue(condition, out var matches))
                throw new InvalidDataException("A saved conditional setting requires an explicit filter assumption.");
            current = Nodes[matches ? current.WhenMatches!.Value : current.WhenDoesNotMatch!.Value];
        }
        return current.Value ?? throw LapsConfiguredPolicyStorage.Invalid();
    }

    internal SavedLapsDirectoryValue UnderDirectoryAssessment(LapsPolicySetting setting) =>
        Settings.Single(value => value.Setting == setting).DirectoryAssessment;

    internal static SavedLapsConfiguredPolicy Create(LapsConfiguredPolicy value, Guid judgement,
        Guid? selectedDerivation, string? derivationSeal, CancellationToken token)
    {
        var nodes = new List<SavedLapsNode?>();
        var sources = new List<SavedLapsSource>();
        var sourceIds = new Dictionary<(int Link, int? Entry), int>();
        var links = new Dictionary<GpoHierarchyLink, int>(ReferenceEqualityComparer.Instance);
        for (var index = 0; index < value.Inputs.Hierarchy.Links.Length; index++)
            links.Add(value.Inputs.Hierarchy.Links[index], index);
        int? Source(LapsSettingSource? source)
        {
            if (source is null) return null;
            if (!links.TryGetValue(source.Link, out var link)) throw LapsConfiguredPolicyStorage.Invalid();
            var key = (link, source.EntryIndex);
            if (sourceIds.TryGetValue(key, out var saved)) return saved;
            var id = sources.Count;
            sources.Add(new(link, source.Policy, source.FileSysPath, source.EntryIndex, source.Instruction));
            sourceIds.Add(key, id);
            return id;
        }
        SavedLapsValue? Answer(LapsConfiguredValue? answer) => answer is null ? null
            : new(answer.State, answer.Number, answer.Principal, answer.DomainAdmins, Source(answer.Source), answer.Reason);
        var settings = ImmutableArray.CreateBuilder<SavedLapsSetting>();
        foreach (var setting in Enum.GetValues<LapsPolicySetting>())
        {
            token.ThrowIfCancellationRequested();
            var original = value.Settings[setting];
            var ids = new Dictionary<LapsSettingDecision, int>(ReferenceEqualityComparer.Instance);
            var pending = new Stack<LapsSettingDecision>();
            int Register(LapsSettingDecision decision)
            {
                if (ids.TryGetValue(decision, out var found)) return found;
                var id = nodes.Count;
                ids.Add(decision, id);
                nodes.Add(null);
                pending.Push(decision);
                return id;
            }
            var root = Register(original.Decision);
            while (pending.TryPop(out var decision))
            {
                token.ThrowIfCancellationRequested();
                var id = ids[decision];
                nodes[id] = decision switch
                {
                    LapsSettingBranch branch => new(id, setting, null, null, null, null, null,
                        branch.Condition, Register(branch.WhenMatches), Register(branch.WhenDoesNotMatch)),
                    LapsSettingLeaf leaf => new(id, setting, leaf.State, Source(leaf.Source),
                        leaf.Previous is null ? null : Register(leaf.Previous), leaf.Reason,
                        Answer(LapsConfiguredPolicyCalculator.Describe(setting, leaf, value.DsrMDecryptorWhenApplicable)),
                        null, null, null),
                    _ => throw LapsConfiguredPolicyStorage.Invalid(),
                };
            }
            var projected = value.UnderDirectoryAssessment(setting);
            settings.Add(new(setting, root, Answer(original.UniformOrderedProjectionValue),
                original.IsDefiniteForComputer, original.PossibleSources.Select(source => Source(source)!.Value)
                    .Distinct().ToImmutableArray(), original.DecisionNodeCount,
                new(Answer(projected.Value), projected.UsedAssessments.Select(assessment =>
                    assessment.Condition ?? throw LapsConfiguredPolicyStorage.Invalid()).ToImmutableArray(),
                    projected.UnresolvedCondition, projected.Reason)));
        }
        var policies = value.Inputs.Policies.Select(policy =>
        {
            var protocol = policy.Protocol;
            var wmi = policy.Wmi;
            return new SavedGpoApplicability(policy.Policy, policy.PolicyLinks.Select(link =>
                links.TryGetValue(link, out var index) ? index : throw LapsConfiguredPolicyStorage.Invalid()).ToImmutableArray(),
                policy.DomainOuState, policy.Security,
                new(protocol.Inputs, protocol.FunctionalityVersion, protocol.Flags, protocol.DirectoryVersion,
                    protocol.Limitations, protocol.State, protocol.FunctionalitySupported, protocol.ComputerHalfEnabled, protocol.NonEmpty),
                new(new(wmi.Policy, wmi.PolicyValues, wmi.Reference, wmi.Filter, wmi.FilterValues),
                    wmi.Definition.IsSuccess, wmi.Definition.IsSuccess ? wmi.Definition.Value : [],
                    wmi.Definition.Error), policy.Conditional, policy.DirectoryAssessment, policy.PolicyState, policy.State,
                policy.Limitations);
        }).ToImmutableArray();
        return new(judgement, value.CaptureGenerationId, value.EvidenceSeal, selectedDerivation, derivationSeal,
            value.DerivationGenerationId, value.Computer, value.Inputs.Hierarchy, policies, value.RegistryPolicies.Select(policy =>
                new SavedLapsRegistryInput(policy.Applicability.Policy.ObjectId, policy.RegistryExtension,
                    policy.ExtensionValues, policy.Registry, policy.ExtensionLimitation)).ToImmutableArray(),
            sources.ToImmutableArray(), nodes.Select(node => node ?? throw LapsConfiguredPolicyStorage.Invalid()).ToImmutableArray(),
            settings.ToImmutable(), value.DsrMDecryptorWhenApplicable, value.HasOpenPolicyScope, value.Limitations,
            LapsPolicySettingsEvidence.RegistryKey, value.DefaultsRequireSelectionOfThisPolicyRoot,
            GpoDirectoryWmiAssessment.Assumption, false);
    }

    internal void Validate(CancellationToken token)
    {
        void Require(bool condition) { if (!condition) throw LapsConfiguredPolicyStorage.Invalid(); }
        Require(JudgementGenerationId != Guid.Empty && CaptureGenerationId != Guid.Empty
            && EvidenceSeal.Length == 64 && EvidenceSeal.All(Uri.IsHexDigit)
            && (DerivationGenerationId is null) == (DerivationSeal is null)
            && (DerivationSeal is null || DerivationSeal.Length == 64 && DerivationSeal.All(Uri.IsHexDigit))
            && (CalculationDerivationGenerationId is null || CalculationDerivationGenerationId == DerivationGenerationId)
            && Computer.ObjectId > 0 && Computer.CaptureGenerationId == CaptureGenerationId
            && Hierarchy.CaptureGenerationId == CaptureGenerationId && Hierarchy.EvidenceSeal == EvidenceSeal
            && Hierarchy.Computer == Computer && Hierarchy.ComputerValues.ObjectGuid == Computer.ObjectGuid
            && Hierarchy.ComputerValues.DistinguishedName == Computer.DistinguishedName
            && HasOpenPolicyScope == (!Hierarchy.SiteScopeResolved || !Hierarchy.DomainOuEvidenceComplete)
            && RegistryPolicyRoot == LapsPolicySettingsEvidence.RegistryKey && DefaultsRequireSelectionOfThisPolicyRoot
            && DirectoryAssumption == GpoDirectoryWmiAssessment.Assumption && !IsObservedWmiResult
            && !Policies.IsDefault && !RegistryPolicies.IsDefault && !Sources.IsDefault && !Nodes.IsDefault
            && !Settings.IsDefault && !Limitations.IsDefault && Settings.Length == 4
            && Policies.All(policy => policy is not null) && RegistryPolicies.All(policy => policy is not null)
            && Sources.All(source => source is not null) && Nodes.All(node => node is not null)
            && Settings.All(setting => setting is not null)
            && Settings.Select(setting => setting.Setting).Distinct().Count() == 4);
        var policies = new Dictionary<long, SavedGpoApplicability>();
        var conditions = new HashSet<GpoWmiConditionKey>();
        foreach (var policy in Policies)
        {
            token.ThrowIfCancellationRequested();
            Require(policies.TryAdd(policy.Policy.ObjectId, policy)
                && policy.Policy.CaptureGenerationId == CaptureGenerationId
                && policy.Security.CaptureGenerationId == CaptureGenerationId && policy.Security.EvidenceSeal == EvidenceSeal
                && policy.Security.Computer == Computer && policy.Security.Policy == policy.Policy
                && policy.Security.ComputerValues.ObjectGuid == Computer.ObjectGuid
                && policy.Security.PolicyValues.ObjectGuid == policy.Policy.ObjectGuid
                && (policy.Security.DerivationGenerationId is null || policy.Security.DerivationGenerationId == CalculationDerivationGenerationId)
                && policy.Protocol.Inputs.CaptureGenerationId == CaptureGenerationId
                && policy.Protocol.Inputs.Policy == policy.Policy && policy.Wmi.Source.Policy == policy.Policy
                && policy.Protocol.Inputs.PolicyValues.ObjectGuid == policy.Policy.ObjectGuid
                && policy.Wmi.Source.PolicyValues.ObjectGuid == policy.Policy.ObjectGuid
                && policy.Wmi.DefinitionAvailable == (policy.Wmi.Error is null) && !policy.Wmi.Queries.IsDefault
                && (!policy.Wmi.DefinitionAvailable || policy.Wmi.Queries.Length > 0)
                && policy.DirectoryAssessment.CaptureGenerationId == CaptureGenerationId
                && policy.DirectoryAssessment.EvidenceSeal == EvidenceSeal && policy.DirectoryAssessment.Computer == Computer
                && policy.DirectoryAssessment.Facts.OriginalValues.ObjectGuid == Computer.ObjectGuid
                && policy.DirectoryAssessment.Condition == policy.Conditional.Wmi?.Condition);
            Require(!policy.PolicyLinkIndices.IsDefault && policy.PolicyLinkIndices.All(index =>
                index >= 0 && index < Hierarchy.Links.Length
                && (Hierarchy.Links[index].Policy?.ObjectId == policy.Policy.ObjectId
                    || Hierarchy.Links[index].Policy is null && string.Equals(Hierarchy.Links[index].Link.DistinguishedName,
                        policy.Policy.DistinguishedName, StringComparison.OrdinalIgnoreCase))));
            if (policy.Wmi.Source.Filter is { } sourceFilter)
                Require(sourceFilter.CaptureGenerationId == CaptureGenerationId && policy.Wmi.Source.FilterValues is not null
                    && sourceFilter.ObjectGuid == policy.Wmi.Source.FilterValues.ObjectGuid
                    && sourceFilter.DistinguishedName == policy.Wmi.Source.FilterValues.DistinguishedName);
            if (policy.Conditional.Wmi is { } alternative)
            {
                var key = alternative.Condition;
                Require(key.CaptureGenerationId == CaptureGenerationId && key.EvidenceSeal == EvidenceSeal
                    && key.ComputerObjectId == Computer.ObjectId && policy.Wmi.Source.Filter is { } filter
                    && filter.CaptureGenerationId == CaptureGenerationId && key.FilterObjectId == filter.ObjectId);
                conditions.Add(key);
            }
        }
        var registry = new Dictionary<long, SavedLapsRegistryInput>();
        foreach (var input in RegistryPolicies)
            Require(registry.TryAdd(input.PolicyRow, input) && policies.TryGetValue(input.PolicyRow, out var policy)
                && input.ExtensionValues.ObjectGuid == policy.Policy.ObjectGuid);
        for (var index = 0; index < Sources.Length; index++)
        {
            var source = Sources[index];
            Require(source.LinkIndex >= 0 && source.LinkIndex < Hierarchy.Links.Length
                && source.Policy == Hierarchy.Links[source.LinkIndex].Policy
                && source.EntryIndex.HasValue == (source.Instruction is not null));
            if (source.Policy is { } policy && policies.TryGetValue(policy.ObjectId, out var inputs))
                Require(source.FileSysPath == inputs.Protocol.Inputs.TemplateVersion.FileSysPath);
            if (source.EntryIndex is { } entry)
            {
                Require(source.Policy is not null && registry.TryGetValue(source.Policy.ObjectId, out var input)
                    && input.Registry is not null && entry >= 0 && entry < input.Registry.Settings.Count);
                var expected = registry[source.Policy!.ObjectId].Registry!.Settings[entry];
                Require(source.Instruction!.KeyPath == expected.KeyPath && source.Instruction.ValueName == expected.ValueName
                    && source.Instruction.RegistryType == expected.RegistryType && source.Instruction.Data.SequenceEqual(expected.Data));
            }
        }
        void Value(SavedLapsValue? value)
        {
            if (value is null) return;
            Require(Enum.IsDefined(value.State) && (value.Source is null || value.Source >= 0 && value.Source < Sources.Length)
                && (value.State != LapsConfiguredValueState.Unresolved || !string.IsNullOrWhiteSpace(value.Reason)));
        }
        for (var index = 0; index < Nodes.Length; index++)
        {
            token.ThrowIfCancellationRequested();
            var node = Nodes[index];
            Require(node.Id == index && Enum.IsDefined(node.Setting));
            if (node.Condition is { } condition)
                Require(conditions.Contains(condition) && node.LeafState is null && node.Source is null
                    && node.Previous is null && node.Reason is null && node.Value is null
                    && node.WhenMatches is not null && node.WhenDoesNotMatch is not null);
            else
            {
                Require(node.LeafState is { } state && Enum.IsDefined(state) && node.Value is not null
                    && node.WhenMatches is null && node.WhenDoesNotMatch is null
                    && node.Source == node.Value.Source
                    && (state != LapsRegistryState.Unresolved || node.Value.State == LapsConfiguredValueState.Unresolved
                        && !string.IsNullOrWhiteSpace(node.Reason))
                    && (state is not (LapsRegistryState.Untouched or LapsRegistryState.Deleted)
                        || node.Value.State != LapsConfiguredValueState.PolicyValue));
                Value(node.Value);
            }
            foreach (var child in Children(node))
                Require(child >= 0 && child < Nodes.Length && Nodes[child].Setting == node.Setting);
        }
        var visited = new HashSet<int>();
        var active = new HashSet<int>();
        foreach (var setting in Settings)
        {
            Require(Enum.IsDefined(setting.Setting) && setting.Root >= 0 && setting.Root < Nodes.Length
                && Nodes[setting.Root].Setting == setting.Setting && !setting.PossibleSources.IsDefault
                && setting.PossibleSources.All(id => id >= 0 && id < Sources.Length)
                && (!setting.IsDefiniteForComputer || !HasOpenPolicyScope && setting.UniformOrderedProjectionValue is not null));
            Value(setting.UniformOrderedProjectionValue);
            Value(setting.DirectoryAssessment.Value);
            Require(!setting.DirectoryAssessment.UsedConditions.IsDefault
                && setting.DirectoryAssessment.UsedConditions.Distinct().Count() == setting.DirectoryAssessment.UsedConditions.Length
                && setting.DirectoryAssessment.UsedConditions.All(conditions.Contains)
                && (setting.DirectoryAssessment.UnresolvedCondition is null
                    || conditions.Contains(setting.DirectoryAssessment.UnresolvedCondition.Value)
                    && setting.DirectoryAssessment.Value is null && !string.IsNullOrWhiteSpace(setting.DirectoryAssessment.Reason)));
            var pending = new Stack<(int Id, bool End)>();
            pending.Push((setting.Root, false));
            while (pending.TryPop(out var work))
            {
                token.ThrowIfCancellationRequested();
                if (work.End) { active.Remove(work.Id); visited.Add(work.Id); continue; }
                Require(!active.Contains(work.Id));
                if (visited.Contains(work.Id)) continue;
                active.Add(work.Id);
                pending.Push((work.Id, true));
                foreach (var child in Children(Nodes[work.Id])) pending.Push((child, false));
            }
            var decisions = new HashSet<int>();
            var branches = new Stack<int>();
            branches.Push(setting.Root);
            while (branches.TryPop(out var id))
            {
                if (!decisions.Add(id)) continue;
                var node = Nodes[id];
                if (node.Condition is not null)
                {
                    branches.Push(node.WhenMatches!.Value);
                    branches.Push(node.WhenDoesNotMatch!.Value);
                }
            }
            Require(decisions.Count == setting.DecisionNodeCount);
            var projected = setting.DirectoryAssessment;
            var supplied = projected.UsedConditions.ToDictionary(key => key, key =>
            {
                var assessments = Policies.Where(policy => policy.DirectoryAssessment.Condition == key)
                    .Select(policy => policy.DirectoryAssessment.State).Distinct().ToArray();
                Require(assessments.Length == 1 && assessments[0] != GpoDirectoryWmiState.Unresolved);
                return assessments[0] == GpoDirectoryWmiState.MatchesRecordedPlatform;
            });
            var used = new List<GpoWmiConditionKey>();
            var selected = Nodes[setting.Root];
            while (selected.Condition is { } key && supplied.TryGetValue(key, out var matches))
            {
                used.Add(key);
                selected = Nodes[matches ? selected.WhenMatches!.Value : selected.WhenDoesNotMatch!.Value];
            }
            Require(used.SequenceEqual(projected.UsedConditions));
            if (selected.Condition is { } missing)
                Require(projected.Value is null && projected.UnresolvedCondition == missing
                    && !string.IsNullOrWhiteSpace(projected.Reason));
            else
                Require(projected.UnresolvedCondition is null && projected.Reason is null && projected.Value == selected.Value);
        }
        Require(visited.Count == Nodes.Length);
    }

    private static IEnumerable<int> Children(SavedLapsNode node)
    {
        if (node.WhenMatches is { } yes) yield return yes;
        if (node.WhenDoesNotMatch is { } no) yield return no;
        if (node.Previous is { } previous) yield return previous;
    }
}
