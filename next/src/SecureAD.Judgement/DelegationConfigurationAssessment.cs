using System.Diagnostics;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class DelegationConfigurationAssessment(IReadOnlyList<IRule> rules, string seal, Guid derivation, string derivationSeal,
    bool captureComplete, CapturedGroupMembershipIndex identities)
{
    private readonly Dictionary<Guid, DelegationConfigurationAccount> _accounts = [];
    private readonly Dictionary<string, List<(DelegationConfigurationAccount Account, AttributeValue Value)>> _registrations =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Guid> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<Guid> _conflicts = [];
    private readonly Dictionary<string, DelegationResourceScope?> _scopes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _inputLimits = new(StringComparer.Ordinal);
    private readonly HashSet<string> _unqualifiedRegistrations = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, IReadOnlyList<string>> _sourceLimits = [];
    private readonly Dictionary<string, PreparationGaps> _preparationGaps = rules.ToDictionary(rule => rule.Definition.Id, _ => new PreparationGaps());
    private int _notApplicable;
    private int _accountCount;
    private int _unknownClasses;

    internal void Add(ObjectAttributes source, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var classes = source.Find("objectClass")?.Values;
        if (classes is not { Count: > 0 } || !classes.Any(value => !string.IsNullOrWhiteSpace(value.Text))
            || classes.Any(value => value.Bytes is not null || string.IsNullOrWhiteSpace(value.Text)))
        {
            _unknownClasses++;
            var reason = classes is not { Count: > 0 } ? "objectClass" : "DelegationConfiguration.AccountClassUnreadable";
            foreach (var gap in _preparationGaps.Values) gap.Add(reason);
            return;
        }
        if (!AttributeWriteRules.IsAccount(source)) { _notApplicable++; return; }
        _accountCount++;
        if (source.Find("servicePrincipalName")?.HasValue != true
            && source.Find(DelegationConfigurationRules.ConstrainedAttribute)?.HasValue != true
            && source.Find(DelegationConfigurationRules.ResourceAttribute)?.HasValue != true)
        {
            foreach (var rule in rules)
            {
                if (source.Find(AttributeFor(rule)) is null) _preparationGaps[rule.Definition.Id].Add(AttributeFor(rule));
                else if (source.Completeness != EvidenceCompleteness.Complete)
                    _preparationGaps[rule.Definition.Id].Add("DelegationConfiguration.AccountSourceIncomplete");
            }
            return;
        }
        var qualified = identities.QualifyTarget(source);
        if (source.ObjectGuid is not { } guid || guid == Guid.Empty || string.IsNullOrWhiteSpace(source.DomainFqdn)
            || qualified.Identity is null || source.Find("isDeleted")?.Values.Any(value =>
                !string.Equals(value.Text, "FALSE", StringComparison.OrdinalIgnoreCase)) == true)
        {
            foreach (var gap in _preparationGaps.Values) gap.Add("DelegationConfiguration.AccountIdentityUnavailable");
            foreach (var value in source.Find("servicePrincipalName")?.Values ?? [])
                if (value.Text is { } text) _unqualifiedRegistrations.Add(text);
            return;
        }
        var kind = source.Find("objectClass")!.Values.LastOrDefault()?.Text;
        if (string.IsNullOrWhiteSpace(kind))
        {
            foreach (var gap in _preparationGaps.Values) gap.Add("DelegationConfiguration.AccountIdentityUnavailable");
            return;
        }
        var snapshot = source.Snapshot();
        var values = snapshot.Attributes.Where(attribute => DelegationConfigurationRules.IdentityAttributes
            .Contains(attribute.LdapDisplayName, StringComparer.OrdinalIgnoreCase)).ToArray();
        var account = new DelegationConfigurationAccount(guid, source.DistinguishedName, source.DomainFqdn, kind,
            source.CapturedUtc, source.Completeness, values);
        _sourceLimits.TryAdd(guid, qualified.Limitations.Select(limit => "AccountIdentity." + limit.Reason).Distinct().ToArray());
        if (_names.TryGetValue(source.DistinguishedName, out var existing) && existing != guid) _conflicts.Add(existing);
        if (_accounts.TryGetValue(guid, out var before) && !Same(before.DistinguishedName, source.DistinguishedName)) _conflicts.Add(guid);
        if (_names.TryGetValue(source.DistinguishedName, out existing) && existing != guid) _conflicts.Add(guid);
        _names[source.DistinguishedName] = guid;
        _accounts.TryAdd(guid, account);
        foreach (var value in Find(account, "servicePrincipalName")?.Values ?? [])
        {
            if (value.Bytes is not null || value.Ordinal < 0 || value.Text is not { } text || !DuplicateServicePrincipalNames.Supports(text))
            {
                _inputLimits.Add("ServiceRegistrationUnsupported");
                continue;
            }
            if (!_registrations.TryGetValue(text, out var owners)) _registrations.Add(text, owners = []);
            owners.Add((account, value));
        }
    }

    internal IReadOnlyList<(IRule Rule, RuleExecution Execution, TimeSpan Time)> Complete(
        Func<string, DelegationResourceScope?> scope, CancellationToken token)
    {
        var results = new List<(IRule, RuleExecution, TimeSpan)>();
        foreach (var rule in rules)
        {
            token.ThrowIfCancellationRequested();
            var watch = Stopwatch.StartNew();
            var findings = new List<Finding>();
            var limits = _inputLimits.Where(value => rule is ConstrainedDelegationToRelevantService
                || value != "ServiceRegistrationUnsupported").ToHashSet(StringComparer.Ordinal);
            if (!captureComplete) limits.Add("CaptureIncomplete");
            var gaps = _preparationGaps[rule.Definition.Id];
            var missing = new Dictionary<string, int>(gaps.Reasons, StringComparer.OrdinalIgnoreCase);
            var notJudged = gaps.Objects;
            foreach (var account in _accounts.Values.OrderBy(value => value.ObjectGuid))
            {
                token.ThrowIfCancellationRequested();
                if (_conflicts.Contains(account.ObjectGuid))
                {
                    notJudged++;
                    Missing("DelegationConfiguration.AccountIdentityAmbiguous");
                    continue;
                }
                var attributeName = AttributeFor(rule);
                var attribute = Find(account, attributeName);
                if (attribute is null) { notJudged++; Missing(attributeName); continue; }
                var localLimits = _sourceLimits[account.ObjectGuid].ToHashSet(StringComparer.Ordinal);
                if (account.Completeness != EvidenceCompleteness.Complete) localLimits.Add("AccountSourceIncomplete");
                if (!attribute.HasValue)
                {
                    if (localLimits.Count != 0)
                    {
                        notJudged++;
                        foreach (var limit in localLimits) Missing("DelegationConfiguration." + limit);
                    }
                    continue;
                }
                if (!captureComplete) localLimits.Add("CaptureIncomplete");
                if (!Ordered(attribute.Values)) localLimits.Add("ConfigurationOrdinalsUnusable");
                if (rule is ConstrainedDelegationToRelevantService)
                {
                    var resources = new Dictionary<Guid, List<DelegationServiceOccurrence>>();
                    foreach (var value in attribute.Values)
                    {
                        if (value.Ordinal < 0 || value.Bytes is not null || value.Text is not { } configured
                            || !DuplicateServicePrincipalNames.Supports(configured))
                        {
                            localLimits.Add("ConfiguredServiceUnsupported");
                            continue;
                        }
                        var owners = _registrations.GetValueOrDefault(configured) ?? [];
                        var unique = owners.Select(owner => owner.Account.ObjectGuid).Distinct().ToArray();
                        if (unique.Length != 1 || _conflicts.Contains(unique[0]) || _unqualifiedRegistrations.Contains(configured))
                        {
                            localLimits.Add(unique.Length == 0 ? "ServiceResourceUnresolved" : "ServiceResourceAmbiguous");
                            continue;
                        }
                        var resource = owners[0].Account;
                        var relevant = Scope(resource.DistinguishedName);
                        if (relevant is null) { localLimits.Add("ResourceRelevanceUnassessed"); continue; }
                        localLimits.UnionWith(_sourceLimits[resource.ObjectGuid].Select(value => "Resource." + value));
                        localLimits.UnionWith(relevant.Limitations.Select(value => "ResourceAnalysis." + value));
                        localLimits.UnionWith(_inputLimits);
                        if (!resources.TryGetValue(resource.ObjectGuid, out var occurrences)) resources.Add(resource.ObjectGuid, occurrences = []);
                        foreach (var owner in owners)
                            occurrences.Add(new(value.Ordinal, configured, owner.Value.Ordinal, owner.Value.Text!));
                    }
                    foreach (var (id, occurrences) in resources.OrderBy(pair => pair.Key))
                    {
                        var resource = _accounts[id];
                        var evidence = Evidence(DelegationConfigurationKind.Constrained, account, resource,
                            Scope(resource.DistinguishedName)!, occurrences.OrderBy(value => value.ConfigurationOrdinal)
                                .ThenBy(value => value.RegistrationOrdinal).ToArray(), [], localLimits);
                        findings.Add(Finding(rule, account, evidence));
                    }
                }
                else
                {
                    var relevant = Scope(account.DistinguishedName);
                    if (relevant is null) { notJudged++; Missing("DelegationConfiguration.ResourceRelevanceUnassessed"); continue; }
                    localLimits.UnionWith(relevant.Limitations.Select(value => "ResourceAnalysis." + value));
                    if (attribute.Values.Count != 1 || attribute.Values[0] is not { Ordinal: 0, Text: null, Bytes: { } bytes })
                    {
                        notJudged++;
                        Missing("DelegationConfiguration.ResourceDescriptorUnavailable");
                        continue;
                    }
                    var grants = ResourceDelegationGrantReader.Read(bytes);
                    localLimits.UnionWith(grants.Limits);
                    if (grants.Grants.Count != 0)
                    {
                        var evidence = Evidence(DelegationConfigurationKind.ResourceBased, account, account, relevant, [], grants.Grants, localLimits);
                        findings.Add(Finding(rule, account, evidence));
                    }
                }
                limits.UnionWith(localLimits);
                if (localLimits.Count != 0)
                {
                    notJudged++;
                    foreach (var limit in localLimits) Missing("DelegationConfiguration." + limit);
                }
            }
            foreach (var limit in limits) if (!missing.ContainsKey("DelegationConfiguration." + limit)) Missing("DelegationConfiguration." + limit);
            var execution = new RuleExecution(rule.Definition,
                missing.Count == 0 && limits.Count == 0 ? RuleExecutionOutcome.Succeeded : RuleExecutionOutcome.Indeterminate,
                _accountCount + _unknownClasses - notJudged, _notApplicable, notJudged,
                missing.OrderBy(value => value.Key, StringComparer.Ordinal).Select(value => new MissingInput(value.Key, value.Value)).ToArray(),
                findings, null);
            watch.Stop();
            results.Add((rule, execution, watch.Elapsed));
            void Missing(string reason) => missing[reason] = missing.GetValueOrDefault(reason) + 1;
        }
        return results;

        DelegationResourceScope? Scope(string dn)
        {
            if (!_scopes.TryGetValue(dn, out var existing)) _scopes.Add(dn, existing = scope(dn));
            return existing;
        }
        DelegationConfigurationEvidence Evidence(DelegationConfigurationKind kind, DelegationConfigurationAccount account,
            DelegationConfigurationAccount resource, DelegationResourceScope relevance, IReadOnlyList<DelegationServiceOccurrence> services,
            IReadOnlyList<ResourceDelegationGrant> grants, HashSet<string> limitations) =>
            new(kind, seal, derivation, derivationSeal, DelegationConfigurationRules.PolicyVersion, SecurityDescriptorParser.Version,
                account, resource, relevance, services, grants, captureComplete, limitations.Order(StringComparer.Ordinal).ToArray());
    }

    private static Finding Finding(IRule rule, DelegationConfigurationAccount account, DelegationConfigurationEvidence evidence) =>
        new(rule.Definition.Id, rule.Definition.Version, Severity.High,
            new(FindingSubjectKind.Account, evidence.ConfigurationKind == DelegationConfigurationKind.Constrained
                ? DelegationConfigurationRules.Key(account.ObjectGuid, evidence.Resource.ObjectGuid) : account.ObjectGuid.ToString("D")),
            account.ObjectGuid, account.DistinguishedName, account.DomainFqdn, account.ObjectClass, Detail(evidence), account.Completeness, evidence)
            { PrincipalName = Find(account, "sAMAccountName")?.OnlyValue?.Text ?? account.DistinguishedName };

    internal static string Detail(DelegationConfigurationEvidence evidence)
    {
        var constrained = evidence.ConfigurationKind == DelegationConfigurationKind.Constrained;
        var detail = constrained ? ConstrainedDelegationToRelevantService.Explanation : ResourceBasedDelegationOnRelevantResource.Explanation;
        detail += "\n\nCaptured resource: " + evidence.Resource.DistinguishedName
            + "\nResource scope: " + (evidence.Scope.EstablishedTier0 ? "Established Tier 0"
                : "Identified controller/dependency relevant to Tier 0; not an established Tier 0 classification")
            + "\nRecorded classification bases: " + string.Join(", ", evidence.Scope.ClassificationBases)
            + "\nRelevant Tier 0 anchors:\n" + string.Join("\n", evidence.Scope.AnchorDns);
        if (constrained)
            detail += "\n\nOriginal configured service values:\n" + string.Join("\n", evidence.Services
                .Select(value => "msDS-AllowedToDelegateTo[" + value.ConfigurationOrdinal + "]: " + value.ConfiguredService
                    + " (captured servicePrincipalName[" + value.RegistrationOrdinal + "]: " + value.RegisteredService + ")"));
        else
        {
            detail += "\n\nRecorded delegation holders:\n" + string.Join("\n", evidence.Grants.Select(grant =>
                grant.TrusteeSid + (grant.NullDacl ? " (NULL DACL)" : " (entries " + string.Join(", ", grant.EntryOrdinals) + ")")));
            var descriptor = SecurityDescriptorParser.Parse(Find(evidence.Resource, DelegationConfigurationRules.ResourceAttribute)!.Values.Single().Bytes!);
            detail += "\n\nOriginal RBCD entries:\n" + (descriptor.DaclState == DaclState.Null ? "NULL DACL" :
                string.Join("\n", descriptor.DaclAces.OrderBy(entry => entry.Ordinal).Select(entry =>
                    "[" + entry.Ordinal + "] " + entry.AceType + " " + entry.TrusteeSid + " mask 0x"
                        + unchecked((uint)entry.AccessMask).ToString("X8", System.Globalization.CultureInfo.InvariantCulture)
                        + " flags 0x" + entry.AceFlags.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)
                        + (entry.HasObjectType ? " object type " + entry.ObjectTypeGuid : "")
                        + (entry.HasInheritedObjectType ? " inherited object type " + entry.InheritedObjectTypeGuid : ""))));
        }
        if (evidence.Limitations.Count != 0 || evidence.Scope.Limitations.Count != 0)
            detail += "\n\nAssessment incomplete:\n" + string.Join("\n",
                evidence.Limitations.Concat(evidence.Scope.Limitations.Select(value => "ResourceAnalysis." + value))
                    .Distinct().Select(DelegationConfigurationLimitations.Describe));
        return detail;
    }

    private static string AttributeFor(IRule rule) => rule is ConstrainedDelegationToRelevantService
        ? DelegationConfigurationRules.ConstrainedAttribute : DelegationConfigurationRules.ResourceAttribute;
    private sealed class PreparationGaps
    {
        internal int Objects { get; private set; }
        internal Dictionary<string, int> Reasons { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal void Add(string reason)
        {
            Objects++;
            Reasons[reason] = Reasons.GetValueOrDefault(reason) + 1;
        }
    }
    internal static ObjectAttribute? Find(DelegationConfigurationAccount account, string name) =>
        account.Attributes.SingleOrDefault(attribute => Same(attribute.LdapDisplayName, name));
    internal static bool Ordered(IReadOnlyList<AttributeValue> values) =>
        values.Select(value => value.Ordinal).Order().SequenceEqual(Enumerable.Range(0, values.Count));
    private static bool Same(string first, string second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
}
