using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public sealed class UnexpectedGpoDirectoryControl : IObjectRule
{
    public RuleDefinition Definition { get; } = GpoDirectoryPermissionRules.Definition("SEC-080");
    public RuleVerdict Judge(ObjectAttributes subject) => throw GpoDirectoryPermissionRules.InputsRequired();
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) =>
        GpoDirectoryPermissionRules.Judge(subject, context, Definition);
}

public sealed class UnexpectedGroupPolicyLinkWrite : IObjectRule
{
    public RuleDefinition Definition { get; } = GpoDirectoryPermissionRules.Definition("SEC-081");
    public RuleVerdict Judge(ObjectAttributes subject) => throw GpoDirectoryPermissionRules.InputsRequired();
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) =>
        GpoDirectoryPermissionRules.Judge(subject, context, Definition);
}

internal sealed record GpoDirectoryPermissionInputs(Guid GenerationId, Tier0InputBinding Binding,
    Func<string, string?> DomainSid, bool CaptureIsComplete, CancellationToken CancellationToken);

internal sealed record GpoDirectoryOperationDefinition(GpoDirectoryOperation Operation, string? Attribute, string Label, int Mask);

internal static class GpoDirectoryPermissionRules
{
    internal const int EngineVersion = 1;
    internal const string Caution = "This is captured directory-permission evidence, not authorization for every group member. "
        + "It does not prove a policy change, SYSVOL file modification, client processing or a completed path to Tier 0.";
    internal const string Incomplete = "GPO-directory or link permissions and expected-holder scope could not be fully assessed "
        + "from the captured evidence. Established findings remain valid; other access may exist.";
    private static readonly GpoDirectoryOperationDefinition[] Operations =
    [
        new(GpoDirectoryOperation.PolicyFilePath, "gPCFileSysPath", "Policy-file path", 0x20),
        new(GpoDirectoryOperation.FunctionalityVersion, "gPCFunctionalityVersion", "Policy functionality version", 0x20),
        new(GpoDirectoryOperation.EnablementFlags, "flags", "Policy enablement flags", 0x20),
        new(GpoDirectoryOperation.PolicyVersion, "versionNumber", "Policy version", 0x20),
        new(GpoDirectoryOperation.ComputerExtensions, "gPCMachineExtensionNames", "Computer extension list", 0x20),
        new(GpoDirectoryOperation.UserExtensions, "gPCUserExtensionNames", "User extension list", 0x20),
        new(GpoDirectoryOperation.WmiFilter, "gPCWQLFilter", "WMI-filter reference", 0x20),
        new(GpoDirectoryOperation.PermissionList, null, "Change permissions on the GPO directory object", 0x40000),
        new(GpoDirectoryOperation.Links, "gPLink", "Group Policy links", 0x20),
    ];

    internal static RuleDefinition Definition(string rule) => new(rule, Title(rule), Severity.High, 1,
        rule == "SEC-080" ? ["groupPolicyContainer"] : ["domainDNS", "domain", "organizationalUnit", "site"],
        ["objectClass", "objectGUID", "displayName", "nTSecurityDescriptor", "schemaIDGUID", "lDAPDisplayName", "attributeSecurityGUID"],
        [nameof(DerivedFactKind.ProtectedPrincipals), nameof(DerivedFactKind.AdministrativeMembership)]);
    internal static string Title(string rule) => rule switch
    {
        "SEC-080" => "Unexpected GPO-directory control permission",
        "SEC-081" => "Unexpected Group Policy link-write permission",
        _ => throw Invalid(),
    };
    internal static string Explanation(string rule) => rule switch
    {
        "SEC-080" => "The captured permissions establish control over this GPO's policy-related directory properties "
            + "or permission list. Review whether this delegation is required.",
        "SEC-081" => "The captured permissions establish write access to Group Policy links at this scope. "
            + "This can change the linked GPOs, their order or link options.",
        _ => throw Invalid(),
    };
    internal static string Action(string rule) => rule switch
    {
        "SEC-080" => "Review the named holder and granting entries. Restrict only unintended directory control, "
            + "checking legitimate GPO administration and service dependencies before changing access.",
        "SEC-081" => "Confirm who should manage links here. If access is unintended, restrict the recorded link-write delegation. "
            + "Review policy dependencies before changing permissions or links.",
        _ => throw Invalid(),
    };
    internal static IReadOnlyList<GpoDirectoryOperationDefinition> For(string rule) => rule switch
    {
        "SEC-080" => Operations.Where(operation => operation.Operation != GpoDirectoryOperation.Links).ToArray(),
        "SEC-081" => [Operations[^1]],
        _ => throw Invalid(),
    };
    internal static GpoDirectoryOperationDefinition Operation(GpoDirectoryOperation value) =>
        Operations.SingleOrDefault(operation => operation.Operation == value) ?? throw Invalid();
    internal static InvalidOperationException InputsRequired() => new("The GPO-directory rules require their declared prepared permission inputs.");
    internal static InvalidDataException Invalid() => new("The saved GPO-directory permission or its source binding is invalid.");
    internal static string Key(string holder, string? scope) => AttributeWriteRules.Key(holder, scope);

    internal static RuleVerdict Judge(ObjectAttributes subject, JudgingContext context, RuleDefinition rule)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (subject.Find("objectClass")?.Values.Any(value => !string.IsNullOrWhiteSpace(value.Text)) != true)
            return RuleVerdict.CouldNotJudge(["objectClass"]);
        if (!rule.IsAbout(subject)) return RuleVerdict.Judged([]);
        if (rule.Id == "SEC-081" && AttributeReading.LastText(subject, "objectClass") is "domain" or "domainDNS")
        {
            if (context.NamingContexts is null) return Unresolved();
            if (!context.NamingContexts.TryGetValue(subject.DistinguishedName, out var kind) || kind != NamingContextKind.Domain)
                return RuleVerdict.Judged([]);
        }
        if (context.GpoDirectoryPermissions is not { } inputs) return Unresolved();
        return Assess(subject, context, inputs, rule);
    }

    private static RuleVerdict Unresolved() => RuleVerdict.CouldNotResolve(
        [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.GpoDirectoryPermissionIncomplete)]);

    private static RuleVerdict Assess(ObjectAttributes subject, JudgingContext context,
        GpoDirectoryPermissionInputs inputs, RuleDefinition rule)
    {
        if (inputs.GenerationId == Guid.Empty || !inputs.Binding.IsSupported) throw Invalid();
        if (subject.ObjectGuid is not { } guid || guid == Guid.Empty) return RuleVerdict.CouldNotJudge(["objectGUID"]);
        if (context.Permissions?.Invoke(subject.DistinguishedName) is not { } permissions
            || permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
            return Unresolved();
        if (permissions.DistinguishedName != subject.DistinguishedName
            || !permissions.Entries.Select(entry => entry.Ordinal).SequenceEqual(permissions.Entries.Select(entry => entry.Ordinal).Order())
            || permissions.Entries.Select(entry => entry.Ordinal).Distinct().Count() != permissions.Entries.Count) throw Invalid();
        var classes = subject.Find("objectClass")!.Values.Select(value => value.Text).OfType<string>().ToArray();
        var targetClass = classes[^1];
        if (string.IsNullOrWhiteSpace(subject.DomainFqdn)) return Unresolved();
        var operations = For(rule.Id);
        var catalogue = context.SchemaGuids;
        if (catalogue is null) return Unresolved();
        var target = new GpoDirectoryResource(guid, subject.DistinguishedName, subject.DomainFqdn, targetClass,
            rule.Id == "SEC-080" ? AttributeReading.Text(subject, "displayName") : null, subject.CapturedUtc);
        var mask = operations.Aggregate(0, (all, operation) => all | operation.Mask);
        var holders = permissions.Entries.Where(entry => FullControlEvaluator.Applies(entry)
            && (entry.AccessMask & mask) != 0 && entry.AceType.StartsWith("AccessAllowed", StringComparison.Ordinal))
            .Select(entry => entry.Trustee).DistinctBy(holder => holder.Sid, StringComparer.OrdinalIgnoreCase).ToList();
        if (permissions.DaclState == DaclState.Null)
            holders.Add(new("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null));
        var findings = new List<Finding>();
        var unresolved = new HashSet<UnresolvedInput>();
        if (permissions.DaclCompleteness != DaclCompleteness.Complete)
            unresolved.Add(new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.GpoDirectoryPermissionIncomplete));
        foreach (var holder in holders)
        {
            inputs.CancellationToken.ThrowIfCancellationRequested();
            var holderScope = Sid.IsBuiltinDomain(holder.Sid) ? subject.DomainFqdn : null;
            var routes = context.MembershipRoutes?.Invoke(holder.Sid, holderScope)
                ?? context.ProtectedPrincipals?.Lookup(holder.Sid, holderScope)?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
            var domains = new[] { subject.DomainFqdn, holder.DomainFqdn, context.ForestFqdn }.OfType<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(domain => domain, inputs.DomainSid, StringComparer.OrdinalIgnoreCase);
            var source = new FullControlSource(subject.DistinguishedName, guid, null, subject.DomainFqdn, classes, holder, holderScope,
                !Sid.IsBuiltinDomain(holder.Sid) || ControlEdgeDeriver.IsDomainTarget(subject, context.ForestFqdn)
                    && !string.IsNullOrWhiteSpace(inputs.DomainSid(subject.DomainFqdn)),
                context.NamingContexts?.ContainsKey(subject.DistinguishedName) == true,
                permissions.Availability, permissions.DaclState, permissions.DaclCompleteness, permissions.DaclWasCanonical, permissions.Entries);
            var rights = operations.Select(operation => Evaluate(source, operation, catalogue)).ToArray();
            var established = rights.Any(right => right.State == GpoDirectoryPermissionState.Established);
            var expected = ControlEdgeDeriver.Expected(holder, subject, context.ForestFqdn, routes,
                permissions.DaclCompleteness == DaclCompleteness.Complete,
                established && permissions.DaclState != DaclState.Null, inputs.DomainSid);
            var limits = rights.SelectMany(right => right.Limitations).Distinct(StringComparer.Ordinal).ToList();
            if (!inputs.CaptureIsComplete) limits.Add("CaptureIncomplete");
            if (rights.Any(right => !right.IsComplete) || expected.State == ControlExpectedness.Unknown
                || permissions.DaclCompleteness != DaclCompleteness.Complete)
            {
                unresolved.Add(new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.GpoDirectoryPermissionIncomplete));
                if (expected.State == ControlExpectedness.Unknown) limits.Add(expected.Reason.ToString());
            }
            if (!established || expected.State != ControlExpectedness.Unexpected) continue;
            var definitions = operations.Where(operation => operation.Attribute is not null)
                .SelectMany(operation => catalogue.FindByLdapName(operation.Attribute!) is { } definition ? new[] { definition } : [])
                .Concat(permissions.Entries.Where(entry => entry.ObjectTypeGuid is not null)
                    .SelectMany(entry => catalogue.FindByGuid(entry.ObjectTypeGuid!)));
            if (catalogue.FindByLdapName(targetClass) is { } classDefinition) definitions = definitions.Append(classDefinition);
            var schemas = definitions.Distinct().OrderBy(entry => entry.LdapName, StringComparer.Ordinal).ThenBy(entry => entry.Guid, StringComparer.Ordinal).ToArray();
            var sets = permissions.Entries.Where(entry => entry.ObjectTypeGuid is not null).Select(entry => entry.ObjectTypeGuid!)
                .Distinct(StringComparer.OrdinalIgnoreCase).Select(value => (Guid: value, Members: catalogue.MembersOfPropertySet(value)))
                .Where(value => value.Members is not null).ToDictionary(value => value.Guid, value => value.Members!, StringComparer.OrdinalIgnoreCase);
            foreach (var assignment in catalogue.PropertySetsForAttributes(operations.Select(operation => operation.Attribute).OfType<string>()))
                sets[assignment.Key] = assignment.Value;
            var evidence = new GpoDirectoryPermissionEvidence(inputs.GenerationId, inputs.Binding.EvidenceSeal,
                inputs.Binding.DerivationGenerationId, inputs.Binding.DerivationSeal, PrincipalClassificationRegistry.Version, EngineVersion,
                rule.Id, target, classes, holder, holderScope, source.NamingContextRootEstablished, permissions,
                context.ForestFqdn, domains, routes, expected.Reason.ToString(),
                schemas, sets, rights, limits.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
            findings.Add(new(rule.Id, rule.Version, rule.Severity, new(FindingSubjectKind.Account, Key(holder.Sid, holderScope)),
                guid, subject.DistinguishedName, subject.DomainFqdn, targetClass, Explanation(rule.Id), subject.Completeness, evidence)
                { PrincipalName = holder.Name ?? holder.Sid });
        }
        return new(findings, [], unresolved.ToArray());
    }

    internal static GpoDirectoryRight Evaluate(FullControlSource source, GpoDirectoryOperationDefinition operation, SchemaGuidCatalog catalogue)
    {
        var scopes = source.Entries.Where(entry => FullControlEvaluator.Applies(entry) && (entry.AccessMask & operation.Mask) != 0)
            .Select(entry =>
            {
                var scope = operation.Attribute is null
                    ? (entry.HasObjectType ? ControlEvaluationState.Unknown : ControlEvaluationState.Established,
                        "Original standard WRITE_DAC permission.")
                    : ControlEdgeDeriver.AttributeScope(entry, operation.Attribute, source.Classes.LastOrDefault(), catalogue);
                return new GpoDirectoryEntryScope(entry.Ordinal, State(scope.Item1), scope.Item2);
            }).ToArray();
        if (operation.Attribute is { } name && catalogue.FindUnambiguousByLdapName(name) is not
            { Kind: SchemaGuidKind.Attribute, Source: SchemaGuidSource.Captured })
            return new(operation.Operation, GpoDirectoryPermissionState.Unresolved, [], [], scopes, ["CapturedAttributeSchemaUnavailable"]);
        if (operation.Attribute is not null && catalogue.FindUnambiguousByLdapName(source.Classes.LastOrDefault() ?? "") is not
            { Kind: SchemaGuidKind.ObjectClass, Source: SchemaGuidSource.Captured })
            return new(operation.Operation, GpoDirectoryPermissionState.Unresolved, [], [], scopes, ["CapturedTargetClassSchemaUnavailable"]);
        var lookup = scopes.ToDictionary(scope => scope.Ordinal);
        bool? MatchDeny(PermissionEntry entry) =>
            source.Holder.Sid == "S-1-5-11" && entry.Trustee.Sid == "S-1-1-0" ? true : null;
        var answer = FullControlEvaluator.AssessAttributeRight(source, operation.Mask, entry =>
            lookup.TryGetValue(entry.Ordinal, out var scope) ? ControlState(scope.State) : ControlEvaluationState.NotEstablished,
            MatchDeny, false);
        return new(operation.Operation, State(answer.State), answer.GrantOrdinals, answer.BlockingOrdinals, scopes,
            Enum.GetValues<ControlUncertainty>().Where(value => value != ControlUncertainty.None && (answer.Uncertainty & value) == value)
                .Select(value => value.ToString()).ToArray());
    }

    internal static GpoDirectoryPermissionState State(ControlEvaluationState state) => state switch
    {
        ControlEvaluationState.Established => GpoDirectoryPermissionState.Established,
        ControlEvaluationState.NotEstablished => GpoDirectoryPermissionState.NotEstablished,
        ControlEvaluationState.Unknown => GpoDirectoryPermissionState.Unresolved,
        _ => throw Invalid(),
    };
    private static ControlEvaluationState ControlState(GpoDirectoryPermissionState state) => state switch
    {
        GpoDirectoryPermissionState.Established => ControlEvaluationState.Established,
        GpoDirectoryPermissionState.NotEstablished => ControlEvaluationState.NotEstablished,
        GpoDirectoryPermissionState.Unresolved => ControlEvaluationState.Unknown,
        _ => throw Invalid(),
    };
}
