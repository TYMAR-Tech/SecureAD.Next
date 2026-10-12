using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-014 reports unexpected RBCD-attribute write permission, not successful impersonation.</summary>
public sealed class UnexpectedResourceBasedDelegationWrite : IObjectRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = AttributeWriteRules.Definition("SEC-014", "Unexpected RBCD-configuration write permission");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) => throw AttributeWriteRules.InputsRequired();
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) => AttributeWriteRules.Judge(subject, context, Definition);
}

/// <summary>SEC-024 reports unexpected SPN-attribute write permission, not restricted validated-SPN permission.</summary>
public sealed class UnexpectedServicePrincipalNameWrite : IObjectRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = AttributeWriteRules.Definition("SEC-024", "Unexpected service-principal-name write permission");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) => throw AttributeWriteRules.InputsRequired();
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) => AttributeWriteRules.Judge(subject, context, Definition);
}

/// <summary>SEC-025 reports unexpected key-credential attribute write permission, not successful authentication.</summary>
public sealed class UnexpectedKeyCredentialLinkWrite : IObjectRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = AttributeWriteRules.Definition("SEC-025", "Unexpected key-credential-link write permission");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) => throw AttributeWriteRules.InputsRequired();
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) => AttributeWriteRules.Judge(subject, context, Definition);
}

internal static class AttributeWriteRules
{
    internal const string ScopeNote = "This finding establishes permission to write the named attribute. It does not prove a successful directory change, "
        + "service impersonation, authentication, account takeover or a completed path to Tier 0.";
    internal const string Guidance = "Review the named holder and the original granting entries. Remove only the unintended write permission, "
        + "checking other rights in the same entry and any inherited or group-held grant before changing it. "
        + "Review service and sign-in dependencies first; removing a legitimate grant can break them.";

    internal static RuleDefinition Definition(string id, string title) => new(id, title, Severity.High, 1,
        ["user", "computer", "inetOrgPerson", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"],
        ["objectClass", "objectGUID", "objectSid", "nTSecurityDescriptor", "userAccountControl", "sAMAccountName", "schemaIDGUID",
            "lDAPDisplayName", "attributeSecurityGUID"],
        [nameof(DerivedFactKind.ProtectedPrincipals), nameof(DerivedFactKind.AdministrativeMembership)]);

    internal static bool IsAttributeWrite(ControlCapability capability) => capability is ControlCapability.CanWriteKeyCredentialLink
        or ControlCapability.CanWriteServicePrincipalName or ControlCapability.CanWriteResourceBasedConstrainedDelegation;

    internal static (AttributeWritePermissionKind Kind, ControlCapability Capability, string Attribute, string Guid) Operation(string rule)
    {
        var operation = rule switch
        {
            "SEC-014" => (Kind: AttributeWritePermissionKind.ResourceBasedConstrainedDelegation, Capability: ControlCapability.CanWriteResourceBasedConstrainedDelegation,
                Attribute: "msDS-AllowedToActOnBehalfOfOtherIdentity"),
            "SEC-024" => (Kind: AttributeWritePermissionKind.ServicePrincipalName, Capability: ControlCapability.CanWriteServicePrincipalName,
                Attribute: "servicePrincipalName"),
            "SEC-025" => (Kind: AttributeWritePermissionKind.KeyCredentialLink, Capability: ControlCapability.CanWriteKeyCredentialLink,
                Attribute: "msDS-KeyCredentialLink"),
            _ => throw new InvalidDataException("The attribute-write rule is not supported."),
        };
        return (operation.Kind, operation.Capability, operation.Attribute,
            SchemaGuidCatalog.Embedded.GuidFor(operation.Attribute) ?? throw new InvalidDataException("The property has no authoritative schema identity."));
    }

    internal static string RuleFor(AttributeWritePermissionKind kind) => kind switch
    {
        AttributeWritePermissionKind.ResourceBasedConstrainedDelegation => "SEC-014",
        AttributeWritePermissionKind.ServicePrincipalName => "SEC-024",
        AttributeWritePermissionKind.KeyCredentialLink => "SEC-025",
        _ => throw new InvalidDataException("The attribute-write permission kind is not supported."),
    };

    internal static RuleVerdict Judge(ObjectAttributes subject, JudgingContext context, RuleDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (subject.Find("objectClass")?.Values.Any(value => !string.IsNullOrWhiteSpace(value.Text)) != true)
            return RuleVerdict.CouldNotJudge(["objectClass"]);
        if (!IsAccount(subject)) return RuleVerdict.Judged([]);
        return context.AttributeWrites is { } assessment ? assessment.For(subject, definition)
            : RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.NotDerived)]);
    }

    private static readonly string[] AccountClasses = ["user", "computer", "inetOrgPerson", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"];
    internal static bool IsAccount(ObjectAttributes subject) => subject.Find("objectClass")?.Values.Any(value =>
        AccountClasses.Contains(value.Text, StringComparer.OrdinalIgnoreCase)) == true;
    internal static string Key(string holder, string? scope) => holder.ToUpperInvariant() + ":" + (scope?.ToUpperInvariant() ?? "");
    internal static InvalidOperationException InputsRequired() => new("The attribute-write rules require their declared prepared permission inputs.");
}

internal sealed class AttributeWriteAssessment(ObjectAttributes subject, ControlObjectEvaluation permissions,
    JudgingContext context, Tier0InputBinding binding, bool captureComplete, bool unsupportedMask, Guid generation)
{
    internal RuleVerdict For(ObjectAttributes offered, RuleDefinition rule)
    {
        if (!ReferenceEquals(offered, subject)) throw new InvalidOperationException("The attribute-write assessment belongs to another captured object.");
        if (!binding.IsSupported || permissions.Target != subject.DistinguishedName
            || permissions.Edges.Any(edge => edge.GenerationId != generation || edge.DerivationGenerationId != binding.DerivationGenerationId
                || edge.Target != subject.DistinguishedName || edge.TargetGuid != subject.ObjectGuid))
            throw new InvalidDataException("The attribute-write assessment does not match its captured object and analysis generation.");
        if (subject.ObjectGuid is null || subject.ObjectGuid == Guid.Empty) return RuleVerdict.CouldNotJudge(["objectGUID"]);
        var operation = AttributeWriteRules.Operation(rule.Id);
        var catalogue = context.SchemaGuids;
        var attribute = catalogue?.FindUnambiguousByLdapName(operation.Attribute);
        // A shipped GUID can name a permission, but cannot prove this captured forest carries the attribute.
        if (attribute is not { Kind: SchemaGuidKind.Attribute, Source: SchemaGuidSource.Captured }
            || !Same(attribute.Guid, operation.Guid))
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.AttributeWriteSchemaUnavailable)]);
        if (context.AdministrativeMembership is not { } identities) return RuleVerdict.CouldNotResolve(
            [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable)]);
        var identity = identities.QualifyTarget(subject);
        if (identity.Identity is not { } target || target.ObjectClass is not ("user" or "computer" or "inetOrgPerson"))
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable)]);
        var targetClass = subject.Find("objectClass")!.Values[^1].Text!;
        var classDefinition = catalogue!.FindByLdapName(targetClass);
        var candidates = permissions.Edges.Where(edge => edge.Capability == operation.Capability).ToArray();
        var limits = new HashSet<string>();
        var controls = subject.Find("userAccountControl")?.Values ?? [];
        var control = ServiceAccountReading.ReadControl(controls);
        if (control is null) limits.Add("AccountStateUnreadable");
        if (unsupportedMask) limits.Add("UnsupportedGenericMask");
        if (!captureComplete) limits.Add("CaptureIncomplete");
        foreach (var limitation in identity.Limitations) limits.Add(limitation.Reason.ToString());
        if ((permissions.Uncertainty & (ControlUncertainty.DescriptorIncomplete | ControlUncertainty.DescriptorUnreadable)) != 0)
            limits.Add(permissions.Uncertainty.ToString());
        foreach (var edge in candidates)
        {
            if (!edge.IsComplete) limits.Add(edge.Uncertainty.ToString());
            if (edge.Expectedness == ControlExpectedness.Unknown) limits.Add(edge.ExpectednessReason.ToString());
        }
        if (permissions.DescriptorOutcome is "DescriptorNotRead" or "EntriesUnparsed") limits.Add("DescriptorUnreadable");
        var savedLimits = limits.Order(StringComparer.Ordinal).ToArray();
        var findings = candidates.Where(edge => edge.IsComplete && edge.Expectedness == ControlExpectedness.Unexpected)
            .OrderBy(edge => edge.HolderSid, StringComparer.OrdinalIgnoreCase).ThenBy(edge => edge.HolderScope, StringComparer.OrdinalIgnoreCase)
            .Select(edge =>
            {
                var entries = edge.Evidence.OrderBy(entry => entry.Ordinal).ToArray();
                var guids = entries.Where(entry => entry.ObjectTypeGuid is not null).Select(entry => entry.ObjectTypeGuid!)
                    .Append(attribute.Guid).ToHashSet(StringComparer.OrdinalIgnoreCase);
                // A GUID may name both an attribute and a validated write; retain every indexed meaning.
                var definitions = guids.SelectMany(catalogue.FindByGuid).Append(attribute);
                if (classDefinition is not null) definitions = definitions.Append(classDefinition);
                var schema = definitions.Distinct()
                    .OrderBy(entry => entry.LdapName, StringComparer.Ordinal).ThenBy(entry => entry.Guid, StringComparer.Ordinal).ToArray();
                var sets = guids.Order(StringComparer.Ordinal).Select(guid => (Guid: guid, Members: catalogue.MembersOfPropertySet(guid)))
                    .Where(pair => pair.Members is not null).ToDictionary(pair => pair.Guid, pair => pair.Members!, StringComparer.OrdinalIgnoreCase);
                var proof = new AttributeWritePermissionEvidence(edge.GenerationId, binding.EvidenceSeal, binding.DerivationGenerationId,
                    binding.DerivationSeal, PrincipalClassificationRegistry.Version, ControlEdgeStorage.EngineVersion, operation.Kind, target, identity.Domains,
                    controls.Select(value => value with { Bytes = value.Bytes?.ToArray() }).ToArray(),
                    edge.HolderSid, edge.HolderScope, edge.HolderName, edge.ExpectednessReason.ToString(), attribute, schema, sets,
                    entries.Select(entry =>
                    {
                        var scope = ControlEdgeDeriver.OperationScope(entry, 0x20, operation.Attribute, targetClass, catalogue);
                        return new AttributeWritePermissionScope(entry.Ordinal, scope.State.ToString(), scope.Source);
                    }).ToArray(), entries, edge.DescriptorOutcome, savedLimits);
                var name = edge.HolderName ?? edge.HolderSid;
                var disabled = control is null ? " The target account's enabled or disabled state could not be read."
                    : (control.Value & 2) != 0 ? " The target account is currently disabled; the permission remains a dormant exposure." : "";
                var detail = name + " holds unexpected write permission on " + operation.Attribute + " on " + subject.DistinguishedName
                    + ". " + AttributeWriteRules.ScopeNote + disabled
                    + "\n\nOriginal permission entries:\n" + string.Join("\n", entries.Select(entry => "Entry " + entry.Ordinal + ": "
                        + entry.AceType + "; " + entry.Trustee.Sid + "; mask 0x" + entry.AccessMask.ToString("X8")
                        + (entry.ObjectTypeGuid is null ? "; all properties" : "; scope " + entry.ObjectTypeGuid)
                        + (entry.IsInherited ? "; inherited" : "; explicit")));
                if (savedLimits.Length != 0) detail += "\n\nOther permission or expectedness inputs remain incomplete: " + string.Join("; ", savedLimits) + ".";
                return new Finding(rule.Id, rule.Version, rule.Severity, new(FindingSubjectKind.Account, AttributeWriteRules.Key(edge.HolderSid, edge.HolderScope)),
                    subject.ObjectGuid.Value, subject.DistinguishedName, subject.DomainFqdn!, targetClass, detail,
                    subject.Completeness, proof) { PrincipalName = name };
            }).ToArray();
        return new(findings, control is null ? ["userAccountControl"] : [], savedLimits.Length == 0 ? []
            : [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.AttributeWriteIncomplete)]);
    }

    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
}
