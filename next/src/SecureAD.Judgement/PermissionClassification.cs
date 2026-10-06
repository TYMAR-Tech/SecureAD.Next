using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>The schema meanings and property-set membership used when producing a permission reading.</summary>
public sealed record PermissionSchemaSupport(string Guid, IReadOnlyList<SchemaGuidEntry> Definitions,
    IReadOnlyList<string>? PropertySetMembers, IReadOnlyList<string> AmbiguousNames);

/// <summary>One displayed right and its entry-level risk assessment, not requester authorization.</summary>
public sealed record ClassifiedPermissionRight(PermissionRight Right, PermissionAssessment Assessment);

/// <summary>An original entry, its recorded wording and scope, and the independent assessment of each right.</summary>
public sealed record ClassifiedPermissionEntry(PermissionEntry Entry, string Summary, bool RightsAreComplete,
    PermissionScope Scope, IReadOnlyList<ClassifiedPermissionRight> Rights,
    PermissionSchemaSupport? ObjectType, PermissionSchemaSupport? InheritedObjectType);

/// <summary>A complete production result can still contain incomplete evidence and unclassifiable rights.</summary>
public sealed record PermissionClassification(ObjectPermissions Permissions,
    IReadOnlyList<ClassifiedPermissionEntry> Entries, int ProducerVersion, int SchemaVersion, bool HasCapturedSchema);

/// <summary>A permission classification bound to the exact published judgement and its inputs.</summary>
public sealed record SavedPermissionClassification(JudgementDescription Description, PermissionClassification Classification);

/// <summary>Produces per-right interpretations once during judging; completed-run screens read the saved answers.</summary>
public sealed class PermissionClassificationProducer
{
    /// <summary>The interpretation contract, advanced when production semantics change.</summary>
    public const int Version = 1;
    private readonly SchemaGuidCatalog _catalog;
    private readonly PermissionWordingWriter _words;
    private readonly PermissionScopeWriter _scopes;
    private readonly DangerousPermissionClassifier _risks;
    private readonly Dictionary<string, PermissionSchemaSupport> _support = new(StringComparer.Ordinal);

    /// <summary>Uses the same captured-over-shipped schema for wording, scope and assessment.</summary>
    public PermissionClassificationProducer(SchemaGuidCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        _catalog = catalog;
        _words = new(catalog);
        _scopes = new(catalog);
        _risks = new(catalog);
    }

    /// <summary>Preserves raw masks and original ordinals, including duplicate and unsupported entries.</summary>
    public PermissionClassification CreateObjectResult(ObjectPermissions permissions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        cancellationToken.ThrowIfCancellationRequested();
        var entries = new List<ClassifiedPermissionEntry>();
        foreach (var entry in permissions.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Shorthand remains named and qualified, never expanded into asserted authorization.
            var wording = _words.Describe(entry.AccessMask, entry.ObjectTypeGuid);
            var scope = _scopes.Describe(entry.InheritanceFlags, entry.PropagationFlags,
                entry.IsInherited, entry.InheritedObjectTypeGuid);
            entries.Add(new(entry, wording.Summary, wording.RightsAreComplete, scope,
                [.. wording.Rights.Select(right => new ClassifiedPermissionRight(right, Assess(entry, right)))],
                Support(entry.ObjectTypeGuid), Support(entry.InheritedObjectTypeGuid)));
        }
        return new(permissions, entries, Version, SchemaGuidCatalog.Version, _catalog.HasCapturedEntries);
    }

    private PermissionAssessment Assess(PermissionEntry entry, PermissionRight right)
    {
        if (!right.IsNamed)
            return PermissionAssessment.CannotClassify(PermissionClassificationStorage.Message("UnnamedRight"));
        if (!Enum.TryParse<AceType>(entry.AceType, ignoreCase: false, out var aceType))
            return PermissionAssessment.CannotClassify(PermissionClassificationStorage.Message("UnknownAceType"));
        return _risks.Classify(aceType, right.Bits, entry.ObjectTypeGuid,
            EntryReachReader.FromPropagationFlags(entry.PropagationFlags));
    }

    private PermissionSchemaSupport? Support(string? guid)
    {
        if (guid is null) return null;
        if (_support.TryGetValue(guid, out var support)) return support;
        var definitions = _catalog.FindByGuid(guid);
        support = new(guid, definitions, _catalog.MembersOfPropertySet(guid),
            Array.AsReadOnly(definitions.Select(value => value.LdapName).Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(name => _catalog.FindUnambiguousByLdapName(name) is null).ToArray()));
        _support.Add(guid, support);
        return support;
    }
}
