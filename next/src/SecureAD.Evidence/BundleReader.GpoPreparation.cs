using System.Collections.Immutable;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

public sealed partial class BundleReader
{
    private Dictionary<long, ObjectAttributes>? _gpoPolicyValues;
    private Dictionary<long, ObjectAttributes>? _gpoFilterValues;
    private Dictionary<long, CapturedGpoTemplateVersion>? _gpoTemplates;
    private Dictionary<long, Result<CapturedWmiReference>>? _gpoWmiReferences;
    private Dictionary<long, Result<ImmutableArray<CapturedWmiQuery>>>? _gpoWmiDefinitions;

    internal ObjectAttributes ReadGpoPolicyValues(CapturedObjectIdentity policy,
        IReadOnlyCollection<string> attributes, CancellationToken token) =>
        ReadGpoValues(policy, attributes, token, ref _gpoPolicyValues, "policy");

    private ObjectAttributes ReadGpoFilterValues(CapturedObjectIdentity filter, CancellationToken token) =>
        ReadGpoValues(filter, ["objectClass", "msWMI-ID", "msWMI-Name", "msWMI-Parm2"],
            token, ref _gpoFilterValues, "filter");

    private ObjectAttributes ReadGpoValues(CapturedObjectIdentity identity, IReadOnlyCollection<string> attributes,
        CancellationToken token, ref Dictionary<long, ObjectAttributes>? cache, string kind)
    {
        CheckGpoPreparationLifetime(token);
        RequireIdentity(identity);
        ArgumentNullException.ThrowIfNull(attributes);
        RecordGpoPreparation(kind + "-metadata-request");
        var selected = attributes.ToHashSet(StringComparer.OrdinalIgnoreCase);
        ObjectAttributes? known = null;
        if (cache is not null) cache.TryGetValue(identity.ObjectId, out known);
        var missing = known is null ? selected.ToArray()
            : selected.Where(name => known.Find(name) is null).ToArray();
        if (known is null || missing.Length != 0)
        {
            RecordGpoPreparation(kind + "-metadata-read");
            var read = ObjectAttributesReader.ReadAt(Connection, identity.ObjectId, missing)?.Snapshot()
                ?? throw new InvalidDataException("The captured object identity no longer exists.");
            // Read only requested fields, so an unrelated unusable value cannot break this view.
            known = known is null ? read : known with
            {
                Attributes = known.Attributes.Concat(read.Attributes)
                    .OrderBy(value => value.LdapDisplayName, StringComparer.OrdinalIgnoreCase).ToImmutableArray(),
            };
            CheckGpoPreparationLifetime(token);
            if (_protection is not null) (cache ??= [])[identity.ObjectId] = known;
        }
        else RecordGpoPreparation(kind + "-metadata-hit");
        CheckGpoPreparationLifetime(token);
        return known with
        {
            Attributes = known.Attributes.Where(value => selected.Contains(value.LdapDisplayName)).ToImmutableArray(),
        };
    }

    private Result<CapturedWmiReference> ReadPreparedWmiReference(long policyId, string raw, CancellationToken token)
    {
        CheckGpoPreparationLifetime(token);
        if (_gpoWmiReferences is not null && _gpoWmiReferences.TryGetValue(policyId, out var saved))
        {
            RecordGpoPreparation("wmi-reference-hit");
            return saved;
        }
        RecordGpoPreparation("wmi-reference-decode");
        var reference = CapturedWmiEncoding.Reference(raw);
        CheckGpoPreparationLifetime(token);
        if (_protection is not null) (_gpoWmiReferences ??= []).Add(policyId, reference);
        return reference;
    }

    private void CheckGpoPreparationLifetime(CancellationToken token)
    {
        _ = Connection;
        token.ThrowIfCancellationRequested();
        _nameLookupCancellation.ThrowIfCancellationRequested();
    }

    private void ClearGpoPreparation()
    {
        _gpoPolicyValues = null;
        _gpoFilterValues = null;
        _gpoTemplates = null;
        _gpoWmiReferences = null;
        _gpoWmiDefinitions = null;
    }

    internal void RecordGpoPreparation(string operation)
    {
        if (!GpoPreparations.Enabled) return;
        GpoPreparations.Add(1, new KeyValuePair<string, object?>("operation", operation),
            new KeyValuePair<string, object?>("source", _nameLookupSource ??= Connection.DataSource),
            new KeyValuePair<string, object?>("bundle", BundleDirectory));
    }
}
