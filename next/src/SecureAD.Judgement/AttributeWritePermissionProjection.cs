using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed record SavedWriteEntrySource(int Ordinal, bool IsDeny, string Sid, string? ObjectType,
    bool HasObjectType, bool IsInherited);

internal sealed class AttributeWritePermissionProjection
{
    private readonly SavedProofJsonReader _json;
    private readonly IReadOnlyList<SavedWriteEntrySource> _entries;
    private readonly AttributeWritePermissionKind _kind;
    private readonly string _attributeName, _attributeGuid, _invalidDetails;
    private readonly Dictionary<string, SchemaGuidEntry> _definitions = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _scopes = [];
    private bool _captureIncomplete, _otherLimitations, _stateUnreadable;
    private long _scopeCount;

    private AttributeWritePermissionProjection(SavedProofJsonReader json, IReadOnlyList<SavedWriteEntrySource> entries, string ruleId)
    {
        (_json, _entries) = (json, entries);
        var operation = AttributeWriteRules.Operation(ruleId);
        (_kind, _attributeName, _attributeGuid) = (operation.Kind, operation.Attribute, operation.Guid);
        _invalidDetails = SavedAttributeWritePermission.InvalidDetailsForRule(ruleId);
    }

    internal static SavedAttributeWritePermission Read(Stream stream, FindingListItem selected, JudgementDescription description,
        string derivationSeal, IReadOnlyList<SavedWriteEntrySource> entries, long totalEntries,
        AttributeWritePermissionMark? after, AttributeWritePermissionMark? next, CancellationToken token) =>
        SavedProofJsonReader.Read(stream, token, SavedAttributeWritePermission.InvalidDetailsForRule(selected.RuleId), json =>
            new AttributeWritePermissionProjection(json, entries, selected.RuleId).Read(selected, description, derivationSeal, totalEntries, after, next));

    private SavedAttributeWritePermission Read(FindingListItem selected, JudgementDescription description,
        string derivationSeal, long totalEntries, AttributeWritePermissionMark? after, AttributeWritePermissionMark? next)
    {
        Guid targetGuid = Guid.Empty;
        string? dn = null, domain = null, targetSid = null, actualClass = null;
        string? holder = null, holderScope = null, holderName = null, reason = null, outcome = null;
        uint? control = null;
        var attributeValid = false;
        var keys = _json.Object(name =>
        {
            switch (name)
            {
                case "GenerationId": _json.Require(_json.GuidValue() == description.GenerationId); break;
                case "EvidenceSeal": _json.Require(_json.Text() == description.EvidenceSeal); break;
                case "DerivationGenerationId": _json.Require(_json.GuidValue() == description.DerivationGenerationId); break;
                case "DerivationSeal": _json.Require(_json.Text() == derivationSeal); break;
                case "PrincipalCatalogueVersion": _json.Require(_json.Number() == PrincipalClassificationRegistry.Version); break;
                case "ControlEngineVersion": _json.Require(_json.Number() == ControlEdgeStorage.EngineVersion); break;
                case "PermissionKind": _json.Require(_json.Text() == _kind.ToString()); break;
                case "Target": (targetGuid, dn, domain, targetSid, actualClass) = Target(); break;
                case "Domains": _json.Skip("array"); break;
                case "AccountControl": control = AccountControl(); break;
                case "HolderSid": holder = _json.Text(); break;
                case "HolderScope": holderScope = _json.OptionalText(); break;
                case "HolderName": holderName = _json.OptionalText(); break;
                case "ExpectednessReason": reason = _json.Text(); break;
                case "Attribute":
                    var attribute = Definition();
                    attributeValid = attribute.Kind == SchemaGuidKind.Attribute && attribute.Source == SchemaGuidSource.Captured
                        && attribute.LdapName == _attributeName && Same(attribute.Guid, _attributeGuid);
                    break;
                case "SchemaEntries":
                    _json.Array(() =>
                    {
                        var definition = Definition();
                        // Attribute/validated-write aliases are not assignment-breadth definitions.
                        if (definition.Kind is SchemaGuidKind.PropertySet or SchemaGuidKind.ObjectClass
                            && _entries.Any(entry => Same(entry.ObjectType, definition.Guid)))
                            _json.Require(_definitions.TryAdd(definition.Guid, definition));
                    });
                    break;
                case "PropertySetMembers": _json.Skip("object"); break;
                case "Scopes": Scopes(); break;
                case "Entries": _json.Require(_json.Array(() => throw Invalid()) == 0); break;
                case "DescriptorOutcome": outcome = _json.Text(); break;
                case "Limitations":
                    _json.Array(() =>
                    {
                        var limitation = _json.Text();
                        if (limitation == "CaptureIncomplete") _captureIncomplete = true;
                        else _otherLimitations = true;
                        if (limitation == "AccountStateUnreadable") _stateUnreadable = true;
                    });
                    break;
                case "IsComplete":
                    var complete = _json.Bit();
                    _json.Require(complete == selected.EvidenceIsComplete);
                    break;
                default: throw Invalid();
            }
        });
        _json.RequireKeys(keys, "GenerationId", "EvidenceSeal", "DerivationGenerationId", "DerivationSeal",
            "PrincipalCatalogueVersion", "ControlEngineVersion", "PermissionKind", "Target", "Domains", "AccountControl",
            "HolderSid", "HolderScope", "HolderName", "ExpectednessReason", "Attribute", "SchemaEntries", "PropertySetMembers",
            "Scopes", "Entries", "DescriptorOutcome", "Limitations", "IsComplete");
        var nullDacl = outcome == nameof(EffectiveAccessOutcome.GrantsEveryoneEverything);
        _json.Require(attributeValid && holder is not null && reason is not null && Sid.ToBytes(targetSid) is not null
            && _scopeCount == totalEntries && _scopes.Count == _entries.Count
            && (control is not null || _stateUnreadable)
            && (nullDacl ? totalEntries == 0 && after is null && next is null && holder == "S-1-1-0"
                : outcome == nameof(EffectiveAccessOutcome.Computed) && totalEntries > 0));
        var context = new AttributeWritePermissionContext(selected.Reference!.Value, selected.Subject,
            new(targetGuid, dn!, domain!, actualClass!), holder!, holderScope, holderName, reason!,
            control is null ? null : (control.Value & 2) != 0, nullDacl, selected.EvidenceIsComplete,
            _captureIncomplete, _otherLimitations, _kind);
        _json.Require(context.Matches(selected));
        var rows = _entries.Select(entry => Row(entry, targetSid!, holder!)).ToArray();
        var page = new SavedAttributeWritePermission(context, rows, next);
        _json.Require(page.IsExpectedPage(after?.Ordinal ?? -1));
        return page;
    }

    private (Guid Guid, string Dn, string Domain, string Sid, string Class) Target()
    {
        var guid = Guid.Empty;
        string? dn = null, domain = null, sid = null, actualClass = null;
        var lastClass = -1;
        var keys = _json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = _json.GuidValue(); break;
                case "DistinguishedName": dn = _json.Text(); break;
                case "DomainFqdn": domain = _json.Text(); break;
                case "Sid": sid = _json.Text(); break;
                case "Values":
                    _json.Array(() =>
                    {
                        string? attribute = null, value = null;
                        long ordinal = -1;
                        var fields = _json.Object(field =>
                        {
                            switch (field)
                            {
                                case "Attribute": attribute = _json.Text(); break;
                                case "Ordinal": ordinal = _json.Number(); break;
                                case "Value": value = _json.Text(); break;
                                default: throw Invalid();
                            }
                        });
                        _json.RequireKeys(fields, "Attribute", "Ordinal", "Value");
                        _json.Require(ordinal <= int.MaxValue);
                        if (attribute == "objectClass" && ordinal > lastClass)
                        {
                            lastClass = (int)ordinal;
                            actualClass = value;
                        }
                    });
                    break;
                case "NamingContext":
                case "SidScope":
                case "ObjectClass":
                case "GroupType":
                case "CapturedUtc":
                case "Completeness": _json.Skip(); break;
                default: throw Invalid();
            }
        });
        _json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "NamingContext", "DomainFqdn", "Sid", "SidScope",
            "ObjectClass", "GroupType", "CapturedUtc", "Completeness", "Values");
        _json.Require(dn is not null && domain is not null && sid is not null && actualClass is not null);
        return (guid, dn!, domain!, sid!, actualClass!);
    }

    private uint? AccountControl()
    {
        uint? control = null;
        var count = _json.Array(() =>
        {
            long ordinal = -1;
            string? text = null;
            var binary = false;
            var keys = _json.Object(name =>
            {
                switch (name)
                {
                    case "Ordinal": ordinal = _json.Number(); break;
                    case "Text": text = _json.OptionalText(); break;
                    case "Bytes": binary = !_json.IsNull(); _json.Skip(); break;
                    case "Stored": _json.Skip("string"); break;
                    default: throw Invalid();
                }
            });
            _json.RequireKeys(keys, "Ordinal", "Text", "Bytes", "Stored");
            if (ordinal == 0 && !binary && uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value)) control = value;
        });
        return count == 1 ? control : null;
    }

    private SchemaGuidEntry Definition()
    {
        string? guid = null, name = null;
        var kind = default(SchemaGuidKind);
        var source = default(SchemaGuidSource);
        var keys = _json.Object(field =>
        {
            switch (field)
            {
                case "Guid": guid = _json.Text(); break;
                case "LdapName": name = _json.Text(); break;
                case "Kind": _json.Require(Enum.TryParse(_json.Text(), out kind) && Enum.IsDefined(kind)); break;
                case "Source": _json.Require(Enum.TryParse(_json.Text(), out source) && Enum.IsDefined(source)); break;
                default: throw Invalid();
            }
        });
        _json.RequireKeys(keys, "Guid", "LdapName", "Kind", "Source");
        _json.Require(Guid.TryParse(guid, out _) && name is not null);
        return new(guid!, name!, kind, source);
    }

    private void Scopes()
    {
        var previous = -1L;
        _scopeCount = _json.Array(() =>
        {
            long ordinal = -1;
            string? state = null;
            var keys = _json.Object(name =>
            {
                switch (name)
                {
                    case "Ordinal": ordinal = _json.Number(); break;
                    case "State": state = _json.Text(); break;
                    case "Basis": _json.Skip("string"); break;
                    default: throw Invalid();
                }
            });
            _json.RequireKeys(keys, "Ordinal", "State", "Basis");
            _json.Require(ordinal > previous && ordinal <= int.MaxValue && state == nameof(ControlEvaluationState.Established));
            previous = ordinal;
            if (_entries.Any(entry => entry.Ordinal == ordinal)) _json.Require(_scopes.Add((int)ordinal));
        });
    }

    private SavedPropertyWriteEntry Row(SavedWriteEntrySource entry, string targetSid, string holder)
    {
        _json.Require(entry.Sid == holder || entry.Sid == PermissionTrustee.PrincipalSelfSid && targetSid == holder);
        var kind = SavedPropertyWriteScope.AllProperties;
        string? name = null;
        if (entry.HasObjectType)
        {
            _json.Require(Guid.TryParse(entry.ObjectType, out _));
            if (Same(entry.ObjectType, _attributeGuid))
                kind = SavedPropertyWriteScope.Attribute;
            else
            {
                _definitions.TryGetValue(entry.ObjectType!, out var definition);
                kind = definition?.Kind == SchemaGuidKind.ObjectClass ? SavedPropertyWriteScope.ObjectClass : SavedPropertyWriteScope.PropertySet;
                name = definition?.Source == SchemaGuidSource.Captured ? definition.LdapName : null;
            }
        }
        return new(entry.Ordinal, entry.IsDeny, kind, name, entry.IsInherited, _kind);
    }

    private static bool Same(string? left, string? right) => left is not null && right is not null
        && left.Equals(right, StringComparison.OrdinalIgnoreCase);
    private InvalidDataException Invalid() => new(_invalidDetails);
}
