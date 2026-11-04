using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class DelegationConfigurationProjection
{
    private readonly SavedProofJsonReader _json;
    private readonly long _offset;
    private readonly List<string> _services = [];
    private readonly List<SavedDelegationHolder> _holders = [];
    private readonly DelegationConfigurationKind _kind;
    private long _serviceCount;
    private bool _hasNullDacl;
    private DelegationConfigurationInputLimitations _limits;

    private DelegationConfigurationProjection(SavedProofJsonReader json, long offset, DelegationConfigurationKind kind) =>
        (_json, _offset, _kind) = (json, offset, kind);

    internal static SavedDelegationConfiguration Read(Stream stream, FindingListItem selected, JudgementDescription description,
        string derivationSeal, DelegationConfigurationMark? after, CancellationToken token)
    {
        var kind = selected.RuleId switch
        {
            "SEC-012" => DelegationConfigurationKind.Constrained,
            "SEC-013" => DelegationConfigurationKind.ResourceBased,
            _ => throw new InvalidDataException(SavedDelegationConfiguration.ConstrainedInvalidDetails),
        };
        return SavedProofJsonReader.Read(stream, token, SavedDelegationConfiguration.InvalidDetailsFor(kind), json =>
            new DelegationConfigurationProjection(json, after?.Offset ?? 0, kind).Read(selected, description, derivationSeal, after));
    }

    private SavedDelegationConfiguration Read(FindingListItem selected, JudgementDescription description,
        string derivationSeal, DelegationConfigurationMark? after)
    {
        SavedDelegationIdentity? account = null, resource = null;
        var accountComplete = false;
        var resourceComplete = false;
        var inputsComplete = false;
        var reportedComplete = false;
        var established = false;
        var scopeGeneration = Guid.Empty;
        var scopeResource = Guid.Empty;
        string? scopeDn = null;
        var keys = _json.Object(name =>
        {
            switch (name)
            {
                case "ConfigurationKind": _json.Require(_json.Text() == _kind.ToString()); break;
                case "EvidenceSeal": _json.Require(_json.Text() == description.EvidenceSeal); break;
                case "DerivationGenerationId": _json.Require(_json.GuidValue() == description.DerivationGenerationId); break;
                case "DerivationSeal": _json.Require(_json.Text() == derivationSeal); break;
                case "PolicyVersion": _json.Require(_json.Number() == DelegationConfigurationRules.PolicyVersion); break;
                case "DescriptorParserVersion": _json.Require(_json.Number() == SecurityDescriptorParser.Version); break;
                case "Account": (account, accountComplete) = Identity(); break;
                case "Resource": (resource, resourceComplete) = Identity(); break;
                case "Scope":
                    (scopeGeneration, scopeResource, scopeDn, established) = Scope();
                    break;
                case "Services":
                    if (_kind == DelegationConfigurationKind.Constrained) Services();
                    else _json.Require(_json.Array(() => throw Invalid()) == 0);
                    break;
                case "Grants":
                    if (_kind == DelegationConfigurationKind.ResourceBased) Grants();
                    else _json.Require(_json.Array(() => throw Invalid()) == 0);
                    break;
                case "InputsComplete": inputsComplete = _json.Bit(); break;
                case "Limitations": _json.Array(ReadLimitation); break;
                case "IsComplete": reportedComplete = _json.Bit(); break;
                default: throw Invalid();
            }
        });
        _json.RequireKeys(keys, "ConfigurationKind", "EvidenceSeal", "DerivationGenerationId", "DerivationSeal",
            "PolicyVersion", "DescriptorParserVersion", "Account", "Resource", "Scope", "Services", "Grants",
            "InputsComplete", "Limitations", "IsComplete");
        _json.Require(_json.AtEnd && account is not null && resource is not null
            && scopeGeneration == description.GenerationId && scopeResource == resource.ObjectGuid
            && scopeDn == resource.DistinguishedName && _serviceCount > _offset);
        if (!inputsComplete) _json.Require(_limits.HasFlag(DelegationConfigurationInputLimitations.CaptureIncomplete));
        if (!accountComplete || !resourceComplete) _limits |= DelegationConfigurationInputLimitations.Other;
        _json.Require(reportedComplete == (inputsComplete && accountComplete && resourceComplete
            && _limits == DelegationConfigurationInputLimitations.None));
        _json.Require(!_hasNullDacl || _serviceCount == 1 && _offset == 0);
        var context = new DelegationConfigurationContext(_kind, selected.Reference!.Value, selected.Subject, account!, resource!,
            established, reportedComplete, _limits, _hasNullDacl);
        _json.Require(context.Matches(selected) && (after is null || after.Value.ResourceGuid == resource!.ObjectGuid));
        DelegationConfigurationMark? next = _serviceCount > _offset + SavedDelegationConfiguration.PageSize
            ? new(description.GenerationId, context.Reference.FindingId, resource!.ObjectGuid,
                _offset + SavedDelegationConfiguration.PageSize) : null;
        var page = new SavedDelegationConfiguration(context, _services, _holders, next);
        _json.Require(page.IsExpectedPage(_offset));
        return page;
    }

    private (SavedDelegationIdentity Identity, bool Complete) Identity()
    {
        var guid = Guid.Empty;
        string? dn = null, domain = null, kind = null;
        var complete = false;
        var keys = _json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = _json.GuidValue(); break;
                case "DistinguishedName": dn = _json.Text(); break;
                case "DomainFqdn": domain = _json.Text(); break;
                case "ObjectClass": kind = _json.Text(); break;
                case "CapturedUtc":
                    _json.Require(DateTimeOffset.TryParse(_json.Text(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _));
                    break;
                case "Completeness":
                    _json.Require(Enum.TryParse<EvidenceCompleteness>(_json.Text(), out var value) && Enum.IsDefined(value));
                    complete = value == EvidenceCompleteness.Complete;
                    break;
                case "Attributes": _json.Skip("array"); break;
                default: throw Invalid();
            }
        });
        _json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "DomainFqdn", "ObjectClass", "CapturedUtc", "Completeness", "Attributes");
        var identity = new SavedDelegationIdentity(guid, dn!, domain!, kind!);
        _json.Require(identity.IsValid);
        return (identity, complete);
    }

    private (Guid Generation, Guid Resource, string Dn, bool Established) Scope()
    {
        var generation = Guid.Empty;
        var resource = Guid.Empty;
        string? dn = null;
        var established = false;
        long bases = 0, anchors = 0, relations = 0;
        var keys = _json.Object(name =>
        {
            switch (name)
            {
                case "GenerationId": generation = _json.GuidValue(); break;
                case "ResourceGuid": resource = _json.GuidValue(); break;
                case "TargetDn": dn = _json.Text(); break;
                case "Fingerprint":
                    var fingerprint = _json.Text();
                    _json.Require(fingerprint.Length == 64 && fingerprint.All(char.IsAsciiHexDigit));
                    break;
                case "EstablishedTier0": established = _json.Bit(); break;
                case "ClassificationBases": bases = _json.Array(() => _json.Require(!string.IsNullOrWhiteSpace(_json.Text()))); break;
                case "AnchorDns": anchors = _json.Array(() => _json.Require(!string.IsNullOrWhiteSpace(_json.Text()))); break;
                case "RelationIds": relations = _json.Array(() => _json.Require(_json.Number() > 0)); break;
                case "Limitations": _json.Array(() => { _json.Text(); _limits |= DelegationConfigurationInputLimitations.Other; }); break;
                default: throw Invalid();
            }
        });
        _json.RequireKeys(keys, "GenerationId", "ResourceGuid", "TargetDn", "Fingerprint", "EstablishedTier0",
            "ClassificationBases", "AnchorDns", "RelationIds", "Limitations");
        _json.Require(!string.IsNullOrWhiteSpace(dn) && anchors > 0 && (established ? bases > 0 : bases == 0 && relations > 0));
        return (generation, resource, dn!, established);
    }

    private void Services()
    {
        _serviceCount = _json.Array(() =>
        {
            if (_serviceCount < _offset || _serviceCount >= _offset + SavedDelegationConfiguration.PageSize)
            {
                _json.Skip("object");
            }
            else
            {
                string? configured = null, registered = null;
                var keys = _json.Object(name =>
                {
                    switch (name)
                    {
                        case "ConfigurationOrdinal": _json.Require(_json.Number() <= int.MaxValue); break;
                        case "ConfiguredService": configured = _json.Text(); break;
                        case "RegistrationOrdinal": _json.Require(_json.Number() <= int.MaxValue); break;
                        case "RegisteredService": registered = _json.Text(); break;
                        default: throw Invalid();
                    }
                });
                _json.RequireKeys(keys, "ConfigurationOrdinal", "ConfiguredService", "RegistrationOrdinal", "RegisteredService");
                _json.Require(configured is not null && registered is not null && DuplicateServicePrincipalNames.Supports(configured)
                    && configured.Equals(registered, StringComparison.OrdinalIgnoreCase));
                _services.Add(configured!);
            }
            _serviceCount++;
        });
    }

    private void ReadLimitation()
    {
        var reason = _json.Text();
        _limits |= reason switch
        {
            "CaptureIncomplete" => DelegationConfigurationInputLimitations.CaptureIncomplete,
            "ServiceResourceUnresolved" => DelegationConfigurationInputLimitations.UnresolvedService,
            "ServiceResourceAmbiguous" => DelegationConfigurationInputLimitations.AmbiguousService,
            "ResourceRelevanceUnassessed" => DelegationConfigurationInputLimitations.UnassessedResource,
            "ResourceDescriptorIncomplete" or "ResourceDescriptorUnavailable" or "ResourceDelegationEntryUnsupported"
                or "StoredGenericRightUnsupported" when _kind == DelegationConfigurationKind.ResourceBased =>
                DelegationConfigurationInputLimitations.ConfigurationUnassessed,
            _ => DelegationConfigurationInputLimitations.Other,
        };
    }

    private void Grants()
    {
        _serviceCount = _json.Array(() =>
        {
            string? sid = null;
            var nullDacl = false;
            long entries = 0, previous = -1;
            var keys = _json.Object(name =>
            {
                switch (name)
                {
                    case "TrusteeSid": sid = _json.Text(); break;
                    case "NullDacl": nullDacl = _json.Bit(); break;
                    case "EntryOrdinals":
                        entries = _json.Array(() =>
                        {
                            var ordinal = _json.Number();
                            _json.Require(ordinal <= int.MaxValue && ordinal > previous);
                            previous = ordinal;
                        });
                        break;
                    default: throw Invalid();
                }
            });
            _json.RequireKeys(keys, "TrusteeSid", "EntryOrdinals", "NullDacl");
            _json.Require(sid is not null && new SavedDelegationHolder(sid).IsValid);
            if (nullDacl)
            {
                _json.Require(entries == 0 && sid == WellKnownSidCatalog.AllSids.Single(value => value.ConstantName == "EVERYONE").Sid);
                _hasNullDacl = true;
            }
            else
            {
                _json.Require(entries > 0);
                if (_serviceCount >= _offset && _serviceCount < _offset + SavedDelegationConfiguration.PageSize)
                    _holders.Add(new(sid!));
            }
            _serviceCount++;
        });
    }

    private InvalidDataException Invalid() => new(SavedDelegationConfiguration.InvalidDetailsFor(_kind));
}
