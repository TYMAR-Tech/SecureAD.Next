using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed record ServiceAccountLinkHeader(long PagePosition, long Position, Guid Group, Guid Member,
    Guid Reference, long Witnesses, bool IsPrimaryGroup);
internal sealed record ServiceAccountWitnessValue(long Position, Guid Source, string Attribute, int Ordinal, string Value);
internal sealed record ServiceAccountProjectionResult(SavedServiceAccountContext Context,
    IReadOnlyList<SavedServiceAccountRow<SavedServiceAccountName>> Names, IReadOnlyList<ServiceAccountLinkHeader> Links,
    IReadOnlyList<ServiceAccountWitnessValue> Values,
    IReadOnlyList<SavedServiceAccountRow<AdministrativeMembershipLimitation>> Limitations,
    IReadOnlyDictionary<Guid, SavedServiceAccountIdentity> Identities);

internal sealed class ServiceAccountProjection(SavedProofJsonReader json, FindingListItem selected,
    JudgementDescription description, string? derivationSeal, ServiceAccountPageKind? kind, long offset,
    long linkPosition, IReadOnlySet<Guid>? wanted)
{
    private readonly Dictionary<Guid, SavedServiceAccountIdentity> _identities = [];
    private readonly Dictionary<string, SavedServiceAccountIdentity> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SavedServiceAccountRow<SavedServiceAccountName>> _names = [];
    private readonly List<ServiceAccountLinkHeader> _links = [];
    private readonly List<ServiceAccountWitnessValue> _values = [];
    private readonly List<SavedServiceAccountRow<AdministrativeMembershipLimitation>> _limits = [];
    private SavedServiceAccountFacts? _account;
    private Guid _target;
    private long _entryCount, _linkCount, _limitCount;
    private bool _membership, _inputsComplete = true, _membershipComplete = true, _complete, _captureIncomplete;
    private MembershipRouteIncompleteReason _reasons;
    private string? _root;

    internal static ServiceAccountProjectionResult Read(Stream stream, FindingListItem selected,
        JudgementDescription description, string? derivationSeal, ServiceAccountPageKind? kind, long offset,
        long linkPosition, IReadOnlySet<Guid>? wanted, CancellationToken token) =>
        SavedProofJsonReader.Read(stream, token, SavedServiceAccountContext.InvalidDetails, json =>
            new ServiceAccountProjection(json, selected, description, derivationSeal, kind, offset, linkPosition, wanted).Read());

    private ServiceAccountProjectionResult Read()
    {
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "Account": Account(); break;
                case "AdministrativeMembership":
                    if (json.IsNull()) json.Skip(); else { _membership = true; Membership(); }
                    break;
                case "IsComplete": _complete = json.Bit(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "Account", "AdministrativeMembership", "IsComplete");
        json.Require(_account is not null && _membership == (selected.RuleId == "SEC-100"));
        SavedServiceAccountIdentity? source = null, target = null;
        if (_membership)
        {
            json.Require(_identities.TryGetValue(selected.ObjectGuid, out source)
                && _identities.TryGetValue(_target, out target) && (_inputsComplete || _captureIncomplete));
            json.Require(_membershipComplete == (_inputsComplete && _reasons == MembershipRouteIncompleteReason.None && _limitCount == 0));
            json.Require(target is { IsValid: true, ObjectClass: "group" }
                && GroupMembershipFindingStorage.MatchesTarget(BroadMembershipTarget.AdministrativeGroup,
                    target.Sid, target.GroupType, target.NamingContext, _root));
            foreach (var identity in _identities.Values)
                json.Require(identity.IsValid && _domains.TryGetValue(identity.DomainFqdn, out var domain)
                    && Same(identity.NamingContext, domain.NamingContext)
                    && (identity.ObjectClass == "foreignSecurityPrincipal" || Sid.IsBuiltinDomain(identity.Sid)
                        || Same(Sid.IssuingDomain(identity.Sid), domain.Sid)));
        }
        var context = new SavedServiceAccountContext(selected.Reference!.Value, selected.RuleId, selected.Subject,
            _account!, source, target, _entryCount, _linkCount, _limitCount, _inputsComplete, _reasons, _complete);
        json.Require(context.Matches(selected));
        return new(context, _names, _links, _values, _limits, _identities);
    }

    private void Account()
    {
        Guid guid = Guid.Empty; string? dn = null, domain = null, lastClass = null;
        var captured = default(DateTimeOffset); var coverage = default(EvidenceCompleteness); var accountKind = default(ServiceAccountKind);
        var missing = new List<string>(); uint? control = null, originalControl = null;
        long services = 0, classes = 0, controls = 0;
        bool managed = false, groupManaged = false, computer = false, group = false;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = json.GuidValue(); break;
                case "DistinguishedName": dn = json.Text(); break;
                case "DomainFqdn": domain = json.Text(); break;
                case "CapturedUtc": captured = CaptureTime(); break;
                case "Completeness": coverage = EnumValue<EvidenceCompleteness>(); break;
                case "Kind": accountKind = EnumValue<ServiceAccountKind>(); break;
                case "ObjectClasses":
                    long position = 0;
                    classes = json.Array(() =>
                    {
                        var value = OriginalValue();
                        json.Require(value.OriginalOrdinal == position++ && value.IsReadable);
                        lastClass = value.Text;
                        managed |= Same(lastClass, "msDS-ManagedServiceAccount");
                        groupManaged |= Same(lastClass, "msDS-GroupManagedServiceAccount");
                        computer |= Same(lastClass, "computer"); group |= Same(lastClass, "group");
                    });
                    break;
                case "ServicePrincipalNames":
                    long servicePosition = 0;
                    services = json.Array(() =>
                    {
                        if (kind == ServiceAccountPageKind.Names && wanted is null && InPage(servicePosition))
                            _names.Add(new(servicePosition, OriginalValue()));
                        else json.Skip("object");
                        servicePosition++;
                    });
                    break;
                case "AccountControl":
                    controls = json.Array(() =>
                    {
                        if (controls == 0)
                        {
                            var value = OriginalValue();
                            if (value is { OriginalOrdinal: 0, HasBinary: false, Text: { } text }
                                && uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)) originalControl = parsed;
                        }
                        else json.Skip("object");
                        controls++;
                    });
                    if (controls != 1) originalControl = null;
                    break;
                case "UserAccountControl":
                    if (json.IsNull()) json.Skip();
                    else { var number = json.Number(); json.Require(number <= uint.MaxValue); control = (uint)number; }
                    break;
                case "MissingAttributes":
                    json.Array(() => missing.Add(json.Text()));
                    break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "DomainFqdn", "CapturedUtc", "Completeness", "Kind",
            "ObjectClasses", "ServicePrincipalNames", "AccountControl", "UserAccountControl", "MissingAttributes");
        json.Require(classes > 0 && dn is not null && domain is not null && lastClass == selected.ObjectClass
            && originalControl == control && missing.Distinct(StringComparer.OrdinalIgnoreCase).Count() == missing.Count
            && missing.All(value => value is "servicePrincipalName" or "userAccountControl")
            && missing.Contains("userAccountControl") == (control is null)
            && (accountKind switch
            {
                ServiceAccountKind.SpnBearingUser => !managed && !groupManaged && !computer && !group && Same(lastClass, "user") && services > 0,
                ServiceAccountKind.StandaloneManagedServiceAccount => managed && !groupManaged,
                ServiceAccountKind.GroupManagedServiceAccount => groupManaged,
                _ => false,
            }));
        _account = new(guid, dn!, domain!, lastClass!, selected.PrincipalName, captured, coverage, accountKind, control,
            string.Join(", ", missing), services);
    }

    private SavedServiceAccountName OriginalValue()
    {
        long ordinal = 0; string? text = null; bool binary = false;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "Ordinal": ordinal = json.SignedNumber(); break;
                case "Text": if (json.IsNull()) json.Skip(); else text = json.ValueText(); break;
                case "Bytes": if (json.IsNull()) json.Skip(); else { binary = true; json.Skip("string"); } break;
                case "Stored": json.Skip("string"); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "Ordinal", "Text", "Bytes", "Stored");
        json.Require(ordinal is >= int.MinValue and <= int.MaxValue);
        return new((int)ordinal, text, binary);
    }

    private void Membership()
    {
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "EvidenceSeal": json.Require(json.Text() == description.EvidenceSeal); break;
                case "DerivationGenerationId": json.Require(json.GuidValue() == description.DerivationGenerationId); break;
                case "DerivationSeal": json.Require(json.Text() == derivationSeal); break;
                case "PrincipalCatalogueVersion": json.Require(json.Number() == PrincipalClassificationRegistry.Version); break;
                case "PolicyVersion": json.Require(json.Number() == ServiceAccountWithAdministrativeMembership.PolicyVersion); break;
                case "ForestRootNamingContext": _root = json.OptionalText(); break;
                case "AccountGuid": json.Require(json.GuidValue() == selected.ObjectGuid); break;
                case "TargetGuid": _target = json.GuidValue(); break;
                case "Principals":
                    json.Array(() =>
                    {
                        var identity = Identity();
                        if (identity.ObjectGuid == selected.ObjectGuid || identity.ObjectGuid == _target || wanted?.Contains(identity.ObjectGuid) == true)
                            json.Require(_identities.TryAdd(identity.ObjectGuid, identity));
                    });
                    break;
                case "Domains":
                    json.Array(() =>
                    {
                        var domain = Identity();
                        if (_identities.Values.Any(identity => Same(identity.DomainFqdn, domain.DomainFqdn)))
                            json.Require(domain.ObjectClass == "domainDNS" && domain.GroupType is null && domain.SidScope is null
                                && domain.NamingContext == domain.DistinguishedName && Same(DnHelper.DnToFqdn(domain.NamingContext), domain.DomainFqdn)
                                && PrincipalClassificationRegistry.DomainRid(domain.Sid + "-0") == 0 && _domains.TryAdd(domain.DomainFqdn, domain));
                    });
                    break;
                case "Links": Links(); break;
                case "InputsComplete": _inputsComplete = json.Bit(); break;
                case "RouteIncompleteReasons":
                    _reasons = EnumValue<MembershipRouteIncompleteReason>(flags: true);
                    json.Require(!_reasons.HasFlag(MembershipRouteIncompleteReason.ForestMaskUnreadable));
                    break;
                case "Limitations": Limitations(); break;
                case "IsComplete": _membershipComplete = json.Bit(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "EvidenceSeal", "DerivationGenerationId", "DerivationSeal", "PrincipalCatalogueVersion", "PolicyVersion",
            "ForestRootNamingContext", "AccountGuid", "TargetGuid", "Principals", "Domains", "Links", "InputsComplete",
            "RouteIncompleteReasons", "Limitations", "IsComplete");
    }

    private SavedServiceAccountIdentity Identity()
    {
        Guid guid = Guid.Empty; string? dn = null, nc = null, domain = null, sid = null, scope = null, type = null; long? groupType = null;
        var captured = default(DateTimeOffset); var coverage = default(EvidenceCompleteness);
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = json.GuidValue(); break;
                case "DistinguishedName": dn = json.Text(); break;
                case "NamingContext": nc = json.Text(); break;
                case "DomainFqdn": domain = json.Text(); break;
                case "Sid": sid = json.Text(); break;
                case "SidScope": scope = json.OptionalText(); break;
                case "ObjectClass": type = json.Text(); break;
                case "GroupType": if (json.IsNull()) json.Skip(); else groupType = json.SignedNumber(); break;
                case "CapturedUtc": captured = CaptureTime(); break;
                case "Completeness": coverage = EnumValue<EvidenceCompleteness>(); break;
                case "Values": json.Skip("array"); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "NamingContext", "DomainFqdn", "Sid", "SidScope",
            "ObjectClass", "GroupType", "CapturedUtc", "Completeness", "Values");
        json.Require(dn is not null && nc is not null && domain is not null && sid is not null && type is not null);
        return new(guid, dn!, nc!, domain!, sid!, scope, type!, groupType, captured, coverage);
    }

    private void Links()
    {
        long position = 0;
        _linkCount = json.Array(() =>
        {
            Guid group = Guid.Empty, member = Guid.Empty, reference = Guid.Empty; long witnesses = 0; bool primary = false;
            var keys = json.Object(name =>
            {
                switch (name)
                {
                    case "GroupGuid": group = json.GuidValue(); break;
                    case "MemberGuid": member = json.GuidValue(); break;
                    case "MemberReferenceGuid": reference = json.GuidValue(); break;
                    case "Witnesses":
                        long witnessPosition = 0;
                        witnesses = json.Array(() =>
                        {
                            var value = Witness(kind == ServiceAccountPageKind.Values && position == linkPosition
                                && wanted is null && InPage(witnessPosition), witnessPosition);
                            primary |= value.Attribute == "primaryGroupID";
                            witnessPosition++;
                        });
                        break;
                    default: throw Invalid();
                }
            });
            json.RequireKeys(keys, "GroupGuid", "MemberGuid", "MemberReferenceGuid", "Witnesses");
            json.Require(witnesses > 0);
            var pagePosition = kind == ServiceAccountPageKind.EntryMemberships ? _entryCount : position;
            if (kind == ServiceAccountPageKind.EntryMemberships && member == selected.ObjectGuid && InPage(_entryCount)
                || kind == ServiceAccountPageKind.Links && InPage(position)
                || kind == ServiceAccountPageKind.Values && position == linkPosition)
                _links.Add(new(pagePosition, position, group, member, reference, witnesses, primary));
            if (member == selected.ObjectGuid) _entryCount++;
            position++;
        });
    }

    private ServiceAccountWitnessValue Witness(bool keep, long position)
    {
        Guid source = Guid.Empty; string? attribute = null, value = null; long ordinal = -1;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "SourceObjectGuid": source = json.GuidValue(); break;
                case "Attribute": attribute = json.Text(); break;
                case "Ordinal": ordinal = json.Number(); break;
                case "Value": if (keep) value = json.ValueText(); else json.Skip("string"); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "SourceObjectGuid", "Attribute", "Ordinal", "Value");
        json.Require(attribute is "member" or "memberOf" or "primaryGroupID" && ordinal <= int.MaxValue);
        var result = new ServiceAccountWitnessValue(position, source, attribute!, (int)ordinal, value ?? "");
        if (keep) _values.Add(result);
        return result;
    }

    private void Limitations()
    {
        long position = 0;
        _limitCount = json.Array(() =>
        {
            string? dn = null; var reason = default(AdministrativeMembershipReason);
            var keys = json.Object(name =>
            {
                switch (name) { case "DistinguishedName": dn = json.Text(); break; case "Reason": reason = EnumValue<AdministrativeMembershipReason>(); break; default: throw Invalid(); }
            });
            json.RequireKeys(keys, "DistinguishedName", "Reason");
            json.Require(dn is not null);
            _captureIncomplete |= reason == AdministrativeMembershipReason.CaptureIncomplete;
            if (kind == ServiceAccountPageKind.Limitations && InPage(position)) _limits.Add(new(position, new(dn!, reason)));
            position++;
        });
    }
    private DateTimeOffset CaptureTime()
    {
        json.Require(DateTimeOffset.TryParse(json.Text(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var time));
        return time;
    }
    private T EnumValue<T>(bool flags = false) where T : struct, Enum
    {
        json.Require(Enum.TryParse<T>(json.Text(), out var value));
        json.Require(flags
            ? (Convert.ToInt64(value, CultureInfo.InvariantCulture) & ~Enum.GetValues<T>().Aggregate(0L,
                (all, item) => all | Convert.ToInt64(item, CultureInfo.InvariantCulture))) == 0
            : Enum.IsDefined(value));
        return value;
    }
    private bool InPage(long position) => position >= offset && position - offset < SavedServiceAccountContext.PageSize;
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    private static InvalidDataException Invalid() => new(SavedServiceAccountContext.InvalidDetails);
}
