using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed record BroadMembershipLinkHeader(long Position, Guid Group, Guid Member, Guid Reference, long Witnesses);
internal sealed record BroadMembershipWitnessValue(long Position, Guid Source, string Attribute, int Ordinal, string Value);
internal sealed record BroadMembershipProjectionResult(SavedBroadMembershipContext Context,
    IReadOnlyList<SavedBroadMembershipRow<SavedBroadIdentity>> Sources, IReadOnlyList<BroadMembershipLinkHeader> Links,
    IReadOnlyList<BroadMembershipWitnessValue> Values,
    IReadOnlyList<SavedBroadMembershipRow<AdministrativeMembershipLimitation>> Limitations,
    IReadOnlyDictionary<Guid, SavedBroadMembershipIdentity> Identities);

internal sealed class BroadMembershipProjection(SavedProofJsonReader json, FindingListItem selected,
    JudgementDescription description, string derivationSeal, BroadMembershipPageKind kind, long offset,
    long linkPosition, IReadOnlySet<Guid>? wanted)
{
    private readonly Dictionary<Guid, SavedBroadMembershipIdentity> _identities = [];
    private readonly Dictionary<string, SavedBroadMembershipIdentity> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SavedBroadMembershipRow<SavedBroadIdentity>> _sources = [];
    private readonly List<BroadMembershipLinkHeader> _links = [];
    private readonly List<BroadMembershipWitnessValue> _values = [];
    private readonly List<SavedBroadMembershipRow<AdministrativeMembershipLimitation>> _limits = [];
    private long _sourceCount, _linkCount, _limitCount;
    private bool _inputsComplete, _complete, _captureIncomplete;
    private string? _root, _configuration;

    internal static BroadMembershipProjectionResult Read(Stream stream, FindingListItem selected,
        JudgementDescription description, string derivationSeal, BroadMembershipPageKind kind, long offset,
        long linkPosition, IReadOnlySet<Guid>? wanted, CancellationToken token) =>
        SavedProofJsonReader.Read(stream, token, SavedBroadMembershipContext.InvalidDetails, json =>
            new BroadMembershipProjection(json, selected, description, derivationSeal, kind, offset, linkPosition, wanted).Read());

    private BroadMembershipProjectionResult Read()
    {
        var targetKind = selected.RuleId == "SEC-061" ? BroadMembershipTarget.PreWindows2000CompatibleAccess : BroadMembershipTarget.AdministrativeGroup;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "EvidenceSeal": json.Require(json.Text() == description.EvidenceSeal); break;
                case "DerivationGenerationId": json.Require(json.GuidValue() == description.DerivationGenerationId); break;
                case "DerivationSeal": json.Require(json.Text() == derivationSeal); break;
                case "PrincipalCatalogueVersion": json.Require(json.Number() == PrincipalClassificationRegistry.Version); break;
                case "PolicyVersion": json.Require(json.Number() == (selected.RuleId == "SEC-061"
                    ? BroadPreWindows2000Membership.PolicyVersion : BroadAdministrativeGroupMembership.PolicyVersion)); break;
                case "ForestRootNamingContext": _root = json.OptionalText(); break;
                case "ConfigurationNamingContext": _configuration = json.OptionalText(); break;
                case "TargetGuid": json.Require(json.GuidValue() == selected.ObjectGuid); break;
                case "Principals":
                    json.Array(() =>
                    {
                        var identity = Identity();
                        if (identity.ObjectGuid == selected.ObjectGuid || wanted?.Contains(identity.ObjectGuid) == true)
                            json.Require(identity.IsValid && _identities.TryAdd(identity.ObjectGuid, identity));
                    });
                    break;
                case "Domains":
                    json.Array(() =>
                    {
                        var domain = Identity();
                        if (_identities.Values.Any(identity => Same(identity.DomainFqdn, domain.DomainFqdn)))
                            json.Require(domain.ObjectClass == "domainDNS" && domain.DomainFqdn is not null
                                && domain.NamingContext == domain.DistinguishedName && domain.GroupType is null && domain.SidScope is null
                                && Same(DnHelper.DnToFqdn(domain.NamingContext), domain.DomainFqdn)
                                && PrincipalClassificationRegistry.DomainRid(domain.Sid + "-0") == 0
                                && _domains.TryAdd(domain.DomainFqdn, domain));
                    });
                    break;
                case "BroadSources": Sources(); break;
                case "Links": Links(); break;
                case "InputsComplete": _inputsComplete = json.Bit(); break;
                case "Limitations": Limitations(); break;
                case "TargetKind": json.Require(json.Text() == targetKind.ToString()); break;
                case "IsComplete": _complete = json.Bit(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "EvidenceSeal", "DerivationGenerationId", "DerivationSeal", "PrincipalCatalogueVersion",
            "PolicyVersion", "ForestRootNamingContext", "ConfigurationNamingContext", "TargetGuid", "Principals", "Domains",
            "BroadSources", "Links", "InputsComplete", "Limitations", "TargetKind", "IsComplete");
        json.Require(_identities.TryGetValue(selected.ObjectGuid, out var target) && (_inputsComplete || _captureIncomplete));
        json.Require(GroupMembershipFindingStorage.MatchesTarget(targetKind, target!.Sid, target.GroupType, target.NamingContext, _root));
        foreach (var identity in _identities.Values)
        {
            var configurationIdentity = identity.ObjectClass == "foreignSecurityPrincipal"
                && CapturedGroupMembershipIndex.Special(identity.Sid) && Same(identity.NamingContext, _configuration)
                && (identity.DomainFqdn is null || Same(identity.DomainFqdn, DnHelper.DnToFqdn(identity.NamingContext)));
            json.Require(configurationIdentity || identity.DomainFqdn is not null && _domains.TryGetValue(identity.DomainFqdn, out var domain)
                && Same(identity.NamingContext, domain.NamingContext)
                && (identity.ObjectClass == "foreignSecurityPrincipal" || Sid.IsBuiltinDomain(identity.Sid)
                    || Same(Sid.IssuingDomain(identity.Sid), domain.Sid)));
        }
        var context = new SavedBroadMembershipContext(selected.Reference!.Value, selected.RuleId, selected.Subject, target,
            _sourceCount, _linkCount, _limitCount, _inputsComplete, _complete);
        json.Require(context.Matches(selected));
        return new(context, _sources, _links, _values, _limits, _identities);
    }

    private SavedBroadMembershipIdentity Identity()
    {
        Guid guid = Guid.Empty; string? dn = null, nc = null, domain = null, sid = null, scope = null, type = null; long? groupType = null;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = json.GuidValue(); break;
                case "DistinguishedName": dn = json.Text(); break;
                case "NamingContext": nc = json.Text(); break;
                case "DomainFqdn": domain = json.OptionalText(); break;
                case "Sid": sid = json.Text(); break;
                case "SidScope": scope = json.OptionalText(); break;
                case "ObjectClass": type = json.Text(); break;
                case "GroupType": if (json.IsNull()) json.Skip(); else groupType = json.SignedNumber(); break;
                case "CapturedUtc": json.Skip("string"); break;
                case "Completeness": json.Skip("string"); break;
                case "Values": json.Skip("array"); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "NamingContext", "DomainFqdn", "Sid", "SidScope",
            "ObjectClass", "GroupType", "CapturedUtc", "Completeness", "Values");
        json.Require(dn is not null && nc is not null && sid is not null && type is not null);
        return new(guid, dn!, nc!, domain, sid!, scope, type!, groupType);
    }

    private void Sources()
    {
        long position = 0;
        _sourceCount = json.Array(() =>
        {
            if (kind != BroadMembershipPageKind.Sources || wanted is not null || position < offset
                || position >= offset + SavedBroadMembershipContext.PageSize) json.Skip("object");
            else
            {
                string? sid = null, scope = null, name = null; long identities = 0;
                var keys = json.Object(property =>
                {
                    switch (property)
                    {
                        case "Sid": sid = json.Text(); break;
                        case "SidScope": scope = json.OptionalText(); break;
                        case "Name": name = json.Text(); break;
                        case "IdentityGuids": identities = json.Array(() => json.GuidValue()); break;
                        default: throw Invalid();
                    }
                });
                json.RequireKeys(keys, "Sid", "SidScope", "Name", "IdentityGuids");
                json.Require(sid is not null && BroadPrincipalCatalogue.IsBroad(sid)
                    && name == BroadPrincipalCatalogue.NameOf(sid) && identities > 0
                    && (Sid.IsBuiltinDomain(sid) ? !string.IsNullOrWhiteSpace(scope) : scope is null));
                _sources.Add(new(position, new(sid!, scope, name!)));
            }
            position++;
        });
    }

    private void Links()
    {
        long position = 0;
        _linkCount = json.Array(() =>
        {
            var requested = kind == BroadMembershipPageKind.Links && position >= offset
                    && position < offset + SavedBroadMembershipContext.PageSize
                || kind == BroadMembershipPageKind.Values && position == linkPosition;
            if (!requested) json.Skip("object");
            else
            {
                Guid group = Guid.Empty, member = Guid.Empty, reference = Guid.Empty; long witnesses = 0;
                var keys = json.Object(property =>
                {
                    switch (property)
                    {
                        case "GroupGuid": group = json.GuidValue(); break;
                        case "MemberGuid": member = json.GuidValue(); break;
                        case "MemberReferenceGuid": reference = json.GuidValue(); break;
                        case "Witnesses":
                            long witnessPosition = 0;
                            witnesses = json.Array(() =>
                            {
                                if (kind != BroadMembershipPageKind.Values || wanted is not null || witnessPosition < offset
                                    || witnessPosition >= offset + SavedBroadMembershipContext.PageSize) json.Skip("object");
                                else _values.Add(Witness(witnessPosition));
                                witnessPosition++;
                            });
                            break;
                        default: throw Invalid();
                    }
                });
                json.RequireKeys(keys, "GroupGuid", "MemberGuid", "MemberReferenceGuid", "Witnesses");
                json.Require(witnesses > 0);
                _links.Add(new(position, group, member, reference, witnesses));
            }
            position++;
        });
    }

    private BroadMembershipWitnessValue Witness(long position)
    {
        Guid source = Guid.Empty; string? attribute = null, value = null; long ordinal = -1;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "SourceObjectGuid": source = json.GuidValue(); break;
                case "Attribute": attribute = json.Text(); break;
                case "Ordinal": ordinal = json.Number(); break;
                case "Value": value = json.ValueText(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "SourceObjectGuid", "Attribute", "Ordinal", "Value");
        json.Require(attribute is "member" or "memberOf" && ordinal <= int.MaxValue && value is not null);
        return new(position, source, attribute!, (int)ordinal, value!);
    }

    private void Limitations()
    {
        long position = 0;
        _limitCount = json.Array(() =>
        {
            string? dn = null, reason = null;
            var keys = json.Object(name =>
            {
                switch (name) { case "DistinguishedName": dn = json.Text(); break; case "Reason": reason = json.Text(); break; default: throw Invalid(); }
            });
            json.RequireKeys(keys, "DistinguishedName", "Reason");
            json.Require(dn is not null && Enum.TryParse<AdministrativeMembershipReason>(reason, out var parsed) && Enum.IsDefined(parsed));
            var limitation = Enum.Parse<AdministrativeMembershipReason>(reason!);
            _captureIncomplete |= limitation == AdministrativeMembershipReason.CaptureIncomplete;
            if (kind == BroadMembershipPageKind.Limitations && position >= offset && position < offset + SavedBroadMembershipContext.PageSize)
                _limits.Add(new(position, new(dn!, limitation)));
            position++;
        });
    }
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    private static InvalidDataException Invalid() => new(SavedBroadMembershipContext.InvalidDetails);
}
