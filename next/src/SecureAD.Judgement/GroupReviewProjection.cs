using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class GroupReviewProjection(SavedProofJsonReader json, FindingListItem selected,
    JudgementDescription description, string derivationSeal, bool referencesRequested, GroupReviewReferenceMark? after)
{
    private readonly Dictionary<Guid, SavedReviewGroup> _principals = [];
    private readonly List<SavedGroupReference> _references = [];
    private readonly List<string> _limits = [];
    private readonly HashSet<Guid> _foreignReferences = [];
    private readonly Dictionary<long, string?> _requestedOrdinals = [];
    private readonly HashSet<long> _matchedOrdinals = [];
    private bool _captureIncomplete;
    private Guid _target, _nested;
    private long _referenceCount, _witnessCount;
    private bool _inputsComplete, _complete;
    private int? _direct, _threshold, _total, _unresolved, _unreadable;
    private GroupMembershipLimitations _totalLimits;

    internal static SavedGroupReferences Read(Stream stream, FindingListItem selected, JudgementDescription description,
        string derivationSeal, bool requested, GroupReviewReferenceMark? after, CancellationToken token) =>
        SavedProofJsonReader.Read(stream, token, SavedGroupReview.InvalidDetails(selected.RuleId), json =>
            new GroupReviewProjection(json, selected, description, derivationSeal, requested, after).Read());

    private SavedGroupReferences Read()
    {
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "EvidenceSeal": json.Require(json.Text() == description.EvidenceSeal); break;
                case "DerivationGenerationId": json.Require(json.GuidValue() == description.DerivationGenerationId); break;
                case "DerivationSeal": json.Require(json.Text() == derivationSeal); break;
                case "PrincipalCatalogueVersion": json.Require(json.Number() == PrincipalClassificationRegistry.Version); break;
                case "PolicyVersion": json.Require(json.Number() == GroupMembershipReviewRules.PolicyVersion); break;
                case "ForestRootNamingContext": case "ConfigurationNamingContext": json.OptionalText(); break;
                case "ReviewKind": json.Require(json.Text() == (selected.RuleId == "SEC-050"
                    ? nameof(GroupMembershipReviewKind.PrivilegedGroupSize) : nameof(GroupMembershipReviewKind.GroupNestedInDomainAdmins))); break;
                case "TargetGuid": _target = json.GuidValue(); break;
                case "NestedGroupGuid": if (json.IsNull()) json.Skip(); else _nested = json.GuidValue(); break;
                case "Principals": json.Array(() => { var group = Identity(); json.Require(_principals.TryAdd(group.Identity.ObjectGuid, group)); }); break;
                case "Domains": json.Skip("array"); break;
                case "MemberValues": MemberValues(); break;
                case "Links": Links(); break;
                case "DirectMembers": _direct = OptionalNumber(); break;
                case "ReviewThreshold": _threshold = OptionalNumber(); break;
                case "KnownTotal": Total(); break;
                case "InputsComplete": _inputsComplete = json.Bit(); break;
                case "Limitations": json.Array(Limitation); break;
                case "IsComplete": _complete = json.Bit(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "EvidenceSeal", "DerivationGenerationId", "DerivationSeal", "PrincipalCatalogueVersion",
            "PolicyVersion", "ForestRootNamingContext", "ConfigurationNamingContext", "ReviewKind", "TargetGuid",
            "NestedGroupGuid", "Principals", "Domains", "MemberValues", "Links", "DirectMembers", "ReviewThreshold",
            "KnownTotal", "InputsComplete", "Limitations", "IsComplete");
        json.Require(_principals.ContainsKey(_target));
        var affected = selected.RuleId == "SEC-050" ? _target : _nested;
        json.Require(_principals.ContainsKey(affected) && (_inputsComplete || _captureIncomplete)
            && _complete == (_inputsComplete && _limits.Count == 0 && _totalLimits == GroupMembershipLimitations.None)
            && (selected.RuleId == "SEC-050" ? _nested == Guid.Empty && _witnessCount == 0
                && _principals.Count == 1
                : _nested != Guid.Empty && _witnessCount == _referenceCount
                    && _principals.Count == _foreignReferences.Union([_target, _nested]).Count()));
        foreach (var reference in _foreignReferences)
        {
            json.Require(_principals.TryGetValue(reference, out var identity));
            var member = _principals[_nested]; var target = _principals[_target];
            json.Require(Same(identity!.Sid, member.Sid) && (reference == _nested
                || identity.Identity.ObjectClass == "foreignSecurityPrincipal"
                    && Same(identity.Identity.DomainFqdn, target.Identity.DomainFqdn)
                    && (!Sid.IsBuiltinDomain(member.Sid) || Same(identity.Identity.DomainFqdn, member.Identity.DomainFqdn))));
        }
        json.Require(!referencesRequested || selected.RuleId == "SEC-050" || _matchedOrdinals.Count == _requestedOrdinals.Count);
        var context = new SavedGroupReview(selected.Reference!.Value, selected.RuleId, selected.Subject, _principals[affected],
            _principals[_target], _direct, _threshold, _total, _unresolved, _unreadable, _totalLimits,
            _inputsComplete, string.Join("\n", _limits), _complete, _referenceCount, _foreignReferences.Any(value => value != _nested));
        json.Require(context.Matches(selected));
        var start = after?.Offset ?? 0;
        json.Require(after is not { } mark || mark.GenerationId == context.Reference.GenerationId
            && mark.FindingId == context.Reference.FindingId && mark.AffectedGuid == context.Affected.Identity.ObjectGuid
            && mark.DestinationGuid == context.Destination.Identity.ObjectGuid && mark.Offset > 0 && mark.Offset < _referenceCount
            && mark.Offset % SavedGroupReview.PageSize == 0);
        GroupReviewReferenceMark? next = referencesRequested && start + _references.Count < _referenceCount
            ? new(context.Reference.GenerationId, context.Reference.FindingId, context.Affected.Identity.ObjectGuid,
                context.Destination.Identity.ObjectGuid, start + _references.Count) : null;
        var page = new SavedGroupReferences(context, _references, next);
        json.Require(!referencesRequested || page.IsExpectedPage(after));
        return page;
    }

    private SavedReviewGroup Identity()
    {
        Guid guid = Guid.Empty; string? dn = null, domain = null, sid = null, scope = null, kind = null; long? type = null;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = json.GuidValue(); break;
                case "DistinguishedName": dn = json.Text(); break;
                case "NamingContext": json.Text(); break;
                case "DomainFqdn": domain = json.OptionalText(); break;
                case "Sid": sid = json.Text(); break;
                case "SidScope": scope = json.OptionalText(); break;
                case "ObjectClass": kind = json.Text(); break;
                case "GroupType": if (json.IsNull()) json.Skip(); else type = json.SignedNumber(); break;
                case "CapturedUtc": json.Skip("string"); break;
                case "Completeness": json.Text(); break;
                case "Values": json.Skip("array"); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "NamingContext", "DomainFqdn", "Sid", "SidScope",
            "ObjectClass", "GroupType", "CapturedUtc", "Completeness", "Values");
        json.Require(dn is not null && domain is not null && kind is not null && Sid.ToBytes(sid) is not null);
        var identity = new SavedDelegationIdentity(guid, dn!, domain!, kind!);
        json.Require(identity.IsValid);
        return new(identity, sid!, scope, type);
    }

    private void MemberValues()
    {
        var position = 0L; var start = after?.Offset ?? 0;
        _referenceCount = json.Array(() =>
        {
            if (!referencesRequested || position < start || position >= start + SavedGroupReview.PageSize) json.Skip("object");
            else
            {
                string? value = null; long ordinal = -1;
                var keys = json.Object(name =>
                {
                    switch (name)
                    {
                        case "Ordinal": ordinal = json.Number(); break;
                        case "Text": if (json.IsNull()) json.Skip(); else value = json.ValueText(); break;
                        case "Bytes": case "Stored": json.Skip(); break;
                        default: throw Invalid();
                    }
                });
                json.RequireKeys(keys, "Ordinal", "Text", "Bytes", "Stored");
                json.Require(_requestedOrdinals.TryAdd(ordinal, value));
                _references.Add(new(position, string.IsNullOrWhiteSpace(value) ? null : value));
            }
            position++;
        });
    }

    private void Links() => json.Array(() =>
    {
        Guid group = Guid.Empty, member = Guid.Empty, reference = Guid.Empty;
        string? recordedDn = null; long witnesses = 0;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "GroupGuid": group = json.GuidValue(); break;
                case "MemberGuid": member = json.GuidValue(); break;
                case "MemberReferenceGuid": reference = json.GuidValue(); break;
                case "Witnesses":
                    witnesses = json.Array(() =>
                    {
                        long ordinal = -1; string? value = null;
                        var witness = json.Object(field =>
                        {
                            switch (field)
                            {
                                case "SourceObjectGuid": json.Require(json.GuidValue() == _target); break;
                                case "Attribute": json.Require(json.Text() == "member"); break;
                                case "Ordinal": ordinal = json.Number(); break;
                                case "Value": value = json.Text(); break;
                                default: throw Invalid();
                            }
                        });
                        json.RequireKeys(witness, "SourceObjectGuid", "Attribute", "Ordinal", "Value");
                        json.Require(recordedDn is null || Same(recordedDn, value));
                        recordedDn = value;
                        if (_requestedOrdinals.TryGetValue(ordinal, out var original))
                            json.Require(original == value && _matchedOrdinals.Add(ordinal));
                    });
                    break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "GroupGuid", "MemberGuid", "MemberReferenceGuid", "Witnesses");
        json.Require(group == _target && member == _nested && witnesses > 0 && _foreignReferences.Add(reference)
            && _principals.TryGetValue(reference, out var identity) && Same(recordedDn, identity.Identity.DistinguishedName));
        _witnessCount += witnesses;
    });

    private void Total()
    {
        if (json.IsNull()) { json.Skip(); return; }
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "KnownMembers": _total = Number(); break;
                case "UnresolvedReferences": _unresolved = Number(); break;
                case "UnreadableReferences": _unreadable = Number(); break;
                case "Limitations": json.Array(() =>
                {
                    json.Require(Enum.TryParse<GroupMembershipLimitations>(json.Text(), out var flag)
                        && Enum.IsDefined(flag) && flag != GroupMembershipLimitations.None && !_totalLimits.HasFlag(flag));
                    _totalLimits |= flag;
                }); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "KnownMembers", "UnresolvedReferences", "UnreadableReferences", "Limitations");
        json.Require((_unresolved > 0) == _totalLimits.HasFlag(GroupMembershipLimitations.UnresolvedReferences)
            && (_unreadable > 0) == _totalLimits.HasFlag(GroupMembershipLimitations.UnreadableReferences));
    }

    private void Limitation()
    {
        string? dn = null; AdministrativeMembershipReason? reason = null;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "DistinguishedName": dn = json.Text(); break;
                case "Reason":
                    json.Require(Enum.TryParse<AdministrativeMembershipReason>(json.Text(), out var parsed) && Enum.IsDefined(parsed));
                    reason = parsed; break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "DistinguishedName", "Reason");
        json.Require(reason is not null && dn is not null);
        _captureIncomplete |= reason == AdministrativeMembershipReason.CaptureIncomplete;
        _limits.Add(CapturedGroupMembershipIndex.Describe(reason!.Value) + ": " + dn);
    }
    private int Number() { var value = json.Number(); json.Require(value <= int.MaxValue); return (int)value; }
    private int? OptionalNumber() { if (json.IsNull()) { json.Skip(); return null; } return Number(); }
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private InvalidDataException Invalid() => new(SavedGroupReview.InvalidDetails(selected.RuleId));
}
