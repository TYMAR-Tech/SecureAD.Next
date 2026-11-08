using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal enum CircularMembershipReadKind { Groups, Links, FindLink, Witnesses, Identities }
internal sealed record CircularMembershipLinkHeader(long Position, Guid GroupGuid, Guid MemberGuid, int WitnessCount);
internal sealed record CircularMembershipWitnessValue(long Position, Guid SourceGuid, string Attribute, int Ordinal, string Value);
internal sealed record CircularMembershipProjectionResult(SavedCircularMembershipContext Context,
    IReadOnlyDictionary<long, CircularMembershipGroup> Groups, IReadOnlyList<CircularMembershipLinkHeader> Links,
    IReadOnlyList<CircularMembershipWitnessValue> Witnesses);

internal sealed class CircularMembershipProjection(SavedProofJsonReader json, FindingListItem selected,
    JudgementDescription description, CircularMembershipReadKind kind, long offset, IReadOnlySet<long>? groupPositions,
    Guid selectedGroup, Guid selectedMember, long selectedLinkPosition)
{
    private readonly Dictionary<long, CircularMembershipGroup> _groups = [];
    private readonly List<CircularMembershipLinkHeader> _links = [];
    private readonly List<CircularMembershipWitnessValue> _witnesses = [];
    private int _groupCount, _linkCount;
    private bool _inventoryComplete, _complete;

    internal static CircularMembershipProjectionResult Read(Stream stream, FindingListItem selected, JudgementDescription description,
        CircularMembershipReadKind kind, long offset, IReadOnlySet<long>? groupPositions, Guid group, Guid member, long linkPosition,
        CancellationToken token) => SavedProofJsonReader.Read(stream, token, SavedCircularMembershipContext.InvalidDetails, json =>
            new CircularMembershipProjection(json, selected, description, kind, offset, groupPositions, group, member, linkPosition).Read());

    private CircularMembershipProjectionResult Read()
    {
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "EvidenceSeal": json.Require(json.Text() == description.EvidenceSeal); break;
                case "DerivationGenerationId": json.Require(json.GuidValue() == description.DerivationGenerationId); break;
                case "ComponentKey": json.Require(json.Text() == selected.Subject.Key); break;
                case "Groups": Groups(); break;
                case "Links": Links(); break;
                case "InventoryComplete": _inventoryComplete = json.Bit(); break;
                case "IsComplete": _complete = json.Bit(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "EvidenceSeal", "DerivationGenerationId", "ComponentKey", "Groups", "Links", "InventoryComplete", "IsComplete");
        json.Require(_groups.TryGetValue(0, out var anchor) && _complete == _inventoryComplete);
        var context = new SavedCircularMembershipContext(selected.Reference!.Value, selected.Subject, anchor!,
            _groupCount, _linkCount, _inventoryComplete, selected.Coverage);
        json.Require(context.Matches(selected));
        return new(context, _groups, _links, _witnesses);
    }

    private void Groups()
    {
        long position = 0;
        _groupCount = Count(json.Array(() =>
        {
            var requested = position == 0 || groupPositions?.Contains(position) == true
                || kind == CircularMembershipReadKind.Groups && position >= offset && position < offset + SavedCircularMembershipContext.PageSize;
            if (!requested) json.Skip("object");
            else
            {
                Guid guid = Guid.Empty; string? dn = null, domain = null, sid = null, scope = null;
                var keys = json.Object(name =>
                {
                    switch (name)
                    {
                        case "ObjectGuid": guid = json.GuidValue(); break;
                        case "DistinguishedName": dn = json.Text(); break;
                        case "DomainFqdn": domain = json.Text(); break;
                        case "Sid": sid = json.Text(); break;
                        case "SidScope": scope = json.OptionalText(); break;
                        default: throw Invalid();
                    }
                });
                json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "DomainFqdn", "Sid", "SidScope");
                json.Require(dn is not null && domain is not null && sid is not null);
                var group = new CircularMembershipGroup(guid, dn!, domain!, sid!, scope);
                json.Require(SavedCircularMembershipContext.ValidGroup(group) && _groups.TryAdd(position, group));
            }
            position++;
        }));
    }

    private void Links()
    {
        long position = 0;
        _linkCount = Count(json.Array(() =>
        {
            var requested = kind == CircularMembershipReadKind.FindLink
                || kind == CircularMembershipReadKind.Links && position >= offset && position < offset + SavedCircularMembershipContext.PageSize
                || kind == CircularMembershipReadKind.Witnesses && position == selectedLinkPosition;
            if (!requested) json.Skip("object");
            else
            {
                Guid group = Guid.Empty, member = Guid.Empty; int witnesses = 0; bool complete = false;
                var keys = json.Object(name =>
                {
                    switch (name)
                    {
                        case "GroupGuid": group = json.GuidValue(); break;
                        case "MemberGuid": member = json.GuidValue(); break;
                        case "Witnesses":
                            long witnessPosition = 0;
                            witnesses = Count(json.Array(() =>
                            {
                                if (kind != CircularMembershipReadKind.Witnesses || witnessPosition < offset
                                    || witnessPosition >= offset + SavedCircularMembershipContext.PageSize) json.Skip("object");
                                else _witnesses.Add(Witness(witnessPosition));
                                witnessPosition++;
                            }));
                            break;
                        case "IsComplete": complete = json.Bit(); break;
                        default: throw Invalid();
                    }
                });
                json.RequireKeys(keys, "GroupGuid", "MemberGuid", "Witnesses", "IsComplete");
                json.Require(witnesses > 0 && complete);
                if (kind == CircularMembershipReadKind.FindLink)
                {
                    if (group == selectedGroup && member == selectedMember)
                    {
                        json.Require(_links.Count == 0);
                        _links.Add(new(position, group, member, witnesses));
                    }
                }
                else
                {
                    json.Require(kind != CircularMembershipReadKind.Witnesses || group == selectedGroup && member == selectedMember);
                    _links.Add(new(position, group, member, witnesses));
                }
            }
            position++;
        }));
    }

    private CircularMembershipWitnessValue Witness(long position)
    {
        Guid source = Guid.Empty; string? attribute = null, value = null; long ordinal = -1;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "SourceObjectGuid": source = json.GuidValue(); break;
                case "Attribute": attribute = json.Text(); break;
                case "Ordinal": ordinal = json.Number(); break;
                case "Value": value = json.Text(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "SourceObjectGuid", "Attribute", "Ordinal", "Value");
        json.Require(attribute is "member" or "memberOf" && value is not null && ordinal <= int.MaxValue);
        return new(position, source, attribute!, checked((int)ordinal), value!);
    }
    private int Count(long count) { json.Require(count is > 0 and <= int.MaxValue); return (int)count; }
    private static InvalidDataException Invalid() => new(SavedCircularMembershipContext.InvalidDetails);
}
