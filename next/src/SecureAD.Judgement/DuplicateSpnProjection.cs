using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal sealed class DuplicateSpnProjection
{
    private enum Pass { Select, LocateOwners, ResolveOwners }
    private readonly FindingListItem _selected;
    private readonly JudgementDescription _description;
    private readonly DuplicateSpnMark? _request;
    private readonly List<DuplicateSpnOwner> _owners = [];
    private readonly List<(Guid Owner, int Ordinal, string Value)> _occurrences = [];
    private readonly Dictionary<Guid, DuplicateSpnOwner> _registrationOwners = [];
    private readonly Dictionary<long, Guid> _ownerPositions = [];
    private readonly List<string> _limitations = [];
    private DuplicateSpnOwner? _affected;
    private string? _forest, _key, _verdict;
    private int _spnCount;
    private long _ownerCount, _occurrenceCount;
    private long _affectedPosition = -1;
    private int Index => _request?.SpnIndex ?? 0;
    private long Offset => _request?.Offset ?? 0;
    private bool Registrations => _request?.Kind == DuplicateSpnPageKind.CapturedRegistrations;

    private DuplicateSpnProjection(FindingListItem selected, JudgementDescription description, DuplicateSpnMark? request) =>
        (_selected, _description, _request) = (selected, description, request);

    internal static SavedDuplicateSpn Read(Stream proof, FindingListItem selected, JudgementDescription description,
        DuplicateSpnMark? request, CancellationToken token)
    {
        var projection = new DuplicateSpnProjection(selected, description, request);
        projection.Read(proof, token, Pass.Select);
        if (projection.Registrations)
        {
            proof.Position = 0;
            projection.Read(proof, token, Pass.LocateOwners);
        }
        if (projection._affected is null || projection.Registrations)
        {
            Require(projection._affectedPosition >= 0);
            projection._ownerPositions[projection._affectedPosition] = selected.ObjectGuid;
            proof.Position = 0;
            projection.Read(proof, token, Pass.ResolveOwners);
        }
        var context = new DuplicateSpnContext(selected.Reference!.Value, selected.Subject, projection._affected!,
            projection._forest!, projection._limitations.ToArray());
        Require(context.Matches(selected));
        var total = projection.Registrations ? projection._occurrenceCount : projection._ownerCount;
        var count = projection.Registrations ? projection._occurrences.Count : projection._owners.Count;
        var position = new DuplicateSpnMark(description.GenerationId, selected.Reference.Value.FindingId, selected.ObjectGuid,
            projection.Index, projection.Registrations ? DuplicateSpnPageKind.CapturedRegistrations : DuplicateSpnPageKind.RegisteredObjects, projection.Offset);
        var originals = projection._occurrences.Select(value => new SavedSpnRegistration(
            projection._registrationOwners.TryGetValue(value.Owner, out var owner) ? owner : throw Invalid(), value.Ordinal, value.Value)).ToArray();
        var page = new SavedDuplicateSpn(context, projection.Index, projection._key!, projection._spnCount,
            position.Kind, position.Offset, total, projection._owners.ToArray(), originals,
            position.Offset + count < total ? position with { Offset = position.Offset + count } : null);
        Require(page.IsExpectedPage(request));
        return page;
    }

    private void Read(Stream proof, CancellationToken token, Pass pass) =>
        SavedProofJsonReader.Read(proof, token, SavedDuplicateSpn.InvalidDetails, json =>
        {
            var keys = json.Object(name =>
            {
                switch (name)
                {
                    case "EvidenceSeal": Require(json.Text() == _description.EvidenceSeal); break;
                    case "ForestFqdn": _forest = json.Text(); break;
                    case "SubjectGuid": Require(json.GuidValue() == _selected.ObjectGuid); break;
                    case "Duplicates":
                        var index = -1L;
                        var count = json.Array(() =>
                        {
                            index++;
                            if (index == Index) Match(json, pass);
                            else json.Skip("object");
                        });
                        Require(count is > 0 and <= int.MaxValue && Index < count);
                        _spnCount = (int)count;
                        break;
                    case "Limitations":
                        if (pass != Pass.Select) json.Skip("array");
                        else json.Array(() => _limitations.Add(json.Text()));
                        break;
                    case "Verdict": _verdict = json.Text(); break;
                    default: throw Invalid();
                }
            });
            json.RequireKeys(keys, "EvidenceSeal", "ForestFqdn", "SubjectGuid", "Duplicates", "Limitations", "Verdict");
            Require(_key is not null && _affectedPosition >= 0 && _ownerCount >= 2 && _occurrenceCount >= 2
                && _verdict == (_limitations.Count == 0 ? "RecordedDuplicates" : "RecordedDuplicatesWithLimitations"));
            return true;
        });

    private void Match(SavedProofJsonReader json, Pass pass)
    {
        var wantedOwners = pass == Pass.LocateOwners ? _occurrences.Select(value => value.Owner).ToHashSet() : null;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "MatchKey": _key = json.Text(); break;
                case "Owners":
                    var index = -1L;
                    _ownerCount = json.Array(() =>
                    {
                        index++;
                        if (pass == Pass.ResolveOwners)
                        {
                            if (!_ownerPositions.TryGetValue(index, out var guid)) { json.Skip("object"); return; }
                            var resolved = Owner(json);
                            Require(resolved.ObjectGuid == guid);
                            if (guid == _selected.ObjectGuid) _affected = resolved;
                            if (Registrations) Require(_registrationOwners.TryAdd(guid, resolved));
                            return;
                        }
                        if (pass == Pass.Select && !Registrations && index >= Offset && index - Offset < SavedDuplicateSpn.PageSize)
                        {
                            var owner = Owner(json);
                            _owners.Add(owner);
                            if (owner.ObjectGuid == _selected.ObjectGuid)
                            {
                                _affectedPosition = index;
                                _affected = owner;
                            }
                        }
                        else
                        {
                            var guid = OwnerGuid(json);
                            if (guid == _selected.ObjectGuid) _affectedPosition = index;
                            if (pass == Pass.LocateOwners && wantedOwners!.Contains(guid)) Require(_ownerPositions.TryAdd(index, guid));
                        }
                    });
                    break;
                case "Occurrences":
                    if (pass != Pass.Select) { json.Skip("array"); break; }
                    var occurrenceIndex = -1L;
                    _occurrenceCount = json.Array(() =>
                    {
                        occurrenceIndex++;
                        if (!Registrations || occurrenceIndex < Offset || occurrenceIndex - Offset >= SavedDuplicateSpn.PageSize)
                        {
                            json.Skip("object");
                            return;
                        }
                        Guid owner = Guid.Empty;
                        long ordinal = -1;
                        string? value = null;
                        var fields = json.Object(field =>
                        {
                            switch (field)
                            {
                                case "OwnerGuid": owner = json.GuidValue(); break;
                                case "Ordinal": ordinal = json.Number(); break;
                                case "Value": value = json.Text(); break;
                                default: throw Invalid();
                            }
                        });
                        json.RequireKeys(fields, "OwnerGuid", "Ordinal", "Value");
                        Require(ordinal is >= 0 and <= int.MaxValue && value is not null);
                        _occurrences.Add((owner, (int)ordinal, value!));
                    });
                    break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "MatchKey", "Owners", "Occurrences");
    }

    private static DuplicateSpnOwner Owner(SavedProofJsonReader json)
    {
        Guid guid = Guid.Empty;
        string? dn = null, domain = null, kind = null, account = null;
        var keys = json.Object(name =>
        {
            switch (name)
            {
                case "ObjectGuid": guid = json.GuidValue(); break;
                case "DistinguishedName": dn = json.Text(); break;
                case "DomainFqdn": domain = json.Text(); break;
                case "ObjectClass": kind = json.Text(); break;
                case "AccountName": account = json.OptionalText(); break;
                default: throw Invalid();
            }
        });
        json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "DomainFqdn", "ObjectClass", "AccountName");
        return new(guid, dn!, domain!, kind!, account);
    }

    private static Guid OwnerGuid(SavedProofJsonReader json)
    {
        var guid = Guid.Empty;
        var keys = json.Object(name =>
        {
            if (name == "ObjectGuid") guid = json.GuidValue();
            else json.Skip();
        });
        json.RequireKeys(keys, "ObjectGuid", "DistinguishedName", "DomainFqdn", "ObjectClass", "AccountName");
        return guid;
    }

    private static void Require(bool condition) { if (!condition) throw Invalid(); }
    private static InvalidDataException Invalid() => new(SavedDuplicateSpn.InvalidDetails);
}
