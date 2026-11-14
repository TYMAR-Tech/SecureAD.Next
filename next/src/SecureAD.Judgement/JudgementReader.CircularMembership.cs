using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Shows one recorded loop, retaining one successor per group rather than enumerating every possible cycle.</summary>
    public Result<SavedCircularMembershipLoop> ReadCircularMembershipLoop(FindingReference reference, CircularMembershipLoopMark? after)
    {
        var selected = ReadCircularSelection(reference);
        if (!selected.IsSuccess) return Result<SavedCircularMembershipLoop>.Failure(selected.Error);
        var finding = selected.Value;
        RequireCircularPosition(finding, after?.GenerationId, after?.FindingId, after?.ComponentKey, after?.Offset);
        var read = ReadCircularProof(finding, CircularMembershipReadKind.Loop, 0, positions: null);
        if (read.FirstLinks.Count != read.Context.GroupCount
            || read.FirstLinks.Values.Any(value => !read.FirstLinks.ContainsKey(value.MemberGuid))) throw CircularInvalid();
        var visited = new Dictionary<Guid, int>();
        var path = new List<CircularMembershipLinkHeader>();
        var current = read.Context.Anchor.ObjectGuid;
        while (!visited.ContainsKey(current))
        {
            _readCancellation.ThrowIfCancellationRequested();
            if (!read.FirstLinks.TryGetValue(current, out var link)) throw CircularInvalid();
            visited.Add(current, path.Count); path.Add(link); current = link.MemberGuid;
        }
        var cycle = path.Skip(visited[current]).ToArray();
        var key = Tier0PathCalculation.Fingerprint(cycle.Select(link => link.GroupGuid.ToString("D") + ":" + link.MemberGuid.ToString("D")));
        var start = after?.Offset ?? 0;
        if (cycle.Length == 0 || start >= cycle.Length || after is { } mark && mark.LoopKey != key) throw CircularInvalid();
        var headers = cycle.Skip(checked((int)start)).Take(SavedCircularMembershipContext.PageSize).ToArray();
        var positions = headers.SelectMany(link => new[] { link.GroupGuid, link.MemberGuid }).Distinct()
            .ToDictionary(guid => guid, guid => CircularGroupPosition(reference.FindingId, guid, expected: null));
        var identities = ReadCircularProof(finding, CircularMembershipReadKind.Identities, 0, positions.Values.ToHashSet());
        if (identities.Context != read.Context) throw CircularInvalid();
        var steps = headers.Select((link, index) => new SavedCircularMembershipLoopStep(start + index,
            new(link.Position, Identity(link.GroupGuid), Identity(link.MemberGuid), link.WitnessCount))).ToArray();
        CircularMembershipLoopMark? next = start + steps.Length < cycle.Length
            ? new(reference.GenerationId, reference.FindingId, finding.Subject.Key, key, start + steps.Length) : null;
        var page = new SavedCircularMembershipLoop(read.Context, key, cycle[0].GroupGuid, cycle.Length,
            read.Context.GroupCount > cycle.Length || read.Context.LinkCount > cycle.Length, steps, next);
        if (!page.IsExpectedPage(after)) throw CircularInvalid();
        return Result<SavedCircularMembershipLoop>.Success(page);

        CircularMembershipGroup Identity(Guid guid) => identities.Groups.TryGetValue(positions[guid], out var group) && group.ObjectGuid == guid
            ? group : throw CircularInvalid();
    }

    /// <summary>Reads the original cycle-inventory flag and one saved group page, without reconstructing the graph.</summary>
    public Result<SavedCircularMembershipGroups> ReadCircularMembershipGroups(FindingReference reference, CircularMembershipGroupMark? after)
    {
        var selected = ReadCircularSelection(reference);
        if (!selected.IsSuccess) return Result<SavedCircularMembershipGroups>.Failure(selected.Error);
        var finding = selected.Value;
        RequireCircularPosition(finding, after?.GenerationId, after?.FindingId, after?.ComponentKey, after?.Offset);
        var start = after?.Offset ?? 0;
        var read = ReadCircularProof(finding, CircularMembershipReadKind.Groups, start, positions: null);
        var groups = read.Groups.Where(pair => pair.Key >= start && pair.Key < start + SavedCircularMembershipContext.PageSize)
            .OrderBy(pair => pair.Key).Select(pair => new SavedCircularMembershipGroup(pair.Key, pair.Value)).ToArray();
        CircularMembershipGroupMark? next = start + groups.Length < read.Context.GroupCount
            ? new(reference.GenerationId, reference.FindingId, finding.Subject.Key, start + groups.Length) : null;
        var page = new SavedCircularMembershipGroups(read.Context, groups, next);
        if (!page.IsExpectedPage(after)) throw CircularInvalid();
        return Result<SavedCircularMembershipGroups>.Success(page);
    }

    /// <summary>Reads one requested page of direct links and only its endpoint identities, without original witness values.</summary>
    public Result<SavedCircularMembershipLinks> ReadCircularMembershipLinks(FindingReference reference, CircularMembershipLinkMark? after)
    {
        var selected = ReadCircularSelection(reference);
        if (!selected.IsSuccess) return Result<SavedCircularMembershipLinks>.Failure(selected.Error);
        var finding = selected.Value;
        RequireCircularPosition(finding, after?.GenerationId, after?.FindingId, after?.ComponentKey, after?.Offset);
        var start = after?.Offset ?? 0;
        var headers = ReadCircularProof(finding, CircularMembershipReadKind.Links, start, positions: null);
        var positions = headers.Links.SelectMany(link => new[] { link.GroupGuid, link.MemberGuid }).Distinct()
            .ToDictionary(guid => guid, guid => CircularGroupPosition(reference.FindingId, guid, expected: null));
        // Link endpoints occur earlier in the current JSON record. A second bounded projection
        // reads only those identities, rather than retaining every group or inventing a new format.
        var identities = ReadCircularProof(finding, CircularMembershipReadKind.Identities, 0, positions.Values.ToHashSet());
        if (identities.Context != headers.Context) throw CircularInvalid();
        var links = headers.Links.Select(link => new SavedCircularMembershipLink(link.Position,
            Identity(link.GroupGuid), Identity(link.MemberGuid), link.WitnessCount)).ToArray();
        CircularMembershipLinkMark? next = start + links.Length < headers.Context.LinkCount
            ? new(reference.GenerationId, reference.FindingId, finding.Subject.Key, start + links.Length) : null;
        var page = new SavedCircularMembershipLinks(headers.Context, links, next);
        if (!page.IsExpectedPage(after)) throw CircularInvalid();
        return Result<SavedCircularMembershipLinks>.Success(page);

        CircularMembershipGroup Identity(Guid guid) => identities.Groups.TryGetValue(positions[guid], out var group) && group.ObjectGuid == guid
            ? group : throw CircularInvalid();
    }

    /// <summary>Reads every original occurrence on the selected direct link in bounded pages, keeping member/memberOf source direction.</summary>
    public Result<SavedCircularMembershipWitnesses> ReadCircularMembershipWitnesses(FindingReference reference,
        Guid groupGuid, Guid memberGuid, CircularMembershipWitnessMark? after)
    {
        var selected = ReadCircularSelection(reference);
        if (!selected.IsSuccess) return Result<SavedCircularMembershipWitnesses>.Failure(selected.Error);
        var finding = selected.Value;
        RequireCircularPosition(finding, after?.GenerationId, after?.FindingId, after?.ComponentKey, after?.Offset);
        if (groupGuid == Guid.Empty || memberGuid == Guid.Empty || after is { } mark && (mark.GroupGuid != groupGuid || mark.MemberGuid != memberGuid))
            throw CircularInvalid();
        var header = ReadCircularProof(finding, CircularMembershipReadKind.FindLink, 0, group: groupGuid, member: memberGuid, positions: null);
        if (header.Links.Count != 1) throw CircularInvalid();
        var link = header.Links[0];
        var groupPosition = CircularGroupPosition(reference.FindingId, groupGuid, expected: null);
        var memberPosition = CircularGroupPosition(reference.FindingId, memberGuid, expected: null);
        var read = ReadCircularProof(finding, CircularMembershipReadKind.Witnesses, after?.Offset ?? 0,
            new HashSet<long> { groupPosition, memberPosition }, groupGuid, memberGuid, link.Position);
        if (read.Context != header.Context || read.Links.Count != 1 || read.Links[0] != link
            || !read.Groups.TryGetValue(groupPosition, out var group) || group.ObjectGuid != groupGuid
            || !read.Groups.TryGetValue(memberPosition, out var member) || member.ObjectGuid != memberGuid) throw CircularInvalid();
        var values = read.Witnesses.Select(value => new SavedCircularMembershipWitness(value.Position,
            value.SourceGuid == groupGuid ? group : value.SourceGuid == memberGuid ? member : throw CircularInvalid(),
            value.Attribute, value.Ordinal, value.Value)).ToArray();
        var start = after?.Offset ?? 0;
        CircularMembershipWitnessMark? next = start + values.Length < link.WitnessCount
            ? new(reference.GenerationId, reference.FindingId, finding.Subject.Key, groupGuid, memberGuid, start + values.Length) : null;
        var page = new SavedCircularMembershipWitnesses(read.Context, new(link.Position, group, member, link.WitnessCount), values, next);
        if (!page.IsExpectedPage(after)) throw CircularInvalid();
        return Result<SavedCircularMembershipWitnesses>.Success(page);
    }

    private Result<FindingListItem> ReadCircularSelection(FindingReference reference)
    {
        var selected = ReadSelectedFindingCore(reference, false, CircularGroupMembership.Explanation);
        return !selected.IsSuccess || selected.Value.RuleId == "SEC-052" ? selected
            : Result<FindingListItem>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged",
                ErrorSeverity.Failed, SavedCircularMembershipContext.InvalidDetails, BundleDirectory));
    }

    private CircularMembershipProjectionResult ReadCircularProof(FindingListItem finding, CircularMembershipReadKind kind,
        long offset, IReadOnlySet<long>? positions, Guid group = default, Guid member = default, long linkPosition = -1)
    {
        _readCancellation.ThrowIfCancellationRequested();
        OpenPart(StoreSegmentRole.PermissionProof);
        var reference = finding.Reference!.Value;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,typeof(proof),fingerprint FROM finding_circular_membership WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetValue(0) is not string generation || generation != reference.GenerationId.ToString("D")
                || row.GetString(1) != "text" || row.GetValue(2) is not byte[] { Length: 32 }) throw CircularInvalid();
        }
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_circular_membership", "proof", reference.FindingId, readOnly: true);
        var result = CircularMembershipProjection.Read(proof, finding, Description, kind, offset, positions, group, member, linkPosition, _readCancellation);
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT COUNT(*) FROM finding_circular_group WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            if (command.ExecuteScalar() is not long count || count != result.Context.GroupCount) throw CircularInvalid();
        }
        foreach (var identity in result.Groups)
        {
            if (CircularGroupPosition(reference.FindingId, identity.Value.ObjectGuid, identity.Value) != identity.Key) throw CircularInvalid();
        }
        _readCancellation.ThrowIfCancellationRequested();
        return result;
    }

    private long CircularGroupPosition(long findingId, Guid guid, CircularMembershipGroup? expected)
    {
        _readCancellation.ThrowIfCancellationRequested();
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT g.distinguished_name,g.domain_fqdn,
                (SELECT COUNT(*) FROM finding_circular_group earlier
                    WHERE earlier.finding_id=$id AND earlier.object_guid<$guid)
            FROM finding_circular_group g WHERE g.finding_id=$id AND g.object_guid=$guid
            """;
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$guid", guid.ToString("D"));
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string dn || row.GetValue(1) is not string domain
            || row.GetValue(2) is not long position || position < 0
            || expected is not null && (dn != expected.DistinguishedName || domain != expected.DomainFqdn)) throw CircularInvalid();
        return position;
    }

    private static void RequireCircularPosition(FindingListItem finding, Guid? generation, long? id, string? component, long? offset)
    {
        if (offset is { } position && (generation != finding.Reference!.Value.GenerationId || id != finding.Reference.Value.FindingId
            || component != finding.Subject.Key || position <= 0 || position % SavedCircularMembershipContext.PageSize != 0)) throw CircularInvalid();
    }
    private static InvalidDataException CircularInvalid() => new(SavedCircularMembershipContext.InvalidDetails);
}
