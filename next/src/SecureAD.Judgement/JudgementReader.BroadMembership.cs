using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    public Result<SavedBroadMembershipPage<SavedBroadIdentity>> ReadBroadMembershipSources(FindingReference reference, BroadMembershipMark? after)
    {
        var selected = ReadBroadSelection(reference);
        if (!selected.IsSuccess) return Result<SavedBroadMembershipPage<SavedBroadIdentity>>.Failure(selected.Error);
        var read = ReadBroadProof(selected.Value, BroadMembershipPageKind.Sources, after?.Offset ?? 0, linkPosition: -1, wanted: null);
        return Result<SavedBroadMembershipPage<SavedBroadIdentity>>.Success(BroadPage(read, BroadMembershipPageKind.Sources, read.Sources, after, link: null));
    }
    public Result<SavedBroadMembershipPage<SavedBroadMembershipLink>> ReadBroadMembershipLinks(FindingReference reference, BroadMembershipMark? after)
    {
        var selected = ReadBroadSelection(reference);
        if (!selected.IsSuccess) return Result<SavedBroadMembershipPage<SavedBroadMembershipLink>>.Failure(selected.Error);
        var read = ReadBroadProof(selected.Value, BroadMembershipPageKind.Links, after?.Offset ?? 0, linkPosition: -1, wanted: null);
        var identities = BroadIdentities(selected.Value, read, BroadMembershipPageKind.Links, after?.Offset ?? 0, -1);
        var rows = read.Links.Select(header => new SavedBroadMembershipRow<SavedBroadMembershipLink>(header.Position, BroadLink(header, identities))).ToArray();
        return Result<SavedBroadMembershipPage<SavedBroadMembershipLink>>.Success(BroadPage(read, BroadMembershipPageKind.Links, rows, after, link: null));
    }
    public Result<SavedBroadMembershipPage<SavedBroadMembershipWitness>> ReadBroadMembershipValues(FindingReference reference, long linkPosition, BroadMembershipMark? after)
    {
        var selected = ReadBroadSelection(reference);
        if (!selected.IsSuccess) return Result<SavedBroadMembershipPage<SavedBroadMembershipWitness>>.Failure(selected.Error);
        if (linkPosition < 0) throw BroadInvalid();
        var read = ReadBroadProof(selected.Value, BroadMembershipPageKind.Values, after?.Offset ?? 0, linkPosition, wanted: null);
        if (read.Links.Count != 1) throw BroadInvalid();
        var identities = BroadIdentities(selected.Value, read, BroadMembershipPageKind.Values, after?.Offset ?? 0, linkPosition);
        var link = BroadLink(read.Links[0], identities);
        var rows = read.Values.Select(value =>
        {
            var source = value.Attribute == "member" ? link.ContainingGroup : link.RecordedThrough;
            var destination = value.Attribute == "member" ? link.RecordedThrough : link.ContainingGroup;
            if (value.Source != source.ObjectGuid || !string.Equals(value.Value, destination.DistinguishedName, StringComparison.OrdinalIgnoreCase)) throw BroadInvalid();
            return new SavedBroadMembershipRow<SavedBroadMembershipWitness>(value.Position, new(source, value.Attribute, value.Ordinal, value.Value));
        }).ToArray();
        return Result<SavedBroadMembershipPage<SavedBroadMembershipWitness>>.Success(BroadPage(read, BroadMembershipPageKind.Values, rows, after, link));
    }
    public Result<SavedBroadMembershipPage<AdministrativeMembershipLimitation>> ReadBroadMembershipLimitations(FindingReference reference, BroadMembershipMark? after)
    {
        var selected = ReadBroadSelection(reference);
        if (!selected.IsSuccess) return Result<SavedBroadMembershipPage<AdministrativeMembershipLimitation>>.Failure(selected.Error);
        var read = ReadBroadProof(selected.Value, BroadMembershipPageKind.Limitations, after?.Offset ?? 0, linkPosition: -1, wanted: null);
        return Result<SavedBroadMembershipPage<AdministrativeMembershipLimitation>>.Success(BroadPage(read, BroadMembershipPageKind.Limitations, read.Limitations, after, link: null));
    }

    private Result<FindingListItem> ReadBroadSelection(FindingReference reference)
    {
        var selected = ReadSelectedFindingCore(reference, false, "");
        return !selected.IsSuccess || selected.Value.RuleId is "SEC-061" or "SEC-062" ? selected
            : Result<FindingListItem>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged", ErrorSeverity.Failed,
                SavedBroadMembershipContext.InvalidDetails, BundleDirectory));
    }
    private BroadMembershipProjectionResult ReadBroadProof(FindingListItem finding, BroadMembershipPageKind kind, long offset,
        long linkPosition, IReadOnlySet<Guid>? wanted)
    {
        _readCancellation.ThrowIfCancellationRequested();
        if (offset < 0) throw BroadInvalid();
        OpenPart(StoreSegmentRole.PermissionProof);
        var reference = finding.Reference!.Value;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,typeof(proof),fingerprint FROM finding_broad_group_membership WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetValue(0) is not string generation || generation != reference.GenerationId.ToString("D")
                || row.GetString(1) != "text" || row.GetValue(2) is not byte[] { Length: 32 }) throw BroadInvalid();
        }
        _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        if (_findingDerivationSeal is null) throw BroadInvalid();
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_broad_group_membership", "proof", reference.FindingId, readOnly: true);
        return BroadMembershipProjection.Read(proof, finding, Description, _findingDerivationSeal, kind, offset, linkPosition, wanted, _readCancellation);
    }
    private IReadOnlyDictionary<Guid, SavedBroadMembershipIdentity> BroadIdentities(FindingListItem finding,
        BroadMembershipProjectionResult first, BroadMembershipPageKind kind, long offset, long link)
    {
        var wanted = first.Links.SelectMany(header => new[] { header.Group, header.Member, header.Reference }).ToHashSet();
        var second = ReadBroadProof(finding, kind, offset, link, wanted);
        if (second.Context != first.Context || wanted.Any(guid => !second.Identities.ContainsKey(guid))) throw BroadInvalid();
        return second.Identities;
    }
    private static SavedBroadMembershipLink BroadLink(BroadMembershipLinkHeader header, IReadOnlyDictionary<Guid, SavedBroadMembershipIdentity> identities)
    {
        var group = identities[header.Group]; var member = identities[header.Member]; var reference = identities[header.Reference];
        if (group.ObjectClass != "group" || !string.Equals(member.Sid, reference.Sid, StringComparison.OrdinalIgnoreCase)
            || member.ObjectGuid != reference.ObjectGuid && (reference.ObjectClass != "foreignSecurityPrincipal" || member.ObjectClass != "group"
                || !string.Equals(reference.DomainFqdn, group.DomainFqdn, StringComparison.OrdinalIgnoreCase)
                || SecureAD.Kernel.Security.Sid.IsBuiltinDomain(member.Sid)
                    && !string.Equals(reference.DomainFqdn, member.DomainFqdn, StringComparison.OrdinalIgnoreCase))) throw BroadInvalid();
        return new(header.Position, group, member, reference, header.Witnesses);
    }
    private static SavedBroadMembershipPage<T> BroadPage<T>(BroadMembershipProjectionResult read, BroadMembershipPageKind kind,
        IReadOnlyList<SavedBroadMembershipRow<T>> rows, BroadMembershipMark? after, SavedBroadMembershipLink? link)
    {
        var total = kind switch { BroadMembershipPageKind.Sources => read.Context.SourceCount, BroadMembershipPageKind.Links => read.Context.LinkCount,
            BroadMembershipPageKind.Values => link!.WitnessCount, _ => read.Context.LimitationCount };
        var start = after?.Offset ?? 0;
        BroadMembershipMark? next = start + rows.Count < total
            ? new(read.Context.Reference.GenerationId, read.Context.Reference.FindingId, read.Context.Target.ObjectGuid, kind, link?.Position ?? -1, start + rows.Count) : null;
        var page = new SavedBroadMembershipPage<T>(read.Context, kind, link, rows, next);
        if (!page.IsExpectedPage(after)) throw BroadInvalid();
        return page;
    }
    private static InvalidDataException BroadInvalid() => new(SavedBroadMembershipContext.InvalidDetails);
}
