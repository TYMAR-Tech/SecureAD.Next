using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    public Result<SavedServiceAccountDetails> ReadServiceAccount(FindingReference reference)
    {
        var selected = ReadServiceSelection(reference);
        if (!selected.IsSuccess) return Result<SavedServiceAccountDetails>.Failure(selected.Error);
        var kind = selected.Value.RuleId == "SEC-100" ? ServiceAccountPageKind.EntryMemberships : (ServiceAccountPageKind?)null;
        var read = ReadServiceProof(selected.Value, kind, 0, linkPosition: -1, wanted: null);
        var entries = kind is not null ? ServiceLinksPage(selected.Value, read, kind.Value, null) : null;
        return Result<SavedServiceAccountDetails>.Success(new(read.Context, entries));
    }
    public Result<SavedServiceAccountPage<SavedServiceAccountName>> ReadServiceAccountNames(FindingReference reference, ServiceAccountMark? after)
    {
        var selected = ReadServiceSelection(reference);
        if (!selected.IsSuccess) return Result<SavedServiceAccountPage<SavedServiceAccountName>>.Failure(selected.Error);
        var read = ReadServiceProof(selected.Value, ServiceAccountPageKind.Names, after?.Offset ?? 0, linkPosition: -1, wanted: null);
        return Result<SavedServiceAccountPage<SavedServiceAccountName>>.Success(ServicePage(read.Context, ServiceAccountPageKind.Names, read.Names, after, link: null));
    }
    public Result<SavedServiceAccountPage<SavedServiceAccountLink>> ReadServiceAccountEntryMemberships(FindingReference reference, ServiceAccountMark? after) =>
        ReadServiceLinks(reference, ServiceAccountPageKind.EntryMemberships, after);
    public Result<SavedServiceAccountPage<SavedServiceAccountLink>> ReadServiceAccountLinks(FindingReference reference, ServiceAccountMark? after) =>
        ReadServiceLinks(reference, ServiceAccountPageKind.Links, after);
    private Result<SavedServiceAccountPage<SavedServiceAccountLink>> ReadServiceLinks(FindingReference reference, ServiceAccountPageKind kind, ServiceAccountMark? after)
    {
        var selected = ReadServiceSelection(reference, administrative: true);
        if (!selected.IsSuccess) return Result<SavedServiceAccountPage<SavedServiceAccountLink>>.Failure(selected.Error);
        var read = ReadServiceProof(selected.Value, kind, after?.Offset ?? 0, linkPosition: -1, wanted: null);
        return Result<SavedServiceAccountPage<SavedServiceAccountLink>>.Success(ServiceLinksPage(selected.Value, read, kind, after));
    }
    public Result<SavedServiceAccountPage<SavedServiceAccountWitness>> ReadServiceAccountValues(FindingReference reference, long linkPosition, ServiceAccountMark? after)
    {
        var selected = ReadServiceSelection(reference, administrative: true);
        if (!selected.IsSuccess) return Result<SavedServiceAccountPage<SavedServiceAccountWitness>>.Failure(selected.Error);
        if (linkPosition < 0) throw ServiceAccountInvalid();
        var read = ReadServiceProof(selected.Value, ServiceAccountPageKind.Values, after?.Offset ?? 0, linkPosition, wanted: null);
        if (read.Links.Count != 1) throw ServiceAccountInvalid();
        var identities = ServiceAccountIdentities(selected.Value, read, ServiceAccountPageKind.Values, after?.Offset ?? 0, linkPosition);
        var link = ServiceAccountLink(read.Links[0], identities);
        var rows = read.Values.Select(value =>
        {
            if (!identities.TryGetValue(value.Source, out var source)) throw ServiceAccountInvalid();
            return new SavedServiceAccountRow<SavedServiceAccountWitness>(value.Position, new(source, value.Attribute, value.Ordinal, value.Value));
        }).ToArray();
        return Result<SavedServiceAccountPage<SavedServiceAccountWitness>>.Success(ServicePage(read.Context, ServiceAccountPageKind.Values, rows, after, link));
    }
    public Result<SavedServiceAccountPage<AdministrativeMembershipLimitation>> ReadServiceAccountLimitations(FindingReference reference, ServiceAccountMark? after)
    {
        var selected = ReadServiceSelection(reference, administrative: true);
        if (!selected.IsSuccess) return Result<SavedServiceAccountPage<AdministrativeMembershipLimitation>>.Failure(selected.Error);
        var read = ReadServiceProof(selected.Value, ServiceAccountPageKind.Limitations, after?.Offset ?? 0, linkPosition: -1, wanted: null);
        return Result<SavedServiceAccountPage<AdministrativeMembershipLimitation>>.Success(
            ServicePage(read.Context, ServiceAccountPageKind.Limitations, read.Limitations, after, link: null));
    }
    private Result<FindingListItem> ReadServiceSelection(FindingReference reference, bool administrative = false)
    {
        var selected = ReadSelectedFindingCore(reference, false, "");
        return !selected.IsSuccess || (administrative ? selected.Value.RuleId == "SEC-100" : selected.Value.RuleId is "SEC-100" or "SEC-101")
            ? selected : Result<FindingListItem>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged", ErrorSeverity.Failed,
                SavedServiceAccountContext.InvalidDetails, BundleDirectory));
    }
    private ServiceAccountProjectionResult ReadServiceProof(FindingListItem finding, ServiceAccountPageKind? kind, long offset,
        long linkPosition, IReadOnlySet<Guid>? wanted)
    {
        _readCancellation.ThrowIfCancellationRequested();
        if (offset < 0) throw ServiceAccountInvalid();
        OpenPart(StoreSegmentRole.PermissionProof);
        var reference = finding.Reference!.Value;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,typeof(proof),fingerprint FROM finding_service_account WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetValue(0) is not string generation || generation != reference.GenerationId.ToString("D")
                || row.GetString(1) != "text" || row.GetValue(2) is not byte[] { Length: 32 }) throw ServiceAccountInvalid();
        }
        if (finding.RuleId == "SEC-100")
        {
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            if (_findingDerivationSeal is null) throw ServiceAccountInvalid();
        }
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_service_account", "proof", reference.FindingId, readOnly: true);
        return ServiceAccountProjection.Read(proof, finding, Description, _findingDerivationSeal, kind, offset, linkPosition, wanted, _readCancellation);
    }
    private SavedServiceAccountPage<SavedServiceAccountLink> ServiceLinksPage(FindingListItem finding,
        ServiceAccountProjectionResult read, ServiceAccountPageKind kind, ServiceAccountMark? after)
    {
        var identities = ServiceAccountIdentities(finding, read, kind, after?.Offset ?? 0, -1);
        var rows = read.Links.Select(header =>
            new SavedServiceAccountRow<SavedServiceAccountLink>(header.PagePosition, ServiceAccountLink(header, identities))).ToArray();
        return ServicePage(read.Context, kind, rows, after, link: null);
    }
    private IReadOnlyDictionary<Guid, SavedServiceAccountIdentity> ServiceAccountIdentities(FindingListItem finding,
        ServiceAccountProjectionResult first, ServiceAccountPageKind kind, long offset, long link)
    {
        var wanted = first.Links.SelectMany(header => new[] { header.Group, header.Member, header.Reference }).ToHashSet();
        var second = ReadServiceProof(finding, kind, offset, link, wanted);
        if (second.Context != first.Context || wanted.Any(guid => !second.Identities.ContainsKey(guid))) throw ServiceAccountInvalid();
        return second.Identities;
    }
    private static SavedServiceAccountLink ServiceAccountLink(ServiceAccountLinkHeader header, IReadOnlyDictionary<Guid, SavedServiceAccountIdentity> identities) =>
        new(header.Position, identities[header.Group], identities[header.Member], identities[header.Reference], header.Witnesses, header.IsPrimaryGroup);
    private static SavedServiceAccountPage<T> ServicePage<T>(SavedServiceAccountContext context, ServiceAccountPageKind kind,
        IReadOnlyList<SavedServiceAccountRow<T>> rows, ServiceAccountMark? after, SavedServiceAccountLink? link)
    {
        var total = kind switch
        {
            ServiceAccountPageKind.Names => context.Account.ServiceNameCount,
            ServiceAccountPageKind.EntryMemberships => context.EntryMembershipCount,
            ServiceAccountPageKind.Links => context.LinkCount,
            ServiceAccountPageKind.Values => link!.WitnessCount,
            _ => context.LimitationCount,
        };
        var start = after?.Offset ?? 0;
        ServiceAccountMark? next = start + rows.Count < total
            ? new(context.Reference.GenerationId, context.Reference.FindingId, context.Account.ObjectGuid, context.Target?.ObjectGuid,
                kind, link?.Position ?? -1, start + rows.Count) : null;
        var page = new SavedServiceAccountPage<T>(context, kind, link, rows, next);
        if (!page.IsExpectedPage(after)) throw ServiceAccountInvalid();
        return page;
    }
    private static InvalidDataException ServiceAccountInvalid() => new(SavedServiceAccountContext.InvalidDetails);
}
