using System.IO;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>Read-only access to one captured lifetime; it cannot create, select or dispose a run.</summary>
internal sealed partial class AssetReadRequest(
    OpenedRunResults? session, Func<bool> isSelected, CancellationToken cancellationToken) : IAssetReader
{
    private readonly CancellationToken _readCancellation = cancellationToken;

    /// <inheritdoc/>
    public Func<bool> CaptureReadValidity() => () => session is not null && isSelected() && session.IsCurrent;

    /// <inheritdoc/>
    public Result<ObjectSearchPage> SearchObjects(string bundleDirectory, string search, ObjectSearchMark? after) =>
        WithRun(bundleDirectory, run => run.ReadNavigation(reader => reader.SearchObjects(search, after, _readCancellation), _readCancellation));

    /// <inheritdoc/>
    public Result<DelegationPrincipalPage> FindDelegationPrincipals(string bundleDirectory, string search, DelegationPrincipalMark? after) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.FindDelegationPrincipals(search, after, _readCancellation), _readCancellation));

    /// <inheritdoc/>
    public Result<DelegationPage> ReadDelegations(string bundleDirectory, DelegationQuery query, DelegationPageMark? after) =>
        WithRun(bundleDirectory, run => run.ReadDelegations(query, after, _readCancellation));

    /// <inheritdoc/>
    public Result<SavedPermissionClassification> ReadPermissionClassification(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, run => run.ReadPermissionClassification(distinguishedName, _readCancellation));

    /// <inheritdoc/>
    public Result<ControlEdgePage> ReadControlEdges(string bundleDirectory, string? target, string? holderSid,
        string? holderScope, bool includeExpected, long afterId) =>
        ReadProduct(bundleDirectory, reader => reader.ReadControlEdges(target, holderSid, holderScope, includeExpected, afterId),
            "ControlEdgesUnreadable", "Stored control edges could not be read:");

    /// <inheritdoc/>
    public Result<SelfMembershipAssessmentSet> ReadSelfMembershipAssessments(string bundleDirectory, string? target, string? requester) =>
        ReadProduct(bundleDirectory, reader => reader.ReadSelfMembershipAssessments(target, requester),
            "SelfMembershipAssessmentsUnreadable", "Stored Self-Membership requester assessments could not be read:");

    /// <inheritdoc/>
    public Result<MemberAttributionDetail> ReadMemberAttribution(string bundleDirectory, string holderSid, string? holderScope, string target) =>
        ReadMemberProduct(bundleDirectory, reader => reader.ReadMemberAttribution(holderSid, holderScope, target));

    /// <inheritdoc/>
    public Result<MemberPermissionPage> ReadPermissionsThroughMembership(string bundleDirectory, string memberSid, string? memberScope, bool includeExpected, long afterId) =>
        ReadMemberProduct(bundleDirectory, reader => reader.ReadPermissionsThroughMembership(memberSid, memberScope, includeExpected, afterId));

    private Result<T> ReadMemberProduct<T>(string bundleDirectory, Func<JudgementReader, T> read) =>
        ReadProduct(bundleDirectory, read, "MemberAttributionUnreadable",
            new System.Resources.ResourceManager("SecureAD.Shell.Resources.MemberAttributionPresentation", typeof(AssetReadRequest).Assembly)
                .GetString("InvalidEvidence", System.Globalization.CultureInfo.CurrentUICulture)
                ?? throw new System.Resources.MissingManifestResourceException("InvalidEvidence"));

    private Result<T> ReadProduct<T>(string bundleDirectory, Func<JudgementReader, T> read, string code, string message,
        bool lightweight = false)
    {
        Result<T> Read(JudgementReader reader)
        {
            try { return Result<T>.Success(read(reader)); }
            catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
                or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException or System.Text.Json.JsonException or ArgumentException)
            {
                return Result<T>.Failure(AuditError.Create(ErrorCategory.Shell, code, ErrorSeverity.Failed,
                    message + " " + error.Message, bundleDirectory));
            }
        }
        return Flatten(WithRun(bundleDirectory, run => lightweight
            ? run.ReadFindings(Read, _readCancellation)
            : run.ReadJudgement(Read, _readCancellation)));
    }

    /// <inheritdoc/>
    public Result<DirectoryTree> ReadTree(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadNavigation(reader => reader.ReadTree(), _readCancellation));

    public Result<GroupInventoryPage> ReadGroups(string bundleDirectory, GroupInventoryQuery query, GroupInventoryMark? after) =>
        WithRun(bundleDirectory, run => run.ReadFindings(reader => reader.ReadGroupInventory(query, after, _readCancellation), _readCancellation));

    public Result<CapturedMemberReferences> ResolveMembershipReferences(string bundleDirectory, IReadOnlyList<string> names) =>
        WithRun(bundleDirectory, run => run.ReadNavigation(reader => reader.ResolveMembershipReferences(names, _readCancellation), _readCancellation));

    public Result<ObjectPage> ListObjects(string bundleDirectory, string containerDn, ListingScope scope, ObjectPageMark? after) =>
        WithRun(bundleDirectory, run => run.ReadNavigation(reader => reader.ListObjects(containerDn, scope, after, _readCancellation), _readCancellation));

    public Result<CapturedObjectIdentity?> ReadObjectIdentity(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, run => run.ReadNavigation(reader => reader.ReadObjectIdentity(distinguishedName), _readCancellation));

    public Result<CapturedMembershipPage?> ReadCapturedMembership(string bundleDirectory, string distinguishedName,
        bool parents, CapturedMembershipMark? after) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader =>
            reader.ReadCapturedMembership(distinguishedName, parents, after, _readCancellation), _readCancellation));

    public Result<ObjectAttributes?> ReadObjectAttributes(string bundleDirectory, string distinguishedName,
        IReadOnlyCollection<string> attributes) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader =>
            reader.ReadObjectAttributes(distinguishedName, attributes), _readCancellation));

    /// <inheritdoc/>
    public Result<LapsPage> ListLapsComputers(string bundleDirectory, LapsQuery query, LapsPageMark? after) =>
        WithRun(bundleDirectory, run => run.ReadLapsComputers(query, after, _readCancellation));

    /// <inheritdoc/>
    public Result<ObjectPermissions?> ReadPermissions(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadPermissions(distinguishedName), _readCancellation));

    /// <inheritdoc/>
    public Result<ObjectAttributes?> ReadObjectAttributes(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadObjectAttributes(distinguishedName), _readCancellation));

    /// <inheritdoc/>
    public Result<ForestInventory> ReadInventory(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadOverview(reader => reader.ReadInventory(), _readCancellation));

    /// <inheritdoc/>
    public Result<int?> ReadGroupsWithUnidentifiedMembers(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadGroupsWithUnidentifiedMembers(_readCancellation));

    /// <inheritdoc/>
    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadSchemaGuids(_readCancellation));

    /// <inheritdoc/>
    public Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        return Flatten(WithRun(bundleDirectory, run => run.ReadFindings(reader =>
        {
            if (query.After is { } mark && mark.GenerationId != reader.Description.GenerationId)
                return Changed<FindingsPage>(bundleDirectory);
            var page = reader.ReadPage(query);
            return page.IsSuccess
                ? Result<FindingsPage>.Success(page.Value with
                { Next = page.Value.Next is { } next ? next with { GenerationId = reader.Description.GenerationId } : null })
                : page;
        }, _readCancellation)));
    }

    public Result<FindingListPage> ReadFindingsList(string bundleDirectory, FindingsQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        return Flatten(WithRun(bundleDirectory, run => run.ReadFindings(reader =>
        {
            if (query.After is { } mark && mark.GenerationId != reader.Description.GenerationId)
                return Changed<FindingListPage>(bundleDirectory);
            return reader.ReadListPage(query);
        }, _readCancellation)));
    }

    /// <inheritdoc/>
    public Result<StoredRuleExecutions> ReadRuleExecutions(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadFindings(reader => reader.ReadRuleExecutions(), _readCancellation));

    /// <inheritdoc/>
    public Result<FindingsFilterValues> ReadFindingsFilterValues(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadFindings(reader => reader.ReadFilterValues(), _readCancellation));

    private Result<T> WithRun<T>(string bundleDirectory, Func<OpenedRunResults, Result<T>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        _readCancellation.ThrowIfCancellationRequested();
        var path = Path.GetFullPath(bundleDirectory);
        if (session is null || !isSelected()
            || !string.Equals(session.Directory, path, StringComparison.OrdinalIgnoreCase)) return Changed<T>(path);
        var result = read(session);
        _readCancellation.ThrowIfCancellationRequested();
        return isSelected() ? result : Changed<T>(path);
    }

    private static Result<T> Flatten<T>(Result<Result<T>> read) =>
        read.IsSuccess ? read.Value : Result<T>.Failure(read.Error);

    private static Result<T> Changed<T>(string directory) => Result<T>.Failure(AuditError.Create(
        ErrorCategory.Shell, "SavedResultsGenerationChanged", ErrorSeverity.Failed, SavedPathText.Get("GenerationChanged"), directory));
}
