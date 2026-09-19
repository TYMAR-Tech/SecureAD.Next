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

    private Result<T> ReadProduct<T>(string bundleDirectory, Func<JudgementReader, T> read, string code, string message) =>
        Flatten(WithRun(bundleDirectory, run => run.ReadJudgement(reader =>
        {
            try { return Result<T>.Success(read(reader)); }
            catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
                or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException or System.Text.Json.JsonException or ArgumentException)
            {
                return Result<T>.Failure(AuditError.Create(ErrorCategory.Shell, code, ErrorSeverity.Failed,
                    message + " " + error.Message, bundleDirectory));
            }
        }, _readCancellation)));

    /// <inheritdoc/>
    public Result<DirectoryTree> ReadTree(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadTree(), _readCancellation));

    /// <inheritdoc/>
    public Result<ObjectPage> ListObjects(string bundleDirectory, string containerDn, ListingScope scope, int pageNumber) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ListObjects(containerDn, scope, pageNumber), _readCancellation));

    /// <inheritdoc/>
    public Result<LapsPage> ListLapsComputers(string bundleDirectory, string containerDn, ListingScope scope, int pageNumber) =>
        WithRun(bundleDirectory, run => run.ReadLapsComputers(containerDn, scope, pageNumber, _readCancellation));

    /// <inheritdoc/>
    public Result<ObjectPermissions?> ReadPermissions(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadPermissions(distinguishedName), _readCancellation));

    /// <inheritdoc/>
    public Result<ObjectAttributes?> ReadObjectAttributes(string bundleDirectory, string distinguishedName) =>
        WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadObjectAttributes(distinguishedName), _readCancellation));

    /// <inheritdoc/>
    public Result<ForestInventory> ReadInventory(string bundleDirectory) =>
        Flatten(WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadInventory(), _readCancellation)));

    /// <inheritdoc/>
    public Result<int?> ReadGroupsWithUnidentifiedMembers(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadDerivation(reader => reader.GroupsWithUnidentifiedMembers(), _readCancellation));

    /// <inheritdoc/>
    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadSchemaGuids(_readCancellation));

    /// <inheritdoc/>
    public Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        return Flatten(WithRun(bundleDirectory, run => run.ReadJudgement(reader =>
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

    /// <inheritdoc/>
    public Result<StoredRuleExecutions> ReadRuleExecutions(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadJudgement(reader => reader.ReadRuleExecutions(), _readCancellation));

    /// <inheritdoc/>
    public Result<FindingsFilterValues> ReadFindingsFilterValues(string bundleDirectory) =>
        WithRun(bundleDirectory, run => run.ReadJudgement(reader => reader.ReadFilterValues(), _readCancellation));

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
