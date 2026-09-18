using System.IO;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>
/// The asset source, over real bundles on a real disk.
/// </summary>
/// <remarks>Evidence and findings share the selected run's protected files, not a shared query connection.</remarks>
internal sealed partial class BundleAssetSource : IAssetSource, IDisposable
{
    /// <inheritdoc/>
    public Result<ControlEdgePage> ReadControlEdges(string bundleDirectory, string? target, string? holderSid,
        string? holderScope, bool includeExpected, long afterId)
    {
        var opened = JudgementReader.Open(bundleDirectory);
        if (!opened.IsSuccess) return Result<ControlEdgePage>.Failure(opened.Error);
        using var reader = opened.Value;
        try
        {
            return Result<ControlEdgePage>.Success(reader.ReadControlEdges(target, holderSid, holderScope, includeExpected, afterId));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            return Result<ControlEdgePage>.Failure(AuditError.Create(ErrorCategory.Shell, "ControlEdgesUnreadable",
                ErrorSeverity.Failed, "Stored control edges could not be read: " + error.Message, bundleDirectory));
        }
    }

    /// <inheritdoc/>
    public Result<SelfMembershipAssessmentSet> ReadSelfMembershipAssessments(string bundleDirectory, string? target, string? requester)
    {
        var opened = JudgementReader.Open(bundleDirectory);
        if (!opened.IsSuccess) return Result<SelfMembershipAssessmentSet>.Failure(opened.Error);
        using var reader = opened.Value;
        try
        {
            return Result<SelfMembershipAssessmentSet>.Success(reader.ReadSelfMembershipAssessments(target, requester));
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            return Result<SelfMembershipAssessmentSet>.Failure(AuditError.Create(ErrorCategory.Shell, "SelfMembershipAssessmentsUnreadable",
                ErrorSeverity.Failed, "Stored Self-Membership requester assessments could not be read: " + error.Message, bundleDirectory));
        }
    }

    private readonly object _sessionGate = new();
    private OpenedRunResults? _results;
    private bool _closed;

    /// <inheritdoc/>
    public Result<MemberAttributionDetail> ReadMemberAttribution(string bundleDirectory, string holderSid, string? holderScope, string target) =>
        ReadMemberProduct(bundleDirectory, reader => reader.ReadMemberAttribution(holderSid, holderScope, target));

    /// <inheritdoc/>
    public Result<MemberPermissionPage> ReadPermissionsThroughMembership(string bundleDirectory, string memberSid, string? memberScope, bool includeExpected, long afterId) =>
        ReadMemberProduct(bundleDirectory, reader => reader.ReadPermissionsThroughMembership(memberSid, memberScope, includeExpected, afterId));

    private static Result<T> ReadMemberProduct<T>(string bundleDirectory, Func<JudgementReader, T> read)
    {
        var opened = JudgementReader.Open(bundleDirectory);
        if (!opened.IsSuccess) return Result<T>.Failure(opened.Error);
        using var reader = opened.Value;
        try { return Result<T>.Success(read(reader)); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException
            or Microsoft.Data.Sqlite.SqliteException or System.Text.Json.JsonException or ArgumentException)
        {
            return Result<T>.Failure(AuditError.Create(ErrorCategory.Shell, "MemberAttributionUnreadable", ErrorSeverity.Failed,
                (new System.Resources.ResourceManager("SecureAD.Shell.Resources.MemberAttributionPresentation", typeof(BundleAssetSource).Assembly)
                    .GetString("InvalidEvidence", System.Globalization.CultureInfo.CurrentUICulture)
                    ?? throw new System.Resources.MissingManifestResourceException("InvalidEvidence")) + " " + error.Message, bundleDirectory));
        }
    }
    /// <inheritdoc/>
    public Result<DirectoryTree> ReadTree(string bundleDirectory)
    {
        return WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadTree()));
    }

    /// <inheritdoc/>
    public Result<ObjectPage> ListObjects(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);

        return WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ListObjects(containerDn, scope, pageNumber)));
    }

    /// <inheritdoc/>
    public Result<LapsPage> ListLapsComputers(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);

        return WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ListLapsComputers(containerDn, scope, pageNumber)));
    }

    /// <inheritdoc/>
    public Result<ObjectPermissions?> ReadPermissions(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        return WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadPermissions(distinguishedName)));
    }

    /// <inheritdoc/>
    public Result<ObjectAttributes?> ReadObjectAttributes(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        return WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadObjectAttributes(distinguishedName)));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Not cached, unlike <see cref="ReadSchemaGuids"/>. The schema is read once because walking
    /// every definition in the forest is expensive; counting is one grouped scan, and a cache here
    /// would buy little while adding a second place the dashboard's numbers could come from.
    /// </remarks>
    public Result<ForestInventory> ReadInventory(string bundleDirectory)
    {
        return Flatten(WithRun(bundleDirectory, run => run.ReadEvidence(reader => reader.ReadInventory())));
    }

    /// <inheritdoc/>
    public Result<int?> ReadGroupsWithUnidentifiedMembers(string bundleDirectory)
    {
        return WithRun(bundleDirectory, run => run.ReadDerivation(reader => reader.GroupsWithUnidentifiedMembers()));
    }

    /// <inheritdoc/>
    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory)
    {
        return WithRun(bundleDirectory, run => run.ReadSchemaGuids());
    }

    /// <inheritdoc/>
    public Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
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
        })));
    }

    /// <inheritdoc/>
    public Result<StoredRuleExecutions> ReadRuleExecutions(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        return WithRun(bundleDirectory, run => run.ReadJudgement(reader => reader.ReadRuleExecutions()));
    }

    /// <inheritdoc/>
    public Result<FindingsFilterValues> ReadFindingsFilterValues(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        return WithRun(bundleDirectory, run => run.ReadJudgement(reader => reader.ReadFilterValues()));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        OpenedRunResults? previous;
        lock (_sessionGate) { previous = _results; _results = null; _closed = true; }
        previous?.Dispose();
    }

    /// <inheritdoc/>
    public void CloseRun() => Dispose();

    /// <inheritdoc/>
    public void SelectRun(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        var path = Path.GetFullPath(bundleDirectory);
        OpenedRunResults? previous;
        lock (_sessionGate)
        {
            if (_results is { } current && string.Equals(current.Directory, path, StringComparison.OrdinalIgnoreCase)
                && current.IsCurrent) return;
            previous = _results;
            _results = new OpenedRunResults(path);
            _closed = false;
        }
        previous?.Dispose();
    }

    private Result<T> WithRun<T>(string bundleDirectory, Func<OpenedRunResults, Result<T>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        var path = Path.GetFullPath(bundleDirectory);
        OpenedRunResults session;
        lock (_sessionGate)
        {
            if (_closed) return Changed<T>(path);
            _results ??= new OpenedRunResults(path);
            session = _results;
            if (!string.Equals(session.Directory, path, StringComparison.OrdinalIgnoreCase)) return Changed<T>(path);
        }
        var result = read(session);
        lock (_sessionGate) return ReferenceEquals(_results, session) ? result : Changed<T>(path);
    }

    private static Result<T> Flatten<T>(Result<Result<T>> read) =>
        read.IsSuccess ? read.Value : Result<T>.Failure(read.Error);

    private static Result<T> Changed<T>(string directory) => Result<T>.Failure(AuditError.Create(
        ErrorCategory.Shell, "SavedResultsGenerationChanged", ErrorSeverity.Failed, SavedPathText.Get("GenerationChanged"), directory));
}
