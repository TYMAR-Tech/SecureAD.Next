using System.IO;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;

namespace SecureAD.Shell.Services;

/// <summary>
/// The asset source, over real bundles on a real disk.
/// </summary>
/// <remarks>
/// <para>
/// <b>It keeps the bundle it was last asked about open.</b> The seal is verified once, when the
/// operator arrives at a run, rather than on every page turned - see <see cref="IAssetSource"/>
/// for why that matters. Moving to another run closes the previous bundle before opening the next,
/// so at most one is held and an operator can always move, copy or delete every run but the one on
/// screen.
/// </para>
/// <para>
/// <b>Verification is not skipped, only not repeated.</b> The bundle is opened with SQLite told the
/// file is immutable, which it is: the seal has just proved so, and nothing in this product writes
/// to sealed evidence.
/// </para>
/// </remarks>
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

    private BundleReader? _open;

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
    private string? _openPath;

    /// <summary>
    /// The open bundle's schema catalogue, built on first use and dropped with the bundle.
    /// </summary>
    /// <remarks>
    /// Cached because reading it walks every schema definition in the forest, and unlike the seal
    /// there is nothing dangerous about not repeating it: the bundle is immutable, so the answer
    /// cannot change while it is open.
    /// </remarks>
    private SchemaGuidCatalog? _schema;

    /// <inheritdoc/>
    public Result<DirectoryTree> ReadTree(string bundleDirectory)
    {
        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(() => opened.Value.ReadTree(), bundleDirectory)
            : Result<DirectoryTree>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<ObjectPage> ListObjects(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(
                () => opened.Value.ListObjects(containerDn, scope, pageNumber), bundleDirectory)
            : Result<ObjectPage>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<LapsPage> ListLapsComputers(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(
                () => opened.Value.ListLapsComputers(containerDn, scope, pageNumber),
                bundleDirectory)
            : Result<LapsPage>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<ObjectPermissions?> ReadPermissions(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(() => opened.Value.ReadPermissions(distinguishedName), bundleDirectory)
            : Result<ObjectPermissions?>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<ObjectAttributes?> ReadObjectAttributes(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(() => opened.Value.ReadObjectAttributes(distinguishedName), bundleDirectory)
            : Result<ObjectAttributes?>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Not cached, unlike <see cref="ReadSchemaGuids"/>. The schema is read once because walking
    /// every definition in the forest is expensive; counting is one grouped scan, and a cache here
    /// would buy little while adding a second place the dashboard's numbers could come from.
    /// </remarks>
    public Result<ForestInventory> ReadInventory(string bundleDirectory)
    {
        var opened = Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<ForestInventory>.Failure(opened.Error);

        // The reader already returns a Result, because a run whose coverage cannot be established
        // has no counts rather than empty ones. Guarded wraps a second one around it for the I/O
        // case, and the inner refusal is the one worth showing an operator.
        var guarded = Guarded(() => opened.Value.ReadInventory(), bundleDirectory);

        return guarded.IsSuccess
            ? guarded.Value
            : Result<ForestInventory>.Failure(guarded.Error);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Opened and closed per call rather than held like the evidence, for the reason the judgement
    /// reads give: a derivation is rewritten whenever an operator re-derives, and a held handle
    /// would answer from the store that existed when the screen was opened.
    /// </remarks>
    public Result<int?> ReadGroupsWithUnidentifiedMembers(string bundleDirectory)
    {
        var opened = DerivationReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<int?>.Failure(opened.Error);

        using var reader = opened.Value;

        try
        {
            return Result<int?>.Success(reader.GroupsWithUnidentifiedMembers());
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            return Result<int?>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "DerivationCannotBeRead",
                ErrorSeverity.Failed,
                $"The derivation in '{bundleDirectory}' was opened and could not be read. "
                + error.Message,
                bundleDirectory));
        }
    }

    /// <inheritdoc/>
    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory)
    {
        var opened = Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<SchemaGuidCatalog>.Failure(opened.Error);

        if (_schema is not null)
            return Result<SchemaGuidCatalog>.Success(_schema);

        var read = Guarded(() => opened.Value.ReadSchemaGuids(), bundleDirectory);

        if (read.IsSuccess)
            _schema = read.Value;

        return read;
    }

    /// <inheritdoc/>
    public Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(query);

        // Opened and closed per page rather than held like the evidence. A judgement is rewritten
        // whenever a bundle is judged again, and a reader kept open across that would go on
        // answering from the file that was replaced. It is also small: the evidence is held open
        // because verifying its seal re-reads gigabytes, and that reason does not apply here.
        var opened = JudgementReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<FindingsPage>.Failure(opened.Error);

        try
        {
            using var reader = opened.Value!;
            return reader.ReadPage(query);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<FindingsPage>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "JudgementCannotBeRead",
                ErrorSeverity.Failed,
                $"The judgement in '{bundleDirectory}' was opened and could not be read. "
                + $"{ex.Message}",
                bundleDirectory));
        }
    }

    /// <inheritdoc/>
    public Result<StoredRuleExecutions> ReadRuleExecutions(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var opened = JudgementReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<StoredRuleExecutions>.Failure(opened.Error);

        try
        {
            using var reader = opened.Value!;
            return Result<StoredRuleExecutions>.Success(reader.ReadRuleExecutions());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<StoredRuleExecutions>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "JudgementCannotBeRead",
                ErrorSeverity.Failed,
                $"The judgement in '{bundleDirectory}' was opened and could not be read. "
                + $"{ex.Message}",
                bundleDirectory));
        }
    }

    /// <inheritdoc/>
    public Result<FindingsFilterValues> ReadFindingsFilterValues(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var opened = JudgementReader.Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<FindingsFilterValues>.Failure(opened.Error);

        try
        {
            using var reader = opened.Value!;
            return Result<FindingsFilterValues>.Success(reader.ReadFilterValues());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<FindingsFilterValues>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "JudgementCannotBeRead",
                ErrorSeverity.Failed,
                $"The judgement in '{bundleDirectory}' was opened and could not be read. "
                + $"{ex.Message}",
                bundleDirectory));
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _open?.Dispose();
        _open = null;
        _openPath = null;
        _schema = null;
    }

    private Result<BundleReader> Open(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        if (_open is not null
            && string.Equals(_openPath, bundleDirectory, StringComparison.OrdinalIgnoreCase))
        {
            return _open;
        }

        Dispose();

        var opening = BundleReader.Open(bundleDirectory);
        if (!opening.IsSuccess)
            return opening;

        _open = opening.Value;
        _openPath = bundleDirectory;
        return opening;
    }

    /// <summary>
    /// Turns a failure to read an opened bundle into a refusal the shell can state.
    /// </summary>
    /// <remarks>
    /// The seal was intact, so the bytes are the bytes that were sealed. A failure here is a defect
    /// in this build rather than damage to the bundle, and it is worded as one.
    /// </remarks>
    private static Result<T> Guarded<T>(Func<T> read, string bundleDirectory)
    {
        try
        {
            return Result<T>.Success(read());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<T>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "BundleCannotBeRead",
                ErrorSeverity.Failed,
                $"'{bundleDirectory}' was opened and could not be read. {ex.Message}",
                bundleDirectory));
        }
    }
}
