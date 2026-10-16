using System.IO;
using System.Diagnostics;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>Owns one selected run's protected files, never a connection shared between queries.</summary>
internal sealed partial class OpenedRunResults : IDisposable, IAsyncDisposable
{
    private readonly ProtectedRunFiles _files;
    private readonly RunProtectionSessions.Lease? _sharedProtection;
    private readonly SemaphoreSlim _gate = new(1);
    private readonly CancellationTokenSource _stopping = new();
    private readonly object _schemaGate = new();
    private SchemaGuidCatalog? _schema;
    private ProtectedStoreFile? _evidence;
    private ProtectedStoreFile? _navigation;
    private ProtectedStoreFile? _overview;
    private ProtectedStoreFile? _delegations;
    private ProtectedStoreFile? _membership;
    private ProtectedStoreFile? _derivation;
    private ProtectedStoreFile? _judgement;
    private DerivationDescription? _derived;
    private StoreRootManifest? _browseDerivation;
    private StoreRootManifest? _findingsCapture;
    private bool _disposed;
    private int _disposeRequested;

    internal OpenedRunResults(string directory) : this(directory, null) { }

    internal OpenedRunResults(string directory, RunProtectionSessions.Lease? protection)
    {
        Directory = Path.GetFullPath(directory);
        if (protection is not null
            && !string.Equals(protection.Files.Directory, Directory, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The protected lifetime belongs to another run.", nameof(protection));
        _sharedProtection = protection;
        _files = protection?.Files ?? new ProtectedRunFiles(Directory);
    }

    internal string Directory { get; }

    internal bool IsCurrent
    {
        get
        {
            if (Volatile.Read(ref _disposeRequested) != 0) return false;
            try
            {
                if (Pending() is not null) return false;
                var judgement = Volatile.Read(ref _judgement)?.Generation;
                var derivation = Volatile.Read(ref _derivation)?.Generation;
                return CaptureIsCurrent() && BrowseDerivationIsCurrent()
                    && (judgement is null || AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Judgement).Value.Hash == _judgement!.Root.Hash)
                    && (derivation is null || AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation).Value == derivation);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
        }
    }

    internal Result<SchemaGuidCatalog> ReadSchemaGuids(CancellationToken cancellationToken = default) => ReadNavigation(reader =>
    {
        lock (_schemaGate) return _schema ??= reader.ReadSchemaGuids();
    }, cancellationToken);

    internal Result<T> ReadEvidence<T>(Func<BundleReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenEvidence, (reader, _) => read(reader), _ => CaptureIsCurrent() ? null : Unavailable("GenerationChanged"), cancellationToken);

    internal Result<T> ReadNavigation<T>(Func<BundleReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenNavigation, (reader, _) => read(reader), _ => CaptureIsCurrent() ? null : Unavailable("GenerationChanged"), cancellationToken);

    internal Result<T> ReadCapturedDelegations<T>(Func<BundleReader, T> read, CancellationToken cancellationToken) =>
        Read(OpenCapturedDelegations, (reader, _) => read(reader),
            _ => CaptureIsCurrent() ? null : Unavailable("GenerationChanged"), cancellationToken);

    private Result<T> ReadMembership<T>(Func<DerivationReader, T> read, CancellationToken cancellationToken) =>
        Read(OpenMembership, (reader, _) => read(reader),
            reader => CurrentDerivation(reader.Description.GenerationId)
                ?? (!CaptureIsCurrent() || !BrowseDerivationIsCurrent() ? Unavailable("GenerationChanged") : null), cancellationToken);

    internal Result<T> ReadOverview<T>(Func<DashboardOverviewReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenOverview, (reader, _) => read(reader), _ => CaptureIsCurrent() ? null : Unavailable("GenerationChanged"), cancellationToken);

    internal Result<int?> ReadGroupsWithUnidentifiedMembers(CancellationToken cancellationToken)
    {
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stopping.Token);
        var token = stopping.Token;
        token.ThrowIfCancellationRequested();
        _gate.Wait(token);
        try
        {
            if (_disposed) return Result<int?>.Failure(Unavailable("GenerationChanged"));
            if (Pending() is { } pending) return Result<int?>.Failure(pending);
            var overview = OpenOverview(token);
            if (!overview.IsSuccess) return Result<int?>.Failure(overview.Error);
            overview.Value.Dispose();
            var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Derivation);
            if (!selected.IsSuccess) return Result<int?>.Failure(selected.Error);
            var root = selected.Value;
            if (root.Segment(StoreSegmentRole.Derivation).SchemaVersion != DerivationReader.StorageVersion
                || root.DerivationSummary is not { Version: 1 } summary
                || summary.EvidenceSeal != _overview!.Root.EvidenceSeal || root.EvidenceSeal != summary.EvidenceSeal
                || summary.GenerationId != root.GenerationId
                || summary.NestingWasDerived && summary.GroupsWithUnidentifiedMembers is not >= 0
                || !summary.NestingWasDerived && summary.GroupsWithUnidentifiedMembers is not null)
                return Result<int?>.Failure(Unavailable("InvalidEvidence"));
            if (_browseDerivation is not null && _browseDerivation.Hash != root.Hash)
                return Result<int?>.Failure(Unavailable("GenerationChanged"));
            _browseDerivation = root;
            if (!CaptureIsCurrent() || !BrowseDerivationIsCurrent())
                return Result<int?>.Failure(Unavailable("GenerationChanged"));
            token.ThrowIfCancellationRequested();
            return Result<int?>.Success(summary.GroupsWithUnidentifiedMembers);
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or SqliteException)
        {
            return Result<int?>.Failure(Unavailable("InvalidEvidence", error.Message));
        }
        finally { _gate.Release(); }
    }

    internal Result<T> ReadJudgement<T>(Func<JudgementReader, T> read, CancellationToken cancellationToken = default) =>
        ReadJudgement((reader, _) => read(reader), cancellationToken);

    internal Result<T> ReadJudgement<T>(Func<JudgementReader, CancellationToken, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenJudgement, read, reader => Current(reader.Description), cancellationToken);

    internal Result<T> ReadFindings<T>(Func<JudgementReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenFindings, (reader, _) => read(reader), reader => CurrentFindings(reader.Description), cancellationToken);

    internal Result<T> ReadDerivation<T>(Func<DerivationReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenDerivation, (reader, _) => read(reader), reader => CurrentDerivation(reader.Description.GenerationId), cancellationToken);

    /// <summary>Reads one object's saved permission interpretations, against the evidence's own descriptor.</summary>
    /// <param name="distinguishedName">The object to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <remarks>
    /// <b>This is the join <c>P-280</c> needs, and this is the only place it can be made.</b> The
    /// saved interpretations are keyed per descriptor, so an object reaches its permissions through
    /// a descriptor identity — and only the sealed evidence is entitled to say which descriptor an
    /// object carries. <see cref="JudgementReader"/> holds the judgement connection alone and
    /// cannot reach it. So the evidence is asked first, its answer is carried across, and the
    /// judgement refuses to read anything against a descriptor the evidence did not name.
    /// </remarks>
    internal Result<SavedPermissionClassification> ReadPermissionClassification(string distinguishedName,
        CancellationToken cancellationToken = default)
    {
        var carried = ReadEvidence(evidence => evidence.ReadDescriptorId(distinguishedName), cancellationToken);
        if (!carried.IsSuccess) return Result<SavedPermissionClassification>.Failure(carried.Error);
        var read = ReadJudgement((reader, token) => reader.ReadPermissionClassification(distinguishedName, carried.Value, token), cancellationToken);
        if (!read.IsSuccess && read.Error.Code == "Evidence.judgementManifestAbsent")
            return Result<SavedPermissionClassification>.Failure(AuditError.Create(ErrorCategory.Shell, "PermissionClassificationUnavailable",
                ErrorSeverity.Failed, PermissionClassificationText.Get("Unavailable"), Directory));
        return read;
    }

    internal Result<LapsPage> ReadLapsComputers(LapsQuery query, LapsPageMark? after,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        var coverage = ReadNavigation(reader => reader.ReadListingCoverage(query.Container, query.Scope), cancellationToken);
        if (!coverage.IsSuccess) return Result<LapsPage>.Failure(coverage.Error);
        var read = ReadFindings(judgement => judgement.ListLapsComputers(query, after, coverage.Value, cancellationToken), cancellationToken);
        if (!read.IsSuccess && read.Error.Code == "Evidence.judgementManifestAbsent")
            return Result<LapsPage>.Failure(AuditError.Create(ErrorCategory.Shell, "LapsInventoryUnavailable",
                ErrorSeverity.Failed, LapsInventoryText.Get("Unavailable"), Directory));
        return read;
    }

    private Result<T> Read<TReader, T>(Func<CancellationToken, Result<TReader>> open, Func<TReader, CancellationToken, T> read,
        Func<TReader, AuditError?> current, CancellationToken cancellationToken) where TReader : IDisposable
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stopping.Token);
            var token = stopping.Token;
            Result<TReader> opened;
            _gate.Wait(token);
            try
            {
                if (_disposed) return Result<T>.Failure(Unavailable("GenerationChanged"));
                var opening = Stopwatch.GetTimestamp();
                opened = open(token);
                NavigationDiagnostics.Mark("opening/checking", Stopwatch.GetElapsedTime(opening));
            }
            finally { _gate.Release(); }
            if (!opened.IsSuccess)
            {
                token.ThrowIfCancellationRequested();
                return Result<T>.Failure(opened.Error);
            }
            using var reader = opened.Value;
            token.ThrowIfCancellationRequested();
            var querying = Stopwatch.GetTimestamp();
            var value = read(reader, token);
            NavigationDiagnostics.Mark("query", Stopwatch.GetElapsedTime(querying));
            token.ThrowIfCancellationRequested();
            _gate.Wait(token);
            try
            {
                var checking = Stopwatch.GetTimestamp();
                if (current(reader) is { } error) return Result<T>.Failure(error);
                token.ThrowIfCancellationRequested();
                NavigationDiagnostics.Mark("generation check", Stopwatch.GetElapsedTime(checking));
                return Result<T>.Success(value);
            }
            finally { _gate.Release(); }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Result<T>.Failure(Unavailable("GenerationChanged"));
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException
            or SqliteException or System.Text.Json.JsonException or ArgumentException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _disposeRequested) != 0) return Result<T>.Failure(Unavailable("GenerationChanged"));
            return Result<T>.Failure(Unavailable("InvalidEvidence", error.Message));
        }
    }

    private Result<BundleReader> OpenEvidence(CancellationToken cancellationToken)
    {
        if (_evidence is null)
        {
            var file = _files.Capture(StoreSegmentRole.Evidence, cancellationToken);
            if (!file.IsSuccess) return Result<BundleReader>.Failure(file.Error);
            _evidence = file.Value;
        }
        NavigationDiagnostics.Identity("evidenceSeal", _evidence.Fingerprint);
        return BundleReader.Open(_evidence, cancellationToken);
    }

    private Result<BundleReader> OpenNavigation(CancellationToken cancellationToken)
    {
        if (_navigation is null)
        {
            var file = _files.Capture(StoreSegmentRole.Navigation, cancellationToken);
            if (!file.IsSuccess) return Result<BundleReader>.Failure(file.Error);
            _navigation = file.Value;
        }
        NavigationDiagnostics.Identity("evidenceSeal", _navigation.Root.EvidenceSeal);
        return BundleReader.Open(_navigation, cancellationToken);
    }

    private Result<DashboardOverviewReader> OpenOverview(CancellationToken cancellationToken)
    {
        if (_overview is null)
        {
            var file = _files.Capture(StoreSegmentRole.Overview, cancellationToken);
            if (!file.IsSuccess) return Result<DashboardOverviewReader>.Failure(file.Error);
            _overview = file.Value;
        }
        NavigationDiagnostics.Identity("evidenceSeal", _overview.Root.EvidenceSeal);
        return DashboardOverviewReader.Open(_overview, cancellationToken);
    }

    private Result<BundleReader> OpenCapturedDelegations(CancellationToken token)
    {
        if (_delegations is null)
        {
            var file = _files.Capture(StoreSegmentRole.Delegations, token);
            if (!file.IsSuccess) return Result<BundleReader>.Failure(file.Error);
            _delegations = file.Value;
        }
        return BundleReader.Open(_delegations, token);
    }

    private Result<DerivationReader> OpenMembership(CancellationToken token)
    {
        if (Pending() is { } pending) return Result<DerivationReader>.Failure(pending);
        var capture = AnalysisStoreLifecycle.ResolveCapture(Directory);
        if (!capture.IsSuccess) return Result<DerivationReader>.Failure(capture.Error);
        var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Derivation);
        if (!selected.IsSuccess) return Result<DerivationReader>.Failure(selected.Error);
        if (!CaptureIsCurrent() || _browseDerivation is not null && _browseDerivation.Hash != selected.Value.Hash)
            return Result<DerivationReader>.Failure(Unavailable("GenerationChanged"));
        if (_membership is not null && _membership.Root.Hash != selected.Value.Hash)
            return Result<DerivationReader>.Failure(Unavailable("GenerationChanged"));
        if (_membership is null)
        {
            var file = _files.Analysis(AnalysisStoreKind.Derivation, StoreSegmentRole.Membership, token);
            if (!file.IsSuccess) return Result<DerivationReader>.Failure(file.Error);
            _membership = file.Value;
        }
        var opened = DerivationReader.Open(_membership, token);
        if (!opened.IsSuccess) return opened;
        if (opened.Value.Description.State is not (DerivationRunState.Completed or DerivationRunState.CompletedDegraded)
            || opened.Value.Description.EvidenceSeal != capture.Value.EvidenceSeal
            || _membership.Root.EvidenceSeal != capture.Value.EvidenceSeal)
        {
            opened.Value.Dispose();
            return Result<DerivationReader>.Failure(Unavailable("GenerationChanged"));
        }
        _browseDerivation = selected.Value;
        _findingsCapture = capture.Value;
        return opened;
    }

    private bool CaptureIsCurrent()
    {
        var root = _evidence?.Root ?? _navigation?.Root ?? _overview?.Root ?? _delegations?.Root ?? _findingsCapture;
        if (root is null) return true;
        var selected = AnalysisStoreLifecycle.ResolveCapture(Directory);
        return selected.IsSuccess && selected.Value.Hash == root.Hash
            && (_evidence is null || _evidence.Root.Hash == root.Hash)
            && (_navigation is null || _navigation.Root.Hash == root.Hash)
            && (_overview is null || _overview.Root.Hash == root.Hash)
            && (_delegations is null || _delegations.Root.Hash == root.Hash)
            && (_findingsCapture is null || _findingsCapture.Hash == root.Hash);
    }

    private bool BrowseDerivationIsCurrent()
    {
        if (_browseDerivation is null) return true;
        var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Derivation);
        return selected.IsSuccess && selected.Value.Hash == _browseDerivation.Hash;
    }

    private Result<DerivationReader> OpenDerivation(CancellationToken cancellationToken)
    {
        if (Pending() is { } pending) return Result<DerivationReader>.Failure(pending);
        var evidence = OpenEvidence(cancellationToken);
        if (!evidence.IsSuccess) return Result<DerivationReader>.Failure(evidence.Error);
        evidence.Value.Dispose();
        var selected = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation);
        if (!selected.IsSuccess) return Result<DerivationReader>.Failure(selected.Error);
        if (_derivation is not null && _derivation.Generation != selected.Value)
            return Result<DerivationReader>.Failure(Unavailable("GenerationChanged"));
        if (_derivation is null)
        {
            var file = _files.Analysis(AnalysisStoreKind.Derivation, StoreSegmentRole.Derivation, cancellationToken);
            if (!file.IsSuccess) return Result<DerivationReader>.Failure(file.Error);
            _derivation = file.Value;
        }
        var opened = DerivationReader.Open(_derivation, cancellationToken);
        if (!opened.IsSuccess) return opened;
        var description = opened.Value.Description;
        var error = description.State is not (DerivationRunState.Completed or DerivationRunState.CompletedDegraded)
            ? Unavailable("Unfinished")
            : description.EvidenceSeal != _evidence!.Fingerprint ? Unavailable("GenerationChanged")
            : CurrentDerivation(description.GenerationId);
        if (error is not null)
        {
            opened.Value.Dispose();
            return Result<DerivationReader>.Failure(error);
        }
        _derived = description;
        return opened;
    }

    private Result<JudgementReader> OpenFindings(CancellationToken cancellationToken)
    {
        if (Pending() is { } pending) return Result<JudgementReader>.Failure(pending);
        var capture = AnalysisStoreLifecycle.ResolveCapture(Directory);
        if (!capture.IsSuccess) return Result<JudgementReader>.Failure(capture.Error);
        if (!CaptureIsCurrent() || _findingsCapture is not null && _findingsCapture.Hash != capture.Value.Hash)
            return Result<JudgementReader>.Failure(Unavailable("GenerationChanged"));
        var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Judgement);
        if (!selected.IsSuccess) return Result<JudgementReader>.Failure(selected.Error);
        if (_judgement is not null && _judgement.Root.Hash != selected.Value.Hash)
            return Result<JudgementReader>.Failure(Unavailable("GenerationChanged"));
        if (_judgement is null)
        {
            var file = _files.Analysis(AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement, cancellationToken);
            if (!file.IsSuccess) return Result<JudgementReader>.Failure(file.Error);
            _judgement = file.Value;
        }
        NavigationDiagnostics.Identity("judgementGeneration", _judgement.Root.GenerationId.ToString("D"));
        var opened = JudgementReader.Open(_judgement, cancellationToken);
        if (!opened.IsSuccess) return opened;
        var reader = opened.Value;
        var accepted = false;
        try
        {
            if (reader.Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
                return Result<JudgementReader>.Failure(Unavailable("Unfinished"));
            if (reader.Description.EvidenceSeal != capture.Value.EvidenceSeal)
                return Result<JudgementReader>.Failure(Unavailable("GenerationChanged"));
            if (reader.Description.DerivationGenerationId is { } generation)
            {
                var derivation = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Derivation);
                if (!derivation.IsSuccess) return Result<JudgementReader>.Failure(derivation.Error);
                if (derivation.Value.GenerationId != generation || derivation.Value.EvidenceSeal != reader.Description.EvidenceSeal
                    || derivation.Value.Segment(StoreSegmentRole.Derivation).SchemaVersion != DerivationReader.StorageVersion
                    || _browseDerivation is not null && _browseDerivation.Hash != derivation.Value.Hash)
                    return Result<JudgementReader>.Failure(Unavailable("GenerationChanged"));
                _browseDerivation = derivation.Value;
            }
            _findingsCapture = capture.Value;
            NavigationDiagnostics.Identity("evidenceSeal", capture.Value.EvidenceSeal);
            if (CurrentFindings(reader.Description) is { } error) return Result<JudgementReader>.Failure(error);
            accepted = true;
            return opened;
        }
        finally { if (!accepted) reader.Dispose(); }
    }

    private Result<JudgementReader> OpenJudgement(CancellationToken cancellationToken)
    {
        var opened = OpenFindings(cancellationToken);
        if (!opened.IsSuccess) return opened;
        var reader = opened.Value;
        var accepted = false;
        try
        {
            var evidence = OpenEvidence(cancellationToken);
            if (!evidence.IsSuccess) return Result<JudgementReader>.Failure(evidence.Error);
            evidence.Value.Dispose();
            if (reader.Description.DerivationGenerationId is { } generation && _derived?.GenerationId != generation)
            {
                var derivation = OpenDerivation(cancellationToken);
                if (!derivation.IsSuccess) return Result<JudgementReader>.Failure(derivation.Error);
                derivation.Value.Dispose();
            }
            if (Current(reader.Description) is { } error) return Result<JudgementReader>.Failure(error);
            accepted = true;
            return opened;
        }
        finally { if (!accepted) reader.Dispose(); }
    }

    private AuditError? Pending() =>
        AnalysisStoreLifecycle.HasUnpublishedChanges(Directory, AnalysisStoreKind.Derivation)
        || AnalysisStoreLifecycle.HasUnpublishedChanges(Directory, AnalysisStoreKind.Judgement)
            ? Unavailable("Unfinished") : null;

    private AuditError? CurrentDerivation(Guid generation)
    {
        if (Pending() is { } pending) return pending;
        var selected = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation);
        return !selected.IsSuccess ? selected.Error
            : selected.Value.GenerationId != generation ? Unavailable("GenerationChanged") : null;
    }

    private AuditError? Current(JudgementDescription description)
    {
        if (CurrentFindings(description) is { } error) return error;
        if (_evidence?.Fingerprint != description.EvidenceSeal)
            return Unavailable("GenerationChanged");
        if (description.DerivationGenerationId is { } generation)
        {
            if (_derived?.GenerationId != generation || _derived.EvidenceSeal != description.EvidenceSeal)
                return Unavailable("GenerationChanged");
            return CurrentDerivation(generation);
        }
        return null;
    }

    private AuditError? CurrentFindings(JudgementDescription description)
    {
        if (Pending() is { } pending) return pending;
        var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Judgement);
        if (!selected.IsSuccess) return selected.Error;
        if (selected.Value.GenerationId != description.GenerationId || _judgement?.Root.Hash != selected.Value.Hash
            || _findingsCapture?.EvidenceSeal != description.EvidenceSeal || !CaptureIsCurrent() || !BrowseDerivationIsCurrent())
            return Unavailable("GenerationChanged");
        if (description.DerivationGenerationId is { } generation
            && (_browseDerivation is not { } derived || derived.GenerationId != generation || derived.EvidenceSeal != description.EvidenceSeal))
            return Unavailable("GenerationChanged");
        return null;
    }

    private AuditError Unavailable(string reason) => Unavailable(reason, null);

    private AuditError Unavailable(string reason, string? detail) =>
        AuditError.Create(ErrorCategory.Shell, "SavedResults" + reason, ErrorSeverity.Failed,
            SavedPathText.Get(reason) + (detail is null ? "" : " " + detail), Directory);

    public void Dispose()
    {
        // Cancellation precedes waiting: an opener holding the gate may be hashing a large file.
        if (Interlocked.Exchange(ref _disposeRequested, 1) != 0) return;
        _stopping.Cancel();
        _gate.Wait();
        try
        {
            if (_disposed) return;
            _disposed = true;
            if (_sharedProtection is { } shared) shared.Dispose();
            else _files.Dispose();
            _stopping.Dispose();
        }
        finally { _gate.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        Dispose();
        if (_sharedProtection is { } shared) await shared.DisposeAsync().ConfigureAwait(false);
        else await _files.DisposeAsync().ConfigureAwait(false);
    }
}
