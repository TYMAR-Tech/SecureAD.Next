using System.IO;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>Owns one selected run's protected files, never a connection shared between queries.</summary>
internal sealed class OpenedRunResults(string directory) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1);
    private readonly CancellationTokenSource _stopping = new();
    private readonly object _schemaGate = new();
    private SchemaGuidCatalog? _schema;
    private ProtectedStoreFile? _evidence;
    private ProtectedStoreFile? _derivation;
    private ProtectedStoreFile? _judgement;
    private DerivationDescription? _derived;
    private bool _disposed;
    private int _disposeRequested;

    internal string Directory { get; } = Path.GetFullPath(directory);

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
                return (judgement is null || AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Judgement).Value == judgement)
                    && (derivation is null || AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation).Value == derivation);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
        }
    }

    internal Result<SchemaGuidCatalog> ReadSchemaGuids() => ReadEvidence(reader =>
    {
        lock (_schemaGate) return _schema ??= reader.ReadSchemaGuids();
    });

    internal Result<T> ReadEvidence<T>(Func<BundleReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenEvidence, (reader, _) => read(reader), _ => null, cancellationToken);

    internal Result<T> ReadJudgement<T>(Func<JudgementReader, T> read, CancellationToken cancellationToken = default) =>
        ReadJudgement((reader, _) => read(reader), cancellationToken);

    internal Result<T> ReadJudgement<T>(Func<JudgementReader, CancellationToken, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenJudgement, read, reader => Current(reader.Description), cancellationToken);

    internal Result<T> ReadDerivation<T>(Func<DerivationReader, T> read, CancellationToken cancellationToken = default) =>
        Read(OpenDerivation, (reader, _) => read(reader), reader => CurrentDerivation(reader.Description.GenerationId), cancellationToken);

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
                opened = open(token);
            }
            finally { _gate.Release(); }
            if (!opened.IsSuccess)
            {
                token.ThrowIfCancellationRequested();
                return Result<T>.Failure(opened.Error);
            }
            using var reader = opened.Value;
            token.ThrowIfCancellationRequested();
            var value = read(reader, token);
            token.ThrowIfCancellationRequested();
            _gate.Wait(token);
            try
            {
                if (current(reader) is { } error) return Result<T>.Failure(error);
                token.ThrowIfCancellationRequested();
                return Result<T>.Success(value);
            }
            finally { _gate.Release(); }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Result<T>.Failure(Unavailable("GenerationChanged"));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException
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
            var file = ProtectedStoreFile.OpenEvidence(Directory, cancellationToken);
            if (!file.IsSuccess) return Result<BundleReader>.Failure(file.Error);
            _evidence = file.Value;
        }
        return BundleReader.Open(_evidence, cancellationToken);
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
            var file = ProtectedStoreFile.OpenAnalysis(Directory, selected.Value, cancellationToken);
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

    private Result<JudgementReader> OpenJudgement(CancellationToken cancellationToken)
    {
        if (Pending() is { } pending) return Result<JudgementReader>.Failure(pending);
        var evidence = OpenEvidence(cancellationToken);
        if (!evidence.IsSuccess) return Result<JudgementReader>.Failure(evidence.Error);
        evidence.Value.Dispose();
        var selected = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Judgement);
        if (!selected.IsSuccess) return Result<JudgementReader>.Failure(selected.Error);
        if (_judgement is not null && _judgement.Generation != selected.Value)
            return Result<JudgementReader>.Failure(Unavailable("GenerationChanged"));
        if (_judgement is null)
        {
            var file = ProtectedStoreFile.OpenAnalysis(Directory, selected.Value, cancellationToken);
            if (!file.IsSuccess) return Result<JudgementReader>.Failure(file.Error);
            _judgement = file.Value;
        }
        var opened = JudgementReader.Open(_judgement, cancellationToken);
        if (!opened.IsSuccess) return opened;
        var reader = opened.Value;
        var accepted = false;
        try
        {
            if (reader.Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
                return Result<JudgementReader>.Failure(Unavailable("Unfinished"));
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
        if (Pending() is { } pending) return pending;
        var selected = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Judgement);
        if (!selected.IsSuccess) return selected.Error;
        if (selected.Value.GenerationId != description.GenerationId || _evidence?.Fingerprint != description.EvidenceSeal)
            return Unavailable("GenerationChanged");
        if (description.DerivationGenerationId is { } generation)
        {
            if (_derived?.GenerationId != generation || _derived.EvidenceSeal != description.EvidenceSeal)
                return Unavailable("GenerationChanged");
            return CurrentDerivation(generation);
        }
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
            _judgement?.Dispose();
            _derivation?.Dispose();
            _evidence?.Dispose();
            _stopping.Dispose();
        }
        finally { _gate.Release(); }
    }
}
