using Microsoft.Data.Sqlite;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>A verified store whose database and seal remain protected until every acquired reader has closed.</summary>
public sealed class ProtectedStoreFile : IDisposable, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly FileStream _data;
    private readonly FileStream _seal;
    private int _readers;
    private bool _closing;
    private readonly Dictionary<StoreSegmentRole, ProtectedStoreFile> _related = [];
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal object EvidenceDescriptionGate { get; } = new();
    internal BundleDescription? EvidenceDescription { get; set; }

    private ProtectedStoreFile(string directory, AnalysisStoreGeneration? generation, FileStream data, FileStream seal,
        StoreRootManifest root, StoreSegmentRole role)
    {
        BundleDirectory = directory;
        Generation = generation;
        _data = data;
        _seal = seal;
        Root = root;
        Role = role;
    }

    /// <summary>The bundle owning the protected file.</summary>
    public string BundleDirectory { get; }

    /// <summary>The exact analysis generation, or null for evidence.</summary>
    public AnalysisStoreGeneration? Generation { get; }
    /// <summary>The complete root whose declaration this protected file verified.</summary>
    public StoreRootManifest Root { get; }
    /// <summary>The product actually verified; another product cannot acquire this file's verdict.</summary>
    public StoreSegmentRole Role { get; }

    /// <summary>The verified fingerprint, retained only while the files are protected.</summary>
    public string Fingerprint { get; private set; } = "";

    /// <summary>Protects and verifies the evidence without opening an analytical reader.</summary>
    public static Result<ProtectedStoreFile> OpenEvidence(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Evidence, cancellationToken);

    /// <summary>Verifies captured navigation without opening or hashing attributes or permissions.</summary>
    public static Result<ProtectedStoreFile> OpenNavigation(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Navigation, cancellationToken);

    /// <summary>Verifies the small Dashboard overview without opening the object catalogue.</summary>
    public static Result<ProtectedStoreFile> OpenOverview(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Overview, cancellationToken);

    private static Result<ProtectedStoreFile> OpenCapture(string directory, StoreSegmentRole role, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var selected = AnalysisStoreLifecycle.ResolveCapture(directory);
        if (!selected.IsSuccess) return Result<ProtectedStoreFile>.Failure(selected.Error);
        var path = role switch
        {
            StoreSegmentRole.Evidence => BundleLayout.EvidencePath(directory),
            StoreSegmentRole.Navigation => BundleLayout.NavigationPath(directory, selected.Value.GenerationId),
            StoreSegmentRole.Overview => BundleLayout.OverviewPath(directory, selected.Value.GenerationId),
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };
        return Open(directory, null, path, path + ".seal",
            () => BundleSealing.VerifySegment(path, path + ".seal", role.ToString(), token), token, selected.Value, role);
    }

    /// <summary>Protects and verifies the specified immutable analysis generation.</summary>
    public static Result<ProtectedStoreFile> OpenAnalysis(string directory, AnalysisStoreGeneration generation,
        CancellationToken cancellationToken = default)
        => OpenAnalysisSegment(directory, generation,
            generation?.Kind == AnalysisStoreKind.Judgement ? StoreSegmentRole.Judgement : StoreSegmentRole.Derivation,
            cancellationToken);

    /// <summary>Verifies only the declared analysis product, retaining its exact publication root.</summary>
    public static Result<ProtectedStoreFile> OpenAnalysisSegment(string directory, AnalysisStoreGeneration generation,
        StoreSegmentRole role, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(generation);
        var selected = AnalysisStoreLifecycle.ResolveRoot(directory, generation.Kind);
        if (!selected.IsSuccess) return Result<ProtectedStoreFile>.Failure(selected.Error);
        if (selected.Value.GenerationId != generation.GenerationId)
            return Failure("GenerationChanged", "The selected analysis generation changed before opening.", directory);
        if (!selected.Value.Segments.Any(segment => segment.Role == role))
            return Failure("Absent", "The publication root does not declare this analysis product.", directory);
        var path = BundleLayout.AnalysisSegmentDataPath(directory, generation, role);
        return Open(directory, generation, path, path + ".seal",
            () => BundleSealing.VerifySegment(path, path + ".seal", role.ToString(), cancellationToken),
            cancellationToken, selected.Value, role);
    }

    private ProtectedStoreFile Related(StoreSegmentRole role, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (Generation is not { Kind: AnalysisStoreKind.Judgement } generation
                || Role != StoreSegmentRole.Judgement || !BundleLayout.JudgementParts.Contains(role))
                throw new ArgumentException("This product cannot acquire a judgement proof part.", nameof(role));
            if (_related.TryGetValue(role, out var existing)) return existing;
            var opened = OpenAnalysisSegment(BundleDirectory, generation, role, cancellationToken);
            if (!opened.IsSuccess) throw new InvalidDataException(opened.Error.Description);
            var file = opened.Value;
            if (file.Root.Hash != Root.Hash)
            {
                file.Dispose();
                throw new InvalidDataException("The selected judgement root changed before its proof part opened.");
            }
            _related.Add(role, file);
            return file;
        }
    }

    private static Result<ProtectedStoreFile> Open(string directory, AnalysisStoreGeneration? generation,
        string dataPath, string sealPath, Func<SealVerdict> verify, CancellationToken cancellationToken,
        StoreRootManifest root, StoreSegmentRole role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        cancellationToken.ThrowIfCancellationRequested();
        FileStream? data = null;
        FileStream? seal = null;
        try
        {
            if ((File.GetAttributes(dataPath) & FileAttributes.ReparsePoint) != 0
                || (File.GetAttributes(sealPath) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("A selected store or seal is a link.");
            // SQLite opens by name. Deny both writes and replacement before hashing and keep
            // that protection until the last connection releases its lease.
            data = new FileStream(dataPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            seal = new FileStream(sealPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var verdict = verify();
            if (!verdict.MayBeOpened)
                return Failure(verdict.State.ToString(), verdict.Detail, dataPath);
            cancellationToken.ThrowIfCancellationRequested();
            var contents = BundleSealing.ReadSeal(sealPath) ?? throw new InvalidDataException(sealPath);
            var declaration = root.Segment(role);
            if (data.Length != declaration.ByteLength || contents.Hash != declaration.Hash)
                return Failure("Mismatch", "The selected store bytes or seal contradict the publication root.", dataPath);
            var result = new ProtectedStoreFile(Path.GetFullPath(directory), generation, data, seal, root, role)
                { Fingerprint = contents.Hash };
            data = null;
            seal = null;
            return result;
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return Failure(error is FileNotFoundException ? "Absent" : "Unreadable", error.Message, dataPath);
        }
        finally
        {
            data?.Dispose();
            seal?.Dispose();
        }
    }

    /// <summary>Acquires an independent connection; disposal of the store waits for this lease's release.</summary>
    public Lease Acquire(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closing, this);
            _readers++;
        }
        SqliteConnection? connection = null;
        try
        {
            connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                // Immutable mode never incorporates unverified WAL/journal contents.
                DataSource = BundleReader.ImmutableDataSource(Path.GetFullPath(_data.Name)),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());
            connection.Open();
            cancellationToken.ThrowIfCancellationRequested();
            return new Lease(this, connection, cancellationToken);
        }
        catch
        {
            connection?.Dispose();
            Release();
            throw;
        }
    }

    /// <summary>Prevents new acquisitions; existing readers retain protection until they finish.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_closing) return;
            _closing = true;
            if (_readers == 0) CloseFiles();
        }
    }

    /// <summary>Closes the store and waits until every reader has released its file protection.</summary>
    public async ValueTask DisposeAsync()
    {
        Dispose();
        await _closed.Task.ConfigureAwait(false);
    }

    private void Release()
    {
        lock (_gate)
        {
            _readers--;
            if (_closing && _readers == 0) CloseFiles();
        }
    }

    private void CloseFiles()
    {
        try
        {
            foreach (var file in _related.Values) file.Dispose();
            _seal.Dispose();
            _data.Dispose();
            _closed.TrySetResult();
        }
        catch (IOException error)
        {
            _closed.TrySetException(error);
            throw;
        }
    }

    private static Result<ProtectedStoreFile> Failure(string reason, string detail, string path) =>
        Result<ProtectedStoreFile>.Failure(AuditError.Create(ErrorCategory.Evidence, "ProtectedStore" + reason,
            ErrorSeverity.Failed, detail, path));

    /// <summary>One reader's connection and ownership of the unchanged verified files.</summary>
    public sealed class Lease : IDisposable
    {
        private ProtectedStoreFile? _owner;
        private readonly Dictionary<StoreSegmentRole, ProtectedStoreFile> _attachments = [];

        internal Lease(ProtectedStoreFile owner, SqliteConnection connection, CancellationToken cancellationToken)
        {
            _owner = owner;
            Connection = connection;
            // SqliteCommand.Cancel is a no-op. The native progress callback cancels even a
            // single long-running statement, on its own worker, without sharing the connection.
            if (cancellationToken.CanBeCanceled)
                SQLitePCL.raw.sqlite3_progress_handler(connection.Handle ?? throw new InvalidOperationException(),
                    1000, _ => cancellationToken.IsCancellationRequested ? 1 : 0, null);
        }

        /// <summary>The connection owned by this lease; it must not be shared between concurrent operations.</summary>
        public SqliteConnection Connection { get; }

        /// <summary>Attaches a separately verified immutable part without opening an unprotected file.</summary>
        public string Attach(StoreSegmentRole role, CancellationToken cancellationToken = default)
        {
            var owner = _owner ?? throw new ObjectDisposedException(nameof(Lease));
            cancellationToken.ThrowIfCancellationRequested();
            var schema = role.ToString();
            if (_attachments.ContainsKey(role)) return schema;
            var file = owner.Related(role, cancellationToken);
            lock (file._gate)
            {
                ObjectDisposedException.ThrowIf(file._closing, file);
                file._readers++;
            }
            try
            {
                using var command = Connection.CreateCommand();
                command.CommandText = $"ATTACH DATABASE $path AS \"{schema}\"";
                command.Parameters.AddWithValue("$path", BundleReader.ImmutableDataSource(Path.GetFullPath(file._data.Name)));
                command.ExecuteNonQuery();
                _attachments.Add(role, file);
                return schema;
            }
            catch
            {
                file.Release();
                throw;
            }
        }

        /// <summary>Closes this connection before releasing its file protection.</summary>
        public void Dispose()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            if (owner is null) return;
            try { Connection.Dispose(); }
            finally
            {
                try { foreach (var file in _attachments.Values) file.Release(); }
                finally { owner.Release(); }
            }
        }
    }
}
