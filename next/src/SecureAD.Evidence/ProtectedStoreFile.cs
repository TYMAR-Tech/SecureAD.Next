using Microsoft.Data.Sqlite;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>A verified store whose database and seal remain protected until every acquired reader has closed.</summary>
public sealed class ProtectedStoreFile : IDisposable
{
    private readonly object _gate = new();
    private readonly FileStream _data;
    private readonly FileStream _seal;
    private int _readers;
    private bool _closing;
    internal object EvidenceDescriptionGate { get; } = new();
    internal BundleDescription? EvidenceDescription { get; set; }

    private ProtectedStoreFile(string directory, AnalysisStoreGeneration? generation, FileStream data, FileStream seal)
    {
        BundleDirectory = directory;
        Generation = generation;
        _data = data;
        _seal = seal;
    }

    /// <summary>The bundle owning the protected file.</summary>
    public string BundleDirectory { get; }

    /// <summary>The exact analysis generation, or null for evidence.</summary>
    public AnalysisStoreGeneration? Generation { get; }

    /// <summary>The verified fingerprint, retained only while the files are protected.</summary>
    public string Fingerprint { get; private set; } = "";

    /// <summary>Protects and verifies the evidence without opening an analytical reader.</summary>
    public static Result<ProtectedStoreFile> OpenEvidence(string directory, CancellationToken cancellationToken = default) =>
        Open(directory, null, BundleLayout.EvidencePath(directory), BundleLayout.SealPath(directory),
            () => BundleSealing.Verify(directory, cancellationToken), cancellationToken);

    /// <summary>Protects and verifies the specified immutable analysis generation.</summary>
    public static Result<ProtectedStoreFile> OpenAnalysis(string directory, AnalysisStoreGeneration generation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(generation);
        return Open(directory, generation,
            BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId),
            BundleLayout.AnalysisGenerationSealPath(directory, generation.Kind, generation.GenerationId),
            () => BundleSealing.VerifyAnalysisGeneration(directory, generation,
                generation.Kind == AnalysisStoreKind.Judgement ? "judgement store" : "derived facts",
                generation.Kind == AnalysisStoreKind.Judgement
                    ? "It does not prove every scheduled rule reached a verdict, which is a claim the store makes in its own tables."
                    : "It does not prove every closure is complete, which is a claim the store makes in its own tables.", cancellationToken),
            cancellationToken);
    }

    private static Result<ProtectedStoreFile> Open(string directory, AnalysisStoreGeneration? generation,
        string dataPath, string sealPath, Func<SealVerdict> verify, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        cancellationToken.ThrowIfCancellationRequested();
        FileStream? data = null;
        FileStream? seal = null;
        try
        {
            // SQLite opens by name. Deny both writes and replacement before hashing and keep
            // that protection until the last connection releases its lease.
            data = new FileStream(dataPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            seal = new FileStream(sealPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var verdict = verify();
            if (!verdict.MayBeOpened)
                return Failure(verdict.State.ToString(), verdict.Detail, dataPath);
            cancellationToken.ThrowIfCancellationRequested();
            var contents = BundleSealing.ReadSeal(sealPath) ?? throw new InvalidDataException(sealPath);
            var result = new ProtectedStoreFile(Path.GetFullPath(directory), generation, data, seal)
                { Fingerprint = contents.Hash };
            data = null;
            seal = null;
            return result;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
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
        _seal.Dispose();
        _data.Dispose();
    }

    private static Result<ProtectedStoreFile> Failure(string reason, string detail, string path) =>
        Result<ProtectedStoreFile>.Failure(AuditError.Create(ErrorCategory.Evidence, "ProtectedStore" + reason,
            ErrorSeverity.Failed, detail, path));

    /// <summary>One reader's connection and ownership of the unchanged verified files.</summary>
    public sealed class Lease : IDisposable
    {
        private ProtectedStoreFile? _owner;

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

        /// <summary>Closes this connection before releasing its file protection.</summary>
        public void Dispose()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            if (owner is null) return;
            try { Connection.Dispose(); }
            finally { owner.Release(); }
        }
    }
}
