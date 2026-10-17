using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;
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
    private bool _verificationFailed;
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

    internal static FileStream ProtectPublicationFile(string path, FileShare sharing)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("A publishing store or seal is a link.");
        return new FileStream(path, FileMode.Open, FileAccess.Read, sharing);
    }

    internal static void RequireSameFile(FileStream before, FileStream after)
    {
        var first = Identity(before);
        var second = Identity(after);
        if (first.Volume != second.Volume || first.Low != second.Low || first.High != second.High)
            throw new InvalidDataException("A capture product was replaced during publication.");
    }

    private static FileIdentity Identity(FileStream stream)
    {
        // Rename needs delete sharing. Compare the still-write-protected original with the
        // final non-replaceable handle before carrying its sealing result across that rename.
        if (!GetFileInformationByHandleEx(stream.SafeFileHandle, 18, out var identity, 24))
            throw new IOException("The publishing file's identity could not be established.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        return identity;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdentity
    {
        internal ulong Volume;
        internal ulong Low;
        internal ulong High;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileIdentity information, uint size);

    internal static ProtectedStoreFile FromPublishedCapture(string directory, FileStream data, FileStream seal,
        StoreRootManifest root, StoreSegmentRole role) =>
        new(Path.GetFullPath(directory), null, data, seal, root, role) { Fingerprint = root.Segment(role).Hash };

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

    /// <summary>Whether every file byte was verified during this continuously protected lifetime.</summary>
    public bool WholeFileVerified => Fingerprint.Length != 0;

    internal bool MayReadRequested
    {
        get { lock (_gate) return !_verificationFailed; }
    }

    /// <summary>Protects and verifies the evidence without opening an analytical reader.</summary>
    public static Result<ProtectedStoreFile> OpenEvidence(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Evidence, cancellationToken);

    /// <summary>Verifies captured navigation without opening or hashing attributes or permissions.</summary>
    public static Result<ProtectedStoreFile> OpenNavigation(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Navigation, cancellationToken);

    /// <summary>Verifies the small Dashboard overview without opening the object catalogue.</summary>
    public static Result<ProtectedStoreFile> OpenOverview(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Overview, cancellationToken);

    /// <summary>Verifies the captured permission-browsing product without unrelated attribute data.</summary>
    public static Result<ProtectedStoreFile> OpenDelegations(string directory, CancellationToken cancellationToken = default) =>
        OpenCapture(directory, StoreSegmentRole.Delegations, cancellationToken);

    internal static Result<ProtectedStoreFile> OpenCaptureRequested(string directory, StoreSegmentRole role, CancellationToken token) =>
        OpenCapture(directory, role, token, requested: true);

    private static Result<ProtectedStoreFile> OpenCapture(string directory, StoreSegmentRole role, CancellationToken token,
        bool requested = false)
    {
        token.ThrowIfCancellationRequested();
        var selected = AnalysisStoreLifecycle.ResolveCapture(directory);
        if (!selected.IsSuccess) return Result<ProtectedStoreFile>.Failure(selected.Error);
        var path = role switch
        {
            StoreSegmentRole.Evidence => BundleLayout.EvidencePath(directory),
            StoreSegmentRole.Navigation => BundleLayout.NavigationPath(directory, selected.Value.GenerationId),
            StoreSegmentRole.Overview => BundleLayout.OverviewPath(directory, selected.Value.GenerationId),
            StoreSegmentRole.Delegations => BundleLayout.DelegationsPath(directory, selected.Value.GenerationId),
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };
        return Open(directory, null, path, path + ".seal",
            () => BundleSealing.VerifySegment(path, path + ".seal", role.ToString(), token), token, selected.Value, role,
            verifyWholeFile: !requested);
    }

    /// <summary>Protects and verifies the specified immutable analysis generation.</summary>
    public static Result<ProtectedStoreFile> OpenAnalysis(string directory, AnalysisStoreGeneration generation,
        CancellationToken cancellationToken = default)
        => OpenAnalysisSegment(directory, generation,
            generation?.Kind == AnalysisStoreKind.Judgement ? StoreSegmentRole.Judgement : StoreSegmentRole.Derivation,
            cancellationToken);

    /// <summary>Verifies only the declared analysis product, retaining its exact publication root.</summary>
    public static Result<ProtectedStoreFile> OpenAnalysisSegment(string directory, AnalysisStoreGeneration generation,
        StoreSegmentRole role, CancellationToken cancellationToken = default) =>
        OpenAnalysisSegmentCore(directory, generation, role, cancellationToken, requested: false);

    internal static Result<ProtectedStoreFile> OpenAnalysisRequested(string directory, AnalysisStoreGeneration generation,
        StoreSegmentRole role, CancellationToken token) => OpenAnalysisSegmentCore(directory, generation, role, token, requested: true);

    private static Result<ProtectedStoreFile> OpenAnalysisSegmentCore(string directory, AnalysisStoreGeneration generation,
        StoreSegmentRole role, CancellationToken cancellationToken, bool requested)
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
            cancellationToken, selected.Value, role, verifyWholeFile: !requested);
    }

    private ProtectedStoreFile Related(StoreSegmentRole role, CancellationToken cancellationToken, bool requested = false)
    {
        lock (_gate)
        {
            if (Generation is not { Kind: AnalysisStoreKind.Judgement } generation
                || Role != StoreSegmentRole.Judgement || !BundleLayout.JudgementParts.Contains(role))
                throw new ArgumentException("This product cannot acquire a judgement proof part.", nameof(role));
            if (_related.TryGetValue(role, out var existing))
            {
                if (!requested)
                {
                    var verified = existing.RequireWholeVerification(cancellationToken);
                    if (!verified.IsSuccess) throw new InvalidDataException(verified.Error.Description);
                }
                return existing;
            }
            var opened = requested ? OpenAnalysisRequested(BundleDirectory, generation, role, cancellationToken)
                : OpenAnalysisSegment(BundleDirectory, generation, role, cancellationToken);
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
        StoreRootManifest root, StoreSegmentRole role, bool verifyWholeFile = true)
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
            if (verifyWholeFile)
            {
                var verdict = verify();
                if (!verdict.MayBeOpened)
                    return Failure(verdict.State.ToString(), verdict.Detail, dataPath);
            }
            cancellationToken.ThrowIfCancellationRequested();
            var contents = BundleSealing.ReadSeal(sealPath) ?? throw new InvalidDataException(sealPath);
            var declaration = root.Segment(role);
            if (contents.Algorithm != BundleSealing.Algorithm
                || data.Length != declaration.ByteLength || contents.Hash != declaration.Hash)
                return Failure("Mismatch", "The selected store bytes or seal contradict the publication root.", dataPath);
            if (!verifyWholeFile)
            {
                RequireNoSidecars(dataPath);
                var details = declaration.RequestedDetails;
                if (details is null || details.Role != role || details.GenerationId != root.GenerationId
                    || details.SchemaVersion != declaration.SchemaVersion
                    || details.EvidenceSeal != (generation is null ? "" : root.EvidenceSeal))
                    return Failure("Unsupported", "The selected product has no compatible requested-detail commitment.", dataPath);
            }
            var result = new ProtectedStoreFile(Path.GetFullPath(directory), generation, data, seal, root, role)
                { Fingerprint = verifyWholeFile ? contents.Hash : "" };
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
        var verified = RequireWholeVerification(cancellationToken);
        if (!verified.IsSuccess) throw new InvalidDataException(verified.Error.Description);
        return AcquireCore(cancellationToken);
    }

    internal Lease AcquireRequested(CancellationToken cancellationToken)
    {
        RequireNoSidecars(_data.Name);
        if (Root.Segment(Role).RequestedDetails is null)
            throw new InvalidDataException("The selected product has no requested-detail index.");
        return AcquireCore(cancellationToken);
    }

    private Lease AcquireCore(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closing, this);
            if (_verificationFailed) throw new InvalidDataException("The selected file failed whole-file verification.");
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

    internal Result<ProtectedStoreFile> RequireWholeVerification(CancellationToken token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closing, this);
            token.ThrowIfCancellationRequested();
            if (_verificationFailed) return Failure("Mismatch", "The selected file failed whole-file verification.", _data.Name);
            if (WholeFileVerified) return this;
            var verdict = BundleSealing.VerifySegment(_data.Name, _seal.Name, Role.ToString(), token);
            if (!verdict.MayBeOpened)
            {
                _verificationFailed = true;
                return Failure(verdict.State.ToString(), verdict.Detail, _data.Name);
            }
            Fingerprint = Root.Segment(Role).Hash;
            return this;
        }
    }

    private static void RequireNoSidecars(string path)
    {
        foreach (var suffix in new[] { "-wal", "-journal" })
            if (File.Exists(path + suffix) && new FileInfo(path + suffix).Length != 0)
                throw new InvalidDataException("Requested detail cannot use uncheckpointed journal or write-ahead-log bytes.");
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
        public string Attach(StoreSegmentRole role, CancellationToken cancellationToken = default) =>
            AttachCore(role, cancellationToken, requested: false);

        /// <summary>Attaches source-bound requested pages, not a verdict about all proof-file bytes.</summary>
        public RequestedDetailReader AttachRequested(StoreSegmentRole role, CancellationToken cancellationToken = default)
        {
            var owner = _owner ?? throw new ObjectDisposedException(nameof(Lease));
            var schema = AttachCore(role, cancellationToken, requested: true);
            var file = _attachments[role];
            RequireNoSidecars(file._data.Name);
            var reader = RequestedDetailIndex.Open(Connection, schema,
                file.Root.Segment(role).RequestedDetails ?? throw RequestedDetailMap.Invalid(), cancellationToken);
            reader.RequireCurrent(() =>
            {
                if (_owner is null || !owner.MayReadRequested || !file.MayReadRequested) return false;
                var current = AnalysisStoreLifecycle.ResolveRoot(owner.BundleDirectory, AnalysisStoreKind.Judgement);
                return current.IsSuccess && current.Value.Hash == owner.Root.Hash;
            });
            return reader;
        }

        private string AttachCore(StoreSegmentRole role, CancellationToken cancellationToken, bool requested)
        {
            var owner = _owner ?? throw new ObjectDisposedException(nameof(Lease));
            cancellationToken.ThrowIfCancellationRequested();
            var schema = role.ToString();
            var file = owner.Related(role, cancellationToken, requested);
            if (_attachments.ContainsKey(role)) return schema;
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
