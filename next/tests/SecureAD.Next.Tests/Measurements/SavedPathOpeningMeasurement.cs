using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Data.Sqlite;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Next.Tests.Measurements;

/// <summary>Opening-only adapter in the shell's existing friend assembly; never runs judging or capture.</summary>
public sealed class SavedPathOpeningMeasurement : IDisposable
{
    private const string Repository = @"C:\Users\jistrand\source\repos\razamus\SecureAD.Next";
    private const string Input = Repository + @"\next\artifacts\p242-lookup-optimization\75b787807339426eb8a5023a4ad85154\measure-after-v1\bundle";
    private const string OutputRoot = Repository + @"\next\artifacts\p246-ddb2a0ff3ba0473892ce08b417939184";
    private const string Generation = "5ca58a13-2ac7-4a42-b373-99a9873db814";
    private const string Derivation = "81a28479-a5ba-4456-b57c-3bd6e65a4a2d";
    private const string NotRead = "Saved results have not been read.";
    private const string Loading = "Loading and validating saved results...";
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private static readonly Dictionary<string, string> Files = new(StringComparer.Ordinal)
    {
        ["evidence.db"] = "22A3C4A749195563E3A7CDBA6AA07996BB44FFC0D867F0286D2A87183824F135",
        ["evidence.db.seal"] = "B079E7FEB209CFCC9C292BE451AF4E3188BA77F51A9B47DF6D6FE2BEE89552A8",
        ["derivation.current.json"] = "58A9D89DA6C9C00C4A1E6D40AF918BEBC51C2D8D9064B966326F48885B44C7E8",
        ["derivation.81a28479a5ba4456b57c3bd6e65a4a2d.db"] = "F1EA95F93D6204D26DAB9B8F279EEAF6463B405936D88E983DE94A9D0EC5B496",
        ["derivation.81a28479a5ba4456b57c3bd6e65a4a2d.db.seal"] = "6F9A629CCFF4CF80BD49FB1EA092AEB572A6EB4C9928686F5189E7494F3CCBBC",
        ["judgement.current.json"] = "5E7DC7B29E8CA01E172EE71A790A50FE815916A506F8251AC84612F2C5D97A5D",
        ["judgement.5ca58a132ac74a42b37399a9873db814.db"] = "8C0B021BA4C4574D1260FD48EF73782E497751D30A557BCB1A325105FB9F60A3",
        ["judgement.5ca58a132ac74a42b37399a9873db814.db.seal"] = "1BFD73C2D71FE87BCE2021136A897DC98218DE78501D784A7F1F39E93CCB1469",
    };
    private readonly Dictionary<string, string> _sources = new(StringComparer.Ordinal);
    private readonly Stopwatch _clock = new();
    private readonly TaskCompletionSource<double> _finished = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private string _output = null!;
    private string _bundle = null!;
    private string _subject = null!;
    private Thread? _thread;
    private Dispatcher _dispatcher = null!;
    private BundleAssetSource _source = null!;
    private ObjectViewModel _object = null!;
    private SavedTier0PathSectionViewModel _section = null!;
    private Grid _pane = null!;
    private System.Threading.Timer? _heartbeat;
    private System.Threading.Timer? _navigation;
    private bool _invoked;
    private bool _navigateAway;
    private bool _navigationDelivered;
    private bool _navigationWasInFlight;
    private double? _heartbeatRequested;
    private double? _heartbeatDelivered;
    private double? _navigationRequested;
    private double? _navigationDeliveredAt;
    private double? _selectionReturned;
    private long _allocated;
    private TimeSpan _cpu;
    private int[] _collections = [];
    private bool _done;
    private bool _disposed;

    public void Prepare()
    {
        Require(_output is null, "The adapter instance has already been prepared.");
        Require(string.Equals(Path.TrimEndingDirectorySeparator(Path.GetTempPath()),
            Path.Combine(OutputRoot, "isolated-temp"), StringComparison.OrdinalIgnoreCase),
            "Launch with the isolated TEMP/TMP job before loading the test assembly.");
        _output = Path.Combine(OutputRoot, "opening-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_output);
        Console.WriteLine("Retained opening-only outputs: " + _output);
        _bundle = Path.Combine(_output, "bundle");
        Directory.CreateDirectory(_bundle);
        foreach (var (name, expected) in Files)
        {
            var original = Path.Combine(Input, name);
            Require(Hash(original) == expected, "Retained input differs: " + name);
            if (name.EndsWith(".db", StringComparison.Ordinal))
                Require(!File.Exists(original + "-wal") || new FileInfo(original + "-wal").Length == 0,
                    "Refusing uncheckpointed retained input: " + name);
            File.Copy(original, Path.Combine(_bundle, name), false);
            Require(Hash(Path.Combine(_bundle, name)) == expected, "Copy fingerprint differs: " + name);
        }
        SnapshotSources();
        SaveBinaries("preflight");
        var databaseOpens = new List<object>();
        try
        {
            foreach (var name in Files.Keys.Where(name => name.EndsWith(".db", StringComparison.Ordinal)))
            {
                var path = Path.Combine(_bundle, name);
                using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                    { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
                connection.Open();
                using var query = connection.CreateCommand();
                query.CommandText = "PRAGMA schema_version";
                var schemaCookie = query.ExecuteScalar();
                Require(schemaCookie is not null, "Copied database header could not be read: " + name);
                databaseOpens.Add(new { Name = name, FullPathCharacters = path.Length, SchemaCookie = schemaCookie });
            }
        }
        catch (Exception error)
        {
            Save("database-open-preflight.json", new { IsSuccess = false, TimingStarted = _clock.IsRunning,
                Databases = databaseOpens, Error = error.ToString() });
            throw;
        }
        Save("database-open-preflight.json", new { IsSuccess = true, TimingStarted = _clock.IsRunning, Databases = databaseOpens });
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Path.Combine(_bundle, "evidence.db"), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString()))
        {
            connection.Open();
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT COUNT(*), COUNT(DISTINCT domain_fqdn), (SELECT COUNT(*) FROM ace) FROM captured_object";
            using var row = query.ExecuteReader();
            Require(row.Read() && row.GetInt64(0) == 34700 && row.GetInt64(1) == 9 && row.GetInt64(2) == 590000,
                "The retained workload shape differs.");
        }
        var parent = "OU=Accounts,OU=Operations,OU=Directory,OU=Synthetic,DC=measure,DC=lab";
        _subject = "CN=" + "User00000-00000".PadRight(97 - parent.Length - 4, 'x') + "," + parent;
        Save("setup.json", new
        {
            Input, CopiedBundle = _bundle, Subject = _subject, JudgementGeneration = Generation,
            DerivationGeneration = Derivation, InputFingerprints = Files, Objects = 34700, Domains = 9, PhysicalAces = 590000,
            Runtime = RuntimeInformation.FrameworkDescription, OS = RuntimeInformation.OSDescription,
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(), Environment.ProcessorCount,
            ProcessorOverride = Environment.GetEnvironmentVariable("DOTNET_PROCESSOR_COUNT"),
            Environment.MachineName, Environment.ProcessId, Environment.ProcessPath,
            ProcessHash = Hash(Environment.ProcessPath!), DiagnosticTimeoutMinutes = 30,
            ProductionRequesterPolicy = "Disabled (not invoked)", LegacyDiscoveryBudget = (string?)null,
            TemporaryDirectory = Path.GetTempPath(),
            Sources = _sources, HeadAtApproval = "6cabc9edec29b517e4d4e9c66322033343a6340b",
            Boundary = "Retained reduced synthetic evidence; saved-section dispatcher/layout only, not physical-display or full-audit acceptance",
        });
        var opened = JudgementReader.Open(_bundle);
        Save("reader-preflight.json", new { opened.IsSuccess, opened.Error, TimingStarted = _clock.IsRunning,
            Description = opened.IsSuccess ? opened.Value.Description : null });
        if (opened.IsSuccess) opened.Value.Dispose();
        Require(opened.IsSuccess, "The current reader refused the copied saved generation: " + opened.Error?.Description);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _thread = new Thread(() =>
        {
            _dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(_dispatcher));
            try
            {
                _source = new BundleAssetSource();
                var assets = new AssetsViewModel(_source);
                assets.Show(_bundle, false);
                assets.OpenObject(new(new(_subject, "User", null, "user", "DC=measure,DC=lab")));
                _object = assets.Opened ?? throw new InvalidOperationException("The copied object could not be opened: " + assets.Refusal);
                _section = (SavedTier0PathSectionViewModel)_object.Section(ObjectSectionCatalog.SavedTier0Path)!;
                Require(_section.Result == NotRead, "Setup unexpectedly read a saved path.");
                var resources = (ResourceDictionary)Application.LoadComponent(
                    new Uri("/SecureAD;component/Views/Sections/ObjectSectionTemplates.xaml", UriKind.Relative));
                var template = (DataTemplate)resources[new DataTemplateKey(typeof(SavedTier0PathSectionViewModel))];
                _pane = new Grid();
                _pane.Children.Add(new ContentPresenter { Content = _section, ContentTemplate = template });
                Layout();
                ready.SetResult();
                Dispatcher.Run();
            }
            catch (Exception error) { ready.TrySetException(error); _finished.TrySetException(error); }
            finally { _source?.Dispose(); }
        }) { IsBackground = true, Name = "P246 saved-path opening dispatcher" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        ready.Task.WaitAsync(TimeSpan.FromMinutes(5)).GetAwaiter().GetResult();
        SaveBinaries("before");
    }

    public double OpenSavedSection(bool navigateAway)
    {
        Require(!_invoked, "Each prepared adapter permits exactly one opening, without warmup or averaging.");
        _invoked = true;
        _navigateAway = navigateAway;
        _dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(() =>
        {
            try
            {
                _section.PropertyChanged += (_, _) => _dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(CheckFinished));
                _allocated = GC.GetTotalAllocatedBytes(true);
                _cpu = Process.GetCurrentProcess().TotalProcessorTime;
                _collections = [GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2)];
                _clock.Start();
                _heartbeat = new System.Threading.Timer(_ =>
                {
                    var requested = _clock.Elapsed.TotalMilliseconds;
                    _dispatcher.BeginInvoke(DispatcherPriority.Send, new Action(() =>
                    {
                        _heartbeatRequested = requested;
                        _heartbeatDelivered = _clock.Elapsed.TotalMilliseconds;
                        CheckFinished();
                    }));
                }, null, 100, Timeout.Infinite);
                if (navigateAway)
                    _navigation = new System.Threading.Timer(_ =>
                    {
                        var requested = _clock.Elapsed.TotalMilliseconds;
                        _dispatcher.BeginInvoke(DispatcherPriority.Send, new Action(() => Navigate(requested)));
                    }, null, 1000, Timeout.Infinite);
                _object.Show(ObjectSectionCatalog.SavedTier0Path);
                _selectionReturned = _clock.Elapsed.TotalMilliseconds;
                _dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(CheckFinished));
            }
            catch (Exception error) { Fail(error); }
        }));
        try { return _finished.Task.WaitAsync(TimeSpan.FromMinutes(30)).GetAwaiter().GetResult(); }
        catch (Exception error)
        {
            Save("failure.json", new { Error = error.ToString(), ElapsedMs = _clock.Elapsed.TotalMilliseconds });
            Dispose();
            throw;
        }
    }

    private void Navigate(double requested)
    {
        try
        {
            _navigationRequested = requested;
            _navigationDeliveredAt = _clock.Elapsed.TotalMilliseconds;
            _navigationWasInFlight = _section.Result is NotRead or Loading;
            _object.Show(ObjectSectionCatalog.Overview);
            _navigationDelivered = true;
            CheckFinished();
        }
        catch (Exception error) { Fail(error); }
    }

    private void CheckFinished()
    {
        if (_done || !_invoked || _selectionReturned is null) return;
        try
        {
            // The corrected baseline has no worker. If the asynchronous implementation exposes its
            // completion task, observe it without changing this frozen adapter or substituting a fake read.
            var completion = _section.GetType().GetProperty("ReadCompletion", BindingFlags.Public | BindingFlags.Instance)
                ?.GetValue(_section) as Task;
            if (completion is { IsCompleted: false })
            {
                _ = completion.ContinueWith(_ => _dispatcher.BeginInvoke(DispatcherPriority.ContextIdle,
                    new Action(CheckFinished)), CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);
                return;
            }
            if (_navigateAway ? !_navigationDelivered : _section.Result is NotRead or Loading) return;
            if (!_navigationWasInFlight)
            {
                Require(_section.Result == "Supported route recorded", "Saved proof did not validate: " + _section.Result + " " + _section.Detail);
                Require(_section.Provenance.Contains(Generation, StringComparison.OrdinalIgnoreCase)
                    && _section.Provenance.Contains(Derivation, StringComparison.OrdinalIgnoreCase)
                    && _section.Steps.Count > 0, "Displayed proof is not bound to the retained generations.");
            }
            else
                Require(_section.Result == NotRead && _section.Steps.Count == 0 && _section.Provenance.Length == 0,
                    "Cancelled navigation published a saved result.");
            if (!_heartbeatDelivered.HasValue) return;
            Layout();
            _clock.Stop();
            _done = true;
            _heartbeat?.Dispose();
            _navigation?.Dispose();
            using var process = Process.GetCurrentProcess();
            Save("measurement.json", new
            {
                NavigateAway = _navigateAway, ElapsedMs = _clock.Elapsed.TotalMilliseconds,
                SelectionReturnedMs = _selectionReturned, HeartbeatRequestedMs = _heartbeatRequested,
                HeartbeatDeliveredMs = _heartbeatDelivered, DispatcherQueueDelayMs = _heartbeatDelivered - _heartbeatRequested,
                NavigationRequestedMs = _navigationRequested, NavigationDeliveredMs = _navigationDeliveredAt,
                NavigationQueueDelayMs = _navigationDeliveredAt - _navigationRequested,
                CancellationExercisedDuringRead = _navigationWasInFlight,
                CancellationSettledMs = _navigationWasInFlight ? _clock.Elapsed.TotalMilliseconds - _navigationDeliveredAt : null,
                WorkerCompletionTaskObserved = completion is not null,
                AllocatedBytes = GC.GetTotalAllocatedBytes(true) - _allocated,
                CpuMs = (process.TotalProcessorTime - _cpu).TotalMilliseconds,
                Gen0 = GC.CollectionCount(0) - _collections[0], Gen1 = GC.CollectionCount(1) - _collections[1],
                Gen2 = GC.CollectionCount(2) - _collections[2], EndWorkingSetBytes = process.WorkingSet64,
                EndPrivateBytes = process.PrivateMemorySize64, ProcessLifetimePeakWorkingSetBytes = process.PeakWorkingSet64,
                Caveat = "One opening with profiler/observer overhead; process peak is lifetime, not opening-only; no physical-display acceptance",
            });
            Save("display.json", new { _section.Result, _section.Detail, _section.Provenance, _section.Distance,
                _section.Destination, _section.AutomaticChecks, _section.SavedQuestions, _section.Steps, _section.Limitations });
            _finished.TrySetResult(_clock.Elapsed.TotalMilliseconds);
        }
        catch (Exception error) { Fail(error); }
    }

    private void Fail(Exception error)
    {
        _done = true;
        _clock.Stop();
        _heartbeat?.Dispose();
        _navigation?.Dispose();
        Save("refused-display.json", new { _section.Result, _section.Detail, _section.Provenance,
            _section.Steps, _section.AutomaticChecks, _section.SavedQuestions });
        _finished.TrySetException(error);
    }

    private void Layout()
    {
        _pane.Measure(new Size(1000, 700));
        _pane.Arrange(new Rect(0, 0, 1000, 700));
        _pane.UpdateLayout();
    }

    private void SnapshotSources()
    {
        var next = Path.Combine(Repository, "next");
        var roots = new[] { Path.Combine(next, "src"), Path.Combine(next, "tests"), Path.Combine(next, "tools") }
            .Concat(Directory.GetDirectories(next, "BenchmarkSuite*"));
        var files = roots.SelectMany(root => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            .Where(path => !path.Contains("\\bin\\", StringComparison.OrdinalIgnoreCase)
                && !path.Contains("\\obj\\", StringComparison.OrdinalIgnoreCase))
            .Where(path => Path.GetExtension(path) is ".cs" or ".csproj" or ".resx" or ".xaml" or ".props" or ".targets")
            .Concat(Directory.EnumerateFiles(Repository, "*.props")).Order(StringComparer.Ordinal);
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(Repository, file);
            var copy = Path.Combine(_output, "source", relative + ".snapshot");
            Directory.CreateDirectory(Path.GetDirectoryName(copy)!);
            File.Copy(file, copy, false);
            _sources.Add(relative, Hash(copy));
            Require(Hash(file) == _sources[relative], "Source changed while recording provenance: " + relative);
        }
    }

    private void SaveBinaries(string phase)
    {
        var binaries = AppDomain.CurrentDomain.GetAssemblies()
            .Where(value => !value.IsDynamic && value.Location.Length > 0)
            .Where(value => value.GetName().Name!.StartsWith("SecureAD", StringComparison.OrdinalIgnoreCase)
                || value.GetName().Name!.StartsWith("Benchmark", StringComparison.OrdinalIgnoreCase)
                || value.GetName().Name!.Contains("Sqlite", StringComparison.OrdinalIgnoreCase)
                || value.GetName().Name!.StartsWith("SQLitePCL", StringComparison.OrdinalIgnoreCase))
            .Select(value => new { value.Location, Hash = Hash(value.Location), Module = value.ManifestModule.ModuleVersionId,
                Configuration = value.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration,
                Version = value.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion }).ToArray();
        var directory = Path.Combine(_output, "binaries-" + phase);
        Directory.CreateDirectory(directory);
        foreach (var binary in binaries) File.Copy(binary.Location, Path.Combine(directory, Path.GetFileName(binary.Location)), false);
        Save("binaries-" + phase + ".json", binaries);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _heartbeat?.Dispose();
        _navigation?.Dispose();
        if (_thread is { IsAlive: true })
        {
            _dispatcher.BeginInvokeShutdown(DispatcherPriority.Background);
            Require(_thread.Join(TimeSpan.FromSeconds(30)), "The measurement dispatcher did not stop; retained failure, not a cancellation bound.");
        }
        if (_output is null) return;
        SaveBinaries("after");
        var sourceDrift = _sources.Where(value => Hash(Path.Combine(Repository, value.Key)) != value.Value).Select(value => value.Key).ToArray();
        var inputDrift = Files.Where(value => Hash(Path.Combine(Input, value.Key)) != value.Value
            || Hash(Path.Combine(_bundle, value.Key)) != value.Value).Select(value => value.Key).ToArray();
        Save("integrity.json", new { SourceDrift = sourceDrift, InputDrift = inputDrift,
            Accepted = _finished.Task.IsCompletedSuccessfully && sourceDrift.Length == 0 && inputDrift.Length == 0 });
        Require(sourceDrift.Length == 0 && inputDrift.Length == 0, "Source or sealed input changed during opening.");
    }

    private void Save(string name, object value)
    {
        using var file = new FileStream(Path.Combine(_output, name), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, value, Json);
    }

    private static string Hash(string path)
    {
        using var file = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(file));
    }

    private static void Require(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }
}
