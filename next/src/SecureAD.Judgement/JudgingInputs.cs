using System.Collections;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class JudgingInputs : IDisposable
{
    private static readonly Meter SelectionMeter = new("SecureAD.Judgement.Inputs");
    private static readonly Counter<long> SelectionRequests = SelectionMeter.CreateCounter<long>("guard.logical_requests");
    private static readonly Counter<long> CaptureResolves = SelectionMeter.CreateCounter<long>("guard.capture_resolves");
    private static readonly Counter<long> DerivationResolves = SelectionMeter.CreateCounter<long>("guard.derivation_resolves");
    private static readonly Histogram<double> SelectionMilliseconds = SelectionMeter.CreateHistogram<double>("guard.current_ms");
    private static readonly Counter<long> InputBindings = SelectionMeter.CreateCounter<long>("inputs.bindings");
    private sealed record InputSet(ProtectedRunFiles Files, ProtectedStoreFile Evidence,
        Result<StoreRootManifest> Derivation);
    private readonly InputSet _inputs;
    private readonly JudgingInputs? _parent;
    private ProtectedRunFiles? _ownedFiles;
    private readonly CancellationToken _cancellationToken;
    private ProtectedStoreFile? _derivedFile;
    private DerivationReader? _derivation;
    private StoredDerivation? _facts;
    private CapturedMembershipInput? _membership;
    private RequesterMembershipContext? _requesterMemberships;
    private Result<IReadOnlyDictionary<string, NamingContextKind>>? _contexts;
    private OwnerImplicitRightsSetting? _ownerRights;
    private readonly Dictionary<string, string?> _domainSids = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    private JudgingInputs(InputSet inputs, BundleReader bundle, CancellationToken cancellationToken,
        JudgingInputs? parent)
    {
        _inputs = inputs;
        _parent = parent;
        Bundle = bundle;
        _cancellationToken = cancellationToken;
    }

    internal BundleReader Bundle { get; }
    internal string Directory => _inputs.Evidence.BundleDirectory;
    internal string EvidenceSeal => _inputs.Evidence.Fingerprint;
    internal StoredDerivation Facts => _facts ?? throw OwnershipAuditStorage.InvalidProof();

    internal OwnerImplicitRightsSetting OwnerRights
    {
        get
        {
            CheckLifetime();
            return _ownerRights ??= DirectoryHeuristics.OwnerImplicitRights(Bundle.ReadForestHeuristics());
        }
    }

    internal static Result<JudgingInputs> Open(string directory, CancellationToken cancellationToken)
    {
        var files = new ProtectedRunFiles(directory);
        var accepted = false;
        try
        {
            var opened = Open(files, cancellationToken);
            if (opened.IsSuccess)
            {
                opened.Value._ownedFiles = files;
                accepted = true;
            }
            return opened;
        }
        finally { if (!accepted) files.Dispose(); }
    }

    internal static Result<JudgingInputs> Open(ProtectedRunFiles files, CancellationToken cancellationToken)
    {
        var file = files.Capture(StoreSegmentRole.Evidence, cancellationToken);
        if (!file.IsSuccess) return Result<JudgingInputs>.Failure(file.Error);
        var selected = AnalysisStoreLifecycle.ResolveRoot(files.Directory, AnalysisStoreKind.Derivation);
        if (selected.IsSuccess && selected.Value.EvidenceSeal != file.Value.Fingerprint)
            selected = Result<StoreRootManifest>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "ProtectedStoreGenerationChanged", ErrorSeverity.Failed,
                "The selected analysis belongs to another capture.", files.Directory));
        cancellationToken.ThrowIfCancellationRequested();
        var opened = BundleReader.Open(file.Value, cancellationToken);
        if (!opened.IsSuccess) return Result<JudgingInputs>.Failure(opened.Error);
        if (InputBindings.Enabled) InputBindings.Add(1, new KeyValuePair<string, object?>("bundle", files.Directory));
        return new JudgingInputs(new(files, file.Value, selected), opened.Value, cancellationToken, parent: null);
    }

    internal Result<JudgingInputs> Fork(CancellationToken cancellationToken)
    {
        CheckLifetime();
        cancellationToken.ThrowIfCancellationRequested();
        var opened = BundleReader.Open(_inputs.Evidence, cancellationToken);
        return opened.IsSuccess ? new JudgingInputs(_inputs, opened.Value, cancellationToken, this)
            : Result<JudgingInputs>.Failure(opened.Error);
    }

    internal Result<DerivationReader> OpenDerivation() => OpenDerivationCore(true);

    internal Result<DerivationReader> OpenMembershipDerivation() => OpenDerivationCore(false);

    private Result<DerivationReader> OpenDerivationCore(bool readFacts)
    {
        CheckLifetime();
        if (_derivation is not null)
        {
            try
            {
                if (readFacts && _facts is null) _facts = Freeze(_derivation.Read());
            }
            catch (Exception error) when (error is SqliteException or FormatException or ArgumentException or InvalidOperationException)
            {
                _cancellationToken.ThrowIfCancellationRequested();
                return Result<DerivationReader>.Failure(AuditError.Create(ErrorCategory.Evidence, "DerivationUnreadable",
                    ErrorSeverity.Failed, $"The verified derivation could not be read: {error.Message}", Directory));
            }
            CheckLifetime();
            return _derivation;
        }
        var selected = _inputs.Derivation;
        if (!selected.IsSuccess) return Result<DerivationReader>.Failure(selected.Error);
        var file = _inputs.Files.BoundDerivation(_inputs.Evidence, selected.Value, _cancellationToken);
        if (!file.IsSuccess) return Result<DerivationReader>.Failure(file.Error);
        DerivationReader? reader = null;
        var accepted = false;
        try
        {
            var opened = DerivationReader.Open(file.Value, _cancellationToken);
            if (!opened.IsSuccess) return opened;
            reader = opened.Value;
            // Full consumers must still validate stored products; selected membership questions
            // do not depend on unrelated protected-principal facts.
            var facts = readFacts ? reader.Read() : null;
            CheckLifetime();
            if (reader.Description.GenerationId != selected.Value.GenerationId
                || reader.Description.EvidenceSeal != EvidenceSeal || file.Value.Root.Hash != selected.Value.Hash)
                throw OwnershipAuditStorage.InvalidProof();
            _facts = facts is null ? null : Freeze(facts);
            _derivedFile = file.Value;
            _derivation = reader;
            accepted = true;
            return reader;
        }
        catch (Exception error) when (error is SqliteException or FormatException or ArgumentException or InvalidOperationException)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            return Result<DerivationReader>.Failure(AuditError.Create(ErrorCategory.Evidence, "DerivationUnreadable",
                ErrorSeverity.Failed, $"The verified derivation could not be read: {error.Message}", Directory));
        }
        finally
        {
            if (!accepted)
            {
                reader?.Dispose();
            }
        }
    }

    internal CapturedMembershipInput ReadMembershipInput()
    {
        CheckLifetime();
        if (_membership is not null) return _membership;
        var input = (_derivation ?? throw OwnershipAuditStorage.InvalidProof()).ReadMembershipInput();
        if (input.DerivationGenerationId != Facts.Description.GenerationId) throw OwnershipAuditStorage.InvalidProof();
        return _membership = input.Prepare(_cancellationToken);
    }

    internal Result<IReadOnlyDictionary<string, NamingContextKind>> ReadNamingContexts()
    {
        CheckLifetime();
        if (_contexts is { } existing) return existing;
        var read = Bundle.ReadNamingContexts();
        return (_contexts = read.IsSuccess
            ? Result<IReadOnlyDictionary<string, NamingContextKind>>.Success(
                read.Value.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase))
            : read).Value;
    }

    internal RequesterMembershipContext RequesterMemberships(Tier0InputBinding binding,
        IReadOnlyDictionary<string, Tier0Target> identities, CancellationToken cancellationToken)
    {
        CheckLifetime();
        if (_requesterMemberships is { } existing)
        {
            existing.RequireBinding(binding);
            return existing;
        }
        var derivation = OpenDerivation();
        var contexts = ReadNamingContexts();
        var scope = Bundle.ReadScope();
        if (!derivation.IsSuccess || !contexts.IsSuccess || !scope.IsSuccess) throw Tier0PathStorage.InvalidProof();
        var result = new RequesterMembershipContext(derivation.Value, binding, Bundle.ReadObjectAttributes, identities, contexts.Value, cancellationToken);
        result.BindForestScope(scope.Value);
        return _requesterMemberships = result;
    }

    internal string? ReadDomainSid(string domain)
    {
        CheckLifetime();
        if (_domainSids.TryGetValue(domain, out var sid)) return sid;
        var root = Bundle.ReadObjectAttributes(string.Join(',', domain.Split('.').Select(part => "DC=" + part)));
        var value = root?.Find("objectSid")?.OnlyValue;
        sid = value?.Bytes is { } bytes ? Sid.ToText(bytes) : value?.Text;
        _domainSids.Add(domain, sid);
        return sid;
    }

    internal Tier0InputBinding Binding()
    {
        CheckLifetime();
        var generation = _derivedFile?.Generation?.GenerationId ?? throw OwnershipAuditStorage.InvalidProof();
        var contexts = ReadNamingContexts();
        if (!contexts.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        return OwnershipAuditRun.Binding(Directory, EvidenceSeal, generation, Bundle.Description.ForestFqdn, contexts.Value);
    }

    internal void RequireFor(JudgementDescription description)
    {
        CheckLifetime();
        if (description.EvidenceSeal != EvidenceSeal
            || description.DerivationGenerationId != _derivedFile?.Generation?.GenerationId)
            throw OwnershipAuditStorage.InvalidProof();
    }

    internal void RequireActiveInputs() => CheckLifetime();

    internal void RequireSameInputs(JudgingInputs other)
    {
        ArgumentNullException.ThrowIfNull(other);
        CheckLifetime();
        other.CheckLifetime();
        if (!ReferenceEquals(_inputs, other._inputs))
            throw OwnershipAuditStorage.InvalidProof();
    }

    private void RequireSelectedForPublication()
    {
        CheckLifetime();
        var started = SelectionMilliseconds.Enabled || LapsCalculationDiagnostics.IsActive ? Stopwatch.GetTimestamp() : 0;
        RecordSelection(SelectionRequests);
        try
        {
            RecordSelection(CaptureResolves);
            Result<StoreRootManifest> capture;
            using (LapsCalculationDiagnostics.Measure("capture-selection"))
                capture = AnalysisStoreLifecycle.ResolveCapture(Directory);
            if (!capture.IsSuccess || capture.Value.Hash != _inputs.Evidence.Root.Hash)
                throw OwnershipAuditStorage.InvalidProof();
            if (_derivedFile?.Generation is not null)
            {
                RecordSelection(DerivationResolves);
                Result<StoreRootManifest> selected;
                using (LapsCalculationDiagnostics.Measure("derivation-selection"))
                    selected = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Derivation);
                if (!selected.IsSuccess || !MatchesDerivation(selected.Value, _derivedFile))
                    throw OwnershipAuditStorage.InvalidProof();
            }
            CheckLifetime();
        }
        finally
        {
            if (started != 0)
            {
                var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                SelectionMilliseconds.Record(elapsed,
                    new KeyValuePair<string, object?>("bundle", Directory));
                LapsCalculationDiagnostics.RecordCurrentSelection(elapsed);
            }
        }
    }

    private static bool MatchesDerivation(StoreRootManifest selected, ProtectedStoreFile? file) =>
        file?.Generation is not { } generation
            || selected.GenerationId == generation.GenerationId && selected.Hash == file.Root.Hash;

    private void RecordSelection(Counter<long> counter, long count = 1)
    {
        if (counter.Enabled) counter.Add(count, new KeyValuePair<string, object?>("bundle", Directory));
    }

    internal IDisposable? ProtectPublication(JudgementDescription description)
    {
        RequireFor(description);
        RequireSelectedForPublication();
        if (_derivedFile is null) return null;
        // Pin the mutable selection only for publication, closing the gap between its last
        // check and the judgement manifest replacement without locking it for the whole run.
        var selection = new FileStream(AnalysisStoreLifecycle.ManifestPath(Directory, AnalysisStoreKind.Derivation),
            FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            RequireFor(description);
            RequireSelectedForPublication();
            return selection;
        }
        catch
        {
            selection.Dispose();
            throw;
        }
    }

    private void CheckLifetime()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _cancellationToken.ThrowIfCancellationRequested();
        _parent?.CheckLifetime();
    }

    private static StoredDerivation Freeze(StoredDerivation facts) => facts with
    {
        Phases = facts.Phases.ToImmutableArray(),
        Completeness = facts.Completeness with
        {
            PartialGroups = facts.Completeness.PartialGroups.ToImmutableArray(),
            MissingPartitions = facts.Completeness.MissingPartitions.ToImmutableArray(),
            UnresolvedTrustees = facts.Completeness.UnresolvedTrustees.ToImmutableArray(),
        },
        ProtectedPrincipals = facts.ProtectedPrincipals with
        {
            Value = facts.ProtectedPrincipals.Value is not { } principals ? null : principals with
            {
                Catalogue = principals.Catalogue.ToImmutableArray(),
                Principals = principals.Principals.Select(principal => principal with
                {
                    Path = principal.Path.ToImmutableArray(),
                    MembershipRoutes = FreezeRoutes(principal.MembershipRoutes),
                }).ToImmutableArray(),
            },
        },
        AttributeVisibility = facts.AttributeVisibility with
        {
            Value = facts.AttributeVisibility.Value is not { } visibility ? null
                : new StoredAttributeVisibility(visibility.Attributes.ToImmutableArray()),
        },
        NestingCycles = facts.NestingCycles with
        {
            Cycles = facts.NestingCycles.Cycles?.Select(cycle => (IReadOnlyList<int>)cycle.ToImmutableArray()).ToImmutableArray(),
        },
    };

    internal static MembershipRouteSummary FreezeRoutes(MembershipRouteSummary routes) => routes with
    {
        Memberships = routes.Memberships.Select(group => group with
        {
            Routes = group.Routes.Select(route => route with { Steps = route.Steps.ToImmutableArray() }).ToImmutableArray(),
        }).ToImmutableArray(),
    };

    private static ObjectAttributes FreezeAttributes(ObjectAttributes subject) => subject.Snapshot();

    internal sealed class AttributeSnapshot(IEnumerable<ObjectAttributes> values) : IReadOnlyList<ObjectAttributes>
    {
        private readonly ImmutableArray<ObjectAttributes> _values = values.Select(FreezeAttributes).ToImmutableArray();
        public int Count => _values.Length;
        public ObjectAttributes this[int index] => _values[index];
        public IEnumerator<ObjectAttributes> GetEnumerator() => ((IEnumerable<ObjectAttributes>)_values).GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _requesterMemberships?.Dispose();
        _requesterMemberships = null;
        try { _derivation?.Dispose(); }
        finally
        {
            try { Bundle.Dispose(); }
            finally
            {
                _ownedFiles?.Dispose();
                _membership = null;
                _facts = null;
            }
        }
    }
}
