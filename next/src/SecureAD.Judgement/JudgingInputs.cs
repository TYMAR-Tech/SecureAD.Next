using System.Collections;
using System.Collections.Immutable;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class JudgingInputs : IDisposable
{
    private readonly ProtectedStoreFile _evidence;
    private readonly CancellationToken _cancellationToken;
    private ProtectedStoreFile? _derivedFile;
    private DerivationReader? _derivation;
    private StoredDerivation? _facts;
    private CapturedMembershipInput? _membership;
    private Result<IReadOnlyDictionary<string, NamingContextKind>>? _contexts;
    private OwnerImplicitRightsSetting? _ownerRights;
    private bool _disposed;

    private JudgingInputs(ProtectedStoreFile evidence, BundleReader bundle, CancellationToken cancellationToken)
    {
        _evidence = evidence;
        Bundle = bundle;
        _cancellationToken = cancellationToken;
    }

    internal BundleReader Bundle { get; }
    internal string Directory => _evidence.BundleDirectory;
    internal string EvidenceSeal => _evidence.Fingerprint;
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
        var file = ProtectedStoreFile.OpenEvidence(directory, cancellationToken);
        if (!file.IsSuccess) return Result<JudgingInputs>.Failure(file.Error);
        var accepted = false;
        try
        {
            var opened = BundleReader.Open(file.Value, cancellationToken);
            if (!opened.IsSuccess) return Result<JudgingInputs>.Failure(opened.Error);
            accepted = true;
            return new JudgingInputs(file.Value, opened.Value, cancellationToken);
        }
        finally { if (!accepted) file.Value.Dispose(); }
    }

    internal Result<DerivationReader> OpenDerivation()
    {
        CheckLifetime();
        if (_derivation is not null)
        {
            RequireCurrent();
            return _derivation;
        }
        var selected = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation);
        if (!selected.IsSuccess) return Result<DerivationReader>.Failure(selected.Error);
        var file = ProtectedStoreFile.OpenAnalysis(Directory, selected.Value, _cancellationToken);
        if (!file.IsSuccess) return Result<DerivationReader>.Failure(file.Error);
        DerivationReader? reader = null;
        var accepted = false;
        try
        {
            var opened = DerivationReader.Open(file.Value, _cancellationToken);
            if (!opened.IsSuccess) return opened;
            reader = opened.Value;
            // The protected overload validates the header, not the stored products. Keep the
            // full reading that the directory-based opener required, and consume it only once.
            var facts = reader.Read();
            var current = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation);
            if (!current.IsSuccess || current.Value != selected.Value || facts.Description.EvidenceSeal != EvidenceSeal)
                throw OwnershipAuditStorage.InvalidProof();
            _facts = Freeze(facts);
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
                file.Value.Dispose();
            }
        }
    }

    internal CapturedMembershipInput ReadMembershipInput()
    {
        CheckLifetime();
        if (_membership is not null) return _membership;
        var input = (_derivation ?? throw OwnershipAuditStorage.InvalidProof()).ReadMembershipInput();
        if (input.DerivationGenerationId != Facts.Description.GenerationId) throw OwnershipAuditStorage.InvalidProof();
        var objects = ImmutableArray.CreateBuilder<ObjectAttributes>();
        foreach (var subject in input.Objects)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            objects.Add(subject with
            {
                Attributes = subject.Attributes.Select(attribute => attribute with
                {
                    Values = new AttributeValues(attribute.Values),
                }).ToImmutableArray(),
            });
        }
        return _membership = input with { Objects = objects.ToImmutable() };
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

    internal Tier0InputBinding Binding()
    {
        RequireCurrent();
        var generation = _derivedFile?.Generation?.GenerationId ?? throw OwnershipAuditStorage.InvalidProof();
        var contexts = ReadNamingContexts();
        if (!contexts.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        return OwnershipAuditRun.Binding(Directory, EvidenceSeal, generation, Bundle.Description.ForestFqdn, contexts.Value);
    }

    internal void RequireFor(JudgementDescription description)
    {
        RequireCurrent();
        if (description.EvidenceSeal != EvidenceSeal
            || description.DerivationGenerationId != _derivedFile?.Generation?.GenerationId)
            throw OwnershipAuditStorage.InvalidProof();
    }

    internal void RequireCurrent()
    {
        CheckLifetime();
        if (_derivedFile?.Generation is not { } generation) return;
        var selected = AnalysisStoreLifecycle.Resolve(Directory, AnalysisStoreKind.Derivation);
        if (!selected.IsSuccess || selected.Value != generation) throw OwnershipAuditStorage.InvalidProof();
    }

    internal IDisposable? ProtectPublication(JudgementDescription description)
    {
        RequireFor(description);
        if (_derivedFile is null) return null;
        // Pin the mutable selection only for publication, closing the gap between its last
        // check and the judgement manifest replacement without locking it for the whole run.
        var selection = new FileStream(AnalysisStoreLifecycle.ManifestPath(Directory, AnalysisStoreKind.Derivation),
            FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            RequireFor(description);
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

    // Text records are immutable; binary values need a detached view, just like prepared ACE data.
    private sealed class AttributeValues(IReadOnlyList<AttributeValue> values) : IReadOnlyList<AttributeValue>
    {
        private readonly AttributeValue[] _values = values.ToArray();
        public int Count => _values.Length;
        public AttributeValue this[int index] => _values[index].Bytes is null ? _values[index]
            : _values[index] with { Bytes = _values[index].Bytes!.ToArray() };
        public IEnumerator<AttributeValue> GetEnumerator()
        {
            for (var index = 0; index < Count; index++) yield return this[index];
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _derivation?.Dispose(); }
        finally
        {
            try { Bundle.Dispose(); }
            finally
            {
                _derivedFile?.Dispose();
                _evidence.Dispose();
                _membership = null;
                _facts = null;
            }
        }
    }
}
