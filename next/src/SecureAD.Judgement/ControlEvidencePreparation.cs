using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal sealed class ControlEvidencePreparation
{
    internal const string MeterName = "SecureAD.Judgement.ControlPreparation";
    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> PermissionPreparations = Meter.CreateCounter<long>("control.permission_preparations");
    private static readonly Counter<long> SequencePreparations = Meter.CreateCounter<long>("control.sequence_preparations");
    private static readonly Counter<long> RoutePreparations = Meter.CreateCounter<long>("control.route_preparations");
    private static readonly Counter<long> PermissionReads = Meter.CreateCounter<long>("control.permission_reads");
    private static readonly Counter<long> RouteReads = Meter.CreateCounter<long>("control.route_reads");

    internal sealed record Edge(ControlEdge Value, ImmutableArray<SharedPermissionStorage.PreparedEntry> Entries,
        SharedProofStorage.PreparedRoutes Routes);
    internal sealed record Assessment(FullControlAssessment Value, SharedProofStorage.PreparedRoutes Routes);

    internal sealed class Sequence(ImmutableArray<PermissionEntry> originals,
        ImmutableArray<SharedPermissionStorage.PreparedEntry> entries, Guid generation)
    {
        private string? _payload;
        private ImmutableArray<PermissionEntry> _originals = originals;
        internal ImmutableArray<PermissionEntry> Originals => _originals;
        internal ImmutableArray<SharedPermissionStorage.PreparedEntry> Entries { get; } = entries;
        internal string Payload
        {
            get
            {
                if (_payload is not null) return _payload;
                SequencePreparations.Add(1, Tag(generation));
                return _payload = JsonSerializer.Serialize(Originals, ProofSerialization.Options);
            }
        }
        internal byte[] Fingerprint => SHA256.HashData(Encoding.UTF8.GetBytes(Payload));
        internal void ReleaseOriginals() => _originals = [];
    }

    private readonly Guid? _generation;
    private readonly Guid? _derivation;

    private ControlEvidencePreparation(ControlObjectEvaluation value, Guid? generation, Guid? derivation,
        ImmutableArray<Edge> edges, ImmutableArray<Assessment> assessments, Sequence? source)
    {
        Value = value;
        _generation = generation;
        _derivation = derivation;
        Edges = edges;
        Assessments = assessments;
        Source = source;
    }

    internal ControlObjectEvaluation Value { get; }
    internal ImmutableArray<Edge> Edges { get; }
    internal ImmutableArray<Assessment> Assessments { get; }
    internal Sequence? Source { get; }

    internal void RequireFor(Guid generation, Guid? derivation)
    {
        if (_generation is { } bound && (bound != generation || _derivation != derivation)
            || Edges.Any(edge => edge.Value.GenerationId != generation || edge.Value.DerivationGenerationId != derivation)
            || Assessments.Any(assessment => assessment.Value.GenerationId != generation || assessment.Value.DerivationGenerationId != derivation))
            throw FullControlEvaluator.InvalidProof();
    }

    internal static ControlEvidencePreparation Create(ControlObjectEvaluation value, Guid generation,
        Guid? derivation, CancellationToken cancellationToken = default)
        => CreateCore(value, generation, derivation, cancellationToken);

    private static ControlEvidencePreparation CreateCore(ControlObjectEvaluation value, Guid? generation,
        Guid? derivation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(value);
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(value.Target) || value.Edges is null || value.FullControlAssessments is null)
            throw FullControlEvaluator.InvalidProof();
        return new Builder(value.Target, generation, derivation, cancellationToken).Create(value);
    }

    internal static ControlEvidencePreparation Create(ControlObjectEvaluation value)
        // Low-level row verification carries independent bindings; production supplies the pinned resource generation.
        => CreateCore(value, null, null, default);

    internal static void PreparingPermission(Guid generation) => PermissionPreparations.Add(1, Tag(generation));
    internal static void PreparingRoutes(Guid generation) => RoutePreparations.Add(1, Tag(generation));
    internal static void ReadingPermission(Guid generation) => PermissionReads.Add(1, Tag(generation));
    internal static void ReadingRoutes(Guid generation) => RouteReads.Add(1, Tag(generation));
    private static KeyValuePair<string, object?> Tag(Guid generation) => new("generation", generation.ToString("D"));

    private sealed class Builder(string target, Guid? generation, Guid? derivation, CancellationToken token)
    {
        private readonly Dictionary<Guid, Dictionary<PermissionEntry, (PermissionEntry Original, SharedPermissionStorage.PreparedEntry Reference)>> _entries = [];
        private readonly Dictionary<Guid, Dictionary<IReadOnlyList<PermissionEntry>, Sequence>> _sequences = [];
        private readonly Dictionary<(MembershipRouteSummary Routes, Guid Generation, Guid? Derivation, int Catalogue), SharedProofStorage.PreparedRoutes> _routes = [];

        private Sequence Entries(IReadOnlyList<PermissionEntry> source, Guid sourceGeneration)
        {
            if (!_entries.TryGetValue(sourceGeneration, out var values))
                _entries.Add(sourceGeneration, values = new(ReferenceEqualityComparer.Instance));
            if (!_sequences.TryGetValue(sourceGeneration, out var sequences))
                _sequences.Add(sourceGeneration, sequences = new(ReferenceEqualityComparer.Instance));
            if (sequences.TryGetValue(source, out var sequence)) return sequence;
            var originals = ImmutableArray.CreateBuilder<PermissionEntry>(source.Count);
            var references = ImmutableArray.CreateBuilder<SharedPermissionStorage.PreparedEntry>(source.Count);
            foreach (var entry in source)
            {
                token.ThrowIfCancellationRequested();
                if (entry is null || entry.Trustee is null || entry.ApplicationData is null)
                    throw FullControlEvaluator.InvalidProof();
                if (!values.TryGetValue(entry, out var owned))
                {
                    var snapshot = entry with { ApplicationData = entry.ApplicationData.ToArray() };
                    owned = (snapshot, SharedPermissionStorage.PreparedEntry.Create(target, sourceGeneration, snapshot));
                    values.Add(entry, owned);
                }
                originals.Add(owned.Original);
                references.Add(owned.Reference);
            }
            sequence = new(originals.MoveToImmutable(), references.MoveToImmutable(), sourceGeneration);
            sequences.Add(source, sequence);
            return sequence;
        }

        private SharedProofStorage.PreparedRoutes Routes(MembershipRouteSummary routes, Guid sourceGeneration, Guid? sourceDerivation, int catalogue)
        {
            token.ThrowIfCancellationRequested();
            var key = (routes, sourceGeneration, sourceDerivation, catalogue);
            if (_routes.TryGetValue(key, out var prepared)) return prepared;
            prepared = SharedProofStorage.PreparedRoutes.Create(routes, sourceGeneration, sourceDerivation, catalogue);
            _routes.Add(key, prepared);
            return prepared;
        }

        internal ControlEvidencePreparation Create(ControlObjectEvaluation value)
        {
            var edges = ImmutableArray.CreateBuilder<Edge>(value.Edges.Count);
            var proofs = ImmutableArray.CreateBuilder<ControlEdge>(value.Edges.Count);
            foreach (var edge in value.Edges)
            {
                token.ThrowIfCancellationRequested();
                if (edge.Target != target || generation is { } bound && (edge.GenerationId != bound || edge.DerivationGenerationId != derivation)
                    || edge.Evidence is null || edge.Preconditions is null) throw FullControlEvaluator.InvalidProof();
                var entries = Entries(edge.Evidence, edge.GenerationId);
                var routes = Routes(edge.MembershipRoutes, edge.GenerationId, edge.DerivationGenerationId, edge.PrincipalCatalogueVersion);
                var proof = edge with { Evidence = entries.Originals, Preconditions = edge.Preconditions.ToImmutableArray(),
                    MembershipRoutes = routes.Routes };
                ReplicationControlDeriver.ValidateStored(proof);
                OwnershipControlDeriver.ValidateStored(proof);
                proofs.Add(proof);
                edges.Add(new(proof with { Evidence = [], MembershipRoutes = MembershipRouteSummary.NotDerived },
                    entries.Entries, routes));
            }
            var frozenEdges = proofs.MoveToImmutable();
            var assessments = ImmutableArray.CreateBuilder<Assessment>(value.FullControlAssessments.Count);
            Sequence? common = null;
            foreach (var assessment in value.FullControlAssessments)
            {
                token.ThrowIfCancellationRequested();
                var source = assessment.Source;
                if (source is null || source.Target != target || generation is { } bound && (assessment.GenerationId != bound
                    || assessment.DerivationGenerationId != derivation) || source.Entries is null
                    || source.Classes is null || source.AuthorityDomainSids is null
                    || assessment.Rights is null || assessment.SupportingCapabilities is null)
                    throw FullControlEvaluator.InvalidProof();
                var entries = Entries(source.Entries, assessment.GenerationId);
                common ??= entries;
                if (!ReferenceEquals(entries, common) && entries.Payload != common.Payload)
                    throw FullControlEvaluator.InvalidProof();
                var routes = Routes(source.MembershipRoutes, assessment.GenerationId, assessment.DerivationGenerationId, assessment.PrincipalCatalogueVersion);
                var proof = assessment with
                {
                    Source = source with
                    {
                        Entries = entries.Originals,
                        Classes = source.Classes.ToImmutableArray(),
                        AuthorityDomainSids = new ReadOnlyDictionary<string, string?>(
                            source.AuthorityDomainSids.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal)),
                        MembershipRoutes = routes.Routes,
                    },
                    Rights = assessment.Rights.Select(right => right with
                    {
                        GrantOrdinals = right.GrantOrdinals.ToImmutableArray(),
                        BlockingOrdinals = right.BlockingOrdinals.ToImmutableArray(),
                    }).ToImmutableArray(),
                    SupportingCapabilities = assessment.SupportingCapabilities.ToImmutableArray(),
                };
                FullControlEvaluator.Validate(proof, frozenEdges);
                assessments.Add(new(proof with
                {
                    Source = proof.Source with { Entries = [], MembershipRoutes = MembershipRouteSummary.NotDerived },
                }, routes));
            }
            var preparedEdges = edges.MoveToImmutable();
            var preparedAssessments = assessments.MoveToImmutable();
            var metadata = value with
            {
                Edges = preparedEdges.Select(edge => edge.Value).ToImmutableArray(),
                FullControlAssessments = preparedAssessments.Select(assessment => assessment.Value).ToImmutableArray(),
            };
            if (common is not null) _ = common.Payload;
            foreach (var sequences in _sequences.Values)
                foreach (var sequence in sequences.Values) sequence.ReleaseOriginals();
            return new(metadata, generation, derivation, preparedEdges, preparedAssessments, common);
        }
    }
}
