using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

// Test-only collection keeps earlier exact-output checks usable. The production producer
// emits directly into its saved work plan and never falls back to this accumulator.
internal static class RequesterSelectionEvaluation
{
    internal static PathRequesterSelection Select(Func<string, ObjectAttributes?> attributes,
        Func<string, ObjectPermissions?> permissions, PathInputs inputs, IReadOnlyDictionary<string, Tier0PathNode> nodes,
        IReadOnlyDictionary<string, NamingContextKind> contexts, CancellationToken token, PostPassDiagnostics? diagnostic,
        RequesterMembershipContext? memberships)
    {
        var sink = new Collector();
        var scan = new PathRequesterSelector(attributes, permissions, inputs, nodes, contexts, token, diagnostic, sink)
            { Memberships = memberships }.Select();
        return sink.Finish(scan);
    }

    internal sealed class Collector : IPathRequesterSelectionSink
    {
        private readonly Dictionary<string, PathRequesterCandidate> _candidates = new(StringComparer.Ordinal);
        private readonly List<PathRequesterSelectionSource> _sources = [];
        private readonly HashSet<PathRequesterSelectionLimitation> _limitations = [];

        public bool Include(PathRequesterCandidate candidate)
        {
            var key = PathRequesterSelector.Key(candidate);
            if (!_candidates.TryGetValue(key, out var previous))
            {
                _candidates.Add(key, candidate);
                return true;
            }
            var seen = new HashSet<PathRequesterSelectionWitness>(previous.Witnesses);
            var witnesses = previous.Witnesses.ToList();
            foreach (var witness in candidate.Witnesses)
                if (seen.Add(witness)) witnesses.Add(witness);
            _candidates[key] = previous with { Witnesses = witnesses };
            return false;
        }

        public void Source(PathRequesterSelectionSource source) => _sources.Add(source);
        public void Limit(PathRequesterSelectionLimitation limitation) => _limitations.Add(limitation);

        internal PathRequesterSelection Finish(PathRequesterSelectionScan scan) => new(scan.Version,
            scan.JudgementGenerationId, scan.InputFingerprint, scan.InputScanCompleted,
            _candidates.Values.OrderBy(PathRequesterSelector.Key, StringComparer.Ordinal).ToArray(),
            _sources.ToArray(), _limitations.OrderBy(Tier0PathCalculation.Fingerprint, StringComparer.Ordinal).ToArray());
    }
}
