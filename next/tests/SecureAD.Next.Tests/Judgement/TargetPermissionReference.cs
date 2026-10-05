using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;

namespace SecureAD.Next.Tests.Judgement;

// The lab-confirmed format-52 producer and witness validator before target batching.
internal static class TargetPermissionReference
{
    internal sealed class CancellingList<T>(T value, CancellationTokenSource stopping) : IReadOnlyList<T>
    {
        internal int Visits { get; private set; }
        public int Count => 3;
        public T this[int index] => value;

        public IEnumerator<T> GetEnumerator()
        {
            for (var index = 0; index < Count; index++)
            {
                if (index == 2) throw new InvalidOperationException("Grouping continued after cancellation.");
                if (index == 1) stopping.Cancel();
                Visits++;
                yield return value;
            }
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    internal static IReadOnlyList<SavedRequesterDaclProof> Create(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs,
        IReadOnlyList<RequesterDaclRequest> requests, CancellationToken cancellationToken,
        OwnAccountMembershipAssessment? obtainedMembership, RequesterMembershipContext? memberships,
        bool currentSourceFingerprints = false)
    {
        if (requests.Count == 0) return [];
        sources.RequireFor(description);
        var bundle = sources.Bundle;
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw Tier0PathStorage.InvalidProof();
        var results = new List<SavedRequesterDaclProof>();
        var originals = new Dictionary<long, IReadOnlyList<PermissionEntry>>();
        foreach (var request in requests.OrderBy(RequesterDaclProofs.Key, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var permissions = bundle.ReadPermissions(request.TargetDn);
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanWriteDacl' ORDER BY id";
            query.Parameters.AddWithValue("$target", request.TargetDn);
            var ids = new List<long>();
            using (var read = query.ExecuteReader()) while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ids.Add(read.GetInt64(0));
            }
            var edges = ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id)).ToArray();
            var assessment = RequesterDaclEvaluator.Assess(request, inputs, description, identities,
                bundle.ReadObjectAttributes, permissions, contexts.Value, edges, bundle.Description.ForestFqdn, cancellationToken,
                obtainedMembership, memberships, (edge, grant) => OriginalEntries(edge)
                    .Any(original => Tier0PathCalculation.Fingerprint(original) == Tier0PathCalculation.Fingerprint(grant)));
            var holders = new List<ObjectAttributes?>();
            foreach (var dn in (permissions?.Entries ?? []).Select(entry => entry.Trustee.DistinguishedName)
                .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                holders.Add(bundle.ReadObjectAttributes(dn));
            }
            var material = new
            {
                Requester = bundle.ReadObjectAttributes(request.RequesterDn), Target = bundle.ReadObjectAttributes(request.TargetDn),
                Permissions = permissions, Holders = holders, Forest = bundle.Description.ForestFqdn,
                Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray(),
                ObtainedMembership = obtainedMembership,
                Membership = assessment.Evidence.Select(value => value.Membership).ToArray(),
                ObtainedGroupMembership = assessment.Evidence.Select(value => value.ObtainedGroupMembership).ToArray(),
                ResourceContext = assessment.ResourceContext,
            };
            var source = currentSourceFingerprints
                ? SourceFingerprintReference.FromLegacy(PathSourceFamily.RequesterDacl, description, inputs, material)
                : Tier0PathCalculation.Fingerprint(material);
            results.Add(new(assessment, source));
        }
        return results;

        IReadOnlyList<PermissionEntry> OriginalEntries(ControlEdge edge)
        {
            if (!originals.TryGetValue(edge.Id, out var entries))
                originals[edge.Id] = entries = ControlEdgeStorage.ReadExactAces(connection, edge);
            return entries;
        }
    }

    internal static bool EntryMatches(ControlEdge edge, PermissionEntry grant) =>
        edge.Evidence.Any(original => Tier0PathCalculation.Fingerprint(original) == Tier0PathCalculation.Fingerprint(grant));

    internal static void ValidateWitnesses(BundleReader bundle, IReadOnlyDictionary<string, NamingContextKind> contexts,
        IReadOnlyList<PathUncertaintyRegion> regions, CancellationToken cancellationToken)
    {
        if (regions.Count != 0) bundle.PrepareBulkObjectLookup();
        foreach (var region in regions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var subject = region.Source.TargetDn is { } dn ? bundle.ReadObjectAttributes(dn) : null;
            var target = subject is null ? null : OwnershipAuditRun.Target(subject, contexts);
            if (region != Region(region.Source, target) || !WitnessMatches(region.Source, target, bundle))
                throw new InvalidDataException("The preserved path-witness validator refused the source.");
        }
    }

    internal static PathUncertaintyRegion Region(Tier0DiscoveryLimitation source, Tier0Target? target)
    {
        var cause = source.Reason switch
        {
            Tier0DiscoveryReason.CaptureIncomplete or Tier0DiscoveryReason.DescriptorUnavailable
                or Tier0DiscoveryReason.DescriptorIncomplete => PathUncertaintyCause.CapturedEvidenceIncomplete,
            Tier0DiscoveryReason.NullDacl or Tier0DiscoveryReason.BroadTrustee => PathUncertaintyCause.BroadPrincipalNotExpanded,
            Tier0DiscoveryReason.UnresolvedTrustee or Tier0DiscoveryReason.MissingIdentity => PathUncertaintyCause.IdentityUnresolved,
            Tier0DiscoveryReason.UnsupportedRoute => PathUncertaintyCause.AnalysisUnsupported,
            _ => throw new InvalidDataException("The preserved path-witness validator refused the reason."),
        };
        return new(source, cause, source.TrusteeSid is null ? PathSubjectScope.UnknownWithinForest : PathSubjectScope.RecordedTrustee,
            source.TargetDn is null ? PathTargetScope.Forest : PathTargetScope.Object, target);
    }

    private static bool WitnessMatches(Tier0DiscoveryLimitation source, Tier0Target? target, BundleReader bundle)
    {
        if (source.Reason == Tier0DiscoveryReason.CaptureIncomplete)
        {
            var scope = bundle.ReadScope();
            return source.TargetDn is null && scope.IsSuccess && !scope.Value.AllDeclaredDomainsAreComplete;
        }
        if (target is null || source.TargetDn != target.DistinguishedName) return false;
        if (source.Reason == Tier0DiscoveryReason.MissingIdentity) return !target.IsValid;
        var descriptor = bundle.ReadPermissions(target.DistinguishedName);
        if (source.Reason == Tier0DiscoveryReason.DescriptorUnavailable)
            return descriptor is null || descriptor.Availability != DescriptorAvailability.Read || descriptor.DaclState == DaclState.Unreadable;
        if (descriptor is null) return false;
        if (source.Reason == Tier0DiscoveryReason.DescriptorIncomplete) return descriptor.DaclCompleteness != DaclCompleteness.Complete;
        if (source.Reason == Tier0DiscoveryReason.NullDacl) return descriptor.DaclState == DaclState.Null;
        return source.PermissionOrdinal is { } ordinal
            ? descriptor.Entries.Any(entry => entry.Ordinal == ordinal && entry.Trustee.Sid == source.TrusteeSid)
            : descriptor.Owner?.Sid == source.TrusteeSid || descriptor.DaclState == DaclState.Null && source.TrusteeSid == "S-1-1-0";
    }
}
