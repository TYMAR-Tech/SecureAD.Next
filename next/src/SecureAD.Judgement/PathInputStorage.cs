using System.Globalization;
using System.Resources;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class PathInputStorage
{
    private const int Version = 1;
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.PathInputs", typeof(PathInputStorage).Assembly);
    private sealed record Header(int Version, Guid Generation, string EvidenceSeal, Guid? DerivationGeneration,
        PathInputAvailability Availability, Tier0InputBinding? Input, Tier0Coverage Coverage,
        int DiscoveryVersion, int ControlEngineVersion, int AnchorCount, int RegionCount);

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE path_input (id INTEGER PRIMARY KEY CHECK(id=1), proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE path_anchor (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_seed(target));
        CREATE TABLE path_uncertainty (id INTEGER PRIMARY KEY, proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        """);

    internal static void Start(SqliteConnection connection, JudgementDescription description, bool requested)
    {
        var header = new Header(Version, description.GenerationId, description.EvidenceSeal, description.DerivationGenerationId,
            requested ? PathInputAvailability.RequiredInputsUnavailable : PathInputAvailability.NotProduced,
            null, OwnershipAuditStorage.UnavailableCoverage, Tier0DiscoveryCoverage.CurrentVersion,
            ControlEdgeStorage.EngineVersion, 0, 0);
        WriteHeader(connection, null, header);
    }

    internal static void Write(SqliteConnection connection, OwnershipScopeSelection selection,
        Tier0DiscoveryCoverage discovery, IReadOnlyDictionary<string, Tier0Target> observed, CancellationToken cancellationToken)
    {
        var previous = ReadHeader(connection) ?? throw InvalidProof();
        if (previous.Availability != PathInputAvailability.RequiredInputsUnavailable
            || selection.JudgementGenerationId != previous.Generation || selection.Input.EvidenceSeal != previous.EvidenceSeal
            || selection.Input.DerivationGenerationId != previous.DerivationGeneration || selection.WasCancelled)
            throw InvalidProof();
        var anchors = FixedTargets(selection.Classifications).ToArray();
        using var transaction = connection.BeginTransaction();
        foreach (var anchor in anchors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Execute(connection, transaction, "INSERT INTO path_anchor VALUES ($target)", ("$target", anchor.DistinguishedName));
        }
        foreach (var limitation in discovery.Limitations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = limitation.TargetDn is { } dn && observed.TryGetValue(dn, out var value) ? value : null;
            var json = JsonSerializer.Serialize(Region(limitation, target), ProofSerialization.Options);
            Execute(connection, transaction, "INSERT INTO path_uncertainty (proof,fingerprint) VALUES ($proof,$hash)",
                ("$proof", json), ("$hash", OwnershipAuditStorage.Hash(json)));
        }
        WriteHeader(connection, transaction, previous with { Availability = PathInputAvailability.Recorded,
            Input = selection.Input, Coverage = selection.Coverage, AnchorCount = anchors.Length, RegionCount = discovery.Limitations.Count });
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    internal static PathInputs Read(SqliteConnection connection, JudgementDescription description,
        CancellationToken cancellationToken = default) => Read(connection, description, out _, cancellationToken);

    internal static PathInputs Read(SqliteConnection connection, JudgementDescription description,
        out OwnershipAuditStorage.Snapshot? ownershipInputs, CancellationToken cancellationToken)
    {
        ownershipInputs = null;
        cancellationToken.ThrowIfCancellationRequested();
        var header = ReadHeader(connection);
        using var anchors = connection.CreateCommand();
        anchors.CommandText = "SELECT target FROM path_anchor ORDER BY target";
        var targetNames = new List<string>();
        using (var read = anchors.ExecuteReader()) while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            targetNames.Add(read.GetString(0));
        }
        var regions = ReadRegions(connection, cancellationToken);
        using var product = connection.CreateCommand();
        product.CommandText = "SELECT discovery_scoped FROM control_product WHERE id=1";
        var scoped = Convert.ToInt64(product.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
        if (header is null)
        {
            if (scoped || targetNames.Count != 0 || regions.Count != 0) throw InvalidProof();
            return Empty(description, PathInputAvailability.NotProduced);
        }
        if (header.Generation != description.GenerationId || header.EvidenceSeal != description.EvidenceSeal
            || header.DerivationGeneration != description.DerivationGenerationId
            || header.AnchorCount != targetNames.Count || header.RegionCount != regions.Count)
            throw InvalidProof();
        if (header.Availability != PathInputAvailability.Recorded)
        {
            if (scoped || header.Input is not null || targetNames.Count != 0 || regions.Count != 0
                || header.Coverage != OwnershipAuditStorage.UnavailableCoverage) throw InvalidProof();
            return Empty(description, header.Availability);
        }
        if (!scoped || header.Input is null || !header.Input.IsSupported) throw InvalidProof();
        ownershipInputs = new OwnershipAuditStorage.Snapshot(connection, description, cancellationToken);
        var ownership = ownershipInputs.Header ?? throw InvalidProof();
        if (ownership.Generation != description.GenerationId || ownership.EvidenceSeal != description.EvidenceSeal
            || ownership.DerivationGeneration != description.DerivationGenerationId
            || ownership.Input != header.Input || ownership.Coverage != header.Coverage) throw InvalidProof();
        var seeds = ownershipInputs.Seeds;
        var targets = ownershipInputs.ByTarget;
        if (seeds.Length != ownership.SeedCount || targets.Count != ownership.TargetCount
            || seeds.Any(seed => seed.Classification.Input != header.Input
                || !targets.TryGetValue(seed.Target, out var target) || target.Identity != seed.Classification.Target
                || target.Selection != OwnershipScopeState.Included)) throw InvalidProof();
        var classifications = seeds.Select(seed => seed.Classification).ToArray();
        var fixedTargets = FixedTargets(classifications).ToArray();
        if (!targetNames.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(fixedTargets.Select(item => item.DistinguishedName)))
            throw InvalidProof();
        var relations = new List<Tier0RelevanceRelation>();
        foreach (var link in ownershipInputs.Relations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!targets.TryGetValue(link.Controller, out var controller) || !targets.TryGetValue(link.Affected, out var affected)
                || controller.Selection != OwnershipScopeState.Included || affected.Selection != OwnershipScopeState.Included)
                throw InvalidProof();
            relations.Add(link.EdgeId is { } id
                ? Tier0RelevanceRelation.FromControlEdge(header.Input, controller.Identity, affected.Identity,
                    ControlEdgeStorage.ReadExact(connection, description, link.Affected, id))
                : Tier0RelevanceRelation.FromCapturedPermission(header.Input, controller.Identity, affected.Identity,
                    link.WitnessCapability ?? throw InvalidProof(), new(link.WitnessTarget ?? throw InvalidProof(),
                        link.WitnessOrdinal, link.WitnessTrustee ?? throw InvalidProof(), link.WitnessIsOwner)
                        { GroupMembership = link.GroupMembership }));
        }
        if (relations.Count != ownership.RelationCount) throw InvalidProof();
        // These are references, not a new permission interpretation. Full permission proofs remain
        // behind ReadControlEdges; copying them here would create another forest-wide permission store.
        using var permissions = connection.CreateCommand();
        permissions.CommandText = "SELECT id,generation,derivation_generation FROM control_edge ORDER BY id";
        var ids = new List<long>();
        using (var read = permissions.ExecuteReader())
            while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (Guid.Parse(read.GetString(1)) != description.GenerationId || read.IsDBNull(2)
                    || Guid.Parse(read.GetString(2)) != description.DerivationGenerationId) throw InvalidProof();
                ids.Add(read.GetInt64(0));
            }
        return new(description.GenerationId, header.Availability, header.Input, header.Coverage, fixedTargets,
            classifications, relations, ids, regions, SelfMembershipCoverageStorage.Read(connection, description));
    }

    // Source qualification belongs to producing a result, never to browsing its saved projection.
    internal static void ValidateSources(SqliteConnection connection, JudgementDescription description, JudgingInputs sources,
        OwnershipAuditStorage.Snapshot? ownership, PathInputs inputs, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        sources.RequireFor(description);
        if (inputs.Availability != PathInputAvailability.Recorded) return;
        var validated = OwnershipAuditValidation.Validate(connection, description, sources,
            ownership ?? throw InvalidProof(), cancellationToken);
        if (Tier0PathCalculation.Fingerprint(inputs.Classifications) != Tier0PathCalculation.Fingerprint(validated.Classifications)
            || Tier0PathCalculation.Fingerprint(inputs.AdmissionRelationships) != Tier0PathCalculation.Fingerprint(validated.Relations))
            throw InvalidProof();
        var bundle = sources.Bundle;
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw InvalidProof();
        ValidateWitnesses(bundle, contexts.Value, inputs.UncertaintyRegions, cancellationToken);
        sources.RequireFor(description);
    }

    internal static void ValidateWitnesses(BundleReader bundle, IReadOnlyDictionary<string, NamingContextKind> contexts,
        IReadOnlyList<PathUncertaintyRegion> regions, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (regions.Count != 0) bundle.PrepareBulkObjectLookup();
        foreach (var batch in regions.Select(region =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return region;
            }).GroupBy(region => region.Source.TargetDn, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var subject = batch.Key is { } dn ? bundle.ReadObjectAttributes(dn) : null;
            var target = subject is null ? null : OwnershipAuditRun.Target(subject, contexts);
            var descriptor = target is not null && batch.Any(region =>
                region.Source.Reason is not (Tier0DiscoveryReason.CaptureIncomplete or Tier0DiscoveryReason.MissingIdentity))
                ? bundle.ReadPermissions(target.DistinguishedName) : null;
            var occurrences = descriptor is not null && batch.Any(region => region.Source.PermissionOrdinal.HasValue)
                ? descriptor.Entries.Select(entry => (entry.Ordinal, (string?)entry.Trustee.Sid)).ToHashSet() : null;
            var captureIncomplete = false;
            if (batch.Any(region => region.Source.Reason == Tier0DiscoveryReason.CaptureIncomplete))
            {
                var scope = bundle.ReadScope();
                captureIncomplete = scope.IsSuccess && !scope.Value.AllDeclaredDomainsAreComplete;
            }
            foreach (var region in batch)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (region != Region(region.Source, target)
                    || !WitnessMatches(region.Source, target, descriptor, occurrences, captureIncomplete)) throw InvalidProof();
            }
        }
    }

    private static PathInputs Empty(JudgementDescription description, PathInputAvailability availability) =>
        new(description.GenerationId, availability, null, OwnershipAuditStorage.UnavailableCoverage, [], [], [], [], [], null);

    internal static IEnumerable<Tier0Target> FixedTargets(IEnumerable<Tier0Classification> classifications) =>
        classifications.Where(item => item.Supports.Any(support => support.Basis is Tier0Basis.Core or Tier0Basis.PartitionRoot
            or Tier0Basis.EnterpriseCaRegistration or Tier0Basis.EnterpriseCaHost))
            .Select(item => item.Target).Distinct().OrderBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase);

    private static PathUncertaintyRegion Region(Tier0DiscoveryLimitation source, Tier0Target? target)
    {
        var cause = source.Reason switch
        {
            Tier0DiscoveryReason.CaptureIncomplete or Tier0DiscoveryReason.DescriptorUnavailable
                or Tier0DiscoveryReason.DescriptorIncomplete => PathUncertaintyCause.CapturedEvidenceIncomplete,
            Tier0DiscoveryReason.NullDacl or Tier0DiscoveryReason.BroadTrustee => PathUncertaintyCause.BroadPrincipalNotExpanded,
            Tier0DiscoveryReason.UnresolvedTrustee or Tier0DiscoveryReason.MissingIdentity => PathUncertaintyCause.IdentityUnresolved,
            Tier0DiscoveryReason.UnsupportedRoute => PathUncertaintyCause.AnalysisUnsupported,
            _ => throw InvalidProof(),
        };
        // A SID is retained as a witness, not resolved using the recorded forest-root domain.
        // Missing trustees and unbounded capture gaps must not disappear through enumeration.
        return new(source, cause, source.TrusteeSid is null ? PathSubjectScope.UnknownWithinForest : PathSubjectScope.RecordedTrustee,
            source.TargetDn is null ? PathTargetScope.Forest : PathTargetScope.Object, target);
    }

    private static bool WitnessMatches(Tier0DiscoveryLimitation source, Tier0Target? target, ObjectPermissions? descriptor,
        HashSet<(int Ordinal, string? Sid)>? occurrences, bool captureIncomplete)
    {
        if (source.Reason == Tier0DiscoveryReason.CaptureIncomplete)
            return source.TargetDn is null && captureIncomplete;
        if (target is null || source.TargetDn != target.DistinguishedName) return false;
        if (source.Reason == Tier0DiscoveryReason.MissingIdentity) return !target.IsValid;
        if (source.Reason == Tier0DiscoveryReason.DescriptorUnavailable)
            return descriptor is null || descriptor.Availability != DescriptorAvailability.Read || descriptor.DaclState == DaclState.Unreadable;
        if (descriptor is null) return false;
        if (source.Reason == Tier0DiscoveryReason.DescriptorIncomplete) return descriptor.DaclCompleteness != DaclCompleteness.Complete;
        if (source.Reason == Tier0DiscoveryReason.NullDacl) return descriptor.DaclState == DaclState.Null;
        return source.PermissionOrdinal is { } ordinal
            ? occurrences?.Contains((ordinal, source.TrusteeSid)) == true
            : descriptor.Owner?.Sid == source.TrusteeSid || descriptor.DaclState == DaclState.Null && source.TrusteeSid == "S-1-1-0";
    }

    private static IReadOnlyList<PathUncertaintyRegion> ReadRegions(SqliteConnection connection, CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof,fingerprint FROM path_uncertainty ORDER BY id";
        using var read = command.ExecuteReader();
        var regions = new List<PathUncertaintyRegion>();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var json = read.GetString(0);
            if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual((byte[])read.GetValue(1))) throw InvalidProof();
            var region = JsonSerializer.Deserialize<PathUncertaintyRegion>(json, ProofSerialization.Options) ?? throw InvalidProof();
            if (region.Source is null || region.Source.PermissionOrdinal < 0
                || !Enum.IsDefined(region.Cause) || !Enum.IsDefined(region.Subjects) || !Enum.IsDefined(region.Targets)
                || region != Region(region.Source, region.RecordedResource)) throw InvalidProof();
            regions.Add(region);
        }
        return regions;
    }

    private static Header? ReadHeader(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof,fingerprint FROM path_input WHERE id=1";
        using var read = command.ExecuteReader();
        if (!read.Read()) return null;
        var json = read.GetString(0);
        if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual((byte[])read.GetValue(1))) throw InvalidProof();
        var header = JsonSerializer.Deserialize<Header>(json, ProofSerialization.Options) ?? throw InvalidProof();
        if (header.Version != Version || !Enum.IsDefined(header.Availability) || header.Coverage is null
            || header.DiscoveryVersion != Tier0DiscoveryCoverage.CurrentVersion || header.ControlEngineVersion != ControlEdgeStorage.EngineVersion
            || header.AnchorCount < 0 || header.RegionCount < 0) throw InvalidProof();
        return header;
    }

    private static void WriteHeader(SqliteConnection connection, SqliteTransaction? transaction, Header header)
    {
        var json = JsonSerializer.Serialize(header, ProofSerialization.Options);
        Execute(connection, transaction, "INSERT OR REPLACE INTO path_input VALUES (1,$proof,$hash)",
            ("$proof", json), ("$hash", OwnershipAuditStorage.Hash(json)));
    }

    private static InvalidDataException InvalidProof() => new(Resources.GetString("InvalidProof", CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException("InvalidProof"));

    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] values)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
