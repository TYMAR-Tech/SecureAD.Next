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

    internal static PathInputs Read(SqliteConnection connection, JudgementDescription description, string directory)
    {
        var header = ReadHeader(connection);
        using var anchors = connection.CreateCommand();
        anchors.CommandText = "SELECT target FROM path_anchor ORDER BY target";
        var targetNames = new List<string>();
        using (var read = anchors.ExecuteReader()) while (read.Read()) targetNames.Add(read.GetString(0));
        var regions = ReadRegions(connection);
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
        var ownership = OwnershipAuditStorage.ReadHeader(connection, requireComplete: true) ?? throw InvalidProof();
        if (ownership.Input != header.Input || ownership.Coverage != header.Coverage) throw InvalidProof();
        var validated = OwnershipAuditValidation.Validate(connection, description, directory);
        var fixedTargets = FixedTargets(validated.Classifications).ToArray();
        if (!targetNames.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(fixedTargets.Select(item => item.DistinguishedName)))
            throw InvalidProof();
        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess) throw InvalidProof();
        using var bundle = opened.Value;
        var contexts = bundle.ReadNamingContexts();
        if (!contexts.IsSuccess) throw InvalidProof();
        foreach (var region in regions)
        {
            var subject = region.Source.TargetDn is { } dn ? bundle.ReadObjectAttributes(dn) : null;
            var target = subject is null ? null : OwnershipAuditRun.Target(subject, contexts.Value);
            if (region != Region(region.Source, target) || !WitnessMatches(region.Source, target, bundle)) throw InvalidProof();
        }
        // These are references, not a new permission interpretation. Full permission proofs remain
        // behind ReadControlEdges; copying them here would create another forest-wide permission store.
        using var permissions = connection.CreateCommand();
        permissions.CommandText = "SELECT id,generation,derivation_generation FROM control_edge ORDER BY id";
        var ids = new List<long>();
        using (var read = permissions.ExecuteReader())
            while (read.Read())
            {
                if (Guid.Parse(read.GetString(1)) != description.GenerationId || read.IsDBNull(2)
                    || Guid.Parse(read.GetString(2)) != description.DerivationGenerationId) throw InvalidProof();
                ids.Add(read.GetInt64(0));
            }
        return new(description.GenerationId, header.Availability, header.Input, header.Coverage, fixedTargets,
            validated.Classifications, validated.Relations, ids, regions, SelfMembershipCoverageStorage.Read(connection, description));
    }

    private static PathInputs Empty(JudgementDescription description, PathInputAvailability availability) =>
        new(description.GenerationId, availability, null, OwnershipAuditStorage.UnavailableCoverage, [], [], [], [], [], null);

    private static IEnumerable<Tier0Target> FixedTargets(IEnumerable<Tier0Classification> classifications) =>
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

    private static IReadOnlyList<PathUncertaintyRegion> ReadRegions(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof,fingerprint FROM path_uncertainty ORDER BY id";
        using var read = command.ExecuteReader();
        var regions = new List<PathUncertaintyRegion>();
        while (read.Read())
        {
            var json = read.GetString(0);
            if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual((byte[])read.GetValue(1))) throw InvalidProof();
            var region = JsonSerializer.Deserialize<PathUncertaintyRegion>(json, ProofSerialization.Options) ?? throw InvalidProof();
            if (region.Source is null || region.Source.PermissionOrdinal < 0) throw InvalidProof();
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
