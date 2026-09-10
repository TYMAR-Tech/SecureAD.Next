using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class OwnershipAuditValidation
{
    // Replay only stored seed witnesses and inclusion links. No new discovery, membership walk or assessment is performed.
    internal static void Validate(SqliteConnection connection, JudgementDescription description, string directory)
    {
        var header = OwnershipAuditStorage.ValidateCounts(connection, description);
        if (header is null) return;
        var rows = OwnershipAuditStorage.Targets(connection);
        var targets = rows.ToDictionary(item => item.Identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var seeds = OwnershipAuditStorage.Seeds(connection);
        var links = OwnershipAuditStorage.Relations(connection);
        var known = Enum.GetValues<Tier0Limitations>().Aggregate(Tier0Limitations.None, (all, value) => all | value);
        if ((header.Coverage.Limitations & ~known) != 0 || !header.Coverage.ProcessingComplete
            || header.Coverage.AnalysisComplete || header.Coverage.IsComplete) throw OwnershipAuditStorage.InvalidProof();
        foreach (var row in rows)
        {
            if (row.Selection == OwnershipScopeState.OutsideComputedScope
                || row.Selection == OwnershipScopeState.Included && !row.Identity.IsValid
                || row.Execution == OwnershipAssessmentExecution.Completed && row.Candidates != 0
                || header.Input is null && row.Selection != OwnershipScopeState.Undetermined)
                throw OwnershipAuditStorage.InvalidProof();
        }
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT target,principal_sid,principal_scope FROM control_object";
            using var read = command.ExecuteReader();
            while (read.Read())
            {
                if (!targets.TryGetValue(read.GetString(0), out var target)
                    || target.Identity.Sid != (read.IsDBNull(1) ? null : read.GetString(1))
                    || target.Identity.SidScope != (read.IsDBNull(2) ? null : read.GetString(2))) throw OwnershipAuditStorage.InvalidProof();
            }
        }
        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        using var bundle = opened.Value;
        if (OwnershipAuditRun.OwnerRightsHash(DirectoryHeuristics.OwnerImplicitRights(bundle.ReadForestHeuristics())) != header.OwnerRightsContextHash)
            throw OwnershipAuditStorage.InvalidProof();
        if (header.Input is null)
        {
            if (header.Coverage.InputsComplete || seeds.Count != 0 || links.Count != 0) throw OwnershipAuditStorage.InvalidProof();
            return;
        }
        if (header.DerivationGeneration is not { } generation
            || OwnershipAuditRun.Binding(directory, description.EvidenceSeal, generation, bundle.Description.ForestFqdn) != header.Input)
            throw OwnershipAuditStorage.InvalidProof();
        var derived = DerivationReader.Open(directory);
        if (!derived.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        using var derivation = derived.Value;
        var input = derivation.ReadMembershipInput();
        if (input.DerivationGenerationId != generation) throw OwnershipAuditStorage.InvalidProof();
        var contexts = bundle.ReadNamingContexts();
        if (!contexts.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        var identities = input.Objects.GroupBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows.Where(item => item.Selection == OwnershipScopeState.Included))
        {
            if (!identities.TryGetValue(row.Identity.DistinguishedName, out var objects) || objects.Length != 1
                || OwnershipAuditRun.Target(objects[0], contexts.Value) != row.Identity) throw OwnershipAuditStorage.InvalidProof();
        }
        var seedByDn = seeds.ToDictionary(item => item.Target, StringComparer.OrdinalIgnoreCase);
        if (seeds.Any(seed => !targets.ContainsKey(seed.Target))) throw OwnershipAuditStorage.InvalidProof();
        var classifications = Tier0Classifier.QualifyMany(header.Input, seeds.Select(seed => targets[seed.Target].Identity), input,
            target => seedByDn[target.DistinguishedName].Routes).Classifications;
        foreach (var classification in classifications)
        {
            var seed = seedByDn[classification.Target.DistinguishedName];
            if (classification.State != Tier0State.Established || targets[seed.Target].Selection != OwnershipScopeState.Included
                || !OwnershipAuditStorage.Hash(JsonSerializer.Serialize(classification, ProofSerialization.Options)).AsSpan().SequenceEqual(seed.Fingerprint))
                throw OwnershipAuditStorage.InvalidProof();
        }
        var relations = new List<Tier0RelevanceRelation>();
        var permissions = new Dictionary<string, IReadOnlyDictionary<int, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var link in links)
        {
            if (!targets.TryGetValue(link.Controller, out var controller) || !targets.TryGetValue(link.Affected, out var affected)
                || controller.Selection != OwnershipScopeState.Included || affected.Selection != OwnershipScopeState.Included)
                throw OwnershipAuditStorage.InvalidProof();

            // A capture-backed route names an owner or an entry rather than a stored edge, so it is
            // checked against the captured descriptor directly. The point of the check is unchanged:
            // a retained route must still be supported by the evidence it claims, and a witness that
            // no longer matches what capture holds is refused rather than replayed.
            if (link.EdgeId is not { } edgeId)
            {
                if (link.WitnessTarget is null || link.WitnessTrustee is null || link.WitnessCapability is not { } capability
                    || link.WitnessTarget != affected.Identity.DistinguishedName) throw OwnershipAuditStorage.InvalidProof();
                var descriptor = bundle.ReadPermissions(link.WitnessTarget) ?? throw OwnershipAuditStorage.InvalidProof();
                if (link.WitnessIsOwner)
                {
                    if (link.WitnessOrdinal is not null || descriptor.Owner?.Sid != link.WitnessTrustee)
                        throw OwnershipAuditStorage.InvalidProof();
                }
                else if (link.WitnessOrdinal is not { } ordinal
                    || descriptor.Entries.FirstOrDefault(entry => entry.Ordinal == ordinal) is not { } witnessed
                    || witnessed.Trustee.Sid != link.WitnessTrustee)
                    throw OwnershipAuditStorage.InvalidProof();
                relations.Add(Tier0RelevanceRelation.FromCapturedPermission(header.Input, controller.Identity,
                    affected.Identity, capability, new(link.WitnessTarget, link.WitnessOrdinal,
                        link.WitnessTrustee, link.WitnessIsOwner)));
                continue;
            }
            var edge = ControlEdgeStorage.ReadEdge(connection, description, edgeId);
            if (!permissions.TryGetValue(edge.Target, out var original))
            {
                var captured = bundle.ReadPermissions(edge.Target) ?? throw OwnershipAuditStorage.InvalidProof();
                original = captured.Entries.ToDictionary(entry => entry.Ordinal, SharedPermissionStorage.ValueKey);
                permissions.Add(edge.Target, original);
            }
            if (ControlEdgeStorage.ReadExactAces(connection, edge).Any(entry =>
                !original.TryGetValue(entry.Ordinal, out var source) || source != SharedPermissionStorage.ValueKey(entry)))
                throw OwnershipAuditStorage.InvalidProof();
            relations.Add(Tier0RelevanceRelation.FromControlEdge(header.Input, controller.Identity, affected.Identity, edge));
        }
        var replay = OwnershipScopeSelector.Select(header.Input, description.GenerationId, classifications, relations, header.Coverage,
            CancellationToken.None, progress: null);
        var selected = replay.Decisions.Where(item => item.State == OwnershipScopeState.Included).Select(item => item.Target).ToHashSet();
        if (!selected.SetEquals(rows.Where(item => item.Selection == OwnershipScopeState.Included).Select(item => item.Identity)))
            throw OwnershipAuditStorage.InvalidProof();
    }
}
