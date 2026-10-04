using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class OwnershipAuditValidation
{
    private static readonly Meter ReadbackMeter = new("SecureAD.Judgement.Readback");
    private static readonly Counter<long> AnalyticalReads = ReadbackMeter.CreateCounter<long>("judgement.analytical_reads");

    // Replay only stored seed witnesses and inclusion links. No new discovery, membership walk or assessment is performed.
    internal static (IReadOnlyList<Tier0Classification> Classifications, IReadOnlyList<Tier0RelevanceRelation> Relations)
        Validate(SqliteConnection connection, JudgementDescription description, JudgingInputs sources,
            OwnershipAuditStorage.Snapshot ownership, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        sources.RequireFor(description);
        ownership.RequireFor(connection, description);
        AnalyticalReads.Add(1, new KeyValuePair<string, object?>("bundle", sources.Directory));
        var header = OwnershipAuditStorage.ValidateCounts(connection, description);
        if (header != ownership.Header) throw OwnershipAuditStorage.InvalidProof();
        if (header is null) return ([], []);
        var rows = ownership.Targets;
        var targets = ownership.ByTarget;
        var seeds = ownership.Seeds;
        var links = ownership.Relations;
        var known = Enum.GetValues<Tier0Limitations>().Aggregate(Tier0Limitations.None, (all, value) => all | value);
        if ((header.Coverage.Limitations & ~known) != 0 || !header.Coverage.ProcessingComplete
            || header.Coverage.AnalysisComplete || header.Coverage.IsComplete) throw OwnershipAuditStorage.InvalidProof();
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
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
                cancellationToken.ThrowIfCancellationRequested();
                if (!targets.TryGetValue(read.GetString(0), out var target)
                    || target.Identity.Sid != (read.IsDBNull(1) ? null : read.GetString(1))
                    || target.Identity.SidScope != (read.IsDBNull(2) ? null : read.GetString(2))) throw OwnershipAuditStorage.InvalidProof();
            }
        }
        var bundle = sources.Bundle;
        if (OwnershipAuditRun.OwnerRightsHash(sources.OwnerRights) != header.OwnerRightsContextHash)
            throw OwnershipAuditStorage.InvalidProof();
        if (header.Input is null)
        {
            if (header.Coverage.InputsComplete || seeds.Length != 0 || links.Length != 0) throw OwnershipAuditStorage.InvalidProof();
            return ([], []);
        }
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        if (header.DerivationGeneration is not { } generation
            || sources.Binding() != header.Input)
            throw OwnershipAuditStorage.InvalidProof();
        var input = sources.ReadMembershipInput();
        if (input.DerivationGenerationId != generation) throw OwnershipAuditStorage.InvalidProof();
        var identities = input.Objects.GroupBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows.Where(item => item.Selection == OwnershipScopeState.Included))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!identities.TryGetValue(row.Identity.DistinguishedName, out var objects) || objects.Length != 1
                || OwnershipAuditRun.Target(objects[0], contexts.Value) != row.Identity) throw OwnershipAuditStorage.InvalidProof();
        }
        var seedByDn = seeds.ToDictionary(item => item.Target, StringComparer.OrdinalIgnoreCase);
        if (seeds.Any(seed => !targets.ContainsKey(seed.Target))) throw OwnershipAuditStorage.InvalidProof();
        var classifications = Tier0Classifier.QualifyMany(header.Input, seeds.Select(seed => targets[seed.Target].Identity), input,
            target => seedByDn[target.DistinguishedName].Routes, cancellationToken).Classifications;
        foreach (var classification in classifications)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var seed = seedByDn[classification.Target.DistinguishedName];
            if (classification.State != Tier0State.Established || targets[seed.Target].Selection != OwnershipScopeState.Included
                || !OwnershipAuditStorage.Hash(JsonSerializer.Serialize(classification, ProofSerialization.Options)).AsSpan().SequenceEqual(seed.Fingerprint.AsSpan()))
                throw OwnershipAuditStorage.InvalidProof();
        }
        // Visit one resource at a time, but retain the stored order in the returned proof.
        // A changed order would change the fingerprint even when every witness still agrees.
        var relations = new Tier0RelevanceRelation[links.Length];
        var order = Enumerable.Range(0, links.Length).OrderBy(index =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!targets.TryGetValue(links[index].Affected, out var target)) throw OwnershipAuditStorage.InvalidProof();
            return target.Identity.DistinguishedName;
        }, StringComparer.Ordinal);
        string? preparedTarget = null;
        ObjectPermissions? preparedPermissions = null;
        IReadOnlyDictionary<int, string>? originalEntries = null;
        ObjectPermissions PermissionsFor(string target)
        {
            if (preparedTarget != target)
            {
                preparedTarget = null;
                preparedPermissions = null;
                originalEntries = null;
                cancellationToken.ThrowIfCancellationRequested();
                preparedPermissions = bundle.ReadPermissions(target) ?? throw OwnershipAuditStorage.InvalidProof();
                preparedTarget = target;
            }
            return preparedPermissions!;
        }
        foreach (var index in order)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var link = links[index];
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
                var descriptor = PermissionsFor(link.WitnessTarget);
                if (link.WitnessIsOwner)
                {
                    if (link.WitnessOrdinal is not null || descriptor.Owner?.Sid != link.WitnessTrustee)
                        throw OwnershipAuditStorage.InvalidProof();
                }
                else if (link.WitnessOrdinal is not { } ordinal
                    || descriptor.Entries.FirstOrDefault(entry => entry.Ordinal == ordinal) is not { } witnessed
                    || witnessed.Trustee.Sid != link.WitnessTrustee)
                    throw OwnershipAuditStorage.InvalidProof();
                if (link.GroupMembership is { } membership)
                {
                    if (link.WitnessIsOwner || capability != ControlCapability.CanWriteDacl) throw OwnershipAuditStorage.InvalidProof();
                    RequesterMembershipContext.RequireGroupSources(membership, controller.Identity, affected.Identity,
                        link.WitnessTrustee, bundle.ReadObjectAttributes, cancellationToken);
                }
                relations[index] = Tier0RelevanceRelation.FromCapturedPermission(header.Input, controller.Identity,
                    affected.Identity, capability, new(link.WitnessTarget, link.WitnessOrdinal,
                        link.WitnessTrustee, link.WitnessIsOwner) { GroupMembership = link.GroupMembership });
                continue;
            }
            var edge = ControlEdgeStorage.ReadEdge(connection, description, edgeId);
            var captured = PermissionsFor(edge.Target);
            var original = originalEntries ??= captured.Entries.ToDictionary(entry => entry.Ordinal, SharedPermissionStorage.ValueKey);
            if (ControlEdgeStorage.ReadExactAces(connection, edge).Any(entry =>
                !original.TryGetValue(entry.Ordinal, out var source) || source != SharedPermissionStorage.ValueKey(entry)))
                throw OwnershipAuditStorage.InvalidProof();
            relations[index] = Tier0RelevanceRelation.FromControlEdge(header.Input, controller.Identity, affected.Identity, edge);
        }
        var replay = OwnershipScopeSelector.Select(header.Input, description.GenerationId, classifications, relations, header.Coverage,
            cancellationToken, progress: null);
        cancellationToken.ThrowIfCancellationRequested();
        if (replay.WasCancelled) throw new OperationCanceledException(cancellationToken);
        var selected = replay.Decisions.Where(item => item.State == OwnershipScopeState.Included).Select(item => item.Target).ToHashSet();
        if (!selected.SetEquals(rows.Where(item => item.Selection == OwnershipScopeState.Included).Select(item => item.Identity)))
            throw OwnershipAuditStorage.InvalidProof();
        ownership.RequireFor(connection, description);
        return (classifications, relations);
    }
}
