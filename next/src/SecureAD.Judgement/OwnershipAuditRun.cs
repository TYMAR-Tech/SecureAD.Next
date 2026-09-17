using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class OwnershipAuditRun
{
    internal static string OwnerRightsHash(OwnerImplicitRightsSetting? setting) =>
        Convert.ToHexString(OwnershipAuditStorage.Hash(JsonSerializer.Serialize(setting, ProofSerialization.Options)));

    internal static Tier0InputBinding Binding(string directory, string evidenceSeal, Guid derivationGeneration, string? forest,
        IReadOnlyDictionary<string, NamingContextKind> namingContexts)
    {
        var path = BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Derivation, derivationGeneration);
        var seal = JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(path), ProofSerialization.Options) ?? throw OwnershipAuditStorage.InvalidProof();
        if (seal.Algorithm != BundleSealing.Algorithm) throw OwnershipAuditStorage.InvalidProof();
        var root = string.IsNullOrWhiteSpace(forest) ? null : string.Join(',', forest.Split('.').Select(part => "DC=" + part));
        var configurations = namingContexts.Where(item => item.Value == NamingContextKind.Configuration)
            .Select(item => item.Key).Take(2).ToArray();
        var binding = new Tier0InputBinding(evidenceSeal, derivationGeneration, seal.Hash,
            PrincipalClassificationRegistry.Version, PolicyVersion: 2, ContractVersion: 2, ForestRootNamingContext: root,
            ConfigurationNamingContext: configurations.Length == 1 ? configurations[0] : null);
        if (!binding.IsSupported) throw OwnershipAuditStorage.InvalidProof();
        return binding;
    }

    internal static Tier0Target Target(ObjectAttributes subject, IReadOnlyDictionary<string, NamingContextKind> namingContexts)
    {
        string? namingContext = subject.DistinguishedName;
        while (namingContext is not null && !namingContexts.ContainsKey(namingContext)) namingContext = DnHelper.GetParentDn(namingContext);
        var sid = OwnerRightsReading.TargetSid(subject);
        return new(subject.ObjectGuid, subject.DistinguishedName, namingContext ?? "", subject.DomainFqdn, sid,
            Sid.IsBuiltinDomain(sid) ? subject.DomainFqdn : null);
    }

    internal static void Assess(SqliteConnection connection, BundleReader bundle, JudgementDescription description,
        CapturedMembershipInput? input, Tier0InputBinding? binding, JudgingContext context, Func<string, string?> domainSid,
        long objectsRead, IProgress<JudgingRun.JudgingProgress> progress, CancellationToken cancellationToken,
        bool scopeAlreadyPlanned = false)
    {
        progress.Report(new(objectsRead) { Phase = JudgingPhase.SelectingOwnershipScope });
        cancellationToken.ThrowIfCancellationRequested();
        var targets = OwnershipAuditStorage.Targets(connection);
        MembershipRouteSummary? Routes(Tier0Target target) => target.Sid is { } sid
            ? context.ProtectedPrincipals?.Lookup(sid, target.SidScope)?.MembershipRoutes : null;

        // WHEN DISCOVERY RAN FIRST THE SCOPE IS ALREADY DECIDED AND STORED. Re-deriving it here from
        // the control edges would reintroduce exactly the dependency decision 0116 removed: the
        // edges only exist for objects this selection admitted, so a second selection built from
        // them would be reasoning from its own output.
        if (!scopeAlreadyPlanned)
        {
            OwnershipScopeSelection? selection = null;
            if (input is not null && binding is not null)
            {
                var coverage = OwnershipAuditStorage.UnavailableCoverage with { InputsComplete = input.IsComplete,
                    Limitations = OwnershipAuditStorage.UnavailableCoverage.Limitations & ~Tier0Limitations.InputIncomplete };
                var classifications = Tier0Classifier.QualifyMany(binding, targets.Select(item => item.Identity), input, Routes, cancellationToken).Classifications;
                var edges = ControlEdgeStorage.ReadScopeEdges(connection, description);
                var relations = Relations(binding, targets, edges, ref coverage, cancellationToken);
                selection = OwnershipScopeSelector.Select(binding, description.GenerationId, classifications, relations, coverage,
                    cancellationToken, new ScopeProgress(progress, objectsRead));
                cancellationToken.ThrowIfCancellationRequested();
                if (selection.WasCancelled) throw new OperationCanceledException(cancellationToken);
            }
            else if (input is not null || binding is not null) throw OwnershipAuditStorage.InvalidProof();
            OwnershipAuditStorage.Plan(connection, selection, Routes, cancellationToken);
        }
        progress.Report(new(objectsRead) { Phase = JudgingPhase.AssessingOwnership });
        foreach (var target in OwnershipAuditStorage.Targets(connection).Where(item => item.Selection == OwnershipScopeState.Included))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidates = ControlEdgeStorage.ReadOwnerCandidates(connection, description, target.Identity.DistinguishedName);
            var transitions = new List<ControlEdge>();
            if (candidates.Count != 0)
            {
                var subject = bundle.ReadObjectAttributes(target.Identity.DistinguishedName) ?? throw OwnershipAuditStorage.InvalidProof();
                var permissions = bundle.ReadPermissions(target.Identity.DistinguishedName) ?? throw OwnershipAuditStorage.InvalidProof();
                foreach (var candidate in candidates)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var targetSid = OwnerRightsReading.TargetSid(subject);
                    var holder = permissions.Entries.Select(entry => entry.Trustee)
                        .Select(trustee => trustee.Sid == "S-1-5-10" && targetSid is not null
                            ? trustee with { Sid = targetSid, Name = subject.DistinguishedName, DistinguishedName = subject.DistinguishedName,
                                DomainFqdn = subject.DomainFqdn, WellKnownRole = null } : trustee)
                        .FirstOrDefault(trustee => trustee.Sid == candidate.HolderSid)
                        ?? (permissions.DaclState == DaclState.Null && candidate.HolderSid == "S-1-1-0"
                            ? new PermissionTrustee("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null)
                            : throw OwnershipAuditStorage.InvalidProof());
                    transitions.Add(OwnershipControlDeriver.Transition(candidate, subject, permissions, context, holder, domainSid));
                }
            }
            ControlEdgeStorage.AppendOwnership(connection, description, target.Identity.DistinguishedName, transitions);
            progress.Report(new(objectsRead) { Phase = JudgingPhase.AssessingOwnership });
        }
        cancellationToken.ThrowIfCancellationRequested();
        OwnershipAuditStorage.Complete(connection, description);
    }

    internal static IReadOnlyList<Tier0RelevanceRelation> Relations(Tier0InputBinding input,
        IReadOnlyList<OwnershipAuditStorage.TargetRow> targets, IReadOnlyList<ControlEdge> edges,
        ref Tier0Coverage coverage, CancellationToken cancellationToken)
    {
        var byDn = targets.ToDictionary(item => item.Identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var bySid = targets.Where(item => item.Identity.Sid is not null)
            .GroupBy(item => (item.Identity.Sid!.ToUpperInvariant(), item.Identity.SidScope?.ToUpperInvariant()))
            .ToDictionary(group => group.Key, group => group.ToArray());
        var relations = new List<Tier0RelevanceRelation>();
        foreach (var edge in edges)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = (edge.HolderSid.ToUpperInvariant(), edge.HolderScope?.ToUpperInvariant());
            if (!byDn.TryGetValue(edge.Target, out var target) || !target.Identity.IsValid
                || !bySid.TryGetValue(key, out var holders) || holders.Length != 1 || !holders[0].Identity.IsValid)
            {
                coverage = coverage with { InputsComplete = false, Limitations = coverage.Limitations | Tier0Limitations.IdentityUnverified };
                continue;
            }
            relations.Add(Tier0RelevanceRelation.FromControlEdge(input, holders[0].Identity, target.Identity, edge));
        }
        return relations;
    }

    private sealed class ScopeProgress(IProgress<JudgingRun.JudgingProgress> progress, long objectsRead) : IProgress<OwnershipScopeProgress>
    {
        public void Report(OwnershipScopeProgress value) => progress.Report(new(objectsRead) { Phase = JudgingPhase.SelectingOwnershipScope });
    }
}
