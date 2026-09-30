using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

/// <summary>
/// Turns discovered candidates into an admitted scope, then assesses that scope and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the boundary decision 0116 moved.</b> Detailed control and full-control products used
/// to be derived for every streamed object and read back afterwards to work out which handful
/// mattered. They are now derived here, for the targets a supported incoming route from a Tier-0
/// seed actually reached.
/// </para>
/// <para>
/// <b>The evaluators are unchanged and remain the authority.</b> Admission decides which objects are
/// handed to <see cref="ControlEdgeDeriver"/>; it does not decide what any permission grants, and
/// the permission semantics, expectedness and proof of an admitted object are exactly what they were
/// when every object was assessed.
/// </para>
/// <para>
/// <b>Reaching nothing is not the same as finding nothing.</b> If seeds cannot be qualified the
/// coverage says so, and an object that discovery never reached is recorded as not assessed
/// automatically rather than as safe, empty or unimportant.
/// </para>
/// </remarks>
internal static class Tier0AdmissionRun
{
    internal static int Admit(SqliteConnection connection, BundleReader bundle, JudgementDescription description,
        CapturedMembershipInput? input, Tier0InputBinding binding, Tier0DiscoveryScheduler discovery,
        JudgingContext context, Func<string, string?> domainSid, Guid generation, Guid? derivationGeneration,
        CancellationToken cancellationToken, JudgingStatus? status = null)
    {
        ArgumentNullException.ThrowIfNull(discovery);
        ArgumentNullException.ThrowIfNull(binding);
        cancellationToken.ThrowIfCancellationRequested();

        // Without membership input no seed can be qualified, so nothing is admitted. That is an
        // explicit empty scope with its reason recorded, not a claim that the forest is clean.
        if (input is null) return 0;

        OwnershipScopeSelection selection;
        using (var diagnostic = status?.BeginPostPass("scope-selection", generation))
        {
            diagnostic?.Part("resolve-candidates");
            var candidates = discovery.Candidates(diagnostic);
            diagnostic?.Counter("resolvedRelations", candidates.Count);
            diagnostic?.Part("discovery-coverage");
            var coverage = discovery.Coverage();
            diagnostic?.Part("prepare-targets");
            var targets = discovery.Observed.Values.Where(target => target.IsValid).ToArray();
            diagnostic?.Counter("classificationTargets", targets.Length);
            diagnostic?.Part("classify-targets");
            var classifications = Tier0Classifier.QualifyMany(binding, targets, input,
                target => target.Sid is { } sid ? context.ProtectedPrincipals?.Lookup(sid, target.SidScope)?.MembershipRoutes : null,
                cancellationToken).Classifications;
            diagnostic?.Counter("classifiedTargets", classifications.Count());
            diagnostic?.Part("select-scope");
            selection = OwnershipScopeSelector.Select(binding, generation, classifications, candidates,
                Source(coverage), cancellationToken, diagnostic?.ScopeProgress);
            cancellationToken.ThrowIfCancellationRequested();
            if (selection.WasCancelled) throw new OperationCanceledException(cancellationToken);

            // Recorded before detailed products exist; diagnostics do not reconstruct scope from them.
            diagnostic?.Part("save-scope");
            OwnershipAuditStorage.Plan(connection, selection,
                target => target.Sid is { } sid ? context.ProtectedPrincipals?.Lookup(sid, target.SidScope)?.MembershipRoutes : null,
                cancellationToken);
            diagnostic?.Part("save-path-uncertainty");
            PathInputStorage.Write(connection, selection, coverage, discovery.Observed, cancellationToken);
            diagnostic?.Complete();
        }

        using var assessment = status?.BeginPostPass("admitted-control", generation);
        assessment?.Targets(selection.Decisions.Count(item => item.State == OwnershipScopeState.Included));
        var admitted = 0;
        var identitiesPrepared = false;
        foreach (var decision in selection.Decisions.Where(item => item.State == OwnershipScopeState.Included))
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Name lookup scans the forest-wide index. Reuse row identities on this reader for
            // admission and ownership, but do not allocate a map for an empty admitted scope.
            if (!identitiesPrepared)
            {
                assessment?.Part("prepare-identities");
                bundle.PrepareBulkObjectLookup();
                identitiesPrepared = true;
            }
            assessment?.Part("read-evidence");
            var subject = bundle.ReadObjectAttributes(decision.Target.DistinguishedName);

            // An admitted target the capture cannot produce is a gap, not a silent skip. It keeps
            // its descriptor row and stays unassessed.
            if (subject is null)
            {
                assessment?.TargetFinished(available: false);
                continue;
            }
            var permissions = bundle.ReadPermissions(decision.Target.DistinguishedName);
            assessment?.Part("evaluate-control");
            var evaluation = ControlEdgeDeriver.Derive(subject, permissions, context, generation, derivationGeneration, domainSid);
            assessment?.Part("store-control");
            ControlEdgeStorage.Assess(connection, evaluation);
            admitted++;
            assessment?.TargetFinished();
        }

        // The scope was planned before these products existed, so its owner-candidate counts were
        // taken against edges that had not been derived yet.
        assessment?.Part("recount-owner-candidates");
        OwnershipAuditStorage.RecountCandidates(connection, cancellationToken);
        assessment?.Complete();
        return admitted;
    }

    /// <summary>
    /// Carries discovery's limitations into the selector's coverage, so an incomplete scan cannot
    /// produce a scope that claims completeness.
    /// </summary>
    /// <remarks>
    /// <b>The switch is exhaustive on purpose.</b> A default arm would silently give any reason added
    /// later a mapping nobody chose, and the wrong limitation is worse than a build failure - it
    /// understates what a scan could not follow. Adding a reason must mean deciding what it means here.
    /// </remarks>
    private static Tier0Coverage Source(Tier0DiscoveryCoverage coverage)
    {
        var limitations = Tier0Limitations.None;
        if (!coverage.CaptureIsComplete) limitations |= Tier0Limitations.InputIncomplete;
        foreach (var limitation in coverage.Limitations)
            limitations |= limitation.Reason switch
            {
                Tier0DiscoveryReason.CaptureIncomplete or Tier0DiscoveryReason.DescriptorUnavailable
                    or Tier0DiscoveryReason.DescriptorIncomplete => Tier0Limitations.InputIncomplete,
                Tier0DiscoveryReason.NullDacl or Tier0DiscoveryReason.BroadTrustee
                    => Tier0Limitations.ControlQualificationUnsupported,
                Tier0DiscoveryReason.UnresolvedTrustee or Tier0DiscoveryReason.MissingIdentity
                    => Tier0Limitations.IdentityUnverified,
                Tier0DiscoveryReason.UnsupportedRoute => Tier0Limitations.DependencyQualificationUnsupported,
            };

        // Control qualification is unsupported by discovery in every case: a named permission is a
        // captured fact and never an established control operation.
        limitations |= Tier0Limitations.ControlQualificationUnsupported;
        return new(coverage.CaptureIsComplete && (limitations & Tier0Limitations.InputIncomplete) == 0,
            false, true, limitations);
    }
}
