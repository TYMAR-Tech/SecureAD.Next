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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(discovery);
        ArgumentNullException.ThrowIfNull(binding);
        cancellationToken.ThrowIfCancellationRequested();

        // Without membership input no seed can be qualified, so nothing is admitted. That is an
        // explicit empty scope with its reason recorded, not a claim that the forest is clean.
        if (input is null) return 0;

        var candidates = discovery.Candidates();
        var coverage = discovery.Coverage();
        var targets = discovery.Observed.Values.Where(target => target.IsValid).ToArray();
        var classifications = Tier0Classifier.ClassifyMany(binding, targets, input,
            target => target.Sid is { } sid ? context.ProtectedPrincipals?.Lookup(sid, target.SidScope)?.MembershipRoutes : null,
            cancellationToken);

        var selection = OwnershipScopeSelector.Select(binding, generation, classifications, candidates,
            Source(coverage), cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (selection.WasCancelled) throw new OperationCanceledException(cancellationToken);

        // Recorded before the products are derived, so the ownership pass reads this decision rather
        // than reconstructing scope from the edges below. Reconstructing it would make the selection
        // depend on the very products it was supposed to gate.
        OwnershipAuditStorage.Plan(connection, selection,
            target => target.Sid is { } sid ? context.ProtectedPrincipals?.Lookup(sid, target.SidScope)?.MembershipRoutes : null,
            cancellationToken);

        var admitted = 0;
        foreach (var decision in selection.Decisions.Where(item => item.State == OwnershipScopeState.Included))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var subject = bundle.ReadObjectAttributes(decision.Target.DistinguishedName);

            // An admitted target the capture cannot produce is a gap, not a silent skip. It keeps
            // its descriptor row and stays unassessed.
            if (subject is null) continue;
            var permissions = bundle.ReadPermissions(decision.Target.DistinguishedName);
            ControlEdgeStorage.Assess(connection, ControlEdgeDeriver.Derive(subject, permissions, context,
                generation, derivationGeneration, domainSid, includeOwnerTransitions: false));
            admitted++;
        }

        // The scope was planned before these products existed, so its owner-candidate counts were
        // taken against edges that had not been derived yet.
        OwnershipAuditStorage.RecountCandidates(connection, cancellationToken);
        return admitted;
    }

    /// <summary>
    /// Carries discovery's limitations into the selector's coverage, so an incomplete scan cannot
    /// produce a scope that claims completeness.
    /// </summary>
    private static Tier0Coverage Source(Tier0DiscoveryCoverage coverage)
    {
        var limitations = Tier0Limitations.None;
        if (!coverage.CaptureIsComplete) limitations |= Tier0Limitations.InputIncomplete;
        if (!coverage.InputScanCompleted) limitations |= Tier0Limitations.ProcessingIncomplete;
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
                _ => Tier0Limitations.ProcessingIncomplete,
            };

        // Control qualification is unsupported by discovery in every case: a named permission is a
        // captured fact and never an established control operation.
        limitations |= Tier0Limitations.ControlQualificationUnsupported;
        return new(coverage.CaptureIsComplete && (limitations & Tier0Limitations.InputIncomplete) == 0,
            false, coverage.InputScanCompleted, limitations);
    }
}
