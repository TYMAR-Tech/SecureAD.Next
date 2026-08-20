using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// The pass that asks every preflight question of every domain, before a run commits hours to a
/// controller that was never going to work.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A8, and
/// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c> is the record
/// bound to it. The four questions and the reasoning for each are there.
/// </para>
/// <para>
/// <b>It never stops early, and that is the point of it.</b> The loop this replaced returned on the
/// first bad domain, so a forest of nine domains with three faults cost four validate passes to
/// discover three facts that were all knowable in one - each pass repeating discovery and
/// reconnecting to every healthy domain. <c>0048</c> requires that every question is answered for
/// every domain before any is allowed to stop the run.
/// </para>
/// <para>
/// <b>It asks several domains at once, and never one controller twice at once.</b> Those are two
/// different rules and only the first of them changed. <c>0048</c> originally made the whole pass
/// sequential; a forest of thirty domains at ten seconds each is five minutes an operator spends
/// watching a window before he may press anything, and it buys nothing, because the reason for the
/// original rule was never the count of connections but the risk of two requests meeting on one
/// machine. That risk is now held where it belongs, by <see cref="PreflightDispatch"/>, which lets
/// every controller be asked at once and each one only once at a time.
/// </para>
/// <para>
/// <b>Why this is not a method on <see cref="CaptureSession"/>.</b> The session builds its own
/// channel factory and takes none, per
/// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c> - it decides nothing an operator could
/// decide differently. Correct, and it means a loop written inside it could not be exercised
/// without a live forest. Taking the factory as an argument here puts the whole pass under test
/// against the controller model, and leaves the session's own surface unchanged.
/// </para>
/// <para>
/// <b>The connections are closed again immediately.</b> A capture opens its own, per the failure
/// policy in <c>docs/next/S-10-politeness.md</c>: a naming context that has to be read again needs
/// a fresh connection, so holding these open would save nothing and would keep a session on every
/// controller in the forest for the length of the run.
/// </para>
/// <para>
/// <b>This decides which domains are asked; <see cref="DomainPreflightRead"/> does the asking.</b>
/// The two were one file until 2026-08-16. Splitting them changed no behaviour and made the rule
/// in <c>SerializedDirectoryAccessGateTests</c> enforceable here - a file may dispatch work or
/// speak to a directory, never both.
/// </para>
/// </remarks>
public static class Preflight
{
    /// <summary>
    /// Asks all four questions of every domain in the plan and returns every answer.
    /// </summary>
    /// <remarks>
    /// The plan's configuration and schema units are not asked about. They were read from the
    /// controller the operator named, and <see cref="CapturePlan"/> already confirmed them against
    /// that controller's own published partition list. What it could not confirm is every other
    /// domain, because it holds one controller's list - a check written there would pass for every
    /// other domain no matter what, which is the shape of <c>F-S28-2</c>. Here there is a real
    /// connection to ask.
    /// </remarks>
    /// <param name="connections">How a connection to each domain's controller is opened.</param>
    /// <param name="plan">The forest as discovery described it, with its selection and roles.</param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public static async Task<PreflightReport> RunAsync(
        IDirectoryChannelFactory connections, ForestPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentNullException.ThrowIfNull(plan);

        var units = plan.Capture.Units.ToList();

        var asking = new List<int>();
        for (var i = 0; i < units.Count; i++)
        {
            if (units[i].Kind == NamingContextKind.Domain)
            {
                asking.Add(i);
            }
        }

        var outcomes = await PreflightDispatch.TogetherAsync(
            [.. asking.Select(index => units[index])],
            (unit, turns) => AskOneDomainAsync(connections, plan, unit, turns, cancellationToken),
            cancellationToken)
            .ConfigureAwait(false);

        var domains = new List<DomainPreflight>();

        for (var at = 0; at < asking.Count; at++)
        {
            units[asking[at]] = outcomes[at].Unit;
            domains.Add(outcomes[at].Row);
        }

        return new PreflightReport(plan.Capture with { Units = units }, domains);
    }

    /// <summary>
    /// One domain, start to finish: asked, moved off its PDC emulator where it should be, and
    /// asked again where it moved.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This reads the plan and writes nothing outside its own return value.</b> It once did the
    /// opposite: the loop above carried <c>roles</c> and <c>selection</c> from one domain to the
    /// next and rewrote both mid-pass, so a domain's re-pin re-ranked every other domain as a side
    /// effect. That was inert only because a controller holds one domain in a real forest, and so
    /// another domain's role holder never appeared in this domain's candidate list -
    /// <c>ControllerSelection</c> has no rule about it and ranks role holders by host name alone.
    /// An assumption that holds by luck stops holding the moment two of these run at once, which is
    /// why the state is gone rather than guarded.
    /// </para>
    /// <para>
    /// <b>Both reads take a turn from <see cref="PreflightDispatch"/>.</b> They are against
    /// different controllers, and different domains are almost always on different controllers
    /// again - but almost always is not a guarantee this code holds, so the turns make it one
    /// rather than inheriting it from Active Directory.
    /// </para>
    /// </remarks>
    private static async Task<DomainOutcome> AskOneDomainAsync(
        IDirectoryChannelFactory connections,
        ForestPlan plan,
        CaptureUnit unit,
        PreflightDispatch turns,
        CancellationToken cancellationToken)
    {
        var asked = await turns.OneAtATimeAsync(
            unit.DomainController,
            () => DomainPreflightRead.AskAsync(connections, unit, plan, cancellationToken),
            cancellationToken)
            .ConfigureAwait(false);

        // 0055: the PDC emulator is established here, over the connection just used, and fed back
        // into ranking. Discovery deliberately asked no domain about it.
        var alternative = MoveOffPdcEmulator(plan, unit, asked.Established);

        if (alternative is null)
        {
            return new DomainOutcome(
                unit, Describe(asked, plan.Selection, unit, repinned: false));
        }

        // The pinned controller is this domain's PDC emulator and a same-site alternative exists,
        // so the domain is preflighted again against it. The unit is rewritten and returned: a
        // re-pin that changed only the report would leave capture reading the machine the re-pin
        // exists to avoid.
        var moved = unit with { DomainController = alternative.PinnedController };

        var second = await turns.OneAtATimeAsync(
            moved.DomainController,
            () => DomainPreflightRead.AskAsync(connections, moved, plan, cancellationToken),
            cancellationToken)
            .ConfigureAwait(false);

        return new DomainOutcome(
            moved, Describe(second, alternative.Selection, moved, repinned: true));
    }

    /// <summary>
    /// What one domain produced: the controller the run will read it from, and the row reporting it.
    /// </summary>
    private sealed record DomainOutcome(CaptureUnit Unit, DomainPreflight Row);

    /// <summary>
    /// Whether this domain should move off the controller it is pinned to, and where to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null means stay: either the PDC emulator was never established, or the pinned controller is
    /// not it, or it is and the forest offers no alternative in the operator's site. The last case
    /// is the one <c>0055</c> allows to proceed, and it is reported rather than retried - moving to
    /// a controller in another site would trade a busy machine for a slow link, which is a different
    /// bad outcome and not one an operator asked for.
    /// </para>
    /// <para>
    /// It is asked once per domain and never in a loop. Re-ranking with the PDC emulator known
    /// cannot produce that same emulator again, so a second pass could only repeat the first.
    /// </para>
    /// <para>
    /// <b>It re-ranks from the plan, never from what another domain's re-pin left behind.</b> The
    /// only role folded in is this domain's own, so the answer for one domain does not depend on
    /// which domains were asked before it or on whether they finished.
    /// </para>
    /// </remarks>
    private static Repin? MoveOffPdcEmulator(
        ForestPlan plan,
        CaptureUnit unit,
        DomainPdcEmulator? established)
    {
        if (established is not
            { Knowledge: PdcEmulatorKnowledge.Established, Holder.HostName: { } holder })
        {
            return null;
        }

        if (!string.Equals(holder, unit.DomainController, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var reranked = ControllerSelection.For(
            plan.Topology,
            plan.Roles.With(established),
            plan.Selection.OperatorSite,
            plan.Capture.Units
                .Where(u => u.Kind == NamingContextKind.Domain)
                .Select(u => u.NamingContext),
            Overrides(plan.Selection));

        if (!reranked.IsSuccess)
        {
            return null;
        }

        var moved = reranked.Value!.Domains.FirstOrDefault(d => string.Equals(
            d.NamingContext, unit.NamingContext, StringComparison.OrdinalIgnoreCase));

        if (moved is null
            || string.Equals(moved.PinnedController, holder, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new Repin(reranked.Value!, moved.PinnedController);
    }

    /// <summary>
    /// A domain moving off its PDC emulator: the ranking that proved it, and where it moved to.
    /// </summary>
    private sealed record Repin(ControllerSelection Selection, string PinnedController);

    /// <summary>
    /// The overrides that produced a selection, so re-ranking obeys the same ones.
    /// </summary>
    /// <remarks>
    /// An overridden domain keeps its override through a re-pin. An operator who named a controller
    /// gets that controller or a refusal, per
    /// <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>; silently moving him off
    /// it because it holds a role would be the substitution the refusal exists to prevent.
    /// </remarks>
    private static IReadOnlyDictionary<string, string> Overrides(ControllerSelection selection) =>
        selection.Domains
            .Where(d => d.WasOverridden)
            .ToDictionary(d => d.NamingContext, d => d.PinnedController, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Joins what a domain answered to what selection knew, so a row states both.
    /// </summary>
    private static DomainPreflight Describe(
        DomainAnswers asked, ControllerSelection selection, CaptureUnit unit, bool repinned)
    {
        var chosen = selection.Domains.FirstOrDefault(d => string.Equals(
            d.NamingContext, unit.NamingContext, StringComparison.OrdinalIgnoreCase));

        var knowledge = asked.Established?.Knowledge ?? PdcEmulatorKnowledge.NotYetEstablished;

        var onPdc = asked.Established is
            { Knowledge: PdcEmulatorKnowledge.Established, Holder.HostName: { } holder }
            && string.Equals(holder, unit.DomainController, StringComparison.OrdinalIgnoreCase);

        return asked.Preflight with
        {
            PdcEmulator = knowledge,
            ReadFromPdcEmulator = onPdc,
            WasRepinnedOffPdcEmulator = repinned,
            SelectionWasInformed = chosen?.IsComplete ?? false,
            Alternatives = chosen?.Failover ?? [],
            ControllerWasNamedByOperator = chosen?.WasOverridden ?? false,
        };
    }
}
