using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Why a controller was chosen to read a domain from, in the order the reasons were applied.
/// </summary>
/// <param name="NamingContext">The domain this concerns.</param>
/// <param name="PinnedController">
/// The controller the run reads this domain from, by DNS host name.
/// </param>
/// <param name="Failover">
/// The remaining candidates in ranked order, which is the list
/// <c>docs/decisions/0040-a-failed-domain-is-read-again-from-another-controller.md</c> walks when a
/// read fails. Empty means this domain has one candidate and no second chance.
/// </param>
/// <param name="IsInOperatorSite">
/// Whether the pinned controller is in the same site as the machine running the audit. False where
/// no candidate was, and also false where the run has no site of its own.
/// </param>
/// <param name="WasOverridden">Whether an operator named this controller rather than ranking it.</param>
public sealed record DomainSelection(
    string NamingContext,
    string PinnedController,
    IReadOnlyList<string> Failover,
    bool IsInOperatorSite,
    bool WasOverridden)
{
    /// <summary>
    /// Whether this domain was ranked on every input the ranking wants, rather than on the ones
    /// that happened to be available.
    /// </summary>
    /// <remarks>
    /// False where the run has no site of its own, or where the domain's PDC emulator was not
    /// established - in which case the busiest machine in the domain sorted level with every other
    /// and may be the one pinned here. A caller reading <see cref="PinnedController"/> without this
    /// cannot tell a fully informed choice from a coin toss between equals, because both produce
    /// exactly one host name.
    /// </remarks>
    public bool IsComplete { get; init; }
}

/// <summary>
/// Which controller each domain is read from, chosen from the candidate list without contacting
/// anything.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is pure arithmetic over data already read.</b> It opens no connection and resolves no
/// name, which is what lets every ranking rule be exercised without a directory. The inputs are
/// <see cref="ForestTopology"/>, <see cref="ForestRoles"/> and the operator's own site.
/// </para>
/// <para>
/// <b>The order of the rules is the whole of the behaviour.</b> Same site first, because a
/// wide-area read of a large domain is the difference between an audit that finishes in an evening
/// and one that does not. Then no established operations master role, the PDC emulator above all,
/// per <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c>. Then lexically by
/// host name, so the same candidate set always produces the same choice and two runs a week apart
/// pick the same controller unless the forest changed.
/// </para>
/// <para>
/// <b>An override is obeyed or the run stops.</b> A named controller that is not an eligible
/// candidate for that domain fails the whole selection and never falls back to the automatic
/// choice. The predecessor fell back silently, so an operator who mistyped a host name got a
/// successful run against a controller they did not name, with nothing recording the substitution.
/// A pinned controller that was quietly not the pinned controller defeats the point of pinning.
/// </para>
/// <para>
/// <b>A domain with no candidates is not an error here.</b> The forest itself is saying that no
/// controller holds it - an orphaned cross-reference, a failed demotion - and what happens next is
/// an operator's attestation per
/// <c>docs/decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md</c>. This records
/// the fact and leaves the decision to the surface that can ask a human.
/// </para>
/// </remarks>
public sealed class ControllerSelection
{
    private ControllerSelection(
        IReadOnlyList<DomainSelection> domains,
        IReadOnlyList<string> domainsWithNoCandidates,
        string? operatorSite)
    {
        Domains = domains;
        DomainsWithNoCandidates = domainsWithNoCandidates;
        OperatorSite = operatorSite;
    }

    /// <summary>One entry per domain a controller was found for, in the order asked about.</summary>
    public IReadOnlyList<DomainSelection> Domains { get; }

    /// <summary>
    /// The domains the forest names no writable controller for. These are not planned against and
    /// not failures; they stop for an attestation.
    /// </summary>
    public IReadOnlyList<string> DomainsWithNoCandidates { get; }

    /// <summary>
    /// The site the machine running the audit is in, or <see langword="null"/> where it matched no
    /// subnet the forest declares.
    /// </summary>
    /// <remarks>
    /// Null is carried rather than resolved to a plausible-looking site. It is also the most useful
    /// thing a bundle can say when someone asks why a capture took nine hours.
    /// </remarks>
    public string? OperatorSite { get; }

    /// <summary>
    /// Whether every domain was both found a controller and ranked on every input the ranking wants.
    /// </summary>
    public bool IsComplete =>
        DomainsWithNoCandidates.Count == 0 && Domains.All(domain => domain.IsComplete);

    /// <summary>
    /// Chooses a controller for each domain, and orders the rest as that domain's failover list.
    /// </summary>
    /// <param name="topology">The candidate list, from the configuration partition.</param>
    /// <param name="roles">
    /// The operations master roles, so a role holder can be ranked last. A domain whose PDC emulator
    /// is not established simply does not benefit from that rule, and says so.
    /// </param>
    /// <param name="operatorSite">
    /// The site the audit is being run from, or <see langword="null"/> where the machine matched no
    /// subnet. Null means no site preference, not a preference for nothing.
    /// </param>
    /// <param name="domainNamingContexts">Every domain the forest has, from its cross-references.</param>
    /// <param name="overrides">
    /// Controllers an operator named, keyed by domain naming context. Empty when none were named.
    /// </param>
    public static Result<ControllerSelection> For(
        ForestTopology topology,
        ForestRoles roles,
        string? operatorSite,
        IEnumerable<string> domainNamingContexts,
        IReadOnlyDictionary<string, string> overrides)
    {
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(domainNamingContexts);
        ArgumentNullException.ThrowIfNull(overrides);

        var selections = new List<DomainSelection>();
        var withNoCandidates = new List<string>();

        foreach (var namingContext in domainNamingContexts)
        {
            var candidates = Rank(topology, roles, operatorSite, namingContext);

            if (candidates.Count == 0)
            {
                withNoCandidates.Add(namingContext);
                continue;
            }

            var pdcEstablished = roles.PdcEmulators.Any(pdc =>
                pdc.Knowledge == PdcEmulatorKnowledge.Established
                && string.Equals(pdc.NamingContext, namingContext, StringComparison.OrdinalIgnoreCase));

            if (!overrides.TryGetValue(namingContext, out var named))
            {
                selections.Add(new DomainSelection(
                    namingContext,
                    candidates[0].HostName,
                    [.. candidates.Skip(1).Select(c => c.HostName)],
                    IsInOperatorSite: IsInOperatorSite(candidates[0], operatorSite),
                    WasOverridden: false)
                {
                    IsComplete = operatorSite is not null && pdcEstablished,
                });

                continue;
            }

            var chosen = candidates.FirstOrDefault(candidate =>
                string.Equals(candidate.HostName, named, StringComparison.OrdinalIgnoreCase));

            if (chosen is null)
            {
                return Result<ControllerSelection>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "OverriddenControllerIsNotACandidate",
                    ErrorSeverity.Failed,
                    $"{named} was named as the controller to read {namingContext} from, and the "
                    + "forest does not list it as holding a writable replica of that domain. The "
                    + "candidates it does list are "
                    + $"{string.Join(", ", candidates.Select(c => c.HostName))}. The run stops here "
                    + "rather than reading the domain from a controller nobody named: a pinned "
                    + "controller that was quietly not the pinned controller defeats the point of "
                    + "pinning.",
                    namingContext));
            }

            selections.Add(new DomainSelection(
                namingContext,
                chosen.HostName,
                [.. candidates.Where(c => c != chosen).Select(c => c.HostName)],
                IsInOperatorSite: IsInOperatorSite(chosen, operatorSite),
                WasOverridden: true)
            {
                IsComplete = operatorSite is not null && pdcEstablished,
            });
        }

        return new ControllerSelection(selections, withNoCandidates, operatorSite);
    }

    /// <summary>
    /// The candidates for one domain, best first.
    /// </summary>
    /// <remarks>
    /// Eligibility is holding a writable replica of the domain, which is the whole of the test: a
    /// read-only controller never reached the candidate list, so nothing here has to know what one
    /// is.
    /// </remarks>
    private static List<ForestController> Rank(
        ForestTopology topology, ForestRoles roles, string? operatorSite, string namingContext) =>
        [.. topology.Controllers
            .Where(controller => controller.WritableNamingContexts.Any(held =>
                string.Equals(held, namingContext, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(controller => IsInOperatorSite(controller, operatorSite))
            .ThenBy(controller => roles.HoldsAnEstablishedRole(controller.HostName))
            .ThenBy(controller => controller.HostName, StringComparer.OrdinalIgnoreCase)];

    /// <summary>
    /// Whether a controller shares the operator's site, which is false whenever the run has no site
    /// of its own rather than true for everything.
    /// </summary>
    private static bool IsInOperatorSite(ForestController controller, string? operatorSite) =>
        operatorSite is not null
        && string.Equals(controller.Site, operatorSite, StringComparison.OrdinalIgnoreCase);
}
