using System.Text;

namespace SecureAD.Audit.Connect;

/// <summary>
/// What a run would read, from which controller, and what it would fall back to - stated before
/// anything is contacted.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a type and not printing code.</b> The same four facts per domain are what the New
/// Audit wizard's domain table shows and what an operator checking a scheduled run needs on a
/// terminal. Written twice they would drift, and the first sign of it would be a preview that
/// disagreed with the run it was previewing.
/// </para>
/// <para>
/// <b>It contacts nobody.</b> Everything here comes from the configuration partition read that
/// discovery already did, per
/// <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c>. That is
/// also its limit, and the limit is stated rather than hidden: a domain's PDC emulator is not
/// established until preflight (<c>0055</c>), so a preview cannot promise the run will not land on
/// one. It says which domains are chosen on incomplete knowledge instead of implying none are.
/// </para>
/// </remarks>
public static class PlanPreview
{
    /// <summary>
    /// Renders the preview as aligned text.
    /// </summary>
    /// <param name="plan">The forest as discovery described it.</param>
    public static string Describe(ForestPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var text = new StringBuilder();

        text.AppendLine($"forest    {plan.Capture.ForestFqdn}");
        text.AppendLine($"site      {DescribeSite(plan)}");
        text.AppendLine();

        foreach (var domain in plan.Selection.Domains)
        {
            text.AppendLine($"domain    {domain.NamingContext}");
            text.AppendLine(
                $"  read from   {domain.PinnedController}"
                + $"{(domain.WasOverridden ? "  (named by the operator)" : string.Empty)}"
                + $"  {DescribeSiteOf(plan, domain)}");

            text.AppendLine(domain.Failover.Count == 0
                ? "  failover    none - this is the only controller the forest names for it"
                : $"  failover    {string.Join(", ", domain.Failover)}");

            if (!domain.IsComplete)
            {
                text.AppendLine(
                    "  note        chosen without every input to the ranking. Its PDC emulator is "
                    + "not established until preflight, so this controller may be it.");
            }

            text.AppendLine();
        }

        foreach (var domain in plan.Selection.DomainsWithNoCandidates)
        {
            text.AppendLine($"domain    {domain}");
            text.AppendLine(
                "  read from   nothing - the forest names no writable controller holding it. The "
                + "cross-reference exists and nothing backs it.");
            text.AppendLine();
        }

        if (!plan.Topology.IsComplete)
        {
            text.AppendLine(
                $"warning   {plan.Topology.ControllersWithNoHostName.Count} controller(s) the forest "
                + "names have no host name and could not be considered. The candidate lists above "
                + "are shorter than the forest is.");
        }

        return text.ToString();
    }

    /// <summary>
    /// Where this machine is, or why that could not be worked out.
    /// </summary>
    /// <remarks>
    /// A forest that declares no subnets and a machine whose address matches none of the subnets a
    /// forest does declare are different faults with different remedies - define the subnets, or
    /// find out why this machine's address is not in any of them. Rendering both as "no site" would
    /// send an operator looking in the wrong place.
    /// </remarks>
    private static string DescribeSite(ForestPlan plan)
    {
        if (plan.Selection.OperatorSite is { } site)
        {
            return site;
        }

        return plan.Topology.Subnets.Count == 0
            ? "unknown - this forest declares no subnets at all, so no machine can be placed in a "
                + "site by address"
            : $"unknown - none of the {plan.Topology.Subnets.Count} subnets this forest declares "
                + "contains an address of this machine";
    }

    /// <summary>
    /// Where a domain's chosen controller is, relative to this machine.
    /// </summary>
    /// <remarks>
    /// <b>Three answers, not two.</b> <c>DomainSelection.IsInOperatorSite</c> is false both when the
    /// controller is genuinely elsewhere and when the run has no site of its own, and the two must
    /// not render alike. Saying "another site" for a run that never established its own site is a
    /// statement about where a customer's controllers are that the product did not measure, which
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids.
    /// </remarks>
    private static string DescribeSiteOf(ForestPlan plan, DomainSelection domain)
    {
        if (plan.Selection.OperatorSite is null)
        {
            return $"(in site {SiteOf(plan, domain.PinnedController)}; whether that is this "
                + "machine's site is unknown)";
        }

        return domain.IsInOperatorSite ? "(same site)" : "(another site)";
    }

    /// <summary>
    /// The site the forest puts a controller in, as the forest names it.
    /// </summary>
    private static string SiteOf(ForestPlan plan, string hostName) =>
        plan.Topology.Controllers
            .FirstOrDefault(c => string.Equals(
                c.HostName, hostName, StringComparison.OrdinalIgnoreCase))
            ?.Site
        ?? "unknown";
}
