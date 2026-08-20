using System.Net;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Which site the machine running the audit is in, worked out from the address ranges the forest
/// declares.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is computed rather than asked for.</b> Ranking a domain's controllers puts the ones
/// near the operator first, and "near" means <i>in the same site</i>. A machine that is joined to
/// the forest could ask Windows, but a machine auditing someone else's forest cannot - and the
/// forest already publishes everything needed to work it out. This is what Netlogon does
/// internally, computed here from data already read, so it works from a machine that is not joined
/// to the forest being audited.
/// </para>
/// <para>
/// <b>The longest prefix wins, and that is not a tie-break.</b> A forest routinely declares
/// <c>10.0.0.0/8</c> for a whole region and <c>10.20.30.0/24</c> for one office inside it. Both
/// contain the same machine and only the second is true about where it is. Taking the first match,
/// or the shortest, would put a controller on another continent at the top of the list.
/// </para>
/// <para>
/// <b>A machine matching nothing has no site, and that is a value.</b> Incomplete subnet coverage is
/// common. <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c>
/// requires the run to say so rather than resolve to a plausible-looking wrong site, and
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> is why: <i>this run had no site</i>
/// is the most useful thing a bundle can say when somebody asks why a capture took nine hours.
/// </para>
/// </remarks>
public static class OperatorSite
{
    /// <summary>
    /// The site the given addresses place a machine in, or null where the forest declares no range
    /// containing any of them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A malformed subnet name is skipped rather than failing the run.</b> The name of a subnet
    /// object is the range, so a name that is not a range is a subnet nobody can route by - and it
    /// is the forest's defect, not this run's. Refusing to plan a capture over it would let one bad
    /// object in a customer's directory stop an audit that has nothing else wrong with it.
    /// </para>
    /// <para>
    /// <b>Ranges of the wrong family are skipped for the same reason.</b> An IPv4 address is not in
    /// an IPv6 range, and asking is a defect rather than a question with an answer.
    /// </para>
    /// </remarks>
    /// <param name="subnets">The address ranges the forest declares, and the sites they belong to.</param>
    /// <param name="addresses">The addresses of the machine running the audit.</param>
    public static string? For(IReadOnlyList<ForestSubnet> subnets, IEnumerable<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(subnets);
        ArgumentNullException.ThrowIfNull(addresses);

        var machine = addresses.ToList();

        string? best = null;
        var longest = -1;

        foreach (var subnet in subnets)
        {
            if (!IPNetwork.TryParse(subnet.Prefix, out var range))
            {
                continue;
            }

            if (range.PrefixLength <= longest)
            {
                // A shorter or equal prefix cannot beat what is already held. Equal is excluded so
                // that two subnets of the same length declared for different sites resolve to the
                // first the forest returned rather than the last, which keeps the answer stable
                // across runs.
                continue;
            }

            foreach (var address in machine)
            {
                if (address.AddressFamily != range.BaseAddress.AddressFamily
                    || !range.Contains(address))
                {
                    continue;
                }

                best = subnet.Site;
                longest = range.PrefixLength;
                break;
            }
        }

        return best;
    }
}
