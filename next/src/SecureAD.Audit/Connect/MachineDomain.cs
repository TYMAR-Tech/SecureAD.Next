using System.Net.NetworkInformation;

namespace SecureAD.Audit.Connect;

/// <summary>
/// The domain membership of the machine this process is running on.
/// </summary>
/// <remarks>
/// <para>
/// The whole of the platform dependency of bootstrap, kept to two properties so that everything
/// which decides where a run starts can be exercised without being run on a domain-joined machine.
/// </para>
/// <para>
/// <b>Neither value is inferred from the other.</b> A machine can have a NetBIOS domain and no DNS
/// suffix, and the two need not be related in a disjoint namespace - the NetBIOS name is not the
/// first label of the DNS name. Deriving one from the other would produce a plausible-looking domain
/// name that resolves to nothing, and the run would report that a forest could not be reached when
/// what actually happened is that this product invented its name.
/// </para>
/// </remarks>
public sealed class MachineDomain : IMachineDomain
{
    /// <inheritdoc/>
    /// <remarks>
    /// From the network stack's own view of the machine rather than from an environment variable,
    /// which a user profile can carry stale across a rejoin.
    /// </remarks>
    public string? DnsDomain
    {
        get
        {
            var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;

            return string.IsNullOrWhiteSpace(domain) ? null : domain;
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <c>USERDOMAIN</c> names the domain of the logged-on account, which on a domain-joined machine
    /// is the machine's domain and on a workgroup machine is the machine's own name. The second case
    /// is why this is compared against the computer name: a machine reporting itself as its own
    /// domain is in no domain, and returning that would send the locator looking for a forest that
    /// does not exist.
    /// </remarks>
    public string? NetBiosDomain
    {
        get
        {
            var domain = Environment.GetEnvironmentVariable("USERDOMAIN");

            if (string.IsNullOrWhiteSpace(domain)
                || string.Equals(domain, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return domain;
        }
    }
}
