using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// This machine's own addresses, which is how a run works out which site it is in.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="MachineDomain"/> and from <see cref="OperatorSite"/> because it is the
/// only part of siting that touches the network stack. Keeping it apart is what lets the matching
/// rules in <see cref="OperatorSite"/> be exercised against any address an argument supplies,
/// including a machine's that the tests are not running on.
/// </para>
/// <para>
/// Loopback, link-local and tunnel addresses are left out. None of them appears in a forest's
/// <c>subnet</c> objects, and a machine matched to a site on the strength of one would be sited by
/// an accident of its own network configuration rather than by where it is.
/// </para>
/// </remarks>
public static class MachineAddresses
{
    /// <summary>
    /// The addresses of every network interface that is up, excluding loopback and tunnels.
    /// </summary>
    /// <remarks>
    /// A <see cref="Result{T}"/> rather than a bare list, because an empty list and a failed
    /// enumeration are different facts with the same shape: the first says this machine has no
    /// usable address and the second says nobody looked. A run sited on the second would report
    /// "no site" as though it had measured one.
    /// </remarks>
    public static Result<IReadOnlyList<IPAddress>> OfThisMachine()
    {
        var addresses = new List<IPAddress>();

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up
                    || adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback
                        or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                foreach (var address in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily is not (AddressFamily.InterNetwork
                        or AddressFamily.InterNetworkV6))
                    {
                        continue;
                    }

                    if (IPAddress.IsLoopback(address.Address)
                        || address.Address.IsIPv6LinkLocal
                        || IsIPv4LinkLocal(address.Address))
                    {
                        continue;
                    }

                    addresses.Add(address.Address);
                }
            }
        }
        catch (NetworkInformationException exception)
        {
            return Result<IReadOnlyList<IPAddress>>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "MachineAddressesCouldNotBeRead",
                ErrorSeverity.Degraded,
                "This machine's own network addresses could not be read: "
                + $"{exception.Message}. Without them the run cannot tell which site it is in, so "
                + "no controller can be preferred for being nearby.",
                context: null));
        }

        return Result<IReadOnlyList<IPAddress>>.Success(addresses);
    }

    /// <summary>
    /// Whether this is a 169.254.0.0/16 address, which means DHCP did not answer.
    /// </summary>
    private static bool IsIPv4LinkLocal(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var octets = address.GetAddressBytes();
        return octets[0] == 169 && octets[1] == 254;
    }
}
