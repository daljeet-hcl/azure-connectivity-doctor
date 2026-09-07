using System.Net;
using System.Net.Sockets;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Classifies IP addresses so the analyzer can reason about private endpoints and split DNS.
/// </summary>
/// <remarks>
/// This matters because an Azure Private Endpoint works by making a public host name resolve to
/// a private address. Whether the answer is private or public is therefore the single most
/// useful signal available for diagnosing private-link problems from inside a workload.
/// </remarks>
public static class IpAddressClassifier
{
    /// <summary>
    /// Determines whether an address is in a private, loopback or link-local range.
    /// </summary>
    /// <param name="address">The address to classify.</param>
    /// <returns><see langword="true"/> when the address is not globally routable.</returns>
    public static bool IsPrivate(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] octets = address.GetAddressBytes();

            // 10.0.0.0/8
            if (octets[0] == 10)
            {
                return true;
            }

            // 172.16.0.0/12
            if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            {
                return true;
            }

            // 192.168.0.0/16
            if (octets[0] == 192 && octets[1] == 168)
            {
                return true;
            }

            // 169.254.0.0/16 link-local, which includes the Azure instance metadata range.
            if (octets[0] == 169 && octets[1] == 254)
            {
                return true;
            }

            // 100.64.0.0/10 carrier-grade NAT, used by some Azure networking features.
            if (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
            {
                return true;
            }

            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
            {
                return true;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                return IsPrivate(address.MapToIPv4());
            }

            return false;
        }

        return false;
    }

    /// <summary>
    /// Returns a short label describing the address scope, for use in evidence output.
    /// </summary>
    /// <param name="address">The address to describe.</param>
    /// <returns>Either <c>private</c> or <c>public</c>.</returns>
    public static string DescribeScope(IPAddress address)
    {
        return IsPrivate(address) ? "private" : "public";
    }
}
