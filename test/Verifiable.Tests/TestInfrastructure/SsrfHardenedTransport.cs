using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.OutboundFetch;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Resolves a host name and supplies the resolved addresses for SSRF validation.
/// Injectable so tests can simulate DNS rebinding without touching the network.
/// </summary>
internal delegate ValueTask<IReadOnlyList<IPAddress>> HostResolverDelegate(string host, CancellationToken cancellationToken);


/// <summary>Thrown when a host resolves (or is a literal) to an address the policy forbids.</summary>
internal sealed class SsrfBlockedException: Exception
{
    public SsrfBlockedException() { }

    public SsrfBlockedException(string message): base(message) { }

    public SsrfBlockedException(string message, Exception innerException): base(message, innerException) { }
}


/// <summary>
/// The connection-time half of the SSRF guard, reduced to its testable security
/// decision. The library owns the rule
/// (<see cref="OutboundFetchPolicy.EvaluateResolvedAddress"/>); this is the thin,
/// transport-specific logic an application's
/// <c>SocketsHttpHandler.ConnectCallback</c> (with auto-redirect disabled) would
/// run before connecting: resolve the host, validate <strong>every</strong>
/// resolved address against the policy, and pin to a permitted address —
/// defeating DNS-rebinding the URL gate cannot catch from a host name alone.
/// </summary>
/// <remarks>
/// The actual <c>ConnectCallback</c> + <see cref="System.Net.Sockets.Socket"/>
/// connect is portable .NET glue around <see cref="ResolveAndPinAsync"/> and is
/// not reproduced here — the per-call <see cref="OutboundFetchPolicy"/> reaches
/// it via <c>HttpRequestMessage.Options</c>; only the decision is unit-tested.
/// </remarks>
internal static class SsrfHardenedTransport
{
    /// <summary>
    /// Resolves <paramref name="host"/> and returns the address to pin the
    /// connection to. An IP literal is validated directly; a host name is
    /// resolved via <paramref name="resolver"/> and <strong>every</strong>
    /// resolved address is validated (rejecting the whole host if any address is
    /// blocked — the rebinding defense). Throws <see cref="SsrfBlockedException"/>
    /// when the policy forbids the address(es).
    /// </summary>
    public static async ValueTask<IPAddress> ResolveAndPinAsync(
        string host, OutboundFetchPolicy policy, HostResolverDelegate resolver, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(resolver);

        string candidate = host.Length > 1 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        if(IPAddress.TryParse(candidate, out IPAddress? literal))
        {
            RejectIfBlocked(policy.EvaluateResolvedAddress(literal), host);
            return literal;
        }

        IReadOnlyList<IPAddress> addresses = await resolver(host, cancellationToken).ConfigureAwait(false);
        if(addresses.Count == 0)
        {
            throw new SsrfBlockedException($"Host '{host}' did not resolve to any address.");
        }

        foreach(IPAddress address in addresses)
        {
            RejectIfBlocked(policy.EvaluateResolvedAddress(address), host);
        }

        return addresses[0];

        static void RejectIfBlocked(OutboundFetchDecision decision, string host)
        {
            if(!decision.IsAllowed)
            {
                throw new SsrfBlockedException($"Host '{host}' resolves to a blocked address: {decision.DenyReason}");
            }
        }
    }
}
