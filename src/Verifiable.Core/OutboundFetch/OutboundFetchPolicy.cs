using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// The per-call policy that governs outbound dereferences of URLs that came out
/// of resolved or otherwise semi-trusted data — federation/OAuth/RFC 9728
/// metadata endpoints, DID documents and their service endpoints, JSON-LD
/// <c>@context</c> URLs, and the like. Carried on the
/// <see cref="ExchangeContext"/> and consulted by the guarded outbound fetch
/// before any URL is contacted, and again on every redirect hop.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Necessary, not sufficient.</strong> <see cref="Evaluate"/> performs
/// the <em>static</em> URL checks — scheme, host allow/deny, and blocked
/// <em>IP-literal</em> ranges (loopback, private, link-local incl. the cloud
/// metadata address, ULA, IPv4-mapped IPv6). It cannot stop a hostname that
/// resolves via DNS to a blocked address (DNS-rebinding): that requires
/// resolving and pinning the address at connection time, which lives in the
/// transport handler. Use this together with a pinning transport.
/// </para>
/// <para>
/// <strong>Secure default, relaxable per call.</strong> <see cref="SecureDefault"/>
/// is HTTPS-only, blocks private/loopback/link-local/ULA literals, and does not
/// follow redirects. A deployment that must reach an internal endpoint relaxes
/// the policy explicitly on the context; the consumer-appropriate default (for
/// example <c>@context</c> resolution uses <see cref="NoNetwork"/>) is chosen at
/// the call site on principled grounds, never to make a test pass.
/// </para>
/// </remarks>
public sealed record OutboundFetchPolicy
{
    private static IReadOnlySet<string> HttpsOnly { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "https" };


    /// <summary>
    /// Whether the policy permits contacting the network at all. When
    /// <see langword="false"/> every URL is denied — the principled default for
    /// JSON-LD <c>@context</c> resolution during signing, where a fetched
    /// context would change the bytes that get signed.
    /// </summary>
    public bool AllowNetwork { get; init; } = true;

    /// <summary>
    /// The permitted URI schemes (case-insensitive). Defaults to <c>https</c>
    /// only.
    /// </summary>
    public IReadOnlySet<string> AllowedSchemes { get; init; } = HttpsOnly;

    /// <summary>
    /// Whether to deny URLs whose host is an IP literal in a loopback, private,
    /// link-local (including <c>169.254.169.254</c>), unique-local, or
    /// unspecified range. Defaults to <see langword="true"/>.
    /// </summary>
    public bool BlockPrivateAndLoopback { get; init; } = true;

    /// <summary>
    /// When non-null, only hosts in this list (matched case-insensitively, exact
    /// host) are permitted. <see langword="null"/> applies no allow-list (the
    /// deny-list and IP-range rules still apply).
    /// </summary>
    public IReadOnlyList<string>? HostAllowList { get; init; }

    /// <summary>Hosts that are always denied (matched case-insensitively, exact host).</summary>
    public IReadOnlyList<string>? HostDenyList { get; init; }

    /// <summary>How redirects are treated. Defaults to <see cref="RedirectMode.None"/>.</summary>
    public RedirectMode Redirects { get; init; } = RedirectMode.None;

    /// <summary>The maximum number of redirect hops to follow. Defaults to 0.</summary>
    public int MaxRedirects { get; init; }


    /// <summary>
    /// The secure default: HTTPS-only, blocks private/loopback/link-local/ULA
    /// IP literals, follows no redirects, network enabled.
    /// </summary>
    public static OutboundFetchPolicy SecureDefault { get; } = new();

    /// <summary>
    /// A policy that denies all outbound network access. The principled default
    /// for JSON-LD <c>@context</c> resolution (static contexts only).
    /// </summary>
    public static OutboundFetchPolicy NoNetwork { get; } = new() { AllowNetwork = false };


    /// <summary>
    /// Classifies a single URL against this policy. Pure and total — never
    /// throws (other than for a null argument), never touches the network.
    /// </summary>
    /// <param name="target">The URL to classify.</param>
    /// <returns>An allow verdict, or a deny verdict carrying the reason.</returns>
    public OutboundFetchDecision Evaluate(Uri target)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(!AllowNetwork)
        {
            return OutboundFetchDecision.Denied("Outbound network access is disabled by policy.");
        }

        if(!target.IsAbsoluteUri)
        {
            return OutboundFetchDecision.Denied("URL must be absolute.");
        }

        if(!AllowedSchemes.Contains(target.Scheme))
        {
            return OutboundFetchDecision.Denied($"Scheme '{target.Scheme}' is not permitted.");
        }

        string host = target.Host;

        if(HostDenyList is not null && ContainsHost(HostDenyList, host))
        {
            return OutboundFetchDecision.Denied($"Host '{host}' is on the deny list.");
        }

        if(HostAllowList is not null && !ContainsHost(HostAllowList, host))
        {
            return OutboundFetchDecision.Denied($"Host '{host}' is not on the allow list.");
        }

        if(TryParseHostAddress(host, out IPAddress? address))
        {
            //The host is an IP literal — classify it with the same rule a
            //pinning transport applies to a resolved address.
            return EvaluateResolvedAddress(address);
        }

        return OutboundFetchDecision.Allowed;
    }


    /// <summary>
    /// Classifies a <em>resolved</em> IP address against the policy's IP-range
    /// rules. A connection-time pinning transport calls this on each address a
    /// host name resolves to — and connects only to a permitted, pinned address
    /// — to defeat the DNS-rebinding that <see cref="Evaluate"/> cannot catch
    /// from a host name alone (the URL gate is necessary, this is the sufficient
    /// other half). Pure and total; never throws beyond a null argument, never
    /// touches the network.
    /// </summary>
    /// <param name="address">The resolved address to classify.</param>
    public OutboundFetchDecision EvaluateResolvedAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if(!AllowNetwork)
        {
            return OutboundFetchDecision.Denied("Outbound network access is disabled by policy.");
        }

        if(BlockPrivateAndLoopback && IsBlockedAddress(address))
        {
            return OutboundFetchDecision.Denied(
                $"Address '{address}' is a loopback, private, link-local, or unique-local address.");
        }

        return OutboundFetchDecision.Allowed;
    }


    private static bool ContainsHost(IReadOnlyList<string> hosts, string host)
    {
        for(int i = 0; i < hosts.Count; ++i)
        {
            if(string.Equals(hosts[i], host, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }


    //Uri.Host wraps IPv6 literals in brackets; trim them before parsing. A
    //non-literal host (a DNS name) does not parse and is left to the
    //connection-time pinning transport to resolve and re-check.
    private static bool TryParseHostAddress(string host, [NotNullWhen(true)] out IPAddress? address)
    {
        string candidate = host.Length > 1 && host[0] == '[' && host[^1] == ']'
            ? host[1..^1]
            : host;

        if(IPAddress.TryParse(candidate, out IPAddress? parsed))
        {
            address = parsed;
            return true;
        }

        address = null;
        return false;
    }


    private static bool IsBlockedAddress(IPAddress address)
    {
        //Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) so a mapped literal
        //cannot smuggle a blocked IPv4 address past the IPv4 checks.
        if(address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if(IPAddress.IsLoopback(address))
        {
            return true;
        }

        if(address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            return b[0] == 0                                  //0.0.0.0/8 unspecified/this-host.
                || b[0] == 10                                 //10.0.0.0/8 private.
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)  //172.16.0.0/12 private.
                || (b[0] == 192 && b[1] == 168)               //192.168.0.0/16 private.
                || (b[0] == 169 && b[1] == 254)               //169.254.0.0/16 link-local incl. 169.254.169.254.
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);//100.64.0.0/10 carrier-grade NAT.
        }

        if(address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] b = address.GetAddressBytes();
            bool unspecified = true;
            for(int i = 0; i < b.Length; ++i)
            {
                if(b[i] != 0) { unspecified = false; break; }
            }

            return unspecified                       //:: unspecified.
                || (b[0] & 0xFE) == 0xFC              //fc00::/7 unique-local.
                || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80); //fe80::/10 link-local.
        }

        return false;
    }
}