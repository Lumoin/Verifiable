using System;
using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;

namespace Verifiable.Tests.Core;

/// <summary>
/// Unit tests for <see cref="OutboundFetchPolicy.Evaluate"/> — the static URL
/// gate (scheme, host allow/deny, blocked IP-literal ranges) — and the per-call
/// carrier on <see cref="ExchangeContext"/>. The connection-time DNS-rebinding
/// guarantee (hostname → resolved IP pinning) is a separate transport concern
/// and is not exercised here.
/// </summary>
[TestClass]
internal sealed class OutboundFetchPolicyTests
{
    [TestMethod]
    public void SecureDefaultAllowsHttpsPublicHostAndRejectsNonHttps()
    {
        OutboundFetchPolicy policy = OutboundFetchPolicy.SecureDefault;

        Assert.IsTrue(policy.Evaluate(new Uri("https://example.com/.well-known/x")).IsAllowed,
            "https to a public host is allowed by the secure default.");
        Assert.IsTrue(policy.Evaluate(new Uri("https://93.184.216.34/meta")).IsAllowed,
            "https to a public IP literal is allowed.");

        Assert.IsFalse(policy.Evaluate(new Uri("http://example.com/")).IsAllowed,
            "http is rejected (https-only default).");
        Assert.IsFalse(policy.Evaluate(new Uri("ftp://example.com/")).IsAllowed,
            "non-http(s) schemes are rejected.");
    }


    [TestMethod]
    public void SecureDefaultBlocksInternalIpLiterals()
    {
        OutboundFetchPolicy policy = OutboundFetchPolicy.SecureDefault;

        string[] blocked =
        [
            "https://127.0.0.1/",            //loopback
            "https://10.0.0.1/",             //private 10/8
            "https://172.16.0.1/",           //private 172.16/12 (low)
            "https://172.31.255.254/",       //private 172.16/12 (high)
            "https://192.168.1.1/",          //private 192.168/16
            "https://169.254.169.254/latest/meta-data/", //link-local cloud metadata
            "https://100.64.0.1/",           //carrier-grade NAT 100.64/10
            "https://0.0.0.0/",              //unspecified
            "https://[::1]/",                //IPv6 loopback
            "https://[fe80::1]/",            //IPv6 link-local
            "https://[fc00::1]/",            //IPv6 unique-local
            "https://[::ffff:127.0.0.1]/",   //IPv4-mapped loopback must not slip through
        ];

        foreach(string url in blocked)
        {
            Assert.IsFalse(policy.Evaluate(new Uri(url)).IsAllowed,
                $"{url} must be denied as an internal/loopback/link-local address.");
        }
    }


    [TestMethod]
    public void RelativeUriIsDenied()
    {
        Assert.IsFalse(
            OutboundFetchPolicy.SecureDefault.Evaluate(new Uri("/relative", UriKind.Relative)).IsAllowed,
            "A relative URI cannot be classified and is denied.");
    }


    [TestMethod]
    public void NoNetworkDeniesEverything()
    {
        OutboundFetchPolicy policy = OutboundFetchPolicy.NoNetwork;

        Assert.IsFalse(policy.Evaluate(new Uri("https://example.com/")).IsAllowed,
            "NoNetwork denies even an otherwise-allowed https public host.");
    }


    [TestMethod]
    public void HostDenyListBlocksAndAllowListRestricts()
    {
        OutboundFetchPolicy denyList = OutboundFetchPolicy.SecureDefault with
        {
            HostDenyList = ["blocked.example"],
        };
        Assert.IsFalse(denyList.Evaluate(new Uri("https://blocked.example/")).IsAllowed,
            "A deny-listed host is rejected (case-insensitive).");
        Assert.IsFalse(denyList.Evaluate(new Uri("https://BLOCKED.example/")).IsAllowed,
            "Deny-list matching is case-insensitive.");
        Assert.IsTrue(denyList.Evaluate(new Uri("https://other.example/")).IsAllowed,
            "A host not on the deny list is still allowed.");

        OutboundFetchPolicy allowList = OutboundFetchPolicy.SecureDefault with
        {
            HostAllowList = ["trusted.example"],
        };
        Assert.IsTrue(allowList.Evaluate(new Uri("https://trusted.example/")).IsAllowed,
            "An allow-listed host is permitted.");
        Assert.IsFalse(allowList.Evaluate(new Uri("https://elsewhere.example/")).IsAllowed,
            "With an allow list set, a host not on it is denied.");
    }


    [TestMethod]
    public void RelaxedPolicyCanPermitInternalHostWhenDeploymentOptsIn()
    {
        //A deployment that legitimately reaches an internal endpoint relaxes the
        //default explicitly — proving the gate is policy-driven, not hardcoded.
        OutboundFetchPolicy relaxed = OutboundFetchPolicy.SecureDefault with
        {
            BlockPrivateAndLoopback = false,
        };

        Assert.IsTrue(relaxed.Evaluate(new Uri("https://10.0.0.5/internal")).IsAllowed,
            "With BlockPrivateAndLoopback off, an internal literal is permitted.");
    }


    [TestMethod]
    public void DeniedDecisionCarriesAReason()
    {
        OutboundFetchDecision decision = OutboundFetchPolicy.SecureDefault.Evaluate(new Uri("http://example.com/"));

        Assert.IsFalse(decision.IsAllowed);
        Assert.IsNotNull(decision.DenyReason, "A deny verdict carries a diagnostic reason.");
    }


    [TestMethod]
    public void EvaluateResolvedAddressBlocksInternalAndAllowsPublic()
    {
        OutboundFetchPolicy policy = OutboundFetchPolicy.SecureDefault;

        System.Net.IPAddress[] blocked =
        [
            System.Net.IPAddress.Loopback,                                  //127.0.0.1
            System.Net.IPAddress.Parse("10.0.0.1"),
            System.Net.IPAddress.Parse("169.254.169.254"),                  //cloud metadata
            System.Net.IPAddress.IPv6Loopback,                              //::1
            System.Net.IPAddress.Parse("fe80::1"),
            System.Net.IPAddress.Parse("::ffff:127.0.0.1"),                 //IPv4-mapped loopback
        ];
        foreach(System.Net.IPAddress address in blocked)
        {
            Assert.IsFalse(policy.EvaluateResolvedAddress(address).IsAllowed,
                $"Resolved address {address} must be blocked (defeats DNS-rebinding).");
        }

        Assert.IsTrue(policy.EvaluateResolvedAddress(System.Net.IPAddress.Parse("93.184.216.34")).IsAllowed,
            "A resolved public address is allowed.");
        Assert.IsFalse(OutboundFetchPolicy.NoNetwork.EvaluateResolvedAddress(System.Net.IPAddress.Parse("93.184.216.34")).IsAllowed,
            "NoNetwork denies even a public resolved address.");
    }


    [TestMethod]
    public void ContextCarrierDefaultsToSecureDefaultAndRoundTrips()
    {
        ExchangeContext context = new();
        Assert.AreSame(OutboundFetchPolicy.SecureDefault, context.OutboundFetchPolicy,
            "An unconfigured context is governed by the secure default, not a null policy.");

        OutboundFetchPolicy custom = OutboundFetchPolicy.NoNetwork;
        context.SetOutboundFetchPolicy(custom);
        Assert.AreSame(custom, context.OutboundFetchPolicy,
            "The set policy round-trips through the context.");
    }
}
