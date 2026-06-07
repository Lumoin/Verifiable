using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the pipeline's structural support for recursive tenancy —
/// two independent tenants on one server with different capability sets,
/// where each tenant's chain reflects only its own capabilities and
/// dispatches in isolation.
/// </summary>
/// <remarks>
/// The Phase 9h pipeline doesn't introduce a recursive-tenancy
/// <em>protocol</em> (PIC-Protocol attenuation chain cryptography is
/// out of scope; that's an agentic-identity track item). What it does
/// guarantee is that the per-request capability gate is genuinely
/// per-request, so a meta-AS can host an operator tenant alongside
/// customer tenants and each one walks its own chain. The tests below
/// verify that structural support — two tenants with different
/// capabilities dispatch independently, and capability attenuation in
/// one does not leak into the other.
/// </remarks>
[TestClass]
internal sealed class RecursiveTenancyTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    //Operator tenant — Dynamic Client Registration capability plus the
    //metadata endpoints. In a real recursive-tenancy deployment the
    //operator's DCR endpoint is what creates customer tenants.
    private static ImmutableHashSet<CapabilityIdentifier> OperatorCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration,
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);

    //Customer tenant — same downstream capabilities as the operator, but
    //*without* DCR. A customer can't sub-register; the operator does.
    private static ImmutableHashSet<CapabilityIdentifier> CustomerCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task OperatorAndCustomerTenantsExposeDifferentEndpointChains()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial operatorKeys = host.RegisterClient(
            "https://operator.test", new Uri("https://operator.test"), OperatorCapabilities);
        using VerifierKeyMaterial customerKeys = host.RegisterClient(
            "https://customer.test", new Uri("https://customer.test"), CustomerCapabilities);

        ServerHttpResponse operatorRegisterResponse = await host.DispatchAtEndpointAsync(
            operatorKeys.Registration.TenantId,
            WellKnownEndpointNames.RegistrationRegister,
            "GET",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse customerRegisterResponse = await host.DispatchAtEndpointAsync(
            customerKeys.Registration.TenantId,
            WellKnownEndpointNames.RegistrationRegister,
            "GET",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Operator's chain includes the RFC 7592 management endpoints because
        //DCR is in its capability set; the GET hits the read handler and
        //either succeeds with the registration payload or fails on bearer
        //validation (depending on whether the test supplied a token).
        //Either way the response is NOT 404 — the chain has the endpoint.
        Assert.AreNotEqual(404, operatorRegisterResponse.StatusCode,
            "Operator tenant has DynamicClientRegistration, so its chain must "
            + "expose RFC 7592 management endpoints. Anything other than 404 "
            + "(authoritative-not-found from the chain walk) proves the "
            + "endpoint was matched and reached its handler.");

        //Customer's chain does NOT include the management endpoints because
        //DCR is absent from its capability set; the chain walk finds nothing
        //and returns 404.
        Assert.AreEqual(404, customerRegisterResponse.StatusCode,
            "Customer tenant lacks DynamicClientRegistration, so its chain "
            + "must not expose RFC 7592 management endpoints — dispatch to "
            + "the management URL returns 404. Capability attenuation in the "
            + "customer tenant did not leak from the operator.");
    }


    [TestMethod]
    public async Task PerRequestCapabilityAttenuationIsTenantScoped()
    {
        await using TestHostShell host = new(TimeProvider);

        //Wire a per-request capability resolver that vetoes the JWKS
        //endpoint, but only for the customer tenant. The operator's chain
        //must keep JWKS; the customer's chain must drop it.
        host.Server.Integration.ResolveCapabilitiesAsync = (registration, ctx, ct) =>
        {
            HashSet<CapabilityIdentifier> active = [.. registration.AllowedCapabilities];
            if(registration.TenantId.Value.StartsWith("cust-", StringComparison.Ordinal))
            {
                active.Remove(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);
            }
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(active);
        };

        using VerifierKeyMaterial operatorKeys = host.RegisterClient(
            "https://operator-2.test", new Uri("https://operator-2.test"), OperatorCapabilities);
        using VerifierKeyMaterial customerKeys = host.RegisterClient(
            "https://customer-2.test", new Uri("https://customer-2.test"), CustomerCapabilities);

        //Force the customer tenant's segment to start with "cust-" so the
        //veto lambda fires for it. RegisterClient generates a random
        //segment; override by re-registering after a rename is hard, so
        //instead select the predicate by something controllable: the
        //ClientId starts with "https://customer-...". Recheck the predicate.
        host.Server.Integration.ResolveCapabilitiesAsync = (registration, ctx, ct) =>
        {
            HashSet<CapabilityIdentifier> active = [.. registration.AllowedCapabilities];
            if(registration.ClientId.StartsWith("https://customer-", StringComparison.Ordinal))
            {
                active.Remove(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);
            }
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(active);
        };

        ServerHttpResponse operatorJwks = await host.DispatchAtEndpointAsync(
            operatorKeys.Registration.TenantId,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse customerJwks = await host.DispatchAtEndpointAsync(
            customerKeys.Registration.TenantId,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, operatorJwks.StatusCode,
            "Operator JWKS must succeed — the veto lambda only fires for "
            + "tenants whose ClientId starts with 'https://customer-'.");
        Assert.AreEqual(404, customerJwks.StatusCode,
            "Customer JWKS must 404 — ResolveCapabilitiesAsync attenuated "
            + "JwksEndpoint out of the customer's capability set, so the "
            + "endpoint isn't in the chain. The attenuation was tenant-"
            + "scoped: the operator tenant kept its JWKS endpoint.");
    }
}
