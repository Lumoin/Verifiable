using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the per-request capability gate. The chain build calls
/// <see cref="AuthorizationServerIntegration.ResolveCapabilitiesAsync"/>
/// once per request to obtain the active capability set and filters
/// builder-produced candidates by membership in that set before
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
/// runs per survivor.
/// </summary>
/// <remarks>
/// This is the CAEP/RISC consumption point for live capability
/// attenuation. The library default (<see cref="DefaultCapabilityResolver.ResolveAsync"/>)
/// returns <see cref="ClientRecord.AllowedCapabilities"/> unchanged;
/// production deployments wire a delegate that narrows the set in
/// response to per-request signals.
/// </remarks>
[TestClass]
internal sealed class ResolveCapabilitiesAsyncTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string VerifierClientId = "https://verifier.example.com";

    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task ResolveCapabilitiesAsyncAttenuatesChainMembership()
    {
        await using TestHostShell host = new(TimeProvider);

        //Veto JwksEndpoint via the per-call delegate while the static
        //AllowedCapabilities set still includes it.
        host.Server.OAuth().ResolveCapabilitiesAsync = (registration, ctx, ct) =>
        {
            HashSet<CapabilityIdentifier> attenuated =
                [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)];
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(attenuated);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ExchangeContext context = new();
        context.SetServer(host.Server);

        EndpointChain chain = await EndpointChain.BuildForRequestAsync(
            keys.Registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            chain.Select(e => e.Capability),
            "ResolveCapabilitiesAsync vetoed JwksEndpoint — the JWKS endpoint "
            + "must not appear in the chain. The static AllowedCapabilities set "
            + "still includes it, so the absence here proves the per-call "
            + "attenuation point applied.");
        Assert.Contains(
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            chain.Select(e => e.Capability),
            "Non-vetoed capabilities (Discovery) must still appear in the chain — "
            + "this asserts the filter only drops the vetoed capability, not all.");
    }


    [TestMethod]
    public async Task ResolveCapabilitiesAsyncIsConsultedPerRequest()
    {
        await using TestHostShell host = new(TimeProvider);

        //Per-request: read a flag the test sets on ExchangeContext to decide
        //whether to veto JwksEndpoint. The same registration produces
        //different chains across the two calls because the lambda observes
        //request-scoped state.
        host.Server.OAuth().ResolveCapabilitiesAsync = (registration, ctx, ct) =>
        {
            bool vetoJwks =
                ctx.TryGetValue("test.vetoJwks", out object? v) && v is bool b && b;
            HashSet<CapabilityIdentifier> active = vetoJwks
                ? [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)]
                : [.. registration.AllowedCapabilities];
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(active);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ExchangeContext contextWithoutVeto = new();
        contextWithoutVeto.SetServer(host.Server);
        EndpointChain chainWithoutVeto = await EndpointChain.BuildForRequestAsync(
            keys.Registration, contextWithoutVeto, TestContext.CancellationToken)
            .ConfigureAwait(false);

        ExchangeContext contextWithVeto = new();
        contextWithVeto["test.vetoJwks"] = true;
        contextWithVeto.SetServer(host.Server);
        EndpointChain chainWithVeto = await EndpointChain.BuildForRequestAsync(
            keys.Registration, contextWithVeto, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.Contains(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            chainWithoutVeto.Select(e => e.Capability),
            "JWKS endpoint must be present in the no-veto chain — precondition.");
        Assert.DoesNotContain(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            chainWithVeto.Select(e => e.Capability),
            "JWKS endpoint must be absent in the veto chain — proves the lambda "
            + "observed the per-request signal differently across the two calls.");
        Assert.AreNotEqual(
            chainWithoutVeto.Count,
            chainWithVeto.Count,
            "The two chains must differ in size — same registration, different "
            + "per-request signal, different chain shape.");
    }


    [TestMethod]
    public async Task ChainFiltersByCapabilityBeforeUriResolution()
    {
        await using TestHostShell host = new(TimeProvider);

        //Veto JwksEndpoint via ResolveCapabilitiesAsync. Wire
        //ResolveEndpointUriAsync to throw if called for the JWKS endpoint name —
        //the throw proves the filter happens BEFORE URI resolution; if the
        //filter happened after, the throw would fire.
        host.Server.OAuth().ResolveCapabilitiesAsync = (registration, ctx, ct) =>
        {
            HashSet<CapabilityIdentifier> attenuated =
                [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)];
            return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(attenuated);
        };

        ResolveEndpointUriDelegate originalResolver =
            host.Server.OAuth().ResolveEndpointUriAsync!;
        host.Server.OAuth().ResolveEndpointUriAsync =
            (endpointName, registration, ctx, ct) =>
        {
            if(endpointName == WellKnownEndpointNames.MetadataJwks)
            {
                throw new InvalidOperationException(
                    "ResolveEndpointUriAsync must not be called for a capability "
                    + "the chain build already filtered out.");
            }
            return originalResolver(endpointName, registration, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ExchangeContext context = new();
        context.SetServer(host.Server);

        //Build the chain — if the filter order were wrong (URI-resolve first,
        //then capability-filter), the throw above fires and this call raises.
        //The lack of exception is the assertion: filter precedes URI resolution.
        EndpointChain chain = await EndpointChain.BuildForRequestAsync(
            keys.Registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.DoesNotContain(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            chain.Select(e => e.Capability),
            "JWKS must be absent from the chain (filtered) — sanity check that "
            + "the negative chain shape held.");
    }
}
