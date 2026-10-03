using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.OAuth.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the per-request capability gate. The chain build calls
/// <c>AuthorizationServerIntegration.ResolveCapabilitiesAsync</c>
/// once per request to obtain the active capability set and filters
/// builder-produced candidates by membership in that set before
/// <c>AuthorizationServerIntegration.ResolveEndpointUriAsync</c>
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


    /// <summary>
    /// Checks that the request's resolved capability set determines endpoint-chain membership.
    /// <see href="../../../documents/AuthorizationServerDesign.md#22-endpoint-chain-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveCapabilitiesAsyncAttenuatesChainMembership()
    {
        await using TestHostShell host = new(TimeProvider);

        //Veto JwksEndpoint via the per-call delegate while the static
        //AllowedCapabilities set still includes it.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCapabilitiesAsync = (registration, ctx, ct) =>
            {
                HashSet<CapabilityIdentifier> attenuated =
                    [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)];

                return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(attenuated);
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        ExchangeContext context = [];
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


    /// <summary>
    /// Checks that separate requests for one registration can resolve different active endpoint sets.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveCapabilitiesAsyncIsConsultedPerRequest()
    {
        await using TestHostShell host = new(TimeProvider);

        //Per-request: read a flag the test sets on ExchangeContext to decide
        //whether to veto JwksEndpoint. The same registration produces
        //different chains across the two calls because the lambda observes
        //request-scoped state.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCapabilitiesAsync = (registration, ctx, ct) =>
            {
                bool vetoJwks =
                    ctx.TryGetValue("test.vetoJwks", out object? v) && v is bool b && b;
                HashSet<CapabilityIdentifier> active = vetoJwks
                    ? [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)]
                    : [.. registration.AllowedCapabilities];

                return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(active);
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        ExchangeContext contextWithoutVeto = [];
        contextWithoutVeto.SetServer(host.Server);
        EndpointChain chainWithoutVeto = await EndpointChain.BuildForRequestAsync(
            keys.Registration, contextWithoutVeto, TestContext.CancellationToken)
            .ConfigureAwait(false);

        ExchangeContext contextWithVeto = new()
        {
            ["test.vetoJwks"] = true
        };
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


    /// <summary>
    /// Checks that excluded endpoint candidates never reach the application's URI resolver.
    /// <see href="../../../documents/AuthorizationServerDesign.md#22-endpoint-chain-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task ChainFiltersByCapabilityBeforeUriResolution()
    {
        await using TestHostShell host = new(TimeProvider);

        //Veto JwksEndpoint via ResolveCapabilitiesAsync. Wire
        //ResolveEndpointUriAsync to throw if called for the JWKS endpoint name —
        //the throw proves the filter happens BEFORE URI resolution; if the
        //filter happened after, the throw would fire.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCapabilitiesAsync = (registration, ctx, ct) =>
            {
                HashSet<CapabilityIdentifier> attenuated =
                    [.. registration.AllowedCapabilities.Where(c => c != WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)];

                return ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(attenuated);
            };
        }).ConfigureAwait(false);

        ResolveEndpointUriDelegate originalResolver =
            host.Server.OAuth().ResolveEndpointUriAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveEndpointUriAsync =
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
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        ExchangeContext context = [];
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


    /// <summary>
    /// The application's materialization removes a capability, so the request is judged by a chain built for the
    /// materialized registration; the capabilities resolved for that registration are held to those resolved for
    /// the loaded registration, so a capability the resolution withheld from the loaded registration and grants the
    /// materialized one adds no endpoint to the chain. The upper bound of a materialized registration's capabilities
    /// is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task AMaterializedResolutionBeyondTheLoadedResolutionAddsNoEndpointAsync()
    {
        (EndpointChain? chain, _, int statusCode) = await GetJwksUnderABoundedMaterializationAsync().ConfigureAwait(false);

        Assert.AreEqual(200, statusCode);
        Assert.IsNotNull(chain);
        HashSet<CapabilityIdentifier> chainCapabilities = [.. chain.Select(static endpoint => endpoint.Capability)];
        Assert.IsTrue(
            chainCapabilities.SetEquals([WellKnownCapabilityIdentifiers.OAuthJwksEndpoint]),
            string.Join(' ', chainCapabilities.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// The application's materialization removes a capability, so the capabilities the request carries for the
    /// endpoint and its token producers are those resolved for the materialized registration, held to those resolved
    /// for the loaded registration: the set the request carries is the bounded set, not the resolution's own answer.
    /// The upper bound of a materialized registration's capabilities is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task TheRequestCarriesTheBoundedResolutionOfAMaterializedRegistrationAsync()
    {
        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode) = await GetJwksUnderABoundedMaterializationAsync().ConfigureAwait(false);

        Assert.AreEqual(200, statusCode);
        Assert.IsNotNull(resolved);
        Assert.IsTrue(
            resolved.SetEquals([WellKnownCapabilityIdentifiers.OAuthJwksEndpoint]),
            string.Join(' ', resolved.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// Registers the verifier with the presentation, JWKS and discovery capabilities, wires a capability resolution
    /// that withholds discovery from a registration allowing presentation and grants every other registration all it
    /// allows, a materialization that removes the presentation capability and an inspection that reads the request's
    /// chain and resolved capabilities as the answer leaves, then fetches the JWKS over the listener.
    /// </summary>
    /// <returns>The chain and the resolved capabilities the request carried as it was answered, and the status code.</returns>
    private async Task<(EndpointChain? Chain, IReadOnlySet<CapabilityIdentifier>? Resolved, int StatusCode)> GetJwksUnderABoundedMaterializationAsync()
    {
        await using TestHostShell host = new(TimeProvider);

        EndpointChain? observedChain = null;
        IReadOnlySet<CapabilityIdentifier>? observedResolved = null;
        ImmutableHashSet<CapabilityIdentifier> materialized = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCapabilitiesAsync = static (registration, _, _) =>
                ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(
                    registration.AllowedCapabilities.Contains(WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
                        ? registration.AllowedCapabilities.Where(static capability => capability != WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint).ToHashSet()
                        : registration.AllowedCapabilities);
            candidateIntegration.MaterializeRegistrationAsync = (registration, _, _) =>
                ValueTask.FromResult(new RegistrationMaterialization
                {
                    Registration = ((ClientRecord)registration) with { AllowedCapabilities = materialized }
                });
            candidateIntegration.InspectAsync = (stage, context, _) =>
            {
                if(stage is OutgoingResponseStage)
                {
                    observedChain = context.EndpointChain;
                    observedResolved = context.ResolvedCapabilities;
                }

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri jwksUri = TestHostShell.ComposeEndpointUri(
            hosted.HttpBaseAddress!, keys.Registration.TenantId.Value, WellKnownEndpointNames.MetadataJwks);

        using HttpResponseMessage response = await hosted.SharedHttpClient!.GetAsync(
            jwksUri, TestContext.CancellationToken).ConfigureAwait(false);

        return (observedChain, observedResolved, (int)response.StatusCode);
    }
}
