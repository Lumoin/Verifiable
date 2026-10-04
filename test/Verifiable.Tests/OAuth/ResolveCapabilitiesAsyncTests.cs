using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth;
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
        (EndpointChain? chain, _, int statusCode, _, _, _) = await SendUnderABoundedMaterializationAsync(
            Oid4VpCapabilities, JwksAndDiscovery, WellKnownEndpointNames.MetadataJwks).ConfigureAwait(false);

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
        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode, _, _, _) = await SendUnderABoundedMaterializationAsync(
            Oid4VpCapabilities, JwksAndDiscovery, WellKnownEndpointNames.MetadataJwks).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode);
        Assert.IsNotNull(resolved);
        Assert.IsTrue(
            resolved.SetEquals([WellKnownCapabilityIdentifiers.OAuthJwksEndpoint]),
            string.Join(' ', resolved.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// The application's materialization answers a registration that allows the JWKS and discovery capabilities with
    /// the presentation capability added, keeping every capability the loaded registration allows under the same
    /// policy, and the application's capability resolution withholds discovery from a registration that allows
    /// presentation. The capabilities resolved for the materialized registration, held to those resolved for the
    /// loaded registration, are narrower than the loaded resolution, so the chain is built again under them: the
    /// discovery document fetched over the wire is answered as for a registration that held the materialized
    /// capabilities from the start, the same bytes, <c>404</c> with an empty body, and the capability resolution is
    /// called exactly twice, once for the loaded and once for the materialized registration: the chain built again is
    /// handed the answer already given. The capabilities of a materialized registration are resolved and held to the
    /// bound whether or not it keeps every loaded capability, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task AMaterializationKeepingEveryCapabilityIsResolvedUnderTheBoundAsync()
    {
        (_, _, int statusCode, string underMaterialization, int resolutions, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, Oid4VpCapabilities, WellKnownEndpointNames.MetadataDiscovery).ConfigureAwait(false);
        (_, _, _, string heldFromTheStart, _, _) = await SendUnderABoundedMaterializationAsync(
            Oid4VpCapabilities, materialized: null, WellKnownEndpointNames.MetadataDiscovery).ConfigureAwait(false);

        Assert.AreEqual(heldFromTheStart, underMaterialization);
        Assert.AreEqual(404, statusCode);
        Assert.AreEqual("404\nContent-Length: 0\nServer: Kestrel\n\n", underMaterialization);
        Assert.AreEqual(2, resolutions, "The loaded and the materialized registration are each resolved once.");
    }


    /// <summary>
    /// The application's capability resolution hands back one mutable set for the loaded registration allowing the
    /// JWKS and discovery capabilities and, before its second answer, removes discovery from that same set and hands
    /// it back again for a materialized registration that keeps every capability under the same policy. The set the
    /// request is served under is the copy the library made of the first answer, so the second answer is narrower and
    /// the chain is built again under it: the discovery document fetched over the wire is answered as for a
    /// registration that never held discovery, the same bytes, <c>404</c> with an empty body, the chain holds no
    /// discovery endpoint, and the resolution is called exactly twice. The capabilities a request is served under are
    /// the library's own copy, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task AResolutionThatNarrowsTheSetItHandedBackIsHeldToItsSecondAnswerAsync()
    {
        HashSet<CapabilityIdentifier>? handedBack = null;
        (EndpointChain? chain, _, int statusCode, string underMaterialization, int resolutions, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, JwksAndDiscovery, WellKnownEndpointNames.MetadataDiscovery,
            (registration, _) =>
            {
                if(handedBack is null)
                {
                    handedBack = [.. registration.AllowedCapabilities];
                }
                else
                {
                    _ = handedBack.Remove(WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);
                }

                return handedBack;
            }).ConfigureAwait(false);
        (_, _, _, string neverHeld, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery.Remove(WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint), materialized: null,
            WellKnownEndpointNames.MetadataDiscovery).ConfigureAwait(false);

        Assert.AreEqual(neverHeld, underMaterialization);
        Assert.AreEqual(404, statusCode);
        Assert.AreEqual("404\nContent-Length: 0\nServer: Kestrel\n\n", underMaterialization);
        Assert.IsNotNull(chain);
        Assert.DoesNotContain(WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint, chain.Select(static endpoint => endpoint.Capability));
        Assert.AreEqual(2, resolutions, "The loaded and the materialized registration are each resolved once.");
    }


    /// <summary>
    /// The application's capability resolution answers a materialized registration that keeps every capability of the
    /// loaded one (the JWKS and discovery capabilities) with a set that claims to be a subset of every set while its
    /// enumeration yields the presentation capability, outside the bound, and whose membership holds the JWKS
    /// capability alone. The set the request is served under is built by walking the bound and asking the answer for
    /// each capability, so it holds the JWKS capability alone and nothing outside the bound, and the JWKS document is
    /// served. The capabilities a request is served under never exceed the bound, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task AnAnswerClaimingToBeWithinTheBoundIsHeldToTheBoundAsync()
    {
        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode, _, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, JwksAndDiscovery, WellKnownEndpointNames.MetadataJwks,
            static (registration, isLoaded) => isLoaded
                ? registration.AllowedCapabilities
                : new SubsetClaimingSet(
                    ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint),
                    [WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, WellKnownCapabilityIdentifiers.VcVerifiablePresentation])).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode);
        Assert.IsNotNull(resolved);
        HashSet<CapabilityIdentifier> served = [.. resolved];
        Assert.IsTrue(
            served.SetEquals([WellKnownCapabilityIdentifiers.OAuthJwksEndpoint]),
            string.Join(' ', served.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// The application's capability resolution throws <see cref="InvalidOperationException"/> for a materialized
    /// registration that keeps every capability of the loaded one under the same policy, and answers the loaded
    /// registration all it allows. The discovery request is answered over the wire as the same request is answered
    /// when the resolution throws for the loaded registration, the same bytes: the listener answers <c>500</c> with
    /// the body's error <c>server_error</c>, and records the fault once. A resolution that throws for the materialized
    /// registration leaves the dispatch as one that throws for the loaded registration does, which is this library's
    /// rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task AResolutionThatThrowsForTheMaterializedRegistrationFaultsAsForTheLoadedOneAsync()
    {
        (_, _, int statusCode, string underMaterialization, _, Exception[] faults) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, JwksAndDiscovery, WellKnownEndpointNames.MetadataDiscovery,
            static (registration, isLoaded) => isLoaded
                ? registration.AllowedCapabilities
                : throw new InvalidOperationException("The capability source is unavailable.")).ConfigureAwait(false);
        (_, _, _, string forTheLoaded, _, Exception[] loadedFaults) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.MetadataDiscovery,
            static (_, _) => throw new InvalidOperationException("The capability source is unavailable.")).ConfigureAwait(false);

        Assert.AreEqual(forTheLoaded, underMaterialization);
        Assert.AreEqual(500, statusCode);
        Assert.AreEqual(
            "500\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            underMaterialization);
        Assert.AreEqual("The capability source is unavailable.", Assert.ContainsSingle(faults).Message);
        Assert.AreEqual("The capability source is unavailable.", Assert.ContainsSingle(loadedFaults).Message);
    }


    /// <summary>
    /// The application's capability resolution answers a registration that allows the JWKS and discovery capabilities
    /// with those and <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/>, a capability the registration
    /// does not allow, with no materialization. A token exchange request posted to the tenant's token endpoint over the
    /// wire is answered byte for byte as at a registration whose resolution answers only what it allows, <c>404</c>
    /// with an empty body, and the set the request is served under holds the JWKS and discovery capabilities alone: the
    /// set is made by walking the registration's own capabilities and asking the answer for each, so a resolution can
    /// only narrow. The capabilities a request is served under never exceed what its registration allows, which is
    /// this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AResolutionBeyondWhatTheRegistrationAllowsAddsNothingAsync()
    {
        Dictionary<string, string> form = new() { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange };
        (_, IReadOnlySet<CapabilityIdentifier>? resolved, _, string underTheResolution, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.AuthCodeToken,
            static (registration, _) => registration.AllowedCapabilities.Append(WellKnownCapabilityIdentifiers.OAuthTokenExchange).ToHashSet(),
            form).ConfigureAwait(false);
        (_, _, _, string neverHeld, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.AuthCodeToken, resolve: null, form).ConfigureAwait(false);

        Assert.AreEqual(neverHeld, underTheResolution);
        Assert.AreEqual("404\nContent-Length: 0\nServer: Kestrel\n\n", underTheResolution);
        Assert.IsNotNull(resolved);
        HashSet<CapabilityIdentifier> served = [.. resolved];
        Assert.IsTrue(
            served.SetEquals(JwksAndDiscovery),
            string.Join(' ', served.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// The application's materialization writes a capability set of its own under the context entry named
    /// <c>server.resolvedCapabilities</c>, the JWKS, discovery and back-channel logout capabilities, and answers the
    /// registration it was given: in one row the registration allows back-channel logout and the capability resolution
    /// withholds it, in the other the registration does not allow it. The discovery document fetched over the wire, with
    /// the back-channel logout delivery wired, is answered byte for byte as for a registration that never held
    /// back-channel logout, without <c>backchannel_logout_supported</c>, and the request carries no resolved set as it
    /// is answered: a value under that entry's name that is not the library's own entry for the request's context reads
    /// as no set, and a reader of no set allows no capability, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <param name="withoutTheCapability">
    /// <c>withheldByTheResolution</c> for a registration that allows back-channel logout under a resolution that
    /// withholds it; <c>notAllowedByTheRegistration</c> for a registration that does not allow it.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("withheldByTheResolution")]
    [DataRow("notAllowedByTheRegistration")]
    public async Task ASetAnApplicationWritesUnderTheResolvedCapabilitiesEntryServesNothingAsync(string withoutTheCapability)
    {
        (ImmutableHashSet<CapabilityIdentifier> Loaded, Func<IRegistrationRecord, bool, IReadOnlySet<CapabilityIdentifier>>? Resolve) arrangement =
            withoutTheCapability switch
            {
                "withheldByTheResolution" => (WithBackChannelLogout, static (registration, _) => registration.AllowedCapabilities
                    .Where(static capability => capability != WellKnownCapabilityIdentifiers.OidcBackChannelLogout).ToHashSet()),
                "notAllowedByTheRegistration" => (JwksAndDiscovery, null),
                _ => throw new ArgumentOutOfRangeException(nameof(withoutTheCapability), withoutTheCapability, null)
            };

        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode, string underTheWrittenSet, _, _) = await SendUnderABoundedMaterializationAsync(
            arrangement.Loaded, materialized: null, WellKnownEndpointNames.MetadataDiscovery, arrangement.Resolve,
            materializing: StoringAsTheResolvedCapabilitiesEntry(WithBackChannelLogout)).ConfigureAwait(false);
        (_, _, _, string neverHeld, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.MetadataDiscovery).ConfigureAwait(false);

        Assert.AreEqual(neverHeld, underTheWrittenSet);
        Assert.AreEqual(200, statusCode);
        Assert.DoesNotContain("backchannel_logout_supported", underTheWrittenSet);
        Assert.IsNull(resolved, "A set another party writes under server.resolvedCapabilities reads as no set.");
    }


    /// <summary>
    /// The application's outgoing inspection of a first request, under a registration that allows the JWKS, discovery
    /// and back-channel logout capabilities, reads the object under the context entry named
    /// <c>server.resolvedCapabilities</c>; the application's materialization of a second request, under a registration
    /// that allows the JWKS and discovery capabilities alone, stores that same object under the same name and answers
    /// the registration it was given. The second request's discovery document fetched over the wire, with the
    /// back-channel logout delivery wired, is answered byte for byte as a request whose materialization stores a set of
    /// its own under that name, without <c>backchannel_logout_supported</c>, and the second request carries no resolved
    /// set as it is answered: the library's entry answers a set only for the context it was written for, so an entry
    /// carried from another request's context reads as no set, which allows no capability, this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AResolvedCapabilitiesEntryCarriedFromAnotherRequestServesNothingAsync()
    {
        object? carried = null;
        _ = await SendUnderABoundedMaterializationAsync(
            WithBackChannelLogout, materialized: null, WellKnownEndpointNames.MetadataDiscovery,
            outgoing: context => carried = context.GetValueOrDefault(ServerContextKeys.ResolvedCapabilitiesKey)).ConfigureAwait(false);
        Assert.IsNotNull(carried, "The first request carries the library's entry as it is answered.");

        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode, string underTheCarriedEntry, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.MetadataDiscovery,
            materializing: StoringAsTheResolvedCapabilitiesEntry(carried)).ConfigureAwait(false);
        (_, _, _, string underAnApplicationsSet, _, _) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.MetadataDiscovery,
            materializing: StoringAsTheResolvedCapabilitiesEntry(WithBackChannelLogout)).ConfigureAwait(false);

        Assert.AreEqual(underAnApplicationsSet, underTheCarriedEntry);
        Assert.AreEqual(200, statusCode);
        Assert.DoesNotContain("backchannel_logout_supported", underTheCarriedEntry);
        Assert.IsNull(resolved, "An entry carried from another request's context under server.resolvedCapabilities reads as no set.");
    }


    /// <summary>
    /// The application's materialization calls <see cref="EndpointChain.BuildForRequestAsync"/> on the request's own
    /// context with the registration it was given widened by back-channel logout, a capability that registration does
    /// not allow, and answers the registration it was given. The public chain build refuses a context that already
    /// carries the capabilities a chain build resolved for it, so the materialization throws
    /// <see cref="InvalidOperationException"/>: the discovery request fetched over the wire is answered <c>500</c> with
    /// the body's error <c>server_error</c>, the listener records that one fault, and no part of the answer carries
    /// back-channel logout. The public chain build is for a context its caller owns, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APublicChainBuildOnTheRequestsContextWidensNothingAsync()
    {
        (_, _, int statusCode, string underTheBuild, _, Exception[] faults) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, materialized: null, WellKnownEndpointNames.MetadataDiscovery,
            materializing: static async (registration, context, cancellationToken) =>
                _ = await EndpointChain.BuildForRequestAsync(
                    ((ClientRecord)registration) with { AllowedCapabilities = [.. registration.AllowedCapabilities, WellKnownCapabilityIdentifiers.OidcBackChannelLogout] },
                    context, cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(500, statusCode, underTheBuild);
        Assert.AreEqual(
            "500\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            underTheBuild);
        Assert.DoesNotContain("backchannel", underTheBuild);
        _ = Assert.IsInstanceOfType<InvalidOperationException>(Assert.ContainsSingle(faults));
    }


    /// <summary>
    /// The application's capability resolution withholds back-channel logout from the loaded registration, which
    /// allows the JWKS, discovery and back-channel logout capabilities, and grants every other registration all it
    /// allows; the application's policy resolution calls <see cref="EndpointChain.BuildForRequestAsync"/> on the
    /// request's own context in each of its calls; the application's materialization answers another reference of
    /// the registration with every capability. The policy resolution's first call runs before the dispatcher's chain
    /// build, which writes the set the request is served under over what that call built. The set is the dispatcher's
    /// entry and no policy entry, so the policy resolution for the materialized registration, which starts from the
    /// request's arriving policy, leaves it on the context, and the public chain build of the second call refuses a
    /// context that carries it: the discovery request fetched over the wire is answered <c>500</c> with the body's
    /// error <c>server_error</c>, the listener records that one fault, and no part of the answer carries back-channel
    /// logout. A request's context carries the set from the dispatcher's chain build onwards, which is this library's
    /// rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APolicyResolutionBuildingAChainInEachCallIsRefusedInItsSecondCallAsync()
    {
        int policyCalls = 0;
        (_, _, int statusCode, string underTheBuilds, _, Exception[] faults) = await SendUnderABoundedMaterializationAsync(
            WithBackChannelLogout, WithBackChannelLogout, WellKnownEndpointNames.MetadataDiscovery,
            WithholdBackChannelLogoutFromTheLoadedRegistration,
            resolvingPolicy: async (registration, context, call, cancellationToken) =>
            {
                policyCalls = call;
                _ = await EndpointChain.BuildForRequestAsync(registration, context, cancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

        Assert.AreEqual(500, statusCode, underTheBuilds);
        Assert.AreEqual(
            "500\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            underTheBuilds);
        Assert.DoesNotContain("backchannel", underTheBuilds);
        Assert.AreEqual(
            "The context already carries the capabilities of a chain build, and a context carries the "
            + "capabilities of one build. Build the chain on a context of the caller's own.",
            Assert.IsInstanceOfType<InvalidOperationException>(Assert.ContainsSingle(faults)).Message);
        Assert.AreEqual(2, policyCalls, "The policy is resolved for the loaded and for the materialized registration.");
    }


    /// <summary>
    /// The application's capability resolution withholds back-channel logout from the loaded registration, which
    /// allows the JWKS, discovery and back-channel logout capabilities, and grants every other registration all it
    /// allows; the application's policy resolution stores a capability set of its own under the context entry named
    /// <c>server.resolvedCapabilities</c> in its first call and does nothing in its second; the application's
    /// materialization answers another reference of the registration with every capability. The discovery document
    /// fetched over the wire is answered byte for byte as the same request whose policy resolution writes nothing,
    /// <c>200</c> without <c>backchannel_logout_supported</c>, and the request carries the JWKS and discovery
    /// capabilities as it is answered: the dispatcher's chain build writes the set the request is served under over
    /// the value of the first call, and that set is the dispatcher's entry and no policy entry, so the policy
    /// resolution for the materialized registration leaves it in place and the materialized registration is resolved
    /// under it. The served set is no policy entry, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AValueThePolicyResolutionStoresUnderTheServedSetsNameLeavesTheServedSetAsync()
    {
        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode, string underTheWrite, _, _) = await SendUnderABoundedMaterializationAsync(
            WithBackChannelLogout, WithBackChannelLogout, WellKnownEndpointNames.MetadataDiscovery,
            WithholdBackChannelLogoutFromTheLoadedRegistration,
            resolvingPolicy: static (_, context, call, _) =>
            {
                if(call == 1)
                {
                    context[ServerContextKeys.ResolvedCapabilitiesKey] = WithBackChannelLogout;
                }

                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);
        (_, _, _, string withoutTheWrite, _, _) = await SendUnderABoundedMaterializationAsync(
            WithBackChannelLogout, WithBackChannelLogout, WellKnownEndpointNames.MetadataDiscovery,
            WithholdBackChannelLogoutFromTheLoadedRegistration).ConfigureAwait(false);

        Assert.AreEqual(withoutTheWrite, underTheWrite);
        Assert.AreEqual(200, statusCode, underTheWrite);
        Assert.DoesNotContain("backchannel_logout_supported", underTheWrite);
        Assert.IsNotNull(resolved, "The request carries the set the dispatcher's chain build wrote.");
        Assert.IsTrue(
            resolved.SetEquals(JwksAndDiscovery),
            string.Join(' ', resolved.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// The application's policy resolution writes an entry of its own name in its first call, for the loaded
    /// registration, and does nothing in its second, for another reference of the registration the application's
    /// materialization answers with every capability. The discovery document fetched over the wire is answered
    /// <c>200</c>, byte for byte as the same request whose policy resolution writes nothing, and the request's
    /// context carries no entry of that name as the policy resolution's second call runs nor as the answer leaves:
    /// every policy entry the loaded registration's resolution wrote is removed, or returned to the value the request
    /// arrived with, before the materialized registration's policy is resolved, so the materialized registration's
    /// resolution starts from the request's arriving state, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnEntryThePolicyResolutionWritesForTheLoadedRegistrationIsRemovedForTheMaterializedOneAsync()
    {
        string entryName = "application.riskTier";
        bool isEntrySeenAtTheSecondResolution = true;
        bool isEntrySeenAsTheAnswerLeaves = true;
        int policyCalls = 0;
        (_, _, int statusCode, string underTheWrite, _, _) = await SendUnderABoundedMaterializationAsync(
            WithBackChannelLogout, WithBackChannelLogout, WellKnownEndpointNames.MetadataDiscovery,
            WithholdBackChannelLogoutFromTheLoadedRegistration,
            resolvingPolicy: (_, context, call, _) =>
            {
                policyCalls = call;
                if(call == 1)
                {
                    context[entryName] = "elevated";
                }
                else
                {
                    isEntrySeenAtTheSecondResolution = context.ContainsKey(entryName);
                }

                return ValueTask.CompletedTask;
            },
            outgoing: context => isEntrySeenAsTheAnswerLeaves = context.ContainsKey(entryName)).ConfigureAwait(false);
        (_, _, _, string withoutTheWrite, _, _) = await SendUnderABoundedMaterializationAsync(
            WithBackChannelLogout, WithBackChannelLogout, WellKnownEndpointNames.MetadataDiscovery,
            WithholdBackChannelLogoutFromTheLoadedRegistration).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, underTheWrite);
        Assert.AreEqual(withoutTheWrite, underTheWrite);
        Assert.AreEqual(2, policyCalls, "The policy is resolved for the loaded and for the materialized registration.");
        Assert.IsFalse(
            isEntrySeenAtTheSecondResolution,
            "The entry the loaded registration's policy resolution wrote is removed before the materialized registration's policy is resolved.");
        Assert.IsFalse(isEntrySeenAsTheAnswerLeaves, "The entry the loaded registration's policy resolution wrote is absent as the answer leaves.");
    }


    /// <summary>
    /// The application's materialization answers another reference of the registration with the capabilities the
    /// loaded registration allows, the JWKS and discovery capabilities; the application's capability resolution
    /// withholds discovery, the capability of the endpoint the request matches, from the materialized registration;
    /// the application's policy resolution removes the context entry named <c>server.resolvedCapabilities</c> in its
    /// second call, for the materialized registration. The judgement of the materialized registration needs the set
    /// the request is served under, and the context holds none at that point, so the discovery request fetched over
    /// the wire is answered <c>500</c> with the body's error <c>server_error</c> and the description the library
    /// answers a fault of the server's wiring with, the request's trace records that one fault, an
    /// <see cref="InvalidOperationException"/>, and nothing escapes the dispatch: a context without the set is a fault
    /// of the server's wiring, never an empty bound, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DoNotParallelize]
    public async Task APolicyResolutionRemovingTheServedSetInItsSecondCallIsAServerFaultAsync()
    {
        (int statusCode, string withoutTheSet, Exception[] faults, int policyCalls, ActivityEvent[] exceptionEvents) =
            await SendWithTheServedSetRewrittenInTheSecondPolicyCallAsync(
                static context => _ = context.Remove(ServerContextKeys.ResolvedCapabilitiesKey)).ConfigureAwait(false);

        Assert.AreEqual(500, statusCode, withoutTheSet);
        Assert.AreEqual(
            "500\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            withoutTheSet);
        Assert.IsEmpty(faults, "The dispatch answers the fault itself; nothing escapes it.");
        Assert.AreEqual(2, policyCalls, "The policy is resolved for the loaded and for the materialized registration.");
        AssertTheOneFaultIsTheMissingServedSet(exceptionEvents);
    }


    /// <summary>
    /// The application's materialization answers another reference of the registration with the capabilities the
    /// loaded registration allows, the JWKS and discovery capabilities; the application's capability resolution
    /// withholds discovery, the capability of the endpoint the request matches, from the materialized registration;
    /// the application's policy resolution stores a capability set of its own, the JWKS and discovery capabilities,
    /// under the context entry named <c>server.resolvedCapabilities</c> in its second call, for the materialized
    /// registration. A value under that name that is not the library's own entry for the request's context reads as
    /// no set, and the judgement of the materialized registration needs the set the request is served under, so the
    /// discovery request fetched over the wire is answered <c>500</c> with the body's error <c>server_error</c> and
    /// the description the library answers a fault of the server's wiring with, the request's trace records that one
    /// fault, an <see cref="InvalidOperationException"/>, and nothing escapes the dispatch: a context without the set
    /// is a fault of the server's wiring, never an empty bound, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DoNotParallelize]
    public async Task APolicyResolutionReplacingTheServedSetInItsSecondCallIsAServerFaultAsync()
    {
        (int statusCode, string underItsOwnSet, Exception[] faults, int policyCalls, ActivityEvent[] exceptionEvents) =
            await SendWithTheServedSetRewrittenInTheSecondPolicyCallAsync(
                static context => context[ServerContextKeys.ResolvedCapabilitiesKey] = JwksAndDiscovery).ConfigureAwait(false);

        Assert.AreEqual(500, statusCode, underItsOwnSet);
        Assert.AreEqual(
            "500\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            underItsOwnSet);
        Assert.IsEmpty(faults, "The dispatch answers the fault itself; nothing escapes it.");
        Assert.AreEqual(2, policyCalls, "The policy is resolved for the loaded and for the materialized registration.");
        AssertTheOneFaultIsTheMissingServedSet(exceptionEvents);
    }


    /// <summary>
    /// The application's materialization answers another reference of the registration with the capabilities the
    /// loaded registration allows, the JWKS and discovery capabilities; the application's capability resolution
    /// withholds discovery, the capability of the endpoint the request matches, from the materialized registration;
    /// the application's policy resolution runs in both of its calls and touches nothing under the context entry
    /// named <c>server.resolvedCapabilities</c>. The materialized registration is judged under the set the request is
    /// served under, its resolution held to that bound is narrower, and the chain is built again under it: the
    /// discovery request fetched over the wire is answered as a request no endpoint serves, <c>404</c> with an empty
    /// body, and the request carries the JWKS capability alone as it is answered. A materialized registration's
    /// capabilities are held to the set the request is served under, which is this library's rule.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APolicyResolutionLeavingTheServedSetHoldsTheMaterializedRegistrationToItAsync()
    {
        int policyCalls = 0;
        (_, IReadOnlySet<CapabilityIdentifier>? resolved, int statusCode, string underTheServedSet, _, Exception[] faults) =
            await SendUnderABoundedMaterializationAsync(
                JwksAndDiscovery, JwksAndDiscovery, WellKnownEndpointNames.MetadataDiscovery,
                WithholdDiscoveryFromTheMaterializedRegistration,
                resolvingPolicy: (_, _, call, _) =>
                {
                    policyCalls = call;

                    return ValueTask.CompletedTask;
                }).ConfigureAwait(false);

        Assert.AreEqual(404, statusCode, underTheServedSet);
        Assert.AreEqual("404\nContent-Length: 0\nServer: Kestrel\n\n", underTheServedSet);
        Assert.IsEmpty(faults, "A request no endpoint serves is no fault.");
        Assert.AreEqual(2, policyCalls, "The policy is resolved for the loaded and for the materialized registration.");
        Assert.IsNotNull(resolved, "The request carries the set the chain built again wrote.");
        Assert.IsTrue(
            resolved.SetEquals([WellKnownCapabilityIdentifiers.OAuthJwksEndpoint]),
            string.Join(' ', resolved.Select(static capability => capability.Urn)));
    }


    /// <summary>
    /// A caller builds the chain for a registration through <see cref="EndpointChain.BuildForRequestAsync"/> on a
    /// context of its own, then calls it again on that same context: the second call throws
    /// <see cref="InvalidOperationException"/>, since the context already carries the capabilities of one build, and a
    /// call on a fresh context of the caller's own builds the chain and writes that context's capabilities. The
    /// documented contract of <see cref="EndpointChain.BuildForRequestAsync"/>: it throws
    /// <see cref="InvalidOperationException"/> when the context already carries the capabilities a chain build resolved
    /// for it.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ASecondPublicChainBuildOnOneContextIsRefusedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        ExchangeContext context = [];
        context.SetServer(host.Server);
        _ = await EndpointChain.BuildForRequestAsync(
            keys.Registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => EndpointChain.BuildForRequestAsync(keys.Registration, context, TestContext.CancellationToken).AsTask())
            .ConfigureAwait(false);

        ExchangeContext fresh = [];
        fresh.SetServer(host.Server);
        EndpointChain chain = await EndpointChain.BuildForRequestAsync(
            keys.Registration, fresh, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint, chain.Select(static endpoint => endpoint.Capability));
        Assert.IsNotNull(fresh.ResolvedCapabilities, "The fresh context carries the capabilities of its one build.");
    }


    /// <summary>
    /// A caller builds the chain for a registration through <see cref="EndpointChain.BuildForRequestAsync"/> on a
    /// context of its own: that context reads the capabilities the build wrote for it, and a copy of it made with
    /// <see cref="ExchangeContext(IEnumerable{KeyValuePair{string, object}})"/> is equal to it by value, since it holds
    /// the same entries, and reads no capabilities, since the entry named <c>server.resolvedCapabilities</c> is bound
    /// to the context it was written for and is compared with that context by reference. The documented contract of
    /// <see cref="Verifiable.Server.ExchangeContextServerExtensions"/>: a value under that name that is not the
    /// library's own entry for the context read reads as no set, and a reader of no set allows no capability.
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ACopyOfABuiltContextIsEqualByValueAndReadsNoCapabilitiesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);
        ExchangeContext built = [];
        built.SetServer(host.Server);
        _ = await EndpointChain.BuildForRequestAsync(
            keys.Registration, built, TestContext.CancellationToken).ConfigureAwait(false);

        ExchangeContext copy = new(built);

        Assert.IsNotNull(built.ResolvedCapabilities, "The built context reads the capabilities its build wrote for it.");
        Assert.AreEqual(built, copy, "The copy holds the same entries, so it is equal to the built context by value.");
        Assert.IsNull(copy.ResolvedCapabilities, "The copy is another context: the entry it holds is bound to the built context.");
    }


    /// <summary>The JWKS and discovery capabilities, without presentation.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> JwksAndDiscovery { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>The JWKS, discovery and back-channel logout capabilities.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> WithBackChannelLogout { get; } =
        JwksAndDiscovery.Add(WellKnownCapabilityIdentifiers.OidcBackChannelLogout);


    /// <summary>
    /// The step an application's materialization takes on the request's context before it answers: it stores
    /// <paramref name="value"/> under the context entry named <c>server.resolvedCapabilities</c>.
    /// </summary>
    /// <param name="value">The value stored under the entry's name.</param>
    /// <returns>The step, handed the registration, the request's context and the cancellation token.</returns>
    private static Func<IRegistrationRecord, ExchangeContext, CancellationToken, ValueTask> StoringAsTheResolvedCapabilitiesEntry(object value) =>
        (_, context, _) =>
        {
            context[ServerContextKeys.ResolvedCapabilitiesKey] = value;

            return ValueTask.CompletedTask;
        };


    /// <summary>
    /// The capability resolution the fixture wires unless a row hands its own: it withholds discovery from a
    /// registration allowing presentation and grants every other registration all it allows.
    /// </summary>
    /// <param name="registration">The registration the resolution is asked for.</param>
    /// <returns>The capabilities the resolution answers.</returns>
    private static IReadOnlySet<CapabilityIdentifier> WithholdDiscoveryFromPresentation(IRegistrationRecord registration) =>
        registration.AllowedCapabilities.Contains(WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
            ? registration.AllowedCapabilities.Where(static capability => capability != WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint).ToHashSet()
            : registration.AllowedCapabilities;


    /// <summary>
    /// A capability resolution that withholds back-channel logout from the registration the load seam answered and
    /// grants every other registration all it allows: it narrows the loaded registration alone.
    /// </summary>
    /// <param name="registration">The registration the resolution is asked for.</param>
    /// <param name="isLoaded">Whether <paramref name="registration"/> is the reference the load seam answered.</param>
    /// <returns>The capabilities the resolution answers.</returns>
    private static IReadOnlySet<CapabilityIdentifier> WithholdBackChannelLogoutFromTheLoadedRegistration(IRegistrationRecord registration, bool isLoaded) =>
        isLoaded
            ? registration.AllowedCapabilities.Where(static capability => capability != WellKnownCapabilityIdentifiers.OidcBackChannelLogout).ToHashSet()
            : registration.AllowedCapabilities;


    /// <summary>
    /// A capability resolution that withholds discovery from every registration other than the reference the load seam
    /// answered and grants that one all it allows: it narrows a materialized registration alone.
    /// </summary>
    /// <param name="registration">The registration the resolution is asked for.</param>
    /// <param name="isLoaded">Whether <paramref name="registration"/> is the reference the load seam answered.</param>
    /// <returns>The capabilities the resolution answers.</returns>
    private static IReadOnlySet<CapabilityIdentifier> WithholdDiscoveryFromTheMaterializedRegistration(IRegistrationRecord registration, bool isLoaded) =>
        isLoaded
            ? registration.AllowedCapabilities
            : registration.AllowedCapabilities.Where(static capability => capability != WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint).ToHashSet();


    /// <summary>
    /// Sends a GET of the discovery document through <see cref="SendUnderABoundedMaterializationAsync"/> under a
    /// registration that allows the JWKS and discovery capabilities, which the materialization answers as another
    /// reference allowing the same, with <see cref="WithholdDiscoveryFromTheMaterializedRegistration"/> as the
    /// capability resolution and a policy resolution that applies <paramref name="rewrite"/> to the request's context
    /// in its second call, inside a root activity of a trace of its own, and collects the exception events recorded
    /// in that trace. The capture is a process-wide activity listener, so a caller runs apart from other tests
    /// (<see cref="DoNotParallelizeAttribute"/>) and asserts only over the events of the request's own trace.
    /// </summary>
    /// <param name="rewrite">What the policy resolution's second call does to the request's context.</param>
    /// <returns>
    /// The status code, the answer as <see cref="OAuthTestTransport.ProjectWireAnswer"/> projects it, the faults the
    /// listener recorded for the request, how many times the policy was resolved, and the events named
    /// <c>exception</c> of the request's trace.
    /// </returns>
    private async Task<(int StatusCode, string WireAnswer, Exception[] Faults, int PolicyCalls, ActivityEvent[] ExceptionEvents)> SendWithTheServedSetRewrittenInTheSecondPolicyCallAsync(
        Action<ExchangeContext> rewrite)
    {
        int policyCalls = 0;
        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(SendWithTheServedSetRewrittenInTheSecondPolicyCallAsync));
        _ = root.Start();
        (_, _, int statusCode, string answer, _, Exception[] faults) = await SendUnderABoundedMaterializationAsync(
            JwksAndDiscovery, JwksAndDiscovery, WellKnownEndpointNames.MetadataDiscovery,
            WithholdDiscoveryFromTheMaterializedRegistration,
            resolvingPolicy: (_, context, call, _) =>
            {
                policyCalls = call;
                if(call == 2)
                {
                    rewrite(context);
                }

                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);
        root.Stop();

        ActivityEvent[] exceptionEvents = [.. TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId)
            .SelectMany(static activity => activity.Events)
            .Where(static activityEvent => string.Equals(activityEvent.Name, "exception", StringComparison.Ordinal))];

        return (statusCode, answer, faults, policyCalls, exceptionEvents);
    }


    /// <summary>
    /// Asserts that <paramref name="exceptionEvents"/> holds one event, an <see cref="InvalidOperationException"/>
    /// whose message says that the request's context holds no capabilities the request is served under.
    /// </summary>
    /// <param name="exceptionEvents">The events named <c>exception</c> of the request's trace.</param>
    private static void AssertTheOneFaultIsTheMissingServedSet(ActivityEvent[] exceptionEvents)
    {
        ActivityEvent fault = Assert.ContainsSingle(exceptionEvents);
        Assert.AreEqual(
            "System.InvalidOperationException",
            fault.Tags.SingleOrDefault(static tag => string.Equals(tag.Key, "exception.type", StringComparison.Ordinal)).Value as string);
        Assert.AreEqual(
            "The request's context holds no capabilities the request is served under, so the materialized registration "
            + "has nothing to be held to.",
            fault.Tags.SingleOrDefault(static tag => string.Equals(tag.Key, "exception.message", StringComparison.Ordinal)).Value as string);
    }


    /// <summary>
    /// Registers the verifier with <paramref name="loaded"/>, wires <paramref name="resolve"/> as the capability
    /// resolution, counting each call, the back-channel logout delivery so that the discovery document's back-channel
    /// members follow the capability alone, a materialization when <paramref name="materialized"/> or
    /// <paramref name="materializing"/> is given, which takes the step <paramref name="materializing"/> on the request's
    /// context when given and answers the registration with <paramref name="materialized"/>, or the registration it was
    /// given when that is <see langword="null"/>, and an inspection that reads the request's chain and resolved
    /// capabilities as the answer leaves and hands the request's context to <paramref name="outgoing"/> when given, and,
    /// when <paramref name="resolvingPolicy"/> is given, a policy resolution that runs the configured one and then that
    /// step, then sends a GET to <paramref name="endpointName"/> over the listener, or a POST of <paramref name="form"/>
    /// when one is given.
    /// </summary>
    /// <param name="loaded">The capabilities the loaded registration allows.</param>
    /// <param name="materialized">
    /// The capabilities the materialized registration allows, or <see langword="null"/> for no materialization.
    /// </param>
    /// <param name="endpointName">The endpoint the GET is sent to.</param>
    /// <param name="resolve">
    /// The capability resolution, handed the registration and whether it is the reference the load seam answered, or
    /// <see langword="null"/> for <see cref="WithholdDiscoveryFromPresentation"/>.
    /// </param>
    /// <param name="form">The form fields to POST, or <see langword="null"/> to send a GET.</param>
    /// <param name="materializing">
    /// The step the materialization takes on the request's context before it answers, handed the registration it was
    /// given, or <see langword="null"/> for none.
    /// </param>
    /// <param name="outgoing">
    /// What the application's outgoing inspection does with the request's context, or <see langword="null"/> for
    /// nothing beyond the reads the fixture answers.
    /// </param>
    /// <param name="resolvingPolicy">
    /// The step the policy resolution takes on the request's context after the configured policy resolution, handed
    /// the registration the policy is resolved for, the request's context, the number of the call within the request
    /// (1 for the loaded registration, 2 for a materialized one) and the cancellation token, or
    /// <see langword="null"/> to keep the configured policy resolution alone.
    /// </param>
    /// <returns>
    /// The chain and the resolved capabilities the request carried as it was answered, the status code, the answer as
    /// <see cref="OAuthTestTransport.ProjectWireAnswer"/> projects it, with the registration's tenant segment replaced
    /// by <c>{segment}</c> so two registrations' answers compare, how many times the capability resolution was called,
    /// and the faults the listener recorded for the request.
    /// </returns>
    private async Task<(EndpointChain? Chain, IReadOnlySet<CapabilityIdentifier>? Resolved, int StatusCode, string WireAnswer, int Resolutions, Exception[] Faults)> SendUnderABoundedMaterializationAsync(
        ImmutableHashSet<CapabilityIdentifier> loaded,
        ImmutableHashSet<CapabilityIdentifier>? materialized,
        string endpointName,
        Func<IRegistrationRecord, bool, IReadOnlySet<CapabilityIdentifier>>? resolve = null,
        Dictionary<string, string>? form = null,
        Func<IRegistrationRecord, ExchangeContext, CancellationToken, ValueTask>? materializing = null,
        Action<ExchangeContext>? outgoing = null,
        Func<IRegistrationRecord, ExchangeContext, int, CancellationToken, ValueTask>? resolvingPolicy = null)
    {
        await using TestHostShell host = new(TimeProvider);
        HostedAuthorizationServer hosted = host.Host("default");
        Func<IRegistrationRecord, bool, IReadOnlySet<CapabilityIdentifier>> resolution =
            resolve ?? (static (registration, _) => WithholdDiscoveryFromPresentation(registration));

        EndpointChain? observedChain = null;
        IReadOnlySet<CapabilityIdentifier>? observedResolved = null;
        int resolutions = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCapabilitiesAsync = (registration, _, _) =>
            {
                _ = Interlocked.Increment(ref resolutions);
                bool isLoaded = hosted.Registrations.TryGetValue(registration.TenantId.Value, out ClientRecord? stored)
                    && ReferenceEquals(stored, registration);

                return ValueTask.FromResult(resolution(registration, isLoaded));
            };

            candidateIntegration.DeliverBackChannelLogoutAsync = static (_, _, _, _, _) => ValueTask.CompletedTask;
            if(resolvingPolicy is not null)
            {
                ResolveServerPolicyDelegate configuredPolicy = candidateIntegration.ResolvePolicyAsync!;
                int policyCalls = 0;
                candidateIntegration.ResolvePolicyAsync = async (registration, context, cancellationToken) =>
                {
                    await configuredPolicy(registration, context, cancellationToken).ConfigureAwait(false);
                    await resolvingPolicy(
                        registration, context, Interlocked.Increment(ref policyCalls), cancellationToken).ConfigureAwait(false);
                };
            }

            if(materialized is not null || materializing is not null)
            {
                candidateIntegration.MaterializeRegistrationAsync = async (registration, context, cancellationToken) =>
                {
                    if(materializing is not null)
                    {
                        await materializing(registration, context, cancellationToken).ConfigureAwait(false);
                    }

                    return new RegistrationMaterialization
                    {
                        Registration = materialized is null
                            ? registration
                            : ((ClientRecord)registration) with { AllowedCapabilities = materialized }
                    };
                };
            }

            candidateIntegration.InspectAsync = (stage, context, _) =>
            {
                if(stage is OutgoingResponseStage)
                {
                    observedChain = context.EndpointChain;
                    observedResolved = context.ResolvedCapabilities;
                    outgoing?.Invoke(context);
                }

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, loaded).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri endpointUri = TestHostShell.ComposeEndpointUri(
            hosted.HttpBaseAddress!, keys.Registration.TenantId.Value, endpointName);

        using HttpResponseMessage response = form is null
            ? await hosted.SharedHttpClient!.GetAsync(endpointUri, TestContext.CancellationToken).ConfigureAwait(false)
            : await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, endpointUri, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = keys.Registration.TenantId.Value;

        return (observedChain, observedResolved, (int)response.StatusCode,
            OAuthTestTransport.ProjectWireAnswer(response, body).Replace(segment, "{segment}", StringComparison.Ordinal),
            Volatile.Read(ref resolutions), hosted.ConsumeHttpFaults());
    }


    /// <summary>
    /// A capability set whose <see cref="IsSubsetOf"/> answers <see langword="true"/> for every set while its
    /// enumeration yields <see cref="Enumerated"/> and its <see cref="Contains"/> answers by <see cref="Claimed"/>: an
    /// answer of an application's capability resolution that a reader trusting the set's own subset test would keep
    /// whole.
    /// </summary>
    /// <param name="claimed">The capabilities <see cref="Contains"/> answers for.</param>
    /// <param name="enumerated">The capabilities an enumeration yields.</param>
    private sealed class SubsetClaimingSet(
        IReadOnlySet<CapabilityIdentifier> claimed, IReadOnlyCollection<CapabilityIdentifier> enumerated): IReadOnlySet<CapabilityIdentifier>
    {
        /// <summary>The capabilities <see cref="Contains"/> answers for.</summary>
        private IReadOnlySet<CapabilityIdentifier> Claimed { get; } = claimed;

        /// <summary>The capabilities an enumeration yields.</summary>
        private IReadOnlyCollection<CapabilityIdentifier> Enumerated { get; } = enumerated;

        /// <summary>The number of capabilities an enumeration yields.</summary>
        public int Count => Enumerated.Count;

        /// <summary>Answers whether <paramref name="item"/> is among <see cref="Claimed"/>.</summary>
        /// <param name="item">The capability asked for.</param>
        /// <returns>Whether <see cref="Claimed"/> holds it.</returns>
        public bool Contains(CapabilityIdentifier item) => Claimed.Contains(item);

        /// <summary>Answers <see langword="true"/> whatever <paramref name="other"/> holds.</summary>
        /// <param name="other">The set compared with.</param>
        /// <returns><see langword="true"/>.</returns>
        public bool IsSubsetOf(IEnumerable<CapabilityIdentifier> other) => true;

        /// <summary>Compares <see cref="Enumerated"/> with <paramref name="other"/>.</summary>
        /// <param name="other">The set compared with.</param>
        /// <returns>Whether <see cref="Enumerated"/> is a proper subset of it.</returns>
        public bool IsProperSubsetOf(IEnumerable<CapabilityIdentifier> other) => Enumerated.ToHashSet().IsProperSubsetOf(other);

        /// <summary>Compares <see cref="Enumerated"/> with <paramref name="other"/>.</summary>
        /// <param name="other">The set compared with.</param>
        /// <returns>Whether <see cref="Enumerated"/> is a proper superset of it.</returns>
        public bool IsProperSupersetOf(IEnumerable<CapabilityIdentifier> other) => Enumerated.ToHashSet().IsProperSupersetOf(other);

        /// <summary>Compares <see cref="Enumerated"/> with <paramref name="other"/>.</summary>
        /// <param name="other">The set compared with.</param>
        /// <returns>Whether <see cref="Enumerated"/> is a superset of it.</returns>
        public bool IsSupersetOf(IEnumerable<CapabilityIdentifier> other) => Enumerated.ToHashSet().IsSupersetOf(other);

        /// <summary>Compares <see cref="Enumerated"/> with <paramref name="other"/>.</summary>
        /// <param name="other">The set compared with.</param>
        /// <returns>Whether <see cref="Enumerated"/> shares a capability with it.</returns>
        public bool Overlaps(IEnumerable<CapabilityIdentifier> other) => Enumerated.ToHashSet().Overlaps(other);

        /// <summary>Compares <see cref="Enumerated"/> with <paramref name="other"/>.</summary>
        /// <param name="other">The set compared with.</param>
        /// <returns>Whether <see cref="Enumerated"/> holds exactly its capabilities.</returns>
        public bool SetEquals(IEnumerable<CapabilityIdentifier> other) => Enumerated.ToHashSet().SetEquals(other);

        /// <summary>Enumerates <see cref="Enumerated"/>.</summary>
        /// <returns>The enumerator.</returns>
        public IEnumerator<CapabilityIdentifier> GetEnumerator() => Enumerated.GetEnumerator();

        /// <summary>Enumerates <see cref="Enumerated"/>.</summary>
        /// <returns>The enumerator.</returns>
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
