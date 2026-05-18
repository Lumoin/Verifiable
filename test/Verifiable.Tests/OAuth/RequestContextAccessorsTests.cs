using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the per-request accessors the dispatcher places on
/// <see cref="RequestContext"/> at well-defined points in dispatch. The
/// accessors are the per-request source of truth — every downstream
/// handler reads from here rather than threading the values through
/// signatures.
/// </summary>
/// <remarks>
/// The dispatcher places <see cref="RequestContextExtensions.Server"/> at
/// entry (before the IncomingRequestStage inspection fires), and
/// <see cref="RequestContextExtensions.EndpointChain"/> after the chain
/// is built (before the MatchedStage inspection fires). The tests
/// observe each via the inspection hook to verify the ordering is right.
/// </remarks>
[TestClass]
internal sealed class RequestContextAccessorsTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string VerifierClientId = "https://verifier.example.com";

    private static ImmutableHashSet<ServerCapabilityName> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.VerifiablePresentation,
            ServerCapabilityName.JwksEndpoint,
            ServerCapabilityName.DiscoveryEndpoint);


    [TestMethod]
    public async Task ContextServerSetAtDispatchEntryVisibleToIncomingRequestStage()
    {
        await using TestHostShell host = new(TimeProvider);

        AuthorizationServer? observedAtIncomingRequest = null;
        InspectDelegate previousInspect = host.Server.Integration.InspectAsync!;
        host.Server.Integration.InspectAsync = (stage, ctx, ct) =>
        {
            if(stage is IncomingRequestStage)
            {
                observedAtIncomingRequest = ctx.Server;
            }
            return previousInspect(stage, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        await host.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSame(host.Server, observedAtIncomingRequest,
            "context.Server must be set before the IncomingRequestStage inspection "
            + "fires — every per-request delegate downstream reads the active "
            + "AuthorizationServer through this accessor.");
    }


    [TestMethod]
    public async Task EndpointChainOnContextVisibleToMatchedStage()
    {
        await using TestHostShell host = new(TimeProvider);

        EndpointChain? observedAtMatched = null;
        InspectDelegate previousInspect = host.Server.Integration.InspectAsync!;
        host.Server.Integration.InspectAsync = (stage, ctx, ct) =>
        {
            if(stage is MatchedStage)
            {
                observedAtMatched = ctx.EndpointChain;
            }
            return previousInspect(stage, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        await host.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(observedAtMatched,
            "context.EndpointChain must be set before the MatchedStage inspection "
            + "fires — discovery emission and any other chain-walking consumer "
            + "reads the per-request chain through this accessor.");
        Assert.IsGreaterThan(0, observedAtMatched.Count,
            "The chain must be non-empty for a registration with active "
            + "capabilities — sanity check that the chain was built, not just "
            + "an empty fallback.");
    }
}
