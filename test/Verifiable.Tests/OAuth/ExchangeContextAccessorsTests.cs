using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.OAuth.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the per-request accessors the dispatcher places on
/// <see cref="ExchangeContext"/> at well-defined points in dispatch. The
/// accessors are the per-request source of truth — every downstream
/// handler reads from here rather than threading the values through
/// signatures.
/// </summary>
/// <remarks>
/// The dispatcher places <see cref="Verifiable.Server.ExchangeContextServerExtensions.extension(ExchangeContext).Server"/> at
/// entry (before the IncomingRequestStage inspection fires), and
/// <see cref="Verifiable.Server.ExchangeContextServerExtensions.extension(ExchangeContext).EndpointChain"/> after the chain
/// is built (before the MatchedStage inspection fires). The tests
/// observe each via the inspection hook to verify the ordering is right.
/// </remarks>
[TestClass]
internal sealed class ExchangeContextAccessorsTests
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
    /// The incoming-request inspection stage receives the server reference placed on the dispatch context.
    /// <see href="../../../documents/AuthorizationServerDesign.md#21-prologue-stage">Pipeline §2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextServerSetAtDispatchEntryVisibleToIncomingRequestStage()
    {
        await using TestHostShell host = new(TimeProvider);

        EndpointServer? observedAtIncomingRequest = null;
        InspectDelegate previousInspect = host.Server.OAuth().InspectAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.InspectAsync = (stage, ctx, ct) =>
            {
                if(stage is IncomingRequestStage)
                {
                    observedAtIncomingRequest = ctx.Server;
                }

                return previousInspect(stage, ctx, ct);
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        _ = await host.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSame(host.Server, observedAtIncomingRequest,
            "context.Server must be set before the IncomingRequestStage inspection "
            + "fires — every per-request delegate downstream reads the active "
            + "AuthorizationServer through this accessor.");
    }


    /// <summary>
    /// The matched inspection stage receives the endpoint chain built on its dispatch context.
    /// <see href="../../../documents/AuthorizationServerDesign.md#22-endpoint-chain-stage">Pipeline §2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task EndpointChainOnContextVisibleToMatchedStage()
    {
        await using TestHostShell host = new(TimeProvider);

        EndpointChain? observedAtMatched = null;
        InspectDelegate previousInspect = host.Server.OAuth().InspectAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.InspectAsync = (stage, ctx, ct) =>
            {
                if(stage is MatchedStage)
                {
                    observedAtMatched = ctx.EndpointChain;
                }

                return previousInspect(stage, ctx, ct);
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        _ = await host.DispatchAtEndpointAsync(
            keys.Registration.TenantId,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            [],
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
