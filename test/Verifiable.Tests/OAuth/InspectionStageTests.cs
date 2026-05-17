using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the <see cref="InspectionStage"/> emission discipline. The
/// dispatcher fires <see cref="IncomingRequestStage"/>,
/// <see cref="MatchedStage"/>, and <see cref="OutgoingResponseStage"/> on
/// every request; <see cref="StateTransitionStage"/> fires from
/// <see cref="FlowRunner.StepWithEffectsAsync"/> after every successful
/// PDA transition.
/// </summary>
/// <remarks>
/// <see cref="StateTransitionStage"/> emission is the load-bearing hook
/// for replay-determinism event capture per
/// <c>documents/AuthorizationServerDesign.md §2.4</c>. The two tests in
/// this class lock in the "fires on PDA transitions, does not fire on
/// stateless paths" invariant — any future refactor that accidentally
/// emits on stateless paths (polluting the replay log with non-state
/// events) or omits emission on stateful transitions (losing replay
/// fidelity) fails one of these tests loudly.
/// </remarks>
[TestClass]
internal sealed class InspectionStageTests
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
    public async Task StateTransitionStageFiresOnSuccessfulPdaTransition()
    {
        await using TestHostShell host = new(TimeProvider);

        List<StateTransitionStage> recorded = [];
        InspectDelegate previousInspect = host.Server.Integration.InspectAsync!;
        host.Server.Integration.InspectAsync = (stage, ctx, ct) =>
        {
            if(stage is StateTransitionStage transition)
            {
                recorded.Add(transition);
            }

            return previousInspect(stage, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Drive the OID4VP PAR flow — context-state-driven, but goes through
        //FlowRunner because the endpoint is stateful (ParFlowKind).
        (Uri _, string _) = await host.HandleParAsync(
            keys,
            new TransactionNonce("nonce-state-transition-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, recorded.Count,
            "FlowRunner.StepWithEffectsAsync must emit at least one StateTransitionStage "
            + "per successful PDA transition during a PAR dispatch.");

        foreach(StateTransitionStage transition in recorded)
        {
            Assert.IsNotNull(transition.Before,
                "StateTransitionStage.Before must carry the pre-transition state.");
            Assert.IsNotNull(transition.Input,
                "StateTransitionStage.Input must carry the input that drove the transition.");
            Assert.IsNotNull(transition.After,
                "StateTransitionStage.After must carry the post-transition state.");
        }
    }


    [TestMethod]
    public async Task StateTransitionStageDoesNotFireForStatelessEndpointDispatch()
    {
        await using TestHostShell host = new(TimeProvider);

        List<StateTransitionStage> recorded = [];
        InspectDelegate previousInspect = host.Server.Integration.InspectAsync!;
        host.Server.Integration.InspectAsync = (stage, ctx, ct) =>
        {
            if(stage is StateTransitionStage transition)
            {
                recorded.Add(transition);
            }

            return previousInspect(stage, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        string segment = keys.Registration.TenantId;
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(VerifierBaseUri);

        ServerHttpResponse response = await host.DispatchAtPathAsync(
            segment,
            ServerEndpointPaths.Jwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "Stateless JWKS dispatch precondition for the no-emission assertion below.");
        Assert.HasCount(0, recorded,
            "Stateless endpoints serve computed responses without driving the PDA. "
            + "StateTransitionStage must not fire on stateless paths because "
            + "FlowRunner.StepWithEffectsAsync is the only emission site and "
            + "stateless endpoints short-circuit before reaching it.");
    }


    //Helpers go below the public surface.

    private static PreparedDcqlQuery CreatePreparedQuery()
    {
        return DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }]
                }
            ]
        });
    }
}
