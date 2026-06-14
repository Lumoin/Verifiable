using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// SIOPv2 §11.2 cross-device nonce-replay defense, driven end-to-end through the real dispatch
/// chain. The Relying Party MUST check that a Self-Issued ID Token's <c>nonce</c> is known to it
/// and was not used before in an Authorization Response. The defense rides the server's existing
/// <c>(issuer, jti)</c> correlation store via <see cref="JtiReplayGuard"/>, keyed on
/// <c>(client_id, nonce)</c>, consulted as an effect in the SIOP validation action handler.
/// </summary>
[TestClass]
internal sealed class SiopNonceReplayTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string RelyingPartyClientId = "https://rp.example.com";
    private const string SiopNonce = "n-siop-replay-01";

    private static readonly Uri RelyingPartyBaseUri = new("https://rp.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> SiopCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    private static readonly string[] AllowedSiopAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task ReplayedNonceUnderSameClientIdReachesFailedStateSecondTime()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        //The same Self-Issued OP key and the same (client_id, nonce) token are POSTed into two
        //independent flows. The §11.2 store sees the second presentation as a replay even though
        //the §11.1 cryptographic validation passes identically both times.
        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //=== First flow: first use of the nonce — verifies and reaches the terminal verified state. ===
        string firstHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse firstResponse = await PostIdTokenAsync(host, tenant, idToken, firstHandle)
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, firstResponse.StatusCode, firstResponse.Body);
        Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(
            host.GetFlowState(firstHandle).State);

        //=== Second flow: SAME (client_id, nonce) token — §11.2 replay, fails closed. ===
        string secondHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse secondResponse = await PostIdTokenAsync(host, tenant, idToken, secondHandle)
            .ConfigureAwait(false);

        Assert.AreNotEqual((int)HttpStatusCode.OK, secondResponse.StatusCode, secondResponse.Body);
        Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(
            host.GetFlowState(secondHandle).State);
    }


    [TestMethod]
    public async Task DifferentNonceStillVerifiesAfterAPriorVerification()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        //First flow consumes one nonce.
        string firstHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);
        string firstToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse firstResponse = await PostIdTokenAsync(host, tenant, firstToken, firstHandle)
            .ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.OK, firstResponse.StatusCode, firstResponse.Body);

        //A DIFFERENT nonce is a first use under (client_id, nonce) — it must still verify. The
        //store keys on the nonce, so a fresh nonce never collides with the consumed one.
        const string FreshNonce = "n-siop-replay-02";
        string secondHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, FreshNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);
        string secondToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, FreshNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse secondResponse = await PostIdTokenAsync(host, tenant, secondToken, secondHandle)
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, secondResponse.StatusCode, secondResponse.Body);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(
                host.GetFlowState(secondHandle).State);
        Assert.AreEqual(FreshNonce, verified.Nonce);
    }


    private async Task<ServerHttpResponse> PostIdTokenAsync(
        TestHostShell host, string tenant, string idToken, string requestHandle) =>
        await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = idToken,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
}
