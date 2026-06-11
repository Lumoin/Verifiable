using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end SIOPv2 Relying-Party flow driven through the real dispatch chain: the RP prepares a
/// transaction (nonce + client_id), the Wallet mints a JWK-Thumbprint Self-Issued ID Token, and the
/// RP's Self-Issued ID Token response endpoint receives it, runs the §11.1 validation through the
/// shared action executor, and reaches the terminal
/// <see cref="SelfIssuedAuthenticationVerifiedState"/>. Mirrors the OID4VP verifier flow's
/// integration test structure.
/// </summary>
[TestClass]
internal sealed class SiopFlowIntegrationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string RelyingPartyClientId = "https://rp.example.com";
    private const string SiopNonce = "n-siop-transaction-01";

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
    public async Task SelfIssuedIdTokenPostReachesVerifiedState()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        //=== Step 1: the RP prepares the transaction and learns the handle to echo as state. ===
        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(string.IsNullOrWhiteSpace(requestHandle));
        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        //=== Step 2: the Wallet mints a JWK-Thumbprint Self-Issued ID Token bound to the
        //transaction (aud = RP client_id, nonce = the transaction nonce). ===
        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The expected subject — the RFC 9278 JWK Thumbprint URI the validator confirms against.
        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

        //=== Step 3: the Wallet POSTs id_token + state to the SIOP Response endpoint. ===
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
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

        //=== Step 4: 200 and the terminal verified state with the expected subject + nonce. ===
        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        (OAuthFlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, verified.Subject);
        Assert.AreEqual(SiopNonce, verified.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
    }


    //The RFC 9278 sha-256 JWK Thumbprint URI the validator confirms the sub against — the same
    //projection SelfIssuedIdTokenIssuance uses, recomputed from the public key alone.
    private static string SelfIssuedSubjectThumbprint(PublicKeyMemory publicKey)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, algorithm, TestSetup.Base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            jwk, TestSetup.Base64UrlEncoder, Pool);

        return SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint;
    }


    [TestMethod]
    public async Task WrongNonceIdTokenReachesFailedState()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        //A token minted for a DIFFERENT nonce — a valid signature, but the §11.1 nonce binding
        //fails, so the flow must reach terminal failure and the response must not be 200.
        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, "n-some-other-transaction",
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
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

        Assert.AreNotEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(host.GetFlowState(requestHandle).State);
    }
}
