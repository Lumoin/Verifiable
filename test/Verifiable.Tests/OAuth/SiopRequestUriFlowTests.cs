using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end SIOPv2 by-reference flow driven through the real dispatch chain: the Relying Party
/// prepares a transaction and returns a <c>request_uri</c>, the Wallet GETs that URL to fetch the
/// signed §9 Request Object, then mints a JWK-Thumbprint Self-Issued ID Token bound to the
/// transaction and POSTs it. Asserts the served body is a signed compact JWS whose payload carries
/// <c>response_type=id_token</c>, the <c>client_id</c>, the <c>nonce</c>, and the §9.1 <c>aud</c>
/// (both the static-discovery value and the dynamic-discovery issuer), and that it verifies under
/// the RP's signing key. Mirrors <see cref="SiopFlowIntegrationTests"/> for transport and the OID4VP
/// JAR-fetch verification in <c>Oid4VpFlowIntegrationTests</c>.
/// </summary>
[TestClass]
internal sealed class SiopRequestUriFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string RelyingPartyClientId = "https://rp.example.com";
    private const string SiopNonce = "n-siop-request-uri-01";

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

    //The §9 Request Object payload is read back as a generic claim dictionary so the test asserts on
    //the wire-observable values rather than a typed projection.
    private static readonly JwtPartDecoder PartDecoder =
        static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("§9 Request Object JWT part parsed to null.");


    [TestMethod]
    public async Task ByReferenceFlowServesSignedRequestObjectWithDynamicDiscoveryAudience()
    {
        await DriveByReferenceFlowAsync(useStaticDiscoveryAudience: false);
    }


    [TestMethod]
    public async Task ByReferenceFlowServesSignedRequestObjectWithStaticDiscoveryAudience()
    {
        await DriveByReferenceFlowAsync(useStaticDiscoveryAudience: true);
    }


    private async Task DriveByReferenceFlowAsync(bool useStaticDiscoveryAudience)
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        //=== Step 1: the RP prepares the transaction and learns the request_uri + handle. ===
        (string requestHandle, Uri requestUri) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(string.IsNullOrWhiteSpace(requestHandle));
        Assert.IsTrue(requestUri.OriginalString.Contains(requestHandle, StringComparison.Ordinal),
            "The composed request_uri must carry the per-flow handle.");
        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        //=== Step 2: the Wallet GETs the request_uri and receives the signed §9 Request Object. ===
        string requestObjectJws = await host.HandleSiopRequestObjectAsync(
            rpKeys, requestHandle, TestContext.CancellationToken).ConfigureAwait(false);

        //The served body is a compact JWS (header.payload.signature).
        Assert.HasCount(3, requestObjectJws.Split('.'),
            "The §9 Request Object must be a compact JWS with three dot-separated segments.");

        //The flow advanced to the served state, still resolvable by the handle for the response POST.
        Assert.IsInstanceOfType<SiopRequestObjectServedState>(host.GetFlowState(requestHandle).State);

        //=== Step 3: verify the JWS under the RP's signing key and assert the §9 / §9.1 claims. ===
        string expectedAudience = useStaticDiscoveryAudience
            ? SiopAuthorizationRequestParameterValues.StaticDiscoveryRequestObjectAudience
            : rpKeys.Registration.IssuerUri!.OriginalString;

        JwsVerificationResult verification =
            await Jws.VerifyAndDecodeAsync(
                requestObjectJws,
                TestSetup.Base64UrlDecoder,
                PartDecoder,
                Pool,
                rpKeys.SigningPublicKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verification.IsValid,
            "The served §9 Request Object must verify under the RP's signing key.");

        JwtPayload payload = verification.Payload;
        Assert.AreEqual(
            SiopAuthorizationRequestParameterValues.ResponseTypeIdToken,
            GetString(payload, OAuthRequestParameterNames.ResponseType));
        Assert.AreEqual(RelyingPartyClientId, GetString(payload, WellKnownJwtClaimNames.ClientId));
        Assert.AreEqual(SiopNonce, GetString(payload, WellKnownJwtClaimNames.Nonce));
        Assert.AreEqual(requestHandle, GetString(payload, OAuthRequestParameterNames.State));
        Assert.AreEqual(expectedAudience, GetString(payload, WellKnownJwtClaimNames.Aud),
            "The §9.1 aud must match the discovery mode under test.");

        //=== Step 4: the Wallet mints a JWK-Thumbprint Self-Issued ID Token and POSTs it. ===
        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

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

        //=== Step 5: 200 and the terminal verified state with the expected subject + nonce. ===
        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, verified.Subject);
        Assert.AreEqual(SiopNonce, verified.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
    }


    private static string GetString(Dictionary<string, object> payload, string claim)
    {
        Assert.IsTrue(payload.TryGetValue(claim, out object? value),
            $"The §9 Request Object payload is missing the '{claim}' claim.");

        return value switch
        {
            JsonElement element => element.GetString()
                ?? throw new FormatException($"Claim '{claim}' is not a JSON string."),
            string s => s,
            _ => value!.ToString()!
        };
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
}
