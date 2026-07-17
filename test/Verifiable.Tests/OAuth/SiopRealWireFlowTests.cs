using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire capstones for SIOPv2 (contract decision 4), re-composing the three flows
/// <see cref="SiopRequestUriFlowTests"/>, <see cref="SiopFlowIntegrationTests"/>, and
/// <see cref="SiopCombinedResponseFlowTests"/> already prove in-process over
/// <see cref="TestHostShell.StartHttpHostAsync(System.Threading.CancellationToken)"/> and a real
/// <see cref="HttpClient"/>: the by-reference <c>request_uri</c> GET, the self-issued ID Token
/// response POST, and the combined <c>id_token</c> + <c>vp_token</c> response POST. The in-process
/// tests stay as unit coverage — this class never calls <see cref="TestHostShell.DispatchAtEndpointAsync"/>.
/// The <see cref="AuthorizationServerHttpApplication"/> skin already routes the SIOP endpoints; the
/// preparation step stays in-process because it is verifier-internal (never visible to the Wallet),
/// the same status OID4VP's PAR preparation holds.
/// </summary>
[TestClass]
internal sealed class SiopRealWireFlowTests
{
    /// <summary>
    /// MSTest's per-test context, supplying the <see cref="System.Threading.CancellationToken"/> every
    /// socket call in these capstones runs under.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The clock the host, the RP's Request Object, and the Wallet's ID Token all share, pinned to a
    /// fixed instant so signed-artifact expiry checks are deterministic.
    /// </summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>
    /// The shared memory pool backing every pooled carrier these capstones allocate.
    /// </summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The Relying Party's client identifier, registered with the host and asserted as the
    /// <c>client_id</c>/<c>aud</c> of every Request Object and response these capstones exchange.
    /// </summary>
    private const string RelyingPartyClientId = "https://rp.example.com";

    /// <summary>
    /// The issuer identifier stamped into the <c>iss</c> claim of the SD-JWT VC credentials the
    /// combined-response capstone presents.
    /// </summary>
    private const string IssuerId = "https://issuer.example.com";

    /// <summary>
    /// The issuer's key identifier, carried in the SD-JWT VC's protected header <c>kid</c>.
    /// </summary>
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>
    /// <see cref="RelyingPartyClientId"/> as a <see cref="Uri"/>, the shape
    /// <see cref="TestHostShell.RegisterClient"/> and
    /// <see cref="TestHostShell.AlignRegistrationToHostHttpBase"/> require.
    /// </summary>
    private static Uri RelyingPartyBaseUri { get; } = new(RelyingPartyClientId);

    /// <summary>
    /// The capability the RP's registration needs to act as a SIOPv2 self-issued OP relying party.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> SiopCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    /// <summary>
    /// The signing algorithms the RP's §9 Request Object preparation accepts from the Wallet's
    /// Self-Issued ID Token.
    /// </summary>
    private static string[] AllowedSiopAlgorithms { get; } = [WellKnownJwaValues.Es256];

    /// <summary>
    /// Serializes a JWT header dictionary to UTF-8 JSON bytes for §9 Request Object and ID Token signing.
    /// </summary>
    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>
    /// Serializes a JWT payload dictionary to UTF-8 JSON bytes for §9 Request Object and ID Token signing.
    /// </summary>
    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

    /// <summary>
    /// Decodes a base64url-decoded JWT part back into a claims dictionary, for reading the header and
    /// payload off a compact §9 Request Object or ID Token.
    /// </summary>
    private static JwtPartDecoder PartDecoder { get; } =
        static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("§9 Request Object JWT part parsed to null.");


    /// <summary>
    /// By-reference flow: the RP prepares a transaction (in-process, verifier-internal), the Wallet
    /// GETs the composed <c>request_uri</c> over a real socket and receives the signed §9 Request
    /// Object, mints a JWK-Thumbprint Self-Issued ID Token, and POSTs it over a real socket. Both hops
    /// go through <see cref="HostedAuthorizationServer.SharedHttpClient"/> bound to the Kestrel
    /// listener the RP's registration was aligned to — stopping the listener would fail both GETs and
    /// the POST with a connection error.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceRequestObjectFetchAndResponsePostCrossTheRealWire()
    {
        await using TestHostShell host = new(TimeProvider);
        await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        rpKeys.Registration = host.AlignRegistrationToHostHttpBase("default", rpKeys.Registration);
        string tenant = rpKeys.Registration.TenantId.Value;

        const string nonce = "n-siop-real-wire-01";
        (string requestHandle, Uri requestUri) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, nonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        Assert.IsTrue(requestUri.IsAbsoluteUri && requestUri.Authority == hosted.HttpBaseAddress!.Authority,
            "The request_uri must resolve against the Kestrel-aligned RP authority.");
        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        using HttpResponseMessage requestObjectResponse = await hosted.SharedHttpClient!
            .GetAsync(requestUri, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        requestObjectResponse.EnsureSuccessStatusCode();
        string requestObjectJws = await requestObjectResponse.Content
            .ReadAsStringAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, requestObjectJws.Split('.'),
            "The §9 Request Object served over the real GET must be a compact JWS.");
        Assert.IsInstanceOfType<SiopRequestObjectServedState>(host.GetFlowState(requestHandle).State);

        JwsVerificationResult verification = await Jws.VerifyAndDecodeAsync(
            requestObjectJws, TestSetup.Base64UrlDecoder, PartDecoder, Pool,
            rpKeys.SigningPublicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verification.IsValid,
            "The §9 Request Object fetched over the real wire must verify under the RP's signing key.");
        Assert.AreEqual(nonce, GetString(verification.Payload, WellKnownJwtClaimNames.Nonce));
        Assert.AreEqual(requestHandle, GetString(verification.Payload, OAuthRequestParameterNames.State));

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, nonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

        Uri responseUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.SiopResponse, tenant));
        using FormUrlEncodedContent responseBody = new(new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.IdToken] = idToken,
            [OAuthRequestParameterNames.State] = requestHandle
        });

        using HttpResponseMessage response = await hosted.SharedHttpClient!
            .PostAsync(responseUrl, responseBody, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string responseText = await response.Content
            .ReadAsStringAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.OK, (int)response.StatusCode, responseText);

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, verified.Subject);
        Assert.AreEqual(nonce, verified.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
    }


    /// <summary>
    /// Direct (same-device) flow: the RP prepares a transaction in-process, the Wallet mints a
    /// JWK-Thumbprint Self-Issued ID Token, and POSTs <c>id_token</c> + <c>state</c> to the SIOP
    /// Response endpoint over a real socket. Mirrors
    /// <see cref="SiopFlowIntegrationTests.SelfIssuedIdTokenPostReachesVerifiedState"/> with the final
    /// POST re-composed over <see cref="HttpClient"/>.
    /// </summary>
    [TestMethod]
    public async Task SelfIssuedIdTokenPostReachesVerifiedStateOverRealWire()
    {
        await using TestHostShell host = new(TimeProvider);
        await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        const string nonce = "n-siop-real-wire-direct-01";
        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, nonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, nonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

        HostedAuthorizationServer hosted = host.Host("default");
        Uri responseUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.SiopResponse, tenant));
        using FormUrlEncodedContent responseBody = new(new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.IdToken] = idToken,
            [OAuthRequestParameterNames.State] = requestHandle
        });

        using HttpResponseMessage response = await hosted.SharedHttpClient!
            .PostAsync(responseUrl, responseBody, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string responseText = await response.Content
            .ReadAsStringAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.OK, (int)response.StatusCode, responseText);

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, verified.Subject);
        Assert.AreEqual(nonce, verified.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
    }


    /// <summary>
    /// The richest flow: the RP prepares a transaction in-process, the Wallet mints BOTH a
    /// JWK-Thumbprint Self-Issued ID Token and a vp_token (SD-JWT VC + KB-JWT) bound to the same
    /// transaction, and POSTs <c>id_token</c> + <c>vp_token</c> + <c>state</c> as one §12 combined
    /// response over a real socket. Mirrors
    /// <see cref="SiopCombinedResponseFlowTests.CombinedResponsePostReachesVerifiedStateBindingBothArtifacts"/>
    /// with the final POST re-composed over <see cref="HttpClient"/>; the <c>direct_post</c> response
    /// mode crosses the socket as a genuine form POST.
    /// </summary>
    [TestMethod]
    public async Task CombinedVpAndIdTokenResponsePostReachesVerifiedStateOverRealWire()
    {
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync("Alice", "Smith").ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            await using TestHostShell host = new(TimeProvider);
            await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            using VerifierKeyMaterial rpKeys = host.RegisterClient(
                RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
            string tenant = rpKeys.Registration.TenantId.Value;

            host.RegisterIssuerTrust(IssuerId, issuerPublicKey);

            const string nonce = "n-siop-real-wire-combined-01";
            string requestHandle = await host.HandleSiopRequestPreparationAsync(
                rpKeys, nonce, RelyingPartyClientId, AllowedSiopAlgorithms,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

            var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PublicKeyMemory siopPublic = siopKeys.PublicKey;
            using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

            string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, RelyingPartyClientId, nonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            string vpToken = await PresentWithKeyBindingAsync(
                serializedSdJwt, holderPrivateKey, nonce, RelyingPartyClientId).ConfigureAwait(false);

            string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

            HostedAuthorizationServer hosted = host.Host("default");
            Uri responseUrl = new(
                hosted.HttpBaseAddress!,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.SiopResponse, tenant));
            using FormUrlEncodedContent responseBody = new(new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.IdToken] = idToken,
                [AuthorizationResponseParameters.VpToken] = vpToken,
                [OAuthRequestParameterNames.State] = requestHandle
            });

            using HttpResponseMessage response = await hosted.SharedHttpClient!
                .PostAsync(responseUrl, responseBody, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            string responseText = await response.Content
                .ReadAsStringAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual((int)HttpStatusCode.OK, (int)response.StatusCode, responseText);

            (FlowState state, _) = host.GetFlowState(requestHandle);
            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
            Assert.AreEqual(expectedSubject, verified.Subject);
            Assert.AreEqual(nonce, verified.Nonce);
            Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
        }
    }


    /// <summary>
    /// Reads a string-valued claim off a decoded JWT payload, unwrapping the
    /// <see cref="JsonElement"/> shape <see cref="PartDecoder"/> produces. Fails the test with a
    /// descriptive message when <paramref name="claim"/> is absent.
    /// </summary>
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


    /// <summary>
    /// The RFC 9278 sha-256 JWK Thumbprint URI the validator confirms the <c>sub</c> against — the
    /// same projection <c>SelfIssuedIdTokenIssuance</c> uses, recomputed from the public key alone.
    /// </summary>
    private static string SelfIssuedSubjectThumbprint(PublicKeyMemory publicKey)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, algorithm, TestSetup.Base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            jwk, TestSetup.Base64UrlEncoder, Pool);

        return SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint;
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC with the holder's Ed25519 public key in <c>cnf.jwk</c>. The same
    /// construction <see cref="SiopCombinedResponseFlowTests"/> uses for the in-process combined-
    /// response coverage — the issuance-time half every presentation builds on.
    /// </summary>
    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialAsync(string givenName, string familyName)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        var holderKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, givenName),
                new(EudiPid.SdJwt.FamilyName, familyName)
            ]);

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        };

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, IssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    /// <summary>
    /// The wallet-side presentation step: parse the stored SD-JWT, sign a KB-JWT over its hash input
    /// with the holder key bound to the request's <c>nonce</c> and the verifier's Client ID, and
    /// serialise the presentation with key binding per RFC 9901 §4.3. The same construction
    /// <see cref="SiopCombinedResponseFlowTests"/> uses for the in-process combined-response coverage.
    /// </summary>
    private async ValueTask<string> PresentWithKeyBindingAsync(
        string sdJwtWithoutKb, PrivateKeyMemory holderPrivateKey, string nonce, string audience)
    {
        using SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, Pool, TestSalts.TestSaltTag);

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder);

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes(hashInput),
            holderPrivateKey,
            nonce,
            audience,
            TimeProvider.GetUtcNow(),
            TestSetup.Base64UrlEncoder,
            HeaderSerializer,
            PayloadSerializer,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKb = token.WithKeyBinding(compactKbJwt, Pool);

        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }
}
