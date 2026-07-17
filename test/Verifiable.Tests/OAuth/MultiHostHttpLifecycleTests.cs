using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
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
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// One credential across TWO independent Kestrel listeners: the wallet drives OID4VCI
/// issuance against the Credential Issuer's host entirely over real HTTP (Credential
/// Offer deep link → §6 Pre-Authorized Code grant → §7 c_nonce → §8 Credential Request
/// with a verified holder key proof), then presents the just-issued credential to the
/// Verifier's separate host through the HTTP-backed OID4VP wallet client (request_uri
/// fetch → KB-JWT presentation → encrypted direct_post). Every Wallet↔Issuer and
/// Wallet↔Verifier exchange crosses a socket; the two deployments share nothing but
/// the wallet and the SD-JWT issuer trust root.
/// </summary>
[TestClass]
internal sealed class MultiHostHttpLifecycleTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string IssuerHostName = "issuer";
    private const string IssuerClientId = "https://wallet.client.test";
    private static readonly Uri IssuerClientBaseUri = new("https://wallet.client.test");
    private const string ConfigurationId = "eu.europa.ec.eudi.pid.1";
    private const string PreAuthorizedCode = "SplxlOBeZQQYbYS6WxSbIA";
    private const string EndUserSubject = "urn:uuid:end-user-42";

    private const string SdJwtIssuerId = "https://issuer.example.com";
    private const string SdJwtIssuerKeyId = "did:web:issuer.example.com#key-1";

    private const string VerifierClientId = "https://verifier.example.com";
    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuerCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    private static readonly ImmutableHashSet<CapabilityIdentifier> VerifierCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task WalletDrivesIssuanceAndPresentationAcrossTwoKestrelHosts()
    {
        await using TestHostShell app = new(TimeProvider);

        //The Verifier deployment lives on the default host; the Credential Issuer
        //deployment gets its own host, state, key material, and Kestrel port.
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, VerifierCapabilities);
        app.AddHost(IssuerHostName);
        using VerifierKeyMaterial issuerMaterial = app.RegisterDpopClientOnHost(
            IssuerHostName, IssuerClientId, IssuerClientBaseUri,
            PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." The Issuer mints a plain-bearer credential token over
        //HTTP; keep it within the long-lived threshold (lifetimes longer than 5 minutes are
        //considered long lived).
        app.SetAccessTokenLifetime(issuerMaterial, TimeSpan.FromMinutes(5), IssuerHostName);
        string issuerTenant = issuerMaterial.Registration.TenantId.Value;

        //The wallet's long-lived holder key and the SD-JWT issuer trust root the
        //Verifier resolves credential signatures against.
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var sdJwtIssuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory sdJwtIssuerPublic = sdJwtIssuerKeys.PublicKey;
        using PrivateKeyMemory sdJwtIssuerPrivate = sdJwtIssuerKeys.PrivateKey;
        app.RegisterIssuerTrust(SdJwtIssuerId, sdJwtIssuerPublic);

        WireIssuerSeamsState seamState = WireIssuerSeams(
            app.Host(IssuerHostName).Server.OAuth(), sdJwtIssuerPrivate);

        await app.StartHttpHostAsync(IssuerHostName, TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer issuerHost = app.Host(IssuerHostName);
        HttpClient issuerHttp = issuerHost.SharedHttpClient!;

        //=== Act 1: issuance, every exchange over the issuer host's real socket. ===

        //§4: the Issuer composes the offer; the wallet "scans" the deep link.
        CredentialOffer offer = new()
        {
            CredentialIssuer = issuerMaterial.Registration.IssuerUri!,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode
            }
        };
        string deepLink = CredentialOfferSerializer.ToByValueDeepLink(offer);
        string offerJson = Uri.UnescapeDataString(
            deepLink[(deepLink.IndexOf("credential_offer=", StringComparison.Ordinal) + "credential_offer=".Length)..]);
        using JsonDocument offerDoc = JsonDocument.Parse(offerJson);
        string scannedCode = offerDoc.RootElement
            .GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.PreAuthorizedCode)
            .GetProperty("pre-authorized_code").GetString()!;

        //§6: the Pre-Authorized Code grant over an HTTP form POST.
        Uri tokenUrl = new(issuerHost.HttpBaseAddress!, $"/connect/{issuerTenant}/token");
        using FormUrlEncodedContent tokenRequestContent = new(new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
            [OAuthRequestParameterNames.PreAuthorizedCode] = scannedCode
        });
        using HttpResponseMessage tokenResponse = await issuerHttp.PostAsync(
            tokenUrl, tokenRequestContent, TestContext.CancellationToken).ConfigureAwait(false);
        string tokenBody = await tokenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, tokenResponse.StatusCode, tokenBody);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenBody);
        string accessToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //§7: the Nonce Endpoint over HTTP issues the proof challenge.
        Uri nonceUrl = new(issuerHost.HttpBaseAddress!, $"/connect/{issuerTenant}/nonce");
        using ByteArrayContent emptyNonceRequestContent = new([]);
        using HttpResponseMessage nonceResponse = await issuerHttp.PostAsync(
            nonceUrl, emptyNonceRequestContent, TestContext.CancellationToken).ConfigureAwait(false);
        string nonceBody = await nonceResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, nonceResponse.StatusCode, nonceBody);

        using JsonDocument nonceDoc = JsonDocument.Parse(nonceBody);
        string credentialNonce = nonceDoc.RootElement.GetProperty("c_nonce").GetString()!;

        //§8: the Credential Request over HTTP — Bearer authorization, JSON body,
        //and a SIGNED holder key proof carrying the c_nonce.
        string proofJwt = await BuildHolderProofAsync(
            holderPrivate, holderPublic,
            issuerMaterial.Registration.IssuerUri!.OriginalString, credentialNonce).ConfigureAwait(false);
        string credentialRequest = "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"proofs\":{\"jwt\":[\"" + proofJwt + "\"]}}";

        Uri credentialUrl = new(issuerHost.HttpBaseAddress!, $"/connect/{issuerTenant}/credential");
        using HttpRequestMessage credentialHttpRequest = new(HttpMethod.Post, credentialUrl)
        {
            Content = new StringContent(credentialRequest, Encoding.UTF8, WellKnownMediaTypes.Application.Json)
        };
        credentialHttpRequest.Headers.Authorization = new AuthenticationHeaderValue(
            WellKnownAuthenticationSchemes.Bearer, accessToken);
        using HttpResponseMessage credentialResponse = await issuerHttp.SendAsync(
            credentialHttpRequest, TestContext.CancellationToken).ConfigureAwait(false);
        string credentialBody = await credentialResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, credentialResponse.StatusCode, credentialBody);
        Assert.IsTrue(seamState.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");

        using JsonDocument credentialDoc = JsonDocument.Parse(credentialBody);
        string issuedSdJwtVc = credentialDoc.RootElement
            .GetProperty("credentials")[0].GetProperty("credential").GetString()!;

        //=== Act 2: the wallet presents the just-issued credential to the Verifier
        //host over ITS real socket — request_uri fetch, KB-JWT, encrypted direct_post. ===
        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, issuedSdJwtVc, holderPrivate,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The two deployments listen on genuinely different sockets.
        Assert.AreNotEqual(
            issuerHost.HttpBaseAddress, app.Host("default").HttpBaseAddress,
            "Issuer and Verifier must serve from independent Kestrel listeners.");

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-multihost-01"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "The wallet must reach ResponseSent after the HTTP direct_post.");
        PresentationVerifiedState verified =
            (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "The Verifier must verify the credential the Issuer host minted over the wire.");
    }


    /// <summary>Mutable cross-step observations the issuer seams record.</summary>
    private sealed class WireIssuerSeamsState
    {
        public bool IsProofVerified { get; set; }
    }


    /// <summary>
    /// Wires the issuer host's seams with real work: pre-authorized-code validation,
    /// c_nonce minting, and §8 issuance that verifies the holder proof signature plus
    /// its c_nonce before minting the SD-JWT VC bound to the proven key.
    /// </summary>
    private WireIssuerSeamsState WireIssuerSeams(
        AuthorizationServerIntegration integration, PrivateKeyMemory sdJwtIssuerPrivate)
    {
        WireIssuerSeamsState state = new();
        string? mintedNonce = null;

        integration.UseDefaultCredentialRequestJsonParsing();

        integration.ValidatePreAuthorizedCodeAsync = (code, txCode, clientId, _, _, _) =>
            ValueTask.FromResult(string.Equals(code, PreAuthorizedCode, StringComparison.Ordinal)
                ? PreAuthorizedCodeDecision.Grant(EndUserSubject, WellKnownScopes.OpenId)
                : PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode));

        integration.IssueCredentialNonceAsync = (_, _) =>
        {
            mintedNonce = $"c-nonce-{Guid.NewGuid():N}";

            return ValueTask.FromResult(mintedNonce);
        };

        integration.IssueCredentialAsync = async (request, accessTokenPayload, _, _, ct) =>
        {
            string proof = request.Proofs[Oid4VciCredentialParameterNames.JwtProofType][0];
            (PublicKeyMemory proofKey, string? proofNonce) = ReadProof(proof);

            using(proofKey)
            {
                bool isProofSignatureValid = await Jws.VerifyAsync(
                    proof, TestSetup.Base64UrlDecoder, Pool,
                    proofKey, ct).ConfigureAwait(false);

                if(!isProofSignatureValid
                    || mintedNonce is null
                    || !string.Equals(proofNonce, mintedNonce, StringComparison.Ordinal))
                {
                    return CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidProof);
                }

                state.IsProofVerified = true;

                string credential = await IssueSdJwtVcAsync(
                    sdJwtIssuerPrivate, proof, ct).ConfigureAwait(false);

                return CredentialIssuanceDecision.Issue([credential]);
            }
        };

        return state;
    }


    /// <summary>
    /// Issues the EUDI PID SD-JWT VC bound to the holder key proven in
    /// <paramref name="proofJwt"/> — the <c>cnf.jwk</c> is read off the proof header, so
    /// the presented KB-JWT later verifies against exactly the key the wallet proved.
    /// </summary>
    private async ValueTask<string> IssueSdJwtVcAsync(
        PrivateKeyMemory sdJwtIssuerPrivate, string proofJwt, CancellationToken cancellationToken)
    {
        string headerJson = DecodeSegment(proofJwt, segmentIndex: 0);
        Dictionary<string, object>? holderJwk = JwkJsonReader.ExtractObjectProperties(
            Encoding.UTF8.GetBytes(headerJson), "jwk"u8);
        Assert.IsNotNull(holderJwk, "The proof header must carry the holder jwk.");

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: SdJwtIssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk!,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, "Alice"),
                new(EudiPid.SdJwt.FamilyName, "Smith")
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
            sdJwtIssuerPrivate, SdJwtIssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());

        return SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// The wallet's §7.2.1 <c>jwt</c> key proof: typ <c>openid4vci-proof+jwt</c>, the holder
    /// public key in the header <c>jwk</c>, the Credential Issuer as <c>aud</c>, and the
    /// <c>c_nonce</c> in the <c>nonce</c> claim.
    /// </summary>
    private async ValueTask<string> BuildHolderProofAsync(
        PrivateKeyMemory holderPrivate, PublicKeyMemory holderPublic, string audience, string credentialNonce)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublic.Tag.Get<CryptoAlgorithm>(),
            holderPublic.Tag.Get<Purpose>(),
            holderPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = "openid4vci-proof+jwt",
            ["jwk"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
                [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
                [WellKnownJwkMemberNames.X] = jwk.X!,
                [WellKnownJwkMemberNames.Y] = jwk.Y!
            }
        };

        JwtPayload payload = new(capacity: 3)
        {
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Nonce] = credentialNonce,
            [WellKnownJwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            holderPrivate, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>Reads the holder key (header <c>jwk</c>) and <c>nonce</c> claim off a proof JWT.</summary>
    private static (PublicKeyMemory ProofKey, string? Nonce) ReadProof(string proofJwt)
    {
        string headerJson = DecodeSegment(proofJwt, segmentIndex: 0);
        Dictionary<string, object>? jwk = JwkJsonReader.ExtractObjectProperties(
            Encoding.UTF8.GetBytes(headerJson), "jwk"u8);
        Assert.IsNotNull(jwk);

        var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
            jwk!, Pool, TestSetup.Base64UrlDecoder);
        Tag proofTag = Tag.Create(algorithm).With(purpose).With(scheme);
        PublicKeyMemory proofKey = new(keyBytes, proofTag);

        string payloadJson = DecodeSegment(proofJwt, segmentIndex: 1);
        string? nonce = JwkJsonReader.ExtractStringValue(Encoding.UTF8.GetBytes(payloadJson), "nonce"u8);

        return (proofKey, nonce);
    }


    private static string DecodeSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);

        return Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');
    }
}
