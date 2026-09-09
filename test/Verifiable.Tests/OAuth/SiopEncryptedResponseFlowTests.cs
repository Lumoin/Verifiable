using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The encrypted analog of <see cref="SiopFlowIntegrationTests"/>: the SIOPv2 Self-Issued ID Token
/// returned as a compact JWE encrypted to the Relying Party's public encryption key, driven through
/// the real SIOP RP-as-server dispatch chain. The RP prepares a transaction advertising its
/// encryption key, the wallet mints a JWK-Thumbprint id_token bound to the nonce/client_id and then
/// encrypts it as a compact JWE to the RP's encryption key, and the SIOP response endpoint detects
/// the JWE, decrypts it (validating <c>enc</c> against the advertised set), and runs the §11.1
/// validation on the recovered inner id_token — reaching the terminal
/// <see cref="SelfIssuedAuthenticationVerifiedState"/>. The SIOP parallel of the OID4VP encrypted
/// Authorization Response flow.
/// </summary>
[TestClass]
internal sealed class SiopEncryptedResponseFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string RelyingPartyClientId = "https://rp.example.com";
    private const string SiopNonce = "n-siop-encrypted-01";

    private static Uri RelyingPartyBaseUri { get; } = new("https://rp.example.com");

    private static ImmutableHashSet<CapabilityIdentifier> SiopCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    private static string[] AllowedSiopAlgorithms { get; } = [WellKnownJwaValues.Es256];

    //The RP's advertised content-encryption algorithms — the HAIP-mandated A128GCM/A256GCM set.
    private static string[] AllowedEncAlgorithms { get; } =
        [WellKnownJweEncryptionAlgorithms.A128Gcm, WellKnownJweEncryptionAlgorithms.A256Gcm];

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task EncryptedIdTokenPostReachesVerifiedState()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        //The RP registers a dedicated encryption key (distinct from the signing key) and retains its
        //public half so the test wallet can encrypt the id_token JWE to it.
        (KeyId encryptionKeyId, PublicKeyMemory rpEncryptionPublicKey) = host.RegisterRpEncryptionKey();
        using PublicKeyMemory rpEncryptionPublicKeyOwner = rpEncryptionPublicKey;

        //=== Step 1: the RP prepares the transaction advertising its encryption key + accepted enc. ===
        (string requestHandle, _) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false,
            encryptionKeyId: encryptionKeyId.Value,
            allowedEncAlgorithms: AllowedEncAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        //=== Step 2: the wallet mints a plain id_token, then encrypts it as a compact JWE. ===
        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string compactJwe = await MintAndEncryptIdTokenAsync(
            siopPrivate, siopPublic, rpEncryptionPublicKey, SiopNonce,
            WellKnownJweEncryptionAlgorithms.A128Gcm).ConfigureAwait(false);

        //A compact JWE is five dot-separated segments; the endpoint discriminates by this shape.
        Assert.AreEqual(4, CountDots(compactJwe));

        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

        //=== Step 3: the wallet POSTs the JWE in the id_token field + state to the Response endpoint. ===
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = compactJwe,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //=== Step 4: 200 and the terminal verified state with the expected subject + nonce. ===
        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, verified.Subject);
        Assert.AreEqual(SiopNonce, verified.Nonce);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
    }


    [TestMethod]
    public async Task UnadvertisedEncAlgorithmFailsClosedNamingRejectedEnc()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        (KeyId encryptionKeyId, PublicKeyMemory rpEncryptionPublicKey) = host.RegisterRpEncryptionKey();
        using PublicKeyMemory rpEncryptionPublicKeyOwner = rpEncryptionPublicKey;

        //The RP advertises ONLY A256GCM; the wallet encrypts with A128GCM, which is therefore not in
        //the advertised set. The flow must fail closed naming the rejected enc.
        (string requestHandle, _) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false,
            encryptionKeyId: encryptionKeyId.Value,
            allowedEncAlgorithms: [WellKnownJweEncryptionAlgorithms.A256Gcm],
            TestContext.CancellationToken).ConfigureAwait(false);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string compactJwe = await MintAndEncryptIdTokenAsync(
            siopPrivate, siopPublic, rpEncryptionPublicKey, SiopNonce,
            WellKnownJweEncryptionAlgorithms.A128Gcm).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = compactJwe,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode,
            "RFC 6749 §4.1.2.1: an unadvertised JWE 'enc' is a Wallet-attributable malformed response, "
            + "answered as HTTP 400, not as an HTTP 500 Verifier fault.");

        (string wireError, _) = ReadOAuthErrorBody(response.Body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SiopVerifierFlowFailedState failed =
            Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
        Assert.Contains(WellKnownJweEncryptionAlgorithms.A128Gcm, failed.Reason);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "SIOPv2 §11.1: an unadvertised encrypted-response 'enc' is the Malformed refusal class.");
    }


    /// <summary>
    /// An encrypted Self-Issued ID Token carrying exactly four dots — so the response endpoint's own
    /// <c>IsCompactJwe</c> segment-count discriminator routes it to the encrypted path — but whose IV
    /// segment holds a character outside the base64url alphabet is not a well-formed compact JWE per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-3.1">RFC 7516, Section 3.1</see>, a
    /// shape no conformant Wallet produces. <c>JweParsing.ParseCompact</c>'s <see cref="FormatException"/>
    /// routes the presentation to the Malformed refusal class (RFC 6749 §4.1.2.1 <c>invalid_request</c>,
    /// HTTP 400) rather than a Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task NonCompactEncryptedIdTokenIsRefusedAsInvalidRequestNotServerError()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        (KeyId encryptionKeyId, PublicKeyMemory rpEncryptionPublicKey) = host.RegisterRpEncryptionKey();
        using PublicKeyMemory rpEncryptionPublicKeyOwner = rpEncryptionPublicKey;

        (string requestHandle, _) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false,
            encryptionKeyId: encryptionKeyId.Value,
            allowedEncAlgorithms: AllowedEncAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string compactJwe = await MintAndEncryptIdTokenAsync(
            siopPrivate, siopPublic, rpEncryptionPublicKey, SiopNonce,
            WellKnownJweEncryptionAlgorithms.A128Gcm).ConfigureAwait(false);
        string notCompactJwe = MalformIvSegment(compactJwe);

        Assert.AreEqual(4, CountDots(notCompactJwe),
            "The segment count must stay 4 dots so the response endpoint still routes this as an encrypted response.");

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = notCompactJwe,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode,
            "RFC 6749 §4.1.2.1: a non-compact encrypted Self-Issued ID Token is answered as HTTP 400, "
            + "not as an HTTP 500 Verifier fault.");

        (string wireError, _) = ReadOAuthErrorBody(response.Body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");

        (FlowState state, _) = host.GetFlowState(requestHandle);
        SiopVerifierFlowFailedState failed =
            Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "SIOPv2 §11.1: a non-compact encrypted Self-Issued ID Token is the Malformed refusal class.");
    }


    //Replaces the first character of the IV segment (index 2 of the five compact-JWE segments) with
    //'!', a character outside the base64url alphabet — RFC 7516 §3.1's compact serialization rejects
    //it at parse time, before any cryptographic operation, distinct from TamperCiphertext's
    //still-valid-base64url tag-verification failure.
    private static string MalformIvSegment(string compactJwe)
    {
        string[] segments = compactJwe.Split('.');
        segments[2] = "!" + segments[2][1..];

        return string.Join('.', segments);
    }


    /// <summary>
    /// Reads the <c>error</c> member of an RFC 6749 §4.1.2.1 error object, failing the test when the
    /// body is not that object.
    /// </summary>
    /// <param name="body">The response body the SIOP response endpoint wrote.</param>
    /// <returns>The error code and its description.</returns>
    private static (string Error, string? Description) ReadOAuthErrorBody(string body)
    {
        using JsonDocument document = JsonDocument.Parse(body);

        Assert.AreEqual(JsonValueKind.Object, document.RootElement.ValueKind,
            "RFC 6749 §4.1.2.1: the error response body is a JSON object.");
        Assert.IsTrue(
            document.RootElement.TryGetProperty(OAuthRequestParameterNames.Error, out JsonElement error),
            "RFC 6749 §4.1.2.1: error is REQUIRED in the error response.");
        document.RootElement.TryGetProperty(
            OAuthRequestParameterNames.ErrorDescription, out JsonElement description);

        return (error.GetString()!, description.ValueKind == JsonValueKind.String ? description.GetString() : null);
    }


    [TestMethod]
    public async Task TamperedCiphertextFailsTagVerificationNoInnerTokenLeaks()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        (KeyId encryptionKeyId, PublicKeyMemory rpEncryptionPublicKey) = host.RegisterRpEncryptionKey();
        using PublicKeyMemory rpEncryptionPublicKeyOwner = rpEncryptionPublicKey;

        (string requestHandle, _) = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            useStaticDiscoveryAudience: false,
            encryptionKeyId: encryptionKeyId.Value,
            allowedEncAlgorithms: AllowedEncAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string compactJwe = await MintAndEncryptIdTokenAsync(
            siopPrivate, siopPublic, rpEncryptionPublicKey, SiopNonce,
            WellKnownJweEncryptionAlgorithms.A128Gcm).ConfigureAwait(false);

        //Flip one byte of the ciphertext segment (the fourth of five). AES-GCM tag verification then
        //fails inside DecryptAsync, so no inner token is ever recovered.
        string tampered = TamperCiphertext(compactJwe);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = tampered,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(host.GetFlowState(requestHandle).State);
    }


    [TestMethod]
    public async Task BareJwsIdTokenPathStillReachesVerifiedState()
    {
        //The encrypted path must not disturb the bare-JWS id_token path: a three-segment id_token
        //emits SiopResponsePosted and reaches the verified state exactly as SiopFlowIntegrationTests.
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

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, CountDots(idToken));

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

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(
            host.GetFlowState(requestHandle).State);
    }


    /// <summary>
    /// The wallet-side encrypt composition: mint a plain JWK-Thumbprint Self-Issued ID Token bound to
    /// the transaction, then wrap it as a compact JWE (ECDH-ES + AES-GCM) to the RP's public encryption
    /// key with the SAME JWE primitives <see cref="HaipProfile.EncryptResponseAsync(PublicKeyMemory, string, ReadOnlyMemory{byte}, JwtHeaderSerializer, TagToEpkCrvDelegate, KeyAgreementEncryptDelegate, KeyDerivationDelegate, AeadEncryptDelegate, EncodeDelegate, BaseMemoryPool, string, CancellationToken)"/>
    /// uses on the OID4VP wallet side.
    /// </summary>
    private async Task<string> MintAndEncryptIdTokenAsync(
        PrivateKeyMemory siopPrivate,
        PublicKeyMemory siopPublic,
        PublicKeyMemory rpEncryptionPublicKey,
        string nonce,
        string selectedEnc)
    {
        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, nonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        int idTokenByteCount = Encoding.UTF8.GetByteCount(idToken);
        using IMemoryOwner<byte> idTokenBytes = Pool.Rent(idTokenByteCount);
        int written = Encoding.UTF8.GetBytes(idToken, idTokenBytes.Memory.Span);

        return await HaipProfile.EncryptResponseAsync(
            rpEncryptionPublicKey,
            selectedEnc,
            idTokenBytes.Memory[..written],
            HeaderSerializer,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
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


    private static int CountDots(string value)
    {
        int dots = 0;
        foreach(char c in value)
        {
            if(c == '.')
            {
                dots++;
            }
        }

        return dots;
    }


    //Flip a single character in the ciphertext segment (segment index 3 of the five compact-JWE
    //segments) so AES-GCM tag verification fails. The character chosen is base64url-valid, so the
    //tampering is detected by the AEAD tag, not by malformed decoding.
    private static string TamperCiphertext(string compactJwe)
    {
        string[] segments = compactJwe.Split('.');
        char[] ciphertext = segments[3].ToCharArray();
        ciphertext[0] = ciphertext[0] == 'A' ? 'B' : 'A';
        segments[3] = new string(ciphertext);

        return string.Join('.', segments);
    }
}
