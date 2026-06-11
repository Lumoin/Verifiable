using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 §10 encrypted Credential Requests and Responses, driven through the real
/// dispatch pipeline with real ECDH-ES + AES-GCM: the Wallet asks for an encrypted response by
/// supplying its key in <c>credential_response_encryption</c> (the issuer's
/// <see cref="EncryptCredentialResponseDelegate"/> seam composes the JWE), and encrypts its
/// request to the issuer's published key (the <see cref="DecryptCredentialRequestDelegate"/>
/// seam opens it). §8.3's deferral initiation (202 + <c>transaction_id</c> from the Credential
/// Endpoint) is exercised on the way.
/// </summary>
[TestClass]
internal sealed class Oid4VciEncryptionTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string IssuedCredential =
        "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJVbml2ZXJzaXR5RGVncmVlIn0.sig~WyJzYWx0IiwiZGVncmVlIiwiQmFjaGVsb3IiXQ~";

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// §10 response encryption round trip: the Wallet supplies its P-256 key and an
    /// <c>enc</c>; the issuer answers <c>application/jwt</c> carrying a JWE only the Wallet's
    /// private key opens, with the §8.3 credentials inside.
    /// </summary>
    [TestMethod]
    public async Task EncryptedCredentialResponseRoundTripsToTheWallet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.Integration.UseDefaultCredentialRequestJsonParsing();
        host.Server.Integration.IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential], "notif-1"));
        WireResponseEncryptionSeam(host);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //§8.2: a request carrying credential_response_encryption MUST itself be encrypted, so the
        //Wallet wraps the whole body as a JWE to the issuer's request-encryption key.
        using PublicKeyMemory issuerPublic = WireRequestDecryptionSeam(host, out PrivateKeyMemory issuerPrivate);
        using PrivateKeyMemory _ = issuerPrivate;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, response.ContentType);

        string decrypted = await DecryptAsync(response.Body, walletPrivate).ConfigureAwait(false);
        using JsonDocument doc = JsonDocument.Parse(decrypted);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
        Assert.AreEqual("notif-1", doc.RootElement.GetProperty("notification_id").GetString());
    }


    /// <summary>
    /// §8.3 deferral initiation + §9 completion, encrypted end to end: the Credential Endpoint
    /// defers with 202 (encrypted, per §8.3's regardless-of-content rule), and the Deferred
    /// Credential Endpoint later delivers the credentials inside a JWE to the key the Wallet
    /// supplied in the deferred request.
    /// </summary>
    [TestMethod]
    public async Task DeferredIssuanceInitiatesAt202AndDeliversEncrypted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.Integration.UseDefaultCredentialRequestJsonParsing();
        host.Server.Integration.IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Defer("8xLOxBtZp8", 60));
        host.Server.Integration.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //§8.2 / §9.1: both the initial and the deferred request carry
        //credential_response_encryption, so both MUST themselves be encrypted to the issuer's
        //request-encryption key.
        using PublicKeyMemory issuerPublic = WireRequestDecryptionSeam(host, out PrivateKeyMemory issuerPrivate);
        using PrivateKeyMemory _ = issuerPrivate;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //The initial Credential Request asks for encryption — the 202 deferral itself
        //comes back as a JWE per §8.3.
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse deferred = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);

        Assert.AreEqual(202, deferred.StatusCode, deferred.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, deferred.ContentType);

        string deferredJson = await DecryptAsync(deferred.Body, walletPrivate).ConfigureAwait(false);
        using JsonDocument pendingDoc = JsonDocument.Parse(deferredJson);
        Assert.AreEqual("8xLOxBtZp8", pendingDoc.RootElement.GetProperty("transaction_id").GetString());
        Assert.AreEqual(60, pendingDoc.RootElement.GetProperty("interval").GetInt64());

        //The Deferred Credential Request supplies (possibly fresh) encryption parameters —
        //§9.1 says the newly provided object governs, and that request too is encrypted.
        string encryptedDeferredRequest = await EncryptToIssuerAsync(
            DeferredRequestBodyWithEncryption("8xLOxBtZp8", walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse delivered = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciDeferredCredential,
            "POST",
            new RequestFields(),
            BearerHeaders(accessToken),
            encryptedDeferredRequest,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, delivered.StatusCode, delivered.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, delivered.ContentType);

        string deliveredJson = await DecryptAsync(delivered.Body, walletPrivate).ConfigureAwait(false);
        using JsonDocument issuedDoc = JsonDocument.Parse(deliveredJson);
        Assert.AreEqual(IssuedCredential,
            issuedDoc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
    }


    /// <summary>
    /// Fail-closed: a request asking for encryption is never answered in clear — an unwired
    /// seam and malformed parameters each refuse with <c>invalid_encryption_parameters</c>.
    /// </summary>
    [TestMethod]
    public async Task EncryptionRequestFailsClosedWithoutSeamOrParameters()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.Integration.UseDefaultCredentialRequestJsonParsing();
        host.Server.Integration.IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        //EncryptCredentialResponseAsync deliberately left unwired.

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //§8.2: a request carrying credential_response_encryption MUST itself be encrypted, so the
        //Wallet wraps each body as a JWE to the issuer's request-encryption key — these requests
        //must reach the response-seam / parameter-shape checks, not be stopped at the substitution
        //gate.
        using PublicKeyMemory issuerPublic = WireRequestDecryptionSeam(host, out PrivateKeyMemory issuerPrivate);
        using PrivateKeyMemory _ = issuerPrivate;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        string encryptedAsk = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse unwired = await DispatchCredentialAsync(
            host, material, accessToken, encryptedAsk).ConfigureAwait(false);
        Assert.AreEqual(400, unwired.StatusCode, unwired.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, unwired.Body);

        WireResponseEncryptionSeam(host);

        //jwk present but enc missing — the §8.2 REQUIRED member check fires before the seam.
        string missingEnc = "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_response_encryption\":{\"jwk\":" + JwkJson(walletPublic) + "}}";
        string encryptedMissingEnc = await EncryptToIssuerAsync(missingEnc, issuerPublic).ConfigureAwait(false);
        ServerHttpResponse malformed = await DispatchCredentialAsync(
            host, material, accessToken, encryptedMissingEnc).ConfigureAwait(false);
        Assert.AreEqual(400, malformed.StatusCode, malformed.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, malformed.Body);
    }


    /// <summary>
    /// §10 request encryption: the Wallet encrypts the whole Credential Request to the
    /// issuer's published key; the decryption seam opens it and issuance proceeds normally.
    /// Without the seam, an encrypted request is refused rather than misparsed.
    /// </summary>
    [TestMethod]
    public async Task EncryptedCredentialRequestIsOpenedByTheDecryptionSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.Integration.UseDefaultCredentialRequestJsonParsing();

        CredentialRequest? seenRequest = null;
        host.Server.Integration.IssueCredentialAsync = (request, _, _, _, _) =>
        {
            seenRequest = request;

            return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        };

        //The issuer's request-decryption key pair, advertised in real deployments via
        //credential_request_encryption.jwks in the issuer metadata.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string plainRequest = "{\"credential_configuration_id\":\"" + ConfigurationId + "\"}";
        string encryptedRequest = await HaipProfile.EncryptResponseAsync(
            issuerPublic,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            Encoding.UTF8.GetBytes(plainRequest).AsMemory(),
            HeaderSerializer,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //Seam not wired yet: the encrypted request is refused, never misparsed.
        ServerHttpResponse refused = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, refused.Body);

        host.Server.Integration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        ServerHttpResponse issued = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);

        Assert.AreEqual(200, issued.StatusCode, issued.Body);
        Assert.IsNotNull(seenRequest);
        Assert.AreEqual(ConfigurationId, seenRequest!.CredentialConfigurationId,
            "The decrypted request must parse to the same shape as a plain one.");
    }


    /// <summary>
    /// §12.2.4 <c>encryption_required</c> is enforced, not just advertised: when the issuer
    /// metadata contribution promises required response encryption, a request without
    /// <c>credential_response_encryption</c> is refused — never answered in clear — and the
    /// same ask WITH the parameters succeeds.
    /// </summary>
    [TestMethod]
    public async Task ResponseEncryptionRequiredRefusesARequestWithoutParameters()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.Integration.UseDefaultCredentialRequestJsonParsing();
        host.Server.Integration.IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);
        host.Server.Integration.ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["alg_values_supported"] = new List<object> { WellKnownJweAlgorithms.EcdhEs },
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = true
                }
            });

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //§8.2: the accepted ask carries credential_response_encryption, so its request leg MUST
        //be encrypted to the issuer's request-encryption key.
        using PublicKeyMemory issuerPublic = WireRequestDecryptionSeam(host, out PrivateKeyMemory issuerPrivate);
        using PrivateKeyMemory _ = issuerPrivate;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //A plaintext request WITHOUT credential_response_encryption: §12.2.4 required response
        //encryption is missing, so it is refused. The §8.2 substitution rule does not bite here —
        //the request carries no credential_response_encryption — so the body stays plaintext.
        ServerHttpResponse refused = await DispatchCredentialAsync(
            host, material, accessToken,
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\"}").ConfigureAwait(false);
        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, refused.Body);

        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse accepted = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(200, accepted.StatusCode, accepted.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, accepted.ContentType);
    }


    /// <summary>
    /// §10: when the metadata contribution promises required request encryption, a plain
    /// JSON body is refused; the same request as a JWE to the issuer's key succeeds.
    /// </summary>
    [TestMethod]
    public async Task RequestEncryptionRequiredRefusesAPlainBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.Integration.UseDefaultCredentialRequestJsonParsing();
        host.Server.Integration.IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        host.Server.Integration.ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialRequestEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = true
                }
            });

        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.Integration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string plainRequest = "{\"credential_configuration_id\":\"" + ConfigurationId + "\"}";

        ServerHttpResponse refused = await DispatchCredentialAsync(
            host, material, accessToken, plainRequest).ConfigureAwait(false);
        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, refused.Body);

        string encryptedRequest = await HaipProfile.EncryptResponseAsync(
            issuerPublic,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            Encoding.UTF8.GetBytes(plainRequest).AsMemory(),
            HeaderSerializer,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse accepted = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(200, accepted.StatusCode, accepted.Body);
    }


    /// <summary>
    /// Wires the issuer's response-encryption seam with real ECDH-ES + AES-GCM: the recipient
    /// key is reconstructed from the request's <c>jwk</c> and the JWE composed with the same
    /// provider delegates the OID4VP <c>direct_post.jwt</c> path uses.
    /// </summary>
    private static void WireResponseEncryptionSeam(TestHostShell host)
    {
        host.Server.Integration.EncryptCredentialResponseAsync = async (responseJson, encryption, _, _, ct) =>
        {
            Dictionary<string, object> jwkDict = new(StringComparer.Ordinal);
            foreach(KeyValuePair<string, object> member in encryption.Jwk!)
            {
                jwkDict[member.Key] = member.Value;
            }

            var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                jwkDict, Pool, TestSetup.Base64UrlDecoder);
            Tag recipientTag = Tag.Create(
                (typeof(CryptoAlgorithm), algorithm),
                (typeof(Purpose), purpose),
                (typeof(EncodingScheme), scheme));
            using PublicKeyMemory recipientKey = new(keyBytes, recipientTag);

            //§10: the JWE alg comes from the JWK's alg member (never hardcoded) and the JWK's
            //kid — when present — is copied into the JWE protected header. The library has
            //already validated alg presence + advertised-set membership before this seam runs.
            return await HaipProfile.EncryptResponseAsync(
                recipientKey,
                encryption.Enc!,
                Encoding.UTF8.GetBytes(responseJson).AsMemory(),
                HeaderSerializer,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                TestSetup.Base64UrlEncoder,
                Pool,
                keyManagementAlgorithm: encryption.Alg,
                keyId: encryption.Kid,
                cancellationToken: ct).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Generates the issuer's request-decryption key pair, wires the §10
    /// <see cref="DecryptCredentialRequestDelegate"/> seam to open requests with the private key,
    /// and returns the public key the Wallet encrypts to (its <c>credential_request_encryption.jwks</c>
    /// advertisement in a real deployment). The caller owns disposal of both keys.
    /// </summary>
    private PublicKeyMemory WireRequestDecryptionSeam(TestHostShell host, out PrivateKeyMemory issuerPrivate)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        issuerPrivate = issuerKeys.PrivateKey;
        PrivateKeyMemory capturedPrivate = issuerPrivate;
        host.Server.Integration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, capturedPrivate).ConfigureAwait(false);

        return issuerPublic;
    }


    /// <summary>
    /// Encrypts a plaintext (Deferred) Credential Request body to the issuer's published
    /// request-decryption key — the Wallet's §10 / §8.2 request-encryption side.
    /// </summary>
    private async Task<string> EncryptToIssuerAsync(string requestBody, PublicKeyMemory issuerPublic)
    {
        return await HaipProfile.EncryptResponseAsync(
            issuerPublic,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            Encoding.UTF8.GetBytes(requestBody).AsMemory(),
            HeaderSerializer,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Decrypts a compact JWE with the recipient's private key — the Wallet's side of §10.</summary>
    private async Task<string> DecryptAsync(string compactJwe, PrivateKeyMemory recipientPrivate)
    {
        string headerSegment = compactJwe[..compactJwe.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerSegment, Pool);
        string? enc = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "enc"u8);
        Assert.IsNotNull(enc, "JWE protected header must carry 'enc'.");

        using AeadMessage parsedJwe = JweParsing.ParseCompact(
            compactJwe,
            WellKnownJweAlgorithms.EcdhEs,
            enc!,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsedJwe.DecryptAsync(
            recipientPrivate,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return Encoding.UTF8.GetString(decrypted.AsReadOnlySpan());
    }


    private static string JwkJson(PublicKeyMemory recipientPublic)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            recipientPublic.Tag.Get<CryptoAlgorithm>(),
            recipientPublic.Tag.Get<Purpose>(),
            recipientPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        return "{\"kty\":\"" + jwk.Kty + "\",\"crv\":\"" + jwk.Crv + "\",\"x\":\"" + jwk.X
            + "\",\"y\":\"" + jwk.Y + "\",\"alg\":\"" + WellKnownJweAlgorithms.EcdhEs + "\"}";
    }


    private static string CredentialRequestBodyWithEncryption(PublicKeyMemory recipientPublic) =>
        "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
        + "\"credential_response_encryption\":{\"jwk\":" + JwkJson(recipientPublic)
        + ",\"enc\":\"" + WellKnownJweEncryptionAlgorithms.A256Gcm + "\"}}";


    private static string DeferredRequestBodyWithEncryption(string transactionId, PublicKeyMemory recipientPublic) =>
        "{\"transaction_id\":\"" + transactionId + "\","
        + "\"credential_response_encryption\":{\"jwk\":" + JwkJson(recipientPublic)
        + ",\"enc\":\"" + WellKnownJweEncryptionAlgorithms.A256Gcm + "\"}}";


    private static RequestHeaders BearerHeaders(string accessToken) =>
        new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
        });


    private async Task<string> MintAccessTokenAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.Integration.ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    private async Task<ServerHttpResponse> DispatchCredentialAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken, string jsonBody)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            BearerHeaders(accessToken),
            jsonBody,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
