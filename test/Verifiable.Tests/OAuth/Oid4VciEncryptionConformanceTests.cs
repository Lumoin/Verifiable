using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
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
using Verifiable.Server.Routing;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 encryption conformance at the Credential Endpoint: the §8.2 / §9.1 substitution
/// defense and the §10 JWE <c>alg</c> / <c>kid</c> MUSTs, plus the §12.2.4 advertised-set gate.
/// Driven through the real dispatch pipeline with real ECDH-ES + AES-GCM, sibling to
/// <see cref="Oid4VciEncryptionTests"/>.
/// </summary>
[TestClass]
internal sealed class Oid4VciEncryptionConformanceTests
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

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

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
    /// §8.2: "Credential Request encryption MUST be used if the credential_response_encryption
    /// parameter is included, to prevent it being substituted by an attacker." A PLAINTEXT
    /// Credential Request that nonetheless carries credential_response_encryption is a
    /// response-key substitution attempt — refused with invalid_encryption_parameters, never
    /// issued. The encrypted-request + response-encryption happy path still issues.
    /// </summary>
    [TestMethod]
    public async Task PlaintextRequestAskingForEncryptedResponseIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        //The issuer requires encrypted Credential Requests. The §8.2 "Credential Request
        //encryption MUST be used if credential_response_encryption is included" holds regardless
        //of this flag — the unconditional case is covered separately by
        //PlaintextRequestAskingForEncryptedResponseIsRefusedEvenWhenEncryptionNotRequired.
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialRequestEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = true
                }
            });

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //The issuer's request-decryption key, advertised in real deployments via
        //credential_request_encryption.jwks in the issuer metadata.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //A plaintext body carrying credential_response_encryption under the required-request
        //policy: the §8.2 substitution defense fires.
        ServerHttpResponse substituted = await DispatchCredentialAsync(
            host, material, accessToken,
            CredentialRequestBodyWithEncryption(walletPublic)).ConfigureAwait(false);
        Assert.AreEqual(400, substituted.StatusCode, substituted.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, substituted.Body);

        //The same ask, but with the WHOLE request encrypted to the issuer's key, issues — the
        //response-encryption parameters are then authenticated, not substitutable.
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse issued = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(200, issued.StatusCode, issued.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, issued.ContentType);

        string decrypted = await DecryptAsync(issued.Body, walletPrivate).ConfigureAwait(false);
        Assert.Contains(IssuedCredential, decrypted);
    }


    /// <summary>
    /// §8.2 is unconditional: "Credential Request encryption MUST be used if the
    /// credential_response_encryption parameter is included, to prevent it being substituted by an
    /// attacker." The preceding sentence makes encryption a Client MAY when encryption_required is
    /// false, yet this final MUST stands independent of it — so a PLAINTEXT request carrying
    /// credential_response_encryption is refused EVEN WHEN encryption_required is false. Here the
    /// issuer advertises encryption_required:false for both request and response, and the plaintext
    /// substitution attempt is still refused.
    /// </summary>
    [TestMethod]
    public async Task PlaintextRequestAskingForEncryptedResponseIsRefusedEvenWhenEncryptionNotRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        //encryption_required is false on BOTH legs — encryption is a Client MAY here, NOT a MUST
        //from the policy. The §8.2 final-sentence MUST is what refuses the plaintext substitution.
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialRequestEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = false
                },
                CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["alg_values_supported"] = new List<object> { WellKnownJweAlgorithms.EcdhEs },
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = false
                }
            });

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //The issuer can open encrypted requests — but the Wallet sends this one in clear.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //Plaintext body carrying credential_response_encryption, encryption_required:false: the
        //unconditional §8.2 MUST refuses it anyway.
        ServerHttpResponse substituted = await DispatchCredentialAsync(
            host, material, accessToken,
            CredentialRequestBodyWithEncryption(walletPublic)).ConfigureAwait(false);
        Assert.AreEqual(400, substituted.StatusCode, substituted.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, substituted.Body);

        //The same ask, with the whole request encrypted, issues — the response-encryption
        //parameters are now authenticated and not substitutable.
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse issued = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(200, issued.StatusCode, issued.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, issued.ContentType);

        string decrypted = await DecryptAsync(issued.Body, walletPrivate).ConfigureAwait(false);
        Assert.Contains(IssuedCredential, decrypted);
    }


    /// <summary>
    /// §9.1: "Deferred Credential Request encryption MUST [be] used if the
    /// credential_response_encryption parameter is included, to prevent it being substituted by
    /// an attacker." The substitution defense extends to the Deferred Credential Endpoint: a
    /// plaintext deferred request asking for an encrypted response is refused.
    /// </summary>
    [TestMethod]
    public async Task PlaintextDeferredRequestAskingForEncryptedResponseIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        //The issuer requires encrypted requests — the §9.1 substitution defense's policy.
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialRequestEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = true
                }
            });

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        ServerHttpResponse substituted = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciDeferredCredential,
            "POST",
            new RequestFields(),
            BearerHeaders(accessToken),
            DeferredRequestBodyWithEncryption("8xLOxBtZp8", walletPublic),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, substituted.StatusCode, substituted.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, substituted.Body);
    }


    /// <summary>
    /// §9.1: "The Client MAY encrypt the request when encryption_required is false and MUST do so
    /// when encryption_required is true." §10: "When encryption of a message was required but the
    /// received message is unencrypted, it SHOULD be rejected." The request-encryption gate the
    /// Credential Endpoint enforces (covered by RequestEncryptionRequiredRefusesAPlainBody) is
    /// shared by — and here pinned on — the Deferred Credential Endpoint: with the issuer
    /// advertising credential_request_encryption.encryption_required:true, a PLAINTEXT Deferred
    /// Credential Request carrying only a transaction_id is refused with invalid_credential_request,
    /// while the SAME request encrypted to the issuer's key proceeds and issues.
    /// </summary>
    [TestMethod]
    public async Task DeferredRequestEncryptionRequiredRefusesAPlainBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));

        //§9.1: the issuer requires encrypted requests on the request leg.
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialRequestEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = true
                }
            });

        //The issuer's request-decryption key, advertised in real deployments via
        //credential_request_encryption.jwks in the issuer metadata.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //A plaintext deferred request — just the REQUIRED transaction_id, no response-encryption —
        //is the §9.1/§10 "received message is unencrypted" case the gate SHOULD reject.
        string plainDeferredRequest = "{\"transaction_id\":\"8xLOxBtZp8\"}";

        ServerHttpResponse refused = await DispatchDeferredAsync(
            host, material, accessToken, plainDeferredRequest).ConfigureAwait(false);
        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, refused.Body);

        //The SAME request encrypted to the issuer's key satisfies the §9.1 MUST and proceeds.
        string encryptedDeferredRequest = await EncryptToIssuerAsync(
            plainDeferredRequest, issuerPublic).ConfigureAwait(false);
        ServerHttpResponse issued = await DispatchDeferredAsync(
            host, material, accessToken, encryptedDeferredRequest).ConfigureAwait(false);
        Assert.AreEqual(200, issued.StatusCode, issued.Body);
    }


    /// <summary>
    /// §12.2.4: "alg_values_supported : REQUIRED. ... the JWE [RFC7516] encryption algorithms
    /// (alg values) ... supported by the Credential Endpoint to encode the Credential Response."
    /// A credential_response_encryption whose alg is NOT among the advertised alg_values_supported
    /// is unsupported — refused fail-closed with invalid_encryption_parameters before the seam.
    /// </summary>
    [TestMethod]
    public async Task ResponseEncryptionAlgNotAdvertisedIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        //The issuer advertises ONLY ECDH-ES+A256KW — not the plain ECDH-ES the JWK names.
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["alg_values_supported"] = new List<object> { WellKnownJweAlgorithms.EcdhEsA256Kw },
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm }
                }
            });

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted, so it
        //reaches the §12.2.4 advertised-set check rather than the substitution gate.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse refused = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, refused.Body);
    }


    /// <summary>
    /// §10: "The alg parameter MUST be present." A credential_response_encryption whose JWK omits
    /// the alg member cannot satisfy the §10 "JWE alg MUST be equal to the alg value of the chosen
    /// JWK" rule — the library refuses it with invalid_encryption_parameters rather than handing a
    /// headless key to the composition seam.
    /// </summary>
    [TestMethod]
    public async Task ResponseEncryptionJwkWithoutAlgIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted, so it
        //reaches the §10 alg-presence shape check rather than the substitution gate.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //A JWK with kty/crv/x/y but NO alg member.
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            walletPublic.Tag.Get<CryptoAlgorithm>(),
            walletPublic.Tag.Get<Purpose>(),
            walletPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        string jwkWithoutAlg = "{\"kty\":\"" + jwk.Kty + "\",\"crv\":\"" + jwk.Crv
            + "\",\"x\":\"" + jwk.X + "\",\"y\":\"" + jwk.Y + "\"}";
        string body = "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_response_encryption\":{\"jwk\":" + jwkWithoutAlg
            + ",\"enc\":\"" + WellKnownJweEncryptionAlgorithms.A256Gcm + "\"}}";

        string encryptedRequest = await EncryptToIssuerAsync(body, issuerPublic).ConfigureAwait(false);
        ServerHttpResponse refused = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidEncryptionParameters, refused.Body);
    }


    /// <summary>
    /// §10: "If the selected public key contains a kid parameter, the JWE MUST include the same
    /// value in the kid JWE Header Parameter ... of the encrypted message." A response-encryption
    /// JWK carrying a kid is reflected verbatim in the served JWE protected header.
    /// </summary>
    [TestMethod]
    public async Task ResponseEncryptionJwkKidIsCopiedIntoTheJweHeader()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireResponseEncryptionSeam(host);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);

        const string ExpectedKid = "wallet-response-key-2026";
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic, kid: ExpectedKid), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, response.ContentType);

        //Decode the served compact JWE protected header and assert the kid was copied verbatim.
        string headerSegment = response.Body[..response.Body.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerSegment, Pool);
        string? kid = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "kid"u8);
        Assert.AreEqual(ExpectedKid, kid,
            "§10: the JWK's kid MUST appear unchanged in the JWE kid header parameter.");
        string? alg = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "alg"u8);
        Assert.AreEqual(WellKnownJweAlgorithms.EcdhEs, alg,
            "§10: the JWE alg MUST equal the JWK's alg member, not a hardcoded value.");

        //The JWE still opens — the kid header rode along without breaking the AAD-bound content.
        string decrypted = await DecryptAsync(response.Body, walletPrivate).ConfigureAwait(false);
        Assert.Contains(IssuedCredential, decrypted);
    }


    /// <summary>
    /// Encrypts a plaintext (Deferred) Credential Request body to the issuer's published
    /// request-decryption key — the Wallet's §10 request-encryption side.
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


    /// <summary>
    /// Wires the issuer's response-encryption seam with real ECDH-ES + AES-GCM, reading the JWE
    /// alg off the request JWK and copying the JWK's kid into the JWE header (§10).
    /// </summary>
    private static void WireResponseEncryptionSeam(TestHostShell host)
    {
        host.Server.OAuth().EncryptCredentialResponseAsync = async (responseJson, encryption, _, _, ct) =>
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


    private static string JwkJson(PublicKeyMemory recipientPublic, string? kid = null)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            recipientPublic.Tag.Get<CryptoAlgorithm>(),
            recipientPublic.Tag.Get<Purpose>(),
            recipientPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        string kidMember = kid is null ? string.Empty : ",\"kid\":\"" + kid + "\"";

        return "{\"kty\":\"" + jwk.Kty + "\",\"crv\":\"" + jwk.Crv + "\",\"x\":\"" + jwk.X
            + "\",\"y\":\"" + jwk.Y + "\",\"alg\":\"" + WellKnownJweAlgorithms.EcdhEs + "\"" + kidMember + "}";
    }


    private static string CredentialRequestBodyWithEncryption(PublicKeyMemory recipientPublic, string? kid = null) =>
        "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
        + "\"credential_response_encryption\":{\"jwk\":" + JwkJson(recipientPublic, kid)
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

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(tokenResponse.Body);

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


    private async Task<ServerHttpResponse> DispatchDeferredAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken, string jsonBody)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciDeferredCredential,
            "POST",
            new RequestFields(),
            BearerHeaders(accessToken),
            jsonBody,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
