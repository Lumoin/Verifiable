using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 §10 response encryption with a POST-QUANTUM KEM: the Wallet supplies an
/// ML-KEM-768 (FIPS 203) public key in <c>credential_response_encryption</c> and the issuer's
/// seam answers with a JWE whose content key is KEM-encapsulated instead of ECDH-agreed.
/// This pins the seam contract the §10 design promises: the library owns only the wire
/// decisions (a request asking for encryption gets <c>application/jwt</c> or a refusal) and
/// transports whatever compact JWE the deployment composes — the key management suite is
/// entirely the application's, so a quantum-resistant KEM needs NO library change.
/// </summary>
/// <remarks>
/// HONEST STATUS: the JOSE binding for ML-KEM (the AKP JWK shape for KEM keys and the
/// <c>ML-KEM-768</c> JWE <c>alg</c> value) is DRAFT-stage IETF work, not a final IANA
/// registration. These tests therefore pin the KEM-agnosticism of the library seams and a
/// concrete BouncyCastle ML-KEM + AES-GCM composition — not wire interoperability with a
/// finalized profile. When the JOSE PQC registrations finalize, the composition here is the
/// reference for promoting constants into the library.
/// </remarks>
[TestClass]
internal sealed class Oid4VciPostQuantumEncryptionTests
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

    //Draft-stage JOSE value (see the class remarks) — deliberately a test-local constant,
    //not a WellKnownJweAlgorithms member, until the IANA registration is final.
    private const string MlKem768JweAlgorithm = "ML-KEM-768";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// §10 round trip with ML-KEM-768 + A256GCM: the seam encapsulates to the Wallet's KEM
    /// key (the 32-byte shared secret IS the A256GCM content encryption key), the
    /// encapsulation rides the JWE encrypted-key segment — non-empty, unlike ECDH-ES — and
    /// only the Wallet's decapsulation opens the response.
    /// </summary>
    [TestMethod]
    public async Task MlKemEncryptedCredentialResponseRoundTripsToTheWallet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential], "notif-pq-1"));
        WireMlKemResponseEncryptionSeam(host);

        var walletKemKeys = TestKeyMaterialProvider.CreateFreshMlKem768KeyMaterial();
        using PublicKeyMemory walletKemPublic = walletKemKeys.PublicKey;
        using PrivateKeyMemory walletKemPrivate = walletKemKeys.PrivateKey;

        //§8.2: a request carrying credential_response_encryption MUST itself be encrypted. The
        //request leg uses the classical ECDH-ES request-encryption channel — independent of the
        //post-quantum KEM the response leg exercises.
        using PublicKeyMemory issuerPublic = WireRequestDecryptionSeam(host, out PrivateKeyMemory issuerPrivate);
        using PrivateKeyMemory _ = issuerPrivate;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithKemEncryption(walletKemPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, response.ContentType,
            "§10 wire shape is unchanged by the key management suite.");

        string decrypted = await DecryptMlKemJweAsync(response.Body, walletKemPrivate).ConfigureAwait(false);
        using JsonDocument doc = JsonDocument.Parse(decrypted);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
        Assert.AreEqual("notif-pq-1", doc.RootElement.GetProperty("notification_id").GetString());
    }


    /// <summary>
    /// Tampering with the encapsulation is caught: ML-KEM's implicit rejection makes a
    /// flipped-ciphertext decapsulation yield a DIFFERENT pseudorandom secret rather than an
    /// error, so the wrong content key surfaces as an AES-GCM authentication tag failure —
    /// never as silently wrong plaintext.
    /// </summary>
    [TestMethod]
    public async Task TamperedKemEncapsulationFailsAuthentication()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        WireMlKemResponseEncryptionSeam(host);

        var walletKemKeys = TestKeyMaterialProvider.CreateFreshMlKem768KeyMaterial();
        using PublicKeyMemory walletKemPublic = walletKemKeys.PublicKey;
        using PrivateKeyMemory walletKemPrivate = walletKemKeys.PrivateKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted.
        using PublicKeyMemory issuerPublic = WireRequestDecryptionSeam(host, out PrivateKeyMemory issuerPrivate);
        using PrivateKeyMemory _ = issuerPrivate;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithKemEncryption(walletKemPublic), issuerPublic).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, encryptedRequest).ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        string[] parts = response.Body.Split('.');
        using IMemoryOwner<byte> encapsulation = TestSetup.Base64UrlDecoder(parts[1], Pool);
        encapsulation.Memory.Span[0] ^= 0xFF;
        parts[1] = TestSetup.Base64UrlEncoder(encapsulation.Memory.Span);
        string tampered = string.Join('.', parts);

        await Assert.ThrowsAsync<CryptographicException>(
            async () => await DecryptMlKemJweAsync(tampered, walletKemPrivate).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Generates the issuer's classical ECDH-ES request-decryption key pair and wires the §10
    /// <see cref="DecryptCredentialRequestDelegate"/> seam to open requests with the private key.
    /// Returns the public key the Wallet encrypts its request to; the caller owns both keys.
    /// </summary>
    private PublicKeyMemory WireRequestDecryptionSeam(TestHostShell host, out PrivateKeyMemory issuerPrivate)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        issuerPrivate = issuerKeys.PrivateKey;
        PrivateKeyMemory capturedPrivate = issuerPrivate;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptEcdhJweAsync(jwe, capturedPrivate).ConfigureAwait(false);

        return issuerPublic;
    }


    /// <summary>
    /// Encrypts a plaintext Credential Request body to the issuer's classical ECDH-ES
    /// request-encryption key — the Wallet's §8.2 / §10 request-encryption side.
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


    /// <summary>Decrypts a classical ECDH-ES + AES-GCM compact JWE — the issuer's request-decryption side.</summary>
    private async Task<string> DecryptEcdhJweAsync(string compactJwe, PrivateKeyMemory recipientPrivate)
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


    /// <summary>
    /// Wires the §10 response-encryption seam with ML-KEM-768 key encapsulation + AES-GCM
    /// content encryption: encapsulate to the Wallet's <c>pub</c>, use the shared secret as
    /// the content encryption key directly, and carry the encapsulation in the JWE
    /// encrypted-key segment.
    /// </summary>
    private static void WireMlKemResponseEncryptionSeam(TestHostShell host)
    {
        host.Server.OAuth().EncryptCredentialResponseAsync = async (responseJson, encryption, _, _, ct) =>
        {
            string recipientPub = (string)encryption.Jwk!["pub"];
            using IMemoryOwner<byte> recipientKeyBytes = TestSetup.Base64UrlDecoder(recipientPub, Pool);

            (IMemoryOwner<byte> kemCiphertext, IMemoryOwner<byte> sharedSecret) =
                BouncyCastleCryptographicFunctions.EncapsulateMlKem768(recipientKeyBytes.Memory, Pool);
            using IMemoryOwner<byte> encapsulation = kemCiphertext;
            //The 32-byte ML-KEM shared secret is exactly an A256GCM key — no KDF stage in
            //this composition. Ownership of the secret transfers to the key wrapper.
            using SymmetricKeyMemory contentEncryptionKey = new(sharedSecret, CryptoTags.AesGcmCek);

            string headerJson = "{\"alg\":\"" + MlKem768JweAlgorithm + "\",\"enc\":\"" + encryption.Enc + "\"}";
            string encodedHeader = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));

            //AAD is the ASCII bytes of the encoded protected header per RFC 7516 §5.1 step 14.
            byte[] aadBytes = Encoding.ASCII.GetBytes(encodedHeader);
            IMemoryOwner<byte> aadOwner = Pool.Rent(aadBytes.Length);
            aadBytes.CopyTo(aadOwner.Memory.Span);
            using AdditionalData aad = new(aadOwner, CryptoTags.AesGcmAad);

            using AeadEncryptResult sealedContent = await BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync(
                Encoding.UTF8.GetBytes(responseJson).AsMemory(),
                contentEncryptionKey, aad, Pool, ct).ConfigureAwait(false);

            return encodedHeader
                + "." + TestSetup.Base64UrlEncoder(encapsulation.Memory.Span)
                + "." + TestSetup.Base64UrlEncoder(sealedContent.Iv.AsReadOnlySpan())
                + "." + TestSetup.Base64UrlEncoder(sealedContent.Ciphertext.AsReadOnlySpan())
                + "." + TestSetup.Base64UrlEncoder(sealedContent.Tag.AsReadOnlySpan());
        };
    }


    /// <summary>
    /// The Wallet's side: decapsulate the encrypted-key segment with the ML-KEM private key
    /// and open the AES-GCM content with the recovered secret.
    /// </summary>
    private async Task<string> DecryptMlKemJweAsync(string compactJwe, PrivateKeyMemory recipientPrivate)
    {
        string[] parts = compactJwe.Split('.');
        Assert.HasCount(5, parts, "A KEM JWE is still RFC 7516 five-part compact serialization.");
        Assert.IsFalse(string.IsNullOrEmpty(parts[1]),
            "The encapsulation rides the encrypted-key segment — non-empty, unlike ECDH-ES direct agreement.");

        using IMemoryOwner<byte> kemCiphertext = TestSetUpDecode(parts[1]);
        IMemoryOwner<byte> sharedSecret = BouncyCastleCryptographicFunctions.DecapsulateMlKem768(
            recipientPrivate.AsReadOnlyMemory(), kemCiphertext.Memory, Pool);
        using SymmetricKeyMemory contentEncryptionKey = new(sharedSecret, CryptoTags.AesGcmCek);

        byte[] aadBytes = Encoding.ASCII.GetBytes(parts[0]);
        IMemoryOwner<byte> aadOwner = Pool.Rent(aadBytes.Length);
        aadBytes.CopyTo(aadOwner.Memory.Span);
        using AdditionalData aad = new(aadOwner, CryptoTags.AesGcmAad);

        using Nonce iv = new(TestSetUpDecode(parts[2]), CryptoTags.AesGcmIv);
        using Ciphertext ciphertext = new(TestSetUpDecode(parts[3]), CryptoTags.AesGcmCiphertext);
        using AuthenticationTag tag = new(TestSetUpDecode(parts[4]), CryptoTags.AesGcmAuthTag);

        using DecryptedContent decrypted = await BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync(
            ciphertext, contentEncryptionKey, iv, tag, aad, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return Encoding.UTF8.GetString(decrypted.AsReadOnlySpan());
    }


    private static IMemoryOwner<byte> TestSetUpDecode(string base64UrlSegment) =>
        TestSetup.Base64UrlDecoder(base64UrlSegment, Pool);


    /// <summary>
    /// The Wallet's <c>credential_response_encryption</c> carrying an ML-KEM-768 public key
    /// as an AKP JWK (<c>kty</c>/<c>alg</c>/<c>pub</c> — the draft JOSE PQC key shape).
    /// </summary>
    private static string CredentialRequestBodyWithKemEncryption(PublicKeyMemory kemPublic) =>
        "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
        + "\"credential_response_encryption\":{\"jwk\":{\"kty\":\"AKP\",\"alg\":\""
        + MlKem768JweAlgorithm + "\",\"pub\":\"" + TestSetup.Base64UrlEncoder(kemPublic.AsReadOnlySpan())
        + "\"},\"enc\":\"" + WellKnownJweEncryptionAlgorithms.A256Gcm + "\"}}";


    private static RequestHeaders BearerHeaders(string accessToken) =>
        new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
        });


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
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }
}
