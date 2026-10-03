using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
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
/// OID4VCI 1.0 encryption conformance at the Credential Endpoint: the §8.2 / §9.1 substitution
/// defense and the §10 JWE <c>alg</c> / <c>kid</c> MUSTs, plus the §12.2.4 advertised-set gate.
/// Driven through the real dispatch pipeline with real ECDH-ES + AES-GCM, sibling to
/// <see cref="Oid4VciEncryptionTests"/>.
/// </summary>
[TestClass]
internal sealed class Oid4VciEncryptionConformanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string IssuedCredential =
        "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJVbml2ZXJzaXR5RGVncmVlIn0.sig~WyJzYWx0IiwiZGVncmVlIiwiQmFjaGVsb3IiXQ~";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// §8.2: "Credential Request encryption MUST be used if the credential_response_encryption
    /// parameter is included, to prevent it being substituted by an attacker." A PLAINTEXT
    /// Credential Request that nonetheless carries credential_response_encryption is a
    /// response-key substitution attempt — refused with invalid_encryption_parameters, never
    /// issued. The encrypted-request + response-encryption happy path still issues.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task PlaintextRequestAskingForEncryptedResponseIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);

        //The issuer requires encrypted Credential Requests. The §8.2 "Credential Request
        //encryption MUST be used if credential_response_encryption is included" holds regardless
        //of this flag — the unconditional case is covered separately by
        //PlaintextRequestAskingForEncryptedResponseIsRefusedEvenWhenEncryptionNotRequired.
        //The issuer's request-decryption key is advertised as credential_request_encryption.jwks.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        Dictionary<string, object> requestEncryption =
            TestHostShell.ComposeCredentialRequestEncryptionObject(issuerPublic, isEncryptionRequired: true);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId),
                    CredentialRequestEncryption = requestEncryption,
                    CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alg_values_supported"] = new List<object> { WellKnownJweAlgorithms.EcdhEs },
                        ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                        ["encryption_required"] = false
                    }
                });
        }).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task PlaintextRequestAskingForEncryptedResponseIsRefusedEvenWhenEncryptionNotRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);

        //encryption_required is false on BOTH legs — encryption is a Client MAY here, NOT a MUST
        //from the policy. The §8.2 final-sentence MUST is what refuses the plaintext substitution.
        //The issuer can decrypt encrypted requests, its request-decryption key advertised as
        //credential_request_encryption.jwks, but the Wallet sends this one in clear.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        Dictionary<string, object> requestEncryption =
            TestHostShell.ComposeCredentialRequestEncryptionObject(issuerPublic, isEncryptionRequired: false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId),
                    CredentialRequestEncryption = requestEncryption,
                    CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alg_values_supported"] = new List<object> { WellKnownJweAlgorithms.EcdhEs },
                        ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                        ["encryption_required"] = false
                    }
                });
        }).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task PlaintextDeferredRequestAskingForEncryptedResponseIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);

        //The issuer requires encrypted requests, the section 9.1 substitution defense's policy. Its
        //request-encryption public key is advertised as credential_request_encryption.jwks; the
        //plaintext request this row sends is refused before any decryption.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        Dictionary<string, object> requestEncryption =
            TestHostShell.ComposeCredentialRequestEncryptionObject(issuerPublic, isEncryptionRequired: true);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId),
                    CredentialRequestEncryption = requestEncryption
                });
        }).ConfigureAwait(false);

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
            [],
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);

        //Section 9.1: the issuer requires encrypted requests on the request leg; its
        //request-decryption key is advertised as credential_request_encryption.jwks.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        Dictionary<string, object> requestEncryption =
            TestHostShell.ComposeCredentialRequestEncryptionObject(issuerPublic, isEncryptionRequired: true);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId),
                    CredentialRequestEncryption = requestEncryption
                });
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task ResponseEncryptionAlgNotAdvertisedIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);

        //The issuer advertises ONLY ECDH-ES+A256KW — not the plain ECDH-ES the JWK names.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId),
                    CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alg_values_supported"] = new List<object> { WellKnownJweAlgorithms.EcdhEsA256Kw },
                        ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                        ["encryption_required"] = false
                    }
                });
        }).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted, so it
        //reaches the §12.2.4 advertised-set check rather than the substitution gate.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task ResponseEncryptionJwkWithoutAlgIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted, so it
        //reaches the §10 alg-presence shape check rather than the substitution gate.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        //§8.2: the request carrying credential_response_encryption MUST itself be encrypted.
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
    /// A Credential Request asking for an encrypted Credential Response from a Credential Issuer whose
    /// metadata advertises no <c>credential_response_encryption</c> is refused with
    /// <c>invalid_encryption_parameters</c> and the issuance seam is not consulted; the request is
    /// itself encrypted, so no other rule refuses it.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "The Credential Issuer indicates support for encrypted responses by including the
    /// credential_response_encryption parameter in the Credential Issuer Metadata."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task ACredentialRequestAskingForResponseEncryptionTheCatalogueDoesNotAdvertiseIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int issuanceCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref issuanceCalls);

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublicKey).ConfigureAwait(false);
        (int statusCode, string body) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciCredential, accessToken, encryptedRequest).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"invalid_encryption_parameters\",\"error_description\":\""
            + "The Credential Issuer Metadata advertises no credential_response_encryption, so no encrypted response can be requested.\"}",
            body);
        Assert.AreEqual(0, issuanceCalls, "A refused request must not reach the issuance seam.");
    }


    /// <summary>
    /// A Deferred Credential Request asking for an encrypted response from a Credential Issuer whose
    /// metadata advertises no <c>credential_response_encryption</c> is refused with
    /// <c>invalid_encryption_parameters</c> and the deferred-resolution seam is not consulted; the
    /// request is itself encrypted, so no other rule refuses it.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.1">OID4VCI 1.0 Section 9.1</see>:
    /// "The Credential Issuer indicates support for encrypted responses by including the
    /// credential_response_encryption parameter in the Credential Issuer Metadata."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_encryption_parameters: This error occurs when the encryption parameters in the
    /// Credential Request are either invalid or missing."
    /// </summary>
    [TestMethod]
    public async Task ADeferredRequestAskingForResponseEncryptionTheCatalogueDoesNotAdvertiseIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int resolutionCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref resolutionCalls);

                return ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            DeferredRequestBodyWithEncryption("8xLOxBtZp8", walletPublic), issuerPublicKey).ConfigureAwait(false);
        (int statusCode, string body) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciDeferredCredential, accessToken, encryptedRequest)
            .ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"invalid_encryption_parameters\",\"error_description\":\""
            + "The Credential Issuer Metadata advertises no credential_response_encryption, so no encrypted response can be requested.\"}",
            body);
        Assert.AreEqual(0, resolutionCalls, "A refused request must not reach the deferred-resolution seam.");
    }


    /// <summary>
    /// A <c>credential_response_encryption</c> object carries both of its REQUIRED lists, each
    /// non-empty, so a catalogue whose object lacks a list or holds an empty one is a catalogue the
    /// Credential Issuer Metadata endpoint refuses to publish, and the Credential Endpoint serves no
    /// request under it: a Credential Request asking for an encrypted response and a plain Credential
    /// Request asking for none are each answered 500 <c>server_error</c> with the body the metadata
    /// endpoint answers for that catalogue, and the issuance seam is not consulted. The first request
    /// is itself encrypted and names <c>ECDH-ES</c> and <c>A256GCM</c>, the second is plain JSON, so no
    /// rule of either request refuses it first.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "alg_values_supported: REQUIRED. A non-empty array containing a list of the JWE [RFC7516]
    /// encryption algorithms (alg values) [RFC7518] supported by the Credential Endpoint to encode the
    /// Credential Response in a JWT [RFC7519]." And: "enc_values_supported: REQUIRED. A non-empty array
    /// containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by
    /// the Credential Endpoint to encode the Credential Response in a JWT [RFC7519]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected
    /// condition that prevented it from fulfilling the request."
    /// </summary>
    /// <param name="algValue">The one <c>alg_values_supported</c> entry; empty for an empty list, <see langword="null"/> for no member.</param>
    /// <param name="encValue">The one <c>enc_values_supported</c> entry; empty for an empty list, <see langword="null"/> for no member.</param>
    /// <param name="expectedBody">The literal body the metadata endpoint answers for the catalogue.</param>
    [TestMethod]
    [DataRow(null, null, /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_response_encryption is missing the REQUIRED non-empty alg_values_supported array (12.2.4).\"}")]
    [DataRow("ECDH-ES", null, /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_response_encryption is missing the REQUIRED non-empty enc_values_supported array (12.2.4).\"}")]
    [DataRow(null, "A256GCM", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_response_encryption is missing the REQUIRED non-empty alg_values_supported array (12.2.4).\"}")]
    [DataRow("", "A256GCM", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_response_encryption is missing the REQUIRED non-empty alg_values_supported array (12.2.4).\"}")]
    public async Task ACredentialRequestAgainstAResponseEncryptionObjectWithoutBothListsIsRefused(
        string? algValue, string? encValue, string expectedBody)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int issuanceCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref issuanceCalls);

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;
        await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(
            host.Server, ComposeResponseEncryptionObject(algValue, encValue)).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublicKey).ConfigureAwait(false);
        (int statusCode, string body) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciCredential, accessToken, encryptedRequest).ConfigureAwait(false);
        (int plainStatusCode, string plainBody) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciCredential, accessToken,
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\"}", WellKnownMediaTypes.Application.Json)
            .ConfigureAwait(false);

        Assert.AreEqual(500, statusCode, body);
        Assert.AreEqual(expectedBody, body);
        Assert.AreEqual(500, plainStatusCode, plainBody);
        Assert.AreEqual(expectedBody, plainBody);
        Assert.AreEqual(0, issuanceCalls, "A request under a catalogue the metadata endpoint refuses must not reach the issuance seam.");
    }


    /// <summary>
    /// A <c>credential_response_encryption</c> object carries its REQUIRED lists, so a catalogue whose
    /// object is empty is a catalogue the Credential Issuer Metadata endpoint refuses to publish, and
    /// the Deferred Credential Endpoint serves no request under it: a Deferred Credential Request asking
    /// for an encrypted response and a plain one asking for none are each answered 500
    /// <c>server_error</c> with the body the metadata endpoint answers for that catalogue, and the
    /// deferred-resolution seam is not consulted. The first request is itself encrypted, the second is
    /// plain JSON, so no rule of either request refuses it first.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "alg_values_supported: REQUIRED. A non-empty array containing a list of the JWE [RFC7516]
    /// encryption algorithms (alg values) [RFC7518] supported by the Credential Endpoint to encode the
    /// Credential Response in a JWT [RFC7519]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected
    /// condition that prevented it from fulfilling the request."
    /// </summary>
    [TestMethod]
    public async Task ADeferredRequestAgainstAnEmptyResponseEncryptionObjectIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int resolutionCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref resolutionCalls);

                return ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;
        await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(
            host.Server, ComposeResponseEncryptionObject(algValue: null, encValue: null)).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string encryptedRequest = await EncryptToIssuerAsync(
            DeferredRequestBodyWithEncryption("8xLOxBtZp8", walletPublic), issuerPublicKey).ConfigureAwait(false);
        (int statusCode, string body) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciDeferredCredential, accessToken, encryptedRequest)
            .ConfigureAwait(false);
        (int plainStatusCode, string plainBody) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciDeferredCredential, accessToken,
            "{\"transaction_id\":\"8xLOxBtZp8\"}", WellKnownMediaTypes.Application.Json).ConfigureAwait(false);

        string expectedBody = /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\""
            + "credential_response_encryption is missing the REQUIRED non-empty alg_values_supported array (12.2.4).\"}";
        Assert.AreEqual(500, statusCode, body);
        Assert.AreEqual(expectedBody, body);
        Assert.AreEqual(500, plainStatusCode, plainBody);
        Assert.AreEqual(expectedBody, plainBody);
        Assert.AreEqual(0, resolutionCalls, "A request under a catalogue the metadata endpoint refuses must not reach the deferred-resolution seam.");
    }


    /// <summary>
    /// A <c>credential_response_encryption</c> object that sets <c>encryption_required</c> to
    /// <see langword="true"/> and carries neither of its REQUIRED lists is a catalogue the Credential
    /// Issuer Metadata endpoint refuses to publish, so it issues no Credential: a Credential Request
    /// asking for an encrypted response and a plain Credential Request asking for none are each
    /// answered 500 <c>server_error</c> with the body the metadata endpoint answers for that catalogue,
    /// and the issuance seam is not consulted. The first request is itself encrypted, the second is
    /// plain JSON, so no rule of either request refuses it first.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "alg_values_supported: REQUIRED. A non-empty array containing a list of the JWE [RFC7516]
    /// encryption algorithms (alg values) [RFC7518] supported by the Credential Endpoint to encode the
    /// Credential Response in a JWT [RFC7519]." And: "enc_values_supported: REQUIRED. A non-empty array
    /// containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by
    /// the Credential Endpoint to encode the Credential Response in a JWT [RFC7519]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected
    /// condition that prevented it from fulfilling the request."
    /// </summary>
    [TestMethod]
    public async Task ARequiredResponseEncryptionWithoutItsListsIssuesNoCredential()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int issuanceCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref issuanceCalls);

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;
        await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(
            host.Server,
            new Dictionary<string, object>(StringComparer.Ordinal) { ["encryption_required"] = true }).ConfigureAwait(false);

        var walletKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory walletPublic = walletKeys.PublicKey;
        using PrivateKeyMemory walletPrivate = walletKeys.PrivateKey;

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        (int withoutStatusCode, string withoutBody) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciCredential, accessToken,
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\"}", WellKnownMediaTypes.Application.Json)
            .ConfigureAwait(false);
        string withResponseEncryption = await EncryptToIssuerAsync(
            CredentialRequestBodyWithEncryption(walletPublic), issuerPublicKey).ConfigureAwait(false);
        (int withStatusCode, string withBody) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciCredential, accessToken, withResponseEncryption)
            .ConfigureAwait(false);

        string expectedBody = /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\""
            + "credential_response_encryption is missing the REQUIRED non-empty alg_values_supported array (12.2.4).\"}";
        Assert.AreEqual(500, withoutStatusCode, withoutBody);
        Assert.AreEqual(expectedBody, withoutBody);
        Assert.AreEqual(500, withStatusCode, withBody);
        Assert.AreEqual(expectedBody, withBody);
        Assert.AreEqual(0, issuanceCalls, "A request under a catalogue the metadata endpoint refuses must not reach the issuance seam.");
    }


    /// <summary>
    /// The Credential Endpoint serves a request only under a catalogue the Credential Issuer Metadata
    /// endpoint publishes: a plain Credential Request under a catalogue whose encryption object lacks a
    /// REQUIRED member, or carries <c>encryption_required</c> as a string, is answered exactly as the
    /// metadata endpoint answers for that catalogue, 500 <c>server_error</c> with the same body, and the
    /// issuance seam is not consulted. The request asks for no encrypted response and is not itself
    /// encrypted, so no encryption rule of the request refuses it.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>,
    /// on <c>credential_response_encryption</c>: "encryption_required: REQUIRED. Boolean value specifying
    /// whether the Credential Issuer requires the additional encryption on top of TLS for the Credential
    /// Response." And on <c>credential_request_encryption</c>: "jwks: REQUIRED. A JSON Web Key Set, as
    /// defined in [RFC7591], that contains one or more public keys, to be used by the Wallet as an input
    /// to a key agreement for encryption of the Credential Request."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected
    /// condition that prevented it from fulfilling the request."
    /// </summary>
    /// <param name="faultyObject">Which encryption object the catalogue carries without its REQUIRED shape.</param>
    /// <param name="expectedMetadataBody">The literal body the metadata endpoint answers for the catalogue.</param>
    [TestMethod]
    [DataRow("credential_response_encryption with encryption_required as a string", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_response_encryption is missing the REQUIRED boolean encryption_required member (12.2.4).\"}")]
    [DataRow("credential_response_encryption without encryption_required", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_response_encryption is missing the REQUIRED boolean encryption_required member (12.2.4).\"}")]
    [DataRow("credential_request_encryption without jwks", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_request_encryption is missing the REQUIRED jwks member (12.2.4).\"}")]
    public async Task ACredentialRequestUnderAnEncryptionObjectTheMetadataEndpointRefusesIsAServerError(
        string faultyObject, string expectedMetadataBody)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int issuanceCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref issuanceCalls);

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        (Dictionary<string, object>? RequestEncryption, Dictionary<string, object>? ResponseEncryption) encryptionObjects = faultyObject switch
        {
            "credential_response_encryption with encryption_required as a string" =>
                (null, ComposeResponseEncryptionObject(WellKnownJweAlgorithms.EcdhEs, WellKnownJweEncryptionAlgorithms.A256Gcm, encryptionRequired: "true")),
            "credential_response_encryption without encryption_required" =>
                (null, ComposeResponseEncryptionObject(WellKnownJweAlgorithms.EcdhEs, WellKnownJweEncryptionAlgorithms.A256Gcm)),
            "credential_request_encryption without jwks" =>
                (new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["enc_values_supported"] = new List<object> { WellKnownJweEncryptionAlgorithms.A256Gcm },
                    ["encryption_required"] = false
                }, null),
            _ => throw new ArgumentOutOfRangeException(nameof(faultyObject), faultyObject, "No catalogue is composed for this object.")
        };
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host, encryptionObjects.RequestEncryption).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;
        if(encryptionObjects.ResponseEncryption is Dictionary<string, object> responseEncryption)
        {
            await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(host.Server, responseEncryption).ConfigureAwait(false);
        }

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        (int statusCode, string body) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciCredential, accessToken,
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\"}", WellKnownMediaTypes.Application.Json)
            .ConfigureAwait(false);
        (int metadataStatusCode, string metadataBody) = await host.FetchCredentialIssuerMetadataOverWireAsync(
            material.Registration.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(500, metadataStatusCode, metadataBody);
        Assert.AreEqual(expectedMetadataBody, metadataBody);
        Assert.AreEqual(metadataStatusCode, statusCode, body);
        Assert.AreEqual(metadataBody, body);
        Assert.AreEqual(0, issuanceCalls, "A request under a catalogue the metadata endpoint refuses must not reach the issuance seam.");
    }


    /// <summary>
    /// The Deferred Credential Endpoint serves a request only under a catalogue the Credential Issuer
    /// Metadata endpoint publishes: a plain Deferred Credential Request under a catalogue whose
    /// <c>credential_response_encryption</c> carries <c>encryption_required</c> as the string
    /// <c>"true"</c> is answered exactly as the metadata endpoint answers for that catalogue, 500
    /// <c>server_error</c> with the same body, and the deferred-resolution seam is not consulted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "encryption_required: REQUIRED. Boolean value specifying whether the Credential Issuer requires the
    /// additional encryption on top of TLS for the Credential Response."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected
    /// condition that prevented it from fulfilling the request."
    /// </summary>
    [TestMethod]
    public async Task ADeferredRequestUnderAStringEncryptionRequiredFlagIsAServerError()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        int resolutionCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            candidateIntegration.ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref resolutionCalls);

                return ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        (PublicKeyMemory issuerPublic, PrivateKeyMemory issuerPrivate) =
            await WireCatalogueWithoutResponseEncryptionAsync(host).ConfigureAwait(false);
        using PublicKeyMemory issuerPublicKey = issuerPublic;
        using PrivateKeyMemory issuerPrivateKey = issuerPrivate;
        await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(
            host.Server,
            ComposeResponseEncryptionObject(WellKnownJweAlgorithms.EcdhEs, WellKnownJweEncryptionAlgorithms.A256Gcm, encryptionRequired: "true"))
            .ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        (int statusCode, string body) = await PostOverWireAsync(
            host, material, WellKnownEndpointNames.Oid4VciDeferredCredential, accessToken,
            "{\"transaction_id\":\"8xLOxBtZp8\"}", WellKnownMediaTypes.Application.Json).ConfigureAwait(false);
        (int metadataStatusCode, string metadataBody) = await host.FetchCredentialIssuerMetadataOverWireAsync(
            material.Registration.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(500, metadataStatusCode, metadataBody);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\""
            + "credential_response_encryption is missing the REQUIRED boolean encryption_required member (12.2.4).\"}",
            metadataBody);
        Assert.AreEqual(metadataStatusCode, statusCode, body);
        Assert.AreEqual(metadataBody, body);
        Assert.AreEqual(0, resolutionCalls, "A request under a catalogue the metadata endpoint refuses must not reach the deferred-resolution seam.");
    }


    /// <summary>
    /// Composes a <c>credential_response_encryption</c> object as an application may hand it over, with
    /// each list present only when its value is given (an empty value is an empty list, any other value
    /// a list of that one entry), <c>encryption_required</c> present only when
    /// <paramref name="encryptionRequired"/> is given, and no other member, so absent values compose the
    /// empty object.
    /// </summary>
    /// <param name="algValue">The one <c>alg_values_supported</c> entry; empty for an empty list, <see langword="null"/> for no member.</param>
    /// <param name="encValue">The one <c>enc_values_supported</c> entry; empty for an empty list, <see langword="null"/> for no member.</param>
    /// <param name="encryptionRequired">The <c>encryption_required</c> value as handed over, or <see langword="null"/> for no member.</param>
    /// <returns>The object the catalogue carries.</returns>
    private static Dictionary<string, object> ComposeResponseEncryptionObject(
        string? algValue, string? encValue, object? encryptionRequired = null)
    {
        Dictionary<string, object> responseEncryption = new(StringComparer.Ordinal);
        if(algValue is not null)
        {
            responseEncryption["alg_values_supported"] = algValue.Length == 0 ? new List<object>() : new List<object> { algValue };
        }

        if(encValue is not null)
        {
            responseEncryption["enc_values_supported"] = encValue.Length == 0 ? new List<object>() : new List<object> { encValue };
        }

        if(encryptionRequired is not null)
        {
            responseEncryption["encryption_required"] = encryptionRequired;
        }

        return responseEncryption;
    }


    /// <summary>
    /// Wires a catalogue listing <see cref="ConfigurationId"/> with no <c>credential_response_encryption</c>
    /// object, and the request-decryption seam over a fresh issuer exchange pair, so a row's encrypted
    /// request is opened and judged against a Credential Issuer advertising no response encryption; with
    /// <paramref name="requestEncryption"/> set, the catalogue carries it as its
    /// <c>credential_request_encryption</c> object as the application hands it over.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="requestEncryption">The <c>credential_request_encryption</c> object, or <see langword="null"/> for none.</param>
    /// <returns>The issuer's request-encryption pair; the caller disposes both.</returns>
    private async Task<(PublicKeyMemory IssuerPublic, PrivateKeyMemory IssuerPrivate)> WireCatalogueWithoutResponseEncryptionAsync(
        TestHostShell host, IReadOnlyDictionary<string, object>? requestEncryption = null)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId),
                    CredentialRequestEncryption = requestEncryption
                });
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, _) =>
                await DecryptAsync(jwe, issuerPrivate).ConfigureAwait(false);
        }).ConfigureAwait(false);

        return (issuerKeys.PublicKey, issuerPrivate);
    }


    /// <summary>
    /// POSTs a (Deferred) Credential Request to the endpoint <paramref name="endpointName"/> names over the
    /// host's loopback listener with <paramref name="accessToken"/> under the Bearer scheme, starting the
    /// listener when it is not running: a compact JWE as <c>application/jwt</c>, or with
    /// <paramref name="mediaType"/> set, a plain body as that media type.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose endpoint is addressed.</param>
    /// <param name="endpointName">The endpoint addressed.</param>
    /// <param name="accessToken">The Access Token presented under the Bearer scheme.</param>
    /// <param name="body">The request body: a compact JWE, or a plain body of <paramref name="mediaType"/>.</param>
    /// <param name="mediaType">The body's media type, or <see langword="null"/> for <c>application/jwt</c>.</param>
    /// <returns>The status code and body the wire delivered.</returns>
    private async Task<(int StatusCode, string Body)> PostOverWireAsync(
        TestHostShell host, VerifierKeyMaterial material, string endpointName, string accessToken, string body, string? mediaType = null)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri endpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!, material.Registration.TenantId.Value, endpointName);

        using StringContent content = new(body, Encoding.UTF8, mediaType ?? WellKnownMediaTypes.Application.Jwt);
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint) { Content = content };
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, "Bearer " + accessToken);
        using HttpResponseMessage response = await host.Host("default").SharedHttpClient!
            .SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, responseBody);
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
    /// alg off the request JWK and copying the JWK's kid into the JWE header (section 10), and makes the
    /// catalogue advertise ECDH-ES with A256GCM for encrypted responses.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    private static async Task WireResponseEncryptionSeamAsync(TestHostShell host)
    {
        await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(
            host.Server, [WellKnownJweAlgorithms.EcdhEs], [WellKnownJweEncryptionAlgorithms.A256Gcm]).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EncryptCredentialResponseAsync = async (responseJson, encryption, _, _, ct) =>
            {
                Dictionary<string, object> jwkDict = new(StringComparer.Ordinal);
                foreach(KeyValuePair<string, object> member in encryption.Jwk!)
                {
                    jwkDict[member.Key] = member.Value;
                }

                var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                    jwkDict, Pool, TestSetup.Base64UrlDecoder);
                Tag recipientTag = Tag.Create(algorithm).With(purpose).With(scheme);
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
        }).ConfigureAwait(false);
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
            enc,
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


    /// <summary>
    /// Completes the fixture token exchange and returns an access token for the credential endpoint request.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            [],
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
            [],
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
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
