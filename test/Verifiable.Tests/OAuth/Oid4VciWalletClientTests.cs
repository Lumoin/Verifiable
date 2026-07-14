using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net.Http;
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
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The reusable <see cref="Oid4VciWalletClient"/> driving OID4VCI 1.0 issuance over REAL
/// Kestrel HTTP: §6 Pre-Authorized Code Token Request → §7 Nonce Request → §8 Credential
/// Request carrying a verified §7.2.1 holder key proof. Two flavours are exercised — a plain
/// Bearer-authorized, plaintext-response issuance, and a §10 ECDH-ES encrypted-response
/// issuance the wallet decrypts. These replace the hand-rolled raw-<see cref="HttpClient"/>
/// issuance flow with a single client call.
/// </summary>
[TestClass]
internal sealed class Oid4VciWalletClientTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    private const string ConfigurationId = "eu.europa.ec.eudi.pid.1";
    private const string PreAuthorizedCode = "SplxlOBeZQQYbYS6WxSbIA";
    private const string EndUserSubject = "urn:uuid:end-user-42";
    private const string IssuedCredential = "issued-credential-opaque-42";

    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuerCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// Pre-Authorized Code → plain Bearer → plaintext response: the wallet client drives §6/§7/§8
    /// over a real socket and returns the issued Credential, and the issuer seam confirms it
    /// verified the holder proof signature and its c_nonce.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverPlainBearerAndPlaintextResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        IssuerSeamObservations observations = WireIssuerSeams(host);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        string issued = await walletClient.IssuePreAuthorizedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(IssuedCredential, issued,
            "The wallet client must return the credential the Issuer minted over the wire.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString, observations.ProofAudience,
            "The minted proof must carry the Credential Issuer identifier as aud.");
    }


    /// <summary>
    /// Pre-Authorized Code → §10 ECDH-ES encrypted response: the wallet asks for response
    /// encryption, the issuer seam composes the JWE with real ECDH-ES + AES-GCM, and the wallet's
    /// DecryptResponse drop-out opens it and reads the credential.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverEncryptedResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        IssuerSeamObservations observations = WireIssuerSeams(host);
        WireResponseEncryptionSeam(host);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The wallet's §10 response-encryption key pair: the public side rides the
        //credential_response_encryption ask, the private side opens the JWE.
        var responseKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory responsePublic = responseKeys.PublicKey;
        using PrivateKeyMemory responsePrivate = responseKeys.PrivateKey;

        //§8.2: a request carrying credential_response_encryption MUST itself be encrypted. The
        //issuer's request-decryption key pair (advertised via credential_request_encryption.jwks)
        //opens what the wallet's EncryptRequest seam seals.
        var requestKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory requestPublic = requestKeys.PublicKey;
        using PrivateKeyMemory requestPrivate = requestKeys.PrivateKey;
        host.Server.OAuth().DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
            await DecryptAsync(jwe, requestPrivate, ct).ConfigureAwait(false);

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            decryptResponse: (compactJwe, ct) => DecryptAsync(compactJwe, responsePrivate, ct),
            encryptRequest: (requestBody, ct) => EncryptToIssuerAsync(requestBody, requestPublic, ct));

        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = EcJwkMembers(responsePublic),
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        string issued = await walletClient.IssuePreAuthorizedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(IssuedCredential, issued,
            "The wallet must decrypt the §10 JWE response and read the credential.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof even on the encrypted path.");
    }


    /// <summary>
    /// §4.1.3: "the Wallet MUST send an HTTP GET request to the URI to retrieve the referenced
    /// Credential Offer Object ... and parse it to recreate the Credential Offer parameters." The
    /// wallet client accepts a by-reference Pre-Authorized offer link, GETs the offer off the real
    /// Issuer endpoint, and drives the fetched offer through to issuance — proving the §4.1.3 fetch
    /// feeds the same downstream §6/§7/§8 path as a directly-composed offer.
    /// </summary>
    [TestMethod]
    public async Task FetchedByReferenceOfferDrivesIssuanceEndToEnd()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        IssuerSeamObservations observations = WireIssuerSeams(host);

        //The Issuer stores the by-reference offer the wallet will fetch and drive to issuance.
        CredentialOffer storedOffer = ComposeOffer(material);
        host.Server.OAuth().ResolveCredentialOfferAsync =
            (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                string.Equals(offerId, OfferId, StringComparison.Ordinal) ? storedOffer : null);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Uri offerEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredentialOffer);
        Uri credentialOfferUri = new($"{offerEndpoint}?{CredentialOfferParameterNames.Id}={OfferId}");
        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(credentialOfferUri);

        HttpClient httpClient = host.Host("default").SharedHttpClient!;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host, fetchCredentialOffer: (uri, ct) => FetchOfferAsync(httpClient, uri, ct));

        //§4.1.3: resolve the by-reference link to the offer (GET + parse), then drive issuance off
        //the fetched offer — the same call shape the by-value tests use.
        CredentialOffer fetchedOffer = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, TestContext.CancellationToken).ConfigureAwait(false);

        string issued = await walletClient.IssuePreAuthorizedAsync(
            fetchedOffer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(IssuedCredential, issued,
            "The fetched by-reference offer must drive issuance to the same credential as a composed offer.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof minted from the fetched offer.");
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString, observations.ProofAudience,
            "The fetched offer's credential_issuer must carry through as the proof aud.");
    }


    /// <summary>
    /// The detailed result surfaces every Credential of a §8.2 batch response and the §8.3
    /// <c>notification_id</c> — both of which the single-string overload drops.
    /// </summary>
    [TestMethod]
    public async Task DetailedResultSurfacesBatchCredentialsAndNotificationId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        WireIssuerSeams(host);

        const string NotificationId = "notif-batch-7Qm2";
        const string FirstCredential = "issued-credential-1";
        const string SecondCredential = "issued-credential-2";
        host.Server.OAuth().IssueCredentialAsync = (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue(
                [FirstCredential, SecondCredential], NotificationId));

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        CredentialIssuanceResult result = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsDeferred, "A direct issuance is not deferred.");
        Assert.HasCount(2, result.Credentials, "Both batch Credentials must be surfaced.");
        Assert.AreEqual(FirstCredential, result.Credentials[0]);
        Assert.AreEqual(SecondCredential, result.Credentials[1]);
        Assert.AreEqual(NotificationId, result.NotificationId, "The §8.3 notification_id must be surfaced.");
        Assert.IsFalse(string.IsNullOrEmpty(result.AccessToken), "The access token for follow-up legs must be carried.");
    }


    /// <summary>
    /// A §8.3 deferral (HTTP 202) surfaces as a deferred result carrying the <c>transaction_id</c> and
    /// <c>interval</c>; polling the §9 Deferred Credential Endpoint with that <c>transaction_id</c> then
    /// returns the issued Credential.
    /// </summary>
    [TestMethod]
    public async Task DeferredIssuanceThenPollReturnsCredential()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        WireIssuerSeams(host);

        const string TransactionId = "txn-deferred-7Qm2";
        const string NotificationId = "notif-deferred-7Qm2";
        host.Server.OAuth().IssueCredentialAsync = (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Defer(TransactionId, intervalSeconds: 5));
        host.Server.OAuth().ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
            ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential], NotificationId));

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        CredentialIssuanceResult deferred = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(deferred.IsDeferred, "An HTTP 202 deferral must surface as deferred.");
        Assert.AreEqual(TransactionId, deferred.TransactionId);
        Assert.AreEqual(5, deferred.DeferredIntervalSeconds, "The §8.3 interval must be surfaced.");
        Assert.IsEmpty(deferred.Credentials, "A deferral carries no Credentials yet.");

        CredentialIssuanceResult polled = await walletClient.PollDeferredCredentialAsync(
            deferred.TransactionId!,
            deferred.AccessToken,
            deferred.TokenType,
            ResolveDeferredEndpoint(host, material),
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(polled.IsDeferred, "The poll returned the ready Credential.");
        Assert.HasCount(1, polled.Credentials);
        Assert.AreEqual(IssuedCredential, polled.Credentials[0]);
        Assert.AreEqual(NotificationId, polled.NotificationId);
    }


    /// <summary>
    /// After issuance, the Wallet reports a §11 <c>credential_accepted</c> Notification with the
    /// <c>notification_id</c> the response carried; the Issuer's notification seam receives the matching
    /// id and event.
    /// </summary>
    [TestMethod]
    public async Task NotificationReportsCredentialAccepted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities);
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        WireIssuerSeams(host);

        const string NotificationId = "notif-accept-7Qm2";
        host.Server.OAuth().IssueCredentialAsync = (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential], NotificationId));

        CredentialNotification? observed = null;
        host.Server.OAuth().ProcessCredentialNotificationAsync = (notification, _, _, _, _) =>
        {
            observed = notification;

            return ValueTask.FromResult(CredentialNotificationDecision.Accept);
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        CredentialIssuanceResult result = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(NotificationId, result.NotificationId);

        await walletClient.SendCredentialNotificationAsync(
            result.NotificationId!,
            Oid4VciNotificationEvents.CredentialAccepted,
            result.AccessToken,
            result.TokenType,
            ResolveNotificationEndpoint(host, material),
            eventDescription: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(observed, "The Issuer's notification seam must have received the report.");
        Assert.AreEqual(NotificationId, observed!.NotificationId);
        Assert.AreEqual(Oid4VciNotificationEvents.CredentialAccepted, observed.Event);
    }


    /// <summary>Cross-step observations the issuer seams record for assertions.</summary>
    private sealed class IssuerSeamObservations
    {
        public bool IsProofVerified { get; set; }
        public string? ProofAudience { get; set; }
    }


    //Composes the §4 Credential Offer the Issuer hands the Wallet (by-value), carrying the
    //Pre-Authorized Code grant.
    private static CredentialOffer ComposeOffer(VerifierKeyMaterial material) =>
        new()
        {
            CredentialIssuer = material.Registration.IssuerUri!,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode
            }
        };


    //Resolves the Token / Nonce / Credential endpoint URLs against the started host's real
    //Kestrel base address using the fixture's /connect/{segment}/<suffix> URL shape.
    private static Oid4VciIssuanceEndpoints ResolveEndpoints(TestHostShell host, VerifierKeyMaterial material)
    {
        Uri baseUri = host.Host("default").HttpBaseAddress!;
        string segment = material.Registration.TenantId.Value;

        return new Oid4VciIssuanceEndpoints
        {
            TokenEndpoint = TestHostShell.ComposeEndpointUri(baseUri, segment, WellKnownEndpointNames.Oid4VciPreAuthorizedToken),
            NonceEndpoint = TestHostShell.ComposeEndpointUri(baseUri, segment, WellKnownEndpointNames.Oid4VciNonce),
            CredentialEndpoint = TestHostShell.ComposeEndpointUri(baseUri, segment, WellKnownEndpointNames.Oid4VciCredential)
        };
    }


    //Resolves the §9 Deferred Credential Endpoint URL against the started host's real Kestrel base
    //address using the fixture's /connect/{segment}/<suffix> URL shape.
    private static Uri ResolveDeferredEndpoint(TestHostShell host, VerifierKeyMaterial material) =>
        TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciDeferredCredential);


    //Resolves the §11 Notification Endpoint URL against the started host's real Kestrel base address.
    private static Uri ResolveNotificationEndpoint(TestHostShell host, VerifierKeyMaterial material) =>
        TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciNotification);


    //Builds the wallet client over HttpClient-backed transport delegates that close over the
    //started host's SharedHttpClient. The wallet library stays System.Net-free; the test
    //supplies the HTTP plumbing.
    private Oid4VciWalletClient BuildWalletClient(
        TestHostShell host,
        Oid4VciDecryptResponseDelegate? decryptResponse = null,
        Oid4VciEncryptRequestDelegate? encryptRequest = null,
        Oid4VciFetchCredentialOfferDelegate? fetchCredentialOffer = null)
    {
        HttpClient httpClient = host.Host("default").SharedHttpClient!;

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (endpoint, formFields, ct) => SendFormPostAsync(httpClient, endpoint, formFields, ct),
            SendJsonPost = (endpoint, body, headers, ct) => SendJsonPostAsync(httpClient, endpoint, body, headers, ct),
            FetchCredentialOffer = fetchCredentialOffer,
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            DecryptResponse = decryptResponse,
            EncryptRequest = encryptRequest
        };

        return new Oid4VciWalletClient(configuration);
    }


    //The wallet's §4.1.3 by-reference Credential Offer GET transport: a real HTTP GET over the
    //started host's SharedHttpClient. The library stays System.Net-free.
    private static async ValueTask<(int StatusCode, string Body)> FetchOfferAsync(
        HttpClient httpClient, Uri credentialOfferUri, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await httpClient.GetAsync(
            credentialOfferUri, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    //The wallet's §8.2 request-encryption seam: wraps the Credential Request body as a compact
    //JWE to the Issuer's published request-encryption key with real ECDH-ES + AES-GCM.
    private static async ValueTask<string> EncryptToIssuerAsync(
        string requestBody, PublicKeyMemory issuerPublic, CancellationToken cancellationToken)
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
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    //HttpClient form-POST transport for the §6 Token Request.
    private static async ValueTask<(int StatusCode, string Body)> SendFormPostAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyDictionary<string, string> formFields,
        CancellationToken cancellationToken)
    {
        using FormUrlEncodedContent content = new(formFields);
        using HttpResponseMessage response = await httpClient.PostAsync(
            endpoint, content, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    //HttpClient JSON-POST transport for the §7 Nonce and §8 Credential Requests, attaching the
    //wallet-composed authorization headers and surfacing the response Content-Type.
    private static async ValueTask<(int StatusCode, string Body, string? ContentType)> SendJsonPostAsync(
        HttpClient httpClient,
        Uri endpoint,
        string jsonBody,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint);

        //§7 Nonce Request carries no body; only the §8 Credential Request has one.
        if(jsonBody.Length > 0)
        {
            request.Content = new StringContent(jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        }
        else
        {
            request.Content = new ByteArrayContent([]);
        }

        foreach(KeyValuePair<string, string> header in headers)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        using HttpResponseMessage response = await httpClient.SendAsync(
            request, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string? contentType = response.Content.Headers.ContentType?.MediaType;

        return ((int)response.StatusCode, body, contentType);
    }


    //Wires the issuer seams with real work: pre-authorized-code validation, c_nonce minting,
    //and §8 issuance that verifies the holder proof signature + its c_nonce before issuing the
    //(opaque) credential.
    private static IssuerSeamObservations WireIssuerSeams(TestHostShell host)
    {
        IssuerSeamObservations observations = new();
        string? mintedNonce = null;

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync = (code, txCode, clientId, _, _, _) =>
            ValueTask.FromResult(string.Equals(code, PreAuthorizedCode, StringComparison.Ordinal)
                ? PreAuthorizedCodeDecision.Grant(EndUserSubject, WellKnownScopes.OpenId)
                : PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode));

        host.Server.OAuth().IssueCredentialNonceAsync = (_, _) =>
        {
            mintedNonce = $"c-nonce-{Guid.NewGuid():N}";

            return ValueTask.FromResult(mintedNonce);
        };

        host.Server.OAuth().IssueCredentialAsync = async (request, _, _, _, ct) =>
        {
            string proof = request.Proofs[Oid4VciCredentialParameterNames.JwtProofType][0];
            (PublicKeyMemory proofKey, string? proofNonce, string? proofAudience) = ReadProof(proof);

            using(proofKey)
            {
                bool isProofSignatureValid = await Jws.VerifyAsync(
                    proof, TestSetup.Base64UrlDecoder,
                    Pool,
                    proofKey, ct).ConfigureAwait(false);

                if(!isProofSignatureValid
                    || mintedNonce is null
                    || !string.Equals(proofNonce, mintedNonce, StringComparison.Ordinal))
                {
                    return CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidProof);
                }

                observations.IsProofVerified = true;
                observations.ProofAudience = proofAudience;

                return CredentialIssuanceDecision.Issue([IssuedCredential]);
            }
        };

        return observations;
    }


    //Wires the issuer's §10 response-encryption seam with real ECDH-ES + AES-GCM, reconstructing
    //the recipient key from the request's jwk.
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
                cancellationToken: ct).ConfigureAwait(false);
        };
    }


    //The wallet's §10 decrypt drop-out: opens a compact JWE with the response private key.
    private static async ValueTask<string> DecryptAsync(
        string compactJwe, PrivateKeyMemory recipientPrivate, CancellationToken cancellationToken)
    {
        string headerSegment = compactJwe[..compactJwe.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerSegment, Pool);
        string? enc = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "enc"u8);
        Assert.IsNotNull(enc, "JWE protected header must carry 'enc'.");

        using AeadMessage parsedJwe = JweParsing.ParseCompact(
            compactJwe, WellKnownJweAlgorithms.EcdhEs, enc!, TestSetup.Base64UrlDecoder, Pool);
        using DecryptedContent decrypted = await parsedJwe.DecryptAsync(
            recipientPrivate,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return Encoding.UTF8.GetString(decrypted.AsReadOnlySpan());
    }


    //Reads the holder key (header jwk), nonce, and aud off a proof JWT.
    private static (PublicKeyMemory ProofKey, string? Nonce, string? Audience) ReadProof(string proofJwt)
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
        ReadOnlySpan<byte> payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        string? nonce = JwkJsonReader.ExtractStringValue(payloadBytes, "nonce"u8);
        string? audience = JwkJsonReader.ExtractStringValue(payloadBytes, "aud"u8);

        return (proofKey, nonce, audience);
    }


    private static Dictionary<string, object> EcJwkMembers(PublicKeyMemory recipientPublic)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            recipientPublic.Tag.Get<CryptoAlgorithm>(),
            recipientPublic.Tag.Get<Purpose>(),
            recipientPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
            [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
            [WellKnownJwkMemberNames.X] = jwk.X!,
            [WellKnownJwkMemberNames.Y] = jwk.Y!,
            [WellKnownJwkMemberNames.Alg] = WellKnownJweAlgorithms.EcdhEs
        };
    }


    private static string DecodeSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);

        return Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');
    }
}
