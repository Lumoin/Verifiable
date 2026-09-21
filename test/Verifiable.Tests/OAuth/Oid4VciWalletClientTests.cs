using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
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

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string ConfigurationId = "eu.europa.ec.eudi.pid.1";
    private const string PreAuthorizedCode = "SplxlOBeZQQYbYS6WxSbIA";
    private const string EndUserSubject = "urn:uuid:end-user-42";
    private const string IssuedCredential = "issued-credential-opaque-42";

    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    private static ImmutableHashSet<CapabilityIdentifier> IssuerCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    //Mints the DPoP proof's jti the same way the AuthCode fixtures do — the library default bound
    //to this fixture's own clock, entropy, and pool — whenever a test wires a DpopKey.
    private GenerateIdentifierDelegate DpopJtiGenerator =>
        DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), Pool);


    /// <summary>
    /// Pre-Authorized Code → plain Bearer → plaintext response: the wallet client drives §6/§7/§8
    /// over a real socket and returns the issued Credential, and the issuer seam confirms it
    /// verified the holder proof signature and its c_nonce.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverPlainBearerAndPlaintextResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The issuance must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value,
            "The wallet client must return the credential the Issuer minted over the wire.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString, observations.ProofAudience,
            "The minted proof must carry the Credential Issuer identifier as aud.");
    }


    /// <summary>
    /// §6.3: a Pre-Authorized Code Token Request the hosted Issuer refuses over the real wire
    /// answers the Issuer's own <c>invalid_grant</c> error as a value, rather than throwing. The
    /// Issuer's <see cref="ValidatePreAuthorizedCodeDelegate"/> seam denies the wrong code with
    /// <see cref="PreAuthorizedCodeDenialReason.InvalidCode"/>, which the library maps to
    /// <see cref="OAuthErrors.InvalidGrant"/>.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestRefusedOverRealWireAnswersTheIssuersOwnErrorValueAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        CredentialOffer offer = new()
        {
            CredentialIssuer = material.Registration.IssuerUri!,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = "wrong-pre-authorized-code" }
        };
        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "The wrong pre-authorized code must be a refusal over the real wire.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidGrant, outcome.Error.ErrorCode,
            "The hosted Issuer's own §6.3 mapping of InvalidCode must ride the failure value verbatim.");
    }


    /// <summary>
    /// Pre-Authorized Code → DPoP-bound token → plaintext response, over real Kestrel HTTP, with
    /// the wallet's DPoP wired (<see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>,
    /// <see cref="Oid4VciWalletConfiguration.DpopKey"/>,
    /// <see cref="Oid4VciWalletConfiguration.GenerateIdentifierAsync"/>). A HAIP 1.0 registration
    /// mandates DPoP, so the Issuer challenges the wallet's first §6 Token Request with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>
    /// <c>use_dpop_nonce</c>; the wallet's own retry (already exercised in-process by
    /// <see cref="TokenRequestRetriesOnceOnUseDpopNonceChallengeAndUsesTheSecondAnswer"/>) must
    /// complete it end to end against the real Issuer without the code-validation seam being
    /// consulted on the challenged attempt — proven here by the seam being consulted exactly once
    /// despite the two dials the retry makes.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverDpopBoundTokenWithNonceRetryOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        int preAuthorizedSeamInvocations = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ValidatePreAuthorizedCodeDelegate original = candidateIntegration.ValidatePreAuthorizedCodeAsync!;
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    preAuthorizedSeamInvocations++;

                    return original(code, txCode, clientId, registration, context, ct);
                };

            //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; the seam's
            //granted openid scope is dropped by RFC 6749 §3.3 narrowing before it ever reaches
            //ClientRecord.ScopeToAudience. Fixed resource-server audience, matching the one
            //ScopeToAudience already carries.
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey walletDpopKey = new(walletDpopKeys, WellKnownJwaValues.Es256);

        static ValueTask<string> ConstructWalletDpopProofAsync(
            DpopProofClaims claims, DpopKey key, CancellationToken ct) =>
            DpopProofConstruction.BuildAsync(
                claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, Pool, ct);

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host, constructDpopProofAsync: ConstructWalletDpopProofAsync, dpopKey: walletDpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resultOutcome.IsSuccess, "The issuance must succeed over the wire.");
        CredentialIssuanceResult result = resultOutcome.Value;

        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, result.TokenType,
            "RFC 9449 §5 binds this grant's access token the same way it binds every other grant's; a HAIP 1.0 registration mandates it.");
        Assert.IsTrue(result.IsIssued, "The Credential Request must succeed once presented with a proof for the bound token.");
        Assert.AreEqual(IssuedCredential, result.Credentials[0],
            "The wallet client must return the credential the Issuer minted, having completed the RFC 9449 §8 nonce-challenge retry on the token endpoint.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(1, preAuthorizedSeamInvocations,
            "The nonce-challenged first token attempt must never consult the code-validation seam — only the successful retry does, despite two dials.");
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
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
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, requestPrivate, ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

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

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The encrypted-response issuance must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value,
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        //The Issuer stores the by-reference offer the wallet will fetch and drive to issuance.
        CredentialOffer storedOffer = ComposeOffer(material);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialOfferAsync =
                (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                    string.Equals(offerId, OfferId, StringComparison.Ordinal) ? storedOffer : null);
        }).ConfigureAwait(false);

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
            host, fetchCredentialOffer: GuardedHttpClientTransport.BuildSingleHopTransport(httpClient));

        //§4.1.3: resolve the by-reference link to the offer (GET + parse), then drive issuance off
        //the fetched offer — the same call shape the by-value tests use.
        Result<CredentialOffer, Oid4VciRequestFailure> fetchedOfferOutcome = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(fetchedOfferOutcome.IsSuccess, "The by-reference offer fetch must succeed over the wire.");

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            fetchedOfferOutcome.Value,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The issuance driven off the fetched offer must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value,
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        const string NotificationId = "notif-batch-7Qm2";
        const string FirstCredential = "issued-credential-1";
        const string SecondCredential = "issued-credential-2";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue(
                    [FirstCredential, SecondCredential], NotificationId));
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resultOutcome.IsSuccess, "The batch issuance must succeed over the wire.");
        CredentialIssuanceResult result = resultOutcome.Value;

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        const string TransactionId = "txn-deferred-7Qm2";
        const string NotificationId = "notif-deferred-7Qm2";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Defer(TransactionId, intervalSeconds: 5));

            candidateIntegration.ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential], NotificationId));
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> deferredOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(deferredOutcome.IsSuccess, "The deferred issuance must succeed over the wire.");
        CredentialIssuanceResult deferred = deferredOutcome.Value;

        Assert.IsTrue(deferred.IsDeferred, "An HTTP 202 deferral must surface as deferred.");
        Assert.AreEqual(TransactionId, deferred.TransactionId);
        Assert.AreEqual(5, deferred.DeferredIntervalSeconds, "The §8.3 interval must be surfaced.");
        Assert.IsEmpty(deferred.Credentials, "A deferral carries no Credentials yet.");

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            deferred.TransactionId!,
            deferred.AccessToken,
            deferred.TokenType,
            deferred.ExpiresAt,
            ResolveDeferredEndpoint(host, material),
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pollResult.IsSuccess, "The ready poll must succeed, not refuse.");
        CredentialIssuanceResult polled = pollResult.Value;
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        const string NotificationId = "notif-accept-7Qm2";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential], NotificationId));
        }).ConfigureAwait(false);

        CredentialNotification? observed = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ProcessCredentialNotificationAsync = (notification, _, _, _, _) =>
            {
                observed = notification;

                return ValueTask.FromResult(CredentialNotificationDecision.Accept);
            };
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resultOutcome.IsSuccess, "The issuance must succeed over the wire.");
        CredentialIssuanceResult result = resultOutcome.Value;

        Assert.AreEqual(NotificationId, result.NotificationId);

        Oid4VciRequestFailure? notificationFailure = await walletClient.SendCredentialNotificationAsync(
            result.NotificationId!,
            Oid4VciNotificationEvents.CredentialAccepted,
            result.AccessToken,
            result.TokenType,
            ResolveNotificationEndpoint(host, material),
            eventDescription: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(notificationFailure, "The Issuer must acknowledge the notification (§11.2 HTTP 204).");
        Assert.IsNotNull(observed, "The Issuer's notification seam must have received the report.");
        Assert.AreEqual(NotificationId, observed!.NotificationId);
        Assert.AreEqual(Oid4VciNotificationEvents.CredentialAccepted, observed.Event);
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>: "the endpoints a client POSTs to ... are themselves taken
    /// from discovered metadata, so a malicious or misconfigured metadata document could point
    /// them at an internal, loopback, or cloud-metadata address ... The OutboundFetchPolicy must
    /// therefore gate every method." A §4.1.3 <c>credential_offer_uri</c> naming a loopback address
    /// is refused before the GET is ever sent.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetRefusesLoopbackCredentialOfferUri()
    {
        List<Uri> invocations = [];
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
            {
                invocations.Add(request.Target);
                throw new InvalidOperationException("The offer GET must never be dialed once the policy denies it.");
            });

        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(new Uri("https://127.0.0.1/credential-offer"));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback credential_offer_uri under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies credential_offer_uri.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies to §12.2 metadata's
    /// <c>credential_endpoint</c>: a loopback address is refused before the §8 Credential Request
    /// is ever sent, even though the preceding §7 Nonce Request (a benign endpoint) already
    /// succeeded.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRefusesLoopbackCredentialEndpointBeforeAnyDial()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://127.0.0.1/credential");
        List<Uri> jsonPostInvocations = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPostInvocations.Add(endpoint);

                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"nonce-value\"}"));
                }

                throw new InvalidOperationException("The credential request must never be dialed once the policy denies it.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("https://issuer.example.com/token"),
                NonceEndpoint = nonceEndpoint,
                CredentialEndpoint = credentialEndpoint
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback credential_endpoint under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.HasCount(1, jsonPostInvocations, "Only the benign §7 Nonce Request may reach the transport; the §8 Credential Request must not.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies to §12.2 metadata's
    /// <c>nonce_endpoint</c>: a loopback address is refused before the §7 Nonce Request is ever
    /// sent.
    /// </summary>
    [TestMethod]
    public async Task NonceRequestRefusesLoopbackNonceEndpointBeforeAnyDial()
    {
        List<Uri> jsonPostInvocations = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPostInvocations.Add(endpoint);
                throw new InvalidOperationException("The nonce request must never be dialed once the policy denies it.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("https://issuer.example.com/token"),
                NonceEndpoint = new Uri("https://127.0.0.1/nonce"),
                CredentialEndpoint = new Uri("https://issuer.example.com/credential")
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback nonce_endpoint under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.IsEmpty(jsonPostInvocations, "The transport spy must record ZERO invocations when the policy denies nonce_endpoint.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies to a §9
    /// <c>deferred_credential_endpoint</c> carried over from a prior deferral: a loopback address
    /// is refused before the §9 poll is ever sent.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollRefusesLoopbackDeferredCredentialEndpointBeforeAnyDial()
    {
        List<Uri> jsonPostInvocations = [];
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPostInvocations.Add(endpoint);
                throw new InvalidOperationException("The deferred poll must never be dialed once the policy denies it.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.PollDeferredCredentialAsync(
            "txn-loopback",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://127.0.0.1/deferred"),
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback deferred_credential_endpoint under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.IsEmpty(jsonPostInvocations, "The transport spy must record ZERO invocations when the policy denies deferred_credential_endpoint.");
    }


    /// <summary>
    /// RFC 9449 §5: "the client MUST provide a valid DPoP proof JWT in a DPoP header when making an
    /// access token request ... applicable for all access token requests regardless of grant type."
    /// The §6 Pre-Authorized Code Token Request carries a <c>DPoP</c> header bound to the token
    /// endpoint (<c>htm=POST</c>, <c>htu=</c> the token endpoint) when the configuration carries a
    /// DPoP key, and no <c>DPoP</c> header at all when it does not.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestCarriesDpopHeaderWhenKeyConfiguredAndNoneWhenAbsent()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        string? capturedProofHeader = null;
        string? capturedHtm = null;
        string? capturedHtu = null;

        Oid4VciWalletClient dpopClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, headers, _, _) =>
            {
                _ = headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out capturedProofHeader);

                return ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok-dpop\",\"token_type\":\"DPoP\"}"));
            },
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint),
            constructDpopProofAsync: (claims, _, _) =>
            {
                //Nonce and Credential proofs are minted too; only the §6 Token Request's proof is
                //under test here, identified by its htu.
                if(claims.Htu == tokenEndpoint.GetLeftPart(UriPartial.Path))
                {
                    capturedHtm = claims.Htm;
                    capturedHtu = claims.Htu;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        _ = await IssueViaTokenEndpointAsync(dpopClient, tokenEndpoint, nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.AreEqual("fake-dpop-proof", capturedProofHeader, "A configured DPoP key must attach a DPoP header to the §6 Token Request.");
        Assert.AreEqual(WellKnownHttpMethods.Post, capturedHtm, "The proof's htm claim must be POST.");
        Assert.AreEqual(tokenEndpoint.GetLeftPart(UriPartial.Path), capturedHtu, "The proof's htu claim must be bound to the token endpoint.");

        string? capturedHeaderWithoutDpop = "not-yet-called";
        Oid4VciWalletClient bearerClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, headers, _, _) =>
            {
                capturedHeaderWithoutDpop = headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out string? proof) ? proof : null;

                return ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok-bearer\",\"token_type\":\"Bearer\"}"));
            },
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint));

        _ = await IssueViaTokenEndpointAsync(bearerClient, tokenEndpoint, nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsNull(capturedHeaderWithoutDpop, "No DPoP key configured must mean no DPoP header on the §6 Token Request.");
    }


    /// <summary>
    /// RFC 9449 §8.1: a token endpoint answering <c>use_dpop_nonce</c> with a <c>DPoP-Nonce</c>
    /// header is retried exactly once with the nonce embedded in a fresh proof, and the retry's
    /// answer is used.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestRetriesOnceOnUseDpopNonceChallengeAndUsesTheSecondAnswer()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int formPostInvocations = 0;
        string? secondProofNonceClaim = null;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, headers, _, _) =>
            {
                formPostInvocations++;

                return formPostInvocations == 1
                    ? ValueTask.FromResult(JsonResponse(
                        400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, "as-nonce-1")))
                    : ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}"));
            },
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint),
            constructDpopProofAsync: (claims, _, _) =>
            {
                if(formPostInvocations == 1)
                {
                    secondProofNonceClaim = claims.Nonce;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, nonceEndpoint, credentialEndpoint).ConfigureAwait(false);

        Assert.AreEqual(2, formPostInvocations, "Exactly one retry: the token endpoint must be dialed twice, not three times.");
        Assert.AreEqual("as-nonce-1", secondProofNonceClaim, "The retry's proof must embed the nonce the first challenge supplied.");
        Assert.IsTrue(outcome.IsSuccess, "The retried token request must succeed.");
        Assert.IsFalse(outcome.Value.IsDeferred);
    }


    /// <summary>
    /// RFC 6749 §5.2: a second <c>use_dpop_nonce</c> challenge after the one allowed retry answers
    /// the §6.3 Token Error Response value — never a third request.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestFailsOnSecondUseDpopNonceChallengeRatherThanRetryingAgain()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int formPostInvocations = 0;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
            {
                formPostInvocations++;

                return ValueTask.FromResult(JsonResponse(
                    400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, $"as-nonce-{formPostInvocations}")));
            },
            constructDpopProofAsync: (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, tokenEndpoint, tokenEndpoint).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, outcome.Error.ErrorCode);
        Assert.AreEqual(2, formPostInvocations, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
    }


    /// <summary>
    /// RFC 9449 §5's sender-constraining obligation binds <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>
    /// and <see cref="Oid4VciWalletConfiguration.DpopKey"/> together: a configuration wiring the proof
    /// constructor without the signing key is refused at construction rather than silently degrading
    /// to a plain Bearer request.
    /// </summary>
    [TestMethod]
    public void ConstructWithDpopProofConstructorButNoDpopKeyThrows()
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            ConstructDpopProofAsync = (_, _, _) => ValueTask.FromResult("fake-dpop-proof")
        };

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Oid4VciWalletClient(configuration));

        Assert.Contains(nameof(Oid4VciWalletConfiguration.DpopKey), error.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9449 §5's sender-constraining obligation binds <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>
    /// and <see cref="Oid4VciWalletConfiguration.DpopKey"/> together: a configuration wiring the
    /// signing key without the proof constructor is refused at construction rather than silently
    /// degrading to a plain Bearer request.
    /// </summary>
    [TestMethod]
    public void ConstructWithDpopKeyButNoProofConstructorThrows()
    {
        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            DpopKey = dpopKey
        };

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Oid4VciWalletClient(configuration));

        Assert.Contains(nameof(Oid4VciWalletConfiguration.ConstructDpopProofAsync), error.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9449 §5's sender-constraining obligation binds <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>,
    /// <see cref="Oid4VciWalletConfiguration.DpopKey"/>, and
    /// <see cref="Oid4VciWalletConfiguration.GenerateIdentifierAsync"/> together: a configuration
    /// wiring the proof constructor and the signing key without the jti generator is refused at
    /// construction rather than silently degrading to a plain Bearer request.
    /// </summary>
    [TestMethod]
    public void ConstructWithDpopKeyAndProofConstructorButNoGeneratorThrows()
    {
        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            ConstructDpopProofAsync = (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            DpopKey = dpopKey
        };

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Oid4VciWalletClient(configuration));

        Assert.Contains(nameof(Oid4VciWalletConfiguration.GenerateIdentifierAsync), error.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9449 §9: the Credential Endpoint's own <c>use_dpop_nonce</c> challenge (this Issuer's
    /// wire shape: HTTP 400 with the error in the JSON body, the same shape the §6 Token Endpoint
    /// uses) is retried exactly once with the nonce embedded in a fresh proof.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRetriesOnceOnUseDpopNonceChallengeAndUsesTheSecondAnswer()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int credentialInvocations = 0;
        string? secondProofNonceClaim = null;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}")),
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"));
                }

                credentialInvocations++;

                return credentialInvocations == 1
                    ? ValueTask.FromResult(JsonResponse(
                        400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, "rs-nonce-1")))
                    : ValueTask.FromResult(JsonResponse(200, "{\"credentials\":[{\"credential\":\"cred-after-retry\"}]}"));
            },
            constructDpopProofAsync: (claims, _, _) =>
            {
                if(credentialInvocations == 1 && claims.Htu == credentialEndpoint.GetLeftPart(UriPartial.Path))
                {
                    secondProofNonceClaim = claims.Nonce;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.AreEqual(2, credentialInvocations, "Exactly one retry: the credential endpoint must be dialed twice, not three times.");
        Assert.AreEqual("rs-nonce-1", secondProofNonceClaim, "The retry's proof must embed the nonce the first challenge supplied.");
        Assert.IsTrue(outcome.IsSuccess, "The retried credential request must succeed.");
        Assert.AreEqual("cred-after-retry", outcome.Value.Credentials[0]);
    }


    /// <summary>
    /// The §8.3.1 Credential Error Response shape: a second §9 <c>use_dpop_nonce</c> challenge at
    /// the Credential Endpoint after the one allowed retry answers the failure value — never a
    /// third request.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestFailsOnSecondUseDpopNonceChallengeRatherThanRetryingAgain()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int credentialInvocations = 0;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}")),
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"));
                }

                credentialInvocations++;

                return ValueTask.FromResult(JsonResponse(
                    400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, $"rs-nonce-{credentialInvocations}")));
            },
            constructDpopProofAsync: (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, outcome.Error.ErrorCode);
        Assert.AreEqual(2, credentialInvocations, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
    }


    /// <summary>
    /// RFC 6749 §5.2 / OID4VCI §6.3: a refused Pre-Authorized Code Token Request answers the
    /// <c>invalid_grant</c> Token Error Response as a value carrying the status and wire code.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_grant\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, tokenEndpoint, tokenEndpoint).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A refused Token Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidGrant, outcome.Error.ErrorCode);
        Assert.AreEqual(tokenEndpoint, outcome.Error.Endpoint);
    }


    /// <summary>
    /// §6: a Token Response repeating <c>access_token</c> breaks the RFC 7519-style uniqueness
    /// posture this Wallet applies to a fetched JSON document; it answers MalformedResponse naming
    /// the rule rather than a value.
    /// </summary>
    [TestMethod]
    public async Task TokenResponseRepeatingAccessTokenAnswersMalformedResponse()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(
                    200, "{\"access_token\":\"tok-1\",\"access_token\":\"tok-2\",\"token_type\":\"Bearer\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, tokenEndpoint, tokenEndpoint).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated access_token member must be malformed, not a value.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.IsNull(outcome.Error.ErrorCode);
        Assert.Contains("duplicate member", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §7.1: a refused Nonce Request answers the endpoint's own error value — the status and
    /// whatever <c>error</c> the body carried — rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task NonceRequestRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(401, "{\"error\":\"invalid_token\"}"))
                : throw new InvalidOperationException("The credential request must never be dialed once the nonce request is refused."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A refused Nonce Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(401, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidToken, outcome.Error.ErrorCode);
    }


    /// <summary>
    /// §7.2: a Nonce Response carrying no REQUIRED <c>c_nonce</c> answers MalformedResponse naming
    /// the rule rather than a value.
    /// </summary>
    [TestMethod]
    public async Task NonceResponseWithoutCNonceAnswersMalformedResponse()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{}"))
                : throw new InvalidOperationException("The credential request must never be dialed once the nonce response is malformed."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A Nonce Response carrying no c_nonce must be malformed, not a value.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("c_nonce", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §8.3.1.2: a refused Credential Request answers the <c>invalid_proof</c> Credential Error
    /// Response as a value carrying the status and wire code.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"))
                : ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_proof\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A refused Credential Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidProof, outcome.Error.ErrorCode);
    }


    /// <summary>
    /// §8.3: a Credential Response carrying an empty <c>credentials</c> array answers
    /// MalformedResponse naming the rule rather than a value.
    /// </summary>
    [TestMethod]
    public async Task CredentialResponseWithEmptyCredentialsArrayAnswersMalformedResponse()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"))
                : ValueTask.FromResult(JsonResponse(200, "{\"credentials\":[]}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "An empty credentials[] array must be malformed, not a value.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("credentials", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.3">§11.3</see>:
    /// "invalid_notification_id: The notification_id in the Notification Request was invalid." A
    /// refused Notification Request answers the value rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task NotificationRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_notification_id\"}")));

        Oid4VciRequestFailure? failure = await walletClient.SendCredentialNotificationAsync(
            "notif-unknown",
            Oid4VciNotificationEvents.CredentialAccepted,
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            new Uri("https://issuer.example.com/notification"),
            eventDescription: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(failure, "invalid_notification_id must answer a failure, not null.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, failure.Kind);
        Assert.AreEqual(400, failure.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidNotificationId, failure.ErrorCode);
    }


    /// <summary>
    /// §9.2: a Deferred Credential Endpoint still assembling the Credential answers HTTP 202, and
    /// the poll surfaces it as a deferred, not-yet-ready result rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollStillPendingReturnsDeferredOutcomeWithoutThrowing()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(202, "{\"transaction_id\":\"txn-1\",\"interval\":5}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            "txn-1",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com/deferred"),
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pollResult.IsSuccess, "A still-pending 202 must not be a refusal.");
        Assert.IsTrue(pollResult.Value.IsDeferred, "The still-pending poll must surface as deferred.");
        Assert.AreEqual("txn-1", pollResult.Value.TransactionId);
    }


    /// <summary>
    /// §9.3: a Deferred Credential Request presenting a <c>transaction_id</c> the Issuer does not
    /// recognise answers <c>invalid_transaction_id</c> as a value — <see cref="Oid4VciRequestFailure"/>
    /// — rather than an exception.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollInvalidTransactionIdReturnsRefusalWithoutThrowing()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_transaction_id\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            "txn-unknown",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com/deferred"),
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(pollResult.IsSuccess, "invalid_transaction_id must be a refusal, not a success.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, pollResult.Error.Kind);
        Assert.AreEqual(400, pollResult.Error.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidTransactionId, pollResult.Error.ErrorCode);
    }


    /// <summary>
    /// <see cref="CredentialIssuanceResult.ExpiresAt"/> is the §6 Token Response's <c>expires_in</c>
    /// added to the instant the Wallet sent the Token Request, and <see langword="null"/> when the
    /// response carried no <c>expires_in</c>.
    /// </summary>
    [TestMethod]
    public async Task ExpiresAtEqualsRequestedAtPlusExpiresInWhenPresentAndIsNullWhenAbsent()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient withExpiry = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600}")),
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> withExpiryOutcome = await IssueViaTokenEndpointAsync(
            withExpiry, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsTrue(withExpiryOutcome.IsSuccess);
        Assert.AreEqual(TimeProvider.GetUtcNow().AddSeconds(3600), withExpiryOutcome.Value.ExpiresAt);

        Oid4VciWalletClient withoutExpiry = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> withoutExpiryOutcome = await IssueViaTokenEndpointAsync(
            withoutExpiry, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsTrue(withoutExpiryOutcome.IsSuccess);
        Assert.IsNull(withoutExpiryOutcome.Value.ExpiresAt);
    }


    //Drives IssueWithAccessTokenDetailedAsync's sibling — the grant-based overload — far enough to
    //exercise the §6 Token Request through to a §8 Credential Response, over the in-process spy
    //delegates, so a token-step assertion can run without a live host.
    private async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> IssueViaTokenEndpointAsync(
        Oid4VciWalletClient walletClient, Uri tokenEndpoint, Uri nonceEndpoint, Uri credentialEndpoint,
        CredentialResponseEncryption? responseEncryption = null)
    {
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        return await walletClient.IssuePreAuthorizedDetailedAsync(
            new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = PreAuthorizedCode },
            new Uri("https://issuer.example.com"),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = tokenEndpoint,
                NonceEndpoint = nonceEndpoint,
                CredentialEndpoint = credentialEndpoint
            },
            transactionCode: null,
            responseEncryption,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //A §7/§8 JSON-POST spy: the first call (the Nonce Request, empty body) answers c_nonce; every
    //other call (the Credential Request) answers one issued credential.
    private static Oid4VciJsonPostDelegate CredentialFlowStub(Uri nonceEndpoint, Uri credentialEndpoint) =>
        (endpoint, _, _, _, _) => ValueTask.FromResult(endpoint == nonceEndpoint
            ? JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}")
            : JsonResponse(200, "{\"credentials\":[{\"credential\":\"issued-credential\"}]}"));


    /// <summary>
    /// <see cref="Oid4VciWalletConfiguration.OutboundFetchPolicy"/> governs a §4.1.3 by-reference
    /// GET whose <see cref="ExchangeContext"/> carries no policy: a loopback
    /// <c>credential_offer_uri</c> refuses under the configuration's default and dials once the
    /// configuration names a loopback-allowing policy.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetConsultsConfigurationPolicyWhenContextCarriesNone()
    {
        Uri loopbackOfferUri = new("https://127.0.0.1/credential-offer");
        OutboundFetchPolicy loopbackAllowing = OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false };

        Oid4VciWalletClient deniedClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                throw new InvalidOperationException("The offer GET must never be dialed once the policy denies it."));

        Result<CredentialOffer, Oid4VciRequestFailure> denial = await deniedClient.FetchCredentialOfferAsync(
            loopbackOfferUri, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(denial.IsSuccess, "A loopback credential_offer_uri under the configuration's secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, denial.Error.Kind);

        CredentialOffer minimalOffer = new()
        {
            CredentialIssuer = new Uri("https://issuer.example.com"),
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = "pre-authorized-code" }
        };
        string offerJson = CredentialOfferSerializer.ToJson(minimalOffer);

        Oid4VciWalletClient allowedClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) => ValueTask.FromResult(JsonOfferResponse(offerJson)),
            outboundFetchPolicy: loopbackAllowing);

        Result<CredentialOffer, Oid4VciRequestFailure> allowed = await allowedClient.FetchCredentialOfferAsync(
            loopbackOfferUri, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(allowed.IsSuccess, "A loopback-allowing configuration policy must let the GET dial.");
        Assert.IsNotNull(allowed.Value);
    }


    /// <summary>
    /// A policy set explicitly on the call's <see cref="ExchangeContext"/> overrides
    /// <see cref="Oid4VciWalletConfiguration.OutboundFetchPolicy"/>: a configuration that allows
    /// loopback still refuses when the per-call context names the stricter secure default.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetContextPolicyOverridesConfigurationPolicy()
    {
        Uri loopbackOfferUri = new("https://127.0.0.1/credential-offer");
        OutboundFetchPolicy loopbackAllowing = OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false };

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                throw new InvalidOperationException("The offer GET must never be dialed once the policy denies it."),
            outboundFetchPolicy: loopbackAllowing);

        ExchangeContext strictContext = [];
        strictContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            loopbackOfferUri, strictContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "The stricter per-call context policy must override the loopback-allowing configuration default.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
    }


    /// <summary>
    /// <see cref="OutboundFetchPolicy.SecureDefault"/>'s <see cref="OutboundFetchPolicy.Redirects"/>
    /// is <see cref="RedirectMode.None"/>. A §4.1.3 offer GET whose first hop answers a redirect is
    /// refused rather than followed: the guarded <see cref="OutboundFetch"/> chokepoint stops at the
    /// first hop, so the transport spy is invoked exactly once.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetDoesNotFollowRedirectUnderSecureDefault()
    {
        int invocationCount = 0;
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
            {
                invocationCount++;
                return ValueTask.FromResult(new OutboundResponse
                {
                    StatusCode = 302,
                    Headers = HttpHeaderSet.FromPairs(
                        (WellKnownHttpHeaderNames.Location, "https://elsewhere.example.com/credential-offer"))
                });
            });

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A redirect under the secure default's RedirectMode.None must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No terminal response was fetched; the redirect was refused, not followed.");
        Assert.AreEqual(1, invocationCount,
            "The transport spy must be invoked for the first hop only — the redirect is refused, not followed.");
    }


    /// <summary>
    /// The authoritative post-read size check in
    /// <see cref="Oid4VciWalletClient.FetchCredentialOfferAsync"/> rejects a response exceeding
    /// <see cref="Oid4VciWalletConfiguration.MaximumCredentialOfferBytes"/> even when the transport
    /// disregards the <see cref="OutboundRequest.MaxResponseBytes"/> hint and returns the full,
    /// oversize body — the same defense
    /// <see cref="AuthorizationServerMetadataDocuments.ResolveAsync"/> applies to its own
    /// document fetch.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetRefusesOversizeBody()
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No §6 Token Request is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No §7/§8/§9 request is expected in this test."),
            FetchCredentialOffer = (request, _, _) => ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = 200,
                Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, "application/json")),
                Body = new TaggedMemory<byte>(new byte[128], Tag.Empty)
            }),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            MaximumCredentialOfferBytes = 64
        };
        Oid4VciWalletClient walletClient = new(configuration);

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A body exceeding MaximumCredentialOfferBytes must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode, "The size check runs after a 200 was received.");
        Assert.Contains("maximum size", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.3 defines no error body for the Credential Offer GET; a non-<c>200</c> status still
    /// answers ErrorResponse but with no wire error code.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetNotFoundAnswersErrorResponseWithNullCode()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(new OutboundResponse { StatusCode = 404 }));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A 404 Credential Offer GET must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(404, outcome.Error.StatusCode);
        Assert.IsNull(outcome.Error.ErrorCode, "§4.1.3 defines no error body for this GET.");
    }


    /// <summary>
    /// §4.1.3: the by-reference GET answers <c>200</c> with <c>application/json</c>, but the body
    /// is not well-formed JSON — remote input, so it answers MalformedResponse naming the rule
    /// rather than throwing the <see cref="ArgumentException"/> <see cref="CredentialOfferSerializer.FromJson"/>
    /// raises for a caller-supplied offer.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithNonJsonBodyAnswersMalformedResponseNamingTheRule()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(JsonOfferResponse("not-a-json-object")));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A by-reference offer body that is not well-formed JSON must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("well-formed JSON", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.1: <c>credential_issuer</c> is REQUIRED. A by-reference offer body that is well-formed
    /// JSON but carries none is remote input, so it answers MalformedResponse naming the rule
    /// rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithNoCredentialIssuerAnswersMalformedResponseNamingTheRule()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(JsonOfferResponse(
                    "{\"credential_configuration_ids\":[\"" + ConfigurationId + "\"]}")));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A by-reference offer carrying no credential_issuer must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("credential_issuer", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.1: <c>credential_issuer</c> is "The URL of the Credential Issuer". A by-reference offer
    /// body whose <c>credential_issuer</c> is not a URI reference at all (a scheme with no
    /// authority) answers MalformedResponse naming the member; the body is what the remote party
    /// sent, so no exception leaves the fetch.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithUnparseableCredentialIssuerAnswersMalformedResponseNamingTheRule()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(JsonOfferResponse(
                    "{\"credential_issuer\":\"http://\",\"credential_configuration_ids\":[\"" + ConfigurationId + "\"]}")));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A by-reference offer whose credential_issuer is not a URL must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("credential_issuer", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.3: "The response from the Credential Issuer that contains a Credential Offer Object MUST
    /// use the media type application/json." A response answered with a different media type is
    /// refused.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithWrongContentTypeAnswersMalformedResponse()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(OfferResponseWithContentType(MinimalOfferJson(), "text/html")));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "§4.1.3: a response content type other than application/json must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("text/html", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>A 200 response carrying no Content-Type header is refused the same way a wrong one is.</summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithNoContentTypeHeaderAnswersMalformedResponse()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(OfferResponseWithContentType(MinimalOfferJson(), contentType: null)));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A missing Content-Type header must be a refusal, not a silent accept.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("application/json", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 §8.3.1</see>: "The
    /// type/subtype MAY be followed by semicolon-delimited parameters." A charset parameter does not
    /// change the media type §4.1.3's exact-match gate compares against.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithContentTypeParameterIsAccepted()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, _) =>
                ValueTask.FromResult(OfferResponseWithContentType(MinimalOfferJson(), "application/json; charset=utf-8")));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"A charset parameter must not affect the media-type comparison. Defect: {outcome.Error?.ErrorDescription}");
    }


    /// <summary>
    /// §10: an encrypted-response ask requires the Credential Response to be a JWE with media type
    /// <c>application/jwt</c>; a response answered in clear (<c>application/json</c>) is remote
    /// input, so it answers MalformedResponse naming the rule rather than throwing. The decrypt
    /// delegate is never consulted — the content-type refusal answers before it would run.
    /// </summary>
    [TestMethod]
    public async Task CredentialResponseAnsweredInClearWhenEncryptionAskedAnswersMalformedResponse()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = new Dictionary<string, object> { [WellKnownJwkMemberNames.Kty] = "EC" },
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"))
                : ValueTask.FromResult(JsonResponse(
                    200, "{\"credentials\":[{\"credential\":\"cred\"}]}",
                    (WellKnownHttpHeaderNames.ContentType, "application/json"))),
            encryptRequest: (requestBody, _) => ValueTask.FromResult(requestBody),
            decryptResponse: (_, _) => throw new InvalidOperationException(
                "The content-type refusal must answer before decryption is attempted."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint, responseEncryption)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A response answered in clear when encryption was asked for must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("application/jwt", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §9.2 / §10: the same clear-answer-to-an-encryption-ask rule applies to the Deferred
    /// Credential Endpoint's poll response as it does to the Credential Endpoint's.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollAnsweredInClearWhenEncryptionAskedAnswersMalformedResponse()
    {
        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = new Dictionary<string, object> { [WellKnownJwkMemberNames.Kty] = "EC" },
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(
                    200, "{\"credentials\":[{\"credential\":\"cred\"}]}",
                    (WellKnownHttpHeaderNames.ContentType, "application/json"))),
            encryptRequest: (requestBody, _) => ValueTask.FromResult(requestBody),
            decryptResponse: (_, _) => throw new InvalidOperationException(
                "The content-type refusal must answer before decryption is attempted."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            "txn-1",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com/deferred"),
            responseEncryption,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(pollResult.IsSuccess, "A deferred poll answered in clear when encryption was asked for must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, pollResult.Error.Kind);
        Assert.AreEqual(200, pollResult.Error.StatusCode);
        Assert.Contains("application/jwt", pollResult.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    //Builds a wallet client over in-process spy delegates that never touch the network — the
    //refusal proofs above assert on invocation counts, not wire behaviour, so no HTTP host is
    //needed. Unwired seams default to a delegate that fails loudly if reached.
    private Oid4VciWalletClient BuildInProcessWalletClient(
        Oid4VciFormPostDelegate? sendFormPost = null,
        Oid4VciJsonPostDelegate? sendJsonPost = null,
        OutboundTransportDelegate? fetchCredentialOffer = null,
        OutboundFetchPolicy? outboundFetchPolicy = null,
        ConstructDpopProofDelegate? constructDpopProofAsync = null,
        DpopKey? dpopKey = null,
        Oid4VciEncryptRequestDelegate? encryptRequest = null,
        Oid4VciDecryptResponseDelegate? decryptResponse = null)
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = sendFormPost
                ?? ((_, _, _, _, _) => throw new InvalidOperationException("No §6 Token Request is expected in this test.")),
            SendJsonPost = sendJsonPost
                ?? ((_, _, _, _, _) => throw new InvalidOperationException("No §7/§8/§9 request is expected in this test.")),
            FetchCredentialOffer = fetchCredentialOffer,
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            OutboundFetchPolicy = outboundFetchPolicy ?? OutboundFetchPolicy.SecureDefault,
            ConstructDpopProofAsync = constructDpopProofAsync,
            DpopKey = dpopKey,
            GenerateIdentifierAsync = dpopKey is null ? null : DpopJtiGenerator,
            EncryptRequest = encryptRequest,
            DecryptResponse = decryptResponse
        };

        return new Oid4VciWalletClient(configuration);
    }


    //Builds an HttpResponseData carrying a JSON body and, optionally, response headers (e.g. a
    //DPoP-Nonce challenge header) — the in-process spy delegates' return shape.
    private static HttpResponseData JsonResponse(
        int statusCode, string body, params (string Name, string Value)[] headers) =>
        new()
        {
            StatusCode = statusCode,
            Body = body,
            Headers = headers.Length == 0
                ? ResponseHeaders.Empty
                : new ResponseHeaders { Headers = HttpHeaderSet.FromPairs(headers) }
        };


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
    //started host's SharedHttpClient. The wallet library stays System.Net-free; the test reuses
    //HttpClientTransport (the same real-HttpClient transport the AuthCode real-wire tests use) for
    //wire-faithful status/body/header round-tripping, including the DPoP-Nonce response header the
    //DPoP-bound cases read.
    private Oid4VciWalletClient BuildWalletClient(
        TestHostShell host,
        Oid4VciDecryptResponseDelegate? decryptResponse = null,
        Oid4VciEncryptRequestDelegate? encryptRequest = null,
        OutboundTransportDelegate? fetchCredentialOffer = null,
        ConstructDpopProofDelegate? constructDpopProofAsync = null,
        DpopKey? dpopKey = null)
    {
        HttpClient httpClient = host.Host("default").SharedHttpClient!;

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (endpoint, formFields, headers, _, ct) =>
                HttpClientTransport.SendFormPostAsync(httpClient, endpoint, formFields, headers, ct),
            SendJsonPost = (endpoint, body, headers, _, ct) =>
                HttpClientTransport.SendJsonPostAsync(httpClient, endpoint, body, headers, ct),
            FetchCredentialOffer = fetchCredentialOffer,
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            DecryptResponse = decryptResponse,
            EncryptRequest = encryptRequest,
            OutboundFetchPolicy = TestHostShell.LoopbackOutboundFetchPolicy,
            ConstructDpopProofAsync = constructDpopProofAsync,
            DpopKey = dpopKey,
            GenerateIdentifierAsync = dpopKey is null ? null : DpopJtiGenerator
        };

        return new Oid4VciWalletClient(configuration);
    }


    //The wallet's §4.1.3 by-reference Credential Offer GET transport: a real HTTP GET over the
    //started host's SharedHttpClient. The library stays System.Net-free.
    //An in-process §4.1.3 offer GET response carrying the §4.1.3 mandated application/json content
    //type, for a fetchCredentialOffer spy that never touches the network.
    private static OutboundResponse JsonOfferResponse(string offerJson) =>
        new()
        {
            StatusCode = 200,
            Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, "application/json")),
            Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(offerJson), Tag.Empty)
        };


    //An in-process §4.1.3 offer GET response carrying the given Content-Type header value, or no
    //Content-Type header at all when contentType is null — for the content-type gate's refusal and
    //acceptance proofs, which need control over the header the mandated-content-type test does not.
    private static OutboundResponse OfferResponseWithContentType(string offerJson, string? contentType) =>
        new()
        {
            StatusCode = 200,
            Headers = contentType is null
                ? HttpHeaderSet.Empty
                : HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, contentType)),
            Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(offerJson), Tag.Empty)
        };


    //A minimal, otherwise-conformant §4.1.1 offer body — only what the content-type gate's proofs
    //need the parse to accept once the gate itself lets the response through.
    private static string MinimalOfferJson() =>
        CredentialOfferSerializer.ToJson(new CredentialOffer
        {
            CredentialIssuer = new Uri("https://issuer.example.com"),
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = "pre-authorized-code" }
        });


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


    /// <summary>
    /// Installs the issuer delegates needed by the wallet credential-request cases.
    /// </summary>
    private static async Task<IssuerSeamObservations> WireIssuerSeamsAsync(TestHostShell host)
    {
        IssuerSeamObservations observations = new();
        string? mintedNonce = null;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.ValidatePreAuthorizedCodeAsync = (code, txCode, clientId, _, _, _) =>
                ValueTask.FromResult(string.Equals(code, PreAuthorizedCode, StringComparison.Ordinal)
                    ? PreAuthorizedCodeDecision.Grant(EndUserSubject, WellKnownScopes.OpenId)
                    : PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode));


            candidateIntegration.IssueCredentialNonceAsync = (_, _) =>
            {
                mintedNonce = $"c-nonce-{Guid.NewGuid():N}";

                return ValueTask.FromResult(mintedNonce);
            };


            candidateIntegration.IssueCredentialAsync = async (request, _, _, _, ct) =>
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
        }).ConfigureAwait(false);

        return observations;
    }


    /// <summary>
    /// Installs the response-encryption delegate so the wallet can exercise encrypted credential responses.
    /// </summary>
    private static async Task WireResponseEncryptionSeamAsync(TestHostShell host)
    {
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
                    cancellationToken: ct).ConfigureAwait(false);
            };
        }).ConfigureAwait(false);
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
            compactJwe, WellKnownJweAlgorithms.EcdhEs, enc, TestSetup.Base64UrlDecoder, Pool);
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
            jwk, Pool, TestSetup.Base64UrlDecoder);
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
