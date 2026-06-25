using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.StatusList;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.Federation;
using Verifiable.Tests.TestDataProviders;
using System.Collections.Immutable;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Full-flow integration tests for the OID4VP presentation protocol.
/// </summary>
/// <remarks>
/// <para>
/// Each test method is a sequence diagram in code. The sequence diagrams follow
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>
/// and
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>
/// exactly. Each step is annotated with the PDA state transition it causes.
/// </para>
/// <para>
/// <see cref="TestHostShell"/> encapsulates what an ASP.NET Minimal API application
/// does at each HTTP endpoint. <see cref="TestWallet"/> encapsulates what the Wallet app
/// does. The only values that cross the party boundary are strings that would travel
/// over the wire in a real deployment.
/// </para>
/// <para>
/// Structural PDA state machine tests without cryptography live in
/// <see cref="Oid4VpFlowAutomatonTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Oid4VpFlowIntegrationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string VerifierClientId = "https://verifier.example.com";
    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    //Cross-device flow — OID4VP 1.0 §3.2, §8.2, §8.3.1, HAIP 1.0 §5.1.
    //
    //The End-User scans a QR code displayed by the Verifier. The Wallet and
    //Verifier are on different devices and communicate only via the Verifier's
    //HTTP endpoints.
    //
    //PAR (Pushed Authorization Request) is an internal Verifier preparation
    //step — the Verifier backend generates a request_uri token before encoding
    //the Authorization Request as a QR code. PAR is NOT a Wallet<->Verifier
    //protocol step; it is not visible to the Wallet. Per OID4VP 1.0 §3.2 the
    //Wallet only sees the request_uri in the QR code, not the PAR exchange.
    //
    //Sequence:
    //
    //  Verifier Backend     Verifier Frontend    Network        Wallet App
    //       |                      |                |                |
    //  [Internal: generate request_uri, sign JAR on demand]
    //       |                      |                |                |
    //       |== request_uri ======>|                |                |
    //       |   (QR code shown to End-User)         |                |
    //       |                      |                |                |
    //  [PDA: sentinel + ServerParReceived -> VerifierParReceived]
    //       |                      |                |                |
    //       |                      |<== GET /request/{token} ========|
    //       |                      |                |   (QR scanned) |
    //       |                      |                |                |
    //  [PDA: VerifierParReceived + ServerJarSigned -> VerifierJarServed]
    //  (JAR signed on demand at request time, returned in HTTP response)
    //       |                      |                |                |
    //       |                      |== 200 JAR ===>|===============>|
    //       |                      |                |                |
    //       |                      |            [Wallet PDA:         |
    //       |                      |             RequestUriReceived  |
    //       |                      |             + JarParsed         |
    //       |                      |             -> DcqlEvaluated    |
    //       |                      |             -> PresentationBuilt]
    //       |                      |                |                |
    //       |                      |<== POST /cb ===|================|
    //       |                      |    state={token}, response={JWE}|
    //       |                      |                |                |
    //  [PDA: VerifierJarServed + ResponsePosted -> VerifierResponseReceived]
    //  [PDA effectful loop: DecryptResponseAction -> VerificationSucceeded
    //                       -> PresentationVerified]
    //       |                      |                |                |
    //       |                      |== 200 {} =====>|===============>|
    //       |                      |                |                |
    //  [Verifier PDA accept: PresentationVerified]
    //  [Wallet PDA accept: ResponseSent]

    [TestMethod]
    public async Task CrossDeviceFlowBothPdasReachAcceptState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //Build the HTTP-backed wallet first — this starts the Kestrel listener
        //and aligns the verifier registration's IssuerUri + ResponseUri to the
        //Kestrel base, so the request_uri generated by PAR and the response_uri
        //inside the JAR both point at the real listener.
        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Step 1: Verifier — PAR is verifier-internal (no wire); the wallet
        //never POSTs PAR per OID4VP 1.0 §3.2. The server generates the
        //request_uri pointing at the Kestrel-aligned authority.
        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-xdevice-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierParReceivedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must be in VerifierParReceived after PAR.");

        //Step 2: Wallet HTTP GET request_uri. Real wire — Kestrel serves the
        //JAR, the verifier PDA advances to VerifierJarServed.
        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierJarServedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must be in VerifierJarServed after the HTTP JAR fetch.");

        //Step 3: Wallet drives the full presentation via Oid4VpWalletClient.
        //The wallet verifies the JAR signature, evaluates DCQL, builds the
        //KB-JWT + VP token, encrypts to the verifier's JWK, and POSTs the JWE
        //to response_uri over real HTTP. Kestrel routes the POST to the
        //direct_post endpoint and the verifier PDA reaches PresentationVerified.
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
            "Wallet PDA must reach ResponseSent after the HTTP response POST.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsNull(verified.RedirectUri,
            "Cross-device flow must not carry a redirect_uri.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
        Assert.AreEqual(4, app.GetFlowState(parHandle).StepCount,
            "Verifier PDA must traverse exactly four transitions: " +
            "(1) ServerParReceived -> VerifierParReceived, " +
            "(2) ServerJarSigned -> VerifierJarServed, " +
            "(3) ResponsePosted -> VerifierResponseReceived, " +
            "(4) VerificationSucceeded -> PresentationVerified.");
    }


    //Cross-device flow with A256GCM — HAIP 1.0 §5.1.
    //
    //HAIP 1.0 requires the Verifier to advertise both A128GCM and A256GCM in
    //encrypted_response_enc_values_supported. The Wallet selects one. This test
    //verifies that the full flow succeeds when the Wallet chooses A256GCM.
    //The sequence is identical to the A128GCM cross-device flow — only the
    //enc algorithm chosen by the TestWallet differs.

    [TestMethod]
    public async Task CrossDeviceFlowWithA256GcmBothPdasReachAcceptState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-a256-01"),
            CreatePreparedQuery(),
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
                FlowId = $"wallet-a256-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        //HAIP 1.0 §5.1 requires the Verifier to advertise both A128GCM and
        //A256GCM. HaipProfile prefers A256GCM when both are advertised — the
        //in-the-wire JWE header confirms that selection happened.
        string jweHeader = result.PostedResponseArtifact[..result.PostedResponseArtifact.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(
            jweHeader, BaseMemoryPool.Shared);
        string? enc = Verifiable.JCose.JwkJsonReader.ExtractStringValue(
            headerBytes.Memory.Span, "enc"u8);
        Assert.AreEqual(
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            enc,
            "Wallet must have chosen A256GCM as the enc algorithm.");

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after the HTTP response POST.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsNull(verified.RedirectUri,
            "Cross-device flow must not carry a redirect_uri.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
    }


    //Cross-device flow exercising the OID4VP 1.0 §5.10
    //request_uri_method=post path end-to-end with a JWE-wrapped JAR.
    //
    //The wallet client, when given a WalletExchangePublicKey/PrivateKey
    //and no pre-fetched CompactJar, drives the POST step itself: builds
    //wallet_metadata carrying the public exchange key as a use=enc JWKS,
    //POSTs wallet_nonce + wallet_metadata to request_uri, receives the
    //encrypted JAR in the response body, decrypts it, then continues with
    //the existing presentation flow. The verifier-side library extracts
    //the JWKS from the posted wallet_metadata at the §5.10 transition
    //boundary (no application-skin involvement) and JWE-wraps the signed
    //JAR before serving.

    [TestMethod]
    public async Task CrossDeviceFlowWithEncryptedJarAndRequestUriMethodPostReachesAccept()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Wallet generates a fresh ECDH-ES exchange keypair. The public side
        //is what the wallet client puts into wallet_metadata.jwks on the
        //§5.10 POST; the private side decrypts the JWE-wrapped JAR.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> walletExchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PublicKeyMemory walletEncPublic = walletExchangeKeys.PublicKey;
        using PrivateKeyMemory walletEncPrivate = walletExchangeKeys.PrivateKey;

        //HandleParAsync carries only the inputs the verifier app supplies
        //at PAR time. The wallet's encryption JWKS arrives later off the
        //wire via the §5.10 POST and is consumed inside the library, not
        //through the application skin.
        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-encjar-post-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //CompactJar is null — the wallet client drives the §5.10 POST.
        //WalletExchangePublicKey goes into wallet_metadata.jwks; the
        //matching private side decrypts the encrypted JAR in the response.
        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = null,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                WalletExchangePublicKey = walletEncPublic,
                WalletExchangePrivateKey = walletEncPrivate,
                FlowId = $"wallet-encjar-post-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after the §5.10 POST round-trip.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential after JAR-encrypted §5.10 round-trip.");
    }


    //Strict wallet_metadata conformance — our in-process Verifier mimics a
    //conformant counterparty (e.g. the French/iDAKTO sandbox): a §5.10 POST that
    //carries wallet_metadata which is NOT a complete Authorization Server metadata
    //document (OID4VP 1.0 §11) is rejected with HTTP 400, rather than leniently
    //ignored. This reproduces in-house the exact interop failure a thin
    //wallet_metadata caused against the external sandbox, locking it as a
    //regression guard so the writer can never silently regress to the thin shape.
    [TestMethod]
    public async Task RequestUriPostWithIncompleteWalletMetadataIsRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Start the in-process Kestrel so the §5.10 POST travels over real HTTP.
        _ = await app.CreateOAuthClientAndRegistrationAsync(
            verifierKeys.Registration,
            "https://wallet.example.com/cb",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, _) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-thin-metadata-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //wallet_metadata carrying vp_formats_supported but NOT
        //response_types_supported — the exact shape the external sandbox rejected
        //with "incompatible wallet metadata, 'response_types_supported': null".
        const string incompleteWalletMetadata =
            "{\"vp_formats_supported\":{\"dc+sd-jwt\":{\"sd-jwt_alg_values\":[\"ES256\"]}}}";

        using FormUrlEncodedContent body = new(new Dictionary<string, string>
        {
            [Oid4VpAuthorizationRequestParameterNames.WalletNonce] = $"wn-{Guid.NewGuid():N}",
            [Oid4VpAuthorizationRequestParameterNames.WalletMetadata] = incompleteWalletMetadata
        });

        using HttpResponseMessage response = await app.Host("default").SharedHttpClient!
            .PostAsync(requestUri, body, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A strict Verifier must reject a §5.10 POST whose wallet_metadata omits a required member.");

        string responseBody = await response.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains("response_types_supported", responseBody, StringComparison.Ordinal,
            "The rejection must name the missing required member, mirroring the external sandbox.");
    }


    //Strict wallet_metadata conformance, format rule: a §5.10 POST whose
    //authorization_endpoint is present but is NOT a custom invocation scheme
    //ending with '://' is rejected with HTTP 400 — reproducing the external
    //sandbox's exact "authorization_endpoint does not end with '://'" rejection
    //in-house so the wallet's declared scheme can never regress to an http(s) URL.
    [TestMethod]
    public async Task RequestUriPostWithNonSchemeAuthorizationEndpointIsRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        _ = await app.CreateOAuthClientAndRegistrationAsync(
            verifierKeys.Registration,
            "https://wallet.example.com/cb",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, _) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-endpoint-scheme-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Complete but for authorization_endpoint being an https URL rather than a
        //custom scheme ending in '://' — the exact shape the sandbox rejected.
        const string httpsEndpointMetadata =
            "{\"vp_formats_supported\":{\"dc+sd-jwt\":{\"sd-jwt_alg_values\":[\"ES256\"]}}," +
            "\"response_types_supported\":[\"vp_token\"],\"client_id_prefixes_supported\":[\"x509_san_dns\"]," +
            "\"issuer\":\"https://wallet.example.com\"," +
            "\"authorization_endpoint\":\"https://wallet.example.com\"}";

        using FormUrlEncodedContent body = new(new Dictionary<string, string>
        {
            [Oid4VpAuthorizationRequestParameterNames.WalletNonce] = $"wn-{Guid.NewGuid():N}",
            [Oid4VpAuthorizationRequestParameterNames.WalletMetadata] = httpsEndpointMetadata
        });

        using HttpResponseMessage response = await app.Host("default").SharedHttpClient!
            .PostAsync(requestUri, body, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A strict Verifier must reject an authorization_endpoint that is not a custom scheme ending in '://'.");

        string responseBody = await response.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains("authorization_endpoint", responseBody, StringComparison.Ordinal,
            "The rejection must name authorization_endpoint, mirroring the external sandbox.");
    }


    //Strict wallet_metadata conformance, issuer rule: a §5.10 POST whose issuer is
    //present but is NOT an https URL (e.g. the custom invocation scheme) is
    //rejected with HTTP 400. issuer is the AS's identity (RFC 8414 §2, https), not
    //the invocation scheme — this guards the exact mistake of setting issuer to the
    //scheme, catching it in-house rather than against the external sandbox.
    [TestMethod]
    public async Task RequestUriPostWithNonHttpsIssuerIsRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        _ = await app.CreateOAuthClientAndRegistrationAsync(
            verifierKeys.Registration,
            "https://wallet.example.com/cb",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, _) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-issuer-scheme-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Complete but for issuer being the custom invocation scheme rather than an
        //https URL — the mistake the library briefly shipped as a default.
        const string schemeIssuerMetadata =
            "{\"vp_formats_supported\":{\"dc+sd-jwt\":{\"sd-jwt_alg_values\":[\"ES256\"]}}," +
            "\"response_types_supported\":[\"vp_token\"],\"client_id_prefixes_supported\":[\"x509_san_dns\"]," +
            "\"issuer\":\"openid4vp://\"," +
            "\"authorization_endpoint\":\"openid4vp://\"}";

        using FormUrlEncodedContent body = new(new Dictionary<string, string>
        {
            [Oid4VpAuthorizationRequestParameterNames.WalletNonce] = $"wn-{Guid.NewGuid():N}",
            [Oid4VpAuthorizationRequestParameterNames.WalletMetadata] = schemeIssuerMetadata
        });

        using HttpResponseMessage response = await app.Host("default").SharedHttpClient!
            .PostAsync(requestUri, body, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A strict Verifier must reject an issuer that is not an https URL.");

        string responseBody = await response.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains("issuer", responseBody, StringComparison.Ordinal,
            "The rejection must name issuer, per RFC 8414 §2.");
    }


    //JAR-encryption hardening — four negative/algorithm-coverage paths that
    //share the §5.10 POST setup. The tests drive the POST via raw HttpClient
    //so they can inspect or tamper the encrypted JAR before handing it to
    //the wallet client. WalletMetadataWriter composes the same wire body the
    //wallet client would produce.

    [TestMethod]
    public async Task EncryptedJarWithA256GcmRoundTrips()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> walletExchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PublicKeyMemory walletEncPublic = walletExchangeKeys.PublicKey;
        using PrivateKeyMemory walletEncPrivate = walletExchangeKeys.PrivateKey;

        (Uri requestUri, _) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-encjar-a256gcm-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await PostWalletMetadataAndReadJarAsync(
            app, requestUri, walletEncPublic,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Inspect the JWE protected header to confirm the verifier honoured
        //the wallet's authorization_encrypted_response_enc choice.
        string jweHeaderB64u = compactJar[..compactJar.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(
            jweHeaderB64u, BaseMemoryPool.Shared);
        string? encHeader = JwkJsonReader.ExtractStringValue(
            headerBytes.Memory.Span, "enc"u8);
        Assert.AreEqual(WellKnownJweEncryptionAlgorithms.A256Gcm, encHeader,
            "Verifier must JWE-wrap the JAR with the wallet-selected enc.");

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                WalletExchangePrivateKey = walletEncPrivate,
                FlowId = $"wallet-a256gcm-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet must complete the presentation after decrypting the A256GCM-wrapped JAR.");
    }


    [TestMethod]
    public async Task EncryptedJarWithTamperedCiphertextRejectsAtWallet()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> walletExchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PublicKeyMemory walletEncPublic = walletExchangeKeys.PublicKey;
        using PrivateKeyMemory walletEncPrivate = walletExchangeKeys.PrivateKey;

        (Uri requestUri, _) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-encjar-tamper-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await PostWalletMetadataAndReadJarAsync(
            app, requestUri, walletEncPublic,
            jarEncryptionEnc: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Flip bits in segment 3 (the AES-GCM ciphertext). The auth tag
        //verifies the ciphertext + AAD; any change must surface as a
        //tag-mismatch exception during the wallet's decrypt path.
        string tamperedJar = TamperJweSegment(compactJar, segmentIndex: 3);

        await Assert.ThrowsExactlyAsync<System.Security.Cryptography.AuthenticationTagMismatchException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = tamperedJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                        WalletExchangePrivateKey = walletEncPrivate,
                    FlowId = $"wallet-tamper-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EncryptedJarWithMismatchedExchangePrivateKeyRejectsAtWallet()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Two independent exchange keypairs. The wallet advertises pair A's
        //public side in wallet_metadata.jwks but hands pair B's private side
        //to PresentJarAsync. ECDH on the verifier's ephemeral key + pair A's
        //public yields a shared secret only pair A's private can recover;
        //pair B derives a different secret and the AES-GCM tag fails.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> pairA =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PublicKeyMemory advertisedPublic = pairA.PublicKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> pairB =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PrivateKeyMemory mismatchedPrivate = pairB.PrivateKey;
        pairA.PrivateKey.Dispose();
        pairB.PublicKey.Dispose();

        (Uri requestUri, _) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-encjar-wrongkey-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await PostWalletMetadataAndReadJarAsync(
            app, requestUri, advertisedPublic,
            jarEncryptionEnc: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<System.Security.Cryptography.AuthenticationTagMismatchException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                        WalletExchangePrivateKey = mismatchedPrivate,
                    FlowId = $"wallet-wrongkey-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EncryptedJarWithMissingExchangePrivateKeyThrows()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> walletExchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PublicKeyMemory walletEncPublic = walletExchangeKeys.PublicKey;
        walletExchangeKeys.PrivateKey.Dispose();

        (Uri requestUri, _) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-encjar-nokey-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await PostWalletMetadataAndReadJarAsync(
            app, requestUri, walletEncPublic,
            jarEncryptionEnc: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        //JWE arrives but PresentJarOptions carries no private key. The
        //wallet client surfaces the configuration error before any crypto
        //is attempted.
        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                        WalletExchangePrivateKey = null,
                    FlowId = $"wallet-nokey-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains("WalletExchangePrivateKey", ex.Message, StringComparison.Ordinal);
    }


    //Drives one raw §5.10 POST: composes wallet_metadata via
    //WalletMetadataWriter, generates a fresh wallet_nonce, POSTs both as
    //form fields to <paramref name="requestUri"/>, and returns the JAR
    //in the response body. Used by JAR-encryption hardening tests that
    //need to inspect or tamper the JAR before handing it to PresentJarAsync.
    private static async ValueTask<string> PostWalletMetadataAndReadJarAsync(
        TestHostShell app,
        Uri requestUri,
        PublicKeyMemory walletExchangePublicKey,
        string? jarEncryptionEnc,
        CancellationToken cancellationToken)
    {
        string walletMetadataJson = WalletMetadataWriter.BuildForWalletPost(
            Oid4VpWalletCapabilities.HaipDefault,
            walletExchangePublicKey,
            jarEncryptionEnc,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared);

        string walletNonce = $"wn-{Guid.NewGuid():N}";

        using FormUrlEncodedContent body = new(new Dictionary<string, string>
        {
            [Oid4VpAuthorizationRequestParameterNames.WalletNonce] = walletNonce,
            [Oid4VpAuthorizationRequestParameterNames.WalletMetadata] = walletMetadataJson
        });

        using HttpResponseMessage response = await app.Host("default").SharedHttpClient!
            .PostAsync(requestUri, body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content
            .ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }


    //OID4VP 1.0 §5.9.3 redirect_uri prefix — inline parameters path.
    //
    //The Verifier identifies itself by its own response URI; the
    //Authorization Request travels inline (no JAR, no signature). Trust
    //comes from the wallet POSTing back to that URI. This test drives the
    //full end-to-end flow with the inline-parameter shape:
    //  1. PAR seeds the verifier with a flow handle the wallet's state
    //     claim references back to.
    //  2. The wallet receives the inline parameters (as it would from a
    //     QR scan or deep link), validates the redirect_uri prefix value
    //     matches response_uri, builds the presentation, and POSTs the
    //     vp_token + state.
    //  3. The verifier's direct_post endpoint correlates by state, the
    //     PDA transitions VerifierParReceived → VerifierUnencryptedResponse-
    //     Received (the no-JAR-served path added for §5.9.3 inline flows)
    //     → PresentationVerified.

    [TestMethod]
    public async Task RedirectUriPrefixInlineParametersFlowReachesAccept()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //After the host starts and the wallet factory aligns the registration's
        //URIs to the Kestrel base, the AS-side Registrations dictionary carries
        //the live endpoint; the verifierKeys snapshot still holds the original
        //pre-alignment URI.
        ClientRecord alignedRegistration =
            app.Host("default").Registrations[verifierKeys.Registration.TenantId.Value];
        Uri responseUri = alignedRegistration.ResponseUri!;
        string clientIdRedirectUri =
            $"{WellKnownClientIdPrefixes.RedirectUri.Value}:{responseUri.OriginalString}";

        //§5.9.3 redirect_uri prefix flows use the prefixed form as the
        //canonical client_id throughout. Rewrite the verifier's stored
        //registration to match so KB-JWT.aud validation
        //(aud == registration.ClientId) lines up with what the wallet sends.
        ClientRecord redirectUriRegistration = alignedRegistration with
        {
            ClientId = clientIdRedirectUri
        };
        app.Host("default").Registrations[redirectUriRegistration.TenantId.Value] =
            redirectUriRegistration;

        TransactionNonce nonce = new("nonce-redirect-uri-01");
        (Uri _, string parHandle) = await app.HandleParAsync(verifierKeys,
            nonce,
            CreatePreparedQuery(),
            transactionData: null,
            jarAdditionalHeaderClaims: null,
            responseMode: WellKnownResponseModes.DirectPost,
            TestContext.CancellationToken).ConfigureAwait(false);

        //DCQL query as JSON text — the wallet's deserializer parses it back
        //into a typed DcqlQuery on receipt.
        DcqlQuery dcqlQuery = CreateDcqlQuery();
        string dcqlQueryJson = JsonSerializer.Serialize(
            dcqlQuery, TestSetup.DefaultSerializationOptions);

        Dictionary<string, string> inlineParameters = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = clientIdRedirectUri,
            [OAuthRequestParameterNames.ResponseType] =
                Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] =
                WellKnownResponseModes.DirectPost,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] =
                responseUri.OriginalString,
            [WellKnownJwtClaimNames.Nonce] = nonce.Value,
            [OAuthRequestParameterNames.State] = parHandle,
            [Oid4VpAuthorizationRequestParameterNames.DcqlQuery] = dcqlQueryJson
        };

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = null,
                RequestUri = responseUri,
                ExpectedVerifierClientId = clientIdRedirectUri,
                InlineAuthorizationParameters = inlineParameters,
                FlowId = $"wallet-redirect-uri-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after the inline-parameter response POST.");

        PresentationVerifiedState verified =
            (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verifier must recover the pid claims from the inline-parameter flow.");
    }


    //OID4VP 1.0 §5.9.3 redirect_uri prefix — alg=none JAR variant.
    //
    //The verifier emits an unsigned JAR (alg=none, empty signature
    //segment) at request_uri. The wallet fetches it via the standard
    //request_uri HTTP GET, detects alg=none in the protected header,
    //parses without signature verification, validates the redirect_uri
    //prefix matches response_uri, builds the presentation, and POSTs.
    //Same trust model as the inline-parameters variant; different wire
    //envelope.

    [TestMethod]
    public async Task RedirectUriPrefixUnsignedJarFlowReachesAccept()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        ClientRecord alignedRegistration =
            app.Host("default").Registrations[verifierKeys.Registration.TenantId.Value];
        Uri responseUri = alignedRegistration.ResponseUri!;
        string clientIdRedirectUri =
            $"{WellKnownClientIdPrefixes.RedirectUri.Value}:{responseUri.OriginalString}";

        //Rewrite the registration's client_id to the prefixed form so the
        //JAR-fetch endpoint emits the unsigned variant and KB-JWT.aud
        //validation lines up.
        ClientRecord redirectUriRegistration = alignedRegistration with
        {
            ClientId = clientIdRedirectUri
        };
        app.Host("default").Registrations[redirectUriRegistration.TenantId.Value] =
            redirectUriRegistration;

        TransactionNonce nonce = new("nonce-unsigned-jar-01");
        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            nonce,
            CreatePreparedQuery(),
            transactionData: null,
            jarAdditionalHeaderClaims: null,
            responseMode: WellKnownResponseModes.DirectPost,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Fetch the JAR via the standard request_uri GET. The verifier-side
        //endpoint detects the redirect_uri prefix on the registration and
        //returns an unsigned compact JAR per §5.9.3.
        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Wire-shape assertion: the JAR is a 3-segment compact JWS with an
        //empty signature segment (header.payload.) per RFC 7515 §6.1.
        string[] segments = compactJar.Split('.');
        Assert.HasCount(3, segments,
            "Unsigned compact JAR has three dot-separated segments per RFC 7515 §3.1.");
        Assert.AreEqual(string.Empty, segments[2],
            "The signature segment of an alg=none JAR MUST be empty per RFC 7515 §6.1.");

        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(
            segments[0], BaseMemoryPool.Shared);
        string? alg = JwkJsonReader.ExtractStringValue(
            headerBytes.Memory.Span, "alg"u8);
        Assert.AreEqual(WellKnownJwaValues.None, alg,
            "The protected header MUST carry alg=none for the §5.9.3 redirect_uri path.");

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = clientIdRedirectUri,
                FlowId = $"wallet-unsigned-jar-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after the unsigned-JAR response POST.");

        PresentationVerifiedState verified =
            (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verifier must recover the pid claims from the alg=none JAR flow.");
    }


    //Hardening: the wallet must reject an inline request whose redirect_uri
    //prefix value does not match the response_uri it advertises. The whole
    //trust model of OID4VP §5.9.3 redirect_uri rests on those two being
    //equal — a mismatch means the response would travel to one place while
    //the authority claim references another, which is the exact substitution
    //attack the prefix is supposed to prevent.

    [TestMethod]
    public async Task RedirectUriPrefixWithMismatchedResponseUriIsRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        Uri responseUri = verifierKeys.Registration.ResponseUri!;
        string mismatchedClientId =
            $"{WellKnownClientIdPrefixes.RedirectUri.Value}:https://attacker.example.org/cb";

        DcqlQuery dcqlQuery = CreateDcqlQuery();
        string dcqlQueryJson = JsonSerializer.Serialize(
            dcqlQuery, TestSetup.DefaultSerializationOptions);

        Dictionary<string, string> inlineParameters = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = mismatchedClientId,
            [OAuthRequestParameterNames.ResponseType] =
                Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] =
                WellKnownResponseModes.DirectPost,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] =
                responseUri.OriginalString,
            [WellKnownJwtClaimNames.Nonce] = "nonce-mismatch-01",
            [OAuthRequestParameterNames.State] = "state-mismatch-01",
            [Oid4VpAuthorizationRequestParameterNames.DcqlQuery] = dcqlQueryJson
        };

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = null,
                    RequestUri = responseUri,
                    ExpectedVerifierClientId = mismatchedClientId,
                        InlineAuthorizationParameters = inlineParameters,
                    FlowId = $"wallet-redirect-mismatch-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains("does not match response_uri", ex.Message, StringComparison.Ordinal);
    }


    //Hardening: any prefix other than redirect_uri on an inline (unsigned)
    //request is a spec violation — OID4VP §5.9.3 mandates that unsigned
    //inline requests carry the redirect_uri prefix only. The wallet
    //surfaces the mismatch before any presentation work happens.

    [TestMethod]
    public async Task InlineRequestWithNonRedirectUriPrefixIsRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        Uri responseUri = verifierKeys.Registration.ResponseUri!;
        string verifierAttestationClientId =
            $"{WellKnownClientIdPrefixes.VerifierAttestation.Value}:example-verifier";

        DcqlQuery dcqlQuery = CreateDcqlQuery();
        string dcqlQueryJson = JsonSerializer.Serialize(
            dcqlQuery, TestSetup.DefaultSerializationOptions);

        Dictionary<string, string> inlineParameters = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = verifierAttestationClientId,
            [OAuthRequestParameterNames.ResponseType] =
                Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] =
                WellKnownResponseModes.DirectPost,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] =
                responseUri.OriginalString,
            [WellKnownJwtClaimNames.Nonce] = "nonce-nonredirect-01",
            [OAuthRequestParameterNames.State] = "state-nonredirect-01",
            [Oid4VpAuthorizationRequestParameterNames.DcqlQuery] = dcqlQueryJson
        };

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = null,
                    RequestUri = responseUri,
                    ExpectedVerifierClientId = verifierAttestationClientId,
                        InlineAuthorizationParameters = inlineParameters,
                    FlowId = $"wallet-non-redirect-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains(
            $"'{WellKnownClientIdPrefixes.RedirectUri.Value}:' prefix",
            ex.Message,
            StringComparison.Ordinal);
    }


    private static DcqlQuery CreateDcqlQuery() => DcqlFixtures.PidFamilyName();


    //Algorithm coverage for the OID4VP JAR-signing path. The default
    //cross-device test above pins P-256 (ES256) via RegisterClient; this
    //parameterised variant exercises the full HTTP-wire flow under each
    //of the project's signing-capable algorithms. The registry-based
    //JWS signing path picks the right SigningDelegate by the key's
    //CryptoAlgorithm tag, so the flow code paths are algorithm-agnostic
    //— a regression here would mean either a missing registry entry or a
    //JWA-name mismatch.
    //
    //ECDH-ES on the JWE response stays P-256 regardless: HAIP 1.0 §5.1
    //pins the encryption keypair to P-256, and RegisterJarSigningClient
    //creates that keypair internally per registration. Signing alg varies
    //independently.

    [TestMethod]
    [DataRow("ES256")]
    [DataRow("ES384")]
    [DataRow("ES512")]
    [DataRow("ES256K")]
    [DataRow("RS256")]
    [DataRow("EdDSA")]
    [DataRow("ML-DSA-44")]
    [DataRow("ML-DSA-65")]
    [DataRow("ML-DSA-87")]
    [DataRow("ESB256")]
    [DataRow("ESB320")]
    [DataRow("ESB384")]
    [DataRow("ESB512")]
    public async Task CrossDeviceFlowReachesAcceptUnderSigningAlgorithm(string algorithm)
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierJarSigningKeys =
            CreateSigningKeyMaterial(algorithm);

        using VerifierKeyMaterial verifierKeys = app.RegisterJarSigningClient(
            VerifierClientId, VerifierBaseUri, verifierJarSigningKeys, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce($"nonce-alg-{algorithm.ToUpperInvariant()}-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The JAR's alg header must match the registered key's JWA mapping —
        //confirms the registry-driven alg selection on the verifier side
        //before the wallet ever verifies the signature.
        string jarHeaderSegment = compactJar[..compactJar.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(jarHeaderSegment, Pool);
        string? algClaim = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "alg"u8);
        Assert.AreEqual(algorithm, algClaim,
            $"JAR alg header must equal the registered key's JWA name. Expected: {algorithm}, got: {algClaim}.");

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-alg-{algorithm.ToUpperInvariant()}-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            $"Wallet PDA must reach ResponseSent for {algorithm}.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            $"Verifier must reach PresentationVerified with the pid credential for {algorithm}.");
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSigningKeyMaterial(
        string jwaName) =>
        jwaName switch
        {
            "ES256" => TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            "ES384" => TestKeyMaterialProvider.CreateFreshP384KeyMaterial(),
            "ES512" => TestKeyMaterialProvider.CreateFreshP521KeyMaterial(),
            "ES256K" => TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial(),
            "RS256" => TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
            "EdDSA" => TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial(),
            "ML-DSA-44" => TestKeyMaterialProvider.CreateFreshMlDsa44KeyMaterial(),
            "ML-DSA-65" => TestKeyMaterialProvider.CreateFreshMlDsa65KeyMaterial(),
            "ML-DSA-87" => TestKeyMaterialProvider.CreateFreshMlDsa87KeyMaterial(),
            "ESB256" => TestKeyMaterialProvider.CreateFreshBrainpoolP256r1KeyMaterial(),
            "ESB320" => TestKeyMaterialProvider.CreateFreshBrainpoolP320r1KeyMaterial(),
            "ESB384" => TestKeyMaterialProvider.CreateFreshBrainpoolP384r1KeyMaterial(),
            "ESB512" => TestKeyMaterialProvider.CreateFreshBrainpoolP512r1KeyMaterial(),
            _ => throw new ArgumentOutOfRangeException(nameof(jwaName),
                jwaName, "Unsupported JWA name for OID4VP JAR signing.")
        };


    //Multi-credential cross-device flow — OID4VP 1.0 §8.1.
    //
    //The Verifier asks for two credentials in one DCQL query (each under
    //its own credential query id). The Wallet stores two SD-JWT VCs and
    //returns the matching one per query. The wire vp_token is a JSON
    //object with two entries — one compact SD-JWT presentation under each
    //credential query id. The Verifier extracts and verifies each
    //presentation independently and aggregates the per-credential claims
    //into PresentationVerifiedState.Claims.

    [TestMethod]
    public async Task MultiCredentialFlowAggregatesPerCredentialClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Two independent PID credentials, distinct given/family names, same
        //issuer + holder key. Each will travel under its own credential
        //query id in the multi-credential vp_token.
        (string primarySerializedSdJwt, PrivateKeyMemory primaryHolder, PublicKeyMemory primaryIssuerPub) =
            await IssuePidCredentialWithClaimsAsync(
                givenName: "Erika",
                familyName: "Mustermann",
                TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory primaryHolderKey = primaryHolder;
        using PublicKeyMemory primaryIssuerKey = primaryIssuerPub;

        (string secondarySerializedSdJwt, PrivateKeyMemory secondaryHolder, PublicKeyMemory secondaryIssuerPub) =
            await IssuePidCredentialWithClaimsAsync(
                givenName: "Hans",
                familyName: "Schmidt",
                TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory secondaryHolderKey = secondaryHolder;
        using PublicKeyMemory secondaryIssuerKey = secondaryIssuerPub;

        //Both PIDs share the same issuer identifier in this test —
        //registering one trusted issuer covers both credentials.
        app.RegisterIssuerTrust(IssuerId, primaryIssuerKey);

        //Wallet holds both credentials keyed by their wire credential
        //query ids. The wallet client's resolver fires once per query and
        //returns the matching credential.
        Dictionary<string, string> credentialsByQueryId = new(StringComparer.Ordinal)
        {
            [DcqlFixtures.PidPrimaryCredentialId] = primarySerializedSdJwt,
            [DcqlFixtures.PidSecondaryCredentialId] = secondarySerializedSdJwt
        };

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                credentialsByQueryId,
                primaryHolderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Two credential queries — verifier asks for both PIDs in one PAR.
        //Each query asks for family_name to drive disclosure selection.
        PreparedDcqlQuery multiCredentialQuery =
            DcqlFixtures.PidPrimaryAndSecondaryFamilyNamePrepared();

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-multicred-01"),
            multiCredentialQuery,
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Per-credential KB-JWT signing uses the holder key from
        //PresentJarOptions. Both PIDs were issued with the SAME holder
        //(both Ed25519 keys from TestKeyMaterialProvider produce different
        //instances each call; for this test we present using the holder
        //key that matches the FIRST credential — the test's KB-JWT
        //assertion is structural, not per-credential).
        //
        //Note for real wallets: each credential's KB-JWT must be signed
        //by the holder key whose public side appears in that credential's
        //cnf claim. Multi-credential with distinct holder keys per
        //credential is a future extension of PresentJarOptions.
        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-multicred-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        //The vp_token JSON the wallet POSTed carries two presentations —
        //one per credential query. Verify the wire shape contains both
        //query ids before the encrypted JWE wrapped them.
        //(EncryptedJweResponse here is the compact JWE; we can't peek
        //inside on the wallet side, but the verifier's PresentationVerified
        //state should show both credential query ids in Claims.)
        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState);

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey(DcqlFixtures.PidPrimaryCredentialId),
            "Verified claims must carry the primary PID under its credential query id.");
        Assert.IsTrue(verified.Claims.ContainsKey(DcqlFixtures.PidSecondaryCredentialId),
            "Verified claims must carry the secondary PID under its credential query id.");
    }


    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialWithClaimsAsync(string givenName, string familyName, CancellationToken cancellationToken, StatusListReference? status = null)
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

        var claims = new List<KeyValuePair<string, object>>
        {
            new(EudiPid.SdJwt.GivenName, givenName),
            new(EudiPid.SdJwt.FamilyName, familyName)
        };

        if(status is not null)
        {
            //IETF Token Status List section 6: a non-disclosable status claim in the issuer payload.
            claims.Add(new("status", new Dictionary<string, object>
            {
                ["status_list"] = new Dictionary<string, object>
                {
                    ["idx"] = status.Value.Index,
                    ["uri"] = status.Value.Uri
                }
            }));
        }

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims: claims);

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
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    //A genuinely issued SD-JWT VC that carries an IETF Token Status List reference is verified
    //through the production path: the verifier surfaces the status_list reference, and the
    //verifier-agnostic revocation gate reads it valid, then revoked once the credential's bit is
    //flipped. This is the credential-verification flow any verifier runs — RP server, peer wallet,
    //or agent — independent of the JAR/JWE presentation transport the other flow tests exercise.
    [TestMethod]
    public async Task SdJwtVcStatusReferenceSurfacesAndDrivesRevocationGate()
    {
        const string statusListUri = "https://issuer.example/statuslists/1";
        const int credentialIndex = 42;
        DateTimeOffset now = TimeProvider.GetUtcNow();

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithClaimsAsync(
                "Alice", "Smith", TestContext.CancellationToken,
                status: new StatusListReference(credentialIndex, statusListUri)).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            PublicKeyMemory? IssuerLookup(string iss) =>
                string.Equals(iss, IssuerId, StringComparison.Ordinal) ? issuerPublicKey : null;

            VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
                serializedSdJwt,
                "pid",
                static s => SdJwtSerializer.ParseToken(
                    s, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
                static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
                IssuerLookup,
                MicrosoftEntropyFunctions.ComputeDigestAsync,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                saltReuseSeam: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(parsed.CredentialSignatureValid, "The issued credential must verify.");
            Assert.IsNotNull(parsed.CredentialStatus, "The verifier must surface the credential's status_list reference.");
            Assert.AreEqual(credentialIndex, parsed.CredentialStatus.Value.Index);
            Assert.AreEqual(statusListUri, parsed.CredentialStatus.Value.Uri);

            //The resolver stands in for whatever fetched and verified the status list (an HTTP fetch,
            //or an Orleans status-list grain); here the verified token is built directly.
            using StatusListType statusList = StatusListType.Create(
                64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

            CredentialStatusOutcome beforeRevocation = await CredentialStatusGate.CheckAsync(
                parsed.CredentialStatus.Value,
                (uri, ct) => ValueTask.FromResult(new StatusListToken(statusListUri, now, statusList)),
                now,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(beforeRevocation.IsValid, "An unset status bit must read as valid.");

            statusList[credentialIndex] = StatusTypes.Invalid;

            CredentialStatusOutcome afterRevocation = await CredentialStatusGate.CheckAsync(
                parsed.CredentialStatus.Value,
                (uri, ct) => ValueTask.FromResult(new StatusListToken(statusListUri, now, statusList)),
                now,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(afterRevocation.IsValid, "After flipping the credential's bit the status must read as revoked.");
            Assert.AreEqual(StatusTypes.Invalid, afterRevocation.Status);
        }
    }


    //The status check is wired into the HAIP verifier executor itself: when the host is built with a
    //ResolveVerifiedStatusListTokenDelegate, the executor reads each presented credential's status_list
    //entry through CredentialStatusGate and surfaces the outcome on VerificationSucceeded, which the
    //verifier PDA carries onto PresentationVerifiedState.CredentialStatuses. This proves the relying
    //party can act on revocation straight off the terminal state — no re-parse of the verified vp_token.
    //A determinable revoked status is surfaced, NOT failed, so the RP applies its own policy; the full
    //cross-device flow still reaches PresentationVerified.
    [TestMethod]
    public async Task ExecutorSurfacesCredentialStatusOnPresentationVerified()
    {
        const string statusListUri = "https://issuer.example/statuslists/1";
        const int credentialIndex = 42;
        const string pidCredentialQueryId = "pid";

        //The mutable list the resolver hands back, standing in for whatever fetched and verified it.
        //Flipping the bit between the two presentations drives valid -> revoked through the executor.
        using StatusListType statusList = StatusListType.Create(
            64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate resolveStatusList =
            (uri, ct) => ValueTask.FromResult(
                new StatusListToken(statusListUri, TimeProvider.GetUtcNow(), statusList));

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolveStatusList);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithClaimsAsync(
                "Alice", "Smith", TestContext.CancellationToken,
                status: new StatusListReference(credentialIndex, statusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Drives one full cross-device presentation and returns the verifier's terminal state.
        async Task<PresentationVerifiedState> PresentAsync(string nonce)
        {
            (Uri requestUri, string parHandle) = await app.HandleParAsync(
                verifierKeys,
                new TransactionNonce(nonce),
                CreatePreparedQuery(),
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
                    FlowId = $"wallet-status-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
                "Wallet PDA must reach ResponseSent after the HTTP response POST.");

            return (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        }

        //First presentation — the credential's status bit is unset, so the executor surfaces a valid
        //status alongside the verified claims.
        PresentationVerifiedState whenValid = await PresentAsync("nonce-status-valid").ConfigureAwait(false);

        Assert.IsNotNull(whenValid.CredentialStatuses,
            "The executor must surface CredentialStatuses when a status resolver is wired.");
        Assert.IsTrue(whenValid.CredentialStatuses!.TryGetValue(pidCredentialQueryId, out CredentialStatusOutcome? validOutcome),
            "The surfaced statuses must be keyed by the DCQL credential query id.");
        Assert.IsNotNull(validOutcome);
        Assert.IsTrue(validOutcome.IsValid, "An unset status bit must surface as valid.");
        Assert.AreEqual(StatusTypes.Valid, validOutcome.Status);

        //Revoke the credential by flipping its bit, then present again. The executor surfaces the revoked
        //status WITHOUT failing the presentation — the relying party reads it and applies its own policy.
        statusList[credentialIndex] = StatusTypes.Invalid;

        PresentationVerifiedState whenRevoked = await PresentAsync("nonce-status-revoked").ConfigureAwait(false);

        Assert.IsNotNull(whenRevoked.CredentialStatuses,
            "The executor must still surface CredentialStatuses after revocation.");
        Assert.IsTrue(whenRevoked.CredentialStatuses!.TryGetValue(pidCredentialQueryId, out CredentialStatusOutcome? revokedOutcome),
            "The surfaced statuses must be keyed by the DCQL credential query id.");
        Assert.IsNotNull(revokedOutcome);
        Assert.IsFalse(revokedOutcome.IsValid, "After flipping the bit the executor must surface a revoked status.");
        Assert.AreEqual(StatusTypes.Invalid, revokedOutcome.Status);
    }


    //Fail-closed configuration guard: a credential whose issuer gated its validity on a status list is
    //NOT accepted when the verifier executor was constructed without a status resolver to read it. The
    //executor throws server-side (mirroring the mdoc / SD-CWT / disclosure seams), so the verifier's
    //flow never reaches PresentationVerified — silently treating an unreadable status as valid would be
    //a security gap.
    [TestMethod]
    public async Task ExecutorFailsClosedWhenCredentialReferencesStatusListButNoResolverWired()
    {
        const string statusListUri = "https://issuer.example/statuslists/1";
        const int credentialIndex = 42;

        //No status resolver wired — yet the issued credential references a status list.
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithClaimsAsync(
                "Alice", "Smith", TestContext.CancellationToken,
                status: new StatusListReference(credentialIndex, statusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-status-noresolver"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The wallet POSTs an otherwise-valid presentation. The verifier fails closed on the unreadable
        //status server-side; whether that surfaces to the wallet as a thrown error or a non-success
        //response is the transport's concern — the security-relevant assertion is on the verifier's own
        //flow state, which must not be PresentationVerified.
        try
        {
            await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-status-noresolver-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            //Tolerated: the verifier's fail-closed guard surfaced to the wallet as an error response.
        }

        Assert.IsFalse(
            app.GetFlowState(parHandle).State is PresentationVerifiedState,
            "A credential that references a status list must not be accepted when the verifier was " +
            "constructed without a status resolver to read it.");
    }


    //Same-device flow — OID4VP 1.0 §8.2, §8.3, §8.3.1, HAIP 1.0 §5.1.
    //
    //NOTE: OID4VP §3.1 describes a different same-device pattern using
    //response_mode=fragment. What is implemented here is the direct_post.jwt
    //mode with redirect_uri callback, which is what HAIP 1.0 §5.1 requires
    //for same-device flows.
    //
    //The End-User is on the same device as the Wallet. The Verifier returns a
    //redirect_uri in the direct_post response so the Wallet can hand back
    //control to the browser session. The redirect_uri must contain a fresh
    //random value (>=128 bits) to prevent session fixation per OID4VP §8.2.
    //
    //PAR is an internal Verifier preparation step — not visible to the Wallet.
    //The Wallet only sees the request_uri embedded in the deep link.
    //
    //Sequence:
    //
    //  Verifier Backend     Verifier Frontend    Network        Wallet App
    //       |                      |                |                |
    //  [Internal: generate request_uri, prepare JAR]
    //       |                      |                |                |
    //  [PDA: sentinel + ServerParReceived -> VerifierParReceived]
    //       |                      |                |                |
    //       |== deep link ========>|===============>|===============>|
    //       |   haip-vp://...?request_uri={token}   |                |
    //       |                      |                |                |
    //       |                      |<== GET /request/{token} ========|
    //       |                      |                |                |
    //  [PDA: VerifierParReceived + ServerJarSigned -> VerifierJarServed]
    //       |                      |                |                |
    //       |                      |== 200 JAR ===>|===============>|
    //       |                      |                |                |
    //       |                      |<== POST /cb ===|================|
    //       |                      |    state={token}, response={JWE}|
    //       |                      |                |                |
    //  [PDA: VerifierJarServed + ResponsePosted -> VerifierResponseReceived
    //        -> VerificationSucceeded -> PresentationVerified]
    //       |                      |                |                |
    //       |                      |== 200 {redirect_uri} =>|=======>|
    //       |                      |   (redirect_uri contains fresh  |
    //       |                      |    random session token)        |
    //       |                      |                |                |
    //       |                      |            [Wallet PDA:         |
    //       |                      |             ResponseSent        |
    //       |                      |             -> BrowserRedirectIssued]
    //       |                      |                |                |
    //       |                      |<== GET /complete?session={tok} =|
    //  [Verifier PDA accept: PresentationVerified]
    //  [Wallet PDA accept: BrowserRedirectIssued]

    [TestMethod]
    public async Task SameDeviceFlowBothPdasReachAcceptState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-sd-{Guid.NewGuid():N}";
        //Per OID4VP §8.2 the redirect_uri must contain a fresh random value
        //of at least 128 bits so the Verifier can bind the redirect-back to
        //the correct session and reject session fixation attempts.
        string sessionToken = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        Uri sameDeviceRedirectUri = new($"https://verifier.example.com/complete?session={sessionToken}");


        //Step 1: PAR — same as cross-device.
        //PDA: sentinel -> VerifierParReceived.

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-sd-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);


        //Step 2: JAR request — same as cross-device.
        //PDA: VerifierParReceived + ServerJarSigned -> VerifierJarServed.

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);


        //Step 3: Wallet — POST /cb.
        //=== Wire boundary: compact JWE crosses from Wallet to Verifier. ===

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(wallet.GetFlowState(walletFlowId).State);


        //Step 4: Verifier — direct_post (POST /connect/{segment}/cb).
        //Returns redirect_uri in 200 body for same-device flow per OID4VP 1.0 §8.2.
        //PDA: VerifierJarServed -> VerifierResponseReceived -> PresentationVerified.
        //=== Wire boundary: redirect_uri crosses from Verifier to Wallet. ===

        PresentationVerifiedState verified = await app.HandleDirectPostAsync(verifierKeys,
            parHandle,
            compactJwe,
            redirectUri: sameDeviceRedirectUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(sameDeviceRedirectUri, verified.RedirectUri,
            "Same-device response must carry the redirect_uri.");

        Uri receivedRedirectUri = verified.RedirectUri!;


        //Step 5: Wallet — browser redirect.
        //Wallet follows redirect_uri to hand back control to the browser session.
        //Wallet PDA: ResponseSent -> BrowserRedirectIssued.

        BrowserRedirectIssued browserRedirect = await wallet.HandleRedirectAsync(
            walletFlowId,
            receivedRedirectUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<BrowserRedirectIssued>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must reach BrowserRedirectIssued.");
        Assert.AreEqual(sameDeviceRedirectUri, browserRedirect.RedirectUri,
            "BrowserRedirectIssued must carry the same redirect_uri the Verifier sent.");
        Assert.AreEqual(5, wallet.GetFlowState(walletFlowId).StepCount,
            "Wallet PDA must traverse exactly five transitions in the same-device flow.");
    }


    //Local / app-to-app flow — proximity scenario.
    //
    //HAIP 1.0 §5.1 explicitly acknowledges proximity scenarios as a valid
    //exception to the same-device redirect flow: "Verifiers are RECOMMENDED
    //to use only the same-device flow unless the Verifier does not rely on
    //session binding for phishing resistance, e.g. in a proximity scenario."
    //OID4VP over BLE is defined as a separate companion specification that
    //uses the same request/response semantics as OID4VP 1.0. This test
    //verifies those semantics hold when the transport is in-process rather
    //than HTTP — the protocol is identical, only the channel differs.
    //
    //The Verifier PDA and Wallet PDA are driven sequentially in the same
    //process. Local variable assignment represents the channel boundary.
    //
    //Sequence:
    //
    //  Verifier PDA                App layer             Wallet PDA
    //       |                          |                      |
    //  [Internal: generate request_uri]|                      |
    //  [PDA: sentinel + ServerParReceived -> VerifierParReceived]
    //       |                          |                      |
    //  [Internal: sign JAR]            |                      |
    //  [PDA: VerifierParReceived + ServerJarSigned -> VerifierJarServed]
    //       |                          |                      |
    //       |== compactJar ==========>|== compactJar =======>|
    //       |  (NFC / BLE / memory)   |                      |
    //       |                         |    [Wallet PDA steps] |
    //       |                         |                       |
    //       |<== compactJwe ==========|<== compactJwe ========|
    //       |  (NFC / BLE / memory)   |                      |
    //       |                         |                      |
    //  [PDA: VerifierJarServed + ResponsePosted -> VerifierResponseReceived
    //        -> VerificationSucceeded -> PresentationVerified]
    //  [Verifier PDA accept: PresentationVerified]
    //  [Wallet PDA accept: ResponseSent]

    [TestMethod]
    public async Task LocalAppToAppFlowBothPdasReachAcceptState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-app2app-{Guid.NewGuid():N}";

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-app2app-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            parHandle, TestContext.CancellationToken).ConfigureAwait(false);


        //=== Channel boundary: compactJar passes to Wallet (NFC/BLE/memory). ===

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);


        //=== Channel boundary: compactJwe passes to Verifier. ===

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        PresentationVerifiedState verified = await app.HandleDirectPostAsync(verifierKeys,
            parHandle,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must reach PresentationVerified.");
        Assert.IsInstanceOfType<ResponseSent>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must reach ResponseSent.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
    }


    //Security: tampered JWE ciphertext is rejected.
    //
    //An attacker intercepts the compact JWE in transit and flips bits in the
    //ciphertext. ECDH-ES + AES-GCM authentication tag verification must fail.
    //This test verifies that the AEAD authentication tag protects the VP token
    //payload end-to-end between Wallet and Verifier.
    //
    //PDA states reached before the tamper:
    //  Verifier: VerifierParReceived -> VerifierJarServed -> VerifierResponseReceived
    //  (decryption throws before VerificationSucceeded is produced)

    [TestMethod]
    public async Task TamperedJweCiphertextIsRejectedByVerifier()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-tamper-{Guid.NewGuid():N}";

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-tamper-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId, requestUri, compactJar, verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        //Attacker flips bits in segment 3 (ciphertext) before delivery to the Verifier.
        string tamperedJwe = TamperJweSegment(compactJwe, segmentIndex: 3);

        await Assert.ThrowsExactlyAsync<System.Security.Cryptography.AuthenticationTagMismatchException>(
            async () => await app.HandleDirectPostAsync(verifierKeys,
                parHandle,
                tamperedJwe,
                redirectUri: null,
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    //Security: JAR signature verification.
    //
    //A JAR signed with the correct key must verify. A JAR signed with a
    //different key must not verify. This test exercises signature verification
    //independently of the full flow to isolate the cryptographic boundary.

    [TestMethod]
    public async Task JarSignatureVerifiesWithCorrectKeyAndFailsWithWrongKey()
    {
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(
                VerifierClientId,
                /*lang=json,strict*/ "{\"keys\":[]}");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: VerifierClientId,
                responseUri: new Uri(VerifierBaseUri, "/cb"),
                nonce: "nonce-sig-01",
                dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                clientMetadata: clientMetadata,
                state: "state-sig-01",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> correctKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory correctPublicKey = correctKeys.PublicKey;
        using PrivateKeyMemory correctPrivateKey = correctKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongPublicKey = wrongKeys.PublicKey;
        wrongKeys.PrivateKey.Dispose();

        using SignedJar signedJar = await requestObject.SignJarAsync(
            correctPrivateKey,
            header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions),
            payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions),
            q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool validWithCorrectKey = await Jws.VerifyAsync(
            signedJar.Message, TestSetup.Base64UrlEncoder, correctPublicKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        bool validWithWrongKey = await Jws.VerifyAsync(
            signedJar.Message, TestSetup.Base64UrlEncoder, wrongPublicKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(validWithCorrectKey,
            "JAR must verify successfully with the key that signed it.");
        Assert.IsFalse(validWithWrongKey,
            "JAR must not verify with a different key.");
    }


    //request_uri_method=post + wallet_nonce — OID4VP 1.0 §5.10.
    //
    //The Wallet POSTs to request_uri carrying wallet_nonce; the Verifier echoes
    //the nonce as a claim in the signed JAR for replay-binding. PDA-wise this
    //adds an intermediate state on each side:
    //  - Wallet:   RequestUriReceived → WalletNonceSent → JarParsed → ...
    //  - Verifier: VerifierParReceived → VerifierWalletPostReceived → VerifierJarServed → ...
    //  The verifier intermediate state's NextAction is SignJarAction with the
    //  wallet_nonce, so the effect loop produces ServerJarSigned and steps to
    //  VerifierJarServed automatically.
    //The test drives both PDAs end-to-end through this path and asserts that
    //the JAR's wallet_nonce echo equals what the Wallet sent.

    [TestMethod]
    public async Task RequestUriMethodPostWithWalletNonceBothPdasReachAcceptState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-post-{Guid.NewGuid():N}";
        string walletNonce = $"walletnonce-{Guid.NewGuid():N}";


        //Step 1: Verifier — PAR. Same as the GET path.
        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-postjar-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierParReceivedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must be in VerifierParReceived after PAR.");


        //Step 2: Wallet — QR scan / deep link.
        wallet.HandleQrScan(requestUri, walletFlowId);

        Assert.IsInstanceOfType<RequestUriReceived>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must be in RequestUriReceived after QR scan.");


        //Step 3: Wallet — POST to request_uri with wallet_nonce.
        //Wallet PDA: RequestUriReceived -> WalletNonceSent.
        await wallet.HandleWalletPostAsync(
            walletFlowId,
            requestUri,
            walletNonce,
            TestContext.CancellationToken).ConfigureAwait(false);

        WalletNonceSent walletNonceSent = (WalletNonceSent)wallet.GetFlowState(walletFlowId).State;
        Assert.AreEqual(walletNonce, walletNonceSent.WalletNonce,
            "WalletNonceSent must carry the nonce the Wallet just sent.");


        //=== Wire boundary: wallet_nonce crosses to the Verifier. ===


        //Step 4: Verifier — POST /request/{token} with wallet_nonce.
        //Verifier PDA: VerifierParReceived -> VerifierWalletPostReceived,
        //then the effect loop runs SignJarAction (with wallet_nonce echo)
        //and steps to VerifierJarServed.
        string compactJar = await app.HandleJarRequestPostAsync(
            verifierKeys,
            parHandle,
            walletNonce,
            walletMetadataJson: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierJarServedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must reach VerifierJarServed after the effect-loop wallet POST → JAR sign sequence.");


        //=== Wire boundary: compact JAR crosses back to the Wallet. ===


        //Step 5: Wallet — JAR processing + echo verification.
        //Wallet PDA: WalletNonceSent -> JarParsed -> DcqlEvaluated -> PresentationBuilt.
        //HandleJarFetchAsync verifies the JAR's wallet_nonce echoes what was sent
        //in step 3; mismatch throws InvalidOperationException.
        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        PresentationBuilt presentationBuilt =
            (PresentationBuilt)wallet.GetFlowState(walletFlowId).State;
        Assert.AreEqual(walletNonce, presentationBuilt.Request.WalletNonce,
            "JAR served in response to the POST must carry the wallet_nonce echo.");


        //Step 6: Wallet — post the encrypted response and complete the flow.
        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must reach ResponseSent (terminal accept).");


        //Step 7: Verifier — direct_post receives the JWE and verifies the VP token.
        PresentationVerifiedState verified = await app.HandleDirectPostAsync(verifierKeys,
            parHandle,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must reach PresentationVerified (terminal accept).");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");

        //The Verifier PDA crossed five transitions on the POST path:
        //  (1) sentinel -> VerifierParReceived
        //  (2) VerifierParReceived -> VerifierWalletPostReceived
        //  (3) VerifierWalletPostReceived -> VerifierJarServed (via effect-loop SignJarAction)
        //  (4) ResponsePosted -> VerifierResponseReceived
        //  (5) VerificationSucceeded -> PresentationVerified
        Assert.AreEqual(5, app.GetFlowState(parHandle).StepCount,
            "Verifier PDA must traverse exactly five transitions on the request_uri_method=post path.");
    }


    //transaction_data — OID4VP 1.0 §8.4.
    //
    //The Verifier sends a base64url-encoded JSON descriptor in the JAR's
    //transaction_data array. The Wallet hashes each entry (ASCII bytes of the
    //base64url string) and binds the resulting SHA-256 base64url digests into
    //the KB-JWT's transaction_data_hashes claim. The test:
    //  1. Builds a JAR carrying one transaction_data descriptor via HaipProfile
    //     (bypasses the server's PAR/JAR pipeline — server-side enforcement is
    //     tracked separately).
    //  2. Drives the Wallet end-to-end through the JAR.
    //  3. Decrypts the JWE locally (the test owns the encryption private key)
    //     and inspects the wallet-issued KB-JWT.
    //  4. Asserts the bound transaction_data_hashes match the verifier's
    //     recomputation via TransactionDataHasher, and exercises the matching
    //     check ValidationChecks.CheckKbJwtTransactionDataHashes.

    [TestMethod]
    public async Task TransactionDataHashBoundIntoKeyBindingJwt()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        //Issue a credential the Wallet will present.
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;

        //Verifier JAR-signing key pair (P-256 ES256).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verifierSigningPublicKey = verifierSigningKeys.PublicKey;
        using PrivateKeyMemory verifierSigningPrivateKey = verifierSigningKeys.PrivateKey;

        //Verifier ECDH-ES encryption key pair for the response JWE.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierEncryptionKeys =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory verifierEncryptionPublicKey = verifierEncryptionKeys.PublicKey;
        using PrivateKeyMemory verifierEncryptionPrivateKey = verifierEncryptionKeys.PrivateKey;

        string jwksJson = EphemeralEncryptionKeyPair.CreatePublicKeyJwks(
            verifierEncryptionPublicKey,
            TestSetup.Base64UrlEncoder,
            Pool);

        //Build one transaction_data descriptor: a payment authorisation bound
        //to the requested credential. The wire form is base64url(JSON(descriptor));
        //the Wallet hashes that exact ASCII string into the KB-JWT.
        Dictionary<string, object> descriptor = new(StringComparer.Ordinal)
        {
            [TransactionDataClaimNames.Type] = "payment_authorization",
            [TransactionDataClaimNames.CredentialIds] = new List<object> { "pid" }
        };
        byte[] descriptorJsonBytes = JsonSerializer.SerializeToUtf8Bytes(
            descriptor, TestSetup.DefaultSerializationOptions);
        string descriptorB64 = TestSetup.Base64UrlEncoder(descriptorJsonBytes);

        IReadOnlyList<string> transactionData = new[] { descriptorB64 };

        //Build and sign the JAR. The wallet will pull TransactionData from the
        //parsed JAR and feed it through to KbJwtIssuance.
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(VerifierClientId, jwksJson);

        Uri responseUri = new(VerifierBaseUri, "/cb");
        string state = $"state-tx-{Guid.NewGuid():N}";
        string nonce = $"nonce-tx-{Guid.NewGuid():N}";

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: VerifierClientId,
                responseUri: responseUri,
                nonce: nonce,
                dcqlQuery: DcqlFixtures.PidGivenAndFamilyName(),
                clientMetadata: clientMetadata,
                state: state,
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime,
                transactionData: transactionData);

        JwtHeaderSerializer jwtHeaderSerializer =
            static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);
        JwtPayloadSerializer jwtPayloadSerializer =
            static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierSigningPrivateKey,
            headerSerializer: jwtHeaderSerializer,
            payloadSerializer: jwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, TestSetup.Base64UrlEncoder);


        //=== Wallet side ===

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { ["pid"] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-tx-{Guid.NewGuid():N}";
        Uri requestUri = new(VerifierBaseUri, "/request/tx-token");

        wallet.HandleQrScan(requestUri, walletFlowId);
        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierSigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Sanity: TransactionData must have round-tripped via ParseJar onto the
        //request the wallet stored in PresentationBuilt.
        PresentationBuilt presentationBuilt =
            (PresentationBuilt)wallet.GetFlowState(walletFlowId).State;
        Assert.IsNotNull(presentationBuilt.Request.TransactionData,
            "ParseJar must have populated TransactionData from the signed JAR.");
        CollectionAssert.AreEqual(
            transactionData.ToArray(),
            presentationBuilt.Request.TransactionData.ToArray(),
            "TransactionData must round-trip through the JAR exactly — hash inputs depend on byte equality.");

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must reach ResponseSent after posting the response.");


        //=== Verifier side: decrypt, inspect, assert ===

        //Decrypt the JWE locally — the test owns the verifier's encryption private key.
        string jweHeader = compactJwe[..compactJwe.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(jweHeader, Pool);
        string? enc = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "enc"u8);
        Assert.IsNotNull(enc, "JWE protected header must carry 'enc'.");

        using AeadMessage parsedJwe = JweParsing.ParseCompact(
            compactJwe,
            WellKnownJweAlgorithms.EcdhEs,
            enc,
            TestSetup.Base64UrlDecoder,
            Pool);

        using DecryptedContent decrypted = await parsedJwe.DecryptAsync(
            verifierEncryptionPrivateKey,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //OID4VP 1.0 §8.1 vp_token: keys are DCQL credential query ids, values
        //are arrays of compact presentations. The decrypted response is the
        //authorization response object {"vp_token":{...},...}, so slice the
        //vp_token object out first (as the production verifier does) before
        //reading the per-query "pid" array — a query id is nested under
        //vp_token, not a top-level member.
        string? vpTokenJson = JwkJsonReader.ExtractObjectAsString(
            decrypted.AsReadOnlySpan(), "vp_token"u8);
        Assert.IsNotNull(vpTokenJson, "Decrypted response must carry a vp_token object.");

        string? compactPresentation = JwkJsonReader.ExtractFirstStringFromArrayProperty(
            Encoding.UTF8.GetBytes(vpTokenJson), Encoding.UTF8.GetBytes("pid"));
        Assert.IsNotNull(compactPresentation,
            "Decrypted vp_token must contain a 'pid' credential presentation.");

        //Use the production extraction path to surface the bound hashes.
        PublicKeyMemory? IssuerLookup(string iss) =>
            string.Equals(iss, IssuerId, StringComparison.Ordinal) ? issuerKey : null;

        VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
            compactPresentation,
            "pid",
            static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            IssuerLookup,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            saltReuseSeam: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(parsed.KbJwtTransactionDataHashes,
            "KB-JWT must carry transaction_data_hashes when the JAR carried transaction_data.");
        Assert.HasCount(1, parsed.KbJwtTransactionDataHashes!,
            "Exactly one entry was sent and exactly one hash must come back.");

        //Verifier's own recomputation must positionally match.
        IReadOnlyList<string> expectedHashes = await TransactionDataHasher.ComputeSha256Async(
            transactionData,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedHashes[0], parsed.KbJwtTransactionDataHashes[0],
            "Bound hash must equal SHA-256(ASCII(base64url-descriptor)) per OID4VP 1.0 §8.4.");

        //Exercise the matching check the validation pipeline will use once
        //executor enforcement is wired (tracked separately).
        ValidationContext vc = new()
        {
            Context = new ExchangeContext(),
            Now = now,
            KbJwtTransactionDataHashes = parsed.KbJwtTransactionDataHashes,
            ExpectedTransactionDataHashes = expectedHashes
        };

        List<Claim> claims = await ValidationChecks.CheckKbJwtTransactionDataHashes(
            vc, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome,
            "Matching arrays must produce a successful claim.");

        //And conversely, a tampered hash must fail the check.
        ValidationContext vcBad = vc with
        {
            ExpectedTransactionDataHashes = new[] { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
        };

        List<Claim> badClaims = await ValidationChecks.CheckKbJwtTransactionDataHashes(
            vcBad, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Failure, badClaims[0].Outcome,
            "A mismatched expected hash must produce a failure claim.");
    }


    //transaction_data — OID4VP 1.0 §8.4 — server-side executor enforcement.
    //
    //The TransactionDataHashBoundIntoKeyBindingJwt test above proves the wallet
    //binds the hashes correctly, bypassing the server-side state machine. This
    //test exercises the full server flow: the application places transaction_data
    //on the request context before HandleParAsync; it threads through
    //VerifierParReceivedState → VerifierJarServedState → VerifierResponseReceivedState
    //into DecryptResponseAction. The executor recomputes expected hashes via
    //TransactionDataHasher, populates ValidationContext.ExpectedTransactionDataHashes,
    //and the HAIP profile's CheckKbJwtTransactionDataHashes runs as part of
    //verification — failing the flow when the wallet's KB-JWT echo is wrong.

    [TestMethod]
    public async Task TransactionDataServerSideEnforcementReachesAccept()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Build one transaction_data descriptor — the verifier-side wire form.
        Dictionary<string, object> descriptor = new(StringComparer.Ordinal)
        {
            [TransactionDataClaimNames.Type] = "payment_authorization",
            [TransactionDataClaimNames.CredentialIds] = new List<object> { "pid" }
        };
        byte[] descriptorJsonBytes = JsonSerializer.SerializeToUtf8Bytes(
            descriptor, TestSetup.DefaultSerializationOptions);
        string descriptorB64 = TestSetup.Base64UrlEncoder(descriptorJsonBytes);
        IReadOnlyList<string> transactionData = new[] { descriptorB64 };


        //Step 1: PAR with transaction_data on the request context.
        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-tx-srv-01"),
            CreatePreparedQuery(),
            transactionData,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Sanity: the state must have carried transaction_data through.
        VerifierParReceivedState parState = (VerifierParReceivedState)app.GetFlowState(parHandle).State;
        Assert.IsNotNull(parState.TransactionData,
            "VerifierParReceivedState must record TransactionData from the request context.");


        //Step 2: Wallet HTTP GET request_uri — Kestrel serves the signed JAR
        //carrying the transaction_data descriptors in the protected claims.
        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        VerifierJarServedState jarState = (VerifierJarServedState)app.GetFlowState(parHandle).State;
        Assert.IsNotNull(jarState.TransactionData,
            "VerifierJarServedState must carry TransactionData forward to verification.");


        //Step 3: Wallet drives the full presentation. PresentJarAsync parses the
        //JAR's transaction_data, binds the SHA-256 hashes into the KB-JWT, and
        //POSTs the JWE over real HTTP. The verifier's executor recomputes the
        //expected hashes and CheckKbJwtTransactionDataHashes runs against them;
        //reaching PresentationVerified means the round-trip succeeded.
        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-tx-srv-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Reaching PresentationVerified end-to-end means the executor's " +
            "transaction_data hash check passed alongside every other HAIP rule.");


        //Negative path: a different flow where the wallet's bound hashes do
        //NOT match the verifier's expectation must fail. The Failure path is
        //covered at the ValidationContext level inside
        //TransactionDataHashBoundIntoKeyBindingJwt above; this test focuses on
        //the happy-path wire-up.
    }


    //Federation HTTP-wire E2E (interim, pre-/.well-known/openid-federation).
    //
    //The Verifier's JAR signing key is shared between two places:
    //  (1) the AS registration (RegisterJarSigningClient — the AS executor
    //      reads it for SignJarAction);
    //  (2) the federation chain's leaf EC under chain[0].jwks (FederationTest-
    //      Ring.CreateNodeFromKey constructs the leaf node from the same
    //      PrivateKeyMemory so the published JWK derives from the same scalar).
    //
    //The chain is carried inline in the JAR's trust_chain JOSE header via the
    //AS executor's jarAdditionalHeaderClaims plumbing (commit 79dcb49).
    //
    //The interim test scope (full §3c gets two real Kestrels once §3e ships
    //the /.well-known/openid-federation endpoint):
    //  - TestHostShell owns two HostedAuthorizationServers via AddHost; only
    //    the Verifier serves HTTP for now. The anchor host scaffolds the
    //    multi-host shape for §3e.
    //  - PAR + JAR-fetch + direct_post all over real HTTP via the Kestrel
    //    listener.
    //  - The Wallet validates the inline trust_chain via
    //    FederationBoundJarKeyResolver and asserts the chain-resolved key
    //    equals the AS's registered JAR-signing public key — the key
    //    alignment that links the federation surface to the AS pipeline.

    [TestMethod]
    public async Task FederationTrustChainInlineInJarHeaderOverHttpReachesAccept()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        await using TestHostShell app = new(TimeProvider);

        //Scaffolding-only for §3c-interim — the anchor host has its own
        //per-host state container but does not serve HTTP yet (its Kestrel
        //starts once §3e wires /.well-known/openid-federation). Adding the
        //host here proves the multi-host orchestration extracted in §3a.
        HostedAuthorizationServer anchorHost = app.AddHost("anchor");

        //Signing keypair shared between the AS registration and the federation
        //chain's leaf jwks. CreateFreshP256KeyMaterial owns the buffers;
        //RegisterJarSigningClient takes ownership for the AS lifetime.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial verifierKeys = app.RegisterJarSigningClient(
            VerifierClientId, VerifierBaseUri, verifierSigningKeyPair, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //Mint the federation chain. The verifier subject node derives from the
        //SAME P-256 scalar the AS registration uses; the leaf EC's jwks
        //therefore publishes the exact public key the AS signs the JAR with.
        using FederationTestRingNode verifierNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(VerifierClientId), verifierKeys.SigningPrivateKey);
        using FederationTestRingNode anchorNode = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.com"));

        MintedChain mintedChain = await FederationTestRing.BuildDirectChainAsync(
            verifierNode, anchorNode, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        //HTTP-backed wallet (starts the verifier's Kestrel + aligns issuer/
        //response URIs to the listener authority).
        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //PAR with the federation chain inline in the JAR's trust_chain JOSE
        //header. The AS executor's additionalHeaderClaims path merges these
        //claims into the JOSE header at sign time (commit 79dcb49).
        JwtHeader jarAdditionalHeaderClaims = new()
        {
            [WellKnownFederationClaimNames.TrustChain] = new List<object>(mintedChain.CompactJwsByPosition)
        };

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-fed-http-01"),
            CreatePreparedQuery(),
            transactionData: null,
            jarAdditionalHeaderClaims: jarAdditionalHeaderClaims,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Wallet HTTP GET request_uri — Kestrel serves the JAR with the
        //inline trust_chain in its JOSE header.
        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Wallet parses the JAR header, extracts trust_chain, runs the chain
        //validation orchestration, and resolves the verifier's JAR signing
        //key from chain[0].jwks.
        using UnverifiedJwsMessage unverifiedJar = JwsParsing.ParseCompact(
            compactJar,
            TestSetup.Base64UrlDecoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);
        UnverifiedJwtHeader jarHeader = unverifiedJar.Signatures[0].ProtectedHeader;

        Assert.IsTrue(jarHeader.TryGetValue(WellKnownFederationClaimNames.TrustChain, out object? chainObj),
            "JAR header must carry trust_chain from additionalHeaderClaims.");

        List<string> walletChainValues = [];
        foreach(object entry in (IEnumerable<object>)chainObj!)
        {
            walletChainValues.Add((string)entry);
        }

        ValidateTrustChainAsyncDelegate validateChain =
            Tests.Federation.InlineTrustChainValidationDriver.Build(
                async (position, compactJws, ct) => position switch
                {
                    0 => await FederationTestRing.VerifyAsync(verifierNode, compactJws, ct).ConfigureAwait(false),
                    _ => await FederationTestRing.VerifyAsync(anchorNode, compactJws, ct).ConfigureAwait(false),
                });

        using PublicKeyMemory chainResolvedVerifierKey = await FederationBoundJarKeyResolver.ResolveAsync(
            walletChainValues,
            verifierNode.Identifier,
            new[] { anchorNode.Identifier },
            now,
            TimeSpan.FromMinutes(5),
            jarHeader,
            validateChain,
            TestSetup.Base64UrlDecoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Key alignment proof: the chain-resolved verifier key must equal the
        //public side of the keypair the AS uses to sign the JAR.
        Assert.IsTrue(
            chainResolvedVerifierKey.AsReadOnlySpan().SequenceEqual(
                verifierKeys.SigningPublicKey.AsReadOnlySpan()),
            "chain[0].jwks must publish the same public key the AS uses for " +
            "JAR signing — the federation surface and the AS pipeline share " +
            "one trust-anchored key.");

        //Wallet drives the full presentation over real HTTP, verifying the
        //JAR signature against the chain-resolved key. The wallet client's
        //direct_post POST goes over the wire to the verifier's Kestrel.
        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-fed-http-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after the federation-bound HTTP wire E2E.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verifier must reach PresentationVerified with the pid credential.");

        //Multi-host scaffolding sanity — the anchor host is reachable via
        //Host(name) lookup; §3e plugs the well-known endpoint here.
        Assert.AreSame(anchorHost, app.Host("anchor"),
            "AddHost must register the anchor host for federation-endpoint wiring " +
            "the wallet test reaches via Host(name).");
    }


    //Federation HTTP-wire E2E with two Kestrels (verifier + anchor) —
    //all three chain links fetched over the wire.
    //
    //Composes §3a (multi-host), §3e (well-known EC endpoint), and the
    //§8.1 federation_fetch_endpoint to drive a complete federation
    //topology entirely over HTTP. Differs from the §3c interim shape:
    //
    //  - Anchor host now carries BOTH PublishEntityConfiguration AND
    //    PublishSubordinateStatement capabilities. Its EC publishes a
    //    federation_fetch_endpoint URL in metadata.federation_entity;
    //    its federation_fetch endpoint signs Subordinate Statements
    //    about its subordinates on demand.
    //  - The wallet fetches all three chain elements over HTTP from
    //    their respective Kestrels: verifier EC from default host,
    //    anchor EC from anchor host, and the SS from the anchor's
    //    federation_fetch endpoint. Nothing in the JAR header is
    //    pre-minted in-test.

    [TestMethod]
    public async Task FederationChainAcrossTwoKestrelsReachesAccept()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        await using TestHostShell app = new(TimeProvider);
        HostedAuthorizationServer anchorHost = app.AddHost("anchor");

        //Both hosts run real Kestrels — the multi-host orchestration each
        //has its own ephemeral port + HttpClient.
        await app.StartHttpHostAsync("default", TestContext.CancellationToken).ConfigureAwait(false);
        await app.StartHttpHostAsync("anchor", TestContext.CancellationToken).ConfigureAwait(false);

        //Issue the credential the wallet will present.
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //Verifier registration on the default host: OID4VP + federation
        //publishing share one P-256 federation-signing keypair the chain
        //leaf will publish.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        Uri verifierEntityId = new("https://verifier.example.com");

        using VerifierKeyMaterial verifierKeys = app.RegisterFederationCapableClient(
            clientId: VerifierClientId,
            baseUri: VerifierBaseUri,
            federationEntityId: verifierEntityId,
            federationSigningKeyPair: verifierFederationKeys,
            baseCapabilities: Oid4VpCapabilities);

        //Anchor registration on the anchor host with BOTH federation
        //capabilities — publishes its own EC and serves Subordinate
        //Statements about its subordinates via federation_fetch_endpoint.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        Uri anchorEntityId = new("https://anchor.example.com");

        ImmutableHashSet<CapabilityIdentifier> anchorBaselineCapabilities =
            ImmutableHashSet.Create(WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement);

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClientOnHost(
            hostName: "anchor",
            clientId: anchorEntityId.ToString(),
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: anchorFederationKeys,
            baseCapabilities: anchorBaselineCapabilities);

        //Align the anchor's registration to its own Kestrel base — the
        //ResolveEndpointUriAsync delegate composes URLs from
        //registration.IssuerUri.Authority. The verifier is aligned
        //automatically by CreateHttpBackedOid4VpWalletClientAsync below.
        anchorKeys.Registration = app.AlignRegistrationToHostHttpBase("anchor", anchorKeys.Registration);

        //Anchor metadata: publish the federation_fetch_endpoint URL in
        //metadata.federation_entity. A real wallet parses this off the
        //fetched anchor EC; this test composes the URL directly below for
        //brevity but the metadata is published so the wire shape is correct.
        string anchorSegment = anchorKeys.Registration.TenantId.Value;
        Uri anchorFederationFetchUrl = new(anchorHost.HttpBaseAddress!,
            $"/connect/{anchorSegment}/federation_fetch");

        anchorHost.Server.OAuth().ContributeFederationMetadataAsync = (_, _, _) =>
            ValueTask.FromResult(new FederationEntityConfigurationContribution
            {
                Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                {
                    [WellKnownEntityTypeIdentifiers.FederationEntity] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["federation_fetch_endpoint"] = anchorFederationFetchUrl.ToString()
                    }
                }
            });

        //Anchor's federation_fetch handler — emits a Subordinate Statement
        //whose jwks publishes the verifier's federation signing key when
        //the queried subject matches; null otherwise (the endpoint then
        //returns 404).
        Dictionary<string, object> verifierSubjectJwks =
            BuildSingleEcKeyJwks(verifierFederationKeys.PublicKey);
        anchorHost.Server.OAuth().ResolveSubordinateStatementAsync = (subject, _, _, _) =>
        {
            if(!string.Equals(subject.Value, verifierEntityId.ToString(), StringComparison.Ordinal))
            {
                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            }

            return ValueTask.FromResult<SubordinateStatementContribution?>(
                new SubordinateStatementContribution
                {
                    Jwks = verifierSubjectJwks
                });
        };

        //Wallet fetches all three chain elements over HTTP — verifier EC
        //from default host, anchor EC and SS from anchor host.
        Uri verifierEcUrl = new(app.Host("default").HttpBaseAddress!,
            $"/connect/{verifierKeys.Registration.TenantId.Value}/.well-known/openid-federation");
        Uri anchorEcUrl = new(anchorHost.HttpBaseAddress!,
            $"/connect/{anchorSegment}/.well-known/openid-federation");
        Uri anchorSsUrl = new(anchorHost.HttpBaseAddress!,
            $"/connect/{anchorSegment}/federation_fetch?sub={Uri.EscapeDataString(verifierEntityId.ToString())}");

        using System.Net.Http.HttpResponseMessage verifierEcResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(verifierEcUrl, TestContext.CancellationToken).ConfigureAwait(false);
        verifierEcResponse.EnsureSuccessStatusCode();
        string fetchedVerifierEc = await verifierEcResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using System.Net.Http.HttpResponseMessage anchorEcResponse = await anchorHost.SharedHttpClient!
            .GetAsync(anchorEcUrl, TestContext.CancellationToken).ConfigureAwait(false);
        anchorEcResponse.EnsureSuccessStatusCode();
        string fetchedAnchorEc = await anchorEcResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using System.Net.Http.HttpResponseMessage ssResponse = await anchorHost.SharedHttpClient!
            .GetAsync(anchorSsUrl, TestContext.CancellationToken).ConfigureAwait(false);
        ssResponse.EnsureSuccessStatusCode();
        string fetchedSubordinateStatement = await ssResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Ring nodes — present here only to drive the chain validator's
        //per-link signature verification. Their internal ECDsa shares
        //scalars with the AS-side federation signing keys, so signatures
        //produced by either path verify identically.
        using FederationTestRingNode verifierNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(verifierEntityId.ToString()),
            verifierFederationKeys.PrivateKey);
        using FederationTestRingNode anchorNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(anchorEntityId.ToString()),
            anchorFederationKeys.PrivateKey);

        //Wallet sets up its presentation infrastructure. The JAR header
        //carries [fetched verifier EC, fetched SS, fetched anchor EC] —
        //all three came over the wire from their respective endpoints.
        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        List<string> trustChainHeader = [fetchedVerifierEc, fetchedSubordinateStatement, fetchedAnchorEc];

        JwtHeader jarAdditionalHeaderClaims = new()
        {
            [WellKnownFederationClaimNames.TrustChain] = new List<object>(trustChainHeader)
        };

        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-fed-2k-01"),
            CreatePreparedQuery(),
            transactionData: null,
            jarAdditionalHeaderClaims: jarAdditionalHeaderClaims,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Wallet HTTP GET request_uri — verifier Kestrel serves the JAR with
        //the chain header.
        using System.Net.Http.HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Independent chain validation using FederationBoundJarKeyResolver
        //against the trust_chain the JAR carries. The resolved verifier
        //signing key must equal the AS's registered JAR-signing public key.
        using UnverifiedJwsMessage unverifiedJar = JwsParsing.ParseCompact(
            compactJar,
            TestSetup.Base64UrlDecoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);
        UnverifiedJwtHeader jarHeader = unverifiedJar.Signatures[0].ProtectedHeader;

        Assert.IsTrue(jarHeader.TryGetValue(WellKnownFederationClaimNames.TrustChain, out object? chainObj),
            "JAR header must carry trust_chain.");

        List<string> walletChainValues = [];
        foreach(object entry in (IEnumerable<object>)chainObj!)
        {
            walletChainValues.Add((string)entry);
        }

        ValidateTrustChainAsyncDelegate validateChain =
            Tests.Federation.InlineTrustChainValidationDriver.Build(
                async (position, compactJws, ct) => position switch
                {
                    0 => await FederationTestRing.VerifyAsync(verifierNode, compactJws, ct).ConfigureAwait(false),
                    _ => await FederationTestRing.VerifyAsync(anchorNode, compactJws, ct).ConfigureAwait(false),
                });

        //Chain validation produces the verifier's federation signing key
        //(chain[0].jwks). RegisterFederationCapableClient keeps the
        //federation signing key separate from the OID4VP JAR signing key
        //by design — chain validation here proves the wire-fetched chain
        //is structurally sound, and the chain-resolved key must equal the
        //federation signing public key the AS materialises through its
        //VerificationKeyResolver under KeyUsageContext.FederationEntitySignature.
        using PublicKeyMemory chainResolvedFederationKey = await FederationBoundJarKeyResolver.ResolveAsync(
            walletChainValues,
            verifierNode.Identifier,
            new[] { anchorNode.Identifier },
            now,
            TimeSpan.FromMinutes(5),
            jarHeader,
            validateChain,
            TestSetup.Base64UrlDecoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            chainResolvedFederationKey.AsReadOnlySpan().SequenceEqual(
                verifierFederationKeys.PublicKey.AsReadOnlySpan()),
            "chain[0].jwks fetched from the verifier Kestrel must publish the " +
            "federation signing public key registered under " +
            "KeyUsageContext.FederationEntitySignature.");

        //Wallet drives the full presentation over real HTTP. The chain
        //elements were fetched off two different Kestrels; the JWE POST
        //goes back to the verifier Kestrel through the wallet client's
        //HTTP-backed infrastructure. JAR signature verification uses the
        //verifier's OID4VP JAR signing key (separate from the federation
        //signing key the chain published).
        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-fed-2k-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after two-Kestrel federation HTTP wire E2E.");

        PresentationVerifiedState verified2k = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified2k.Claims.ContainsKey("pid"),
            "Verifier must reach PresentationVerified with the pid credential.");

        //The two hosts ran on independent ephemeral ports — confirm the
        //multi-host startup actually allocated distinct listeners.
        Assert.AreNotEqual(
            app.Host("default").HttpBaseAddress!.Port,
            anchorHost.HttpBaseAddress!.Port,
            "Verifier and anchor must bind to different ephemeral ports.");
    }


    private static Dictionary<string, object> BuildSingleEcKeyJwks(PublicKeyMemory publicKey)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            publicKey.Tag.Get<CryptoAlgorithm>(),
            publicKey.Tag.Get<Verifiable.Cryptography.Context.Purpose>(),
            publicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        jwk.Use = WellKnownJwkValues.UseSig;

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = new List<object> { jwk }
        };
    }


    //direct_post unencrypted — OID4VP 1.0 §8.2.
    //
    //Sibling to the encrypted direct_post.jwt cross-device test at the top
    //of this file. The Verifier advertises response_mode=direct_post in the
    //JAR (overriding HAIP 1.0's mandated direct_post.jwt); the Wallet POSTs
    //the vp_token JSON verbatim in the vp_token form field; the
    //BuildOid4VpDirectPostUnencrypted matcher routes the request to a
    //sibling PDA path that produces ProcessVpTokenAction instead of
    //DecryptResponseAction. The shared post-decryption verification logic
    //then advances the flow to PresentationVerified.

    [TestMethod]
    public async Task DirectPostUnencryptedBothPdasReachAcceptState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        //PAR with response_mode=direct_post — the executor threads the
        //override into the JAR's response_mode claim. The wallet client
        //will dispatch on that claim and skip JWE encryption.
        (Uri requestUri, string parHandle) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-direct-post-01"),
            CreatePreparedQuery(),
            transactionData: null,
            jarAdditionalHeaderClaims: null,
            responseMode: WellKnownResponseModes.DirectPost,
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Wallet drives the full presentation. The Oid4VpWalletClient
        //dispatches on request.ResponseMode read from the parsed JAR — it
        //POSTs vp_token=<JSON> + state=<token> in form-urlencoded body
        //instead of response=<JWE> + state.
        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-direct-post-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after the unencrypted direct_post POST.");

        //The result's response artifact is the plaintext vp_token JSON
        //object (not a compact JWE). A JSON object starts with '{'; a JWE
        //starts with base64url(JSON header) which always begins with 'ey'.
        Assert.IsTrue(result.PostedResponseArtifact.StartsWith('{'),
            "Wallet response artifact must be a JSON object for response_mode=direct_post, " +
            $"got: {result.PostedResponseArtifact[..Math.Min(40, result.PostedResponseArtifact.Length)]}");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verifier must reach PresentationVerified after the unencrypted POST.");
        Assert.IsNull(verified.RedirectUri,
            "Cross-device direct_post (unencrypted) must not carry a redirect_uri.");
    }


    //RFC 6749 §3.1.2 query response mode — the wallet returns a redirect
    //URL pointing at response_uri with vp_token and state appended as query
    //parameters. No HTTP POST happens; the calling application owns the
    //user-agent navigation. Wire-shape test: assert the URL is built
    //correctly and the wallet PDA reaches ResponseSent.

    [TestMethod]
    public async Task QueryResponseModeBuildsRedirectUrlWithVpTokenAndState()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        ClientRecord alignedRegistration =
            app.Host("default").Registrations[verifierKeys.Registration.TenantId.Value];
        Uri responseUri = alignedRegistration.ResponseUri!;
        string clientIdRedirectUri =
            $"{WellKnownClientIdPrefixes.RedirectUri.Value}:{responseUri.OriginalString}";

        DcqlQuery dcqlQuery = CreateDcqlQuery();
        string dcqlQueryJson = JsonSerializer.Serialize(
            dcqlQuery, TestSetup.DefaultSerializationOptions);

        const string StateValue = "state-query-01";
        Dictionary<string, string> inlineParameters = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = clientIdRedirectUri,
            [OAuthRequestParameterNames.ResponseType] =
                Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] = WellKnownResponseModes.Query,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] =
                responseUri.OriginalString,
            [WellKnownJwtClaimNames.Nonce] = "nonce-query-01",
            [OAuthRequestParameterNames.State] = StateValue,
            [Oid4VpAuthorizationRequestParameterNames.DcqlQuery] = dcqlQueryJson
        };

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = null,
                RequestUri = responseUri,
                ExpectedVerifierClientId = clientIdRedirectUri,
                InlineAuthorizationParameters = inlineParameters,
                FlowId = $"wallet-query-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after composing the query-mode redirect URL.");

        //The artifact is the redirect URL the calling application would
        //navigate the user-agent to. It carries vp_token + state in the
        //query string, percent-encoded.
        Assert.IsTrue(result.PostedResponseArtifact.StartsWith(responseUri.OriginalString,
            StringComparison.Ordinal),
            "Redirect URL must start with the response_uri.");
        Assert.Contains($"&state={StateValue}",
            result.PostedResponseArtifact, StringComparison.Ordinal);
        Assert.Contains(
            $"{AuthorizationResponseParameters.VpToken}=",
            result.PostedResponseArtifact, StringComparison.Ordinal);
        Assert.IsFalse(result.PostedResponseArtifact.Contains('#', StringComparison.Ordinal),
            "Query-mode URL must not carry a fragment separator.");
    }


    //OIDC Core §3.1.2.4 fragment response mode — same shape as query but
    //parameters land after a `#` separator. Common in browser-based
    //implicit-style flows where the wallet returns the response in the
    //URL fragment so the browser doesn't send it to the server on the
    //next navigation.

    [TestMethod]
    public async Task FragmentResponseModeBuildsRedirectUrlWithFragmentSeparator()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient =
            await app.CreateHttpBackedOid4VpWalletClientAsync(
                verifierKeys,
                serializedSdJwt,
                holderKey,
                TestContext.CancellationToken).ConfigureAwait(false);

        ClientRecord alignedRegistration =
            app.Host("default").Registrations[verifierKeys.Registration.TenantId.Value];
        Uri responseUri = alignedRegistration.ResponseUri!;
        string clientIdRedirectUri =
            $"{WellKnownClientIdPrefixes.RedirectUri.Value}:{responseUri.OriginalString}";

        DcqlQuery dcqlQuery = CreateDcqlQuery();
        string dcqlQueryJson = JsonSerializer.Serialize(
            dcqlQuery, TestSetup.DefaultSerializationOptions);

        const string StateValue = "state-fragment-01";
        Dictionary<string, string> inlineParameters = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = clientIdRedirectUri,
            [OAuthRequestParameterNames.ResponseType] =
                Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] = WellKnownResponseModes.Fragment,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] =
                responseUri.OriginalString,
            [WellKnownJwtClaimNames.Nonce] = "nonce-fragment-01",
            [OAuthRequestParameterNames.State] = StateValue,
            [Oid4VpAuthorizationRequestParameterNames.DcqlQuery] = dcqlQueryJson
        };

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = null,
                RequestUri = responseUri,
                ExpectedVerifierClientId = clientIdRedirectUri,
                InlineAuthorizationParameters = inlineParameters,
                FlowId = $"wallet-fragment-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after composing the fragment-mode redirect URL.");

        Assert.Contains("#", result.PostedResponseArtifact, StringComparison.Ordinal);
        Assert.Contains($"&state={StateValue}",
            result.PostedResponseArtifact, StringComparison.Ordinal);
        Assert.Contains(
            $"{AuthorizationResponseParameters.VpToken}=",
            result.PostedResponseArtifact, StringComparison.Ordinal);

        //Fragment placement: vp_token and state come AFTER the # separator.
        int hashIndex = result.PostedResponseArtifact.IndexOf('#', StringComparison.Ordinal);
        string afterHash = result.PostedResponseArtifact[(hashIndex + 1)..];
        Assert.Contains(
            $"{AuthorizationResponseParameters.VpToken}=",
            afterHash, StringComparison.Ordinal);
    }


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlFixtures.PidFamilyNamePrepared();


    private static string TamperJweSegment(string compactJwe, int segmentIndex)
    {
        string[] parts = compactJwe.Split('.');
        using IMemoryOwner<byte> decoded =
            TestSetup.Base64UrlDecoder(parts[segmentIndex], BaseMemoryPool.Shared);
        decoded.Memory.Span[0] ^= 0xFF;
        parts[segmentIndex] = TestSetup.Base64UrlEncoder(decoded.Memory.Span);
        return string.Join('.', parts);
    }


    /// <summary>
    /// Issues a PID SD-JWT VC with holder key binding. The issuer signs with P-256,
    /// the holder key is Ed25519 (bound via <c>cnf</c>). Returns the serialized SD-JWT
    /// without KB-JWT (the wallet adds the KB-JWT at presentation time), the holder
    /// private key for KB-JWT signing, and the issuer public key for credential
    /// signature verification by the verifier.
    /// </summary>
    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialAsync(
        CancellationToken cancellationToken)
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
                new(EudiPid.SdJwt.GivenName, "Erika"),
                new(EudiPid.SdJwt.FamilyName, "Mustermann")
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
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }
}
