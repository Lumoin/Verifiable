using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.Tests.TestDataProviders;
using System.Collections.Immutable;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

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
    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly ImmutableHashSet<ServerCapabilityName> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            ServerCapabilityName.VerifiablePresentation,
            ServerCapabilityName.JwksEndpoint,
            ServerCapabilityName.DiscoveryEndpoint);


    //=========================================================================
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
    //=========================================================================

    [TestMethod]
    public async Task CrossDeviceFlowBothPdasReachAcceptState()
    {
        using TestHostShell app = new(TimeProvider);
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

        string walletFlowId = $"wallet-{Guid.NewGuid():N}";


        //=====================================================================
        //Step 1: Verifier — PAR endpoint (POST /connect/{segment}/par).
        //The server validates inputs, generates request_uri and its opaque token, and
        //returns them to the Wallet. JAR signing is deferred.
        //PDA: sentinel -> VerifierParReceived.
        //=====================================================================

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-xdevice-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierParReceivedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must be in VerifierParReceived after PAR.");


        //=====================================================================
        //=== Wire boundary: request_uri crosses from Verifier to Wallet. ===
        //The Wallet receives request_uri in the PAR response body (same-device)
        //or via QR code / deep link (cross-device). Only a string crosses here.
        //=====================================================================


        //=====================================================================
        //Step 2: Wallet — QR scan / deep link.
        //The Wallet receives the request_uri and enters RequestUriReceived.
        //Wallet PDA: sentinel -> RequestUriReceived.
        //=====================================================================

        wallet.HandleQrScan(requestUri, walletFlowId);

        Assert.IsInstanceOfType<RequestUriReceived>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must be in RequestUriReceived after QR scan.");


        //=====================================================================
        //Step 3: Wallet -> Verifier — JAR request (GET /request/{requestUriToken}).
        //The Verifier signs the JAR on demand and returns the compact JWS.
        //PDA: VerifierParReceived + ServerJarSigned -> VerifierJarServed.
        //=====================================================================

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierJarServedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must be in VerifierJarServed after serving the JAR.");


        //=====================================================================
        //=== Wire boundary: compact JWS JAR crosses from Verifier to Wallet. ===
        //=====================================================================


        //=====================================================================
        //Step 4: Wallet — JAR processing.
        //The Wallet fetches, verifies, and processes the JAR: signature
        //verification, DCQL evaluation, disclosure selection, VP token assembly,
        //JWE encryption.
        //Wallet PDA: RequestUriReceived -> JarParsed -> DcqlEvaluated
        //            -> PresentationBuilt.
        //=====================================================================

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationBuilt>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must be in PresentationBuilt after JAR processing.");


        //=====================================================================
        //=== Wire boundary: compact JWE crosses from Wallet to Verifier. ===
        //Only the encrypted JWE string crosses — the plaintext VP token never
        //leaves the Wallet unencrypted.
        //=====================================================================

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must be in ResponseSent after posting the response.");

        Assert.AreEqual(4, wallet.GetFlowState(walletFlowId).StepCount,
            "Wallet PDA must traverse exactly four transitions in the cross-device flow.");


        //=====================================================================
        //Step 5: Verifier — direct_post endpoint (POST /connect/{segment}/cb).
        //The Verifier receives the JWE, decrypts it, verifies the VP token,
        //and advances to PresentationVerified.
        //PDA: VerifierJarServed + ResponsePosted -> VerifierResponseReceived.
        //PDA effectful loop: DecryptResponseAction -> VerificationSucceeded
        //                    -> PresentationVerified.
        //=====================================================================

        PresentationVerifiedState verified = await app.HandleDirectPostAsync(verifierKeys,
            requestUriToken,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must reach PresentationVerified.");
        Assert.IsNull(verified.RedirectUri,
            "Cross-device flow must not carry a redirect_uri.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
        Assert.AreEqual(4, app.GetFlowState(requestUriToken).StepCount,
            "Verifier PDA must traverse exactly four transitions: " +
            "(1) ServerParReceived -> VerifierParReceived, " +
            "(2) ServerJarSigned -> VerifierJarServed, " +
            "(3) ResponsePosted -> VerifierResponseReceived, " +
            "(4) VerificationSucceeded -> PresentationVerified.");
    }


    //=========================================================================
    //Cross-device flow with A256GCM — HAIP 1.0 §5.1.
    //
    //HAIP 1.0 requires the Verifier to advertise both A128GCM and A256GCM in
    //encrypted_response_enc_values_supported. The Wallet selects one. This test
    //verifies that the full flow succeeds when the Wallet chooses A256GCM.
    //The sequence is identical to the A128GCM cross-device flow — only the
    //enc algorithm chosen by the TestWallet differs.
    //=========================================================================

    [TestMethod]
    public async Task CrossDeviceFlowWithA256GcmBothPdasReachAcceptState()
    {
        using TestHostShell app = new(TimeProvider);
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

        string walletFlowId = $"wallet-a256-{Guid.NewGuid():N}";

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-a256-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierParReceivedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must be in VerifierParReceived after PAR.");

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierJarServedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must be in VerifierJarServed after serving the JAR.");

        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        //Verify the JWE enc header is A256GCM before sending to Verifier.
        string jweHeader = compactJwe[..compactJwe.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(
            jweHeader, SensitiveMemoryPool<byte>.Shared);
        string? enc = Verifiable.JCose.JwkJsonReader.ExtractStringValue(
            headerBytes.Memory.Span, "enc"u8);
        Assert.AreEqual(
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            enc,
            "Wallet must have chosen A256GCM as the enc algorithm.");

        PresentationVerifiedState verified = await app.HandleDirectPostAsync(verifierKeys,
            requestUriToken,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must reach PresentationVerified with A256GCM.");
        Assert.IsNull(verified.RedirectUri,
            "Cross-device flow must not carry a redirect_uri.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
    }


    //=========================================================================
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
    //=========================================================================

    [TestMethod]
    public async Task SameDeviceFlowBothPdasReachAcceptState()
    {
        using TestHostShell app = new(TimeProvider);
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

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-sd-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);


        //Step 2: JAR request — same as cross-device.
        //PDA: VerifierParReceived + ServerJarSigned -> VerifierJarServed.

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

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
            requestUriToken,
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


    //=========================================================================
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
    //=========================================================================

    [TestMethod]
    public async Task LocalAppToAppFlowBothPdasReachAcceptState()
    {
        using TestHostShell app = new(TimeProvider);
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

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-app2app-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);


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
            requestUriToken,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(requestUriToken).State,
            "Verifier PDA must reach PresentationVerified.");
        Assert.IsInstanceOfType<ResponseSent>(
            wallet.GetFlowState(walletFlowId).State,
            "Wallet PDA must reach ResponseSent.");
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verified claims must contain the pid credential.");
    }


    //=========================================================================
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
    //=========================================================================

    [TestMethod]
    public async Task TamperedJweCiphertextIsRejectedByVerifier()
    {
        using TestHostShell app = new(TimeProvider);
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

        (Uri requestUri, string requestUriToken) = await app.HandleParAsync(verifierKeys,
            new TransactionNonce("nonce-tamper-01"),
            CreatePreparedQuery(),
            VerifierBaseUri,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(verifierKeys,
            requestUriToken, TestContext.CancellationToken).ConfigureAwait(false);

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
                requestUriToken,
                tamperedJwe,
                redirectUri: null,
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    //=========================================================================
    //Security: JAR signature verification.
    //
    //A JAR signed with the correct key must verify. A JAR signed with a
    //different key must not verify. This test exercises signature verification
    //independently of the full flow to isolate the cryptographic boundary.
    //=========================================================================

    [TestMethod]
    public async Task JarSignatureVerifiesWithCorrectKeyAndFailsWithWrongKey()
    {
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(
                VerifierClientId,
                /*lang=json,strict*/ "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: VerifierClientId,
                responseUri: new Uri(VerifierBaseUri, "/cb"),
                nonce: "nonce-sig-01",
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata);

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
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool validWithCorrectKey = await Jws.VerifyAsync(
            signedJar.Message, TestSetup.Base64UrlEncoder, correctPublicKey)
            .ConfigureAwait(false);

        bool validWithWrongKey = await Jws.VerifyAsync(
            signedJar.Message, TestSetup.Base64UrlEncoder, wrongPublicKey)
            .ConfigureAwait(false);

        Assert.IsTrue(validWithCorrectKey,
            "JAR must verify successfully with the key that signed it.");
        Assert.IsFalse(validWithWrongKey,
            "JAR must not verify with a different key.");
    }


    //=========================================================================
    //Pending: request_uri_method=post / wallet_nonce — OID4VP 1.0 §5.10.
    //=========================================================================

    [TestMethod]
    public void RequestUriMethodPostWithWalletNonceBothPdasReachAcceptState()
    {
        Assert.Inconclusive(
            "request_uri_method=post requires a WalletNonceSent state and a " +
            "corresponding Verifier state for the extra round-trip before JAR " +
            "delivery. New inputs and transitions needed on both PDAs.");
    }


    //=========================================================================
    //Pending: transaction_data — OID4VP 1.0 §8.4.
    //=========================================================================

    [TestMethod]
    public void TransactionDataHashBoundIntoKeyBindingJwt()
    {
        Assert.Inconclusive(
            "transaction_data requires hash computation over the transaction_data " +
            "array from the JAR and binding of the resulting hash into the KB-JWT. " +
            "New fields on JarParsed and PresentationBuilt needed.");
    }


    //=========================================================================
    //Pending: direct_post unencrypted — OID4VP 1.0 §8.2.
    //=========================================================================

    [TestMethod]
    public void DirectPostUnencryptedBothPdasReachAcceptState()
    {
        Assert.Inconclusive(
            "direct_post unencrypted is not mandated by HAIP 1.0. The PDA states " +
            "are identical to the direct_post.jwt path. Implement when needed.");
    }


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }]
                }
            ]
        });


    private static string TamperJweSegment(string compactJwe, int segmentIndex)
    {
        string[] parts = compactJwe.Split('.');
        using IMemoryOwner<byte> decoded =
            TestSetup.Base64UrlDecoder(parts[segmentIndex], SensitiveMemoryPool<byte>.Shared);
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
            disclosablePaths, SaltGenerator.Create,
            issuerPrivateKey, IssuerKeyId, Pool,
            TestSetup.DefaultSerializationOptions,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    private static DcqlQuery BuildPidDcqlQuery() =>
        new()
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims =
                    [
                        ClaimsQuery.ForPath(["given_name"]),
                        ClaimsQuery.ForPath(["family_name"])
                    ]
                }
            ]
        };
}
