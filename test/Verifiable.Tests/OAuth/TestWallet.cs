using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// An in-process Wallet that mirrors what a Wallet app would do at each
/// processing boundary in the OID4VP presentation flow.
/// </summary>
/// <remarks>
/// <para>
/// Each public method corresponds to one user interaction or protocol step.
/// The Wallet holds its own credential store and flow state store — it shares
/// no objects or key material with the Verifier. The only values that cross
/// from the Verifier to this Wallet are strings: the compact JAR and the
/// optional redirect URI.
/// </para>
/// </remarks>
[DebuggerDisplay("TestWallet ExpectedVerifierClientId={ExpectedVerifierClientId}")]
internal sealed class TestWallet
{
    private Dictionary<string, (OAuthFlowState State, int StepCount)> FlowStore { get; } = [];
    private Dictionary<string, string> CredentialStore { get; }
    private TimeProvider Time { get; }
    private PrivateKeyMemory HolderPrivateKey { get; }


    /// <summary>
    /// The Verifier client identifier the Wallet expects in every JAR it receives.
    /// Used for mix-up attack defense.
    /// </summary>
    public string ExpectedVerifierClientId { get; }


    /// <summary>
    /// Creates a new <see cref="TestWallet"/> with a pre-populated credential store
    /// and a holder key for KB-JWT signing.
    /// </summary>
    /// <param name="expectedVerifierClientId">
    /// The Verifier client identifier the Wallet expects in every JAR.
    /// </param>
    /// <param name="credentialStore">
    /// Map from credential identifier to serialized SD-JWT string (without KB-JWT).
    /// The wallet adds the KB-JWT at presentation time.
    /// </param>
    /// <param name="holderPrivateKey">
    /// The holder's private key bound via <c>cnf</c> in the issued credential.
    /// Used to sign KB-JWTs at presentation time.
    /// </param>
    /// <param name="timeProvider">Time provider for expiry computation.</param>
    public TestWallet(
        string expectedVerifierClientId,
        Dictionary<string, string> credentialStore,
        PrivateKeyMemory holderPrivateKey,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedVerifierClientId);
        ArgumentNullException.ThrowIfNull(credentialStore);
        ArgumentNullException.ThrowIfNull(holderPrivateKey);
        ArgumentNullException.ThrowIfNull(timeProvider);

        ExpectedVerifierClientId = expectedVerifierClientId;
        CredentialStore = credentialStore;
        HolderPrivateKey = holderPrivateKey;
        Time = timeProvider;
    }


    /// <summary>
    /// QR scan / deep link received — the user has scanned a QR code or followed
    /// a deep link that contains the <c>request_uri</c>.
    /// </summary>
    /// <remarks>
    /// Creates the Wallet PDA and persists the initial
    /// <see cref="RequestUriReceived"/> state. In a real Wallet app this step
    /// is triggered by the OS routing an <c>openid4vp://</c> or
    /// <c>haip-vp://</c> deep link to the Wallet.
    /// </remarks>
    /// <param name="requestUri">The <c>request_uri</c> from the QR code or deep link.</param>
    /// <param name="walletFlowId">The Wallet-side stable identifier for this flow.</param>
    /// <returns>The <paramref name="walletFlowId"/> for use in subsequent calls.</returns>
    public string HandleQrScan(Uri requestUri, string walletFlowId)
    {
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(walletFlowId);

        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.Create(
                runId: Guid.NewGuid().ToString(),
                requestUri: requestUri,
                expectedVerifierClientId: ExpectedVerifierClientId,
                flowId: walletFlowId,
                timeProvider: Time);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
        return walletFlowId;
    }


    /// <summary>
    /// JAR fetch — the Wallet has fetched the compact JAR from <c>request_uri</c>,
    /// verified the signature, parsed the claims, evaluated the DCQL query, and
    /// selected the minimum required disclosures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In a real Wallet app this method spans two HTTP-level operations: the GET to
    /// <c>request_uri</c> and the local DCQL evaluation. Both are collapsed into one
    /// method here because neither crosses the wire boundary — the JAR arrives as a
    /// string and the DCQL result is computed locally.
    /// </para>
    /// <para>
    /// The Wallet MUST verify the JAR signature before accepting any claims per
    /// OID4VP 1.0 §5.
    /// </para>
    /// </remarks>
    /// <param name="walletFlowId">The Wallet-side flow identifier.</param>
    /// <param name="requestUri">The <c>request_uri</c> the JAR was fetched from.</param>
    /// <param name="compactJar">The compact JWS JAR received from the Verifier.</param>
    /// <param name="verifierSigningPublicKey">
    /// The Verifier's public key used to verify the JAR signature.
    /// In production this would be resolved from the Verifier's JWKS endpoint.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task HandleJarFetchAsync(
        string walletFlowId,
        Uri requestUri,
        string compactJar,
        PublicKeyMemory verifierSigningPublicKey,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(walletFlowId);
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJar);
        ArgumentNullException.ThrowIfNull(verifierSigningPublicKey);

        AuthorizationRequestObject parsedRequest = await JarExtensions.VerifyAndParseJarAsync(
            compactJar,
            verifierSigningPublicKey,
            TestSetup.Base64UrlDecoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<DcqlQuery>(
                json, TestSetup.DefaultSerializationOptions)!,
            json => JsonSerializer.Deserialize<VerifierClientMetadata>(
                json, TestSetup.DefaultSerializationOptions)!,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        (OAuthFlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        await pda.StepAsync(
            new JarReceived(requestUri, parsedRequest, Time.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pdaDcql =
            WalletFlowAutomaton.CreateFromSnapshot(pda.CurrentState, pda.StepCount, Time);

        PreparedDcqlQuery preparedQuery = DcqlPreparer.Prepare(parsedRequest.DcqlQuery!);

        //The wallet matches DCQL credential queries against its credential store.
        //Each key in the store is a credential query identifier (e.g., "pid").
        await pdaDcql.StepAsync(
            new DcqlMatched(
                preparedQuery,
                new Dictionary<string, string>(CredentialStore),
                Time.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pdaDcql.CurrentState, pdaDcql.StepCount);
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pdaSelected =
            WalletFlowAutomaton.CreateFromSnapshot(pdaDcql.CurrentState, pdaDcql.StepCount, Time);

        //For a single credential, the VP token is the serialized SD-JWT.
        //For multiple credentials, it would be a JSON object mapping query IDs to tokens.
        string vpToken = CredentialStore.Count == 1
            ? CredentialStore.Values.First()
            : JsonSerializer.Serialize(CredentialStore, TestSetup.DefaultSerializationOptions);

        await pdaSelected.StepAsync(
            new PresentationSelected(vpToken, Time.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pdaSelected.CurrentState, pdaSelected.StepCount);
    }


    /// <summary>
    /// Response POST — the Wallet encrypts the VP token and POSTs it to
    /// <c>response_uri</c> as a JWE per OID4VP 1.0 §8.3.1 (direct_post.jwt).
    /// </summary>
    /// <remarks>
    /// Returns the compact JWE that would be sent in the HTTP POST body. The
    /// Wallet then advances its PDA to <see cref="ResponseSent"/>.
    /// </remarks>
    /// <param name="walletFlowId">The Wallet-side flow identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWE to POST to the Verifier's <c>response_uri</c>.</returns>
    public async Task<string> HandleResponsePostAsync(
        string walletFlowId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(walletFlowId);

        (OAuthFlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        PresentationBuilt presentationBuilt = (PresentationBuilt)pda.CurrentState;

        //Parse the stored SD-JWT (without KB-JWT) and create the KB-JWT.
        string vpTokenWithKbJwt = await CreateVpTokenWithKeyBindingAsync(
            presentationBuilt.VpTokenJson,
            presentationBuilt.Request.Nonce,
            presentationBuilt.Request.ClientId,
            cancellationToken).ConfigureAwait(false);

        string compactJwe = await HaipProfile.EncryptResponseAsync(
            presentationBuilt.Request,
            Encoding.UTF8.GetBytes(vpTokenWithKbJwt).AsMemory(),
            header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new ResponsePostedByWallet(
                presentationBuilt.Request.ResponseUri!,
                presentationBuilt.Request.State,
                Time.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
        return compactJwe;
    }


    /// <summary>
    /// Redirect received — same-device flow only. The Verifier's HTTP 200 response
    /// to the direct_post.jwt POST contains a <c>redirect_uri</c> JSON field per
    /// OID4VP 1.0 §8.2. The Wallet follows this URI to return the user's browser
    /// session to the Verifier.
    /// </summary>
    /// <param name="walletFlowId">The Wallet-side flow identifier.</param>
    /// <param name="redirectUri">The URI read from the Verifier's response body.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The <see cref="BrowserRedirectIssued"/> terminal state confirming the redirect.
    /// </returns>
    public async Task<BrowserRedirectIssued> HandleRedirectAsync(
        string walletFlowId,
        Uri redirectUri,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(walletFlowId);
        ArgumentNullException.ThrowIfNull(redirectUri);

        (OAuthFlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        await pda.StepAsync(
            new RedirectReceived(redirectUri, Time.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
        return (BrowserRedirectIssued)pda.CurrentState;
    }


    /// <summary>
    /// Returns the current flow state and step count for a given flow identifier.
    /// Used by tests to assert on intermediate and terminal PDA states.
    /// </summary>
    public (OAuthFlowState State, int StepCount) GetFlowState(string walletFlowId) =>
        FlowStore[walletFlowId];


    /// <summary>
    /// Parses the SD-JWT, computes <c>sd_hash</c>, signs a KB-JWT with the holder
    /// private key, attaches it to the token, and returns the serialized SD-JWT
    /// with key binding per RFC 9901 §4.3.
    /// </summary>
    private async Task<string> CreateVpTokenWithKeyBindingAsync(
        string sdJwtWithoutKb,
        string nonce,
        string audience,
        CancellationToken cancellationToken)
    {
        SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

        //Compute sd_hash: SHA-256 of the SD-JWT without KB-JWT (with trailing tilde).
        string hashInput = SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder);
        byte[] hashBytes = SHA256.HashData(Encoding.ASCII.GetBytes(hashInput));
        string sdHash = TestSetup.Base64UrlEncoder(hashBytes);

        //Build KB-JWT header and payload.
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(HolderPrivateKey.Tag);

        JwtHeader kbHeader = JwtHeaderExtensions.ForKeyBinding(algorithm);

        var kbPayload = new Dictionary<string, object>
        {
            [WellKnownJwtClaims.Nonce] = nonce,
            [WellKnownJwtClaims.Aud] = audience,
            [WellKnownJwtClaims.Iat] = Time.GetUtcNow().ToUnixTimeSeconds(),
            [SdConstants.SdHashClaim] = sdHash
        };

        //Sign the KB-JWT with the holder's private key.
        using JwsMessage kbJws = await Jws.SignAsync(
            kbHeader,
            kbPayload,
            static part => new TaggedMemory<byte>(
                Encoding.UTF8.GetBytes(
                    JsonSerializerExtensions.Serialize(
                        part, TestSetup.DefaultSerializationOptions)),
                BufferTags.Json),
            TestSetup.Base64UrlEncoder,
            HolderPrivateKey,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        string compactKbJwt = JwsSerialization.SerializeCompact(
            kbJws, TestSetup.Base64UrlEncoder);

        //Attach the KB-JWT and serialize the full SD-JWT with key binding.
        SdToken<string> tokenWithKb = token.WithKeyBinding(compactKbJwt);
        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }
}
