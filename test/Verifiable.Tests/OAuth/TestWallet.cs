using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Foundation.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// A step-by-step test-only Wallet fixture for OID4VP presentation flows.
/// Each public method corresponds to one user interaction or protocol step,
/// allowing tests to assert PDA state at intermediate transition points. The
/// production wallet path is
/// <see cref="Verifiable.OAuth.Oid4Vp.Wallet.Oid4VpWalletClient.PresentJarAsync"/>,
/// which collapses the whole flow into a single call.
/// </summary>
/// <remarks>
/// <para>
/// The Wallet holds its own credential store and flow state store — it shares
/// no objects or key material with the Verifier. The only values that cross
/// from the Verifier to this Wallet are strings: the compact JAR and the
/// optional redirect URI. KB-JWT signing composes with the production
/// <see cref="Verifiable.OAuth.Oid4Vp.Wallet.KbJwtIssuance"/> primitive — the
/// only wallet-specific path that remains here is the step-by-step PDA
/// progression.
/// </para>
/// </remarks>
[DebuggerDisplay("TestWallet ExpectedVerifierClientId={ExpectedVerifierClientId}")]
internal sealed class TestWallet
{
    private Dictionary<string, (FlowState State, int StepCount)> FlowStore { get; } = [];
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

        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pda =
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
    /// Wallet POST to <c>request_uri</c> — the <c>request_uri_method=post</c>
    /// path per OID4VP 1.0 §5.10. The Wallet sends <paramref name="walletNonce"/>
    /// (and optionally <paramref name="walletMetadataJson"/>) so the Verifier
    /// can echo the nonce in the signed JAR. Drives the Wallet PDA
    /// <c>RequestUriReceived</c> → <c>WalletNonceSent</c>; the JAR fetch and
    /// echo-verification happen subsequently in <see cref="HandleJarFetchAsync"/>.
    /// </summary>
    /// <param name="walletFlowId">The Wallet-side flow identifier.</param>
    /// <param name="requestUri">The <c>request_uri</c> the Wallet is POSTing to.</param>
    /// <param name="walletNonce">The fresh Wallet-issued nonce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task HandleWalletPostAsync(
        string walletFlowId,
        Uri requestUri,
        string walletNonce,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(walletFlowId);
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(walletNonce);

        (FlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        await pda.StepAsync(
            new WalletPostSent(requestUri, walletNonce, Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
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
            StateParameterPolicy.Required,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        (FlowState state, int steps) = FlowStore[walletFlowId];

        //request_uri_method=post path — verify the JAR echoes the wallet_nonce
        //we sent. The state machine alone cannot enforce this (transitions are
        //pure dispatch); the application MUST refuse a JAR whose wallet_nonce
        //does not match. Per OID4VP 1.0 §5.10.
        if(state is WalletNonceSent sent
            && !string.Equals(parsedRequest.WalletNonce, sent.WalletNonce, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"JAR served in response to wallet_nonce='{sent.WalletNonce}' did not echo it correctly " +
                $"(observed: '{parsedRequest.WalletNonce ?? "<absent>"}'). " +
                $"OID4VP 1.0 §5.10 requires the Verifier to bind the Wallet's nonce into the JAR.");
        }

        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        await pda.StepAsync(
            new JarReceived(requestUri, parsedRequest, Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pdaDcql =
            WalletFlowAutomaton.CreateFromSnapshot(pda.CurrentState, pda.StepCount, Time);

        PreparedDcqlQuery preparedQuery = DcqlPreparer.Prepare(parsedRequest.DcqlQuery!);

        //The wallet matches DCQL credential queries against its credential store.
        //Each key in the store is a credential query identifier (e.g., "pid").
        await pdaDcql.StepAsync(
            new DcqlMatched(
                preparedQuery,
                new Dictionary<string, string>(CredentialStore),
                Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pdaDcql.CurrentState, pdaDcql.StepCount);
        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pdaSelected =
            WalletFlowAutomaton.CreateFromSnapshot(pdaDcql.CurrentState, pdaDcql.StepCount, Time);

        //For a single credential, the VP token is the serialized SD-JWT.
        //For multiple credentials, it would be a JSON object mapping query IDs to tokens.
        string vpToken = CredentialStore.Count == 1
            ? CredentialStore.Values.First()
            : JsonSerializer.Serialize(CredentialStore, TestSetup.DefaultSerializationOptions);

        await pdaSelected.StepAsync(
            new PresentationSelected(vpToken, Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

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

        (FlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        PresentationBuilt presentationBuilt = (PresentationBuilt)pda.CurrentState;

        //Parse the stored SD-JWT (without KB-JWT) and create the KB-JWT. When the
        //JAR carried transaction_data per OID4VP 1.0 §8.4, the descriptors travel
        //into the KB-JWT as transaction_data_hashes.
        //Wrap the SD-JWT VC presentation in the OID4VP 1.0 §8.1 spec-shaped
        //vp_token JSON object: keyed by DCQL credential query id, array values.
        string credentialQueryId = CredentialStore.Keys.First();

        string vpTokenWithKbJwt = await CreateVpTokenWithKeyBindingAsync(
            presentationBuilt.VpTokenJson,
            presentationBuilt.Request.Nonce,
            presentationBuilt.Request.ClientId,
            presentationBuilt.Request.TransactionData,
            presentationBuilt.Request.DcqlQuery!,
            credentialQueryId,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        //OID4VP 1.0 §8.3.1: the direct_post.jwt JWE plaintext is the response JWT
        //payload carrying vp_token (+ state) as named claims — the same shape the
        //real Oid4VpWalletClient emits (shared serializer keeps them identical).
        string responseJwtPayloadJson = VpTokenSerializer.SerializeDirectPostJwtResponse(
            new Dictionary<string, string>(StringComparer.Ordinal) { [credentialQueryId] = vpTokenWithKbJwt },
            presentationBuilt.Request.State,
            payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                payload, TestSetup.DefaultSerializationOptions));

        string compactJwe = await HaipProfile.EncryptResponseAsync(
            presentationBuilt.Request,
            Encoding.UTF8.GetBytes(responseJwtPayloadJson).AsMemory(),
            header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new ResponsePostedByWallet(
                presentationBuilt.Request.ResponseUri!,
                presentationBuilt.Request.State,
                Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);

        return compactJwe;
    }


    /// <summary>
    /// Pre-resolved-key overload of <see cref="HandleResponsePostAsync(string, CancellationToken)"/>.
    /// Used by federation-bound flows where the Verifier's encryption key
    /// comes from the resolved trust chain's effective metadata rather
    /// than from <c>client_metadata.jwks</c> (which OID4VP §5.9.3 says
    /// MUST be ignored when the <c>openid_federation:</c> prefix is used).
    /// </summary>
    /// <param name="walletFlowId">The Wallet-side flow identifier.</param>
    /// <param name="preResolvedEncryptionKey">
    /// The Verifier's P-256 encryption key extracted by the test fixture
    /// from chain effective metadata. The wallet does not dispose this —
    /// the caller owns the key.
    /// </param>
    /// <param name="selectedEnc">
    /// JWE enc algorithm to use (<c>A128GCM</c> / <c>A256GCM</c>). The
    /// caller selects per the Verifier's
    /// <c>encrypted_response_enc_values_supported</c> from chain metadata.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<string> HandleResponsePostAsync(
        string walletFlowId,
        PublicKeyMemory preResolvedEncryptionKey,
        string selectedEnc,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(walletFlowId);
        ArgumentNullException.ThrowIfNull(preResolvedEncryptionKey);
        ArgumentException.ThrowIfNullOrEmpty(selectedEnc);

        (FlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        PresentationBuilt presentationBuilt = (PresentationBuilt)pda.CurrentState;

        string credentialQueryId = CredentialStore.Keys.First();

        string vpTokenWithKbJwt = await CreateVpTokenWithKeyBindingAsync(
            presentationBuilt.VpTokenJson,
            presentationBuilt.Request.Nonce,
            presentationBuilt.Request.ClientId,
            presentationBuilt.Request.TransactionData,
            presentationBuilt.Request.DcqlQuery!,
            credentialQueryId,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //OID4VP 1.0 §8.3.1: the direct_post.jwt JWE plaintext is the response JWT
        //payload carrying vp_token (+ state) as named claims — the same shape the
        //real Oid4VpWalletClient emits (shared serializer keeps them identical).
        string responseJwtPayloadJson = VpTokenSerializer.SerializeDirectPostJwtResponse(
            new Dictionary<string, string>(StringComparer.Ordinal) { [credentialQueryId] = vpTokenWithKbJwt },
            presentationBuilt.Request.State,
            payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                payload, TestSetup.DefaultSerializationOptions));

        string compactJwe = await HaipProfile.EncryptResponseAsync(
            preResolvedEncryptionKey,
            selectedEnc,
            Encoding.UTF8.GetBytes(responseJwtPayloadJson).AsMemory(),
            header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new ResponsePostedByWallet(
                presentationBuilt.Request.ResponseUri!,
                presentationBuilt.Request.State,
                Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

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

        (FlowState state, int steps) = FlowStore[walletFlowId];
        PushdownAutomaton<FlowState, FlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.CreateFromSnapshot(state, steps, Time);

        await pda.StepAsync(
            new RedirectReceived(redirectUri, Time.GetUtcNow()),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        FlowStore[walletFlowId] = (pda.CurrentState, pda.StepCount);
        return (BrowserRedirectIssued)pda.CurrentState;
    }


    /// <summary>
    /// Returns the current flow state and step count for a given flow identifier.
    /// Used by tests to assert on intermediate and terminal PDA states.
    /// </summary>
    public (FlowState State, int StepCount) GetFlowState(string walletFlowId) =>
        FlowStore[walletFlowId];


    /// <summary>
    /// Parses the SD-JWT, signs a KB-JWT via the production
    /// <see cref="KbJwtIssuance"/> primitive, attaches it to the token, and
    /// returns the serialized SD-JWT with key binding per RFC 9901 §4.3.
    /// </summary>
    private async Task<string> CreateVpTokenWithKeyBindingAsync(
        string sdJwtWithoutKb,
        string nonce,
        string audience,
        IReadOnlyList<string>? transactionData,
        DcqlQuery dcqlQuery,
        string credentialQueryId,
        CancellationToken cancellationToken)
    {
        using SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag);

        //Minimal disclosure (data minimization) computed through the same Core engine
        //every flow runs — DcqlDisclosure over the parsed token. A null set means a
        //whole-credential request (no specific claims) or a wildcard leaf, so every
        //disclosure is revealed. The verifier's CheckNoOverDisclosure rule rejects
        //anything beyond what the engine selected.
        HashSet<string>? selectedClaimNames = await ComputeSelectedClaimNamesAsync(
            dcqlQuery, credentialQueryId, token, cancellationToken: cancellationToken).ConfigureAwait(false);

        using SdToken<string> presentationToken = token.SelectDisclosures(
            selectedClaimNames is null
                ? static _ => true
                : disclosure => disclosure.ClaimName is not null && selectedClaimNames.Contains(disclosure.ClaimName),
            BaseMemoryPool.Shared);

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(presentationToken, TestSetup.Base64UrlEncoder);
        byte[] hashInputBytes = Encoding.UTF8.GetBytes(hashInput);

        IReadOnlyList<string>? transactionDataHashes = null;
        if(transactionData is { Count: > 0 } txData)
        {
            transactionDataHashes = await TransactionDataHasher.ComputeSha256Async(
                txData,
                TestSetup.Base64UrlEncoder,
                BaseMemoryPool.Shared,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            hashInputBytes,
            HolderPrivateKey,
            nonce,
            audience,
            Time.GetUtcNow(),
            TestSetup.Base64UrlEncoder,
            static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions),
            static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions),
            BaseMemoryPool.Shared,
            transactionDataHashes,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKb = presentationToken.WithKeyBinding(compactKbJwt, BaseMemoryPool.Shared);

        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }


    //The disclosure claim names to reveal for the given credential query, computed
    //through the Core selective-disclosure engine: DcqlDisclosure.ComputeStrategyAsync
    //evaluates the parsed token against the query via SdTokenDcqlAdapter and the
    //decision's SelectedPaths are the minimal set (iss/vct are the always-visible
    //mandatory paths). Returns null — reveal everything — when the query requests the
    //whole credential (no specific claims) or carries a wildcard leaf (open-ended),
    //mirroring the verifier's permissive claims-less / wildcard handling.
    private static async Task<HashSet<string>?> ComputeSelectedClaimNamesAsync(
        DcqlQuery dcqlQuery,
        string credentialQueryId,
        SdToken<string> token,
        CancellationToken cancellationToken)
    {
        CredentialQuery? credentialQuery = null;
        foreach(CredentialQuery candidate in dcqlQuery.Credentials ?? [])
        {
            if(string.Equals(candidate.Id, credentialQueryId, StringComparison.Ordinal))
            {
                credentialQuery = candidate;
                break;
            }
        }

        if(credentialQuery?.Claims is not { Count: > 0 } claimQueries)
        {
            return null;
        }

        foreach(ClaimsQuery claimQuery in claimQueries)
        {
            if(claimQuery.Path is { Count: > 0 } pattern && pattern[pattern.Count - 1].KeyValue is null)
            {
                //Wildcard leaf -> open-ended request; reveal everything.
                return null;
            }
        }

        DisclosureStrategyGraph<SdToken<string>> graph = (await DcqlDisclosure.ComputeStrategyAsync(
            credentialQuery,
            token,
            SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt),
            SdTokenDcqlAdapter.ClaimExtractor<string>,
            mandatoryPaths: new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer("/iss"),
                CredentialPath.FromJsonPointer("/vct")
            },
            cancellationToken: cancellationToken).ConfigureAwait(false)).Graph;

        HashSet<string> selected = new(StringComparer.Ordinal);
        if(graph.Decisions.Count > 0)
        {
            foreach(CredentialPath path in graph.Decisions[0].SelectedPaths)
            {
                selected.Add(path.ToString().TrimStart('/'));
            }
        }

        return selected;
    }
}
