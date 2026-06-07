using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The OID4VP Wallet-side sub-client of <see cref="OAuthClient"/>. Owns the
/// HAIP 1.0 cross-device protocol mechanics — verify the JAR, drive the Wallet
/// PDA, assemble the spec-shaped <c>vp_token</c>, encrypt to the Verifier's
/// JWKS, POST to <c>response_uri</c>, and reach the
/// <see cref="ResponseSent"/> terminal — and delegates all credential logic to
/// the application via a single drop-out:
/// <see cref="Oid4VpWalletConfiguration.ProduceVpTokenPresentations"/>.
/// </summary>
/// <remarks>
/// <para>
/// The client is format-agnostic and holds no credentials. After verifying the
/// JAR it hands the request-derived <see cref="Oid4VpPresentationContext"/> to
/// the application's <see cref="ProduceVpTokenPresentationsDelegate"/>, which
/// runs the wirable Core disclosure engine (<c>DcqlEvaluator</c> →
/// <c>DisclosureComputation</c>) and the format primitives to produce the
/// per-credential-query presentations (and any <c>apu</c> binding). The client
/// then assembles the <c>vp_token</c>, threads the <c>apu</c>, encrypts, POSTs,
/// and walks the PDA — symmetric with how the verifier executor drops out to
/// per-format verify steps and the <c>ClaimIssuer</c> pipeline.
/// </para>
/// <para>
/// Each <see cref="PresentJarAsync"/> invocation is a complete presentation:
/// it constructs a fresh Wallet PDA, advances it through all transitions, and
/// returns the encrypted JWE and the terminal state. Persisted-state Wallet
/// scenarios compose <see cref="WalletFlowAutomaton.CreateFromSnapshot"/>
/// directly rather than going through this client.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpWalletClient")]
public sealed class Oid4VpWalletClient
{
    private readonly OAuthClientInfrastructure infrastructure;
    private readonly Oid4VpWalletConfiguration walletConfiguration;

    //HAIP 1.0 §5.1 allows A128GCM and A256GCM as content-encryption
    //algorithms; OID4VP §5.10 JAR encryption inherits that set absent a
    //wallet-side override. Used to validate the JWE's 'enc' header before
    //any cryptographic operation.
    private static readonly IReadOnlyList<string> HaipAllowedJarEncAlgorithms =
    [
        WellKnownJweEncryptionAlgorithms.A128Gcm,
        WellKnownJweEncryptionAlgorithms.A256Gcm
    ];


    /// <summary>The shared infrastructure carrying transport, time, and encoding delegates.</summary>
    public OAuthClientInfrastructure Infrastructure => infrastructure;


    /// <summary>The format-agnostic wallet configuration carrying JAR-parse/response-encryption delegates and the presentation drop-out.</summary>
    public Oid4VpWalletConfiguration WalletConfiguration => walletConfiguration;


    /// <summary>
    /// Creates a new OID4VP Wallet client.
    /// </summary>
    /// <param name="infrastructure">The shared client infrastructure.</param>
    /// <param name="walletConfiguration">The wallet delegate bundle, including the presentation drop-out.</param>
    /// <exception cref="ArgumentNullException">Thrown when either argument is <see langword="null"/>.</exception>
    public Oid4VpWalletClient(
        OAuthClientInfrastructure infrastructure,
        Oid4VpWalletConfiguration walletConfiguration)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(walletConfiguration);

        this.infrastructure = infrastructure;
        this.walletConfiguration = walletConfiguration;
    }


    /// <summary>
    /// Drives one OID4VP presentation end-to-end. Verifies the inbound JAR,
    /// invokes the application's presentation drop-out, encrypts the
    /// <c>vp_token</c> response to the Verifier's JWKS, and POSTs the JWE to
    /// the Verifier's <c>response_uri</c>.
    /// </summary>
    /// <param name="presentJarOptions">Per-call inputs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWE that was POSTed and the terminal PDA state.</returns>
    /// <remarks>
    /// Convenience overload for a single-tenant wallet that ignores tenancy: it
    /// drives the presentation over a fresh empty
    /// <see cref="ExchangeContext"/>. A multi-tenant deployment uses
    /// <see cref="PresentJarAsync(PresentJarOptions, ExchangeContext, CancellationToken)"/>
    /// to carry per-tenant trust material and transport selection.
    /// </remarks>
    public ValueTask<PresentationResult> PresentJarAsync(
        PresentJarOptions presentJarOptions,
        CancellationToken cancellationToken) =>
        PresentJarAsync(presentJarOptions, new ExchangeContext(), cancellationToken);


    /// <summary>
    /// Drives one OID4VP presentation end-to-end over the supplied
    /// <see cref="ExchangeContext"/>. Verifies the inbound JAR — resolving the
    /// Verifier's signing key by the <c>client_id</c> scheme through
    /// <see cref="Oid4VpWalletConfiguration.VerifierSigningKeyResolver"/>, which
    /// reads the current tenant's trust material off the context — invokes the
    /// application's presentation drop-out, encrypts the <c>vp_token</c>
    /// response to the Verifier's JWKS, and POSTs the JWE to the Verifier's
    /// <c>response_uri</c>.
    /// </summary>
    /// <param name="presentJarOptions">Per-call inputs.</param>
    /// <param name="context">
    /// The per-operation exchange context. The wallet stamps
    /// <see cref="ExchangeContextExtensions.ValidationTime"/> from its
    /// <see cref="TimeProvider"/> before resolving the JAR signing key, and
    /// threads the context into the key resolver, the presentation drop-out, and
    /// the transport delegates. The application places per-tenant trust material
    /// on it (via <see cref="Oid4VpExchangeContextExtensions"/>) before calling.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWE that was POSTed and the terminal PDA state.</returns>
    public async ValueTask<PresentationResult> PresentJarAsync(
        PresentJarOptions presentJarOptions,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentJarOptions);
        ArgumentNullException.ThrowIfNull(context);

        //OID4VP 1.0 §5.9.3 redirect_uri prefix path: the Verifier may send
        //the Authorization Request inline as URL parameters with no JAR.
        //Trust comes from the wallet POSTing the response back to the
        //response URI (which the prefix asserts equals client_id). When
        //the caller supplied InlineAuthorizationParameters the wallet
        //skips JAR fetch and signature verification entirely.
        if(presentJarOptions.InlineAuthorizationParameters is { Count: > 0 })
        {
            return await PresentFromInlineParametersAsync(
                presentJarOptions, context, cancellationToken).ConfigureAwait(false);
        }

        //OID4VP 1.0 §5.10 POST path: when the caller did not pre-fetch the
        //JAR (CompactJar is null), the wallet client drives the
        //request_uri_method=post step itself — POSTing wallet_nonce +
        //wallet_metadata to RequestUri and reading the (encrypted) JAR
        //back from the response body. Otherwise the caller supplied a
        //pre-fetched JAR via the GET path and we skip the POST entirely.
        string? walletNonceSent = null;
        string compactJar;
        if(presentJarOptions.CompactJar is not null)
        {
            compactJar = presentJarOptions.CompactJar;
        }
        else
        {
            (walletNonceSent, compactJar) = await FetchJarViaWalletPostAsync(
                presentJarOptions, context, cancellationToken).ConfigureAwait(false);
        }

        //OID4VP 1.0 §5.10: the JAR may arrive as a JWE-wrapped JWS — the
        //Verifier encrypted it to the wallet's exchange key advertised via
        //wallet_metadata.jwks. JWE Compact Serialization has 5 segments
        //(4 dots) versus the JWS-Compact 3 segments (2 dots); peek the dot
        //count to decide which path to take. When encrypted, decrypt first
        //then hand the recovered signed JAR to the normal verify-and-parse
        //path so the signature is still checked end-to-end.
        string jarForParsing = compactJar;
        int dotCount = 0;
        for(int i = 0; i < jarForParsing.Length; i++)
        {
            if(jarForParsing[i] == '.')
            {
                dotCount++;
            }
        }

        if(dotCount == 4)
        {
            if(presentJarOptions.WalletExchangePrivateKey is null)
            {
                throw new InvalidOperationException(
                    "Received a JWE-wrapped JAR per OID4VP 1.0 §5.10 but " +
                    "PresentJarOptions.WalletExchangePrivateKey is null. " +
                    "Supply the exchange private key whose public side was " +
                    "advertised in wallet_metadata.jwks.");
            }

            if(walletConfiguration.KeyAgreementDecrypt is null
                || walletConfiguration.AeadDecrypt is null)
            {
                throw new InvalidOperationException(
                    "Received a JWE-wrapped JAR but the wallet configuration " +
                    "lacks JAR-decryption delegates. Wire " +
                    "Oid4VpWalletConfiguration.KeyAgreementDecrypt and " +
                    "AeadDecrypt to support OID4VP 1.0 §5.10.");
            }

            DecryptedContent decryptedJar = await HaipProfile.DecryptResponseAsync(
                compactJwe: compactJar,
                ephemeralPrivateKey: presentJarOptions.WalletExchangePrivateKey,
                allowedEncAlgorithms: HaipAllowedJarEncAlgorithms,
                decoder: walletConfiguration.Base64UrlDecoder,
                keyAgreementDecryptDelegate: walletConfiguration.KeyAgreementDecrypt,
                keyDerivationDelegate: walletConfiguration.KeyDerivation,
                aeadDecryptDelegate: walletConfiguration.AeadDecrypt,
                pool: walletConfiguration.MemoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            using(decryptedJar)
            {
                //VerifyAndParseJarAsync takes the compact JWS as a string; the
                //decoded bytes are ASCII (compact JWS is base64url-segments +
                //dots) so UTF-8 round-trips without surrogate pitfalls.
                jarForParsing = Encoding.UTF8.GetString(
                    decryptedJar.AsReadOnlySpan());
            }
        }

        //OID4VP 1.0 §5.9.3 redirect_uri prefix path may arrive over the
        //request_uri channel as an unsigned JAR (alg=none). Peek the
        //protected header before signature verification: a missing or
        //"none" alg routes through ParseUnsignedJarAsync; otherwise the
        //signed-JAR verification path runs as normal.
        string? algHeaderValue = PeekJarAlgHeader(
            jarForParsing,
            walletConfiguration.Base64UrlDecoder,
            walletConfiguration.MemoryPool);

        AuthorizationRequestObject request;
        if(string.Equals(algHeaderValue, WellKnownJwaValues.None, StringComparison.Ordinal))
        {
            request = await JarExtensions.ParseUnsignedJarAsync(
                jarForParsing,
                walletConfiguration.Base64UrlDecoder,
                walletConfiguration.JarHeaderDeserializer,
                walletConfiguration.JarPayloadDeserializer,
                walletConfiguration.DcqlQueryDeserializer,
                walletConfiguration.ClientMetadataDeserializer,
                presentJarOptions.StatePolicy,
                walletConfiguration.MemoryPool).ConfigureAwait(false);

            //An unsigned JAR is only acceptable under the redirect_uri
            //prefix (OID4VP §5.9.3). Enforce the prefix and the
            //prefix-value-equals-response_uri invariant before treating the
            //request as authoritative — same checks as the inline path.
            EnforceRedirectUriPrefixContract(request);
        }
        else
        {
            //OID4VP 1.0 §5.9.3 signed-JAR path: resolve the Verifier's signing
            //key by the client_id scheme rather than trusting a pinned key.
            //Parse the protected header WITHOUT verifying so the resolver can
            //read the scheme-specific material (x5c, trust_chain, attestation
            //jwt, kid); the resolver binds that material to the wallet's
            //trusted ExpectedVerifierClientId and the per-tenant trust anchors
            //on the context. The parsed client_id is cross-checked downstream
            //in PresentWithParsedRequestAsync, so steering key selection via a
            //forged header cannot bypass the mix-up defence.
            UnverifiedJwtHeader jarHeader;
            using(UnverifiedJwsMessage unverifiedJar = JwsParsing.ParseCompact(
                jarForParsing,
                walletConfiguration.Base64UrlDecoder,
                walletConfiguration.JarHeaderDeserializer.Invoke,
                walletConfiguration.MemoryPool))
            {
                //Copy the header into a standalone instance so it survives the
                //UnverifiedJwsMessage's disposal below.
                jarHeader = new UnverifiedJwtHeader(unverifiedJar.Signatures[0].ProtectedHeader);
            }

            //Stamp the trust-material evaluation instant from the wallet's
            //TimeProvider so every resolver hook sees one consistent time.
            context.SetValidationTime(infrastructure.TimeProvider.GetUtcNow());

            using PublicKeyMemory verifierSigningKey = await walletConfiguration.VerifierSigningKeyResolver(
                context,
                presentJarOptions.ExpectedVerifierClientId,
                jarHeader,
                cancellationToken).ConfigureAwait(false);

            request = await JarExtensions.VerifyAndParseJarAsync(
                jarForParsing,
                verifierSigningKey,
                walletConfiguration.Base64UrlDecoder,
                walletConfiguration.JarHeaderDeserializer,
                walletConfiguration.JarPayloadDeserializer,
                walletConfiguration.DcqlQueryDeserializer,
                walletConfiguration.ClientMetadataDeserializer,
                presentJarOptions.StatePolicy,
                walletConfiguration.MemoryPool,
                cancellationToken).ConfigureAwait(false);
        }

        return await PresentWithParsedRequestAsync(
            request, presentJarOptions, walletNonceSent, context, cancellationToken)
            .ConfigureAwait(false);
    }


    //Composes the user-agent redirect URL for the query/fragment response
    //modes. For query: response parameters are appended to the redirect
    //URI's query string (`?vp_token=...&state=...` or `&vp_token=...&state=...`
    //when an existing query is present). For fragment: parameters go after
    //a `#` separator per OIDC Core §3.1.2.4 — any pre-existing fragment on
    //the redirect URI is replaced.
    private static string BuildRedirectResponseUrl(
        Uri redirectUri,
        string responseMode,
        string vpTokenJson,
        string? state)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseMode);
        ArgumentNullException.ThrowIfNull(vpTokenJson);

        string parameterPart =
            $"{AuthorizationResponseParameters.VpToken}={Uri.EscapeDataString(vpTokenJson)}";
        if(!string.IsNullOrEmpty(state))
        {
            parameterPart +=
                $"&{OAuthRequestParameterNames.State}={Uri.EscapeDataString(state)}";
        }

        if(WellKnownResponseModes.IsFragment(responseMode))
        {
            //Fragment replaces any existing fragment on the redirect URI;
            //the user-agent navigation strips it before sending the request
            //to the server, so the verifier-side handler reads the fragment
            //via client-side script.
            string baseUri = redirectUri.GetLeftPart(UriPartial.Query);

            return $"{baseUri}#{parameterPart}";
        }

        //Query: append with the right separator depending on whether the
        //redirect URI already carries a query string.
        char separator = string.IsNullOrEmpty(redirectUri.Query) ? '?' : '&';

        return $"{redirectUri.GetLeftPart(UriPartial.Query)}{separator}{parameterPart}";
    }


    //Reads the JWS protected header's alg parameter without performing any
    //cryptographic verification. Used to route between the signed and
    //unsigned JAR parse paths.
    private static string? PeekJarAlgHeader(
        string compactJar,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        int firstDot = compactJar.IndexOf('.', StringComparison.Ordinal);
        if(firstDot <= 0)
        {
            return null;
        }

        using IMemoryOwner<byte> headerBytes = base64UrlDecoder(
            compactJar.AsSpan(0, firstDot).ToString(), pool);

        return JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "alg"u8);
    }


    //Enforces the OID4VP 1.0 §5.9.3 redirect_uri-prefix trust contract on
    //an unsigned request: client_id MUST begin with redirect_uri: and the
    //prefix value MUST equal the response_uri the wallet will POST to.
    private static void EnforceRedirectUriPrefixContract(
        AuthorizationRequestObject request)
    {
        if(!WellKnownClientIdPrefixes.IsRedirectUri(request.ClientId))
        {
            throw new InvalidOperationException(
                "Received an unsigned Authorization Request without the " +
                $"'{WellKnownClientIdPrefixes.RedirectUri}:' prefix. " +
                "Wallets MUST NOT accept an unsigned request under any other " +
                "prefix per OID4VP 1.0 §5.9.3.");
        }

        string prefixValue = WellKnownClientIdPrefixes.StripPrefix(request.ClientId);
        if(!string.Equals(
            prefixValue,
            request.ResponseUri.OriginalString,
            StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Unsigned JAR's client_id prefix value '{prefixValue}' does " +
                $"not match response_uri '{request.ResponseUri.OriginalString}'. " +
                $"The '{WellKnownClientIdPrefixes.RedirectUri}:' prefix's " +
                "trust model requires the wallet's POST destination to match " +
                "the asserted client identifier.");
        }
    }


    //OID4VP 1.0 §5.9.3 redirect_uri prefix path: the Authorization Request
    //arrived as inline URL parameters (no JAR, no signature). Parse the
    //request, enforce that client_id is the redirect_uri-prefixed form of
    //response_uri, then dispatch into the shared post-parse flow.
    private async ValueTask<PresentationResult> PresentFromInlineParametersAsync(
        PresentJarOptions presentJarOptions,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, string> parameters =
            presentJarOptions.InlineAuthorizationParameters!;

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();

        //Spec text (OID4VP §5.9.3): "If the Client Identifier Scheme is
        //redirect_uri, the Authorization Request MUST NOT be signed."
        //The wallet asserts the prefix is what it expected — any other
        //prefix on an unsigned inline request fails this check and
        //surfaces immediately.
        AuthorizationRequestObject request = AuthorizationRequestObjectFormFields.Parse(
            parameters,
            walletConfiguration.DcqlQueryDeserializer,
            walletConfiguration.ClientMetadataDeserializer,
            now,
            InlineRequestObjectLifetime,
            presentJarOptions.StatePolicy);

        EnforceRedirectUriPrefixContract(request);

        return await PresentWithParsedRequestAsync(
            request, presentJarOptions, walletNonceSent: null, context, cancellationToken)
            .ConfigureAwait(false);
    }


    //Lifetime window stamped on inline Authorization Requests when no
    //exp/nbf claims accompany them on the wire. Mirrors the JAR profile's
    //request-object lifetime; deployments wanting tighter validity can
    //pre-stamp the timing claims in the inline parameter set.
    private static readonly TimeSpan InlineRequestObjectLifetime = TimeSpan.FromMinutes(5);


    private async ValueTask<PresentationResult> PresentWithParsedRequestAsync(
        AuthorizationRequestObject request,
        PresentJarOptions presentJarOptions,
        string? walletNonceSent,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(request.DcqlQuery is null
            || request.DcqlQuery.Credentials is null
            || request.DcqlQuery.Credentials.Count == 0)
        {
            throw new InvalidOperationException(
                "Authorization Request Object does not carry a non-empty dcql_query. " +
                "OID4VP presentation requires at least one credential query.");
        }

        string runId = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthCorrelationId, null, cancellationToken)
            .ConfigureAwait(false);
        string walletFlowId = presentJarOptions.FlowId
            ?? await infrastructure.GenerateIdentifierAsync(
                WellKnownIdentifierPurposes.Oid4VpWalletFlowId, null, cancellationToken)
                .ConfigureAwait(false);

        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, WalletFlowStackSymbol> pda =
            WalletFlowAutomaton.Create(
                runId: runId,
                requestUri: presentJarOptions.RequestUri,
                expectedVerifierClientId: presentJarOptions.ExpectedVerifierClientId,
                flowId: walletFlowId,
                timeProvider: infrastructure.TimeProvider);

        //When the §5.10 POST path was taken, step the PDA through the
        //intermediate WalletNonceSent state so the trace shows the POST
        //round-trip happened. The GET path skips this and goes straight
        //from RequestUriReceived to JarParsed.
        if(walletNonceSent is not null)
        {
            await pda.StepAsync(
                new WalletPostSent(
                    presentJarOptions.RequestUri,
                    walletNonceSent,
                    infrastructure.TimeProvider.GetUtcNow()),
                cancellationToken).ConfigureAwait(false);
        }

        await pda.StepAsync(
            new JarReceived(presentJarOptions.RequestUri, request, infrastructure.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        //The single drop-out: hand the request-derived context to the
        //application, which runs the Core disclosure engine (DcqlEvaluator →
        //DisclosureComputation) and the format primitives to produce the
        //per-credential-query presentations. The wallet client owns only the
        //OID4VP protocol mechanics from here on.
        PreparedDcqlQuery preparedQuery = DcqlPreparer.Prepare(request.DcqlQuery);

        Oid4VpPresentationContext presentationContext = new()
        {
            Request = request,
            PreparedQuery = preparedQuery,
            Now = infrastructure.TimeProvider.GetUtcNow(),
            Base64UrlEncoder = infrastructure.Base64UrlEncoder,
            MemoryPool = walletConfiguration.MemoryPool,
            ExchangeContext = context
        };

        Oid4VpPresentationSet presentationSet = await walletConfiguration.ProduceVpTokenPresentations(
            presentationContext, cancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<string, string> presentationsByQueryId = presentationSet.PresentationsByQueryId;
        if(presentationsByQueryId.Count == 0)
        {
            throw new InvalidOperationException(
                "ProduceVpTokenPresentations returned no presentations; the vp_token requires "
                + "at least one presentation keyed by a DCQL credential query id.");
        }

        string? responseEncryptionApu = presentationSet.ResponseEncryptionApu;

        await pda.StepAsync(
            new DcqlMatched(
                preparedQuery,
                presentationsByQueryId,
                infrastructure.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        string vpTokenJson = presentationsByQueryId.Count == 1
            ? VpTokenSerializer.SerializeSingle(
                presentationsByQueryId.Keys.First(),
                presentationsByQueryId.Values.First(),
                walletConfiguration.JwtPayloadSerializer)
            : VpTokenSerializer.SerializeMultiple(
                presentationsByQueryId,
                walletConfiguration.JwtPayloadSerializer);

        await pda.StepAsync(
            new PresentationSelected(vpTokenJson, infrastructure.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        //An apu binding (e.g. an mdoc mdoc_generated_nonce) can only ride the
        //encrypted direct_post.jwt response — the other response modes emit no
        //JWE to carry it. Reject the mismatch loudly rather than silently
        //dropping a value the Verifier needs to reconstruct the SessionTranscript.
        if(responseEncryptionApu is not null
            && !WellKnownResponseModes.IsDirectPostJwt(request.ResponseMode))
        {
            throw new InvalidOperationException(
                $"The presentation set carries a response-encryption 'apu' value but " +
                $"response_mode '{request.ResponseMode}' emits no JWE to carry it; such formats " +
                "require response_mode=direct_post.jwt.");
        }

        //Dispatch on the Verifier-advertised response_mode. HAIP 1.0 §5.1
        //mandates direct_post.jwt (encrypted); OID4VP 1.0 §8.2 also defines
        //direct_post (plaintext vp_token) for non-HAIP profiles. The wallet
        //client honours whichever the JAR carries — unsupported response
        //modes surface as InvalidOperationException so deployments that
        //extend the set fail loudly here.
        Dictionary<string, string> postFields;
        string responseArtifact;
        if(WellKnownResponseModes.IsDirectPostJwt(request.ResponseMode))
        {
            //OID4VP 1.0 §8.3.1: the JWE plaintext is the response JWT payload that
            //carries vp_token (+ state) as NAMED CLAIMS — not the bare vp_token
            //object. state therefore rides inside the encrypted JWT and is NOT
            //added to the outer form body below.
            string responseJwtPayloadJson = VpTokenSerializer.SerializeDirectPostJwtResponse(
                presentationsByQueryId, request.State, walletConfiguration.JwtPayloadSerializer);
            byte[] responsePayloadBytes = Encoding.UTF8.GetBytes(responseJwtPayloadJson);
            string compactJwe = await HaipProfile.EncryptResponseAsync(
                request,
                responsePayloadBytes,
                walletConfiguration.JwtHeaderSerializer,
                walletConfiguration.TagToEpkCrvConverter,
                walletConfiguration.KeyAgreementEncrypt,
                walletConfiguration.KeyDerivation,
                walletConfiguration.AeadEncrypt,
                infrastructure.Base64UrlEncoder,
                walletConfiguration.Base64UrlDecoder,
                walletConfiguration.MemoryPool,
                agreementPartyUInfo: responseEncryptionApu,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            postFields = new(StringComparer.Ordinal)
            {
                [AuthorizationResponseParameters.Response] = compactJwe
            };
            responseArtifact = compactJwe;
        }
        else if(WellKnownResponseModes.IsDirectPost(request.ResponseMode))
        {
            //OID4VP 1.0 §8.2 plaintext direct_post — the wallet POSTs the
            //vp_token JSON object verbatim alongside state. No JWE
            //construction; the response_uri exposure is at the network layer
            //rather than at the message layer.
            postFields = new(StringComparer.Ordinal)
            {
                [AuthorizationResponseParameters.VpToken] = vpTokenJson
            };
            responseArtifact = vpTokenJson;
        }
        else if(WellKnownResponseModes.IsRedirectVariant(request.ResponseMode))
        {
            //RFC 6749 §3.1.2 / OIDC Core §3.1.2.4 redirect variants
            //(query, fragment): the wallet builds a URL the user-agent
            //navigates to, no HTTP POST. Used for same-device same-process
            //flows. Skip the SendFormPost path and return the constructed
            //URL as the response artifact — application code owns the
            //actual user-agent navigation.
            string redirectUrl = BuildRedirectResponseUrl(
                request.ResponseUri,
                request.ResponseMode,
                vpTokenJson,
                request.State);

            await pda.StepAsync(
                new ResponsePostedByWallet(
                    request.ResponseUri,
                    request.State,
                    infrastructure.TimeProvider.GetUtcNow()),
                cancellationToken).ConfigureAwait(false);

            return new PresentationResult
            {
                PostedResponseArtifact = redirectUrl,
                TerminalState = pda.CurrentState
            };
        }
        else
        {
            throw new InvalidOperationException(
                $"Unsupported response_mode '{request.ResponseMode}' on JAR. "
                + "Supported: 'direct_post' (OID4VP §8.2 plaintext), "
                + "'direct_post.jwt' (HAIP 1.0 §5.1 encrypted), "
                + "'query' (RFC 6749 §3.1.2), and 'fragment' (OIDC Core §3.1.2.4).");
        }

        //state is the outer transport correlator: the Verifier reads it from the
        //form to locate the flow (and its decryption key) BEFORE it can decrypt —
        //so for direct_post.jwt it cannot live ONLY inside the encrypted JWT.
        //§8.3.1 places the authoritative, integrity-protected state inside the
        //response JWT (done above via SerializeDirectPostJwtResponse); this outer
        //copy is the pre-decryption correlation hint a conformant Verifier ignores
        //in favour of the JWT claim. For plaintext direct_post (§8.2) the outer
        //field is the spec location; redirect modes carry state in the URL.
        if(!string.IsNullOrEmpty(request.State))
        {
            postFields[OAuthRequestParameterNames.State] = request.State;
        }

        HttpResponseData postResponse = await infrastructure.SendFormPostAsync(
            request.ResponseUri,
            postFields,
            OutgoingHeaders.Empty,
            context,
            cancellationToken).ConfigureAwait(false);

        if(postResponse.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"direct_post to {request.ResponseUri} returned status {postResponse.StatusCode}: " +
                $"{postResponse.Body}");
        }

        await pda.StepAsync(
            new ResponsePostedByWallet(
                request.ResponseUri,
                request.State,
                infrastructure.TimeProvider.GetUtcNow()),
            cancellationToken).ConfigureAwait(false);

        return new PresentationResult
        {
            PostedResponseArtifact = responseArtifact,
            TerminalState = pda.CurrentState
        };
    }


    /// <summary>
    /// Drives the OID4VP 1.0 §5.10 request_uri_method=post step: builds the
    /// wallet_metadata JSON, generates a fresh wallet_nonce, POSTs both as
    /// form fields to RequestUri via the configured
    /// <see cref="SendFormPostDelegate"/>, and returns the JAR delivered in
    /// the response body alongside the nonce sent (so the PDA trace can
    /// reflect it). Caller validates the JAR's wallet_nonce echo on the
    /// existing decrypt-and-verify path.
    /// </summary>
    private async ValueTask<(string WalletNonce, string CompactJar)> FetchJarViaWalletPostAsync(
        PresentJarOptions presentJarOptions,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(presentJarOptions.WalletExchangePublicKey is null)
        {
            throw new InvalidOperationException(
                "PresentJarOptions.CompactJar is null so the wallet client " +
                "must drive request_uri_method=post per OID4VP 1.0 §5.10 — but " +
                "WalletExchangePublicKey is also null. Supply the exchange " +
                "public side (advertised in wallet_metadata.jwks) or hand the " +
                "client a pre-fetched JAR via CompactJar.");
        }

        if(walletConfiguration.SendFormPost is null)
        {
            throw new InvalidOperationException(
                "PresentJarOptions.CompactJar is null but the wallet " +
                "configuration has no SendFormPost transport delegate. Wire " +
                "Oid4VpWalletConfiguration.SendFormPost to a SendFormPost " +
                "implementation (typically HttpClient-backed in applications, " +
                "Kestrel-loopback in tests) to drive the §5.10 POST.");
        }

        string walletMetadataJson = WalletMetadataWriter.BuildForWalletPost(
            walletConfiguration.WalletCapabilities,
            presentJarOptions.WalletExchangePublicKey,
            presentJarOptions.JarEncryptionEnc,
            infrastructure.Base64UrlEncoder,
            walletConfiguration.MemoryPool);

        string walletNonce = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.Oid4VpWalletNonce, null, cancellationToken)
            .ConfigureAwait(false);

        OutgoingFormFields formFields = new()
        {
            [Oid4VpAuthorizationRequestParameterNames.WalletNonce] = walletNonce,
            [Oid4VpAuthorizationRequestParameterNames.WalletMetadata] = walletMetadataJson
        };

        HttpResponseData response = await walletConfiguration.SendFormPost(
            presentJarOptions.RequestUri,
            formFields,
            OutgoingHeaders.Empty,
            context,
            cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"OID4VP §5.10 request_uri POST returned HTTP {response.StatusCode}; " +
                $"expected 2xx with the JAR in the body. Body preview: " +
                $"{(response.Body is { Length: > 0 } ? response.Body[..Math.Min(120, response.Body.Length)] : "<empty>")}");
        }

        if(string.IsNullOrWhiteSpace(response.Body))
        {
            throw new InvalidOperationException(
                "OID4VP §5.10 request_uri POST returned an empty body; " +
                "expected the JAR (signed JWS or JWE-wrapped JWS).");
        }

        return (walletNonce, response.Body);
    }
}
