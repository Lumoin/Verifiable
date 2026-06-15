using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop.Server.States;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Contributes the SIOPv2 RP flow's effectful action handler to an
/// <see cref="OAuthActionExecutor"/>. The executor is the server's single, shared,
/// action-type-keyed dispatch registry — one instance can hold the handlers of every stateful
/// flow a deployment runs — so <see cref="Register"/> adds the SIOP handler ALONGSIDE whatever
/// else is registered (e.g. the OID4VP verifier handlers), while <see cref="Create"/> is the
/// convenience for a SIOP-only deployment.
/// </summary>
public static class SiopVerifierExecutor
{
    /// <summary>
    /// Registers the SIOPv2 RP flow's effectful handlers on <paramref name="executor"/>: the
    /// <see cref="SignSiopRequestObject"/> handler that signs the §9 Request Object served at the
    /// <c>request_uri</c> (the by-reference path), and the <see cref="ValidateSelfIssuedIdToken"/>
    /// handler that runs the §11.1 validation through <see cref="SelfIssuedIdTokenValidation"/> — the
    /// effectful steps between pure PDA transitions. Signing emits
    /// <see cref="SiopRequestObjectSigned"/>; validation emits
    /// <see cref="SelfIssuedAuthenticationVerified"/> on success or <see cref="SiopFlowFailed"/> with
    /// the failing check otherwise.
    /// </summary>
    /// <param name="executor">The shared executor to contribute the handlers to.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the token segments.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for thumbprint recomputation and §9 Request Object signing.</param>
    /// <param name="headerSerializer">Delegate serializing the §9 Request Object JWT header.</param>
    /// <param name="payloadSerializer">Delegate serializing the §9 Request Object JWT payload.</param>
    /// <param name="pool">Memory pool for validation and signing allocations.</param>
    /// <param name="timeProvider">Time source for the expiry check and verification stamp.</param>
    /// <param name="resolveDidVerificationKey">
    /// Resolves a DID's verification key for the DID Subject Syntax Type; <see langword="null"/>
    /// when only the JWK Thumbprint type is supported (the validator then fails closed on a DID
    /// subject).
    /// </param>
    /// <param name="resolveIssuerKey">
    /// SIOPv2 §12 combined-response seam: resolves a credential issuer's public key from its
    /// identifier for the <c>vp_token</c> issuer-signature check. Closed over here at registration
    /// time the same way the OID4VP verifier executor closes over it — the
    /// <see cref="ValidateCombinedSiopResponse"/> action carries no seams. <see langword="null"/>
    /// for an id_token-only deployment; a combined response then fails closed.
    /// </param>
    /// <param name="parseSdJwtToken">
    /// SIOPv2 §12 combined-response seam: parses the <c>vp_token</c> SD-JWT wire format. Wired to
    /// <c>SdJwtSerializer.ParseToken</c>. <see langword="null"/> for an id_token-only deployment.
    /// </param>
    /// <param name="computeSdJwtHashInput">
    /// SIOPv2 §12 combined-response seam: computes the <c>vp_token</c> KB-JWT <c>sd_hash</c> input.
    /// Wired to <c>SdJwtSerializer.GetSdJwtForHashing</c>. <see langword="null"/> for an
    /// id_token-only deployment.
    /// </param>
    /// <param name="computeDigest">
    /// SIOPv2 §12 combined-response seam: computes the <c>sd_hash</c> digest for the <c>vp_token</c>.
    /// <see langword="null"/> for an id_token-only deployment.
    /// </param>
    /// <param name="vpTokenCredentialQueryId">
    /// The DCQL credential query identifier the <c>vp_token</c> presentation is keyed under when
    /// extracting its claims (the §12 combined response presents a single credential).
    /// </param>
    /// <param name="saltReuseSeam">
    /// SIOPv2 §12 combined-response seam: optional disclosure-salt-reuse detection for the
    /// <c>vp_token</c> (RFC 9901 §9.4). <see langword="null"/> when not opted into.
    /// </param>
    /// <remarks>
    /// <para>
    /// After the §11.1 cryptographic validation passes, the handler enforces the SIOPv2 §11.2
    /// cross-device replay defense: the ID Token's <c>nonce</c> MUST be known to the RP and MUST
    /// NOT have been used in a previous Authorization Response. This rides the server's existing
    /// <c>(issuer, jti)</c> correlation store through <see cref="JtiReplayGuard"/> — keyed on
    /// <c>(client_id, nonce)</c> so the per-transaction nonce, scoped to the RP that issued it,
    /// is the replay token — governed by <see cref="JtiReplayPolicy"/>: <c>Required</c> fails
    /// closed when no store is wired, and the read and first-use record happen as one unit. The
    /// consultation is an EFFECT, run here in the action handler rather than in the pure
    /// preparation/response transitions.
    /// </para>
    /// <para>
    /// The <see cref="ValidateCombinedSiopResponse"/> handler additionally verifies the
    /// <c>vp_token</c> presentation through <see cref="SdJwtVpTokenVerification.VerifyAsync"/> using
    /// the vp_token seams closed over here, and enforces the §12 binding: the id_token nonce, the
    /// vp_token KB-JWT nonce, and the expected transaction nonce must all match, and the vp_token
    /// KB-JWT <c>aud</c> must equal the RP's Client ID. Any miss yields <see cref="SiopFlowFailed"/>
    /// naming the failing check.
    /// </para>
    /// </remarks>
    public static void Register(
        OAuthActionExecutor executor,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> pool,
        TimeProvider timeProvider,
        ResolveDidVerificationKeyDelegate? resolveDidVerificationKey = null,
        ResolveIssuerKeyDelegate? resolveIssuerKey = null,
        ParseSdJwtTokenDelegate? parseSdJwtToken = null,
        ComputeSdJwtHashInputDelegate? computeSdJwtHashInput = null,
        ComputeDigestDelegate? computeDigest = null,
        string vpTokenCredentialQueryId = SiopCombinedResponseCredentialQueryId,
        CommitmentReuseDetectionSeam? saltReuseSeam = null)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(vpTokenCredentialQueryId);

        //SIOPv2 §9 Request Object signing. Signing is an EFFECT, so it runs here in the action
        //handler rather than in the pure PDA transition or the endpoint's BuildInputAsync — the
        //same discipline the OID4VP SignJarAction follows. The handler resolves the registered
        //signing key, composes the §9 claim set (response_type=id_token, client_id, nonce,
        //redirect_uri, the §9.1 aud the endpoint decided, and the state handle), signs it into a
        //compact JWS with the OauthAuthzReqJwt typ per RFC 9101 §5, parks it on the context for the
        //application skin to serve, and emits the served input that steps the PDA forward.
        executor.Register<SignSiopRequestObject>(async (action, context, cancellationToken) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException("Tenant identifier not found in context.");

            PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver!(
                action.SigningKeyId, tenantId, context, cancellationToken).ConfigureAwait(false);

            if(signingKey is null)
            {
                throw new InvalidOperationException(
                    $"Signing key '{action.SigningKeyId}' not found for the SIOP §9 Request Object.");
            }

            //Stamp timing claims from the dispatcher's per-request VerifiedAt when available so all
            //effectful work in this request shares one instant; fall back to the active TimeProvider
            //otherwise. The exp - nbf window is policy, sourced from oauth.Timings, reusing the
            //request-object lifetime axis the OID4VP JAR also reads.
            DateTimeOffset now = context.VerifiedAt ?? timeProvider.GetUtcNow();
            DateTimeOffset exp = now + oauth.Timings.Oid4VpRequestObjectLifetime;

            JwtHeader header = new()
            {
                [WellKnownJwkMemberNames.Alg] = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag),
                [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
            };

            //SIOPv2 §9 Request Object and the OID4VP JAR are the same RFC 9101 oauth-authz-req+jwt
            //artifact, so the wallet resolves the RP's signing key through the same client-id trust
            //fabric (x5c, trust_chain, verifier_attestation jwt, kid). Merge the caller-supplied
            //header material the same way the OID4VP JAR does: alg and typ are the library's to set
            //and are never overwritten — every other key (x5c, trust_chain, jwt, kid) is copied in.
            if(action.AdditionalHeaderClaims is not null)
            {
                foreach(KeyValuePair<string, object> claim in action.AdditionalHeaderClaims)
                {
                    if(claim.Key != WellKnownJwkMemberNames.Alg
                        && claim.Key != WellKnownJoseHeaderNames.Typ)
                    {
                        header[claim.Key] = claim.Value;
                    }
                }
            }

            //SIOPv2 §9 Request Object claim set. response_type=id_token; the RP's client_id is both
            //the iss of the request and the aud the Self-Issued ID Token must carry; the §9.1 aud is
            //the value the endpoint resolved (the static-discovery https://self-issued.me/v2 or the
            //dynamically discovered issuer). state is the per-flow handle the Wallet echoes.
            JwtPayload payload = new()
            {
                [OAuthRequestParameterNames.ResponseType] = SiopAuthorizationRequestParameterValues.ResponseTypeIdToken,
                [WellKnownJwtClaimNames.ClientId] = action.ClientId,
                [WellKnownJwtClaimNames.Iss] = action.ClientId,
                [WellKnownJwtClaimNames.Aud] = action.Audience,
                [OAuthRequestParameterNames.RedirectUri] = action.RedirectUri.OriginalString,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
                [WellKnownJwtClaimNames.Nonce] = action.Nonce,
                [OAuthRequestParameterNames.State] = action.RequestHandle,
                [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Nbf] = now.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Exp] = exp.ToUnixTimeSeconds()
            };

            if(action.IdTokenType is not null)
            {
                payload[SiopAuthorizationRequestParameterNames.IdTokenType] = action.IdTokenType;
            }

            UnsignedJwt unsigned = new(header, payload);
            using JwsMessage signed = await unsigned.SignAsync(
                signingKey,
                headerSerializer,
                payloadSerializer,
                base64UrlEncoder,
                pool,
                cancellationToken).ConfigureAwait(false);

            string compactRequestObject = JwsSerialization.SerializeCompact(signed, base64UrlEncoder);

            //Park the signed compact JWS on the context so the application skin serves it in the
            //HTTP response body at the request_uri endpoint — the SIOP parallel of context.SetJar.
            context.SetSiopRequestObject(compactRequestObject);

            return new SiopRequestObjectSigned { ServedAt = now };
        });

        //The §11.1 cryptographic validation + §11.2 replay consult, shared by the id_token-only
        //handler and the §12 combined handler. Returns the verified verdict on success (the caller
        //layers any further checks on top), or a SiopFlowFailed naming the failing §11.1 / §11.2
        //check. The replay consult is the same server-store EFFECT both paths perform.
        async ValueTask<FlowInput> ValidateIdTokenAsync(
            string idToken,
            string expectedAudience,
            string expectedNonce,
            IReadOnlyList<string> allowedAlgorithms,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
                idToken,
                expectedAudience,
                expectedNonce,
                allowedAlgorithms,
                timeProvider.GetUtcNow(),
                resolveDidVerificationKey,
                base64UrlDecoder,
                base64UrlEncoder,
                pool,
                cancellationToken).ConfigureAwait(false);

            DateTimeOffset now = timeProvider.GetUtcNow();
            if(result.IsValid)
            {
                //SIOPv2 §11.2: the nonce MUST be known to the RP and MUST NOT have been used in a
                //previous Authorization Response. The per-transaction nonce, scoped to the RP that
                //issued it (client_id), is the replay token — so the guard keys on
                //(issuer = client_id, jti = nonce) over the shared (issuer, jti) store. The entry
                //is retained until the token's exp plus skew — exactly the window the §11.1
                //temporal check accepts the token in — falling back to a bounded window when the
                //token (already validated as unexpired) somehow carries no exp. The consultation is
                //a server-store EFFECT: it runs only when the handler ran under a dispatched
                //EndpointServer (context carries the server and the resolved tenant). The
                //free-standing executor primitive — exercised with a bare ExchangeContext and no
                //server-backed store — has no store to consult, the same no-store-not-Required
                //proceed JtiReplayGuard itself applies.
                EndpointServer? server = context.Server;
                TenantId? tenantId = context.TenantId;
                if(server is not null && tenantId is not null)
                {
                    DateTimeOffset replayExpiresAt = result.ExpiresAt is DateTimeOffset exp
                        ? exp + context.ClockSkewTolerance
                        : now + WellKnownDpopValues.DefaultReplayWindow;

                    JtiReplayOutcome nonceReplayOutcome = await JtiReplayGuard.ConsultAsync(
                        server, context, tenantId.Value,
                        expectedAudience, expectedNonce,
                        replayExpiresAt, cancellationToken).ConfigureAwait(false);

                    if(nonceReplayOutcome == JtiReplayOutcome.Replayed)
                    {
                        return new SiopFlowFailed
                        {
                            Reason =
                                "Self-Issued ID Token nonce has already been seen in a previous "
                                + "Authorization Response (SIOPv2 §11.2 cross-device replay).",
                            FailedAt = now
                        };
                    }

                    if(nonceReplayOutcome == JtiReplayOutcome.StoreUnavailable)
                    {
                        return new SiopFlowFailed
                        {
                            Reason =
                                "Self-Issued ID Token nonce replay defense is required by policy but "
                                + "no replay store is configured (SIOPv2 §11.2).",
                            FailedAt = now
                        };
                    }
                }

                return new SelfIssuedAuthenticationVerified
                {
                    Subject = result.Subject!,
                    SubjectSyntaxType = result.SubjectSyntaxType,
                    Nonce = result.Nonce!,
                    VerifiedAt = now
                };
            }

            return new SiopFlowFailed
            {
                Reason =
                    "Self-Issued ID Token validation failed "
                    + $"(structural={result.IsStructurallyValid}, selfIssued={result.IsSelfIssued}, "
                    + $"subJwkShape={result.IsSubJwkShapeValid}, alg={result.IsAlgorithmAllowed}, "
                    + $"signature={result.IsSignatureValid}, subjectConfirmed={result.IsSubjectConfirmed}, "
                    + $"audience={result.IsAudienceValid}, nonce={result.IsNonceValid}, "
                    + $"unexpired={result.IsUnexpired}).",
                FailedAt = now
            };
        }

        executor.Register<ValidateSelfIssuedIdToken>((action, context, cancellationToken) =>
            ValidateIdTokenAsync(
                action.IdToken, action.ExpectedAudience, action.ExpectedNonce,
                action.AllowedAlgorithms, context, cancellationToken));

        executor.Register<ValidateCombinedSiopResponse>(async (action, context, cancellationToken) =>
        {
            //SIOPv2 §12: the id_token authenticates the End-User (§11.1) and the vp_token carries
            //issuer-attested claims — BOTH bound to the same transaction. Run the id_token §11.1 +
            //§11.2 path first (including the replay consult); a miss there fails the whole flow.
            FlowInput idTokenVerdict = await ValidateIdTokenAsync(
                action.IdToken, action.ExpectedAudience, action.ExpectedNonce,
                action.AllowedAlgorithms, context, cancellationToken).ConfigureAwait(false);

            if(idTokenVerdict is not SelfIssuedAuthenticationVerified verifiedIdToken)
            {
                return idTokenVerdict;
            }

            DateTimeOffset now = timeProvider.GetUtcNow();

            //The §12 combined response needs the vp_token-verification seams; a deployment that
            //registered the SIOP handler for id_token-only flows did not supply them, so a combined
            //response that arrives there fails closed rather than silently skipping the vp_token.
            if(resolveIssuerKey is null
                || parseSdJwtToken is null
                || computeSdJwtHashInput is null
                || computeDigest is null)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        "A SIOPv2 §12 combined response carried a vp_token but the SIOP verifier "
                        + "executor was registered without the vp_token-verification seams "
                        + "(resolveIssuerKey / parseSdJwtToken / computeSdJwtHashInput / computeDigest). "
                        + "Pass them to SiopVerifierExecutor.Register / Create to accept combined responses.",
                    FailedAt = now
                };
            }

            //Verify the vp_token presentation with its production primitive — the same
            //SdJwtVpTokenVerification the OID4VP verifier flow runs: credential issuer signature,
            //KB-JWT signature against the cnf holder key, and sd_hash over the disclosed set.
            VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
                action.VpToken,
                vpTokenCredentialQueryId,
                parseSdJwtToken,
                computeSdJwtHashInput,
                resolveIssuerKey,
                computeDigest,
                base64UrlDecoder,
                base64UrlEncoder,
                pool,
                saltReuseSeam,
                cancellationToken).ConfigureAwait(false);

            //SIOPv2 §12 binding: the vp_token's KB-JWT MUST carry the same nonce the RP provided
            //(equal to the verified id_token nonce) and the RP's Client ID as aud. The id_token's
            //nonce binding was already enforced by §11.1 above; here the vp_token half is bound to
            //the same transaction, and the two artifacts are tied together by the shared nonce.
            bool credentialSignatureValid = parsed.CredentialSignatureValid;
            bool kbJwtSignatureValid = parsed.KbJwtSignatureValid;
            bool sdHashValid = parsed.SdHashValid;
            bool vpNonceBound = string.Equals(parsed.KbJwtNonce, action.ExpectedNonce, StringComparison.Ordinal);
            bool vpAudBound = string.Equals(parsed.KbJwtAud, action.ExpectedAudience, StringComparison.Ordinal);
            bool idTokenNonceBound = string.Equals(verifiedIdToken.Nonce, action.ExpectedNonce, StringComparison.Ordinal);
            bool saltReused = parsed.SaltReused;

            if(credentialSignatureValid
                && kbJwtSignatureValid
                && sdHashValid
                && vpNonceBound
                && vpAudBound
                && idTokenNonceBound
                && !saltReused)
            {
                //Both artifacts valid and bound to the same transaction. The authenticated SIOP
                //subject (the id_token's verified sub) is carried forward; SIOPv2 §2.2.1: it is the
                //SIOP subject key's thumbprint, unrelated to the credential's holder binding.
                return verifiedIdToken with { VerifiedAt = now };
            }

            return new SiopFlowFailed
            {
                Reason =
                    "SIOPv2 §12 combined response verification failed "
                    + $"(credentialSignature={credentialSignatureValid}, kbJwtSignature={kbJwtSignatureValid}, "
                    + $"sdHash={sdHashValid}, vpTokenNonceBound={vpNonceBound}, vpTokenAudBound={vpAudBound}, "
                    + $"idTokenNonceBound={idTokenNonceBound}, saltReused={saltReused}).",
                FailedAt = now
            };
        });

        executor.Register<DecryptSiopResponse>(async (action, context, cancellationToken) =>
        {
            //The Wallet returned the Self-Issued ID Token as a compact JWE encrypted to the RP's
            //advertised encryption key. Decryption is an EFFECT, so it runs here in the action handler
            //rather than in the pure PDA transition or the endpoint's BuildInputAsync — the same
            //discipline the OID4VP DecryptResponseAction handler follows. The handler resolves the
            //decryption private key off the server, validates the JWE enc header against the advertised
            //set BEFORE any cryptographic operation, decrypts to recover the inner compact id_token
            //JWS, then runs the shared §11.1 + §11.2 validation on it.
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            if(oauth.Cryptography.DecryptionKeyResolver is null)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        "An encrypted Self-Issued ID Token response arrived but the Authorization "
                        + "Server has no DecryptionKeyResolver configured to resolve the RP's private "
                        + "encryption key.",
                    FailedAt = timeProvider.GetUtcNow()
                };
            }

            PrivateKeyMemory? resolvedKey = await oauth.Cryptography.DecryptionKeyResolver(
                action.DecryptionKeyId, context, cancellationToken).ConfigureAwait(false);

            if(resolvedKey is null)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        $"The decryption key '{action.DecryptionKeyId.Value}' advertised as the RP's "
                        + "encryption key could not be resolved to decrypt the Self-Issued ID Token JWE.",
                    FailedAt = timeProvider.GetUtcNow()
                };
            }

            using PrivateKeyMemory decryptionKey = resolvedKey;

            //Peek enc from the JWE protected header before any cryptographic operation. This is an
            //early, not-yet-authenticated validation: the header is authenticated by AES-GCM tag
            //verification inside DecryptAsync, so tampering with enc causes tag verification to fail.
            //Fail closed when the segment is missing, the enc parameter is absent, or its value is not
            //in the advertised set — naming the rejected value in the latter case.
            int firstDot = action.EncryptedIdToken.IndexOf('.', StringComparison.Ordinal);
            if(firstDot < 0)
            {
                return new SiopFlowFailed
                {
                    Reason = "The encrypted Self-Issued ID Token is not a compact JWE (no dot-separated segments).",
                    FailedAt = timeProvider.GetUtcNow()
                };
            }

            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(
                action.EncryptedIdToken.AsSpan(0, firstDot).ToString(), pool);

            string? enc = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "enc"u8);

            if(enc is null)
            {
                return new SiopFlowFailed
                {
                    Reason = "The Self-Issued ID Token JWE protected header does not contain the 'enc' parameter.",
                    FailedAt = timeProvider.GetUtcNow()
                };
            }

            bool encAllowed = false;
            foreach(string allowed in action.AllowedEncAlgorithms)
            {
                if(string.Equals(enc, allowed, StringComparison.Ordinal))
                {
                    encAllowed = true;
                    break;
                }
            }

            if(!encAllowed)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        $"The Self-Issued ID Token JWE 'enc' value '{enc}' is not in the Relying "
                        + "Party's advertised encrypted-response enc algorithms.",
                    FailedAt = timeProvider.GetUtcNow()
                };
            }

            //Recover the inner compact id_token JWS. AES-GCM tag verification inside DecryptAsync
            //authenticates the protected header (the AAD) and the ciphertext; a tampered byte fails
            //the tag check. The tag-mismatch is mapped to a terminal flow failure here — the inner
            //plaintext is never recovered when the tag does not verify, so no inner token leaks, and
            //the flow reaches SiopVerifierFlowFailedState rather than surfacing an unhandled
            //cryptographic exception to the response endpoint.
            using AeadMessage message = JweParsing.ParseCompact(
                action.EncryptedIdToken,
                WellKnownJweAlgorithms.EcdhEs,
                enc,
                base64UrlDecoder,
                pool);

            string innerIdToken;
            try
            {
                using DecryptedContent decrypted = await message.DecryptAsync(
                    decryptionKey, pool, cancellationToken).ConfigureAwait(false);

                innerIdToken = Encoding.UTF8.GetString(decrypted.AsReadOnlySpan());
            }
            catch(System.Security.Cryptography.CryptographicException)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        "The Self-Issued ID Token JWE failed AES-GCM authentication-tag verification; "
                        + "the ciphertext or protected header was tampered with, so no inner token was "
                        + "recovered.",
                    FailedAt = timeProvider.GetUtcNow()
                };
            }

            //The decrypted plaintext is the bare compact Self-Issued ID Token JWS; run the SAME shared
            //§11.1 + §11.2 validation the bare-JWS path runs, mapping the verdict identically.
            return await ValidateIdTokenAsync(
                innerIdToken, action.ExpectedAudience, action.ExpectedNonce,
                action.AllowedAlgorithms, context, cancellationToken).ConfigureAwait(false);
        });
    }


    /// <summary>
    /// The default DCQL credential query identifier the SIOPv2 §12 combined response's
    /// <c>vp_token</c> presentation is keyed under when extracting its claims. The §12 combined
    /// response presents a single credential, so a single fixed key suffices.
    /// </summary>
    public const string SiopCombinedResponseCredentialQueryId = "siop_vp";


    /// <summary>
    /// Creates a fresh <see cref="OAuthActionExecutor"/> holding only the SIOP RP handlers (§9
    /// Request Object signing, §11.1 ID Token validation, and the §12 combined response when the
    /// vp_token seams are supplied) — the convenience for a deployment that runs SIOP without
    /// OID4VP. Multi-flow deployments instead call <see cref="Register"/> on their existing shared
    /// executor.
    /// </summary>
    public static OAuthActionExecutor Create(
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> pool,
        TimeProvider timeProvider,
        ResolveDidVerificationKeyDelegate? resolveDidVerificationKey = null,
        ResolveIssuerKeyDelegate? resolveIssuerKey = null,
        ParseSdJwtTokenDelegate? parseSdJwtToken = null,
        ComputeSdJwtHashInputDelegate? computeSdJwtHashInput = null,
        ComputeDigestDelegate? computeDigest = null,
        string vpTokenCredentialQueryId = SiopCombinedResponseCredentialQueryId,
        CommitmentReuseDetectionSeam? saltReuseSeam = null)
    {
        OAuthActionExecutor executor = new();
        Register(
            executor, base64UrlDecoder, base64UrlEncoder, headerSerializer, payloadSerializer,
            pool, timeProvider, resolveDidVerificationKey, resolveIssuerKey, parseSdJwtToken,
            computeSdJwtHashInput, computeDigest, vpTokenCredentialQueryId, saltReuseSeam);

        return executor;
    }
}
