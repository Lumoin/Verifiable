using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.StatusList;
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
    /// <see langword="null"/> resolves to <see cref="SiopCombinedResponseCredentialQueryId"/>.
    /// </param>
    /// <param name="saltReuseSeam">
    /// SIOPv2 §12 combined-response seam: optional disclosure-salt-reuse detection for the
    /// <c>vp_token</c> (RFC 9901 §9.4). <see langword="null"/> when not opted into.
    /// </param>
    /// <param name="resolveVerifiedStatusListToken">
    /// SIOPv2 §12 combined-response seam: resolves and verifies the IETF Token Status List token a
    /// presented credential's <c>status.status_list</c> reference points at — the same seam
    /// <see cref="Oid4Vp.HaipOid4VpVerifierExecutor"/> takes, run here through the identical
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus"/> step. <see langword="null"/> when the
    /// deployment does not check credential status; a combined response whose credential references a
    /// status list then fails closed with a configuration fault rather than silently skipping the check.
    /// </param>
    /// <param name="credentialStatusPolicy">
    /// Decides, once per combined response and over every status the response's <c>vp_token</c>
    /// surfaced, whether a determined status refuses the presentation (SD-JWT VC -18: "Verifier policy
    /// decides…"). <see langword="null"/> uses <see cref="CredentialStatusPolicies.Surface"/> — a
    /// determinable revoked or suspended status is recorded on the verified state but never refused.
    /// </param>
    /// <param name="statusListFreshnessPolicy">
    /// The Section 8.3 step 4.b freshness policy applied to a resolved Status List Token's <c>iat</c>, or
    /// <see langword="null"/> to skip the check (today's behavior). Threaded to
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/>.
    /// </param>
    /// <param name="statusListCachingBounds">
    /// The Section 11.5 refresh-interval floor and ceiling applied to a resolved Status List Token's
    /// <c>ttl</c>, or <see langword="null"/> to leave it unclamped (today's behavior). Threaded to
    /// <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/>.
    /// </param>
    /// <param name="unsupportedStatusMechanisms">
    /// What to do with a presented credential whose <c>status</c> claim names only status mechanisms this
    /// library does not evaluate. Defaults to <see cref="UnsupportedStatusMechanismDisposition.Refuse"/> —
    /// Token Status List §8.3's "no statement about the status of the Referenced Token can be made and the
    /// Referenced Token SHOULD be rejected"; pass <see cref="UnsupportedStatusMechanismDisposition.Surface"/>
    /// to accept the presentation instead and read the mechanism names off
    /// <see cref="Oid4Vp.Server.VpCredentialClaims.Status"/>.
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
    /// naming the failing check. A <c>vp_token</c> whose SD-JWT/KB-JWT parse fails, or whose
    /// <c>status.status_list</c> reference does not adhere to the Token Status List §6.2 rules, is a
    /// shape no conformant Wallet would produce; it is refused with
    /// <see cref="VerifierFlowRefusalKind.Malformed"/> — <c>invalid_request</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see> — the
    /// same classification the OID4VP seat gives the identical Wallet-attributable shape, and the
    /// <c>error_description</c> stays the fixed, non-revealing sentence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.9">OID4VP
    /// 1.0 §15.9</see> asks for. Only once every one of the seven binding checks holds does the handler
    /// read the credential's Token Status List status and apply <paramref name="credentialStatusPolicy"/>
    /// — Token Status List §8.3's ordering: "the processing rules for Referenced Tokens … MUST precede
    /// any evaluation of a Referenced Token's status".
    /// </para>
    /// </remarks>
    public static void Register(
        OAuthActionExecutor executor,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        BaseMemoryPool pool,
        TimeProvider timeProvider,
        ResolveDidVerificationKeyDelegate? resolveDidVerificationKey = null,
        ResolveIssuerKeyDelegate? resolveIssuerKey = null,
        ParseSdJwtTokenDelegate? parseSdJwtToken = null,
        ComputeSdJwtHashInputDelegate? computeSdJwtHashInput = null,
        ComputeDigestDelegate? computeDigest = null,
        CredentialQueryId? vpTokenCredentialQueryId = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken = null,
        CredentialStatusPolicy? credentialStatusPolicy = null,
        StatusListFreshnessPolicy? statusListFreshnessPolicy = null,
        StatusListCachingBounds? statusListCachingBounds = null,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms = UnsupportedStatusMechanismDisposition.Refuse)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        CredentialQueryId resolvedVpTokenCredentialQueryId =
            vpTokenCredentialQueryId ?? SiopCombinedResponseCredentialQueryId;

        //SD-JWT VC -18: "Verifier policy decides…". Resolved once at registration time so every
        //ValidateCombinedSiopResponse invocation applies the identical policy over its complete status
        //map. The default never refuses — a determinable revoked/suspended status is still recorded.
        CredentialStatusPolicy statusPolicy = credentialStatusPolicy ?? CredentialStatusPolicies.Surface;

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
                cancellationToken: cancellationToken).ConfigureAwait(false);

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
                cancellationToken: cancellationToken).ConfigureAwait(false);

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

                    SiopFlowFailed? nonceReplayFailure = nonceReplayOutcome switch
                    {
                        //A replayed nonce is a Wallet-attributable input the RP cannot verify a second
                        //time — SIOPv2 §11.2's cross-device replay defense rejects it, the same way an
                        //unverifiable Authorization Response does on the OID4VP seat.
                        JtiReplayOutcome.Replayed => new SiopFlowFailed
                        {
                            Reason =
                                "Self-Issued ID Token nonce has already been seen in a previous "
                                + "Authorization Response (SIOPv2 §11.2 cross-device replay).",
                            FailedAt = now,
                            Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable)
                        },
                        //A nonce the replay guard cannot track is not a shape a conformant Wallet
                        //produces under this RP's policy — Malformed, not a Verifier fault.
                        JtiReplayOutcome.Unacceptable => new SiopFlowFailed
                        {
                            Reason =
                                "Self-Issued ID Token nonce exceeds the length the replay guard "
                                + "can track (SIOPv2 §11.2).",
                            FailedAt = now,
                            Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
                        },
                        //No replay store configured under a Required policy is the deployment's own
                        //configuration fault, not anything the Wallet did — stays a genuine 500 fault.
                        JtiReplayOutcome.StoreUnavailable => new SiopFlowFailed
                        {
                            Reason =
                                "Self-Issued ID Token nonce replay defense is required by policy but "
                                + "no replay store is configured (SIOPv2 §11.2).",
                            FailedAt = now
                        },
                        _ => null
                    };
                    if(nonceReplayFailure is not null)
                    {
                        return nonceReplayFailure;
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

            //The §11.1 cryptographic/structural verdict is negative — a Wallet-attributable input the
            //RP cannot verify, the SIOP twin of the OID4VP seat's Unverifiable classification.
            return new SiopFlowFailed
            {
                Reason =
                    "Self-Issued ID Token validation failed "
                    + $"(structural={result.IsStructurallyValid}, selfIssued={result.IsSelfIssued}, "
                    + $"subJwkShape={result.IsSubJwkShapeValid}, alg={result.IsAlgorithmAllowed}, "
                    + $"signature={result.IsSignatureValid}, subjectConfirmed={result.IsSubjectConfirmed}, "
                    + $"audience={result.IsAudienceValid}, nonce={result.IsNonceValid}, "
                    + $"unexpired={result.IsUnexpired}).",
                FailedAt = now,
                Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable)
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
            //
            //Wallet-attributable malformed-presentation detection mirrors the OID4VP seat's per-format
            //dispatch (HaipOid4VpVerifierExecutor): an unparseable SD-JWT/KB-JWT or a status.status_list
            //reference that fails Section 6.2's own rules is a shape no conformant Wallet would produce
            //— Malformed, not a 500 fault. VerifyAsync throws many exception types for many reasons (a
            //wrong issuer key, a bad signature); only FormatException — the library's own parse-exception
            //type — is targeted here, so a non-format failure is left on the fault path.
            VpTokenParsed parsed;
            try
            {
                parsed = await SdJwtVpTokenVerification.VerifyAsync(
                    action.VpToken,
                    resolvedVpTokenCredentialQueryId,
                    parseSdJwtToken,
                    computeSdJwtHashInput,
                    resolveIssuerKey,
                    computeDigest,
                    base64UrlDecoder,
                    base64UrlEncoder,
                    pool,
                    saltReuseSeam,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(FormatException exception)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        $"Malformed vp_token presentation for credential query '{resolvedVpTokenCredentialQueryId}': "
                        + exception.Message,
                    FailedAt = now,
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
                };
            }

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

            if(!(credentialSignatureValid
                && kbJwtSignatureValid
                && sdHashValid
                && vpNonceBound
                && vpAudBound
                && idTokenNonceBound
                && !saltReused))
            {
                //The §12 binding conjunction is a Wallet-attributable verification verdict — a signature,
                //hash, or binding check failed — the same Unverifiable classification the OID4VP seat
                //answers for its own DCQL/claims/binding verdict failures.
                return new SiopFlowFailed
                {
                    Reason =
                        "SIOPv2 §12 combined response verification failed "
                        + $"(credentialSignature={credentialSignatureValid}, kbJwtSignature={kbJwtSignatureValid}, "
                        + $"sdHash={sdHashValid}, vpTokenNonceBound={vpNonceBound}, vpTokenAudBound={vpAudBound}, "
                        + $"idTokenNonceBound={idTokenNonceBound}, saltReused={saltReused}).",
                    FailedAt = now,
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable)
                };
            }

            //The seven-way binding holds; only now does Token Status List §8.3's ordering permit reading
            //the credential's status ("the processing rules for Referenced Tokens … MUST precede any
            //evaluation of a Referenced Token's status"). Run the identical shared step the OID4VP
            //direct_post seat runs.
            CredentialStatusCheck statusCheck = await VpTokenCredentialStatus.CheckAsync(
                parsed, resolvedVpTokenCredentialQueryId, resolveVerifiedStatusListToken, now,
                statusListFreshnessPolicy, statusListCachingBounds, unsupportedStatusMechanisms,
                cancellationToken)
                .ConfigureAwait(false);

            if(statusCheck.Kind == CredentialStatusCheckKind.Undeterminable)
            {
                return new SiopFlowFailed
                {
                    Reason = statusCheck.LogReason!,
                    FailedAt = now,
                    Refusal = statusCheck.Refusal!.Value
                };
            }

            Dictionary<CredentialQueryId, CredentialStatusOutcome> credentialStatuses = new();
            if(statusCheck.Kind == CredentialStatusCheckKind.Determined)
            {
                credentialStatuses[resolvedVpTokenCredentialQueryId] = statusCheck.Outcome!;
            }

            if(ApplyCredentialStatusPolicy(statusPolicy, credentialStatuses, now) is { } policyRefusal)
            {
                return policyRefusal;
            }

            //Both artifacts valid and bound to the same transaction, and any referenced credential
            //status either did not apply or stood under the wired policy. The authenticated SIOP
            //subject (the id_token's verified sub) is carried forward; SIOPv2 §2.2.1: it is the
            //SIOP subject key's thumbprint, unrelated to the credential's holder binding.
            return verifiedIdToken with
            {
                VerifiedAt = now,
                Credentials = new Dictionary<CredentialQueryId, VpCredentialClaims>
                {
                    [resolvedVpTokenCredentialQueryId] = parsed.Credential
                },
                CredentialStatuses = credentialStatuses.Count > 0 ? credentialStatuses : null
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
                    FailedAt = timeProvider.GetUtcNow(),
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
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
                    FailedAt = timeProvider.GetUtcNow(),
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
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
                    FailedAt = timeProvider.GetUtcNow(),
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
                };
            }

            //Wallet-attributable malformed-response detection: an over-long compact JWE, or one
            //ParseCompact itself rejects (RFC 7516 §3.1 shape, an invalid EPK, a bad IV/tag length), is
            //a shape no conformant Wallet would produce — Malformed, not a 500 fault. The length bound
            //is checked ahead of ParseCompact so an oversized value never reaches its own ArgumentException
            //contract; the parse itself is caught by exactly the FormatException type it throws, the same
            //targeted shape the OID4VP DecryptResponseAction handler uses.
            if(action.EncryptedIdToken.Length > JweParsing.MaxCompactJweByteCount)
            {
                return new SiopFlowFailed
                {
                    Reason =
                        "The encrypted Self-Issued ID Token exceeds the "
                        + $"{JweParsing.MaxCompactJweByteCount}-byte compact-serialization bound.",
                    FailedAt = timeProvider.GetUtcNow(),
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
                };
            }

            AeadMessage message;
            try
            {
                //Recover the inner compact id_token JWS. AES-GCM tag verification inside DecryptAsync
                //authenticates the protected header (the AAD) and the ciphertext; a tampered byte fails
                //the tag check. The tag-mismatch is mapped to a terminal flow failure here — the inner
                //plaintext is never recovered when the tag does not verify, so no inner token leaks, and
                //the flow reaches SiopVerifierFlowFailedState rather than surfacing an unhandled
                //cryptographic exception to the response endpoint.
                message = JweParsing.ParseCompact(
                    action.EncryptedIdToken,
                    WellKnownJweAlgorithms.EcdhEs,
                    enc,
                    base64UrlDecoder,
                    pool);
            }
            catch(FormatException exception)
            {
                return new SiopFlowFailed
                {
                    Reason = $"The encrypted Self-Issued ID Token is not a well-formed compact JWE: {exception.Message}",
                    FailedAt = timeProvider.GetUtcNow(),
                    Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
                };
            }

            using(message)
            {
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
                        FailedAt = timeProvider.GetUtcNow(),
                        Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed)
                    };
                }

                //The decrypted plaintext is the bare compact Self-Issued ID Token JWS; run the SAME shared
                //§11.1 + §11.2 validation the bare-JWS path runs, mapping the verdict identically.
                return await ValidateIdTokenAsync(
                    innerIdToken, action.ExpectedAudience, action.ExpectedNonce,
                    action.AllowedAlgorithms, context, cancellationToken).ConfigureAwait(false);
            }
        });
    }


    /// <summary>
    /// Applies <paramref name="credentialStatusPolicy"/> once over the complete
    /// <paramref name="credentialStatuses"/> map the §12 combined-response handler read, after the
    /// seven-way id_token/vp_token binding has already been confirmed. SD-JWT VC -18: "Verifier policy
    /// decides whether to reject or accept a presentation of a SD-JWT VC based on the status of the
    /// Verifiable Digital Credential." Skipped entirely when the map is empty — nothing was surfaced to
    /// judge. The SIOP-side sibling of <see cref="Oid4Vp.HaipOid4VpVerifierExecutor"/>'s equivalent step.
    /// </summary>
    /// <returns>
    /// A <see cref="SiopFlowFailed"/> carrying <see cref="VerifierFlowRefusalKind.PolicyRefused"/> and the
    /// policy's typed <see cref="CredentialStatusRefusal"/> when the policy refuses; otherwise
    /// <see langword="null"/> to let the presentation stand.
    /// </returns>
    private static SiopFlowFailed? ApplyCredentialStatusPolicy(
        CredentialStatusPolicy credentialStatusPolicy,
        Dictionary<CredentialQueryId, CredentialStatusOutcome> credentialStatuses,
        DateTimeOffset failedAt)
    {
        if(credentialStatuses.Count == 0)
        {
            return null;
        }

        CredentialStatusRefusal? refusal = credentialStatusPolicy(credentialStatuses);
        if(refusal is null)
        {
            return null;
        }

        return new SiopFlowFailed
        {
            Reason = refusal.Description,
            FailedAt = failedAt,
            Refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.PolicyRefused),
            CredentialStatusRefusal = refusal
        };
    }


    /// <summary>
    /// The default DCQL credential query identifier the SIOPv2 §12 combined response's
    /// <c>vp_token</c> presentation is keyed under when extracting its claims. The §12 combined
    /// response presents a single credential, so a single fixed key suffices. The identifier is this
    /// library's own choice — SIOPv2 1.0 §12 registers no credential query identifier — and conforms
    /// to OpenID for Verifiable Presentations 1.0 §6.1's character rule; this member is the value's
    /// single home, deliberately not a name-table constant, so every consumer takes the validated
    /// <see cref="CredentialQueryId"/> rather than a raw string. A <c>sealed record</c>
    /// is not a compile-time constant, so <c>Register</c>/<c>Create</c>'s <c>vpTokenCredentialQueryId</c>
    /// parameters default to <see langword="null"/> and resolve to this value in the method body.
    /// </summary>
    public static CredentialQueryId SiopCombinedResponseCredentialQueryId { get; } = new("siop_vp");


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
        BaseMemoryPool pool,
        TimeProvider timeProvider,
        ResolveDidVerificationKeyDelegate? resolveDidVerificationKey = null,
        ResolveIssuerKeyDelegate? resolveIssuerKey = null,
        ParseSdJwtTokenDelegate? parseSdJwtToken = null,
        ComputeSdJwtHashInputDelegate? computeSdJwtHashInput = null,
        ComputeDigestDelegate? computeDigest = null,
        CredentialQueryId? vpTokenCredentialQueryId = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        ResolveVerifiedStatusListTokenDelegate? resolveVerifiedStatusListToken = null,
        CredentialStatusPolicy? credentialStatusPolicy = null,
        StatusListFreshnessPolicy? statusListFreshnessPolicy = null,
        StatusListCachingBounds? statusListCachingBounds = null,
        UnsupportedStatusMechanismDisposition unsupportedStatusMechanisms = UnsupportedStatusMechanismDisposition.Refuse)
    {
        OAuthActionExecutor executor = new();
        Register(
            executor, base64UrlDecoder, base64UrlEncoder, headerSerializer, payloadSerializer,
            pool, timeProvider, resolveDidVerificationKey, resolveIssuerKey, parseSdJwtToken,
            computeSdJwtHashInput, computeDigest, vpTokenCredentialQueryId, saltReuseSeam,
            resolveVerifiedStatusListToken, credentialStatusPolicy,
            statusListFreshnessPolicy, statusListCachingBounds, unsupportedStatusMechanisms);

        return executor;
    }
}
