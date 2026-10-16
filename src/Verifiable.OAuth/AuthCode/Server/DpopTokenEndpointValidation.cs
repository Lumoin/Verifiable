using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// Shared helper for DPoP proof validation at the token endpoint. Used by
/// both the authorization-code grant (where the binding is being
/// established) and the refresh-token grant (where the binding is being
/// verified against a stored thumbprint).
/// </summary>
/// <remarks>
/// <para>
/// Implements the operational ordering from
/// <c>AuthorizationServerDesign.md §5</c>: structural parse → format/policy
/// checks → cryptographic verification → storage-backed JTI replay check.
/// All DPoP-related response shaping (use_dpop_nonce challenge with fresh
/// nonce, invalid_dpop_proof, ServerError when delegates aren't wired)
/// happens inside this helper; callers receive a single typed outcome.
/// </para>
/// <para>
/// ONE server nonce policy governs every grant this file serves: a proof that carries no nonce
/// is ALWAYS challenged with a fresh <c>DPoP-Nonce</c>, whatever the registration's profile or
/// (at a step endpoint) any stored record says — <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC
/// 9449 §8</see>: the nonce requirement is the server's, never the grant's. <see cref="ValidateAsync"/>
/// applies it exactly as <see cref="ValidatePresentedProofAsync"/> does, so client credentials,
/// token exchange, the JWT-bearer grant and the pre-authorized code grant answer a nonce-less
/// proof identically to the two step endpoints (code redemption, refresh). A proof ABSENT from the request is a separate
/// decision, gated on whether DPoP is required at all (the registration's profile or the client's
/// <c>dpop_bound_access_tokens</c> declaration, or, at a step endpoint's handler, the stored record's own binding).
/// </para>
/// <para>
/// A STEP endpoint (code redemption, refresh live, refresh reuse) never calls
/// <see cref="ValidateAsync"/>: its pre-correlation step calls
/// <see cref="ValidatePresentedProofAsync"/> once, before any record is loaded, and its handler
/// calls <see cref="BindValidatedProofAsync"/> once the record's binding is known. Every other
/// call site (client credentials, token exchange, the JWT-bearer grant, the pre-authorized code
/// grant, and the pushed authorization request) has no pre-correlation step and calls
/// <see cref="ValidateAsync"/>: those requests create no prior record for a request-only decision
/// to run ahead of. At the pushed authorization request the proof is checked as
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>
/// requires ("the authorization server MUST check the provided DPoP proof JWT as defined in Section
/// 4.3"), its <c>htu</c> being the pushed request's own target, and the thumbprint it carries
/// becomes the binding of the code the request leads to.
/// The proof validation (<see cref="DpopRequestReading.ValidateProofAsync"/>: the application's
/// <c>ValidateDpopProofAsync</c>, or the library default when that slot is unassigned and the codecs carry a proof
/// parser), <c>ValidateDpopNonceAsync</c> and the <c>jti</c> guard each run
/// AT MOST once per request: a proof-absent or early-rejected request reaches none of them; a
/// nonce challenge or an invalid proof registers no <c>jti</c>; only a request whose proof
/// validates structurally and cryptographically, and whose nonce (when carried) checks out,
/// reaches the <c>jti</c> guard. Every call this file builds carries no <c>AccessToken</c> on its
/// <see cref="DpopProofValidationRequest"/>, so <c>ath</c> — RFC 9449 §4.3 item 12's
/// resource-call-only check — is never evaluated here; the token endpoint issues an access token,
/// it does not receive one.
/// </para>
/// <para>
/// At the three handler paths that call it (code redemption, refresh live, refresh reuse), the
/// stored-thumbprint compare (<see cref="BindValidatedProofAsync"/>)
/// runs AFTER the nonce decision and the <c>jti</c> guard, both of which
/// <see cref="ValidatePresentedProofAsync"/> already ran on the presented proof — a proof signed
/// by the wrong key is therefore a validly signed proof as far as this file is concerned, and
/// pays the same nonce challenge (or the same <c>jti</c>-store write on a first use) any
/// correctly-keyed proof would, before the wrong key is ever discovered. This is deliberate: the
/// alternative — comparing the thumbprint before the nonce and the <c>jti</c> guard — would answer
/// a nonce-less wrong-key proof differently from a nonce-less unknown-grant proof, reopening
/// exactly the existence oracle the pre-correlation step exists to close.
/// </para>
/// <para>
/// Both <see cref="ValidatePresentedProofAsync"/> and <see cref="ValidateAsync"/> read the request through
/// <see cref="DpopRequestReading"/>, the reading of the target and the proof validation every DPoP-checked endpoint
/// shares with the library's protected resources, which pass every <c>DPoP</c> field line to
/// <see cref="ProtectedResource.DpopResourceAccess"/>'s checks. They read the <c>DPoP</c> field by its field lines
/// (<see cref="DpopRequestReading.ReadDpopField"/>), as the pushed authorization request does, and
/// refuse two or more as <c>invalid_dpop_proof</c> before the absent-or-required decision
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 1: "There is not
/// more than one DPoP HTTP request header field."). They hold the proof's <c>htu</c> to the request's path at
/// <see cref="Verifiable.Server.IncomingRequest.ListenerAuthority"/> when the host stamped one, and at the issuer's
/// authority otherwise (<see cref="DpopRequestReading.ComposeTargetUri"/>; check 9). They hold its <c>alg</c> to the
/// algorithms the authorization server publishes for DPoP proofs (<see cref="ResolveAcceptedProofAlgorithmsAsync"/>;
/// check 5, "is supported by the application, and is acceptable per local policy"), resolved only when a proof is
/// present; a host resolver answering no list is answered <c>server_error</c>. A validation that answers success
/// without the thumbprint or without the claims a success carries is answered <c>server_error</c>.
/// </para>
/// <para>
/// Every nonce challenge, a required proof that is absent among them, carries one <c>DPoP-Nonce</c> field and the
/// field <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>, written whether or not the request names
/// an <c>Origin</c> (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "the
/// server needs to make it available to the application by including DPoP-Nonce in the Access-Control-Expose-Headers
/// response header list value").
/// </para>
/// </remarks>
internal static class DpopTokenEndpointValidation
{
    /// <summary>
    /// The request-only half of DPoP validation, run ONCE per request by a step endpoint's
    /// pre-correlation step, before any stored record exists to bind against.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Runs the whole request-only decision: the proof's structure and signature
    /// (<see cref="DpopRequestReading.ValidateProofAsync"/>), <c>htm</c>/<c>htu</c>, the nonce, and the
    /// <c>jti</c> replay guard — AT MOST once each, in that order: a proof-absent or
    /// early-rejected request reaches none of the later checks, and a nonce challenge or an
    /// invalid proof registers no <c>jti</c>. A proof carrying the server's nonce is validated
    /// against it; a proof WITHOUT a nonce is CHALLENGED with a fresh <c>DPoP-Nonce</c>
    /// regardless of <paramref name="proofRequiredByRegistration"/> or of anything a stored
    /// record might require — <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC
    /// 9449 §8</see>: the nonce requirement is the server's, never the grant's, so the answer is
    /// identical for a grant that does not exist and one that does. The thumbprint binding
    /// compare is NOT made here — there is no record yet to compare against; that half is
    /// <see cref="BindValidatedProofAsync"/>'s.
    /// </para>
    /// <para>
    /// On success (a validated proof, or no proof presented when
    /// <paramref name="proofRequiredByRegistration"/> is <see langword="false"/>) the outcome is
    /// stored on <paramref name="context"/> via <c>SetDpopStepOutcome</c> for
    /// <see cref="BindValidatedProofAsync"/> to read once the endpoint's handler has loaded the
    /// stored record. A challenge or refusal registers no <c>jti</c>. A validated proof always
    /// carries the base64url JWK SHA-256 Thumbprint of its public key
    /// (<see cref="DpopProofValidationResult.JwkThumbprint"/>; the <c>jkt</c> member of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3">RFC 7638 Section 3</see>); an
    /// application's validator answering success with no value, the empty string or text of another
    /// spelling is answered <c>server_error</c>, so a validated proof is never carried as no proof at
    /// all and never binds text that is not spelled as a JWK SHA-256 Thumbprint. A correctly spelled
    /// thumbprint that is not the proof key's own stays the validator's contract: the result carries
    /// no JWK, so the server cannot recompute it.
    /// </para>
    /// </remarks>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="issuerUri">The authorization server's issuer URI; its authority, unless the request carries a listener authority, combined with the request path forms the expected DPoP <c>htu</c> claim, and it keys the JTI replay record.</param>
    /// <param name="now">The current instant the DPoP proof's freshness window is evaluated against.</param>
    /// <param name="proofRequiredByRegistration">
    /// Whether the client's registration requires a proof: its profile mandates DPoP
    /// (<see cref="Verifiable.OAuth.Client.ClientPolicyProfiles.RequiresDpop"/>) or the client declared
    /// <c>dpop_bound_access_tokens</c> <see langword="true"/> (<see cref="ClientRecord.DpopBoundAccessTokens"/>): the
    /// only signals available before any stored record is loaded.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refusal to answer with, or <see langword="null"/> to proceed.</returns>
    public static async ValueTask<ServerHttpResponse?> ValidatePresentedProofAsync(
        EndpointServer server,
        ExchangeContext context,
        ClientRecord registration,
        Uri issuerUri,
        DateTimeOffset now,
        bool proofRequiredByRegistration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(issuerUri);

        var oauth = server.OAuth();

        //RFC 9449 Section 4.3, check 1: "There is not more than one DPoP HTTP request header field."
        //Two field lines are refused as an invalid proof before the absent-or-required decision, so
        //they are never read as no proof at all.
        (string? dpopProofString, bool isDpopFieldRepeated) = DpopRequestReading.ReadDpopField(context.IncomingRequest);
        if(isDpopFieldRepeated)
        {
            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidDpopProof, DpopRequestReading.MoreThanOneDpopFieldDescription);
        }

        if(dpopProofString is null && !proofRequiredByRegistration)
        {
            //No proof presented and the registration does not mandate one — whether the STORED
            //record binds this grant to DPoP anyway is BindValidatedProofAsync's question.
            context.SetDpopStepOutcome(DpopValidationOutcome.NoBinding);

            return null;
        }

        //A server that validates no proof (no validator assigned and no parser for the library default) or holds no
        //nonce delegates cannot check the proof, a fault of its composition, never a fallback to no proof.
        if(!DpopRequestReading.IsProofValidationWired(oauth)
            || oauth.IssueDpopNonceAsync is null
            || oauth.ValidateDpopNonceAsync is null
            || oauth.ResolveServerHmacKeyAsync is null
            || oauth.GetHmacKeySetAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP enforcement is required by policy but DPoP delegates are not wired.");
        }

        if(dpopProofString is null)
        {
            //Required by the registration but absent — issue a fresh nonce challenge.
            string freshNonce = await oauth.IssueDpopNonceAsync(
                issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            return NonceChallenge("DPoP proof required.", freshNonce);
        }

        //RFC 9449 Section 4.3, check 9, against the target URI the server reconstructs from its own
        //configuration (RFC 9110 Section 7.1): the listener authority the host stamped, else the issuer's.
        string tokenEndpointHtu = DpopRequestReading.ComposeTargetUri(context.IncomingRequest!, issuerUri);

        //RFC 9449 Section 4.3, check 5: the alg is held to the server's policy. A host resolver that
        //answers no list leaves no policy to hold it to, so the request fails closed as a server error.
        if(await ResolveAcceptedProofAlgorithmsAsync(oauth, registration, context, cancellationToken).ConfigureAwait(false)
            is not IReadOnlyList<string> acceptedAlgorithms)
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, AlgorithmResolverAnsweredNoListDescription);
        }

        DpopProofValidationRequest validationRequest = new()
        {
            Proof = dpopProofString,
            HttpMethod = WellKnownHttpMethods.Post,
            HttpUrl = tokenEndpointHtu,
            NonceRequired = false,
            AcceptedAlgorithms = acceptedAlgorithms
        };

        DpopProofValidationResult proofResult = await DpopRequestReading.ValidateProofAsync(
            oauth, server.TimeProvider, validationRequest, cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            if(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

                return NonceChallenge("DPoP nonce required.", freshNonce);
            }

            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                $"DPoP proof validation failed: {proofResult.FailureReason}.");
        }

        //A validation that answers success names the base64url JWK SHA-256 Thumbprint of the
        //proof's public key (DpopProofValidationResult.JwkThumbprint; RFC 9449 Section 6.1, the jkt
        //member; RFC 7638 Section 3). An application's validator answering success with no value,
        //the empty string or text of another spelling leaves no thumbprint to bind the code or the
        //tokens to, so the request fails closed as a server error before any nonce or jti work,
        //never an unbound or a misbound issuance; the spelling rule is the one dpop_jkt is held to.
        if(proofResult.JwkThumbprint is not string proofThumbprint
            || !DpopJwkUtilities.IsJwkSha256ThumbprintSpelling(proofThumbprint))
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutThumbprintDescription);
        }

        //A validation that answers success carries the proof's claims, the nonce and the jti the
        //checks below read. An application's validator answering success without them leaves
        //neither to check, so the request fails closed as a server error, as for a missing thumbprint.
        if(proofResult.Claims is not DpopProofClaims proofClaims)
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutClaimsDescription);
        }

        if(proofClaims.Nonce is not null)
        {
            DpopNonceValidationResult nonceResult = await oauth.ValidateDpopNonceAsync(
                proofClaims.Nonce, issuerUri, registration.TenantId, context, cancellationToken)
                .ConfigureAwait(false);
            if(!nonceResult.IsSuccess)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

                return NonceChallenge($"DPoP nonce invalid: {nonceResult.FailureReason}.", freshNonce);
            }
        }
        else
        {
            //A proof without the server's required nonce is CHALLENGED whatever the profile or
            //any stored record says — RFC 9449 §8: the server decides when a nonce is required,
            //and the requirement is the server's, never the grant's. This is what makes the
            //nonce answer independent of the stored record for an unknown and a live grant alike.
            string freshNonce = await oauth.IssueDpopNonceAsync(
                issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            return NonceChallenge("DPoP nonce required.", freshNonce);
        }

        //JTI replay check — the same shared correlation store the JAR path uses, the proof's jti
        //recorded in the context of this request's target URI (RFC 9449 §11.1), governed by
        //JtiReplayPolicy: Required fails closed when no store is wired, and the read and first-use
        //record happen as one unit. Runs only after structural and cryptographic checks pass.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultDpopProofAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, tokenEndpointHtu, proofClaims.Jti,
            now + WellKnownDpopValues.DefaultReplayWindow,
            cancellationToken).ConfigureAwait(false);

        ServerHttpResponse? jtiFailure = jtiOutcome switch
        {
            JtiReplayOutcome.FirstUse => null,
            JtiReplayOutcome.Replayed => ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof jti has been seen previously."),
            JtiReplayOutcome.Unacceptable => ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof jti is too long or carries a character the replay guard cannot store."),
            JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."),

            _ => null
        };
        if(jtiFailure is not null)
        {
            return jtiFailure;
        }

        context.SetDpopStepOutcome(DpopValidationOutcome.Success(new ConfirmationMethod { JwkThumbprint = proofThumbprint }));

        return null;
    }


    /// <summary>
    /// The record-dependent half of DPoP validation, run by a step endpoint's handler once a
    /// stored record's binding is known.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reads the outcome <see cref="ValidatePresentedProofAsync"/> carried on the request
    /// context and performs ONLY the checks that need the stored record: (a) no proof was
    /// presented at the step: when <paramref name="proofRequiredByRecord"/> (a record bound to a
    /// DPoP public key), the endpoint's own not-found constant
    /// (<paramref name="notFoundDescription"/>) under <c>invalid_grant</c>, never a nonce challenge
    /// that would itself prove the record's binding exists; otherwise no binding; (b) a proof was
    /// validated at the step: <paramref name="expectedThumbprint"/> non-null and different from
    /// the carried confirmation's answers the same constant, never <c>invalid_dpop_proof</c>;
    /// otherwise the carried confirmation succeeds. Never re-runs proof parsing, signature
    /// verification, the nonce decision, or the <c>jti</c> replay guard; those ran exactly once,
    /// in the step.
    /// </para>
    /// <para>
    /// The refresh grant passes the binding the refresh token's record stores, decided when the
    /// token was issued, whatever the client's registration declares at the presentation, and
    /// <see cref="Verifiable.OAuth.AuthCode.AuthCodeEndpoints.RefreshTokenNotFoundDescription"/>,
    /// verifying the binding the refresh token was issued under
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "When an
    /// authorization server supporting DPoP issues a refresh token to a public client that presents a
    /// valid DPoP proof at the token endpoint, the refresh token MUST be bound to the respective public
    /// key. The binding MUST be validated when the refresh token is later presented to get new access
    /// tokens.", and "Refresh tokens issued to confidential clients (those having established
    /// authentication credentials with the authorization server) are not bound to the DPoP proof public
    /// key because they are already sender-constrained with a different existing mechanism."): a refresh
    /// token issued to a public client that presents a valid proof is bound to that proof's DPoP key,
    /// and every refresh token is held at every presentation to the binding it was issued under (none
    /// when unbound); a confidential client's is not bound. The code redemption passes the code's binding, the thumbprint the authorization
    /// request named with <c>dpop_jkt</c> or the pushed request's proof carried, and
    /// <see cref="Verifiable.OAuth.AuthCode.AuthCodeEndpoints.CodeGrantNotFoundDescription"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>, "the
    /// authorization server computes the JWK Thumbprint of the proof-of-possession public key in the
    /// DPoP proof and verifies that it matches the dpop_jkt parameter value in the authorization
    /// request. If they do not match, it MUST reject the request." A code bound to no DPoP public key
    /// passes no expected thumbprint, and a validated proof establishes the binding of the issued
    /// tokens.
    /// </para>
    /// </remarks>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="issuerUri">The authorization server's issuer URI; combined with the request path to form the expected DPoP <c>htu</c> claim and to key the JTI replay record.</param>
    /// <param name="carriedOutcome">The outcome <see cref="ValidatePresentedProofAsync"/> recorded on the context earlier in this same request.</param>
    /// <param name="expectedThumbprint">
    /// When non-null, the carried proof's JWK thumbprint MUST match this value: the binding of a
    /// DPoP-bound refresh token or of a DPoP-bound authorization code, being VERIFIED. When null,
    /// the carried <see cref="DpopValidationOutcome.Confirmation"/> is accepted as-is: the record
    /// carries no binding, and a validated proof ESTABLISHES one.
    /// </param>
    /// <param name="proofRequiredByRecord">Whether the STORED record (not the registration's profile) requires a bound DPoP proof.</param>
    /// <param name="notFoundDescription">
    /// The endpoint's own description for an unknown grant, answered under <c>invalid_grant</c> by
    /// both refusals so a refusal that reads the record never tells whether the record exists.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The carried confirmation, no binding, or the refusal to answer with.</returns>
    public static ValueTask<DpopValidationOutcome> BindValidatedProofAsync(
        EndpointServer server,
        ExchangeContext context,
        ClientRecord registration,
        Uri issuerUri,
        DpopValidationOutcome carriedOutcome,
        string? expectedThumbprint,
        bool proofRequiredByRecord,
        string notFoundDescription,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(issuerUri);
        ArgumentNullException.ThrowIfNull(carriedOutcome);
        ArgumentException.ThrowIfNullOrEmpty(notFoundDescription);

        if(carriedOutcome.Confirmation is null)
        {
            if(!proofRequiredByRecord)
            {
                return ValueTask.FromResult(DpopValidationOutcome.NoBinding);
            }

            //A DPoP-bound record (a refresh token, or an authorization code its request bound to a
            //DPoP public key) presented without a proof, under a profile that does not itself
            //require DPoP: RFC 9449 Section 8 governs a PROOF presented without the server's nonce,
            //not a request presenting no proof at all; Section 5 (the binding "MUST be validated
            //when the refresh token is later presented") and Section 10 ("If they do not match, it
            //MUST reject the request.") name no error for a missing proof. A refusal that reads the
            //record answers the endpoint's constant, never a nonce challenge, which would itself
            //prove the record's binding exists, so the answer never tells whether the record exists.
            return ValueTask.FromResult(DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, notFoundDescription)));
        }

        if(expectedThumbprint is not null
            && !string.Equals(carriedOutcome.Confirmation.JwkThumbprint, expectedThumbprint, StringComparison.Ordinal))
        {
            //A valid proof bound to a DPoP public key other than the one the record names: RFC 9449
            //Section 5 prescribes invalid_dpop_proof for an INVALID proof, already answered before
            //correlation in ValidatePresentedProofAsync, and prescribes nothing for a valid proof
            //bound to another DPoP public key; Section 10 says only that the server "MUST reject the
            //request". A refusal that reads the record answers the endpoint's constant so the
            //answer never tells whether the record exists.
            return ValueTask.FromResult(DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, notFoundDescription)));
        }

        return ValueTask.FromResult(DpopValidationOutcome.Success(carriedOutcome.Confirmation));
    }


    /// <summary>
    /// Validates a DPoP proof presented at the token endpoint or at the pushed authorization
    /// request and persists the JTI marker for replay defense. Its callers are the requests with no
    /// pre-correlation step: <c>BuildClientCredentials</c>, <c>BuildTokenExchange</c>, the
    /// JWT-bearer grant's candidate, the pre-authorized code grant's candidate, and the pushed
    /// authorization request (<c>BuildPar</c> and <c>BuildJarPar</c>, which pass
    /// <paramref name="dpopRequired"/> as <see langword="false"/> and read the returned
    /// confirmation as the binding the code is to carry, RFC 9449 Section 10.1), each
    /// establishing a binding rather than verifying one against a stored record, so each passes
    /// <paramref name="expectedThumbprint"/> as <see langword="null"/>. The two step endpoints (code
    /// redemption, refresh) never call this method: their pre-correlation step calls
    /// <see cref="ValidatePresentedProofAsync"/> and their handler calls
    /// <see cref="BindValidatedProofAsync"/>.
    /// </summary>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="issuerUri">The authorization server's issuer URI; its authority, unless the request carries a listener authority, combined with the request path forms the expected DPoP <c>htu</c> claim, and it keys the JTI replay record.</param>
    /// <param name="now">The current instant the DPoP proof's freshness window is evaluated against.</param>
    /// <param name="expectedThumbprint">
    /// When non-null, the proof's JWK thumbprint MUST match this value; no caller passes a
    /// non-null value, since none verifies a binding already on record. When
    /// null, any well-formed proof's thumbprint is captured into the returned
    /// <see cref="DpopValidationOutcome.Confirmation"/>.
    /// </param>
    /// <param name="dpopRequired">Whether presenting a DPoP proof is mandatory for this request; when <see langword="false"/> and none is presented, the token issues as Bearer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The confirmation of the validated proof's public key; no binding when no proof was presented
    /// and none is required; or the refusal to answer with, a <c>server_error</c> among them when
    /// the application's validator answers a proof valid without the base64url JWK SHA-256
    /// Thumbprint <see cref="DpopProofValidationResult.JwkThumbprint"/> promises on success (the
    /// <c>jkt</c> member of <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449
    /// Section 6.1</see>, <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3">RFC 7638
    /// Section 3</see>): no value, the empty string or text of another spelling, never an unbound or a
    /// misbound issuance.
    /// </returns>
    public static async ValueTask<DpopValidationOutcome> ValidateAsync(
        EndpointServer server,
        ExchangeContext context,
        ClientRecord registration,
        Uri issuerUri,
        DateTimeOffset now,
        string? expectedThumbprint,
        bool dpopRequired,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(issuerUri);

        //RFC 9449 Section 4.3, check 1: "There is not more than one DPoP HTTP request header field."
        //Two field lines are refused as an invalid proof before the absent-or-required decision, so
        //they are never read as no proof at all.
        (string? dpopProofString, bool isDpopFieldRepeated) = DpopRequestReading.ReadDpopField(context.IncomingRequest);
        if(isDpopFieldRepeated)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof, DpopRequestReading.MoreThanOneDpopFieldDescription));
        }

        if(dpopProofString is null && !dpopRequired)
        {
            //No proof presented and none required — Bearer issuance.
            return DpopValidationOutcome.NoBinding;
        }

        //A server that validates no proof (no validator assigned and no parser for the library default) or holds no
        //nonce delegates cannot check the proof, a fault of its composition, never a fallback to no proof.
        if(!DpopRequestReading.IsProofValidationWired(oauth)
            || oauth.IssueDpopNonceAsync is null
            || oauth.ValidateDpopNonceAsync is null
            || oauth.ResolveServerHmacKeyAsync is null
            || oauth.GetHmacKeySetAsync is null)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP enforcement is required by policy but DPoP delegates are not wired."));
        }

        if(dpopProofString is null)
        {
            //Required but absent — issue a fresh nonce challenge.
            string freshNonce = await oauth.IssueDpopNonceAsync(
                issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            return DpopValidationOutcome.Failure(NonceChallenge("DPoP proof required.", freshNonce));
        }

        //RFC 9449 Section 4.3, check 9, against the target URI the server reconstructs from its own
        //configuration (RFC 9110 Section 7.1): the listener authority the host stamped, else the issuer's.
        string tokenEndpointHtu = DpopRequestReading.ComposeTargetUri(context.IncomingRequest!, issuerUri);

        //RFC 9449 Section 4.3, check 5: the alg is held to the server's policy. A host resolver that
        //answers no list leaves no policy to hold it to, so the request fails closed as a server error.
        if(await ResolveAcceptedProofAlgorithmsAsync(oauth, registration, context, cancellationToken).ConfigureAwait(false)
            is not IReadOnlyList<string> acceptedAlgorithms)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, AlgorithmResolverAnsweredNoListDescription));
        }

        DpopProofValidationRequest validationRequest = new()
        {
            Proof = dpopProofString,
            HttpMethod = WellKnownHttpMethods.Post,
            HttpUrl = tokenEndpointHtu,
            NonceRequired = false,
            AcceptedAlgorithms = acceptedAlgorithms
        };

        DpopProofValidationResult proofResult = await DpopRequestReading.ValidateProofAsync(
            oauth, server.TimeProvider, validationRequest, cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            if(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

                return DpopValidationOutcome.Failure(NonceChallenge("DPoP nonce required.", freshNonce));
            }

            return DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                $"DPoP proof validation failed: {proofResult.FailureReason}."));
        }

        //A validation that answers success names the base64url JWK SHA-256 Thumbprint of the
        //proof's public key (DpopProofValidationResult.JwkThumbprint; RFC 9449 Section 6.1, the jkt
        //member; RFC 7638 Section 3). RFC 9449 Section 10.1 has the pushed request "behave as if the
        //contained public key's thumbprint was provided using dpop_jkt" and Section 5 has the token
        //endpoint associate the issued token "with the public key from the DPoP proof"; an
        //application's validator answering success with no value, the empty string or text of
        //another spelling leaves neither possible, so the request fails closed as a server error,
        //never an unbound or a misbound issuance, before any nonce or jti work. The spelling rule
        //is the one dpop_jkt is held to.
        if(proofResult.JwkThumbprint is not string proofThumbprint
            || !DpopJwkUtilities.IsJwkSha256ThumbprintSpelling(proofThumbprint))
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutThumbprintDescription));
        }

        //A caller that verifies a binding already on record passes the expected thumbprint; no
        //caller passes one. The ordinal compare runs before any nonce or jti work, so a proof by the
        //wrong DPoP key never reaches storage.
        if(expectedThumbprint is not null
            && !string.Equals(proofThumbprint, expectedThumbprint, StringComparison.Ordinal))
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof thumbprint does not match the bound thumbprint."));
        }

        //A validation that answers success carries the proof's claims, the nonce and the jti the
        //checks below read. An application's validator answering success without them leaves
        //neither to check, so the request fails closed as a server error, as for a missing thumbprint.
        if(proofResult.Claims is not DpopProofClaims proofClaims)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, DpopRequestReading.ValidatedProofWithoutClaimsDescription));
        }

        if(proofClaims.Nonce is not null)
        {
            DpopNonceValidationResult nonceResult = await oauth.ValidateDpopNonceAsync(
                proofClaims.Nonce, issuerUri, registration.TenantId, context, cancellationToken)
                .ConfigureAwait(false);
            if(!nonceResult.IsSuccess)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

                return DpopValidationOutcome.Failure(
                    NonceChallenge($"DPoP nonce invalid: {nonceResult.FailureReason}.", freshNonce));
            }
        }
        else
        {
            //A proof without the server's required nonce is CHALLENGED whatever
            //dpopRequired says — RFC 9449 §8: the nonce requirement is the server's, never the
            //grant's, so every grant at this token endpoint answers a nonce-less proof alike
            //(the same policy ValidatePresentedProofAsync applies at the two step endpoints).
            string freshNonce = await oauth.IssueDpopNonceAsync(
                issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            return DpopValidationOutcome.Failure(NonceChallenge("DPoP nonce required.", freshNonce));
        }

        //JTI replay check — the same shared correlation store the JAR path uses, the proof's jti
        //recorded in the context of this request's target URI (RFC 9449 §11.1), governed by
        //JtiReplayPolicy: Required fails closed when no store is wired, and the read and first-use
        //record happen as one unit. Runs only after structural and cryptographic checks pass.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultDpopProofAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, tokenEndpointHtu, proofClaims.Jti,
            now + WellKnownDpopValues.DefaultReplayWindow,
            cancellationToken).ConfigureAwait(false);

        ServerHttpResponse? jtiFailure = jtiOutcome switch
        {
            JtiReplayOutcome.FirstUse => null,
            JtiReplayOutcome.Replayed => ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof jti has been seen previously."),
            JtiReplayOutcome.Unacceptable => ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof jti is too long or carries a character the replay guard cannot store."),
            JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."),

            _ => null
        };
        if(jtiFailure is not null)
        {
            return DpopValidationOutcome.Failure(jtiFailure);
        }

        return DpopValidationOutcome.Success(new ConfirmationMethod { JwkThumbprint = proofThumbprint });
    }


    /// <summary>
    /// The description a request is answered with under <c>server_error</c> when the host's
    /// <see cref="AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/> answers no list at all for
    /// <see cref="KeyUsageContext.DpopProof"/>, against that delegate's contract of a list on every answer. The server
    /// then holds no policy to check a proof's <c>alg</c> against
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: the alg "is
    /// supported by the application, and is acceptable per local policy"), so the request fails closed rather than
    /// holding the proof to the structural rule alone. The library's protected resources answer the same fault with it.
    /// </summary>
    internal static string AlgorithmResolverAnsweredNoListDescription { get; } =
        "The signing-algorithm resolver answered no list for DPoP proofs.";


    /// <summary>
    /// The description a request to a library protected resource is answered with under <c>server_error</c> when the
    /// host's <see cref="AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/> answers, for
    /// <see cref="KeyUsageContext.DpopProof"/>, a list holding a name that is no RFC 9110 Section 5.6.2 token. The library
    /// holds every <c>algs</c> name to the token grammar, its chosen bound
    /// (<see cref="ProtectedResource.DpopChallenge.IsToken"/>): the clauses that exclude any other name are
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, "alg: An identifier for
    /// a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 5, the alg "indicates a
    /// registered asymmetric digital signature algorithm", every registered name being made of tchar only; a
    /// quoted-string could carry a Collision-Resistant Name (RFC 7515 Section 4.1.1), which no DPoP proof may carry. The
    /// resource reads such an answer as no list
    /// (<see cref="Oid4Vci.CredentialEndpointDpopValidation.ResolveChallengeContextAsync"/>) and holds no proof to it, as
    /// it answers a resolver that answered no list (<see cref="AlgorithmResolverAnsweredNoListDescription"/>). The text
    /// is fixed and names no value of the list.
    /// </summary>
    internal static string AlgorithmResolverAnsweredUnusableListDescription { get; } =
        "The signing-algorithm resolver answered a name for DPoP proofs that a challenge cannot carry.";


    /// <summary>
    /// The token endpoint's nonce challenge: 400 <c>use_dpop_nonce</c> with <paramref name="description"/> in the body,
    /// one <c>DPoP-Nonce</c> field carrying <paramref name="freshNonce"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "there MUST NOT be more
    /// than one DPoP-Nonce header"), and the <c>Access-Control-Expose-Headers</c> field naming the fields a browser
    /// application reads (<see cref="WellKnownDpopValues.ExposedDpopResponseFields"/>; Section 8: "In order for the
    /// application to obtain and use the DPoP-Nonce HTTP response header value, the server needs to make it available
    /// to the application by including DPoP-Nonce in the Access-Control-Expose-Headers response header list value.").
    /// Every nonce challenge of this file, the pushed authorization request's among them, answers through it.
    /// </summary>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <param name="freshNonce">The nonce the challenge supplies.</param>
    /// <returns>The 400 nonce challenge.</returns>
    private static ServerHttpResponse NonceChallenge(string description, string freshNonce) =>
        ServerHttpResponse.BadRequest(OAuthErrors.UseDpopNonce, description)
            .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce)
            .WithHeader(WellKnownHttpHeaderNames.AccessControlExposeHeaders, WellKnownDpopValues.ExposedDpopResponseFields);


    /// <summary>
    /// The JWS <c>alg</c> values the authorization server accepts for a DPoP proof: the host's
    /// <see cref="AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/> answer for
    /// <see cref="KeyUsageContext.DpopProof"/> where it is wired, otherwise
    /// <see cref="DefaultSupportedSigningAlgorithms.ResolveAsync"/>, the one list the authorization server metadata
    /// publishes as <c>dpop_signing_alg_values_supported</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5.1">RFC 9449 Section 5.1</see>), so what is published
    /// is what is accepted. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 5:
    /// the alg "is supported by the application, and is acceptable per local policy". An empty answer accepts no proof.
    /// A host delegate that answers no list at all, against its contract, is answered <see langword="null"/>, which every
    /// caller answers <c>server_error</c> (<see cref="AlgorithmResolverAnsweredNoListDescription"/>): a missing policy
    /// fails closed and is never read as no policy.
    /// </summary>
    /// <param name="oauth">The integration admitted for the request.</param>
    /// <param name="registration">The registration the request belongs to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token passed to the resolution.</param>
    /// <returns>The accepted JWA names, or <see langword="null"/> when the host's delegate answered no list.</returns>
    internal static async ValueTask<IReadOnlyList<string>?> ResolveAcceptedProofAlgorithmsAsync(
        AuthorizationServerIntegration oauth,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(oauth);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        IReadOnlyList<string>? acceptedAlgorithms = oauth.Cryptography.ResolveSupportedSigningAlgorithmsAsync switch
        {
            ResolveSupportedSigningAlgorithmsDelegate resolveSupportedAlgorithms =>
                await resolveSupportedAlgorithms(registration, KeyUsageContext.DpopProof, context, cancellationToken).ConfigureAwait(false),
            _ => await DefaultSupportedSigningAlgorithms.ResolveAsync(
                oauth, registration, KeyUsageContext.DpopProof, context, cancellationToken).ConfigureAwait(false)
        };

        return acceptedAlgorithms;
    }
}


/// <summary>
/// The outcome of DPoP validation at the token endpoint, produced by any of three call sites:
/// <see cref="DpopTokenEndpointValidation.ValidateAsync"/> (the four grants without a
/// pre-correlation step), <see cref="DpopTokenEndpointValidation.ValidatePresentedProofAsync"/>
/// (a step endpoint's request-only decision, carried on <see cref="ExchangeContext"/> for the
/// handler to read), and <see cref="DpopTokenEndpointValidation.BindValidatedProofAsync"/> (a step
/// endpoint's handler, applying the record-dependent remainder to the carried outcome). Carries
/// either the established <see cref="ConfirmationMethod"/> for success, or a fully-shaped
/// <see cref="ServerHttpResponse"/> for the caller to return directly on any failure path (nonce
/// challenge, invalid proof, thumbprint mismatch, JTI replay).
/// </summary>
[DebuggerDisplay("DpopValidationOutcome Success={IsSuccess}")]
internal sealed record DpopValidationOutcome
{
    /// <summary>
    /// The confirmation method derived from the validated proof, or
    /// <see langword="null"/> when no DPoP binding ran (Bearer flow).
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// The HTTP response to return when validation failed. Non-null only
    /// when <see cref="IsSuccess"/> is <see langword="false"/>.
    /// </summary>
    public ServerHttpResponse? FailureResponse { get; init; }

    /// <summary><see langword="true"/> when validation succeeded.</summary>
    public bool IsSuccess => FailureResponse is null;


    /// <summary>Outcome for a Bearer flow — no DPoP binding established.</summary>
    public static DpopValidationOutcome NoBinding { get; } = new();


    /// <summary>Outcome for a successful DPoP validation.</summary>
    public static DpopValidationOutcome Success(ConfirmationMethod? confirmation) =>
        new() { Confirmation = confirmation };


    /// <summary>Outcome for any failure path.</summary>
    public static DpopValidationOutcome Failure(ServerHttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return new() { FailureResponse = response };
    }
}


/// <summary>
/// A typed accessor block over <see cref="ExchangeContext"/> fronting two independent per-request
/// carries a step endpoint's pre-correlation step writes and its handler reads: the DPoP decision
/// (<c>DpopStepOutcome</c>/<see cref="SetDpopStepOutcome"/>, under
/// <see cref="AuthorizationServerHandlers.DpopStepOutcomeKey"/>) the step's
/// <see cref="DpopTokenEndpointValidation.ValidatePresentedProofAsync"/> call and the handler's
/// later <see cref="DpopTokenEndpointValidation.BindValidatedProofAsync"/> call share, and the
/// resolved issuer (<c>CorrelationStepIssuer</c>/<see cref="SetCorrelationStepIssuer"/>,
/// under <see cref="AuthorizationServerHandlers.CorrelationStepIssuerKey"/>) every step endpoint's
/// handler, replay/reuse handler, and <c>PrivateKeyJwtClientAuthentication</c> read instead of
/// resolving a second time — not itself DPoP-specific.
/// </summary>
/// <remarks>
/// Internal — the outcome type <c>DpopStepOutcome</c> carries
/// (<see cref="DpopValidationOutcome"/>) is itself internal, so nothing here is reachable outside
/// <see cref="Verifiable.OAuth"/>. Both carries rest on the contract
/// <see cref="ExchangeContext"/>'s own documentation states: the application's dispatch host hands
/// <see cref="EndpointServer.DispatchAsync"/> a fresh, per-request <see cref="ExchangeContext"/>,
/// so a carry this block reads was always set by a step that ran within the SAME request — never
/// left over from a different one. A stepless endpoint (<c>PrivateKeyJwtClientAuthentication</c>'s
/// stepless callers) therefore reads <c>CorrelationStepIssuer</c> only when a step set it
/// in that same request, and treats it as absent otherwise; the library does not itself enforce a
/// fresh context per request.
/// </remarks>
internal static class ExchangeContextDpopExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the <see cref="DpopValidationOutcome"/> a pre-correlation step recorded for this
        /// request, or <see langword="null"/> when no step ran or none has stored one yet.
        /// </summary>
        internal DpopValidationOutcome? DpopStepOutcome =>
            context.TryGetValue(AuthorizationServerHandlers.DpopStepOutcomeKey, out object? v)
                && v is DpopValidationOutcome outcome ? outcome : null;

        /// <summary>Sets the <see cref="DpopValidationOutcome"/> a pre-correlation step recorded for this request.</summary>
        /// <param name="outcome">The step's outcome.</param>
        internal void SetDpopStepOutcome(DpopValidationOutcome outcome)
        {
            ArgumentNullException.ThrowIfNull(outcome);
            context[AuthorizationServerHandlers.DpopStepOutcomeKey] = outcome;
        }


        /// <summary>
        /// Gets the issuer URI a step endpoint's pre-correlation step resolved once for this
        /// request, carried beside <c>DpopStepOutcome</c> so the endpoint's handler reads
        /// it instead of resolving it a second time. <see langword="null"/> when no step ran, or
        /// one ran but has not resolved an issuer (it answered its own refusal instead).
        /// </summary>
        internal Uri? CorrelationStepIssuer =>
            context.TryGetValue(AuthorizationServerHandlers.CorrelationStepIssuerKey, out object? v)
                && v is Uri issuer ? issuer : null;

        /// <summary>Sets the issuer URI a pre-correlation step resolved once for this request.</summary>
        /// <param name="issuer">The resolved issuer.</param>
        internal void SetCorrelationStepIssuer(Uri issuer)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            context[AuthorizationServerHandlers.CorrelationStepIssuerKey] = issuer;
        }
    }
}
