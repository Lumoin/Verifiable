using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
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
/// decision, gated on whether DPoP is required at all (the registration's profile, or — at a step
/// endpoint's handler — the stored record's own binding).
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
/// <c>ValidateDpopProofAsync</c>, <c>ValidateDpopNonceAsync</c> and the <c>jti</c> guard each run
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
    /// (<c>ValidateDpopProofAsync</c>), <c>htm</c>/<c>htu</c>, the nonce, and the
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
    /// <param name="issuerUri">The authorization server's issuer URI; combined with the request path to form the expected DPoP <c>htu</c> claim and to key the JTI replay record.</param>
    /// <param name="now">The current instant the DPoP proof's freshness window is evaluated against.</param>
    /// <param name="proofRequiredByRegistration">
    /// Whether the client's registration profile mandates DPoP
    /// (<see cref="Verifiable.OAuth.Client.ClientPolicyProfiles.RequiresDpop"/>) — the only
    /// signal available before any stored record is loaded.
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

        string? dpopProofString = null;
        _ = (context.IncomingRequest?.Headers.TryGetSingle(
            WellKnownHttpHeaderNames.DPoP, out dpopProofString));

        if(dpopProofString is null && !proofRequiredByRegistration)
        {
            //No proof presented and the registration does not mandate one — whether the STORED
            //record binds this grant to DPoP anyway is BindValidatedProofAsync's question.
            context.SetDpopStepOutcome(DpopValidationOutcome.NoBinding);

            return null;
        }

        if(oauth.ValidateDpopProofAsync is null
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
            return ServerHttpResponse
                .BadRequest(OAuthErrors.UseDpopNonce, "DPoP proof required.")
                .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
        }

        string tokenEndpointHtu = $"{issuerUri.GetLeftPart(UriPartial.Authority)}{context.IncomingRequest!.Path}";
        DpopProofValidationRequest validationRequest = new()
        {
            Proof = dpopProofString,
            HttpMethod = WellKnownHttpMethods.Post,
            HttpUrl = tokenEndpointHtu,
            NonceRequired = false
        };

        DpopProofValidationResult proofResult = await oauth.ValidateDpopProofAsync(
            validationRequest, cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            if(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
                return ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce, "DPoP nonce required.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
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
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, ValidatedProofWithoutThumbprintDescription);
        }

        if(proofResult.Claims!.Nonce is not null)
        {
            DpopNonceValidationResult nonceResult = await oauth.ValidateDpopNonceAsync(
                proofResult.Claims.Nonce, issuerUri, registration.TenantId, context, cancellationToken)
                .ConfigureAwait(false);
            if(!nonceResult.IsSuccess)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
                return ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce,
                        $"DPoP nonce invalid: {nonceResult.FailureReason}.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
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
            return ServerHttpResponse
                .BadRequest(OAuthErrors.UseDpopNonce, "DPoP nonce required.")
                .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
        }

        //JTI replay check — the same shared correlation store the JAR path uses, the proof's jti
        //recorded in the context of this request's target URI (RFC 9449 §11.1), governed by
        //JtiReplayPolicy: Required fails closed when no store is wired, and the read and first-use
        //record happen as one unit. Runs only after structural and cryptographic checks pass.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultDpopProofAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, tokenEndpointHtu, proofResult.Claims.Jti,
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
    /// The refresh grant passes the refresh token's stored binding and
    /// <see cref="Verifiable.OAuth.AuthCode.AuthCodeEndpoints.RefreshTokenNotFoundDescription"/>,
    /// verifying the binding the refresh token was issued under
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "The
    /// binding MUST be validated when the refresh token is later presented to get new access
    /// tokens."). The code redemption passes the code's binding, the thumbprint the authorization
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
    /// <param name="issuerUri">The authorization server's issuer URI; combined with the request path to form the expected DPoP <c>htu</c> claim and to key the JTI replay record.</param>
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

        string? dpopProofString = null;
        _ = (context.IncomingRequest?.Headers.TryGetSingle(
            WellKnownHttpHeaderNames.DPoP, out dpopProofString));

        if(dpopProofString is null && !dpopRequired)
        {
            //No proof presented and none required — Bearer issuance.
            return DpopValidationOutcome.NoBinding;
        }

        if(oauth.ValidateDpopProofAsync is null
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
            return DpopValidationOutcome.Failure(ServerHttpResponse
                .BadRequest(OAuthErrors.UseDpopNonce, "DPoP proof required.")
                .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce));
        }

        string tokenEndpointHtu = $"{issuerUri.GetLeftPart(UriPartial.Authority)}{context.IncomingRequest!.Path}";
        DpopProofValidationRequest validationRequest = new()
        {
            Proof = dpopProofString,
            HttpMethod = WellKnownHttpMethods.Post,
            HttpUrl = tokenEndpointHtu,
            NonceRequired = false
        };

        DpopProofValidationResult proofResult = await oauth.ValidateDpopProofAsync(
            validationRequest, cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            if(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
                return DpopValidationOutcome.Failure(ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce, "DPoP nonce required.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce));
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
                OAuthErrors.ServerError, ValidatedProofWithoutThumbprintDescription));
        }

        //A caller that verifies a binding already on record passes the expected thumbprint; no
        //caller does so today. The ordinal compare runs before any nonce or jti work, so a proof
        //by the wrong key never reaches storage.
        if(expectedThumbprint is not null
            && !string.Equals(proofThumbprint, expectedThumbprint, StringComparison.Ordinal))
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof thumbprint does not match the bound thumbprint."));
        }

        if(proofResult.Claims!.Nonce is not null)
        {
            DpopNonceValidationResult nonceResult = await oauth.ValidateDpopNonceAsync(
                proofResult.Claims.Nonce, issuerUri, registration.TenantId, context, cancellationToken)
                .ConfigureAwait(false);
            if(!nonceResult.IsSuccess)
            {
                string freshNonce = await oauth.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
                return DpopValidationOutcome.Failure(ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce,
                        $"DPoP nonce invalid: {nonceResult.FailureReason}.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce));
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
            return DpopValidationOutcome.Failure(ServerHttpResponse
                .BadRequest(OAuthErrors.UseDpopNonce, "DPoP nonce required.")
                .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce));
        }

        //JTI replay check — the same shared correlation store the JAR path uses, the proof's jti
        //recorded in the context of this request's target URI (RFC 9449 §11.1), governed by
        //JtiReplayPolicy: Required fails closed when no store is wired, and the read and first-use
        //record happen as one unit. Runs only after structural and cryptographic checks pass.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultDpopProofAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, tokenEndpointHtu, proofResult.Claims.Jti,
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
    /// The description a request is answered with under <c>server_error</c> when the application's
    /// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/> answers a proof valid
    /// without the JWK SHA-256 Thumbprint of its public key that
    /// <see cref="DpopProofValidationResult.JwkThumbprint"/> promises on every success, in the
    /// spelling <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section
    /// 6.1</see> gives the <c>jkt</c> member ("the base64url encoding (as defined in [RFC7515]) of
    /// the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key"): no value, the
    /// empty string and text of another spelling alike. The pushed request cannot then "behave as if
    /// the contained public key's thumbprint was provided using dpop_jkt"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>)
    /// and the token endpoint cannot associate the issued token "with the public key from the DPoP
    /// proof" (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">Section 5</see>), so the
    /// request fails closed rather than binding nothing or binding text that is not spelled as a
    /// thumbprint.
    /// </summary>
    private static string ValidatedProofWithoutThumbprintDescription { get; } =
        "The DPoP proof validator answered no JWK SHA-256 Thumbprint for a valid proof.";
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
