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
/// grant) has no pre-correlation step and keeps calling <see cref="ValidateAsync"/> exactly as
/// before — those grants create no prior record for a request-only decision to run ahead of.
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
    /// stored record. A challenge or refusal registers no <c>jti</c>.
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

        //JTI replay check — the same shared (issuer, jti) correlation store the JAR path
        //uses, governed by JtiReplayPolicy: Required fails closed when no store is wired, and
        //the read and first-use record happen as one unit (RFC 9449 §11.1). Runs only after
        //structural and cryptographic checks pass.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, proofResult.Claims.Jti,
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
                "DPoP proof jti exceeds the length the replay guard can track."),
            JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."),

            _ => null
        };
        if(jtiFailure is not null)
        {
            return jtiFailure;
        }

        ConfirmationMethod? confirmation = proofResult.JwkThumbprint is not null
            ? new ConfirmationMethod { JwkThumbprint = proofResult.JwkThumbprint }
            : null;

        context.SetDpopStepOutcome(DpopValidationOutcome.Success(confirmation));

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
    /// presented at the step — when <paramref name="proofRequiredByRecord"/> (a DPoP-bound
    /// refresh token, the record's own <c>Confirmation</c>), the refresh endpoint's own
    /// not-found constant (<see cref="Verifiable.OAuth.AuthCode.AuthCodeEndpoints.RefreshTokenNotFoundDescription"/>)
    /// under <c>invalid_grant</c>, never a nonce challenge that would itself prove the record's
    /// binding exists; otherwise no binding; (b) a proof was validated at the step —
    /// <paramref name="expectedThumbprint"/> non-null and different from the carried
    /// confirmation's answers the same constant, never <c>invalid_dpop_proof</c>; otherwise the
    /// carried confirmation succeeds. Never re-runs proof parsing, signature verification, the
    /// nonce decision, or the <c>jti</c> replay guard — those ran exactly once, in the step.
    /// </para>
    /// </remarks>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="issuerUri">The authorization server's issuer URI; combined with the request path to form the expected DPoP <c>htu</c> claim and to key the JTI replay record.</param>
    /// <param name="carriedOutcome">The outcome <see cref="ValidatePresentedProofAsync"/> recorded on the context earlier in this same request.</param>
    /// <param name="expectedThumbprint">
    /// When non-null, the carried proof's JWK thumbprint MUST match this value; used on
    /// refresh-grant where the binding is being VERIFIED. When null, the carried
    /// <see cref="DpopValidationOutcome.Confirmation"/> is accepted as-is; used on code-grant
    /// where the binding is being ESTABLISHED.
    /// </param>
    /// <param name="proofRequiredByRecord">Whether the STORED record (not the registration's profile) requires a bound DPoP proof.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static ValueTask<DpopValidationOutcome> BindValidatedProofAsync(
        EndpointServer server,
        ExchangeContext context,
        ClientRecord registration,
        Uri issuerUri,
        DpopValidationOutcome carriedOutcome,
        string? expectedThumbprint,
        bool proofRequiredByRecord,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(issuerUri);
        ArgumentNullException.ThrowIfNull(carriedOutcome);

        if(carriedOutcome.Confirmation is null)
        {
            if(!proofRequiredByRecord)
            {
                return ValueTask.FromResult(DpopValidationOutcome.NoBinding);
            }

            //A DPoP-bound refresh token presented without a proof, under a profile that does not
            //itself require DPoP: RFC 9449 §8 governs a PROOF presented without the server's
            //nonce, not a request presenting no proof at all, and §5 (the binding "MUST be
            //validated when the refresh token is later presented") names no error for a missing
            //proof. A refusal that reads the record answers the endpoint's constant — never a
            //nonce challenge, which would itself prove the record's binding exists — so the
            //answer never tells whether the record exists. Only the refresh grant ever passes
            //proofRequiredByRecord: true (the code grant always passes false, establishing rather
            //than verifying a binding), so this exit is refresh-only.
            return ValueTask.FromResult(DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, Verifiable.OAuth.AuthCode.AuthCodeEndpoints.RefreshTokenNotFoundDescription)));
        }

        if(expectedThumbprint is not null
            && !string.Equals(carriedOutcome.Confirmation.JwkThumbprint, expectedThumbprint, StringComparison.Ordinal))
        {
            //A valid proof bound to a key other than the one the record names: RFC 9449 §5
            //prescribes invalid_dpop_proof for an INVALID proof — already answered before
            //correlation, in ValidatePresentedProofAsync — and prescribes nothing for a valid
            //proof bound to the wrong key. A refusal that reads
            //the record answers the endpoint's constant so the answer never tells whether the
            //record exists. Only the refresh grant ever passes a non-null expectedThumbprint (the
            //code grant always passes null, establishing rather than verifying a binding), so
            //this exit is refresh-only.
            return ValueTask.FromResult(DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidGrant, Verifiable.OAuth.AuthCode.AuthCodeEndpoints.RefreshTokenNotFoundDescription)));
        }

        return ValueTask.FromResult(DpopValidationOutcome.Success(carriedOutcome.Confirmation));
    }


    /// <summary>
    /// Validates a DPoP proof presented at the token endpoint and persists the JTI marker for
    /// replay defense. Its four remaining callers are the grants with no pre-correlation step —
    /// <c>BuildClientCredentials</c>, <c>BuildTokenExchange</c>, the JWT-bearer grant's candidate,
    /// and the pre-authorized code grant's candidate — each establishing a binding rather than
    /// verifying one against a stored record, so each passes <paramref name="expectedThumbprint"/>
    /// as <see langword="null"/>. The two step endpoints (code redemption, refresh) never call
    /// this method: their pre-correlation step calls <see cref="ValidatePresentedProofAsync"/> and
    /// their handler calls <see cref="BindValidatedProofAsync"/>.
    /// </summary>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="issuerUri">The authorization server's issuer URI; combined with the request path to form the expected DPoP <c>htu</c> claim and to key the JTI replay record.</param>
    /// <param name="now">The current instant the DPoP proof's freshness window is evaluated against.</param>
    /// <param name="expectedThumbprint">
    /// When non-null, the proof's JWK thumbprint MUST match this value — no remaining caller
    /// passes a non-null value, since none of the four verifies a binding already on record. When
    /// null, any well-formed proof's thumbprint is captured into the returned
    /// <see cref="DpopValidationOutcome.Confirmation"/>.
    /// </param>
    /// <param name="dpopRequired">Whether presenting a DPoP proof is mandatory for this request; when <see langword="false"/> and none is presented, the token issues as Bearer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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

        //Refresh-grant verifies the bound thumbprint before nonce/JTI work.
        //Cheap string compare; fail-fast keeps storage out of the wrong-key
        //attack surface.
        if(expectedThumbprint is not null
            && !string.Equals(proofResult.JwkThumbprint, expectedThumbprint, StringComparison.Ordinal))
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

        //JTI replay check — the same shared (issuer, jti) correlation store the JAR path
        //uses, governed by JtiReplayPolicy: Required fails closed when no store is wired, and
        //the read and first-use record happen as one unit (RFC 9449 §11.1). Runs only after
        //structural and cryptographic checks pass.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, proofResult.Claims.Jti,
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
                "DPoP proof jti exceeds the length the replay guard can track."),
            JtiReplayOutcome.StoreUnavailable => ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."),

            _ => null
        };
        if(jtiFailure is not null)
        {
            return DpopValidationOutcome.Failure(jtiFailure);
        }

        ConfirmationMethod? confirmation = proofResult.JwkThumbprint is not null
            ? new ConfirmationMethod { JwkThumbprint = proofResult.JwkThumbprint }
            : null;

        return DpopValidationOutcome.Success(confirmation);
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
