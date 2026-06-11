using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Server.States;

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
/// </remarks>
[DebuggerDisplay("DpopTokenEndpointValidation")]
internal static class DpopTokenEndpointValidation
{
    /// <summary>
    /// Validates a DPoP proof presented at the token endpoint and persists
    /// the JTI marker for replay defense.
    /// </summary>
    /// <param name="expectedThumbprint">
    /// When non-null, the proof's JWK thumbprint MUST match this value;
    /// used on refresh-grant where the binding is being VERIFIED. When
    /// null, any well-formed proof's thumbprint is captured into the
    /// returned <see cref="DpopValidationOutcome.Confirmation"/>; used on
    /// code-grant where the binding is being ESTABLISHED.
    /// </param>
    public static async ValueTask<DpopValidationOutcome> ValidateAsync(
        AuthorizationServer server,
        ExchangeContext context,
        ClientRecord registration,
        Uri issuerUri,
        DateTimeOffset now,
        string? expectedThumbprint,
        bool dpopRequired,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(issuerUri);

        string? dpopProofString = null;
        context.IncomingRequest?.Headers.TryGetSingle(
            WellKnownHttpHeaderNames.DPoP, out dpopProofString);

        if(dpopProofString is null && !dpopRequired)
        {
            //No proof presented and none required — Bearer issuance.
            return DpopValidationOutcome.NoBinding;
        }

        if(server.Integration.ValidateDpopProofAsync is null
            || server.Integration.IssueDpopNonceAsync is null
            || server.Integration.ValidateDpopNonceAsync is null
            || server.Integration.ResolveServerHmacKeyAsync is null
            || server.Integration.GetHmacKeySetAsync is null)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP enforcement is required by policy but DPoP delegates are not wired."));
        }

        if(dpopProofString is null)
        {
            //Required but absent — issue a fresh nonce challenge.
            string freshNonce = await server.Integration.IssueDpopNonceAsync(
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

        DpopProofValidationResult proofResult = await server.Integration.ValidateDpopProofAsync(
            validationRequest, cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            if(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch)
            {
                string freshNonce = await server.Integration.IssueDpopNonceAsync(
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
            DpopNonceValidationResult nonceResult = await server.Integration.ValidateDpopNonceAsync(
                proofResult.Claims.Nonce, issuerUri, registration.TenantId, context, cancellationToken)
                .ConfigureAwait(false);
            if(!nonceResult.IsSuccess)
            {
                string freshNonce = await server.Integration.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
                return DpopValidationOutcome.Failure(ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce,
                        $"DPoP nonce invalid: {nonceResult.FailureReason}.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce));
            }
        }
        else if(dpopRequired)
        {
            string freshNonce = await server.Integration.IssueDpopNonceAsync(
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

        if(jtiOutcome == JtiReplayOutcome.Replayed)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "DPoP proof jti has been seen previously."));
        }

        if(jtiOutcome == JtiReplayOutcome.StoreUnavailable)
        {
            return DpopValidationOutcome.Failure(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured."));
        }

        ConfirmationMethod? confirmation = proofResult.JwkThumbprint is not null
            ? new ConfirmationMethod { JwkThumbprint = proofResult.JwkThumbprint }
            : null;

        return DpopValidationOutcome.Success(confirmation);
    }
}


/// <summary>
/// The outcome of <see cref="DpopTokenEndpointValidation.ValidateAsync"/>.
/// Carries either the established <see cref="ConfirmationMethod"/> for
/// success, or a fully-shaped <see cref="ServerHttpResponse"/> for the
/// caller to return directly on any failure path (nonce challenge,
/// invalid proof, thumbprint mismatch, JTI replay).
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
