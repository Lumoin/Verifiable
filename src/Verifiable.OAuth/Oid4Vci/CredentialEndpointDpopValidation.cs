using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Enforces the RFC 9449 DPoP sender constraint at the protected OID4VCI endpoints (Credential,
/// Deferred, Notification). When the validated Access Token carries a <c>cnf.jkt</c> binding, a
/// DPoP proof bound to the SAME key MUST accompany it — the proof-of-possession the token
/// endpoint minted is verified at the resource, not ignored. A bound token is never accepted as
/// a plain bearer: presented under the <c>Bearer</c> scheme it is rejected (§7.1), and a missing
/// DPoP delegate is a configuration error rather than a silent downgrade. The resource-server
/// shape mirrors <c>DpopTokenEndpointValidation</c> but adds the <c>ath</c> binding and computes
/// <c>htu</c> against this endpoint.
/// </summary>
internal static class CredentialEndpointDpopValidation
{
    /// <summary>
    /// Returns the failure response to return, or <see langword="null"/> when the sender
    /// constraint is satisfied or the token is an ordinary bearer token with no binding.
    /// </summary>
    public static async ValueTask<ServerHttpResponse?> EnforceAsync(
        AuthorizationServer server,
        ExchangeContext context,
        ClientRecord registration,
        JwtPayload accessToken,
        string rawAccessToken,
        bool isDpopPresentation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string? boundThumbprint = ReadConfirmationThumbprint(accessToken);
        if(boundThumbprint is null)
        {
            //An ordinary bearer token — there is no sender constraint to honor.
            return null;
        }

        //RFC 9449 §7.1: a sender-constrained token MUST be presented under the DPoP scheme.
        //Accepting it under Bearer would strip the binding the token endpoint established.
        if(!isDpopPresentation)
        {
            return ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                "The Access Token is sender-constrained and must be presented under the DPoP scheme.");
        }

        //A bound token with no DPoP enforcement wired is a misconfiguration — fail loud rather
        //than fall back to bearer, which would silently drop the proof-of-possession check.
        if(server.Integration.ValidateDpopProofAsync is null
            || server.Integration.IssueDpopNonceAsync is null
            || server.Integration.ValidateDpopNonceAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "The Access Token is DPoP-bound but DPoP validation is not configured.");
        }

        Uri issuerUri = await ResolveIssuerAsync(server, registration, context, cancellationToken)
            .ConfigureAwait(false);

        string? dpopProof = null;
        context.IncomingRequest?.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoP, out dpopProof);
        if(dpopProof is null)
        {
            string freshNonce = await server.Integration.IssueDpopNonceAsync(
                issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            return ServerHttpResponse
                .BadRequest(OAuthErrors.UseDpopNonce,
                    "A DPoP proof is required for the sender-constrained Access Token.")
                .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
        }

        string htu = $"{issuerUri.GetLeftPart(UriPartial.Authority)}{context.IncomingRequest!.Path}";
        DpopProofValidationResult proofResult = await server.Integration.ValidateDpopProofAsync(
            new DpopProofValidationRequest
            {
                Proof = dpopProof,
                HttpMethod = WellKnownHttpMethods.Post,
                HttpUrl = htu,
                //ath binds the proof to THIS access token (RFC 9449 §4.2 / §7).
                AccessToken = rawAccessToken,
                NonceRequired = false
            },
            cancellationToken).ConfigureAwait(false);

        if(!proofResult.IsSuccess)
        {
            if(proofResult.FailureReason is DpopProofValidationFailureReason.NonceMissing
                or DpopProofValidationFailureReason.NonceMismatch)
            {
                string freshNonce = await server.Integration.IssueDpopNonceAsync(
                    issuerUri, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

                return ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce, "DPoP nonce required.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
            }

            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                $"DPoP proof validation failed: {proofResult.FailureReason}.");
        }

        //The proving key MUST be the one the token was bound to. Constant-time — the thumbprint
        //is matched, not merely compared.
        if(!FixedTimeComparison.AreEqual(proofResult.JwkThumbprint, boundThumbprint))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof,
                "The DPoP proof key does not match the Access Token's cnf.jkt binding.");
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

                return ServerHttpResponse
                    .BadRequest(OAuthErrors.UseDpopNonce, $"DPoP nonce invalid: {nonceResult.FailureReason}.")
                    .WithHeader(WellKnownHttpHeaderNames.DPoPNonce, freshNonce);
            }
        }

        //jti replay — the same shared (issuer, jti) correlation store, RFC 9449 §11.1.
        JtiReplayOutcome jtiOutcome = await JtiReplayGuard.ConsultAsync(
            server, context, registration.TenantId,
            issuerUri.OriginalString, proofResult.Claims.Jti,
            now + WellKnownDpopValues.DefaultReplayWindow,
            cancellationToken).ConfigureAwait(false);

        if(jtiOutcome == JtiReplayOutcome.Replayed)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidDpopProof, "The DPoP proof jti has been presented previously.");
        }

        if(jtiOutcome == JtiReplayOutcome.StoreUnavailable)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "DPoP proof jti replay defense is required by policy but no jti store is configured.");
        }

        return null;
    }


    private static async ValueTask<Uri> ResolveIssuerAsync(
        AuthorizationServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        server.Integration.ResolveIssuerAsync is not null
            ? await server.Integration.ResolveIssuerAsync(registration, context, cancellationToken)
                .ConfigureAwait(false)
            : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                .ConfigureAwait(false);


    /// <summary>Reads <c>cnf.jkt</c> off the validated Access Token, tolerating either dictionary view.</summary>
    private static string? ReadConfirmationThumbprint(JwtPayload payload)
    {
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? raw))
        {
            return null;
        }

        if(raw is IReadOnlyDictionary<string, object> readOnly
            && readOnly.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? jktValue)
            && jktValue is string jkt
            && !string.IsNullOrWhiteSpace(jkt))
        {
            return jkt;
        }

        if(raw is IDictionary<string, object> writable
            && writable.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? jktValue2)
            && jktValue2 is string jkt2
            && !string.IsNullOrWhiteSpace(jkt2))
        {
            return jkt2;
        }

        return null;
    }
}
