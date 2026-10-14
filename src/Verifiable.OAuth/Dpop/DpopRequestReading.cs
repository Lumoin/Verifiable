using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The reading of a request's <c>DPoP</c> field and target that every DPoP-checked endpoint shares, the token endpoint,
/// the pushed authorization request and the protected resources alike: the field read by its field lines
/// (<see cref="ReadDpopField"/>), the target URI a proof's <c>htu</c> is held to (<see cref="ComposeTargetUri"/>), the
/// proof validation the server runs, the application's or the library default (<see cref="IsProofValidationWired"/>,
/// <see cref="ValidateProofAsync"/>), and the descriptions those endpoints answer a repeated field and a validator's
/// incomplete success with.
/// </summary>
/// <remarks>
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see> holds every receiving
/// server to the same checks, "To validate a DPoP proof, the receiving server MUST ensure the following", so the
/// endpoints read the field and reconstruct the target the same way, and answer a validator's success that carries no
/// thumbprint or no claims with the same descriptions, each in its own response shape.
/// </remarks>
internal static class DpopRequestReading
{
    /// <summary>
    /// The description a request carrying the <c>DPoP</c> field on more than one field line is answered with under
    /// <c>invalid_dpop_proof</c>, at the token endpoint, at the pushed authorization request and at the library's
    /// protected resources. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>:
    /// "To validate a DPoP proof, the receiving server MUST ensure the following: 1. There is not more than one DPoP
    /// HTTP request header field."; the field is <c>DPoP = token68</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">Section 4.1</see>), no list, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see> has a sender generate it
    /// on one line ("a sender MUST NOT generate multiple field lines with the same name in a message ... unless that
    /// field's definition allows multiple field line values to be recombined as a comma-separated list").
    /// </summary>
    internal static string MoreThanOneDpopFieldDescription { get; } = "More than one DPoP header field was presented.";


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
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>),
    /// the token endpoint cannot associate the issued token "with the public key from the DPoP
    /// proof" (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">Section 5</see>), and a protected resource
    /// cannot "check that the public key of the DPoP proof matches the public key to which the access token is bound"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>), so the request fails closed
    /// rather than binding nothing, binding text that is not spelled as a thumbprint, or refusing the client for a fault
    /// of the server's own validator.
    /// </summary>
    internal static string ValidatedProofWithoutThumbprintDescription { get; } =
        "The DPoP proof validator answered no JWK SHA-256 Thumbprint for a valid proof.";


    /// <summary>
    /// The description a request is answered with under <c>server_error</c> when the application's
    /// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/> answers a proof valid without the claims
    /// <see cref="DpopProofValidationResult.Claims"/> carries on every success: the proof's <c>nonce</c>, which the
    /// server holds to the nonce it supplied (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449
    /// Section 4.3</see>, check 10: "If the server provided a nonce value to the client, the nonce claim matches the
    /// server-provided nonce value."), and its <c>jti</c>, which the replay guard records
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see>). With neither to check, the
    /// request fails closed rather than issuing a token or serving a resource under a proof whose nonce and <c>jti</c>
    /// were never read.
    /// </summary>
    internal static string ValidatedProofWithoutClaimsDescription { get; } =
        "The DPoP proof validator answered no claims for a valid proof.";


    /// <summary>
    /// Reads the <c>DPoP</c> field of <paramref name="request"/> by its field lines
    /// (<see cref="RequestHeaders.TryGetAll"/>): one line is the proof; no line, or a field the skin mapped with no
    /// value, is no proof; two or more lines are a repeated field, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 1, refuses
    /// ("There is not more than one DPoP HTTP request header field."), never read as no proof.
    /// </summary>
    /// <param name="request">The inbound request, or <see langword="null"/> when the context carries none.</param>
    /// <returns>The one proof, or <see langword="null"/>; and whether the field was presented on more than one line.</returns>
    internal static (string? Proof, bool IsRepeated) ReadDpopField(IncomingRequest? request)
    {
        IReadOnlyList<string>? values = null;
        _ = request?.Headers.TryGetAll(WellKnownHttpHeaderNames.DPoP, out values);

        return values switch
        {
            null or { Count: 0 } => (null, false),
            { Count: 1 } => (values[0], false),
            _ => (null, true)
        };
    }


    /// <summary>
    /// The target URI a DPoP proof's <c>htu</c> is held to: the scheme and authority of
    /// <see cref="IncomingRequest.ListenerAuthority"/> when the host stamped one, otherwise those of
    /// <paramref name="issuerUri"/>, followed by the request's path.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 9: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment
    /// parts."; <see href="https://www.rfc-editor.org/rfc/rfc9110#section-7.1">RFC 9110 Section 7.1</see>: "Upon receipt
    /// of a client's request, a server reconstructs the target URI from the received components in accordance with
    /// their local configuration and incoming connection context." The authority is the host's configuration or the
    /// issuer's, never a request field.
    /// </summary>
    /// <param name="request">The inbound request.</param>
    /// <param name="issuerUri">The issuer the request is served under.</param>
    /// <returns>The target URI the proof's <c>htu</c> is compared with and the replay record is keyed by.</returns>
    internal static string ComposeTargetUri(IncomingRequest request, Uri issuerUri)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(issuerUri);

        Uri authority = request.ListenerAuthority ?? issuerUri;

        return $"{authority.GetLeftPart(UriPartial.Authority)}{request.Path}";
    }


    /// <summary>
    /// Whether the server validates DPoP proofs: the application assigned
    /// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/>, or the library default
    /// <see cref="DefaultDpopProofValidation"/> can run because the codecs carry its
    /// <see cref="AuthorizationServerCodecs.DpopProofParser"/>, <see cref="AuthorizationServerCodecs.Encoder"/> and
    /// <see cref="AuthorizationServerCodecs.Decoder"/>. A server that validates proofs reads <c>dpop_jkt</c>, checks the
    /// proof of a pushed request and publishes <c>dpop_signing_alg_values_supported</c>; one that validates none answers
    /// a request that presents a proof, or for which DPoP is required, <c>server_error</c>, a fault of its composition.
    /// <see cref="AuthorizationServerIntegration.Validate()"/> reads the same predicate, so a composition that validates
    /// proofs is admitted only with the nonce and HMAC delegates the token endpoint's proof checks require.
    /// </summary>
    /// <param name="oauth">The integration admitted for the request.</param>
    /// <returns><see langword="true"/> when a proof presented to the server is validated.</returns>
    internal static bool IsProofValidationWired(AuthorizationServerIntegration oauth)
    {
        ArgumentNullException.ThrowIfNull(oauth);

        AuthorizationServerCodecs codecs = oauth.Codecs;

        return oauth.ValidateDpopProofAsync is not null
            || (codecs.DpopProofParser is not null && codecs.Encoder is not null && codecs.Decoder is not null);
    }


    /// <summary>
    /// Validates <paramref name="request"/>'s proof with the application's
    /// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/> where it is assigned, and otherwise with the
    /// library default <see cref="DefaultDpopProofValidation.ValidateAsync"/> over the integration's codecs and pool and
    /// <paramref name="timeProvider"/>, the provider the registry serves for the family of the proof's public key
    /// verifying. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate
    /// a DPoP proof, the receiving server MUST ensure the following". The caller has checked
    /// <see cref="IsProofValidationWired"/>.
    /// </summary>
    /// <param name="oauth">The integration admitted for the request.</param>
    /// <param name="timeProvider">The server's clock the proof's <c>iat</c> window is checked against.</param>
    /// <param name="request">The proof and what the endpoint expects of it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    internal static async ValueTask<DpopProofValidationResult> ValidateProofAsync(
        AuthorizationServerIntegration oauth,
        TimeProvider timeProvider,
        DpopProofValidationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(oauth);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(request);

        return oauth.ValidateDpopProofAsync switch
        {
            ValidateDpopProofDelegate validate => await validate(request, cancellationToken).ConfigureAwait(false),
            null => await DefaultDpopProofValidation.ValidateAsync(
                request, oauth.Codecs, timeProvider, oauth.MemoryPool, cancellationToken).ConfigureAwait(false)
        };
    }
}
