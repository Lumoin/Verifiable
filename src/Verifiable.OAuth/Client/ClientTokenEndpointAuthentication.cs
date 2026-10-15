using System.Diagnostics;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Per-call inputs for composing the client assertion a token-endpoint request presents per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see>, the
/// <c>private_key_jwt</c> assertion signed with a key or the <c>client_secret_jwt</c> assertion MACed with a secret
/// (OpenID Connect Core 1.0 §9), which <see cref="ClientAssertionCredential.Of"/> forms the key of and
/// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> attaches. The signing key or the client
/// secret itself is read from
/// <see cref="ClientRegistration.AuthenticationKeyMaterial"/> — this record carries only the pieces that vary
/// independently of the registration (the <c>kid</c> of a signing key, the HMAC algorithm of a client secret, the
/// wire serialisers, and the assertion's validity window).
/// </summary>
[DebuggerDisplay("ClientAssertionOptions SigningKeyId={SigningKeyId} ClientSecretAlgorithm={ClientSecretAlgorithm}")]
public sealed record ClientAssertionOptions
{
    /// <summary>
    /// The <c>kid</c> header parameter value identifying
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s private key to the authorization
    /// server: required for <c>private_key_jwt</c>, and <see langword="null"/> for <c>client_secret_jwt</c>, whose
    /// key is the client's own secret, which its identifier already names, so its header names no <c>kid</c>.
    /// </summary>
    public string? SigningKeyId { get; init; }

    /// <summary>
    /// The JWS <c>alg</c> a <c>client_secret_jwt</c> assertion is MACed under, one of RFC 7518 §3.2's HMAC algorithms
    /// (OpenID Connect Core 1.0 §9: "such as HMAC SHA-256"). Defaults to <see cref="WellKnownJwaValues.Hs256"/>; not read
    /// for <c>private_key_jwt</c>, whose key's own tag names its algorithm.
    /// </summary>
    public string ClientSecretAlgorithm { get; init; } = WellKnownJwaValues.Hs256;

    /// <summary>Serialises the client-assertion protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the client-assertion payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>The validity window of the signed client assertion (RFC 7523 §3). Defaults to one minute.</summary>
    public TimeSpan ClientAssertionLifetime { get; init; } = TimeSpan.FromMinutes(1);
}


/// <summary>
/// Composes the confidential-client authentication assertion
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see> defines - the
/// <c>private_key_jwt</c> assertion signed with the client's key and the <c>client_secret_jwt</c> assertion MACed with
/// its secret (OpenID Connect Core 1.0 §9) alike - shared by every client-side flow that authenticates a confidential
/// client at a token endpoint: the <see cref="Verifiable.OAuth.IdJag.IdJagFlowHandlers"/> mint (§4.3) and redeem (§4.4)
/// exchanges, and the <see cref="Verifiable.OAuth.AuthCode.AuthCodeFlowHandlers"/> authorization-code
/// token leg.
/// </summary>
public static class ClientTokenEndpointAuthentication
{
    /// <summary>
    /// Adds the confidential-client authentication parameters, <c>client_id</c>,
    /// <c>client_assertion_type</c>, and a freshly-composed <c>client_assertion</c>
    /// (RFC 7523 Section 2.2) bound to the authorization server as the registration chooses, to a
    /// token-endpoint request form: the one orchestration every client assertion is attached by, whichever key it is
    /// signed under. The <c>jti</c> is generated for this assertion alone, the validity window runs from
    /// <paramref name="now"/>, the <c>aud</c> value follows <see cref="ClientRegistration.ClientAssertionAudience"/> and
    /// the <c>typ</c> header follows <see cref="ClientRegistration.IsClientAssertionExplicitlyTyped"/>; the key supplies
    /// the header's <c>alg</c> and <c>kid</c> and the signing operation (<see cref="ClientAssertionCredential"/>).
    /// </summary>
    /// <param name="form">The outgoing form fields the assertion parameters are added to.</param>
    /// <param name="registration">
    /// The registration whose <see cref="ClientRegistration.ClientAssertionAudience"/> and
    /// <see cref="ClientRegistration.IsClientAssertionExplicitlyTyped"/> choose the assertion's <c>aud</c>
    /// and <c>typ</c>.
    /// </param>
    /// <param name="tokenEndpoint">
    /// The authorization server's resolved token endpoint URL, whichever endpoint this request is
    /// sent to (the pushed-authorization endpoint included). It becomes the assertion's <c>aud</c>
    /// only when <paramref name="registration"/> chooses
    /// <see cref="ClientAssertionAudience.TokenEndpoint"/>; under
    /// <see cref="ClientAssertionAudience.IssuerIdentifier"/> it is not read. Naming one endpoint's
    /// URL as <c>aud</c> while sending to a different endpoint is the audience-injection attack
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-1">rfc7523bis-11's
    /// Introduction</see> describes; <see cref="ClientAssertionAudience.TokenEndpoint"/>'s own doc
    /// states the deviation from rfc7523bis-11 Section 4 that choosing it makes.
    /// </param>
    /// <param name="key">
    /// The key the assertion is signed under: a private key (<see cref="ClientAssertionCredential.OfPrivateKey"/>) or a client
    /// secret (<see cref="ClientAssertionCredential.OfClientSecret"/>, judged as it was formed).
    /// </param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="clientAssertionLifetime">The assertion's validity window (RFC 7523 Section 3 rule 4).</param>
    /// <param name="infrastructure">Supplies the <c>jti</c> generator, the encoder, and the memory pool.</param>
    /// <param name="now">The instant the assertion's <c>iat</c> and <c>exp</c> are computed from.</param>
    /// <param name="context">The per-operation exchange context passed to the <c>jti</c> generator.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask AttachClientAssertionAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        ClientAssertionCredential key,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        TimeSpan clientAssertionLifetime,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(registration.ClientAssertionAudience);
        ArgumentNullException.ThrowIfNull(tokenEndpoint);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(infrastructure);

        var audience = AudienceOf(registration, tokenEndpoint);
        var jti = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        var clientAssertion = await ClientAssertionSigning.SignAsync(
            registration.ClientId.Value,
            audience,
            jti,
            now,
            now.Add(clientAssertionLifetime),
            key,
            TypeOf(registration),
            headerSerializer,
            payloadSerializer,
            infrastructure.Base64UrlEncoder,
            infrastructure.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        form[OAuthRequestParameterNames.ClientId] = registration.ClientId.Value;
        form[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        form[OAuthRequestParameterNames.ClientAssertion] = clientAssertion;
    }


    /// <summary>
    /// The one value a client assertion composed under the registration names as its <c>aud</c>. rfc7523bis-11 Section 4:
    /// for client authentication the aud value MUST indicate only the issuer identifier of the intended authorization
    /// server, the string the library's own server compares ordinally (PrivateKeyJwtClientAuthentication); RFC 7523
    /// Section 3 item 3 permits (MAY) and OpenID Connect Core Section 9 recommends (SHOULD) the token endpoint URL
    /// instead, for an authorization server that refuses its issuer identifier.
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <param name="tokenEndpoint">The token endpoint, read under <see cref="ClientAssertionAudience.TokenEndpoint"/> alone.</param>
    /// <returns>The audience value.</returns>
    /// <exception cref="NotSupportedException">The registration names an audience form the library defines none of.</exception>
    private static string AudienceOf(ClientRegistration registration, Uri tokenEndpoint) =>
        registration.ClientAssertionAudience.Code switch
        {
            var c when c == ClientAssertionAudience.IssuerIdentifier.Code => registration.AuthorizationServerIssuer.OriginalString,
            var c when c == ClientAssertionAudience.TokenEndpoint.Code => tokenEndpoint.OriginalString,
            _ => throw new NotSupportedException(
                $"Client assertion audience '{registration.ClientAssertionAudience}' is not supported.")
        };


    /// <summary>The <c>typ</c> header a client assertion composed under the registration carries (rfc7523bis-11 Section 4).</summary>
    /// <param name="registration">The registration.</param>
    /// <returns>The <c>typ</c> value.</returns>
    private static string TypeOf(ClientRegistration registration) =>
        registration.IsClientAssertionExplicitlyTyped
            ? WellKnownMediaTypes.Jwt.ClientAuthenticationJwt
            : WellKnownJwkValues.TypeJwt;
}
