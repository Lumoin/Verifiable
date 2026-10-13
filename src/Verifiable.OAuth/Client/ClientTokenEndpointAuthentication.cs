using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Per-call inputs for signing the <c>private_key_jwt</c> client assertion
/// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> attaches to a
/// token-endpoint request per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see>. The signing
/// key itself is read from <see cref="ClientRegistration.AuthenticationKeyMaterial"/> — this record
/// carries only the pieces that vary independently of the registration (the <c>kid</c>, the wire
/// serialisers, and the assertion's validity window).
/// </summary>
[DebuggerDisplay("ClientAssertionOptions SigningKeyId={SigningKeyId}")]
public sealed record ClientAssertionOptions
{
    /// <summary>
    /// The <c>kid</c> header parameter value identifying
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s private key to the authorization
    /// server.
    /// </summary>
    public required string SigningKeyId { get; init; }

    /// <summary>Serialises the client-assertion protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the client-assertion payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>
    /// The validity window of the signed client assertion (RFC 7523 Section 3): its <c>exp</c> less its <c>iat</c>. Defaults
    /// to one minute, the library's own value.
    /// </summary>
    /// <remarks>
    /// The library writes the assertion's <c>iat</c> and <c>exp</c> as whole-second NumericDates, so the value is at
    /// least one and at most <see cref="int.MaxValue"/> whole seconds, the library's own rule: the <c>init</c> accessor
    /// refuses any other value with <see cref="ArgumentOutOfRangeException"/> and holds an issuable value as its whole
    /// seconds.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The value's whole seconds are under one or above <see cref="int.MaxValue"/>.
    /// </exception>
    public TimeSpan ClientAssertionLifetime
    {
        get;
        init => field = TokenLifetimes.RequireIssuable(value, nameof(ClientAssertionLifetime));
    } = TimeSpan.FromMinutes(1);
}


/// <summary>
/// Composes the <c>private_key_jwt</c> confidential-client authentication assertion
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 §2.2</see> defines,
/// shared by every client-side flow that authenticates a confidential client at a token endpoint:
/// the <see cref="Verifiable.OAuth.IdJag.IdJagFlowHandlers"/> mint (§4.3) and redeem (§4.4)
/// exchanges, and the <see cref="Verifiable.OAuth.AuthCode.AuthCodeFlowHandlers"/> authorization-code
/// token leg.
/// </summary>
public static class ClientTokenEndpointAuthentication
{
    /// <summary>
    /// Adds the confidential-client authentication parameters, <c>client_id</c>,
    /// <c>client_assertion_type</c>, and a freshly-signed <c>private_key_jwt</c> <c>client_assertion</c>
    /// (RFC 7523 Section 2.2) bound to the authorization server as the registration chooses, to a
    /// token-endpoint request form. The <c>aud</c> value follows
    /// <see cref="ClientRegistration.ClientAssertionAudience"/> and the <c>typ</c> header follows
    /// <see cref="ClientRegistration.IsClientAssertionExplicitlyTyped"/>.
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
    /// <param name="signingKey">The client's confidential-authentication signing key.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value identifying the key to the AS.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="clientAssertionLifetime">
    /// The assertion's validity window (RFC 7523 Section 3 rule 4): at least one and at most <see cref="int.MaxValue"/>
    /// whole seconds, the library's own rule, issued as its whole seconds.
    /// </param>
    /// <param name="infrastructure">Supplies the <c>jti</c> generator, the encoder, and the memory pool.</param>
    /// <param name="now">The instant the assertion's <c>iat</c> and <c>exp</c> are computed from.</param>
    /// <param name="context">The per-operation exchange context passed to the <c>jti</c> generator.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The whole seconds of <paramref name="clientAssertionLifetime"/> are under one or above <see cref="int.MaxValue"/>;
    /// nothing is added to <paramref name="form"/>.
    /// </exception>
    public static async ValueTask AttachClientAssertionAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        PrivateKeyMemory signingKey,
        string signingKeyId,
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
        ArgumentNullException.ThrowIfNull(infrastructure);

        //The library writes iat and exp as whole-second NumericDates, so the assertion is issued for the whole
        //seconds of its lifetime, at least one.
        TimeSpan issuedLifetime = TokenLifetimes.RequireIssuable(clientAssertionLifetime, nameof(clientAssertionLifetime));

        string jti = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        //rfc7523bis-11 Section 4: for client authentication the aud value MUST indicate only the issuer
        //identifier of the intended authorization server, the string the library's own server compares
        //ordinally (PrivateKeyJwtClientAuthentication); RFC 7523 Section 3 item 3 permits (MAY) and
        //OpenID Connect Core Section 9 recommends (SHOULD) the token endpoint URL instead, for an
        //authorization server that refuses its issuer identifier.
        string audience = registration.ClientAssertionAudience.Code switch
        {
            var c when c == ClientAssertionAudience.IssuerIdentifier.Code => registration.AuthorizationServerIssuer.OriginalString,
            var c when c == ClientAssertionAudience.TokenEndpoint.Code => tokenEndpoint.OriginalString,
            _ => throw new NotSupportedException(
                $"Client assertion audience '{registration.ClientAssertionAudience}' is not supported.")
        };

        string type = registration.IsClientAssertionExplicitlyTyped
            ? WellKnownMediaTypes.Jwt.ClientAuthenticationJwt
            : WellKnownJwkValues.TypeJwt;

        string clientAssertion = await ClientAssertionSigning.SignAsync(
            registration.ClientId.Value,
            audience,
            jti,
            now,
            now.Add(issuedLifetime),
            signingKey,
            signingKeyId,
            type,
            headerSerializer,
            payloadSerializer,
            infrastructure.Base64UrlEncoder,
            infrastructure.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        form[OAuthRequestParameterNames.ClientId] = registration.ClientId.Value;
        form[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        form[OAuthRequestParameterNames.ClientAssertion] = clientAssertion;
    }
}
