using System.Diagnostics;
using Verifiable.OAuth.Oid4Vci;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The response body returned by the token endpoint after a successful exchange.
/// </summary>
/// <remarks>
/// Defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
/// Maps directly to <see cref="Verifiable.OAuth.AuthCode.States.TokenReceivedState"/> via
/// <c>AuthCodeFlow</c>. The caller is responsible for parsing the JSON response body
/// and constructing this record before passing it to the flow.
/// </remarks>
[DebuggerDisplay("TokenResponse TokenType={TokenType} ExpiresIn={ExpiresIn}")]
public sealed record TokenResponse
{
    /// <summary>The opaque access token. Must be treated as a secret.</summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// The token type. Typically <c>Bearer</c> or <c>DPoP</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</see>.
    /// </summary>
    public required string TokenType { get; init; }

    /// <summary>The access token lifetime in seconds, if provided by the server.</summary>
    public int? ExpiresIn { get; init; }

    /// <summary>
    /// The refresh token, if issued. Present only when the authorization server
    /// grants offline access.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// The granted scopes, if different from those requested. <see langword="null"/>
    /// when the granted scopes equal the requested scopes.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The ID Token, if issued. Present in an OpenID Connect token response per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OpenID Connect Core 1.0 §3.1.3.3</see>;
    /// <see langword="null"/> for plain OAuth 2.0 responses that carry no ID Token.
    /// </summary>
    public string? IdToken { get; init; }

    /// <summary>
    /// The <c>openid_credential</c> authorizations the response's <c>authorization_details</c>
    /// granted, each with its <c>credential_configuration_id</c> and its
    /// <c>credential_identifiers</c>, in the order the response lists them; empty when the response
    /// carries no <c>authorization_details</c> or no <c>openid_credential</c> entry in them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="OAuthResponseParsers.ParseTokenResponse"/> fills it and fails the whole parse when
    /// the member is malformed, so a response that parses carries either a well-formed grant or none.
    /// A wallet chooses its Credential Request's target from it through
    /// <see cref="Oid4Vci.CredentialRequestTarget.FromGrantedAuthorizations"/>.
    /// </para>
    /// <para>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response. Each of
    /// these Credential Datasets corresponds to the Credential Configuration referenced in the
    /// credential_configuration_id parameter. The Wallet MUST use these identifiers together with an
    /// Access Token in subsequent Credential Requests."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-7">RFC 9396 Section 7</see>:
    /// "In addition to the token response parameters as defined in [RFC6749], the AS MUST also return
    /// the authorization_details as granted by the resource owner and assigned to the respective
    /// access token."
    /// </para>
    /// </remarks>
    public IReadOnlyList<GrantedCredentialAuthorization> GrantedCredentialAuthorizations { get; init; } = [];
}
