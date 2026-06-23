using System.Diagnostics;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.TokenExchange;

/// <summary>
/// The parameters that compose the body of an OAuth 2.0 Token Exchange request per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>.
/// </summary>
/// <remarks>
/// Posted as <c>application/x-www-form-urlencoded</c> to the token endpoint with <c>grant_type</c> =
/// <c>urn:ietf:params:oauth:grant-type:token-exchange</c>. The client is identified by client
/// authentication at the token endpoint, not by a body parameter. The presence of
/// <see cref="ActorToken"/> selects delegation over impersonation per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">RFC 8693 §1.1</see>.
/// </remarks>
[DebuggerDisplay("TokenExchangeRequest SubjectTokenType={SubjectTokenType}, Delegation={ActorToken != null}")]
public sealed record TokenExchangeRequest
{
    /// <summary>
    /// The security token that represents the identity of the party on behalf of whom the request is
    /// being made (RFC 8693 §2.1, REQUIRED). Confidential.
    /// </summary>
    public required string SubjectToken { get; init; }

    /// <summary>The type of <see cref="SubjectToken"/> (RFC 8693 §2.1, REQUIRED).</summary>
    public required TokenType SubjectTokenType { get; init; }

    /// <summary>
    /// The security token that represents the identity of the acting party (RFC 8693 §2.1, OPTIONAL).
    /// Its presence selects delegation over impersonation; <see cref="ActorTokenType"/> is then
    /// REQUIRED. Confidential.
    /// </summary>
    public string? ActorToken { get; init; }

    /// <summary>
    /// The type of <see cref="ActorToken"/> (RFC 8693 §2.1). REQUIRED when <see cref="ActorToken"/> is
    /// present and MUST be absent otherwise.
    /// </summary>
    public TokenType? ActorTokenType { get; init; }

    /// <summary>
    /// The type of token the client requests (RFC 8693 §2.1, OPTIONAL). When <see langword="null"/> the
    /// authorization server chooses the issued type.
    /// </summary>
    public TokenType? RequestedTokenType { get; init; }

    /// <summary>
    /// The target-resource URIs where the client intends to use the requested token (RFC 8693 §2.1 /
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707">RFC 8707</see>). MAY be empty.
    /// </summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>
    /// The logical names of the target service where the client intends to use the requested token
    /// (RFC 8693 §2.1). MAY be empty.
    /// </summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    /// <summary>
    /// The requested scope of the issued token (RFC 8693 §2.1, OPTIONAL). When <see langword="null"/>
    /// the authorization server decides the issued scope.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> the client requested (a JSON array of authorization
    /// detail objects), or <see langword="null"/> when absent. Carried verbatim for the
    /// draft-ietf-oauth-identity-assertion-authz-grant §4.3.3 policy decision, where the IdP parses
    /// and processes each object; the granted result is returned as
    /// <see cref="TokenExchangeAuthorization.AuthorizationDetailsClaim"/>. Populated for the ID-JAG
    /// profile (<see cref="RequestedTokenType"/> id-jag); base RFC 8693 token exchange does not define
    /// the parameter.
    /// </summary>
    public string? AuthorizationDetails { get; init; }

    /// <summary>The grant type. Always <c>urn:ietf:params:oauth:grant-type:token-exchange</c>.</summary>
    public string GrantType { get; init; } = "urn:ietf:params:oauth:grant-type:token-exchange";
}
