using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The parameters that compose the body of a pushed authorization request.
/// </summary>
/// <remarks>
/// <para>
/// Posted as <c>application/x-www-form-urlencoded</c> to the PAR endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>.
/// </para>
/// <para>
/// The caller encodes this to a form body using <c>ParRequestBodyEncoder.Encode</c>
/// before posting. Keeping the fields typed here prevents mixing up parameter names
/// and allows validation before the network call.
/// </para>
/// </remarks>
[DebuggerDisplay("ParRequestBody ClientId={ClientId}")]
public sealed record ParRequestBody
{
    /// <summary>The client identifier registered with the authorization server.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The Base64url-encoded PKCE code challenge derived from the verifier per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 §4.2</see>.
    /// Always 43 characters for S256.
    /// </summary>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// The PKCE code challenge method. Always <c>S256</c> per HAIP 1.0 and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
    /// </summary>
    public required PkceMethod CodeChallengeMethod { get; init; }

    /// <summary>
    /// The redirect URI to which the authorization server sends the code.
    /// Must exactly match a URI registered for this client.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The requested scopes.</summary>
    public required ImmutableArray<string> Scopes { get; init; }

    /// <summary>
    /// An opaque value used for CSRF protection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// The authorization server echoes this back in the redirect response.
    /// </summary>
    public required string State { get; init; }

    /// <summary>
    /// The response type. Always <c>code</c> for the Authorization Code flow.
    /// </summary>
    public string ResponseType { get; init; } = "code";
}