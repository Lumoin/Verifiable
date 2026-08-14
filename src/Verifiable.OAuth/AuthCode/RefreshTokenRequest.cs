using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The parameters that compose the body of a token refresh request.
/// </summary>
/// <remarks>
/// Posted as <c>application/x-www-form-urlencoded</c> to the token endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>.
/// The refresh flow is independent of the authorization code PDA — the caller
/// initiates it when the access token has expired or is near expiry.
/// </remarks>
[DebuggerDisplay("RefreshTokenRequest ClientId={ClientId}")]
public sealed record RefreshTokenRequest
{
    /// <summary>The client identifier registered with the authorization server.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The refresh token issued during the original token exchange.
    /// Must be kept confidential.
    /// </summary>
    public required string RefreshToken { get; init; }

    /// <summary>
    /// The scopes to request in the refreshed token. When <see langword="null"/>,
    /// the authorization server issues the same scopes as the original grant.
    /// Must not exceed the originally granted scopes.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>The grant type. Always <c>refresh_token</c> for this request.</summary>
    public string GrantType { get; init; } = "refresh_token";

    /// <summary>
    /// The RFC 8707 §2.2 <c>resource</c> indicator(s) to narrow the refreshed access token to, or
    /// <see langword="null"/> to receive an access token scoped to the full resource set
    /// originally granted. Each entry is one absolute URI (RFC 8707 §2); a caller with several
    /// indicators supplies several list entries, which the encoder emits as that many REPEATED
    /// <c>resource</c> occurrences on the wire — a single entry that itself packs several URIs
    /// separated by spaces is a malformed indicator, not a shorthand for repetition. Per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">§2.2</see>, the requested
    /// set MUST be a subset of what was originally granted — the refresh token itself is never
    /// narrowed by it, only the access token this exchange mints.
    /// </summary>
    public IReadOnlyList<string>? Resource { get; init; }
}