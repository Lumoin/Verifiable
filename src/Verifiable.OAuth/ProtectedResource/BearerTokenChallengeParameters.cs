using System.Diagnostics;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The attributes read from an RFC 6750 §3 <c>WWW-Authenticate: Bearer</c>
/// challenge by <see cref="BearerTokenChallenge.TryParse"/>. Every attribute is
/// optional in the challenge, so any may be <see langword="null"/>.
/// </summary>
/// <remarks>
/// The §3.1 error code carried in <see cref="Error"/> tells the client how to
/// proceed: <c>invalid_token</c> means a new access token may be requested and
/// the resource request retried; <c>insufficient_scope</c> means higher
/// privileges are required, with <see cref="Scope"/> naming the scopes to
/// request.
/// </remarks>
/// <param name="Realm">The protection-space identifier (RFC 6750 §3).</param>
/// <param name="Error">The error code (RFC 6750 §3.1), e.g. <see cref="OAuthErrors.InvalidToken"/> or <see cref="OAuthErrors.InsufficientScope"/>.</param>
/// <param name="ErrorDescription">The developer-readable explanation of the error (RFC 6750 §3).</param>
/// <param name="Scope">The space-delimited scopes the resource requires (RFC 6750 §3, RFC 6749 §3.3).</param>
/// <param name="ResourceMetadata">
/// The RFC 9728 Section 5.1 <c>resource_metadata</c> URL. The pointer is resolved by
/// <see cref="ProtectedResourceMetadataDocuments.ResolveFromChallengeAsync"/>, which admits the location
/// formed from the request URL and the root location of its origin, sends no request to any other pointer,
/// and names the identity rule the document's <c>resource</c> satisfied
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>) in
/// <see cref="ProtectedResourceMetadataResolved.Identity"/>.
/// </param>
[DebuggerDisplay("BearerTokenChallengeParameters Error={Error} Scope={Scope}")]
public sealed record BearerTokenChallengeParameters(
    string? Realm,
    string? Error,
    string? ErrorDescription,
    string? Scope,
    Uri? ResourceMetadata);
