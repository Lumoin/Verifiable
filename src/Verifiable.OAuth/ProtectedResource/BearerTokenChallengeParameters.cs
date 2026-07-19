using System;
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
/// The RFC 9728 §5.1 <c>resource_metadata</c> URL. Per RFC 9728 §3.3, the
/// fetched document's <c>resource</c> value MUST be identical to the URL the
/// client used to make the resource request — verify with
/// <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/> before
/// using the document.
/// </param>
[DebuggerDisplay("BearerTokenChallengeParameters Error={Error} Scope={Scope}")]
public sealed record BearerTokenChallengeParameters(
    string? Realm,
    string? Error,
    string? ErrorDescription,
    string? Scope,
    Uri? ResourceMetadata);
