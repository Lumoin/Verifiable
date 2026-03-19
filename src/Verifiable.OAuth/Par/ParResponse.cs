using System.Diagnostics;

namespace Verifiable.OAuth.Par;

/// <summary>
/// The response body returned by the pushed authorization request endpoint.
/// </summary>
/// <remarks>
/// Defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
/// The <see cref="RequestUri"/> becomes the sole parameter of the subsequent
/// authorization redirect, keeping all authorization request parameters out of
/// the browser's address bar and history.
/// </remarks>
/// <param name="RequestUri">
/// The <c>request_uri</c> issued by the authorization server, identifying the
/// pushed authorization request. Used as both the deep-link redirect parameter
/// and the JAR endpoint reference.
/// </param>
/// <param name="ExpiresIn">
/// The lifetime of <paramref name="RequestUri"/> in seconds, as returned in the
/// <c>expires_in</c> response field.
/// </param>
[DebuggerDisplay("ParResponse RequestUri={RequestUri} ExpiresIn={ExpiresIn}")]
public sealed record ParResponse(
    Uri RequestUri,
    int ExpiresIn);
