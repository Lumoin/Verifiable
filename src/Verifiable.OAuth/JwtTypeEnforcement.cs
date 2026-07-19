namespace Verifiable.OAuth;

/// <summary>
/// Whether a signed-JWT validation pass enforces the RFC 9068 §4 <c>typ</c>
/// discriminator (<c>at+jwt</c> / <c>application/at+jwt</c>). Selects the
/// token profile the shared validation core validates against.
/// </summary>
internal enum JwtTypeEnforcement
{
    /// <summary>
    /// Require the header <c>typ</c> to be <c>at+jwt</c> or
    /// <c>application/at+jwt</c> — the OAuth 2.0 JWT access-token profile
    /// (RFC 9068 §4), the discriminator that keeps an ID Token (<c>typ</c>
    /// <c>JWT</c>) or another JWT profile from being accepted as an access token.
    /// </summary>
    RequireAtJwt,

    /// <summary>
    /// Do not constrain the header <c>typ</c> — for signed-JWT profiles that
    /// do not mandate a specific <c>typ</c> and place no restriction on it.
    /// </summary>
    None,

    /// <summary>
    /// Reject the access-token type: a header <c>typ</c> of <c>at+jwt</c> or
    /// <c>application/at+jwt</c> is refused while any other <c>typ</c> (or an
    /// absent one) is accepted. The ID Token profile uses this so a genuine
    /// RFC 9068 access token can never be validated as an ID Token per RFC 8725
    /// §3.11 explicit typing — an ID Token is proof of end-user authentication,
    /// which an access token (possibly a machine subject) is not.
    /// </summary>
    RejectAtJwt
}
