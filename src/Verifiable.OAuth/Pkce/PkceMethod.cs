namespace Verifiable.OAuth.Pkce;

/// <summary>
/// Identifies the code challenge method used in a PKCE exchange.
/// </summary>
/// <remarks>
/// Only <see cref="S256"/> is permitted by
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
/// and
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>.
/// The <c>plain</c> method must not be used because it exposes the verifier to any
/// party that can observe the authorization request, negating the downgrade-attack
/// protection described in
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
/// </remarks>
public enum PkceMethod
{
    /// <summary>
    /// The SHA-256 code challenge method defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 §4.2</see>.
    /// The challenge is the Base64url encoding (without padding) of the SHA-256 hash
    /// of the UTF-8 representation of the code verifier.
    /// </summary>
    S256
}
