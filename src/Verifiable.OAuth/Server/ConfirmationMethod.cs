using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The contents of an RFC 7800 <c>cnf</c> (confirmation) claim. Carries
/// one or more proof-of-possession identifiers that bind an issued token
/// to a key the bearer must demonstrate possession of when presenting
/// the token. Used in both access-token and (future) refresh-token
/// issuance paths to record the binding established at the token
/// endpoint.
/// </summary>
/// <remarks>
/// <para>
/// At present <see cref="JwkThumbprint"/> (RFC 9449 §6 DPoP confirmation)
/// is the only populated member. Future binding methods extend the
/// record without changing the consuming code path:
/// </para>
/// <list type="bullet">
///   <item><description><c>X5tS256</c> for MTLS-bound tokens (RFC 8705 §3)</description></item>
///   <item><description><c>Jwk</c> for embedded-public-key bindings (RFC 7800 §3.2)</description></item>
/// </list>
/// <para>
/// The shape is intentionally an optional-fields record rather than a
/// discriminated union: RFC 7800 §3 permits a <c>cnf</c> object to carry
/// multiple members simultaneously (a token can be both DPoP-bound and
/// MTLS-bound, for example). The producer emits only the members that
/// are set.
/// </para>
/// </remarks>
[DebuggerDisplay("ConfirmationMethod jkt={JwkThumbprint,nq}")]
public sealed record ConfirmationMethod
{
    /// <summary>
    /// RFC 9449 §6 DPoP confirmation method: base64url-encoded RFC 7638
    /// JWK thumbprint of the public key the bearer must demonstrate
    /// possession of via a DPoP proof.
    /// </summary>
    public string? JwkThumbprint { get; init; }


    /// <summary>
    /// Returns <see langword="true"/> when no confirmation members are
    /// populated. An empty <see cref="ConfirmationMethod"/> represents
    /// "no binding" — equivalent to omitting the <c>cnf</c> claim
    /// entirely on the wire.
    /// </summary>
    public bool IsEmpty => JwkThumbprint is null;
}
