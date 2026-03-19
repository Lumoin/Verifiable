using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The Authorization Response body POSTed by the Wallet to the Verifier's
/// <c>response_uri</c> in <c>direct_post.jwt</c> mode, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1">OID4VP 1.0 §8.3.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The body is form-encoded and contains a single <c>response</c> parameter
/// whose value is a compact JWE string. The JWE plaintext is the JWT-encoded
/// Authorization Response containing <c>vp_token</c> and optionally <c>state</c>.
/// </para>
/// <para>
/// HAIP 1.0 requires this response mode for the cross-device encrypted flow.
/// The JWE uses ECDH-ES key agreement with the Verifier's ephemeral P-256 public
/// key carried in the <c>client_metadata</c> <c>jwks</c> parameter.
/// </para>
/// </remarks>
[DebuggerDisplay("DirectPostJwtBody ResponseLength={EncryptedResponse.Length}")]
public sealed class DirectPostJwtBody: IEquatable<DirectPostJwtBody>
{
    /// <summary>
    /// The compact JWE serialization of the encrypted Authorization Response.
    /// The JWE plaintext is a JWT containing <c>vp_token</c> and optionally
    /// <c>state</c>. Corresponds to the <c>response</c> form parameter per
    /// <see cref="AuthorizationResponseParameters.Response"/>.
    /// </summary>
    public required string EncryptedResponse { get; init; }


    /// <inheritdoc/>
    public bool Equals(DirectPostJwtBody? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(EncryptedResponse, other.EncryptedResponse, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is DirectPostJwtBody other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(EncryptedResponse);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(DirectPostJwtBody? left, DirectPostJwtBody? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(DirectPostJwtBody? left, DirectPostJwtBody? right) =>
        !(left == right);
}
