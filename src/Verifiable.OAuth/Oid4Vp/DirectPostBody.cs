using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The Authorization Response body POSTed by the Wallet to the Verifier's
/// <c>response_uri</c> in <c>direct_post</c> mode, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>.
/// </summary>
/// <remarks>
/// The body is form-encoded (<c>application/x-www-form-urlencoded</c>).
/// When DCQL is used, <see cref="VpToken"/> is a JSON-encoded object keyed by
/// credential query IDs. <c>presentation_submission</c> is NOT present — that
/// is a DIF Presentation Exchange concept and is not used with DCQL.
/// </remarks>
[DebuggerDisplay("DirectPostBody State={State}")]
public sealed class DirectPostBody: IEquatable<DirectPostBody>
{
    /// <summary>
    /// The VP Token containing one or more Verifiable Presentations keyed by
    /// DCQL credential query identifier.
    /// </summary>
    public required VpToken VpToken { get; init; }

    /// <summary>
    /// The state value from the Authorization Request, returned unchanged
    /// for CSRF protection per RFC 6749 §4.1.2 and RFC 9700 §4.7. OPTIONAL.
    /// </summary>
    public string? State { get; init; }


    /// <inheritdoc/>
    public bool Equals(DirectPostBody? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(State, other.State, StringComparison.Ordinal)
            && ReferenceEquals(VpToken, other.VpToken);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is DirectPostBody other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(State, VpToken?.GetHashCode());

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(DirectPostBody? left, DirectPostBody? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(DirectPostBody? left, DirectPostBody? right) =>
        !(left == right);
}
