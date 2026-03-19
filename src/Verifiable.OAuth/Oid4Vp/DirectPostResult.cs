using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// The Verifier's HTTP response to a successful Authorization Response POST,
/// as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>.
/// </summary>
/// <remarks>
/// When <see cref="RedirectUri"/> is absent the Wallet is not required to
/// perform any further steps. When present, the Wallet redirects the user to
/// that URI to complete the cross-device handoff.
/// </remarks>
[DebuggerDisplay("DirectPostResult RedirectUri={RedirectUri}")]
public sealed class DirectPostResult: IEquatable<DirectPostResult>
{
    /// <summary>
    /// The URI to redirect the user to after the Wallet has submitted the
    /// Authorization Response. OPTIONAL per OID4VP 1.0 §8.2.
    /// </summary>
    public Uri? RedirectUri { get; init; }


    /// <inheritdoc/>
    public bool Equals(DirectPostResult? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return RedirectUri == other.RedirectUri;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is DirectPostResult other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(RedirectUri);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(DirectPostResult? left, DirectPostResult? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(DirectPostResult? left, DirectPostResult? right) =>
        !(left == right);
}
