using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries the verified claims extracted from the vp_token.
/// Transitions from <see cref="ResponseReceived"/> to <see cref="PresentationVerified"/>.
/// </summary>
/// <param name="Claims">
/// The verified and extracted claims, keyed by DCQL credential query identifier.
/// </param>
/// <param name="VerifiedAt">The UTC instant verification completed.</param>
/// <param name="RedirectUri">
/// The URI to include in the HTTP 200 response body so the Wallet can resume the
/// user's browser session. Required in the same-device flow per OID4VP 1.0 §8.2;
/// <see langword="null"/> in the cross-device flow.
/// </param>
[DebuggerDisplay("VerificationSucceeded VerifiedAt={VerifiedAt}")]
public sealed record VerificationSucceeded(
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Claims,
    DateTimeOffset VerifiedAt,
    Uri? RedirectUri = null): OAuthFlowInput
{
    /// <inheritdoc/>
    public bool Equals(VerificationSucceeded? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return VerifiedAt == other.VerifiedAt
            && ReferenceEquals(Claims, other.Claims)
            && RedirectUri == other.RedirectUri;
    }

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Claims, VerifiedAt, RedirectUri);
}
