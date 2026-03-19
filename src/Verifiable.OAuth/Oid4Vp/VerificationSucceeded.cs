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
[DebuggerDisplay("VerificationSucceeded VerifiedAt={VerifiedAt}")]
public sealed record VerificationSucceeded(
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Claims,
    DateTimeOffset VerifiedAt): OAuthFlowInput
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

        return VerifiedAt == other.VerifiedAt &&
               ReferenceEquals(Claims, other.Claims);
    }

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Claims, VerifiedAt);
}