using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A Relying Party's local policy for how old a Status List Token's <c>iat</c> claim may be while
/// still being considered fresh — Section 8.3 step 4.b.
/// </summary>
/// <remarks>
/// <para>
/// "If the Relying Party has local policies regarding the freshness of the Status List Token, it
/// SHOULD check the issued at claim (iat or 6)."
/// See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token Status List, Section 8.3</see>.
/// </para>
/// <para>
/// Supplying no policy — the default when <see cref="StatusListValidation.GetStatus"/> or
/// <see cref="CredentialStatusGate.CheckAsync"/> is called without one — reproduces today's
/// unconditional behavior: step 4.b runs only when a policy is present. A Status List Token whose
/// <c>iat</c> lies in the future relative to the check's <c>currentTime</c> is never rejected by this
/// policy: the computed age is negative, and a negative age never exceeds <see cref="MaximumAge"/>.
/// Only a token issued further in the past than <see cref="MaximumAge"/> allows fails the check.
/// </para>
/// </remarks>
public sealed record StatusListFreshnessPolicy
{
    /// <summary>
    /// The maximum age — <c>currentTime - iat</c> — a Status List Token may carry and still be
    /// considered fresh.
    /// </summary>
    public TimeSpan MaximumAge { get; }

    /// <summary>
    /// Creates a freshness policy.
    /// </summary>
    /// <param name="maximumAge">The maximum age a Status List Token's <c>iat</c> may carry.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="maximumAge"/> is not a positive duration.
    /// </exception>
    public StatusListFreshnessPolicy(TimeSpan maximumAge)
    {
        if(maximumAge <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumAge), maximumAge, "The maximum age must be a positive duration.");
        }

        MaximumAge = maximumAge;
    }
}
