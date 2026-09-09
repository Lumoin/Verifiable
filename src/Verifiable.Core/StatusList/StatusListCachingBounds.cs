using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A Relying Party's configured floor and ceiling for the <c>ttl</c>-driven refresh interval — Section
/// 11.5.
/// </summary>
/// <remarks>
/// <para>
/// "Clients SHOULD check that both values are within reasonable ranges before requesting new Status
/// List Tokens based on these values to prevent accidentally creating unreasonable amounts of requests
/// for a specific URL. Status Issuers could accidentally or maliciously use this mechanism to
/// effectively DDoS the contained URL of the Status Provider." / "Reasonable values for both claims
/// highly depend on the use-case requirements and clients should be configured with lower/upper bounds
/// for these values that fit their respective use-cases."
/// See <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-11.5">Token Status List, Section 11.5</see>.
/// </para>
/// <para>
/// <see cref="StatusListValidation.ShouldRefresh"/> clamps the token's <c>ttl</c> to
/// <c>[MinimumRefreshInterval, MaximumRefreshInterval]</c> before comparing it against the elapsed
/// time since resolution, so a <c>ttl</c> below the floor never drives requests faster than the floor
/// permits, and a <c>ttl</c> above the ceiling never pins a stale list past it. Section 13.7's guidance
/// for a Status List Token carrying no <c>ttl</c> at all — "Relying Party SHOULD check for updates
/// latest after the time of exp" — coincides with the unconditional step 4.c expiry check
/// <see cref="StatusListValidation.GetStatus"/> already performs; these bounds add no separate
/// no-<c>ttl</c> arm.
/// </para>
/// </remarks>
public sealed record StatusListCachingBounds
{
    /// <summary>The shortest interval a caller is willing to re-request a Status List Token at, regardless of a shorter <c>ttl</c>.</summary>
    public TimeSpan MinimumRefreshInterval { get; }

    /// <summary>The longest interval a caller will hold a cached Status List Token for, regardless of a longer <c>ttl</c>.</summary>
    public TimeSpan MaximumRefreshInterval { get; }

    /// <summary>
    /// Creates caching bounds.
    /// </summary>
    /// <param name="minimumRefreshInterval">The refresh-interval floor.</param>
    /// <param name="maximumRefreshInterval">The refresh-interval ceiling.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="minimumRefreshInterval"/> is not a positive duration, or when
    /// <paramref name="maximumRefreshInterval"/> is less than <paramref name="minimumRefreshInterval"/>.
    /// </exception>
    public StatusListCachingBounds(TimeSpan minimumRefreshInterval, TimeSpan maximumRefreshInterval)
    {
        if(minimumRefreshInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumRefreshInterval), minimumRefreshInterval, "The minimum refresh interval must be a positive duration.");
        }

        if(maximumRefreshInterval < minimumRefreshInterval)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumRefreshInterval), maximumRefreshInterval, "The maximum refresh interval must not be less than the minimum refresh interval.");
        }

        MinimumRefreshInterval = minimumRefreshInterval;
        MaximumRefreshInterval = maximumRefreshInterval;
    }
}
