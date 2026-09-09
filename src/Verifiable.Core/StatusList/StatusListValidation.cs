using System;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Provides validation logic for Status List Tokens and Referenced Tokens
/// as defined in Section 8.3 of the Token Status List specification.
/// </summary>
/// <remarks>
/// <para>
/// All methods accept <see cref="DateTimeOffset"/> parameters for time-dependent checks
/// rather than reading the clock internally. This keeps methods pure and testable.
/// Callers should use <c>TimeProvider.GetUtcNow()</c> for production code and
/// <c>FakeTimeProvider</c> for integration tests.
/// </para>
/// </remarks>
public static class StatusListValidation
{
    /// <summary>
    /// Retrieves the status of a Referenced Token from a Status List Token,
    /// performing the required validation checks from Section 8.3.
    /// </summary>
    /// <param name="token">The Status List Token containing the status data.</param>
    /// <param name="reference">The Status List reference from the Referenced Token.</param>
    /// <param name="currentTime">The current time for expiration and freshness checks.</param>
    /// <param name="freshnessPolicy">
    /// The caller's step 4.b freshness policy, or <see langword="null"/> to skip the check — today's
    /// unconditional behavior. See
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token Status List, Section 8.3</see>
    /// step 4.b: "If the Relying Party has local policies regarding the freshness of the Status List
    /// Token, it SHOULD check the issued at claim (iat or 6)."
    /// </param>
    /// <returns>The status value for the Referenced Token.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="token"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="StatusListValidationException">
    /// Thrown when any validation check fails — subject mismatch, a Status List Token issued further
    /// in the past than <paramref name="freshnessPolicy"/> allows, expiration, or out-of-bounds index.
    /// </exception>
    public static byte GetStatus(
        StatusListToken token,
        StatusListReference reference,
        DateTimeOffset currentTime,
        StatusListFreshnessPolicy? freshnessPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(token);

        //Step 4.a: The subject claim must match the URI in the Referenced Token.
        if(!string.Equals(token.Subject, reference.Uri, StringComparison.Ordinal))
        {
            throw new StatusListValidationException($"Subject mismatch: Status List Token subject '{token.Subject}' does not match reference URI '{reference.Uri}'.");
        }

        //Step 4.b: when the caller has a freshness policy, the token's iat must not be older than
        //its maximum age. A future-dated iat yields a negative age, which never exceeds a positive
        //MaximumAge, so it is never rejected here.
        if(freshnessPolicy is not null)
        {
            TimeSpan age = currentTime - token.IssuedAt;
            if(age > freshnessPolicy.MaximumAge)
            {
                throw new StatusListValidationException(
                    $"Status List Token issued at {token.IssuedAt} is older than the configured freshness policy's maximum age of {freshnessPolicy.MaximumAge}.");
            }
        }

        //Step 4.c: Check expiration if defined.
        if(token.ExpirationTime.HasValue && currentTime > token.ExpirationTime.Value)
        {
            throw new StatusListValidationException($"Status List Token has expired at {token.ExpirationTime.Value}.");
        }

        //Step 6: Retrieve the status value; reject if index is out of bounds.
        if(reference.Index >= token.StatusList.Capacity)
        {
            throw new StatusListValidationException($"Index {reference.Index} is out of bounds for Status List with capacity {token.StatusList.Capacity}.");
        }

        return token.StatusList.Get(reference.Index);
    }

    /// <summary>
    /// Checks whether a cached Status List Token should be refreshed based on
    /// the time-to-live claim and the time it was resolved.
    /// </summary>
    /// <param name="token">The Status List Token to check.</param>
    /// <param name="resolvedAt">The time the token was originally resolved.</param>
    /// <param name="currentTime">The current time.</param>
    /// <param name="cachingBounds">
    /// The caller's Section 11.5 refresh-interval floor and ceiling, or <see langword="null"/> to use
    /// the token's <c>ttl</c> unclamped — today's behavior. When supplied, the effective interval is
    /// <c>ttl</c> clamped to <c>[MinimumRefreshInterval, MaximumRefreshInterval]</c>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the token should be refreshed; otherwise, <see langword="false"/>.
    /// Returns <see langword="false"/> if no time-to-live is defined, or if the resolution instant plus
    /// the effective interval cannot be represented as a <see cref="DateTimeOffset"/> — no
    /// <paramref name="currentTime"/> this method could be called with reaches past
    /// <see cref="DateTimeOffset.MaxValue"/>, so such a token is never due for refresh on that basis.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="token"/> is <see langword="null"/>.
    /// </exception>
    public static bool ShouldRefresh(
        StatusListToken token,
        DateTimeOffset resolvedAt,
        DateTimeOffset currentTime,
        StatusListCachingBounds? cachingBounds = null)
    {
        ArgumentNullException.ThrowIfNull(token);

        if(!token.TimeToLive.HasValue)
        {
            return false;
        }

        double intervalSeconds = token.TimeToLive.Value;
        if(cachingBounds is not null)
        {
            intervalSeconds = Math.Clamp(
                intervalSeconds, cachingBounds.MinimumRefreshInterval.TotalSeconds, cachingBounds.MaximumRefreshInterval.TotalSeconds);
        }

        //A ttl (or a caching-bounds ceiling) near long.MaxValue seconds does not fit the range
        //DateTimeOffset.AddSeconds can add without overflowing; clamped first so the computation below
        //never throws for any ttl value the model accepts.
        intervalSeconds = Math.Min(intervalSeconds, TimeSpan.MaxValue.TotalSeconds);

        DateTimeOffset? refreshAt = TryAddSeconds(resolvedAt, intervalSeconds);

        return refreshAt.HasValue && refreshAt.Value < currentTime;
    }


    /// <summary>
    /// Adds <paramref name="seconds"/> to <paramref name="instant"/>, reporting <see langword="null"/>
    /// instead of throwing when the result would fall outside the representable
    /// <see cref="DateTimeOffset"/> range.
    /// </summary>
    /// <param name="instant">The instant to add to.</param>
    /// <param name="seconds">The number of seconds to add.</param>
    /// <returns>The resulting instant, or <see langword="null"/> when it is not representable.</returns>
    private static DateTimeOffset? TryAddSeconds(DateTimeOffset instant, double seconds)
    {
        try
        {
            return instant.AddSeconds(seconds);
        }
        catch(ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
