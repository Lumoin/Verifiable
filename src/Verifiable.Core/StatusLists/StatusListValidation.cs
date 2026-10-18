using System.Globalization;
using System.Numerics;
using Verifiable.JCose;

namespace Verifiable.Core.StatusLists;

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
            //Older than the maximum age is an iat before the present reduced by it, judged against the date as written.
            if(token.IssuedAt.CompareToEarlierBy(currentTime, freshnessPolicy.MaximumAge) < 0)
            {
                throw new StatusListValidationException(
                    $"Status List Token issued at {token.IssuedAt} is older than the configured freshness policy's maximum age of {freshnessPolicy.MaximumAge}.");
            }
        }

        //Step 4.c: Check expiration if defined. The token is considered expired at its exp (Section 5.1: "the time at which
        //the Status List Token is considered expired"), so the present must lie before it.
        if(token.ExpirationTime is not null && token.ExpirationTime.CompareTo(currentTime) <= 0)
        {
            throw new StatusListValidationException($"Status List Token has expired at {token.ExpirationTime}.");
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

        if(token.TimeToLive is null)
        {
            return false;
        }

        var interval = CacheIntervalOf(token.TimeToLive);
        if(cachingBounds is not null)
        {
            interval = TimeSpan.FromTicks(Math.Clamp(
                interval.Ticks, cachingBounds.MinimumRefreshInterval.Ticks, cachingBounds.MaximumRefreshInterval.Ticks));
        }

        //The token is due once more than the interval has passed since it was resolved. The present is a whole tick, so more than
        //a ttl exactly as written has passed exactly when more than its whole ticks have.
        return currentTime - resolvedAt > interval;
    }


    /// <summary>
    /// The longest interval a positive <c>ttl</c> lets a token be cached for, to the whole tick at or below it: no part of a tick
    /// past a whole one lengthens a cache, and a <c>ttl</c> longer than any <see cref="TimeSpan"/> is the longest there is, which
    /// no present reaches past a resolution.
    /// </summary>
    /// <param name="timeToLive">The <c>ttl</c> in seconds, positive.</param>
    /// <returns>The interval.</returns>
    private static TimeSpan CacheIntervalOf(DecimalNumber timeToLive)
    {
        const int TickDigits = 7;
        const int MostTimeSpanTickDigits = 19;

        var tickPosition = timeToLive.PointPosition + TickDigits;

        if(tickPosition > MostTimeSpanTickDigits)
        {
            return TimeSpan.MaxValue;
        }

        if(tickPosition <= 0)
        {
            return TimeSpan.Zero;
        }

        var digits = timeToLive.SignificantDigits;
        var position = (int)tickPosition;
        var wholeDigits = position >= digits.Length ? string.Concat(digits, new string('0', position - digits.Length)) : digits[..position];
        var ticks = BigInteger.Parse(wholeDigits, NumberStyles.None, CultureInfo.InvariantCulture);

        return ticks > TimeSpan.MaxValue.Ticks ? TimeSpan.MaxValue : TimeSpan.FromTicks((long)ticks);
    }
}
