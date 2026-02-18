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
    /// <param name="currentTime">The current time for expiration checks.</param>
    /// <returns>The status value for the Referenced Token.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="token"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="StatusListValidationException">
    /// Thrown when any validation check fails, such as subject mismatch,
    /// expiration, or out-of-bounds index.
    /// </exception>
    public static byte GetStatus(StatusListToken token, StatusListReference reference, DateTimeOffset currentTime)
    {
        ArgumentNullException.ThrowIfNull(token);

        //Step 4.1: The subject claim must match the URI in the Referenced Token.
        if(!string.Equals(token.Subject, reference.Uri, StringComparison.Ordinal))
        {
            throw new StatusListValidationException($"Subject mismatch: Status List Token subject '{token.Subject}' does not match reference URI '{reference.Uri}'.");
        }

        //Step 4.3: Check expiration if defined.
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
    /// <returns>
    /// <see langword="true"/> if the token should be refreshed; otherwise, <see langword="false"/>.
    /// Returns <see langword="false"/> if no time-to-live is defined.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="token"/> is <see langword="null"/>.
    /// </exception>
    public static bool ShouldRefresh(StatusListToken token, DateTimeOffset resolvedAt, DateTimeOffset currentTime)
    {
        ArgumentNullException.ThrowIfNull(token);

        if(!token.TimeToLive.HasValue)
        {
            return false;
        }

        return resolvedAt.AddSeconds(token.TimeToLive.Value) < currentTime;
    }
}