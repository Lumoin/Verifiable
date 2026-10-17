namespace Verifiable.JCose;

/// <summary>
/// The one reading of a JWT NumericDate every reader of a claims set shares: <c>exp</c>, <c>nbf</c> and <c>iat</c> (RFC 7519
/// sections 4.1.4 to 4.1.6) and every other claim of that type, <c>auth_time</c> among them. RFC 7519 section 2 defines the type:
/// "A JSON numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date/time,
/// ignoring leap seconds", in which "non-integer values can be represented".
/// </summary>
/// <remarks>
/// <para>
/// A fraction names its own instant, kept to the 100-nanosecond tick a <see cref="DateTimeOffset"/> holds, so a reader judges
/// the instant its issuer wrote under the reader's own tolerance: a date a fraction of a second past a bound is past it, and no
/// date is moved to a whole second before it is judged. Only a remainder finer than a tick is taken, on the side that never
/// widens the window the claim bounds: up for <c>iat</c> and <c>nbf</c>, which bound how early a token is accepted, down for
/// <c>exp</c> and every other claim.
/// </para>
/// <para>
/// A value that is no JSON number - a string of digits among them - is no NumericDate, and neither is a count naming an instant
/// no <see cref="DateTimeOffset"/> represents: both read as none, never as an exception. The JSON layers a claims set is parsed
/// with box a number as one of the .NET integer types, as a <see cref="decimal"/> (a fraction, or a count too large for a
/// <see cref="long"/>), or as a <see cref="double"/> or <see cref="float"/>; each is read here.
/// </para>
/// </remarks>
public static class JwtNumericDates
{
    /// <summary>The earliest whole second a <see cref="DateTimeOffset"/> represents, 0001-01-01T00:00:00Z, as seconds since the epoch.</summary>
    private const long EarliestRepresentableSeconds = -62_135_596_800;

    /// <summary>The latest whole second a <see cref="DateTimeOffset"/> represents, 9999-12-31T23:59:59Z, as seconds since the epoch.</summary>
    private const long LatestRepresentableSeconds = 253_402_300_799;

    /// <summary>The earliest instant a <see cref="DateTimeOffset"/> represents, as ticks since the epoch.</summary>
    private const long EarliestRepresentableTicks = EarliestRepresentableSeconds * TimeSpan.TicksPerSecond;

    /// <summary>The latest instant a <see cref="DateTimeOffset"/> represents, as ticks since the epoch: the last tick of its latest whole second.</summary>
    private const long LatestRepresentableTicks = ((LatestRepresentableSeconds + 1) * TimeSpan.TicksPerSecond) - 1;


    /// <summary>
    /// The instant a NumericDate claim names, its fraction of a second kept to the tick, and a remainder finer than a tick taken
    /// on the side that never widens the window the claim bounds - up for <c>iat</c> and <c>nbf</c>, down for <c>exp</c> and every
    /// other claim - or <see langword="null"/> when the value is no JSON number or names an instant no
    /// <see cref="DateTimeOffset"/> represents.
    /// </summary>
    /// <param name="claimName">The claim the value was read from, which decides the side.</param>
    /// <param name="value">The claim's value as the claims set holds it.</param>
    /// <returns>The instant, or <see langword="null"/>.</returns>
    public static DateTimeOffset? InstantOf(string claimName, object? value)
    {
        ArgumentNullException.ThrowIfNull(claimName);

        var roundsUp = WellKnownJwtClaimNames.IsNbf(claimName) || WellKnownJwtClaimNames.IsIat(claimName);
        var ticks = value switch
        {
            long seconds => TicksOfWholeSeconds(seconds),
            int seconds => TicksOfWholeSeconds(seconds),
            short seconds => TicksOfWholeSeconds(seconds),
            sbyte seconds => TicksOfWholeSeconds(seconds),
            byte seconds => TicksOfWholeSeconds(seconds),
            ushort seconds => TicksOfWholeSeconds(seconds),
            uint seconds => TicksOfWholeSeconds(seconds),
            ulong seconds when seconds <= long.MaxValue => TicksOfWholeSeconds((long)seconds),
            decimal seconds => TicksOf(seconds, roundsUp),
            double seconds => TicksOf(seconds, roundsUp),
            float seconds => TicksOf(seconds, roundsUp),
            _ => null
        };

        return ticks is long sinceEpoch && sinceEpoch is >= EarliestRepresentableTicks and <= LatestRepresentableTicks
            ? new DateTimeOffset(DateTimeOffset.UnixEpoch.Ticks + sinceEpoch, TimeSpan.Zero)
            : null;
    }


    /// <summary>The ticks since the epoch a whole count of seconds names, or <see langword="null"/> outside the representable range.</summary>
    /// <param name="seconds">The count.</param>
    /// <returns>The ticks, or <see langword="null"/>.</returns>
    private static long? TicksOfWholeSeconds(long seconds) =>
        seconds is >= EarliestRepresentableSeconds and <= LatestRepresentableSeconds ? seconds * TimeSpan.TicksPerSecond : null;


    /// <summary>
    /// The ticks since the epoch a decimal count of seconds names, exactly where it falls on a tick and on the side given where it
    /// falls between two, or <see langword="null"/> outside the representable range.
    /// </summary>
    /// <param name="seconds">The count.</param>
    /// <param name="roundsUp">Whether a remainder finer than a tick is taken up rather than down.</param>
    /// <returns>The ticks, or <see langword="null"/>.</returns>
    private static long? TicksOf(decimal seconds, bool roundsUp)
    {
        if(seconds is < EarliestRepresentableSeconds or > LatestRepresentableSeconds + 1)
        {
            return null;
        }

        var ticks = seconds * TimeSpan.TicksPerSecond;

        return (long)(roundsUp ? decimal.Ceiling(ticks) : decimal.Floor(ticks));
    }


    /// <summary>
    /// The ticks since the epoch a floating count of seconds names, its whole seconds kept exactly and its fraction to the tick on
    /// the side given, or <see langword="null"/> for no finite count within the representable range.
    /// </summary>
    /// <param name="seconds">The count.</param>
    /// <param name="roundsUp">Whether a remainder finer than a tick is taken up rather than down.</param>
    /// <returns>The ticks, or <see langword="null"/>.</returns>
    private static long? TicksOf(double seconds, bool roundsUp)
    {
        if(!double.IsFinite(seconds) || seconds is < EarliestRepresentableSeconds or > LatestRepresentableSeconds + 1)
        {
            return null;
        }

        //A double holds every whole second of the range exactly, and the count less its whole seconds is exact too, so only the
        //fraction's ticks are rounded.
        var whole = Math.Floor(seconds);
        var fractionTicks = (seconds - whole) * TimeSpan.TicksPerSecond;

        return ((long)whole * TimeSpan.TicksPerSecond) + (long)(roundsUp ? Math.Ceiling(fractionTicks) : Math.Floor(fractionTicks));
    }
}
