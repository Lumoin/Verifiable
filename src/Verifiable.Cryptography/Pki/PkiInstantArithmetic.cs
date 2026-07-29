using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Instant arithmetic that saturates instead of throwing, for the comparisons the validation algorithm of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> makes between an instant and an interval that both come out of
/// attacker-reachable DER.
/// </summary>
/// <remarks>
/// A DER <c>GeneralizedTime</c> reaches to the year 9999 and an
/// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see> <c>Accuracy</c>, or a
/// <c>nextUpdate</c> minus <c>thisUpdate</c> interval read off revocation data, can be tens of thousands of
/// years, so <see cref="DateTimeOffset"/> addition and subtraction can leave the representable range and throw.
/// Nothing in clause 5 defines an exception for that: a comparison is either satisfied or it is not, and an
/// operand that would leave the range is clamped to the end of the range it would leave, which preserves the
/// direction of every comparison these helpers serve. The result is expressed in UTC, which is what
/// <see cref="DateTimeOffset"/> comparison uses in any case.
/// </remarks>
internal static class PkiInstantArithmetic
{
    /// <summary>
    /// Adds an interval to an instant, clamping at the ends of the representable range rather than throwing.
    /// </summary>
    /// <param name="instant">The instant to add to.</param>
    /// <param name="interval">The interval to add; a negative interval subtracts.</param>
    /// <returns>The sum, or the end of the representable range it would have left.</returns>
    public static DateTimeOffset AddSaturating(DateTimeOffset instant, TimeSpan interval) =>
        FromUtcTicks(instant.UtcTicks, interval.Ticks);


    /// <summary>
    /// Subtracts an interval from an instant, clamping at the ends of the representable range rather than
    /// throwing.
    /// </summary>
    /// <param name="instant">The instant to subtract from.</param>
    /// <param name="interval">The interval to subtract; a negative interval adds.</param>
    /// <returns>The difference, or the end of the representable range it would have left.</returns>
    public static DateTimeOffset SubtractSaturating(DateTimeOffset instant, TimeSpan interval) =>
        FromUtcTicks(instant.UtcTicks, interval.Ticks == long.MinValue ? long.MaxValue : -interval.Ticks);


    /// <summary>
    /// Offsets an instant expressed in UTC ticks by a signed number of ticks, clamping at the ends of the
    /// representable range.
    /// </summary>
    /// <param name="utcTicks">The instant, as UTC ticks.</param>
    /// <param name="offsetTicks">The signed number of ticks to offset it by.</param>
    /// <returns>The offset instant, in UTC.</returns>
    private static DateTimeOffset FromUtcTicks(long utcTicks, long offsetTicks)
    {
        if(offsetTicks >= 0)
        {
            long headroom = DateTimeOffset.MaxValue.UtcTicks - utcTicks;

            return offsetTicks >= headroom
                ? DateTimeOffset.MaxValue
                : new DateTimeOffset(utcTicks + offsetTicks, TimeSpan.Zero);
        }

        long available = utcTicks - DateTimeOffset.MinValue.UtcTicks;

        return offsetTicks <= -available
            ? DateTimeOffset.MinValue
            : new DateTimeOffset(utcTicks + offsetTicks, TimeSpan.Zero);
    }
}
