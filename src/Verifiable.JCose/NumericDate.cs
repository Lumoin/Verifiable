using System.Globalization;
using System.Numerics;

namespace Verifiable.JCose;

/// <summary>
/// A NumericDate exactly as written, and the one reading of the type every reader of a claims set shares: <c>exp</c>,
/// <c>nbf</c> and <c>iat</c> (RFC 7519 sections 4.1.4 to 4.1.6) and every other claim of that type, <c>auth_time</c> among
/// them. RFC 7519 section 2 defines the type: "A JSON numeric value representing the number of seconds from
/// 1970-01-01T00:00:00Z UTC until the specified UTC date/time, ignoring leap seconds", in which "non-integer values can be
/// represented".
/// </summary>
/// <remarks>
/// <para>
/// The date keeps every digit its issuer wrote (<see cref="Seconds"/>), and each comparison judges that value against the
/// bound it enforces, exactly: a date before an instant, after it, more than a span after another date. No remainder finer
/// than the 100-nanosecond tick a <see cref="DateTimeOffset"/> holds is ever moved onto a bound, so a date a fraction of a tick
/// past a bound is past it, whichever bound the comparison keeps, and no comparison's direction is chosen by a claim's name.
/// The arithmetic a comparison does - a tolerance added to the present, a span added to a date - is done wide enough that no
/// date the clock represents and no span overflows it.
/// </para>
/// <para>
/// A value that is no JSON number - a string of digits among them - is no NumericDate, and neither is a count naming an instant
/// before <see cref="DateTimeOffset.MinValue"/> or after <see cref="DateTimeOffset.MaxValue"/>: both read as none, never as an
/// exception.
/// </para>
/// </remarks>
public sealed record NumericDate
{
    /// <summary>The power of ten that takes seconds to ticks.</summary>
    private const int TickDigits = 7;

    /// <summary>The most digits the whole ticks of a date the clock represents carry: ten to this power ticks lies past the clock.</summary>
    private const int MostWholeTickDigits = 19;

    /// <summary>The ticks of the earliest instant the clock represents, counted from the epoch.</summary>
    private static Int128 EarliestTicksSinceEpoch { get; } = (Int128)DateTimeOffset.MinValue.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks;

    /// <summary>The ticks of the latest instant the clock represents, counted from the epoch.</summary>
    private static Int128 LatestTicksSinceEpoch { get; } = (Int128)DateTimeOffset.MaxValue.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks;


    /// <summary>Creates the date from its exact count of seconds and the tick it falls at or after.</summary>
    /// <param name="seconds">The exact count of seconds since the epoch.</param>
    /// <param name="atOrBefore">The last tick at or before the date.</param>
    /// <param name="remainder">The exact part of a tick by which the date lies past <paramref name="atOrBefore"/>.</param>
    private NumericDate(DecimalNumber seconds, DateTimeOffset atOrBefore, TickFraction remainder)
    {
        Seconds = seconds;
        AtOrBefore = atOrBefore;
        Remainder = remainder;
        FallsOnTick = remainder.IsZero;
        AtOrAfter = FallsOnTick ? atOrBefore : atOrBefore.AddTicks(1);
    }


    /// <summary>The count of seconds from 1970-01-01T00:00:00Z the date names, exactly as written.</summary>
    public DecimalNumber Seconds { get; }

    /// <summary>The last instant a <see cref="DateTimeOffset"/> holds at or before the date: the date itself when it falls on a tick.</summary>
    public DateTimeOffset AtOrBefore { get; }

    /// <summary>The first instant a <see cref="DateTimeOffset"/> holds at or after the date: the date itself when it falls on a tick.</summary>
    public DateTimeOffset AtOrAfter { get; }

    /// <summary>Whether the date falls exactly on a tick, so <see cref="AtOrBefore"/> and <see cref="AtOrAfter"/> both are the date.</summary>
    public bool FallsOnTick { get; }

    /// <summary>The exact part of a tick by which the date lies past <see cref="AtOrBefore"/>, from zero up to but not including one.</summary>
    private TickFraction Remainder { get; }


    /// <summary>
    /// The date a claim's value names as a claims set holds it, or <see langword="null"/> when the value is no JSON number or names
    /// an instant no <see cref="DateTimeOffset"/> represents. The JSON layers a claims set is parsed with box a number as one of
    /// the .NET integer types, as a <see cref="decimal"/>, as a <see cref="double"/> or <see cref="float"/>, or, where neither an
    /// integer nor a decimal holds it exactly, as the <see cref="DecimalNumber"/> it is; each is read exactly as it is held, and a
    /// date already read is itself.
    /// </summary>
    /// <param name="value">The claim's value.</param>
    /// <returns>The date, or <see langword="null"/>.</returns>
    public static NumericDate? Of(object? value)
    {
        var seconds = value is NumericDate date ? date.Seconds : DecimalNumber.Of(value);

        return seconds is null ? null : FromSeconds(seconds);
    }


    /// <summary>
    /// The date one JSON number token names (RFC 8259 section 6), every digit kept, or <see langword="null"/> when the bytes are
    /// not exactly one JSON number or name an instant no <see cref="DateTimeOffset"/> represents.
    /// </summary>
    /// <param name="utf8Number">The token's UTF-8 bytes.</param>
    /// <returns>The date, or <see langword="null"/>.</returns>
    public static NumericDate? FromJsonNumber(ReadOnlySpan<byte> utf8Number) =>
        DecimalNumber.FromJsonNumber(utf8Number) is DecimalNumber seconds ? FromSeconds(seconds) : null;


    /// <summary>
    /// The date an exact count of seconds since the epoch names, or <see langword="null"/> when it names an instant before
    /// <see cref="DateTimeOffset.MinValue"/> or after <see cref="DateTimeOffset.MaxValue"/>.
    /// </summary>
    /// <param name="seconds">The count of seconds.</param>
    /// <returns>The date, or <see langword="null"/>.</returns>
    public static NumericDate? FromSeconds(DecimalNumber seconds)
    {
        ArgumentNullException.ThrowIfNull(seconds);

        if(seconds.IsZero)
        {
            return new NumericDate(seconds, DateTimeOffset.UnixEpoch, TickFraction.None);
        }

        var tickPosition = seconds.PointPosition + TickDigits;

        if(tickPosition > MostWholeTickDigits)
        {
            return null;
        }

        //The digits before the tick position are whole ticks and the rest a part of a tick; a date below one tick has no whole
        //ticks, and its part of a tick begins with as many zeros as its point lies below the tick.
        var digits = seconds.SignificantDigits;
        var position = tickPosition <= 0 ? 0 : (int)tickPosition;
        var wholeDigits = position >= digits.Length ? string.Concat(digits, new string('0', position - digits.Length)) : digits[..position];
        var wholeTicks = position == 0 ? Int128.Zero : Int128.Parse(wholeDigits, NumberStyles.None, CultureInfo.InvariantCulture);
        var beyondWholeTicks = position == 0
            ? TickFraction.Of(-tickPosition, digits)
            : TickFraction.Of(BigInteger.Zero, position >= digits.Length ? string.Empty : digits[position..]);

        var ticksSinceEpoch = seconds.IsNegative ? -wholeTicks : wholeTicks;
        var remainder = beyondWholeTicks;

        if(seconds.IsNegative && !beyondWholeTicks.IsZero)
        {
            ticksSinceEpoch -= 1;
            remainder = beyondWholeTicks.Complement();
        }

        if(ticksSinceEpoch < EarliestTicksSinceEpoch
            || ticksSinceEpoch > LatestTicksSinceEpoch
            || (ticksSinceEpoch == LatestTicksSinceEpoch && !remainder.IsZero))
        {
            return null;
        }

        return new NumericDate(seconds, DateTimeOffset.UnixEpoch.AddTicks((long)ticksSinceEpoch), remainder);
    }


    /// <summary>The date that is the instant given, to its tick.</summary>
    /// <param name="instant">The instant.</param>
    /// <returns>The date.</returns>
    public static NumericDate FromInstant(DateTimeOffset instant) =>
        FromSeconds(DecimalNumber.Scaled(instant.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks, TickDigits))!;


    /// <summary>
    /// The date that is the instant given, to its tick: every instant a <see cref="DateTimeOffset"/> holds is a NumericDate, so
    /// the conversion keeps every digit and never fails.
    /// </summary>
    /// <param name="instant">The instant.</param>
    public static implicit operator NumericDate(DateTimeOffset instant) => FromInstant(instant);


    /// <summary>
    /// The whole second at or before an instant, as a date: the precision an issuer chooses when it writes its dates as the
    /// integers most readers exchange (RFC 7519 Section 2 admits a fraction, and a received fraction is never moved to a whole
    /// second; this is an issuer's choice for the dates it writes).
    /// </summary>
    /// <param name="instant">The instant.</param>
    /// <returns>The date of the whole second at or before it.</returns>
    public static NumericDate WholeSecondAtOrBefore(DateTimeOffset instant) => FromUnixTimeSeconds(instant.ToUnixTimeSeconds());


    /// <summary>The date a whole count of seconds since the epoch names, as <see cref="DateTimeOffset.FromUnixTimeSeconds"/> reads it.</summary>
    /// <param name="seconds">The count of seconds.</param>
    /// <returns>The date.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The count names an instant no <see cref="DateTimeOffset"/> represents.</exception>
    public static NumericDate FromUnixTimeSeconds(long seconds) => FromInstant(DateTimeOffset.FromUnixTimeSeconds(seconds));


    /// <summary>Compares this date with another exactly, every digit of each kept.</summary>
    /// <param name="other">The other date.</param>
    /// <returns>A negative value when this date is the earlier, zero when they are the same date and a positive value when it is the later.</returns>
    public int CompareTo(NumericDate other)
    {
        ArgumentNullException.ThrowIfNull(other);

        return Seconds.CompareTo(other.Seconds);
    }


    /// <summary>Compares this date with an instant exactly.</summary>
    /// <param name="instant">The instant.</param>
    /// <returns>A negative value when the date lies before the instant, zero when it is the instant and a positive value when it lies after it.</returns>
    public int CompareTo(DateTimeOffset instant) => CompareToTicks(instant.UtcTicks);


    /// <summary>
    /// Compares this date exactly with the instant a span after the instant given - the present extended by a tolerance, say -
    /// without forming that instant, so no span and no instant the clock represents overflows the comparison.
    /// </summary>
    /// <param name="instant">The instant.</param>
    /// <param name="span">The span after it, which may be negative.</param>
    /// <returns>A negative value when the date lies before the instant a span later, zero when it is that instant and a positive value when it lies after it.</returns>
    public int CompareToLaterBy(DateTimeOffset instant, TimeSpan span) => CompareToTicks((Int128)instant.UtcTicks + span.Ticks);


    /// <summary>
    /// Compares this date exactly with the instant a span before the instant given - the present reduced by a tolerance, say -
    /// without forming that instant, so no span and no instant the clock represents overflows the comparison.
    /// </summary>
    /// <param name="instant">The instant.</param>
    /// <param name="span">The span before it, which may be negative.</param>
    /// <returns>A negative value when the date lies before the instant a span earlier, zero when it is that instant and a positive value when it lies after it.</returns>
    public int CompareToEarlierBy(DateTimeOffset instant, TimeSpan span) => CompareToTicks((Int128)instant.UtcTicks - span.Ticks);


    /// <summary>
    /// The first instant a <see cref="DateTimeOffset"/> holds at or after this date extended by a span - the end of a window a
    /// record of the date is kept for, say - or the clock's own last or first instant where that lies past either end of it, so
    /// no span and no date overflows the instant formed.
    /// </summary>
    /// <param name="span">The span after the date, which may be negative.</param>
    /// <returns>The instant.</returns>
    public DateTimeOffset AtOrAfterLaterBy(TimeSpan span)
    {
        var ticks = (Int128)AtOrAfter.UtcTicks + span.Ticks;

        return ticks > DateTimeOffset.MaxValue.UtcTicks ? DateTimeOffset.MaxValue
            : ticks < DateTimeOffset.MinValue.UtcTicks ? DateTimeOffset.MinValue
            : new DateTimeOffset((long)ticks, TimeSpan.Zero);
    }


    /// <summary>
    /// Whether this date lies more than a span after another, exactly: the interval from <paramref name="start"/> to this date
    /// exceeds <paramref name="span"/> by any amount, however small, and is within it at exactly the span.
    /// </summary>
    /// <param name="start">The date the interval starts at.</param>
    /// <param name="span">The span.</param>
    /// <returns><see langword="true"/> when the interval is longer than the span.</returns>
    public bool IsMoreThanAfter(NumericDate start, TimeSpan span)
    {
        ArgumentNullException.ThrowIfNull(start);

        //The interval is the whole ticks between the two dates plus the difference of their parts of a tick, which lies strictly
        //between minus one tick and one tick: the whole ticks decide unless they equal the span, and then the parts do.
        var wholeTicks = (Int128)AtOrBefore.UtcTicks - start.AtOrBefore.UtcTicks;

        if(wholeTicks != span.Ticks)
        {
            return wholeTicks > span.Ticks;
        }

        return Remainder.CompareTo(start.Remainder) > 0;
    }


    /// <summary>
    /// The value a claims set holds this date as, boxed as the library's JSON layer boxes a number it reads
    /// (<see cref="DecimalNumber.ToClaimValue"/>): a <see cref="long"/> for a whole second, so a date issued at a whole second
    /// is written as the integer it always was.
    /// </summary>
    /// <returns>The boxed value.</returns>
    public object ToClaimValue() => Seconds.ToClaimValue();


    /// <summary>The date as one JSON number token naming it exactly (RFC 8259 section 6).</summary>
    /// <returns>The JSON number text of <see cref="Seconds"/>.</returns>
    public override string ToString() => Seconds.ToString();


    /// <summary>Compares this date exactly with the instant a count of ticks names.</summary>
    /// <param name="ticks">The instant's ticks since 0001-01-01T00:00:00Z, wide enough for any tolerance added to them.</param>
    /// <returns>A negative value when the date lies before the instant, zero when it is the instant and a positive value when it lies after it.</returns>
    private int CompareToTicks(Int128 ticks)
    {
        var atOrBefore = (Int128)AtOrBefore.UtcTicks;

        if(atOrBefore != ticks)
        {
            return atOrBefore < ticks ? -1 : 1;
        }

        return FallsOnTick ? 0 : 1;
    }


    /// <summary>
    /// An exact fraction of a tick from zero up to but not including one, as its decimal digits after the point: a run of one
    /// repeated digit, zero or nine, then a finite tail, then zeros without end. A date written with an exponent far below a tick
    /// is the run, never a string of that length.
    /// </summary>
    private sealed record TickFraction
    {
        /// <summary>The digit nine.</summary>
        private const int Nine = 9;

        /// <summary>The number ten, which the last digit of a complement is taken from.</summary>
        private const int Ten = 10;

        /// <summary>The fraction zero.</summary>
        public static TickFraction None { get; } = new(0, BigInteger.Zero, string.Empty);


        /// <summary>Creates the fraction from its run and its tail.</summary>
        /// <param name="runDigit">The digit the run repeats.</param>
        /// <param name="runLength">How many digits the run is.</param>
        /// <param name="tail">The digits after the run, the last of them not a zero.</param>
        private TickFraction(int runDigit, BigInteger runLength, string tail)
        {
            RunDigit = runDigit;
            RunLength = runLength;
            Tail = tail;
        }


        /// <summary>The digit the run repeats: zero, or nine for the part a date before the epoch lies past its tick.</summary>
        public int RunDigit { get; }

        /// <summary>How many digits the run is.</summary>
        public BigInteger RunLength { get; }

        /// <summary>The digits after the run, the last of them not a zero; every digit after them is zero.</summary>
        public string Tail { get; }

        /// <summary>Whether the fraction is zero.</summary>
        public bool IsZero => Tail.Length == 0 && (RunDigit == 0 || RunLength.IsZero);


        /// <summary>The fraction whose digits after the point are a run of zeros and then the digits given.</summary>
        /// <param name="leadingZeros">How many zeros come first.</param>
        /// <param name="digits">The digits after them, the last of them not a zero when there are any.</param>
        /// <returns>The fraction.</returns>
        public static TickFraction Of(BigInteger leadingZeros, string digits)
        {
            var zeros = 0;

            while(zeros < digits.Length && digits[zeros] == '0')
            {
                zeros++;
            }

            return zeros == digits.Length ? None : new TickFraction(0, leadingZeros + zeros, digits[zeros..]);
        }


        /// <summary>
        /// One less this fraction, for a fraction of zeros then a tail that is not zero: every digit becomes nine less itself and
        /// the last ten less itself, so the run of zeros becomes a run of nines.
        /// </summary>
        /// <returns>The complement.</returns>
        public TickFraction Complement()
        {
            var complemented = new char[Tail.Length];

            for(var index = 0; index < Tail.Length; index++)
            {
                var digit = Tail[index] - '0';
                complemented[index] = (char)('0' + (index == Tail.Length - 1 ? Ten - digit : Nine - digit));
            }

            return new TickFraction(Nine, RunLength, new string(complemented));
        }


        /// <summary>Compares this fraction with another exactly, digit by digit, a run of either passed over at once.</summary>
        /// <param name="other">The other fraction.</param>
        /// <returns>A negative value when this fraction is the smaller, zero when they are equal and a positive value when it is the larger.</returns>
        public int CompareTo(TickFraction other)
        {
            var position = BigInteger.Zero;

            while(true)
            {
                var run = ConstantDigitsAt(position);
                var otherRun = other.ConstantDigitsAt(position);

                if(run is not null && otherRun is not null)
                {
                    if(run.Digit != otherRun.Digit)
                    {
                        return run.Digit.CompareTo(otherRun.Digit);
                    }

                    if(run.End is not BigInteger end)
                    {
                        if(otherRun.End is not BigInteger otherEnd)
                        {
                            return 0;
                        }

                        position = otherEnd;
                    }
                    else
                    {
                        position = otherRun.End is BigInteger otherEnd ? BigInteger.Min(end, otherEnd) : end;
                    }

                    continue;
                }

                var comparison = DigitAt(position).CompareTo(other.DigitAt(position));

                if(comparison != 0)
                {
                    return comparison;
                }

                position += 1;
            }
        }


        /// <summary>The digit at a position after the point, counted from zero.</summary>
        /// <param name="position">The position.</param>
        /// <returns>The digit.</returns>
        private int DigitAt(BigInteger position)
        {
            if(position < RunLength)
            {
                return RunDigit;
            }

            var index = position - RunLength;

            return index < Tail.Length ? Tail[(int)index] - '0' : 0;
        }


        /// <summary>
        /// The run of one digit a position lies in - the run itself or the zeros after the tail - or <see langword="null"/> when it
        /// lies in the tail.
        /// </summary>
        /// <param name="position">The position.</param>
        /// <returns>The run, or <see langword="null"/>.</returns>
        private ConstantDigits? ConstantDigitsAt(BigInteger position)
        {
            if(position < RunLength)
            {
                return new ConstantDigits(RunDigit, RunLength);
            }

            return position - RunLength >= Tail.Length ? new ConstantDigits(0, null) : null;
        }
    }


    /// <summary>A run of one digit in a fraction's digits.</summary>
    /// <param name="Digit">The digit the run repeats.</param>
    /// <param name="End">The position after the run, or <see langword="null"/> for a run without end.</param>
    private sealed record ConstantDigits(int Digit, BigInteger? End);
}
