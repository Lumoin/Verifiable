using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// A strictly-parsed <c>xsd:dateTime</c> lexical value — <c>SigningTime</c>'s own content type (clause 5.2.1)
/// — per
/// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2: Datatypes</see>
/// section 3.2.7.1's lexical grammar: <c>'-'? yyyy '-' mm '-' dd 'T' hh ':' mm ':' ss ('.' s+)? (zzzzzz)?</c>.
/// Every field the grammar defines is retained exactly as parsed — sign, year, month, day, hour, minute,
/// second, the fractional-second digit run, and the timezone exactly as written (a literal <c>Z</c> kept
/// distinct from an explicit <c>+00:00</c>/<c>-00:00</c>, per section 3.2.7.3's note that the three forms are
/// value-equivalent but only <c>Z</c> is canonical) — no instant, epoch or <see cref="DateTimeOffset"/> is ever
/// computed: this is a lexical parse of the written value, not a clock read or a timezone conversion.
/// </summary>
/// <remarks>
/// <para>
/// Parsing is strict, with no leniency beyond the grammar itself: no surrounding or embedded whitespace is
/// tolerated anywhere in the value (section 3.2.7.1 defines a single fixed-shape production, not a
/// whitespace-tolerant one), the whole-seconds field is never optional, and every numeral is exact-width per
/// the grammar (two digits for month/day/hour/minute/second/timezone-hour/timezone-minute; four-or-more for
/// the year, with leading zeros prohibited once a fifth digit is present).
/// </para>
/// <para>
/// Section 3.2.7's own note above the lexical-representation clause states plainly that the year numeral
/// <c>'0000'</c> "is prohibited" and that <c>'-0001'</c> names the year 1 Before Common Era — this version of
/// the datatype has no year zero. <see cref="TryParse"/> refuses a year magnitude of zero regardless of sign.
/// Section 3.2.7.1's hour rule — <c>'24'</c> is permitted only when the minutes and seconds represented are
/// zero, denoting the first instant of the following day — is enforced exactly, and this parser additionally
/// refuses a fractional-second component alongside an hour of <c>24</c>: the REC never contemplates the two
/// together, and combining them (e.g. <c>24:00:00.5</c>) would name an instant past the very day boundary the
/// <c>24</c> form exists to denote, so this reader treats the combination as outside the grammar rather than
/// silently accepting or guessing an interpretation.
/// </para>
/// <para>
/// Every deviation from the lexical grammar — a missing field, a wrong separator, embedded whitespace, an
/// out-of-range field, the disallowed year <c>0000</c>, a fractional-second run with no digits, or a timezone
/// whose hour magnitude exceeds 14 or whose minute is non-zero at hour magnitude 14 (section 3.2.7.3) — is
/// reported identically: <see cref="TryParse"/> returns <see langword="false"/>, and a caller wraps that into
/// <see cref="XAdESReadFailure.InvalidDateTimeLexicalForm"/>. Unlike the XAdES structural grammar's many
/// distinctly-named refusal shapes, <c>xsd:dateTime</c> is one closed lexical production with no sub-shape a
/// caller could usefully branch on beyond "matched" or "did not."
/// </para>
/// </remarks>
public readonly struct XAdESDateTime: IEquatable<XAdESDateTime>
{
    /// <summary>The bound this parser enforces on the year numeral's digit count, comfortably inside the
    /// range a <see cref="long"/> accumulation never overflows for, and a hardening bound against a
    /// pathologically long digit run.</summary>
    private const int MaximumYearDigits = 15;

    /// <summary>The bound this parser enforces on the fractional-second digit run's length — the largest
    /// count a <see cref="long"/> accumulation never overflows for, and a hardening bound against a
    /// pathologically long fractional-second run.</summary>
    private const int MaximumFractionalSecondDigits = 18;

    /// <summary>Whether the year numeral carried a leading <c>'-'</c> (a year Before Common Era).</summary>
    public bool IsNegativeYear { get; }

    /// <summary>The year numeral's magnitude; always at least 1 — a magnitude of 0 (the lexical form <c>0000</c>) is refused.</summary>
    public long Year { get; }

    /// <summary>The month, 1 to 12.</summary>
    public int Month { get; }

    /// <summary>The day, 1 to the number of days <see cref="Month"/> has in <see cref="Year"/> (leap years included).</summary>
    public int Day { get; }

    /// <summary>The hour, 0 to 24; 24 occurs only paired with <see cref="Minute"/> and <see cref="Second"/> both zero and <see cref="HasFractionalSecond"/> <see langword="false"/>.</summary>
    public int Hour { get; }

    /// <summary>The minute, 0 to 59.</summary>
    public int Minute { get; }

    /// <summary>The whole-seconds field, 0 to 59.</summary>
    public int Second { get; }

    /// <summary>Whether a fractional-second component (<c>'.' s+</c>) is present.</summary>
    public bool HasFractionalSecond { get; }

    /// <summary>
    /// The fractional-second digit run's value, meaningful only when <see cref="HasFractionalSecond"/> is
    /// <see langword="true"/>; combine with <see cref="FractionalSecondDigitCount"/> for the represented scale
    /// (the digit run <c>"5"</c> and <c>"50"</c> both parse here but denote the same fraction at different
    /// precision — <see cref="FractionalSecondDigitCount"/> distinguishes them, exactly retaining what was written).
    /// </summary>
    public long FractionalSecondNumerator { get; }

    /// <summary>The count of digits <see cref="FractionalSecondNumerator"/> was parsed from; meaningful only when <see cref="HasFractionalSecond"/> is <see langword="true"/>.</summary>
    public int FractionalSecondDigitCount { get; }

    /// <summary>Whether a timezone component (section 3.2.7.3) is present at all.</summary>
    public bool HasTimezone { get; }

    /// <summary>Whether the present timezone is the literal <c>'Z'</c> — kept distinct from an explicit <c>+00:00</c>/<c>-00:00</c>, both of which set this <see langword="false"/> while denoting the same zero-length offset.</summary>
    public bool IsUtcTimezone { get; }

    /// <summary>Whether the present, non-<c>'Z'</c> timezone carries a leading <c>'-'</c>; meaningful only when <see cref="HasTimezone"/> is <see langword="true"/> and <see cref="IsUtcTimezone"/> is <see langword="false"/>.</summary>
    public bool IsTimezoneNegative { get; }

    /// <summary>The present, non-<c>'Z'</c> timezone's hour magnitude, 0 to 14; meaningful only when <see cref="HasTimezone"/> is <see langword="true"/> and <see cref="IsUtcTimezone"/> is <see langword="false"/>.</summary>
    public int TimezoneHours { get; }

    /// <summary>The present, non-<c>'Z'</c> timezone's minute magnitude, 0 to 59 (and always 0 when <see cref="TimezoneHours"/> is 14); meaningful only when <see cref="HasTimezone"/> is <see langword="true"/> and <see cref="IsUtcTimezone"/> is <see langword="false"/>.</summary>
    public int TimezoneMinutes { get; }


    private XAdESDateTime(
        bool isNegativeYear,
        long year,
        int month,
        int day,
        int hour,
        int minute,
        int second,
        bool hasFractionalSecond,
        long fractionalSecondNumerator,
        int fractionalSecondDigitCount,
        bool hasTimezone,
        bool isUtcTimezone,
        bool isTimezoneNegative,
        int timezoneHours,
        int timezoneMinutes)
    {
        IsNegativeYear = isNegativeYear;
        Year = year;
        Month = month;
        Day = day;
        Hour = hour;
        Minute = minute;
        Second = second;
        HasFractionalSecond = hasFractionalSecond;
        FractionalSecondNumerator = fractionalSecondNumerator;
        FractionalSecondDigitCount = fractionalSecondDigitCount;
        HasTimezone = hasTimezone;
        IsUtcTimezone = isUtcTimezone;
        IsTimezoneNegative = isTimezoneNegative;
        TimezoneHours = timezoneHours;
        TimezoneMinutes = timezoneMinutes;
    }


    /// <summary>
    /// Parses an <c>xsd:dateTime</c> lexical value strictly against section 3.2.7.1's grammar.
    /// </summary>
    /// <param name="value">The exact-character lexical value, e.g. an element's simple-content text.</param>
    /// <param name="result">The parsed value on success.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> matches the grammar exactly.</returns>
    internal static bool TryParse(ReadOnlySpan<byte> value, out XAdESDateTime result)
    {
        result = default;
        int pos = 0;
        int length = value.Length;

        bool isNegativeYear = false;
        if(pos < length && value[pos] == (byte)'-')
        {
            isNegativeYear = true;
            ++pos;
        }

        if(!TryParseYear(value, ref pos, out long year) || year == 0)
        {
            return false;
        }

        if(!TryConsume(value, ref pos, (byte)'-')
            || !TryParseFixedDigits(value, ref pos, 2, out int month)
            || !TryConsume(value, ref pos, (byte)'-')
            || !TryParseFixedDigits(value, ref pos, 2, out int day)
            || !TryConsume(value, ref pos, (byte)'T')
            || !TryParseFixedDigits(value, ref pos, 2, out int hour)
            || !TryConsume(value, ref pos, (byte)':')
            || !TryParseFixedDigits(value, ref pos, 2, out int minute)
            || !TryConsume(value, ref pos, (byte)':')
            || !TryParseFixedDigits(value, ref pos, 2, out int second))
        {
            return false;
        }

        if(month < 1 || month > 12)
        {
            return false;
        }

        if(day < 1 || day > DaysInMonth(isNegativeYear, year, month))
        {
            return false;
        }

        if(hour > 24 || minute > 59 || second > 59)
        {
            return false;
        }

        if(hour == 24 && (minute != 0 || second != 0))
        {
            return false;
        }

        bool hasFractionalSecond = false;
        long fractionNumerator = 0;
        int fractionDigitCount = 0;
        if(pos < length && value[pos] == (byte)'.')
        {
            ++pos;
            while(pos < length && IsAsciiDigit(value[pos]))
            {
                if(fractionDigitCount >= MaximumFractionalSecondDigits)
                {
                    return false;
                }

                fractionNumerator = (fractionNumerator * 10) + (value[pos] - (byte)'0');
                ++fractionDigitCount;
                ++pos;
            }

            if(fractionDigitCount == 0)
            {
                return false;
            }

            hasFractionalSecond = true;
        }

        if(hour == 24 && hasFractionalSecond)
        {
            return false;
        }

        bool hasTimezone = false;
        bool isUtcTimezone = false;
        bool isTimezoneNegative = false;
        int timezoneHours = 0;
        int timezoneMinutes = 0;
        if(pos < length)
        {
            if(value[pos] == (byte)'Z')
            {
                ++pos;
                if(pos != length)
                {
                    return false;
                }

                hasTimezone = true;
                isUtcTimezone = true;
            }
            else if(value[pos] == (byte)'+' || value[pos] == (byte)'-')
            {
                isTimezoneNegative = value[pos] == (byte)'-';
                ++pos;
                if(!TryParseFixedDigits(value, ref pos, 2, out timezoneHours)
                    || !TryConsume(value, ref pos, (byte)':')
                    || !TryParseFixedDigits(value, ref pos, 2, out timezoneMinutes))
                {
                    return false;
                }

                if(timezoneHours > 14 || timezoneMinutes > 59 || (timezoneHours == 14 && timezoneMinutes != 0))
                {
                    return false;
                }

                if(pos != length)
                {
                    return false;
                }

                hasTimezone = true;
            }
            else
            {
                return false;
            }
        }

        result = new XAdESDateTime(
            isNegativeYear, year, month, day, hour, minute, second,
            hasFractionalSecond, fractionNumerator, fractionDigitCount,
            hasTimezone, isUtcTimezone, isTimezoneNegative, timezoneHours, timezoneMinutes);

        return true;
    }


    private static bool IsAsciiDigit(byte value) => value >= (byte)'0' && value <= (byte)'9';


    private static bool TryConsume(ReadOnlySpan<byte> value, ref int pos, byte expected)
    {
        if(pos >= value.Length || value[pos] != expected)
        {
            return false;
        }

        ++pos;

        return true;
    }


    private static bool TryParseFixedDigits(ReadOnlySpan<byte> value, ref int pos, int digitCount, out int result)
    {
        result = 0;
        if(pos + digitCount > value.Length)
        {
            return false;
        }

        for(int i = 0; i < digitCount; ++i)
        {
            byte current = value[pos + i];
            if(!IsAsciiDigit(current))
            {
                result = 0;

                return false;
            }

            result = (result * 10) + (current - (byte)'0');
        }

        pos += digitCount;

        return true;
    }


    private static bool TryParseYear(ReadOnlySpan<byte> value, ref int pos, out long year)
    {
        year = 0;
        int start = pos;
        while(pos < value.Length && IsAsciiDigit(value[pos]))
        {
            ++pos;
        }

        int digitCount = pos - start;
        if(digitCount < 4 || digitCount > MaximumYearDigits)
        {
            return false;
        }

        if(digitCount > 4 && value[start] == (byte)'0')
        {
            return false;
        }

        long magnitude = 0;
        for(int i = start; i < pos; ++i)
        {
            magnitude = (magnitude * 10) + (value[i] - (byte)'0');
        }

        year = magnitude;

        return true;
    }


    private static int DaysInMonth(bool isNegativeYear, long yearMagnitude, int month)
    {
        return month switch
        {
            1 or 3 or 5 or 7 or 8 or 10 or 12 => 31,
            4 or 6 or 9 or 11 => 30,
            2 => IsLeapYear(isNegativeYear, yearMagnitude) ? 29 : 28,
            _ => 0
        };
    }


    /// <summary>
    /// Applies the proleptic-Gregorian leap-year test over the astronomical year number. This version of
    /// <c>xsd:dateTime</c> has no year zero (section 3.2.7's own note): the lexical year magnitude <c>m</c>
    /// under a leading <c>'-'</c> names <c>m</c> Before Common Era, which maps to astronomical year
    /// <c>-(m - 1)</c> — <c>'-0001'</c> (1 BCE) is astronomical year 0, a leap year.
    /// </summary>
    private static bool IsLeapYear(bool isNegativeYear, long yearMagnitude)
    {
        long astronomicalYear = isNegativeYear ? -(yearMagnitude - 1) : yearMagnitude;

        return astronomicalYear % 4 == 0 && (astronomicalYear % 100 != 0 || astronomicalYear % 400 == 0);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESDateTime other)
    {
        return IsNegativeYear == other.IsNegativeYear
            && Year == other.Year
            && Month == other.Month
            && Day == other.Day
            && Hour == other.Hour
            && Minute == other.Minute
            && Second == other.Second
            && HasFractionalSecond == other.HasFractionalSecond
            && (!HasFractionalSecond || (FractionalSecondNumerator == other.FractionalSecondNumerator && FractionalSecondDigitCount == other.FractionalSecondDigitCount))
            && HasTimezone == other.HasTimezone
            && (!HasTimezone || (IsUtcTimezone == other.IsUtcTimezone
                && (IsUtcTimezone || (IsTimezoneNegative == other.IsTimezoneNegative && TimezoneHours == other.TimezoneHours && TimezoneMinutes == other.TimezoneMinutes))));
    }


    private void AddFieldsTo(ref HashCode hash)
    {
        hash.Add(IsNegativeYear);
        hash.Add(Year);
        hash.Add(Month);
        hash.Add(Day);
        hash.Add(Hour);
        hash.Add(Minute);
        hash.Add(Second);
        hash.Add(HasFractionalSecond);
        if(HasFractionalSecond)
        {
            hash.Add(FractionalSecondNumerator);
            hash.Add(FractionalSecondDigitCount);
        }

        hash.Add(HasTimezone);
        if(HasTimezone)
        {
            hash.Add(IsUtcTimezone);
            if(!IsUtcTimezone)
            {
                hash.Add(IsTimezoneNegative);
                hash.Add(TimezoneHours);
                hash.Add(TimezoneMinutes);
            }
        }
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESDateTime other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        AddFieldsTo(ref hash);

        return hash.ToHashCode();
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESDateTime left, XAdESDateTime right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESDateTime left, XAdESDateTime right) => !left.Equals(right);
}
