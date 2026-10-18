using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace Verifiable.JCose;

/// <summary>
/// A number written in decimal notation, held exactly: its sign, its significant digits and where its decimal point falls. A
/// JSON number (RFC 8259 section 6: "a sign, a sequence of digits, a fraction part and an exponent part") names such a number,
/// and neither <see cref="decimal"/> nor <see cref="double"/> holds every one: a decimal keeps 28 or 29 significant digits and
/// a double a binary fraction, so a reader that converts first may judge a number its writer never wrote. Every number this
/// type names is the number written, digit for digit, however many digits it carries and however large its exponent.
/// </summary>
/// <remarks>
/// The form is canonical: no significant digit string begins or ends with zero, and zero is one value with no sign, so two
/// instances are equal exactly when they name the same number.
/// </remarks>
public sealed record DecimalNumber
{
    /// <summary>The number zero.</summary>
    public static DecimalNumber Zero { get; } = new(false, string.Empty, BigInteger.Zero);

    /// <summary>The largest integer a <see cref="decimal"/>'s 96-bit mantissa holds.</summary>
    private static BigInteger LargestDecimalMantissa { get; } = (BigInteger.One << 96) - 1;

    /// <summary>Creates the number from its canonical parts.</summary>
    /// <param name="isNegative">Whether the number is below zero.</param>
    /// <param name="significantDigits">The significant digits, neither first nor last a zero; empty for zero.</param>
    /// <param name="pointPosition">The power of ten the digits, read as a fraction after the point, are multiplied by.</param>
    private DecimalNumber(bool isNegative, string significantDigits, BigInteger pointPosition)
    {
        IsNegative = isNegative;
        SignificantDigits = significantDigits;
        PointPosition = pointPosition;
    }


    /// <summary>Whether the number is below zero. Zero is never negative.</summary>
    public bool IsNegative { get; }

    /// <summary>The number's significant digits as ASCII digits, neither the first nor the last a zero; empty for zero.</summary>
    public string SignificantDigits { get; }

    /// <summary>
    /// Where the decimal point falls: the number's magnitude is <c>0.</c> followed by <see cref="SignificantDigits"/>, times ten
    /// to this power. A number from 1 up to but not including 10 has the position 1, and one from 0.1 up to 1 the position 0.
    /// </summary>
    public BigInteger PointPosition { get; }

    /// <summary>Whether the number is zero.</summary>
    public bool IsZero => SignificantDigits.Length == 0;


    /// <summary>
    /// The number a JSON number token names (RFC 8259 section 6: <c>[ minus ] int [ frac ] [ exp ]</c>, where <c>int</c> is a zero
    /// or a digit one to nine followed by digits, <c>frac</c> a point followed by at least one digit and <c>exp</c> an <c>e</c> or
    /// <c>E</c>, an optional sign and at least one digit), or <see langword="null"/> when the bytes are not exactly one such token:
    /// a string, a leading plus, a leading zero before another digit, a bare point and surrounding white space are none.
    /// </summary>
    /// <param name="utf8Number">The token's UTF-8 bytes.</param>
    /// <returns>The number, or <see langword="null"/>.</returns>
    public static DecimalNumber? FromJsonNumber(ReadOnlySpan<byte> utf8Number)
    {
        var position = 0;
        var isNegative = false;

        if(position < utf8Number.Length && utf8Number[position] == (byte)'-')
        {
            isNegative = true;
            position++;
        }

        var integerStart = position;

        if(position >= utf8Number.Length)
        {
            return null;
        }

        if(utf8Number[position] == (byte)'0')
        {
            position++;
        }
        else if(IsDigit(utf8Number[position]))
        {
            position = SkipDigits(utf8Number, position);
        }
        else
        {
            return null;
        }

        var integerDigits = utf8Number[integerStart..position];
        var fractionDigits = ReadOnlySpan<byte>.Empty;

        if(position < utf8Number.Length && utf8Number[position] == (byte)'.')
        {
            var fractionStart = position + 1;
            position = SkipDigits(utf8Number, fractionStart);

            if(position == fractionStart)
            {
                return null;
            }

            fractionDigits = utf8Number[fractionStart..position];
        }

        var exponent = BigInteger.Zero;

        if(position < utf8Number.Length && utf8Number[position] is (byte)'e' or (byte)'E')
        {
            position++;
            var exponentIsNegative = false;

            if(position < utf8Number.Length && utf8Number[position] is (byte)'+' or (byte)'-')
            {
                exponentIsNegative = utf8Number[position] == (byte)'-';
                position++;
            }

            var exponentStart = position;
            position = SkipDigits(utf8Number, exponentStart);

            if(position == exponentStart)
            {
                return null;
            }

            var magnitude = BigInteger.Parse(Encoding.ASCII.GetString(utf8Number[exponentStart..position]), NumberStyles.None, CultureInfo.InvariantCulture);
            exponent = exponentIsNegative ? -magnitude : magnitude;
        }

        if(position != utf8Number.Length)
        {
            return null;
        }

        var digits = string.Concat(Encoding.ASCII.GetString(integerDigits), Encoding.ASCII.GetString(fractionDigits));

        return Normalized(isNegative, digits, integerDigits.Length + exponent);
    }


    /// <summary>
    /// The number a claim's value names as a claims set holds it, or <see langword="null"/> when the value is no number. The JSON
    /// layers a claims set is parsed with box a number as one of the .NET integer types, as a <see cref="decimal"/>, as a
    /// <see cref="double"/> or <see cref="float"/>, or, where neither an integer nor a decimal holds it exactly, as the
    /// <see cref="DecimalNumber"/> it is (<see cref="ToClaimValue"/>); each is read exactly as it is held. The one numeric
    /// conversion every reader of a claim the library judges as a number shares.
    /// </summary>
    /// <param name="value">The claim's value.</param>
    /// <returns>The number, or <see langword="null"/>.</returns>
    public static DecimalNumber? Of(object? value) => value switch
    {
        DecimalNumber exact => exact,
        long whole => FromInteger(whole),
        int whole => FromInteger(whole),
        short whole => FromInteger(whole),
        sbyte whole => FromInteger(whole),
        byte whole => FromInteger(whole),
        ushort whole => FromInteger(whole),
        uint whole => FromInteger(whole),
        ulong whole => FromInteger(whole),
        decimal fraction => FromDecimal(fraction),
        double floating => FromDouble(floating),
        float floating => FromDouble(floating),
        _ => null
    };


    /// <summary>The integer given, exactly.</summary>
    /// <param name="value">The integer.</param>
    /// <returns>The number.</returns>
    public static DecimalNumber FromInteger(BigInteger value)
    {
        var digits = BigInteger.Abs(value).ToString(CultureInfo.InvariantCulture);

        return Normalized(value.Sign < 0, digits, digits.Length);
    }


    /// <summary>The whole number given, exactly: every <see cref="long"/> is a decimal number, so the conversion never fails.</summary>
    /// <param name="value">The whole number.</param>
    public static implicit operator DecimalNumber(long value) => FromInteger(value);


    /// <summary>The number a <see cref="decimal"/> holds, exactly, its scale and sign included.</summary>
    /// <param name="value">The decimal.</param>
    /// <returns>The number.</returns>
    public static DecimalNumber FromDecimal(decimal value)
    {
        Span<int> bits = stackalloc int[4];
        _ = decimal.GetBits(value, bits);

        var low = (uint)bits[0];
        var middle = (uint)bits[1];
        var high = (uint)bits[2];
        var scale = (bits[3] >> 16) & 0xFF;
        var unscaled = (new BigInteger(high) << 64) | (new BigInteger(middle) << 32) | new BigInteger(low);

        return Scaled(bits[3] < 0 ? -unscaled : unscaled, scale);
    }


    /// <summary>
    /// The number a <see cref="double"/> holds, exactly: every finite double is a binary fraction, which a finite run of decimal
    /// digits names exactly (a mantissa times a power of two is the mantissa times the same power of five over a power of ten).
    /// <see langword="null"/> for an infinity or a value that is not a number.
    /// </summary>
    /// <param name="value">The double.</param>
    /// <returns>The number, or <see langword="null"/>.</returns>
    public static DecimalNumber? FromDouble(double value)
    {
        if(!double.IsFinite(value))
        {
            return null;
        }

        if(value == 0)
        {
            return Zero;
        }

        var bits = BitConverter.DoubleToInt64Bits(value);
        var biasedExponent = (int)((bits >> 52) & 0x7FF);
        var fraction = bits & 0xF_FFFF_FFFF_FFFF;
        var mantissa = biasedExponent == 0 ? fraction : fraction | (1L << 52);
        var binaryExponent = biasedExponent == 0 ? -1074 : biasedExponent - 1075;
        var signedMantissa = bits < 0 ? -new BigInteger(mantissa) : new BigInteger(mantissa);

        return binaryExponent >= 0
            ? FromInteger(signedMantissa << binaryExponent)
            : Scaled(signedMantissa * BigInteger.Pow(5, -binaryExponent), -binaryExponent);
    }


    /// <summary>
    /// The value a claims set holds this number as, boxed as the library's JSON layer boxes a number it reads: a
    /// <see cref="long"/> for a whole number a long holds, a <see cref="decimal"/> for one a decimal holds exactly, and this
    /// number itself for any other, so no digit is dropped on the way into a claims set.
    /// </summary>
    /// <returns>The boxed value.</returns>
    public object ToClaimValue()
    {
        const int LargestDecimalScale = 28;

        if(IsZero)
        {
            return 0L;
        }

        //Written as an integer count scaled down by a power of ten: the digits, padded with zeros where the point lies past them.
        var scale = BigInteger.Max(BigInteger.Zero, SignificantDigits.Length - PointPosition);

        if(scale > LargestDecimalScale || PointPosition > LargestDecimalScale + 1)
        {
            return this;
        }

        var padding = (int)BigInteger.Max(BigInteger.Zero, PointPosition - SignificantDigits.Length);
        var unscaled = BigInteger.Parse(SignificantDigits, NumberStyles.None, CultureInfo.InvariantCulture) * BigInteger.Pow(10, padding);

        if(scale.IsZero && unscaled <= long.MaxValue)
        {
            return IsNegative ? (long)-unscaled : (long)unscaled;
        }

        if(unscaled > LargestDecimalMantissa)
        {
            return this;
        }

        var bytes = unscaled.ToByteArray(isUnsigned: true, isBigEndian: false);
        Span<byte> mantissa = stackalloc byte[12];
        bytes.AsSpan().CopyTo(mantissa);

        return new decimal(
            BinaryPrimitives.ReadInt32LittleEndian(mantissa[..4]),
            BinaryPrimitives.ReadInt32LittleEndian(mantissa[4..8]),
            BinaryPrimitives.ReadInt32LittleEndian(mantissa[8..12]),
            IsNegative,
            (byte)scale);
    }


    /// <summary>
    /// Compares this number with another exactly: by sign, then by the position of the decimal point, then digit by digit, so no
    /// digit of either is ever dropped.
    /// </summary>
    /// <param name="other">The other number.</param>
    /// <returns>A negative value when this number is the smaller, zero when they are equal and a positive value when it is the larger.</returns>
    public int CompareTo(DecimalNumber other)
    {
        ArgumentNullException.ThrowIfNull(other);

        var sign = SignOf(this);
        var otherSign = SignOf(other);

        if(sign != otherSign)
        {
            return sign.CompareTo(otherSign);
        }

        if(sign == 0)
        {
            return 0;
        }

        var magnitude = PointPosition != other.PointPosition
            ? PointPosition.CompareTo(other.PointPosition)
            : Math.Sign(string.CompareOrdinal(SignificantDigits, other.SignificantDigits));

        return sign * magnitude;
    }


    /// <summary>
    /// The number as one JSON number token (RFC 8259 section 6) naming it exactly: in plain notation where the point falls within
    /// twenty-five places of the digits, and with an exponent otherwise.
    /// </summary>
    /// <returns>The JSON number text.</returns>
    public override string ToString()
    {
        const int PlainNotationReach = 25;

        if(IsZero)
        {
            return "0";
        }

        var sign = IsNegative ? "-" : string.Empty;
        var digits = SignificantDigits;

        if(PointPosition > digits.Length + PlainNotationReach || PointPosition < -PlainNotationReach)
        {
            var mantissa = digits.Length == 1 ? digits : string.Concat(digits.AsSpan(0, 1), ".", digits.AsSpan(1));

            return string.Create(CultureInfo.InvariantCulture, $"{sign}{mantissa}e{PointPosition - 1}");
        }

        var point = (int)PointPosition;

        if(point <= 0)
        {
            return string.Concat(sign, "0.", new string('0', -point), digits);
        }

        return point >= digits.Length
            ? string.Concat(sign, digits, new string('0', point - digits.Length))
            : string.Concat(sign, digits.AsSpan(0, point), ".", digits.AsSpan(point));
    }


    /// <summary>The number an integer scaled down by a power of ten names: <paramref name="unscaled"/> times ten to the minus <paramref name="scale"/>.</summary>
    /// <param name="unscaled">The integer.</param>
    /// <param name="scale">The power of ten it is divided by.</param>
    /// <returns>The number.</returns>
    internal static DecimalNumber Scaled(BigInteger unscaled, int scale)
    {
        var digits = BigInteger.Abs(unscaled).ToString(CultureInfo.InvariantCulture);

        return Normalized(unscaled.Sign < 0, digits, digits.Length - scale);
    }


    /// <summary>
    /// The canonical number of a sign, a run of digits and the point position of that run: leading zeros move the point left as
    /// they go, trailing zeros go, and a run of zeros alone is zero with no sign.
    /// </summary>
    /// <param name="isNegative">Whether the number is below zero, if it is not zero.</param>
    /// <param name="digits">The digits, which may begin and end with zeros.</param>
    /// <param name="pointPosition">The point position of <paramref name="digits"/> as given.</param>
    /// <returns>The number.</returns>
    private static DecimalNumber Normalized(bool isNegative, string digits, BigInteger pointPosition)
    {
        var leadingZeros = 0;

        while(leadingZeros < digits.Length && digits[leadingZeros] == '0')
        {
            leadingZeros++;
        }

        var end = digits.Length;

        while(end > leadingZeros && digits[end - 1] == '0')
        {
            end--;
        }

        if(end == leadingZeros)
        {
            return Zero;
        }

        return new DecimalNumber(isNegative, digits[leadingZeros..end], pointPosition - leadingZeros);
    }


    /// <summary>The sign of a number: -1 below zero, 0 at zero and 1 above.</summary>
    /// <param name="number">The number.</param>
    /// <returns>The sign.</returns>
    private static int SignOf(DecimalNumber number) => number.IsZero ? 0 : number.IsNegative ? -1 : 1;


    /// <summary>Whether a byte is an ASCII digit.</summary>
    /// <param name="value">The byte.</param>
    /// <returns><see langword="true"/> for <c>0</c> to <c>9</c>.</returns>
    private static bool IsDigit(byte value) => value is >= (byte)'0' and <= (byte)'9';


    /// <summary>The position after the run of ASCII digits starting at <paramref name="index"/>.</summary>
    /// <param name="utf8">The bytes.</param>
    /// <param name="index">The position the run starts at.</param>
    /// <returns>The position of the first byte that is no digit, or the length of the input.</returns>
    private static int SkipDigits(ReadOnlySpan<byte> utf8, int index)
    {
        var position = index;

        while(position < utf8.Length && IsDigit(utf8[position]))
        {
            position++;
        }

        return position;
    }
}
