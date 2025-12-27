using System;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Verifiable.Core.Model.Common;

/// <summary>
/// Provides formatting and parsing for XML Schema 1.1 dateTimeStamp values
/// as required by W3C Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// The dateTimeStamp datatype is defined in XML Schema 1.1 Part 2 as a restriction
/// of dateTime where the timezone is required. This means values must end with
/// either 'Z' (UTC) or a timezone offset like '+01:00' or '-05:00'.
/// </para>
/// <para>
/// Valid examples:
/// </para>
/// <list type="bullet">
/// <item><description><c>2024-01-15T10:30:00Z</c> - UTC without fractional seconds.</description></item>
/// <item><description><c>2024-01-15T10:30:00.123Z</c> - UTC with milliseconds.</description></item>
/// <item><description><c>2024-01-15T10:30:00+01:00</c> - With positive offset.</description></item>
/// <item><description><c>2024-01-15T10:30:00.123456-05:00</c> - With fractional seconds and negative offset.</description></item>
/// </list>
/// <para>
/// Invalid examples (no timezone):
/// </para>
/// <list type="bullet">
/// <item><description><c>2024-01-15T10:30:00</c> - Missing timezone.</description></item>
/// <item><description><c>2024-01-15</c> - Date only.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XML Schema 1.1 Part 2 §3.4.28</see>
/// and <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">VC Data Integrity §2.1 Proofs</see>.
/// </para>
/// </remarks>
public static partial class DateTimeStampFormat
{
    /// <summary>
    /// Canonical format string for UTC timestamps without fractional seconds.
    /// Produces output like <c>2024-01-15T10:30:00Z</c>.
    /// </summary>
    /// <remarks>
    /// This is the recommended format for interoperability as it produces
    /// the most compact valid representation.
    /// </remarks>
    public const string Utc = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    /// <summary>
    /// Format string for UTC timestamps with millisecond precision.
    /// Produces output like <c>2024-01-15T10:30:00.123Z</c>.
    /// </summary>
    public const string UtcMilliseconds = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    /// <summary>
    /// Format string for UTC timestamps with microsecond precision.
    /// Produces output like <c>2024-01-15T10:30:00.123456Z</c>.
    /// </summary>
    public const string UtcMicroseconds = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";

    /// <summary>
    /// Format string for timestamps preserving the original timezone offset.
    /// Produces output like <c>2024-01-15T10:30:00+01:00</c>.
    /// </summary>
    public const string WithOffset = "yyyy-MM-dd'T'HH:mm:sszzz";

    /// <summary>
    /// Format string for timestamps with milliseconds and timezone offset.
    /// Produces output like <c>2024-01-15T10:30:00.123+01:00</c>.
    /// </summary>
    public const string WithOffsetMilliseconds = "yyyy-MM-dd'T'HH:mm:ss.fffzzz";


    /// <summary>
    /// Formats a <see cref="DateTimeOffset"/> as a dateTimeStamp string.
    /// </summary>
    /// <param name="value">The timestamp to format.</param>
    /// <param name="format">
    /// The format string to use. Defaults to <see cref="Utc"/> which produces
    /// compact UTC timestamps like <c>2024-01-15T10:30:00Z</c>.
    /// </param>
    /// <returns>A valid XML Schema 1.1 dateTimeStamp string.</returns>
    /// <remarks>
    /// When using UTC formats (<see cref="Utc"/>, <see cref="UtcMilliseconds"/>,
    /// <see cref="UtcMicroseconds"/>), the value is first converted to UTC.
    /// When using offset formats (<see cref="WithOffset"/>, <see cref="WithOffsetMilliseconds"/>),
    /// the original offset is preserved.
    /// </remarks>
    public static string Format(DateTimeOffset value, string format = Utc)
    {
        var valueToFormat = format == Utc || format == UtcMilliseconds || format == UtcMicroseconds
            ? value.ToUniversalTime()
            : value;

        return valueToFormat.ToString(format, CultureInfo.InvariantCulture);
    }


    /// <summary>
    /// Formats a <see cref="DateTime"/> as a dateTimeStamp string in UTC.
    /// </summary>
    /// <param name="value">The timestamp to format. Assumed to be UTC if Kind is Unspecified.</param>
    /// <param name="format">The format string to use. Defaults to <see cref="Utc"/>.</param>
    /// <returns>A valid XML Schema 1.1 dateTimeStamp string.</returns>
    public static string Format(DateTime value, string format = Utc)
    {
        var utc = value.Kind == DateTimeKind.Local
            ? value.ToUniversalTime()
            : DateTime.SpecifyKind(value, DateTimeKind.Utc);

        return utc.ToString(format, CultureInfo.InvariantCulture);
    }


    /// <summary>
    /// Attempts to parse a dateTimeStamp string into a <see cref="DateTimeOffset"/>.
    /// </summary>
    /// <param name="value">The string to parse.</param>
    /// <param name="result">
    /// When this method returns, contains the parsed <see cref="DateTimeOffset"/>
    /// if parsing succeeded, or <see cref="DateTimeOffset.MinValue"/> if parsing failed.
    /// </param>
    /// <returns>
    /// <c>true</c> if <paramref name="value"/> is a valid dateTimeStamp string
    /// with a timezone designator; otherwise <c>false</c>.
    /// </returns>
    public static bool TryParse(string? value, out DateTimeOffset result)
    {
        result = default;

        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        //Validate format first to ensure timezone is present (required by dateTimeStamp).
        if(!DateTimeStampPattern().IsMatch(value))
        {
            return false;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out result);
    }


    /// <summary>
    /// Parses a dateTimeStamp string into a <see cref="DateTimeOffset"/>.
    /// </summary>
    /// <param name="value">The string to parse.</param>
    /// <returns>The parsed <see cref="DateTimeOffset"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    /// <exception cref="FormatException">
    /// Thrown when <paramref name="value"/> is not a valid dateTimeStamp string.
    /// </exception>
    public static DateTimeOffset Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if(!TryParse(value, out var result))
        {
            throw new FormatException($"The value '{value}' is not a valid XML Schema 1.1 dateTimeStamp. A timezone designator (Z or offset like +01:00) is required.");
        }

        return result;
    }


    /// <summary>
    /// Validates that a string is a properly formatted dateTimeStamp.
    /// </summary>
    /// <param name="value">The string to validate.</param>
    /// <returns>
    /// <c>true</c> if <paramref name="value"/> is a valid dateTimeStamp string
    /// with a timezone designator; otherwise <c>false</c>.
    /// </returns>
    public static bool IsValid(string? value)
    {
        return TryParse(value, out _);
    }


    /// <summary>
    /// Pattern matching XML Schema 1.1 dateTimeStamp lexical representation.
    /// Requires timezone designator (Z or offset).
    /// </summary>
    /// <remarks>
    /// Pattern breakdown:
    /// <list type="bullet">
    /// <item><description><c>\d{4}-\d{2}-\d{2}</c> - Date (yyyy-MM-dd).</description></item>
    /// <item><description><c>T</c> - Date/time separator.</description></item>
    /// <item><description><c>\d{2}:\d{2}:\d{2}</c> - Time (HH:mm:ss).</description></item>
    /// <item><description><c>(\.\d{1,7})?</c> - Optional fractional seconds (1-7 digits).</description></item>
    /// <item><description><c>(Z|[+-]\d{2}:\d{2})</c> - Required timezone (Z or ±HH:mm).</description></item>
    /// </list>
    /// </remarks>
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex DateTimeStampPattern();
}