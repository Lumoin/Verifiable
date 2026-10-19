using Verifiable.JCose;

namespace Verifiable.OAuth.Jar;

/// <summary>
/// Internal helpers for reading typed values out of a parsed JWT claim
/// dictionary. Shared across <see cref="JarExtensions"/> and
/// <see cref="JarVerification"/> so the two paths use one implementation
/// of "required string claim", "optional string claim", and "JWT
/// NumericDate claim" semantics.
/// </summary>
/// <remarks>
/// <para>
/// JWT payload claim values arrive in this library as
/// <see cref="IReadOnlyDictionary{TKey, TValue}"/> of <see cref="string"/>
/// to a nullable <see cref="object"/>, because the chosen JSON deserializer
/// determines the runtime type of each value and a present JSON <c>null</c>
/// is held as a member with no value. <see cref="RequireNumericDate"/>
/// reads a NumericDate by the library's one reading of the type
/// (<see cref="NumericDate.Of"/>), every digit kept.
/// </para>
/// <para>
/// All helpers throw <see cref="FormatException"/> on shape violations
/// rather than returning a result type. The callers are JWT parsers
/// already operating inside a wider try/catch boundary; throwing keeps
/// the parser bodies readable and the caller maps the exception to its
/// flow-shaped error response.
/// </para>
/// </remarks>
internal static class JwtClaimReaders
{
    public static string RequireClaim(
        IReadOnlyDictionary<string, object?> claims,
        string name)
    {
        if(!claims.TryGetValue(name, out object? value) || value is not string str)
        {
            throw new FormatException(
                $"JWT payload is missing required claim '{name}'.");
        }

        return str;
    }


    public static string? OptionalClaim(
        IReadOnlyDictionary<string, object?> claims,
        string name)
    {
        return claims.TryGetValue(name, out object? value) && value is string str ? str : null;
    }


    /// <summary>
    /// Reads a required NumericDate claim as the date it names, every digit kept (<see cref="NumericDate.Of"/>), so the caller
    /// judges each bound against the date written.
    /// </summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="name">The NumericDate claim to read.</param>
    /// <returns>The date the claim names.</returns>
    /// <exception cref="FormatException">The claim is absent, or is no NumericDate naming an instant a clock represents.</exception>
    public static NumericDate RequireNumericDate(
        IReadOnlyDictionary<string, object?> claims,
        string name)
    {
        if(!claims.TryGetValue(name, out object? value) || value is null)
        {
            throw new FormatException(
                $"JWT payload is missing required timing claim '{name}'.");
        }

        if(NumericDate.Of(value) is NumericDate date)
        {
            return date;
        }

        throw new FormatException(
            $"JWT payload claim '{name}' is not a JWT NumericDate value " +
            $"(observed runtime type: {value.GetType().FullName}).");
    }


    /// <summary>Reads a claim value the JSON layer boxed as an integer, of any of its integral boxings, as a 64-bit integer.</summary>
    /// <param name="value">The claim's value, which may be none.</param>
    /// <param name="result">The integer, or zero when the value is no integer a 64-bit integer holds.</param>
    /// <returns><see langword="true"/> when the value is such an integer.</returns>
    public static bool TryToInt64(object? value, out long result)
    {
        switch(value)
        {
            case long l:
            {
                result = l;
                return true;
            }
            case int i:
            {
                result = i;
                return true;
            }
            case short s:
            {
                result = s;
                return true;
            }
            case byte b:
            {
                result = b;
                return true;
            }
            case uint ui:
            {
                result = ui;
                return true;
            }
            case ulong ul when ul <= long.MaxValue:
            {
                result = (long)ul;
                return true;
            }
            case sbyte sb:
            {
                result = sb;
                return true;
            }
            case ushort us:
            {
                result = us;
                return true;
            }
            case decimal d when d >= long.MinValue && d <= long.MaxValue && d == Math.Truncate(d):
            {
                result = (long)d;
                return true;
            }
            default:
            {
                //No other runtime type is a whole-number JSON numeric value this reader accepts.
                break;
            }
        }

        result = 0;

        return false;
    }
}
