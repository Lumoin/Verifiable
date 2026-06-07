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
/// to <see cref="object"/>, because the chosen JSON deserializer
/// determines the runtime type of each value. <see cref="RequireInstant"/>
/// accepts the integer family <c>Verifiable.Json</c>'s narrowing
/// converters produce when materialising a JSON number into an
/// object-typed dictionary, plus <see cref="DateTimeOffset"/> for
/// deserializers that pre-resolve NumericDate claims.
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
        IReadOnlyDictionary<string, object> claims,
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
        IReadOnlyDictionary<string, object> claims,
        string name)
    {
        return claims.TryGetValue(name, out object? value) && value is string str ? str : null;
    }


    public static DateTimeOffset RequireInstant(
        IReadOnlyDictionary<string, object> claims,
        string name)
    {
        if(!claims.TryGetValue(name, out object? value) || value is null)
        {
            throw new FormatException(
                $"JWT payload is missing required timing claim '{name}'.");
        }

        if(value is DateTimeOffset dt)
        {
            return dt;
        }

        if(TryToInt64(value, out long unixSeconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }

        throw new FormatException(
            $"JWT payload claim '{name}' is not a JWT NumericDate value " +
            $"(observed runtime type: {value.GetType().FullName}).");
    }


    public static bool TryToInt64(object value, out long result)
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
        }

        result = 0;

        return false;
    }
}
