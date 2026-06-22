using System.Globalization;
using System.Text;

namespace Verifiable.JCose;

/// <summary>
/// Appends a JSON string literal to a <see cref="StringBuilder"/> for the JWE JSON
/// serializations, escaping the JSON control, quote, and backslash characters of RFC 8259 §7
/// so a value (notably a recipient <c>kid</c>) can never break out of its string and inject
/// structure.
/// </summary>
/// <remarks>
/// The JWE General and Flattened JSON Serializations write the same kinds of values — base64url
/// strings (which carry no escaping characters) and recipient <c>kid</c> strings (which may).
/// Both serializers share this one escaper so the escaping rule is defined once.
/// </remarks>
internal static class JweJsonString
{
    /// <summary>
    /// Appends <paramref name="value"/> as a quoted, escaped JSON string to
    /// <paramref name="builder"/>.
    /// </summary>
    public static void Append(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach(char c in value)
        {
            switch(c)
            {
                case '"':
                {
                    builder.Append("\\\"");
                    break;
                }
                case '\\':
                {
                    builder.Append("\\\\");
                    break;
                }
                case '\n':
                {
                    builder.Append("\\n");
                    break;
                }
                case '\r':
                {
                    builder.Append("\\r");
                    break;
                }
                case '\t':
                {
                    builder.Append("\\t");
                    break;
                }
                default:
                {
                    if(c < ' ')
                    {
                        builder.Append("\\u");
                        builder.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(c);
                    }

                    break;
                }
            }
        }

        builder.Append('"');
    }
}
