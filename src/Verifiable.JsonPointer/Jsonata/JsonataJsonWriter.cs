using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// Serializes a <see cref="JsonataValue"/> to its compact JSON text. The minimal in-repo JSONata
/// evaluator produces a <see cref="JsonataValue"/> object graph (the credential body); a consumer that
/// must hand that body to a JSON deserializer — the W3C VCALM 1.0 §3.6 issuance-in-exchange path, which
/// renders a credential template into a credential body and then signs it through the deployment's
/// Data Integrity seams — turns the value back into a JSON string here.
/// </summary>
/// <remarks>
/// <para>
/// This keeps <c>Verifiable.JsonPointer</c> free of <c>System.Text.Json</c>: the writer emits JSON
/// from the local value model directly. Object members are written in insertion order (the model
/// preserves it), so a constructed credential body renders its members in template order. String
/// escaping matches <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</see> —
/// the named escapes plus <c>\u00XX</c> for the remaining control characters, lowercase hex.
/// </para>
/// <para>
/// Numbers render with invariant culture: an <see cref="JsonataValueKind.Integer"/> as a bare integer,
/// a <see cref="JsonataValueKind.Number"/> with the round-trippable <c>R</c> format.
/// </para>
/// </remarks>
public static class JsonataJsonWriter
{
    /// <summary>
    /// Serializes <paramref name="value"/> to compact JSON text.
    /// </summary>
    /// <param name="value">The value to serialize.</param>
    /// <returns>The compact JSON representation.</returns>
    public static string Write(JsonataValue value)
    {
        var sb = new StringBuilder(256);
        WriteValue(sb, value);

        return sb.ToString();
    }


    private static void WriteValue(StringBuilder sb, JsonataValue value)
    {
        switch(value.Kind)
        {
            case JsonataValueKind.Null:
            {
                sb.Append("null");
                break;
            }

            case JsonataValueKind.Boolean:
            {
                sb.Append(value.AsBoolean() ? "true" : "false");
                break;
            }

            case JsonataValueKind.Integer:
            {
                sb.Append(value.AsInteger().ToString(CultureInfo.InvariantCulture));
                break;
            }

            case JsonataValueKind.Number:
            {
                sb.Append(value.AsNumber().ToString("R", CultureInfo.InvariantCulture));
                break;
            }

            case JsonataValueKind.String:
            {
                WriteString(sb, value.AsString());
                break;
            }

            case JsonataValueKind.Array:
            {
                WriteArray(sb, value.AsArray());
                break;
            }

            case JsonataValueKind.Object:
            {
                WriteObject(sb, value.AsObject());
                break;
            }

            default:
            {
                sb.Append("null");
                break;
            }
        }
    }


    private static void WriteArray(StringBuilder sb, IReadOnlyList<JsonataValue> elements)
    {
        sb.Append('[');
        for(int i = 0; i < elements.Count; ++i)
        {
            if(i > 0)
            {
                sb.Append(',');
            }

            WriteValue(sb, elements[i]);
        }

        sb.Append(']');
    }


    private static void WriteObject(StringBuilder sb, IReadOnlyDictionary<string, JsonataValue> members)
    {
        sb.Append('{');
        bool first = true;
        foreach(KeyValuePair<string, JsonataValue> member in members)
        {
            if(!first)
            {
                sb.Append(',');
            }

            first = false;
            WriteString(sb, member.Key);
            sb.Append(':');
            WriteValue(sb, member.Value);
        }

        sb.Append('}');
    }


    private static void WriteString(StringBuilder sb, string value)
    {
        sb.Append('"');
        for(int i = 0; i < value.Length; ++i)
        {
            char c = value[i];
            switch(c)
            {
                case '"':
                {
                    sb.Append("\\\"");
                    break;
                }

                case '\\':
                {
                    sb.Append("\\\\");
                    break;
                }

                case '\b':
                {
                    sb.Append("\\b");
                    break;
                }

                case '\f':
                {
                    sb.Append("\\f");
                    break;
                }

                case '\n':
                {
                    sb.Append("\\n");
                    break;
                }

                case '\r':
                {
                    sb.Append("\\r");
                    break;
                }

                case '\t':
                {
                    sb.Append("\\t");
                    break;
                }

                default:
                {
                    if(c < 0x20)
                    {
                        sb.Append("\\u");
                        sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
                }
            }
        }

        sb.Append('"');
    }
}
