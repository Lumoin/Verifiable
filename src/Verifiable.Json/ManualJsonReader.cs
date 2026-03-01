using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Reads JSON tokens from a <see cref="Utf8JsonReader"/> into CLR primitives,
/// dictionaries, and lists without producing <see cref="JsonElement"/> values.
/// Uses an explicit stack for nested structures.
/// </summary>
/// <remarks>
/// <para>
/// The type mapping matches <see cref="JsonElementConversion"/>:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="JsonTokenType.String"/> produces <see cref="string"/>.</description></item>
/// <item><description><see cref="JsonTokenType.True"/> and <see cref="JsonTokenType.False"/> produce <see cref="bool"/>.</description></item>
/// <item><description><see cref="JsonTokenType.Number"/> produces <see cref="int"/> if representable, then <see cref="long"/>, otherwise <see cref="decimal"/>.</description></item>
/// <item><description><see cref="JsonTokenType.Null"/> produces <see langword="null"/>.</description></item>
/// <item><description><see cref="JsonTokenType.StartObject"/> produces <see cref="Dictionary{TKey,TValue}"/> with <see cref="string"/> keys and <see cref="object"/> values.</description></item>
/// <item><description><see cref="JsonTokenType.StartArray"/> produces <see cref="List{T}"/> of <see cref="object"/>.</description></item>
/// </list>
/// <para>
/// This utility serves the same role as <see cref="JsonElementConversion"/> but operates
/// on <see cref="Utf8JsonReader"/> directly, enabling converters to avoid buffering into
/// <see cref="JsonElement"/>. The CBOR converter system has a parallel
/// <c>ManualCborReader</c> with the same structure.
/// </para>
/// </remarks>
internal static class ManualJsonReader
{
    /// <summary>
    /// Reads a single JSON value from the reader. The reader must be positioned
    /// on the value's first token. For primitives, returns immediately. For objects
    /// and arrays, reads iteratively using a stack.
    /// </summary>
    /// <param name="reader">The reader positioned on the value's first token.</param>
    /// <returns>The converted CLR value, or <see langword="null"/> for JSON null.</returns>
    internal static object? ReadValue(ref Utf8JsonReader reader)
    {
        switch(reader.TokenType)
        {
            case JsonTokenType.String:
            {
                return reader.GetString();
            }
            case JsonTokenType.Number:
            {
                return ReadNumber(ref reader);
            }
            case JsonTokenType.True:
            {
                return true;
            }
            case JsonTokenType.False:
            {
                return false;
            }
            case JsonTokenType.Null:
            {
                return null;
            }
            case JsonTokenType.StartObject:
            case JsonTokenType.StartArray:
            {
                return ReadStructured(ref reader);
            }
            default:
            {
                throw new JsonException($"Unexpected token type '{reader.TokenType}'.");
            }
        }
    }


    /// <summary>
    /// Narrows a JSON number to the smallest fitting CLR integer type,
    /// falling back to <see cref="decimal"/> for non-integer values.
    /// The narrowing order is <see cref="int"/> then <see cref="long"/>
    /// then <see cref="decimal"/>, matching the behavior expected by
    /// consumers that box numeric claims as <see cref="object"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the single source of truth for JSON number narrowing.
    /// <see cref="JsonElementConversion.NarrowNumber"/> performs the same
    /// logic on <see cref="JsonElement"/> values.
    /// </para>
    /// </remarks>
    internal static object ReadNumber(ref Utf8JsonReader reader)
    {
        if(reader.TryGetInt32(out int i))
        {
            return i;
        }

        if(reader.TryGetInt64(out long l))
        {
            return l;
        }

        return reader.GetDecimal();
    }


    /// <summary>
    /// Reads a nested object or array iteratively. The reader must be positioned
    /// on <see cref="JsonTokenType.StartObject"/> or <see cref="JsonTokenType.StartArray"/>.
    /// </summary>
    private static object ReadStructured(ref Utf8JsonReader reader)
    {
        var stack = new Stack<(object Container, string? PendingKey)>();
        object root = NewContainer(reader.TokenType);
        stack.Push((root, null));

        while(reader.Read())
        {
            switch(reader.TokenType)
            {
                case JsonTokenType.PropertyName:
                {
                    var (container, _) = stack.Pop();
                    stack.Push((container, reader.GetString()!));
                    break;
                }
                case JsonTokenType.StartObject:
                case JsonTokenType.StartArray:
                {
                    stack.Push((NewContainer(reader.TokenType), null));
                    break;
                }
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                {
                    var (completed, _) = stack.Pop();

                    if(stack.Count == 0)
                    {
                        return completed;
                    }

                    var (parent, parentKey) = stack.Pop();
                    Add(parent, parentKey, completed);
                    stack.Push((parent, null));
                    break;
                }
                default:
                {
                    object? primitive = ReadPrimitive(ref reader);
                    var (container, key) = stack.Pop();
                    Add(container, key, primitive);
                    stack.Push((container, null));
                    break;
                }
            }
        }

        throw new JsonException("Unexpected end of JSON input.");
    }


    private static object? ReadPrimitive(ref Utf8JsonReader reader)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString(),
            JsonTokenType.Number => ReadNumber(ref reader),
            JsonTokenType.True => true,
            JsonTokenType.False => false,
            JsonTokenType.Null => null,
            _ => throw new JsonException($"Unexpected token type '{reader.TokenType}'.")
        };
    }


    private static object NewContainer(JsonTokenType tokenType)
    {
        return tokenType switch
        {
            JsonTokenType.StartObject => new Dictionary<string, object>(),
            JsonTokenType.StartArray => new List<object>(),
            _ => throw new JsonException($"Expected StartObject or StartArray, got '{tokenType}'.")
        };
    }


    private static void Add(object container, string? key, object? value)
    {
        if(container is Dictionary<string, object> dict)
        {
            if(value is not null && key is not null)
            {
                dict[key] = value;
            }
        }
        else if(container is List<object> list)
        {
            if(value is not null)
            {
                list.Add(value);
            }
        }
    }
}