using System;
using System.Collections.Generic;
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
    /// <para>
    /// Exponent notation (<c>1e2</c>) and a signed zero (<c>-0</c>) both parse successfully and
    /// normalize to their plain decimal value — <see cref="decimal"/> has no distinct negative-zero
    /// representation, and the exponent is applied rather than preserved lexically. An inline
    /// JSON-LD <c>@context</c> definition is an arbitrary JSON object (its own IRI/term-definition
    /// members aside, nothing constrains what a member's value may be), so this narrowing applies
    /// there too when a definition happens to carry a number: the lexical exponent/signed-zero form
    /// is not preserved on that path either. This is harmless for a cryptosuite like
    /// <c>eddsa-jcs-2022</c>, whose RFC 8785 JCS canonicalization normalizes numbers before signing
    /// regardless, but is a real deviation for any caller expecting byte-for-byte re-emission of an
    /// inline definition's numeric members. It matters identically to every other caller that
    /// materializes an arbitrary JSON object, such as <c>DidDocument.AdditionalData</c>.
    /// </para>
    /// </remarks>
    /// <exception cref="JsonException">
    /// Thrown when the number's text is beyond <see cref="decimal"/>'s representable range — a
    /// malformed-input condition, not a CLR formatting bug, so it is never a <see cref="FormatException"/>.
    /// </exception>
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

        try
        {
            return reader.GetDecimal();
        }
        catch(FormatException exception)
        {
            throw new JsonException("The JSON number is outside the range decimal can represent.", exception);
        }
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


    /// <summary>
    /// Adds a completed member or element to its parent container. A JSON <see langword="null"/> is
    /// data, not absence — <c>{"@vocab": null}</c> is JSON-LD 1.1's way to clear <c>@vocab</c>/<c>@base</c>
    /// or remove a term, and <c>{"a":[1,null]}</c> is an ordinary array element — so
    /// <paramref name="value"/> is stored even when <see langword="null"/>, exactly like every other
    /// value; the CLR permits a <see langword="null"/> reference in an <see cref="object"/>-typed slot
    /// regardless of the non-nullable annotation on <see cref="Dictionary{TKey, TValue}"/>'s and
    /// <see cref="List{T}"/>'s type argument, which is why the null-forgiving operator is used here
    /// rather than widening that argument across every consumer of this materialized shape.
    /// </summary>
    /// <param name="container">The parent <see cref="Dictionary{TKey, TValue}"/> or <see cref="List{T}"/>.</param>
    /// <param name="key">The member name when <paramref name="container"/> is a dictionary; otherwise <see langword="null"/>.</param>
    /// <param name="value">The value to add, which may be <see langword="null"/>.</param>
    private static void Add(object container, string? key, object? value)
    {
        _ = container switch
        {
            Dictionary<string, object> dict when key is not null => TryAddMember(dict, key, value),
            List<object> list => TryAddElement(list, value),
            _ => false
        };
    }


    /// <summary>
    /// Sets <paramref name="value"/> under <paramref name="key"/> in <paramref name="dictionary"/>, using the
    /// null-forgiving operator because a JSON <see langword="null"/> is a valid stored value even though
    /// <see cref="Dictionary{TKey, TValue}"/>'s type argument is non-nullable.
    /// </summary>
    /// <param name="dictionary">The dictionary to add the member to.</param>
    /// <param name="key">The member name.</param>
    /// <param name="value">The value to store, which may be <see langword="null"/>.</param>
    /// <returns><see langword="true"/>, unconditionally, so this can serve as a switch expression arm.</returns>
    private static bool TryAddMember(Dictionary<string, object> dictionary, string key, object? value)
    {
        dictionary[key] = value!;

        return true;
    }


    /// <summary>
    /// Appends <paramref name="value"/> to <paramref name="list"/>, using the null-forgiving operator because
    /// a JSON <see langword="null"/> is a valid array element even though <see cref="List{T}"/>'s type
    /// argument is non-nullable.
    /// </summary>
    /// <param name="list">The list to add the element to.</param>
    /// <param name="value">The value to store, which may be <see langword="null"/>.</param>
    /// <returns><see langword="true"/>, unconditionally, so this can serve as a switch expression arm.</returns>
    private static bool TryAddElement(List<object> list, object? value)
    {
        list.Add(value!);

        return true;
    }
}
