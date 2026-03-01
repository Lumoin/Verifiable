using System.Collections.Generic;
using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Writes CLR primitives, dictionaries, and lists to a <see cref="Utf8JsonWriter"/>
/// without calling <see cref="JsonSerializer"/>. Uses an explicit stack for nested structures.
/// </summary>
/// <remarks>
/// <para>
/// The supported type mapping is the inverse of <see cref="ManualJsonReader"/>:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="string"/> writes as a JSON string.</description></item>
/// <item><description><see cref="bool"/> writes as JSON true or false.</description></item>
/// <item><description><see cref="int"/>, <see cref="long"/>, <see cref="float"/>, <see cref="double"/>, and <see cref="decimal"/> write as JSON numbers.</description></item>
/// <item><description><see langword="null"/> writes as JSON null.</description></item>
/// <item><description><see cref="IDictionary{TKey,TValue}"/> writes as a JSON object.</description></item>
/// <item><description><see cref="IList{T}"/> writes as a JSON array.</description></item>
/// <item><description><see cref="JsonElement"/> writes directly via <see cref="JsonElement.WriteTo"/>.</description></item>
/// </list>
/// <para>
/// The CBOR converter system has a parallel <c>ManualCborWriter</c> with the same structure.
/// </para>
/// </remarks>
internal static class ManualJsonWriter
{
    /// <summary>
    /// Writes a single value. For primitives, writes directly. For dictionaries and lists,
    /// iterates using a stack.
    /// </summary>
    /// <param name="writer">The writer to write to.</param>
    /// <param name="value">The value to write.</param>
    internal static void WriteValue(Utf8JsonWriter writer, object? value)
    {
        if(WritePrimitive(writer, value))
        {
            return;
        }

        WriteStructured(writer, value!);
    }


    /// <summary>
    /// Writes a dictionary as a JSON object. Convenience entry point for callers
    /// that already know the value is a dictionary.
    /// </summary>
    /// <param name="writer">The writer to write to.</param>
    /// <param name="dictionary">The dictionary to write.</param>
    internal static void WriteObject(Utf8JsonWriter writer, IDictionary<string, object> dictionary)
    {
        WriteValue(writer, dictionary);
    }


    /// <summary>
    /// Attempts to write a primitive value. Returns <see langword="true"/> if the value
    /// was a primitive and was written, <see langword="false"/> if it is a structured
    /// type that needs stack-based iteration.
    /// </summary>
    private static bool WritePrimitive(Utf8JsonWriter writer, object? value)
    {
        switch(value)
        {
            case null:
            {
                writer.WriteNullValue();
                return true;
            }
            case string s:
            {
                writer.WriteStringValue(s);
                return true;
            }
            case bool b:
            {
                writer.WriteBooleanValue(b);
                return true;
            }
            case int i:
            {
                writer.WriteNumberValue(i);
                return true;
            }
            case long l:
            {
                writer.WriteNumberValue(l);
                return true;
            }
            case float f:
            {
                writer.WriteNumberValue(f);
                return true;
            }
            case double d:
            {
                writer.WriteNumberValue(d);
                return true;
            }
            case decimal m:
            {
                writer.WriteNumberValue(m);
                return true;
            }
            case JsonElement jsonElement:
            {
                jsonElement.WriteTo(writer);
                return true;
            }
            default:
            {
                return false;
            }
        }
    }


    /// <summary>
    /// Writes a structured value (dictionary or list) iteratively using a stack.
    /// Each stack entry holds an enumerator and a flag indicating whether the
    /// container is an object (for correct closing).
    /// </summary>
    private static void WriteStructured(Utf8JsonWriter writer, object value)
    {
        var stack = new Stack<(IEnumerator<(string? Key, object? Value)> Enumerator, bool IsObject)>();
        bool isObject = value is IDictionary<string, object>;
        stack.Push((Enumerate(value), isObject));

        if(isObject)
        {
            writer.WriteStartObject();
        }
        else
        {
            writer.WriteStartArray();
        }

        while(stack.Count > 0)
        {
            var (enumerator, containerIsObject) = stack.Peek();

            if(!enumerator.MoveNext())
            {
                enumerator.Dispose();
                stack.Pop();

                if(containerIsObject)
                {
                    writer.WriteEndObject();
                }
                else
                {
                    writer.WriteEndArray();
                }

                continue;
            }

            var (key, childValue) = enumerator.Current;

            if(key is not null)
            {
                writer.WritePropertyName(key);
            }

            if(WritePrimitive(writer, childValue))
            {
                continue;
            }

            //Nested container — push its enumerator and open it.
            bool childIsObject = childValue is IDictionary<string, object>;
            stack.Push((Enumerate(childValue!), childIsObject));

            if(childIsObject)
            {
                writer.WriteStartObject();
            }
            else
            {
                writer.WriteStartArray();
            }
        }
    }


    /// <summary>
    /// Creates a uniform enumerator over a container's elements, yielding
    /// <c>(key, value)</c> pairs. For lists, key is <see langword="null"/>.
    /// </summary>
    private static IEnumerator<(string? Key, object? Value)> Enumerate(object container)
    {
        return container switch
        {
            IDictionary<string, object> dict => EnumerateDict(dict),
            System.Collections.IEnumerable enumerable => EnumerateUntyped(enumerable),
            _ => throw new NotSupportedException($"Type '{container.GetType()}' is not a supported JSON container.")
        };
    }


    private static IEnumerator<(string? Key, object? Value)> EnumerateDict(IDictionary<string, object> dict)
    {
        foreach(var kvp in dict)
        {
            yield return (kvp.Key, kvp.Value);
        }
    }


    private static IEnumerator<(string? Key, object? Value)> EnumerateUntyped(System.Collections.IEnumerable enumerable)
    {
        foreach(object? item in enumerable)
        {
            yield return (null, item);
        }
    }
}