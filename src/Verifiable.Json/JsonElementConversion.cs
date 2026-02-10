using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Internal utilities for converting between <see cref="JsonElement"/> and CLR types.
/// </summary>
internal static class JsonElementConversion
{
    /// <summary>
    /// Converts a <see cref="JsonElement"/> to a CLR object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The type mapping is:
    /// </para>
    /// <list type="bullet">
    /// <item><description><see cref="JsonValueKind.String"/> -> <see cref="string"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.True"/> and <see cref="JsonValueKind.False"/> -> <see cref="bool"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.Number"/> -> <see cref="long"/> if representable, otherwise <see cref="decimal"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.Null"/> -> <see langword="null"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.Object"/> -> <see cref="Dictionary{TKey,TValue}"/> of string to object.</description></item>
    /// <item><description><see cref="JsonValueKind.Array"/> -> <see cref="List{T}"/> of object.</description></item>
    /// </list>
    /// </remarks>
    internal static object? Convert(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Number => element.TryGetInt64(out long l) ? (object)l : element.GetDecimal(),
            JsonValueKind.Object => ConvertObject(element),
            JsonValueKind.Array => ConvertArray(element),
            _ => throw new NotSupportedException($"Unsupported JSON value kind: {element.ValueKind}.")
        };
    }


    private static Dictionary<string, object?> ConvertObject(JsonElement element)
    {
        var dict = new Dictionary<string, object?>();
        foreach(JsonProperty prop in element.EnumerateObject())
        {
            dict[prop.Name] = Convert(prop.Value);
        }

        return dict;
    }


    private static List<object?> ConvertArray(JsonElement element)
    {
        var list = new List<object?>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            list.Add(Convert(item));
        }

        return list;
    }
}