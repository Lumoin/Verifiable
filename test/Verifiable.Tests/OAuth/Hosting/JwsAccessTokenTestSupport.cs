using System.Text.Json;
using Verifiable.JCose;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth.Hosting;

/// <summary>
/// System.Text.Json-backed <see cref="JwsAccessTokenJsonParser"/> for the
/// resource-server test infrastructure. Parallel of
/// <see cref="Verifiable.Tests.OAuth.Dpop.DpopTestSupport"/> for the
/// access-token side.
/// </summary>
internal static class JwsAccessTokenTestSupport
{
    public static JwsAccessTokenJsonParser Parser { get; } = new()
    {
        ParseHeader = ParseHeaderJson,
        ParseClaims = ParseClaimsJson
    };


    private static JwtHeader ParseHeaderJson(ReadOnlyMemory<byte> bytes)
    {
        using JsonDocument doc = JsonDocument.Parse(bytes);
        JwtHeader header = new(capacity: 4);
        foreach(JsonProperty prop in doc.RootElement.EnumerateObject())
        {
            object? value = ConvertJsonElement(prop.Value);
            if(value is not null)
            {
                header[prop.Name] = value;
            }
        }
        return header;
    }


    private static JwtPayload ParseClaimsJson(ReadOnlyMemory<byte> bytes)
    {
        using JsonDocument doc = JsonDocument.Parse(bytes);
        JwtPayload payload = new(capacity: 8);
        foreach(JsonProperty prop in doc.RootElement.EnumerateObject())
        {
            object? value = ConvertJsonElement(prop.Value);
            if(value is not null)
            {
                payload[prop.Name] = value;
            }
        }
        return payload;
    }


    private static object? ConvertJsonElement(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number => element.TryGetInt64(out long l) ? l : element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Array => ConvertArray(element),
        JsonValueKind.Object => ConvertObject(element),
        _ => null,
    };


    private static List<object> ConvertArray(JsonElement element)
    {
        List<object> list = [];
        foreach(JsonElement item in element.EnumerateArray())
        {
            object? value = ConvertJsonElement(item);
            if(value is not null)
            {
                list.Add(value);
            }
        }
        return list;
    }


    private static Dictionary<string, object> ConvertObject(JsonElement element)
    {
        Dictionary<string, object> dict = new(StringComparer.Ordinal);
        foreach(JsonProperty prop in element.EnumerateObject())
        {
            object? value = ConvertJsonElement(prop.Value);
            if(value is not null)
            {
                dict[prop.Name] = value;
            }
        }
        return dict;
    }
}
