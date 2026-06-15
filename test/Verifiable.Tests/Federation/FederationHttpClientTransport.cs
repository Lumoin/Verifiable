using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// HttpClient-backed implementations of the federation HTTP delegate
/// types (B.5.1). Lives in the test project per the project's
/// transport-agnostic library discipline: the
/// <c>Verifiable.OAuth.Federation</c> library defines delegate signatures
/// only; concrete <see cref="HttpClient"/> wiring is application or test
/// code. <see cref="HttpClientTransport"/> (under <c>OAuth/</c>) is the
/// precedent for the OAuth client surface; this is its federation peer.
/// </summary>
/// <remarks>
/// <para>
/// Static methods so the test fixture composes them as delegate values
/// by closing over the shared <see cref="HttpClient"/>. No retry,
/// redirect-following, caching, or auth policy is wrapped — real
/// deployments add those at their HTTP client factory layer.
/// </para>
/// </remarks>
internal static class FederationHttpClientTransport
{
    /// <summary>
    /// Builds a <see cref="FetchEntityStatementDelegate"/> that GETs the
    /// entity statement JWS from <paramref name="fetchEndpoint"/> with the
    /// subject in the <c>sub</c> query parameter per §8.1.
    /// </summary>
    public static FetchEntityStatementDelegate BuildFetchEntityStatement(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);

        //The HttpClient is the single-hop transport: a bare custom HttpMessageHandler
        //does not auto-redirect, and a real handler would set AllowAutoRedirect=false.
        //OutboundFetch owns the redirect loop and re-checks every hop against the policy.
        OutboundTransportDelegate transport = async (request, context, cancellationToken) =>
        {
            using HttpRequestMessage httpRequest = new(new HttpMethod(request.Method), request.Target);

            using HttpResponseMessage httpResponse = await httpClient
                .SendAsync(httpRequest, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);

            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
            if(httpResponse.Headers.Location is Uri location)
            {
                headers["Location"] = location.OriginalString;
            }

            byte[] body = await httpResponse.Content
                .ReadAsByteArrayAsync(cancellationToken)
                .ConfigureAwait(false);

            return new OutboundResponse
            {
                StatusCode = (int)httpResponse.StatusCode,
                Headers = headers,
                Body = new TaggedMemory<byte>(body, Tag.Empty),
            };
        };

        return async (subject, fetchEndpoint, context, cancellationToken) =>
        {
            UriBuilder builder = new(fetchEndpoint)
            {
                Query = $"sub={Uri.EscapeDataString(subject.Value)}",
            };

            OutboundRequest request = new() { Target = builder.Uri, Method = "GET" };

            OutboundFetchResult result = await OutboundFetch
                .FetchAsync(request, context, transport, cancellationToken)
                .ConfigureAwait(false);

            if(!result.IsFetched
                || result.Response is not { } response
                || response.StatusCode is < 200 or > 299)
            {
                return null;
            }

            string compactJws = Encoding.UTF8.GetString(response.Body.Span);
            return string.IsNullOrWhiteSpace(compactJws) ? null : TryParseFetchedStatement(compactJws);
        };
    }


    /// <summary>
    /// Parses a compact JWS string into a <see cref="FetchedEntityStatement"/>
    /// using the test infrastructure's encoders and System.Text.Json. The
    /// shape mirrors what an application's fetch delegate does end-to-end;
    /// extracted so tests that supply a JWS directly (rather than over
    /// HTTP) can compose with the same parsing path.
    /// </summary>
    public static FetchedEntityStatement? TryParseFetchedStatement(string compactJws)
    {
        ArgumentException.ThrowIfNullOrEmpty(compactJws);

        string[] parts = compactJws.Split('.');
        if(parts.Length != 3
            || string.IsNullOrEmpty(parts[0])
            || string.IsNullOrEmpty(parts[1])
            || string.IsNullOrEmpty(parts[2]))
        {
            return null;
        }

        Dictionary<string, object> headerDict;
        Dictionary<string, object> payloadDict;
        try
        {
            using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(
                parts[0], BaseMemoryPool.Shared);
            using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(
                parts[1], BaseMemoryPool.Shared);
            headerDict = DecodeJsonObject(headerBytes.Memory.Span);
            payloadDict = DecodeJsonObject(payloadBytes.Memory.Span);
        }
        catch
        {
            return null;
        }

        UnverifiedJwtHeader header = new(headerDict);
        UnverifiedJwtPayload payload = new(payloadDict);
        EntityStatementParseResult parseResult = EntityStatementParser.Parse(header, payload);
        return parseResult.Statement is null
            ? null
            : new FetchedEntityStatement(parseResult.Statement, header, compactJws);
    }


    private static Dictionary<string, object> DecodeJsonObject(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        using JsonDocument document = JsonDocument.Parse(json);
        Dictionary<string, object> result = new(StringComparer.Ordinal);
        foreach(JsonProperty property in document.RootElement.EnumerateObject())
        {
            object? value = ConvertJsonElement(property.Value);
            if(value is not null)
            {
                result[property.Name] = value;
            }
        }
        return result;
    }


    private static object? ConvertJsonElement(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number when element.TryGetInt64(out long l) => l,
        JsonValueKind.Number => element.GetDouble(),
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
        foreach(JsonProperty property in element.EnumerateObject())
        {
            object? value = ConvertJsonElement(property.Value);
            if(value is not null)
            {
                dict[property.Name] = value;
            }
        }
        return dict;
    }
}
