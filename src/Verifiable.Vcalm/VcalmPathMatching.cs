using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.Vcalm;

/// <summary>
/// Shared path matchers for the W3C VCALM 1.0 collection-style endpoints — a POST to a collection path
/// exactly (<c>POST /workflows</c>, the §3.6.3 <c>POST .../exchanges</c> collection), and a method to a
/// collection path plus a single trailing <c>{id}</c> segment (<c>GET /workflows/{id}</c>, the §3.6.7
/// <c>POST /callbacks/{id}</c>). The id is parsed from the trailing path segment when a skin handed the
/// raw path through, or read from a skin's <see cref="RouteValues"/> when it did template routing.
/// </summary>
[DebuggerDisplay("VcalmPathMatching")]
public static class VcalmPathMatching
{
    /// <summary>
    /// Matches the given method to this endpoint's resolved collection path exactly (no trailing id
    /// segment). Returns <see cref="MatchPayload.Empty"/> on a match, or <see langword="null"/> otherwise.
    /// </summary>
    public static ValueTask<MatchPayload?> MatchExactCollection(
        ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(endpoint);

        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
    }


    /// <summary>
    /// Matches the given method to this endpoint's resolved collection path plus a single non-empty
    /// trailing <c>{id}</c> segment. Returns a <see cref="VcalmCollectionItemMatchPayload"/> carrying the
    /// extracted id on a match, or <see langword="null"/> otherwise.
    /// </summary>
    public static ValueTask<MatchPayload?> MatchCollectionItem(
        ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(endpoint);

        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!TryExtractItemId(req.Path, endpoint.ResolvedUri.AbsolutePath, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmCollectionItemMatchPayload(idSegment));
    }


    /// <summary>
    /// Reads the trailing <c>{id}</c> the matcher extracted from a <see cref="VcalmCollectionItemMatchPayload"/>
    /// (URL-unescaped), honouring a skin's <see cref="RouteValues"/> entry under
    /// <paramref name="routeParameterName"/> first. Returns <see langword="null"/> when neither carries one.
    /// </summary>
    public static string? ExtractItemId(ExchangeContext context, string routeParameterName)
    {
        ArgumentNullException.ThrowIfNull(context);

        if(context.MatchPayload is VcalmCollectionItemMatchPayload payload && !string.IsNullOrEmpty(payload.ItemId))
        {
            return Uri.UnescapeDataString(payload.ItemId);
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is not null
            && req.RouteValues.TryGetValue(routeParameterName, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return routeValue;
        }

        return null;
    }


    //Whether requestPath equals collectionPath + "/" + {id}, with {id} a single non-empty segment.
    //Strips query / fragment and a trailing slash first.
    private static bool TryExtractItemId(string requestPath, string collectionPath, out string idSegment)
    {
        idSegment = string.Empty;

        ReadOnlySpan<char> pathSpan = requestPath.AsSpan();
        int queryStart = pathSpan.IndexOf('?');
        if(queryStart >= 0) { pathSpan = pathSpan[..queryStart]; }

        int fragmentStart = pathSpan.IndexOf('#');
        if(fragmentStart >= 0) { pathSpan = pathSpan[..fragmentStart]; }

        ReadOnlySpan<char> collectionSpan = collectionPath.AsSpan();
        if(collectionSpan.Length > 1 && collectionSpan[^1] == '/')
        {
            collectionSpan = collectionSpan[..^1];
        }

        if(pathSpan.Length <= collectionSpan.Length + 1)
        {
            return false;
        }

        if(!pathSpan[..collectionSpan.Length].SequenceEqual(collectionSpan) || pathSpan[collectionSpan.Length] != '/')
        {
            return false;
        }

        ReadOnlySpan<char> tail = pathSpan[(collectionSpan.Length + 1)..];
        if(tail.Length > 0 && tail[^1] == '/')
        {
            tail = tail[..^1];
        }

        if(tail.Length == 0 || tail.Contains('/'))
        {
            return false;
        }

        idSegment = tail.ToString();

        return true;
    }
}


/// <summary>
/// The match payload a collection-item matcher carries: the trailing <c>{id}</c> segment it extracted
/// from the request path, for the handler to read.
/// </summary>
/// <param name="ItemId">The URL-escaped trailing id segment.</param>
public sealed record VcalmCollectionItemMatchPayload(string ItemId): MatchPayload;
