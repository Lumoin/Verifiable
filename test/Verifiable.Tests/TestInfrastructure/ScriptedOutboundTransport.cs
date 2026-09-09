using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.OutboundFetch;
using Verifiable.Foundation;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A single scripted answer <see cref="ScriptedOutboundTransport"/> returns for one absolute request URL.
/// </summary>
internal sealed record ScriptedOutboundResponse
{
    /// <summary>The HTTP status code to answer with.</summary>
    public required int Status { get; init; }

    /// <summary>The response's fields. Defaults to <see cref="HttpHeaderSet.Empty"/>.</summary>
    public HttpHeaderSet Headers { get; init; } = HttpHeaderSet.Empty;

    /// <summary>The response body. Defaults to <see cref="TaggedMemory{T}.Empty"/>.</summary>
    public TaggedMemory<byte> Body { get; init; } = TaggedMemory<byte>.Empty;


    /// <summary>The answer an unscripted URL receives: a fieldless, bodyless 200.</summary>
    public static ScriptedOutboundResponse Default { get; } = new() { Status = 200 };


    /// <summary>A bare status code with no fields and no body.</summary>
    /// <param name="status">The HTTP status code.</param>
    public static ScriptedOutboundResponse WithStatus(int status) =>
        new() { Status = status };


    /// <summary>A redirect: <paramref name="status"/> carrying a <c>Location</c> field naming <paramref name="location"/>.</summary>
    /// <param name="status">The redirect's HTTP status code.</param>
    /// <param name="location">The <c>Location</c> field's value.</param>
    public static ScriptedOutboundResponse RedirectTo(int status, string location) =>
        new() { Status = status, Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.Location, location)) };


    /// <summary><paramref name="status"/> carrying <paramref name="headers"/>, with no body.</summary>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="headers">The response's fields.</param>
    public static ScriptedOutboundResponse WithHeaders(int status, HttpHeaderSet headers) =>
        new() { Status = status, Headers = headers };


    /// <summary><paramref name="status"/> carrying <paramref name="headers"/> and <paramref name="body"/>.</summary>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="headers">The response's fields.</param>
    /// <param name="body">The response body.</param>
    public static ScriptedOutboundResponse WithBody(int status, HttpHeaderSet headers, TaggedMemory<byte> body) =>
        new() { Status = status, Headers = headers, Body = body };
}


/// <summary>
/// A canned, single-hop <see cref="OutboundTransportDelegate"/> whose answers are scripted per absolute
/// request URL, recording every request it receives so a test can assert on what the guarded fetch
/// (<see cref="OutboundFetch"/>) sent. The one shared canned transport every <c>Verifiable.Tests</c> unit
/// test scripting an <see cref="OutboundTransportDelegate"/> extends, rather than re-minting a file-private
/// twin.
/// </summary>
internal sealed class ScriptedOutboundTransport
{
    /// <summary>The scripted answer per absolute request URL.</summary>
    private Dictionary<string, ScriptedOutboundResponse> Routes { get; }


    /// <summary>Creates a transport that answers every URL with <see cref="ScriptedOutboundResponse.Default"/>.</summary>
    public ScriptedOutboundTransport(): this(new Dictionary<string, ScriptedOutboundResponse>(StringComparer.Ordinal))
    {
    }


    /// <summary>Creates a transport with scripted answers.</summary>
    /// <param name="routes">Absolute request URL to the answer it receives.</param>
    public ScriptedOutboundTransport(Dictionary<string, ScriptedOutboundResponse> routes)
    {
        this.Routes = routes;
    }


    /// <summary>Every request the transport was handed, in call order.</summary>
    public List<OutboundRequest> Calls { get; } = [];


    /// <summary>The transport seam the guarded fetch drives.</summary>
    public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
    {
        Calls.Add(request);

        ScriptedOutboundResponse route = Routes.TryGetValue(request.Target.AbsoluteUri, out ScriptedOutboundResponse? scripted)
            ? scripted
            : ScriptedOutboundResponse.Default;

        return ValueTask.FromResult(new OutboundResponse
        {
            StatusCode = route.Status,
            Headers = route.Headers,
            Body = route.Body,
        });
    };
}
