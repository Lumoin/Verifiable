using System.Collections.Concurrent;
using System.Diagnostics;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// One exchange <see cref="IntrospectionExchangeRecorder"/> passed to its inner handler: the request's method, target,
/// header field lines and form body as sent, and the answer's status, <c>Content-Type</c> and header field lines as
/// received.
/// </summary>
[DebuggerDisplay("IntrospectionExchange {Method} {Target} -> {StatusCode}")]
internal sealed class IntrospectionExchange
{
    /// <summary>The request's method as sent.</summary>
    public required string Method { get; init; }

    /// <summary>The request's target URI as sent.</summary>
    public required Uri Target { get; init; }

    /// <summary>The request's header field lines as sent, its content header lines after the request's own, in order.</summary>
    public required IReadOnlyList<KeyValuePair<string, string>> RequestHeaders { get; init; }

    /// <summary>The request's body text as sent; empty when it carried none.</summary>
    public required string RequestBody { get; init; }

    /// <summary>The answer's status code, or <see langword="null"/> while no answer was received.</summary>
    public int? StatusCode { get; set; }

    /// <summary>The answer's <c>Content-Type</c> field value as received, or <see langword="null"/> when it carried none.</summary>
    public string? ResponseContentType { get; set; }

    /// <summary>The answer's header field lines as received, its content header lines after the answer's own, in order.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> ResponseHeaders { get; set; } = [];


    /// <summary>The values of every request header field line named <paramref name="name"/>, compared case-insensitively.</summary>
    /// <param name="name">The field name.</param>
    /// <returns>The values in the order sent; empty when no such line was sent.</returns>
    public IReadOnlyList<string> RequestHeaderValues(string name) =>
        [.. RequestHeaders.Where(line => string.Equals(line.Key, name, StringComparison.OrdinalIgnoreCase)).Select(static line => line.Value)];


    /// <summary>The values of every answer header field line named <paramref name="name"/>, compared case-insensitively.</summary>
    /// <param name="name">The field name.</param>
    /// <returns>The values in the order received; empty when no such line was received.</returns>
    public IReadOnlyList<string> ResponseHeaderValues(string name) =>
        [.. ResponseHeaders.Where(line => string.Equals(line.Key, name, StringComparison.OrdinalIgnoreCase)).Select(static line => line.Value)];
}


/// <summary>
/// The resource server's recording <see cref="DelegatingHandler"/>: the outermost handler of the resource server's
/// outbound <see cref="HttpClient"/> to the authorization server, recording each request's method, target, header field
/// lines and form body as sent and each answer's status, <c>Content-Type</c> and header field lines as received, then
/// passing the request to its inner handler unchanged. The library reaches it through the infrastructure's
/// <see cref="Verifiable.OAuth.AuthCode.SendFormPostDelegate"/>, composed over
/// <see cref="Verifiable.Tests.OAuth.HttpClientTransport.SendFormPostAsync"/>; the inner handler is the single-hop pinned
/// handler of <see cref="LoopbackTls.CreatePinnedHandler(System.Security.Cryptography.X509Certificates.X509Certificate2)"/>
/// with <see cref="SocketsHttpHandler.AllowAutoRedirect"/> off, so a redirect answer reaches the library as received.
/// </summary>
internal sealed class IntrospectionExchangeRecorder: DelegatingHandler
{
    /// <summary>Every exchange the handler passed on, in the order the requests were sent.</summary>
    public ConcurrentQueue<IntrospectionExchange> Exchanges { get; } = new();


    /// <summary>
    /// Builds the recorder over the single-hop handler pinned to <paramref name="pinnedCertificates"/>, the client the
    /// resource server introspects through.
    /// </summary>
    /// <param name="pinnedCertificates">The certificates of the listeners the client dials.</param>
    /// <returns>The recorder; the caller hands it to an <see cref="HttpClient"/>, which disposes it.</returns>
    public static IntrospectionExchangeRecorder OverPinnedSingleHop(
        IReadOnlyCollection<System.Security.Cryptography.X509Certificates.X509Certificate2> pinnedCertificates)
    {
        SocketsHttpHandler? inner = null;
        try
        {
            inner = LoopbackTls.CreatePinnedHandler(pinnedCertificates);
            inner.AllowAutoRedirect = false;
            IntrospectionExchangeRecorder recorder = new() { InnerHandler = inner };
            inner = null;

            return recorder;
        }
        finally
        {
            //The inner handler not handed on to the recorder is released here.
            inner?.Dispose();
        }
    }


    /// <summary>
    /// Records the request, passes it to the inner handler and records the answer on the same exchange.
    /// </summary>
    /// <param name="request">The request the client sends.</param>
    /// <param name="cancellationToken">Cancellation of the exchange.</param>
    /// <returns>The inner handler's answer, unchanged.</returns>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        string body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        List<KeyValuePair<string, string>> requestLines = [];
        AppendLines(requestLines, request.Headers);
        if(request.Content is not null)
        {
            AppendLines(requestLines, request.Content.Headers);
        }

        IntrospectionExchange exchange = new()
        {
            Method = request.Method.Method,
            Target = request.RequestUri!,
            RequestHeaders = requestLines,
            RequestBody = body
        };
        Exchanges.Enqueue(exchange);

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        List<KeyValuePair<string, string>> responseLines = [];
        AppendLines(responseLines, response.Headers);
        AppendLines(responseLines, response.Content.Headers);
        exchange.StatusCode = (int)response.StatusCode;
        exchange.ResponseContentType = response.Content.Headers.ContentType?.ToString();
        exchange.ResponseHeaders = responseLines;

        return response;
    }


    /// <summary>Appends every field line of <paramref name="headers"/> to <paramref name="lines"/>, one entry per value.</summary>
    /// <param name="lines">The lines appended to.</param>
    /// <param name="headers">The header collection read without validation.</param>
    private static void AppendLines(List<KeyValuePair<string, string>> lines, System.Net.Http.Headers.HttpHeaders headers)
    {
        foreach(KeyValuePair<string, System.Net.Http.Headers.HeaderStringValues> header in headers.NonValidated)
        {
            foreach(string value in header.Value)
            {
                lines.Add(new(header.Key, value));
            }
        }
    }
}
