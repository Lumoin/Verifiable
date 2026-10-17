using System.Diagnostics;
using System.Globalization;
using Verifiable.Server.Diagnostics;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The application's HTTP client span, one per attempt to send a request over the wire, on
/// <see cref="SampleTracing.Source"/>, in the OpenTelemetry vocabulary
/// (<see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for HTTP
/// spans</see>: "Instrumentations SHOULD create an HTTP span for each attempt to send an HTTP request over the wire." and
/// "Span kind MUST be CLIENT."). The span is named by the method ("If there is no (low-cardinality) {target} available,
/// HTTP span names SHOULD be {method}."), carries <c>http.request.method</c>, <c>server.address</c>, <c>server.port</c>
/// and <c>url.full</c> from its start ("The following attributes can be important for making sampling decisions and
/// SHOULD be provided at span creation time"), and <c>http.response.status_code</c> once the answer is read; an answer
/// of 400 or above sets <c>error.type</c> to the status code and the status <c>Error</c> ("For HTTP status codes in the
/// 4xx range span status MUST be left unset in case of SpanKind.SERVER and SHOULD be set to Error in case of
/// SpanKind.CLIENT."), a failure before an answer sets <c>error.type</c> to the exception's fully-qualified type name and
/// the status <c>Error</c>, and a cancellation by the caller's token leaves both unset ("the cancellation SHOULD NOT be
/// treated as an error"). No header value and no body is recorded.
/// </summary>
internal sealed class HttpClientSpanHandler: DelegatingHandler
{
    /// <summary>The OpenTelemetry attribute of the request method.</summary>
    private static string HttpRequestMethodTagName => "http.request.method";

    /// <summary>The OpenTelemetry attribute of the server's host.</summary>
    private static string ServerAddressTagName => "server.address";

    /// <summary>The OpenTelemetry attribute of the server's port.</summary>
    private static string ServerPortTagName => "server.port";

    /// <summary>The OpenTelemetry attribute of the absolute request URL.</summary>
    private static string UrlFullTagName => "url.full";

    /// <summary>The OpenTelemetry attribute of the response status code.</summary>
    private static string HttpResponseStatusCodeTagName => "http.response.status_code";


    /// <summary>Sends one attempt of <paramref name="request"/> under its CLIENT span and completes the span with the answer.</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">The caller's cancellation.</param>
    /// <returns>The answer.</returns>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Uri target = request.RequestUri ?? throw new InvalidOperationException("The request names no URI.");
        string method = request.Method.Method;
        ActivityTagsCollection startTags = new()
        {
            [HttpRequestMethodTagName] = method,
            [ServerAddressTagName] = target.Host,
            [ServerPortTagName] = target.Port,
            [UrlFullTagName] = target.GetComponents(UriComponents.AbsoluteUri & ~UriComponents.UserInfo, UriFormat.UriEscaped)
        };

        using Activity? span = SampleTracing.Source.StartActivity(method, ActivityKind.Client, parentContext: default, startTags);
        try
        {
            HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            int statusCode = (int)response.StatusCode;
            _ = span?.SetTag(HttpResponseStatusCodeTagName, statusCode);
            if(statusCode >= 400)
            {
                _ = span?.SetTag(ServerTagNames.ErrorType, statusCode.ToString(CultureInfo.InvariantCulture));
                _ = span?.SetStatus(ActivityStatusCode.Error);
            }

            return response;
        }
        catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch(Exception exception)
        {
            _ = span?.SetTag(ServerTagNames.ErrorType, exception.GetType().FullName);
            _ = span?.SetStatus(ActivityStatusCode.Error);
            throw;
        }
    }
}
