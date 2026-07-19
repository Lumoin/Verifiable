using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Policy-guarded <see cref="HttpClient"/>-backed implementations of the OAuth
/// client transport delegates: every dereference routes through
/// <see cref="OutboundFetch.FetchAsync"/>, which reads the
/// <see cref="OutboundFetchPolicy"/> from the per-call
/// <see cref="ExchangeContext"/> and owns the redirect loop with per-hop
/// re-validation. The wallet/OAuth peer of
/// <see cref="Federation.FederationHttpClientTransport"/>: where the plain
/// <see cref="OAuth.HttpClientTransport"/> sends directly (fine for endpoints
/// the deployment itself configured), this exemplar is for targets that arrive
/// in semi-trusted data — above all the OID4VP <c>request_uri</c>, which an
/// authorization request (QR code, deep link) hands to the wallet for
/// dereferencing: the classic wallet SSRF vector.
/// </summary>
/// <remarks>
/// Lives in the test project per the transport-agnostic library discipline:
/// the libraries define delegate signatures only; concrete HttpClient wiring
/// is application or test code. The inner client is the single-hop transport —
/// a real deployment uses a handler with <c>AllowAutoRedirect = false</c> (and
/// the connection-time pinning of <see cref="SsrfHardenedTransport"/>) so the
/// chokepoint, not the handler, decides every hop.
/// </remarks>
internal static class GuardedHttpClientTransport
{
    /// <summary>The transport-metadata key carrying the non-fetched outcome name.</summary>
    public const string OutcomeMetadataKey = "outboundFetchOutcome";

    /// <summary>The transport-metadata key carrying the policy deny reason.</summary>
    public const string DenyReasonMetadataKey = "outboundFetchDenyReason";

    /// <summary>
    /// The W3C Trace Context response header whose value is copied into
    /// <see cref="HttpResponseData.TransportMetadata"/> under
    /// <see cref="HttpResponseDataKeys.TraceParent"/>.
    /// </summary>
    private const string TraceParentHeaderName = "traceparent";

    /// <summary>
    /// The W3C Trace Context response header whose value is copied into
    /// <see cref="HttpResponseData.TransportMetadata"/> under
    /// <see cref="HttpResponseDataKeys.TraceState"/>.
    /// </summary>
    private const string TraceStateHeaderName = "tracestate";


    /// <summary>
    /// Builds a <see cref="SendFormPostDelegate"/> that routes the POST through
    /// the policy-guarded chokepoint. A target the policy denies never reaches
    /// the network; the failure surfaces as a non-success
    /// <see cref="HttpResponseData"/> (status <c>0</c>) carrying the outcome and
    /// deny reason in <see cref="HttpResponseData.TransportMetadata"/>, which the
    /// client flows treat like any transport failure — fail closed, no throw.
    /// </summary>
    public static SendFormPostDelegate BuildGuardedFormPost(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);

        OutboundTransportDelegate transport = BuildSingleHopTransport(httpClient);

        return async (endpoint, formFields, headers, context, cancellationToken) =>
        {
            var encoded = new StringBuilder();
            foreach(KeyValuePair<string, string> field in formFields)
            {
                if(encoded.Length > 0)
                {
                    encoded.Append('&');
                }

                encoded.Append(Uri.EscapeDataString(field.Key));
                encoded.Append('=');
                encoded.Append(Uri.EscapeDataString(field.Value));
            }

            Dictionary<string, string> requestHeaders = new(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/x-www-form-urlencoded"
            };
            foreach(KeyValuePair<string, string> header in headers.Values)
            {
                requestHeaders[header.Key] = header.Value;
            }

            OutboundRequest request = new()
            {
                Target = endpoint,
                Method = "POST",
                Headers = requestHeaders,
                Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(encoded.ToString()), Tag.Empty)
            };

            OutboundFetchResult result = await OutboundFetch
                .FetchAsync(request, context, transport, cancellationToken)
                .ConfigureAwait(false);

            if(!result.IsFetched || result.Response is not { } response)
            {
                return new HttpResponseData
                {
                    Body = string.Empty,
                    StatusCode = 0,
                    TransportMetadata = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [OutcomeMetadataKey] = result.Outcome.ToString(),
                        [DenyReasonMetadataKey] = result.DenyReason ?? string.Empty
                    }
                };
            }

            ImmutableDictionary<string, string>.Builder headerBuilder =
                ImmutableDictionary.CreateBuilder<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach(KeyValuePair<string, string> header in response.Headers)
            {
                headerBuilder[header.Key] = header.Value;
            }

            //W3C Trace Context response headers are lifted into TransportMetadata under
            //the documented HttpResponseDataKeys constants so that
            //OAuthParseError.WithTransportMetadata can surface the server's trace
            //identity as the DecisionSupport correlation id — the same mapping the
            //plain OAuth.HttpClientTransport performs. A server sends these headers
            //only when its deployment chooses to echo trace context on responses;
            //when absent, TransportMetadata stays null.
            Dictionary<string, string>? transportMetadata = null;
            if(headerBuilder.TryGetValue(TraceParentHeaderName, out string? traceParent))
            {
                transportMetadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [HttpResponseDataKeys.TraceParent] = traceParent
                };
            }

            if(headerBuilder.TryGetValue(TraceStateHeaderName, out string? traceState))
            {
                transportMetadata ??= new Dictionary<string, string>(StringComparer.Ordinal);
                transportMetadata[HttpResponseDataKeys.TraceState] = traceState;
            }

            return new HttpResponseData
            {
                Body = Encoding.UTF8.GetString(response.Body.Span),
                StatusCode = response.StatusCode,
                TransportMetadata = transportMetadata,
                Headers = new ResponseHeaders { Values = headerBuilder.ToImmutable() }
            };
        };
    }


    /// <summary>
    /// Wraps the <see cref="HttpClient"/> as the single-hop
    /// <see cref="OutboundTransportDelegate"/> the chokepoint drives: one
    /// request, no redirect following here — <see cref="OutboundFetch.FetchAsync"/>
    /// owns the loop and re-checks every hop against the policy.
    /// </summary>
    public static OutboundTransportDelegate BuildSingleHopTransport(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);

        return async (request, context, cancellationToken) =>
        {
            using HttpRequestMessage httpRequest = new(new HttpMethod(request.Method), request.Target);

            if(request.Body is { } body)
            {
                httpRequest.Content = new ByteArrayContent(body.Memory.ToArray());
            }

            foreach(KeyValuePair<string, string> header in request.Headers)
            {
                if(!httpRequest.Headers.TryAddWithoutValidation(header.Key, header.Value)
                    && httpRequest.Content is not null)
                {
                    httpRequest.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            using HttpResponseMessage httpResponse = await httpClient
                .SendAsync(httpRequest, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);

            Dictionary<string, string> responseHeaders = new(StringComparer.OrdinalIgnoreCase);
            foreach(KeyValuePair<string, IEnumerable<string>> header in httpResponse.Headers)
            {
                responseHeaders[header.Key] = string.Join(", ", header.Value);
            }

            foreach(KeyValuePair<string, IEnumerable<string>> header in httpResponse.Content.Headers)
            {
                responseHeaders[header.Key] = string.Join(", ", header.Value);
            }

            byte[] responseBody = await httpResponse.Content
                .ReadAsByteArrayAsync(cancellationToken)
                .ConfigureAwait(false);

            return new OutboundResponse
            {
                StatusCode = (int)httpResponse.StatusCode,
                Headers = responseHeaders,
                Body = new TaggedMemory<byte>(responseBody, Tag.Empty)
            };
        };
    }
}
