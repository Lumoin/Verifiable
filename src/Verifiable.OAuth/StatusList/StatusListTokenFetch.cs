using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Foundation;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// The wire format a Status List Token was requested and is expected back in.
/// </summary>
public enum StatusListTokenFormat
{
    /// <summary>JWT format (<c>application/statuslist+jwt</c>), Section 5.1.</summary>
    Jwt,

    /// <summary>CWT format (<c>application/statuslist+cwt</c>), Section 5.2.</summary>
    Cwt
}


/// <summary>
/// Why <see cref="StatusListTokenFetch.FetchAsync"/> ended.
/// </summary>
public enum StatusListTokenFetchOutcome
{
    /// <summary>A 2xx response with the expected content type was obtained. <see cref="StatusListTokenFetchResult.Body"/> carries the raw token.</summary>
    Fetched = 0,

    /// <summary>The target or a redirect hop was denied by the <see cref="OutboundFetchPolicy"/>.</summary>
    PolicyDenied,

    /// <summary>A redirect was returned but not followed (policy <see cref="RedirectMode.None"/> or the redirect chain exceeded its bound).</summary>
    RedirectNotFollowed,

    /// <summary>The transport raised, or no terminal response could be obtained.</summary>
    TransportFailed,

    /// <summary>The terminal response's HTTP status code was outside the 2xx range.</summary>
    UnsuccessfulStatus,

    /// <summary>The terminal response's <c>Content-Type</c> does not match the requested format's media type.</summary>
    ContentTypeMismatch
}


/// <summary>
/// The outcome of a Section 8.1/8.2 Status List Token fetch.
/// </summary>
public sealed record StatusListTokenFetchResult
{
    /// <summary>Why the fetch ended.</summary>
    public required StatusListTokenFetchOutcome Outcome { get; init; }

    /// <summary>
    /// The raw Status List Token body — "the JWS Compact Serialization form" for
    /// <see cref="StatusListTokenFormat.Jwt"/> — when <see cref="Outcome"/> is
    /// <see cref="StatusListTokenFetchOutcome.Fetched"/>; otherwise empty.
    /// </summary>
    public TaggedMemory<byte> Body { get; init; } = TaggedMemory<byte>.Empty;

    /// <summary>The terminal response's <c>Content-Type</c> header value, or <see langword="null"/> when none was reached.</summary>
    public string? ContentType { get; init; }

    /// <summary>The terminal response's HTTP status code, or <c>0</c> when no terminal response was reached.</summary>
    public int StatusCode { get; init; }

    /// <summary>A diagnostic reason for a non-fetched outcome. Do not surface verbatim to untrusted callers.</summary>
    public string? DenyReason { get; init; }

    /// <summary>The URL the fetch ended at, after any redirects.</summary>
    public required Uri FinalUri { get; init; }

    /// <summary>The number of redirect hops followed.</summary>
    public int RedirectCount { get; init; }

    /// <summary>Whether <see cref="Outcome"/> is <see cref="StatusListTokenFetchOutcome.Fetched"/>.</summary>
    public bool IsFetched => Outcome == StatusListTokenFetchOutcome.Fetched;
}


/// <summary>
/// Fetches a Status List Token over the SSRF-policed <see cref="OutboundFetch"/> chokepoint.
/// </summary>
/// <remarks>
/// <para>
/// "the Status Provider MUST use the following content-type": the requested
/// <see cref="StatusListTokenFormat"/>'s media type is sent as <c>Accept</c> and re-checked against
/// the response's <c>Content-Type</c> (parameters such as <c>charset</c> tolerated; compared
/// case-insensitively per <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110
/// §8.3.1</see>). "A successful response that contains a Status List Token MUST use an HTTP status
/// code in the 2xx range" — the whole range, not only 200. "A response MAY also choose to redirect
/// the client to another URI using an HTTP status code in the 3xx range, which clients SHOULD
/// follow" (Section 8.2) and "HTTP clients MUST follow the guidance provided in Section 15.4 of
/// [RFC9110] for handling redirects" (Section 11.4): whether and how many redirects are followed is
/// the caller's <see cref="ExchangeContext.OutboundFetchPolicy"/> — <see cref="OutboundFetchPolicy.SecureDefault"/>
/// follows none; a caller opts into following redirects via <see cref="OutboundFetchPolicy.Redirects"/>
/// / <see cref="OutboundFetchPolicy.MaxRedirects"/>. "The HTTP response SHOULD use Content-Encoding
/// (such as gzip)" is the transport's concern, not this method's. No <c>System.Net.Http</c> is
/// referenced here — the network primitive is the caller-supplied <paramref name="transport"/>, the
/// same discipline <c>ClientIdMetadataDocuments.BuildResolving</c> follows.
/// </para>
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token Status List, Section 8.1</see>,
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Section 8.2</see>, and
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Section 11.4</see>.
/// </remarks>
public static class StatusListTokenFetch
{
    /// <summary>
    /// Fetches the Status List Token at <paramref name="statusListUri"/>.
    /// </summary>
    /// <param name="statusListUri">The Status List Token's <c>uri</c>.</param>
    /// <param name="format">The expected wire format, sent as <c>Accept</c> and checked against the response's <c>Content-Type</c>.</param>
    /// <param name="context">The per-call exchange context; the SSRF policy is read from it.</param>
    /// <param name="transport">The application-supplied single-hop transport.</param>
    /// <param name="maxResponseBytes">An upper bound, in bytes, on the response body accepted, per <see cref="OutboundFetch.OutboundRequest.MaxResponseBytes"/>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The fetch outcome; see <see cref="StatusListTokenFetchResult"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="statusListUri"/>, <paramref name="context"/>, or <paramref name="transport"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="maxResponseBytes"/> is not positive.</exception>
    public static async ValueTask<StatusListTokenFetchResult> FetchAsync(
        Uri statusListUri,
        StatusListTokenFormat format,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        long maxResponseBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(statusListUri);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxResponseBytes);

        string mediaType = MediaTypeFor(format);

        OutboundRequest request = new()
        {
            Target = statusListUri,
            Method = "GET",
            Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.Accept, mediaType)),
            MaxResponseBytes = maxResponseBytes
        };

        OutboundFetchResult fetch;
        try
        {
            //Fully qualified: within Verifiable.* the bare name binds to the OutboundFetch
            //namespace, not the static class of the same leaf name.
            fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(
                request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new StatusListTokenFetchResult
            {
                Outcome = StatusListTokenFetchOutcome.TransportFailed,
                DenyReason = "Transport failure while fetching the Status List Token.",
                FinalUri = statusListUri
            };
        }

        if(!fetch.IsFetched || fetch.Response is null)
        {
            StatusListTokenFetchOutcome outcome = fetch.Outcome switch
            {
                OutboundFetchOutcome.DeniedByPolicy => StatusListTokenFetchOutcome.PolicyDenied,
                OutboundFetchOutcome.RedirectNotFollowed or OutboundFetchOutcome.TooManyRedirects
                    => StatusListTokenFetchOutcome.RedirectNotFollowed,
                _ => StatusListTokenFetchOutcome.TransportFailed
            };

            return new StatusListTokenFetchResult
            {
                Outcome = outcome,
                DenyReason = fetch.DenyReason,
                FinalUri = fetch.FinalUri,
                RedirectCount = fetch.RedirectCount
            };
        }

        OutboundResponse response = fetch.Response;

        if(response.StatusCode is < 200 or > 299)
        {
            return new StatusListTokenFetchResult
            {
                Outcome = StatusListTokenFetchOutcome.UnsuccessfulStatus,
                StatusCode = response.StatusCode,
                DenyReason = $"The Status List Token fetch returned HTTP status {response.StatusCode}.",
                FinalUri = fetch.FinalUri,
                RedirectCount = fetch.RedirectCount
            };
        }

        response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
        if(!IsAcceptableContentType(contentType, mediaType))
        {
            return new StatusListTokenFetchResult
            {
                Outcome = StatusListTokenFetchOutcome.ContentTypeMismatch,
                ContentType = contentType,
                StatusCode = response.StatusCode,
                DenyReason = $"The Status List Token content type '{contentType}' does not match '{mediaType}'.",
                FinalUri = fetch.FinalUri,
                RedirectCount = fetch.RedirectCount
            };
        }

        return new StatusListTokenFetchResult
        {
            Outcome = StatusListTokenFetchOutcome.Fetched,
            Body = response.Body,
            ContentType = contentType,
            StatusCode = response.StatusCode,
            FinalUri = fetch.FinalUri,
            RedirectCount = fetch.RedirectCount
        };
    }


    /// <summary>Maps a requested wire format to the Section 8.1 media type it is negotiated with.</summary>
    /// <param name="format">The requested wire format.</param>
    /// <returns>The media type sent as <c>Accept</c> and checked against the response's <c>Content-Type</c>.</returns>
    private static string MediaTypeFor(StatusListTokenFormat format) => format switch
    {
        StatusListTokenFormat.Jwt => StatusListMediaTypes.StatusListJwtContentType,
        StatusListTokenFormat.Cwt => StatusListMediaTypes.StatusListCwt,
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unknown Status List Token format.")
    };


    /// <summary>
    /// Whether <paramref name="contentType"/> names <paramref name="expectedMediaType"/> — parameters
    /// such as <c>charset</c> stripped, compared case-insensitively per RFC 9110 §8.3.1.
    /// </summary>
    /// <param name="contentType">The response's <c>Content-Type</c> header value.</param>
    /// <param name="expectedMediaType">The media type the fetch requested.</param>
    /// <returns><see langword="true"/> when the media type portion matches.</returns>
    private static bool IsAcceptableContentType(string? contentType, string expectedMediaType)
    {
        if(string.IsNullOrWhiteSpace(contentType))
        {
            return false;
        }

        ReadOnlySpan<char> value = contentType.AsSpan().Trim();
        int parameterDelimiter = value.IndexOf(';');
        ReadOnlySpan<char> mediaType = (parameterDelimiter >= 0 ? value[..parameterDelimiter] : value).Trim();

        return mediaType.Equals(expectedMediaType, StringComparison.OrdinalIgnoreCase);
    }
}
