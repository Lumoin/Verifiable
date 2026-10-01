using System.Globalization;
using Verifiable.Core.Transport;

namespace Verifiable.Core.Outbound;

/// <summary>
/// The single guarded chokepoint every library dereference of a semi-trusted URL
/// routes through — federation/OAuth/RFC 9728 metadata, DID documents and their
/// service endpoints, JSON-LD <c>@context</c>. It reads the
/// <see cref="OutboundFetchPolicy"/> off the <see cref="ExchangeContext"/>,
/// validates the target, drives an application-supplied single-hop
/// <see cref="OutboundTransportDelegate"/>, and <strong>owns the redirect loop</strong>
/// so every hop is re-validated against the policy.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Method-agnostic on purpose.</strong> The seam gates <c>GET</c> and
/// <c>POST</c> alike: the endpoints a client <c>POST</c>s to (token / PAR) come
/// from discovered metadata, so a <c>POST</c> to a discovered URL is an SSRF
/// vector too. See <see cref="OutboundRequest"/> remarks for the full reasoning.
/// </para>
/// <para>
/// <strong>"Don't follow redirects blindly."</strong> The transport must run
/// with auto-redirect off; this loop applies the policy's <see cref="RedirectMode"/>,
/// re-runs <see cref="OutboundFetchPolicy.Evaluate"/> on each <c>Location</c>,
/// caps at <see cref="OutboundFetchPolicy.MaxRedirects"/>, and rewrites the
/// method/body per hop (303 and the common 301/302 handling → <c>GET</c> with no
/// body; 307/308 preserve method and body).
/// </para>
/// <para>
/// <strong>Necessary, not sufficient.</strong> This stops IP-literal SSRF and
/// scheme/host violations across hops. A hostname that resolves to a blocked
/// address (DNS-rebinding) is caught only by a connection-time pinning transport
/// — pair this with one.
/// </para>
/// </remarks>
public static class OutboundFetch
{
    /// <summary>The redirect statuses whose next hop is governed by the fetch policy.</summary>
    private static HashSet<int> RedirectStatusCodes { get; } = [301, 302, 303, 307, 308];


    /// <summary>
    /// Performs a policy-guarded fetch, following redirects per the policy and enforcing the response size
    /// on every hop. A declared or observed excess returns typed evidence without a partial body.
    /// Fail-closed by return: a denied target/hop or an over-long chain yields a
    /// non-<see cref="OutboundFetchOutcome.Fetched"/> result, never a thrown
    /// policy error. The transport is invoked only after the target passes the
    /// policy. Transport failures return their kind; cancellation propagates only when the caller's
    /// token is cancelled. A transport's own cancellation is reported as a timeout.
    /// </summary>
    /// <param name="request">The initial request (carries the explicit method).</param>
    /// <param name="context">The per-call context; the policy is read from it.</param>
    /// <param name="transport">The application-supplied single-hop transport (no auto-redirect).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<OutboundFetchResult> FetchAsync(
        OutboundRequest request,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);
        cancellationToken.ThrowIfCancellationRequested();

        if(request.MaxResponseBytes is long limit)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(limit);
        }

        ValueTask<OutboundTransportResult> ReadHopResponseAsync(int statusCode, HttpHeaderSet headers, Stream body, CancellationToken token) =>
            ReadResponseAsync(statusCode, headers, body, request.MaxResponseBytes, token);

        OutboundFetchPolicy policy = context.OutboundFetchPolicy;
        Uri requested = request.Target;
        OutboundRequest current = request;
        int hops = 0;
        OutboundRedirectRefusal? redirect = null;

        while(true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OutboundFetchDecision decision = policy.Evaluate(current.Target);
            if(!decision.IsAllowed)
            {
                return Stopped(OutboundFetchOutcome.DeniedByPolicy, decision.DenyReason, requested, current.Target, hops, redirect);
            }

            OutboundTransportResult received;
            try
            {
                received = await transport(current, context, ReadHopResponseAsync, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception)
            {
                cancellationToken.ThrowIfCancellationRequested();

                return new OutboundFetchResult
                {
                    Outcome = OutboundFetchOutcome.Unreachable,
                    FailureKind = WrappedCancellation.FindCancellation(exception) is not null
                        ? typeof(TimeoutException)
                        : exception.GetType(),
                    RequestedUri = requested,
                    FinalUri = current.Target,
                    RedirectCount = hops
                };
            }

            cancellationToken.ThrowIfCancellationRequested();
            if(received.TooLarge is OutboundResponseTooLarge tooLarge)
            {
                return new OutboundFetchResult
                {
                    Outcome = OutboundFetchOutcome.TooLarge,
                    TooLarge = tooLarge,
                    RequestedUri = requested,
                    FinalUri = current.Target,
                    RedirectCount = hops
                };
            }

            OutboundResponse response = received.Response!;

            if(!RedirectStatusCodes.Contains(response.StatusCode)
                || !response.Headers.TryGetValue(WellKnownHttpHeaderNames.Location, out string? location)
                || string.IsNullOrWhiteSpace(location))
            {
                //Terminal (non-redirect) response.
                return new OutboundFetchResult
                {
                    Outcome = OutboundFetchOutcome.Fetched,
                    Response = response,
                    RequestedUri = requested,
                    FinalUri = current.Target,
                    RedirectCount = hops,
                };
            }

            //Retain the response facts if this redirect or its target is refused.
            redirect = new OutboundRedirectRefusal(response.StatusCode, location);

            //It is a redirect.
            if(policy.Redirects == RedirectMode.None)
            {
                return Stopped(OutboundFetchOutcome.RedirectNotFollowed,
                    "Redirect not followed (RedirectMode.None).", requested, current.Target, hops, redirect);
            }

            if(hops >= policy.MaxRedirects)
            {
                return Stopped(OutboundFetchOutcome.TooManyRedirects,
                    $"Exceeded MaxRedirects ({policy.MaxRedirects}).", requested, current.Target, hops, redirect);
            }

            if(!Uri.TryCreate(current.Target, location, out Uri? next) || !next.IsAbsoluteUri)
            {
                return Stopped(OutboundFetchOutcome.DeniedByPolicy,
                    "Redirect Location is not a valid absolute URL.", requested, current.Target, hops, redirect);
            }

            if(policy.Redirects == RedirectMode.SameOrigin && !SameOrigin(current.Target, next))
            {
                return Stopped(OutboundFetchOutcome.DeniedByPolicy,
                    "Redirect crosses origin (RedirectMode.SameOrigin).", requested, next, hops, redirect);
            }

            //A 301/302/303 rewrites to GET and DROPS the body; silently turning a body-bearing request (e.g. a
            //one-way DIDComm POST) into a bodyless GET would deliver nothing while still reporting a 2xx success.
            //Only a body-preserving redirect (307/308) may follow a request that carries a body — otherwise the
            //caller must re-resolve and retry the new location explicitly rather than have the body vanish.
            if(current.Body is not null && response.StatusCode is not (307 or 308))
            {
                return Stopped(OutboundFetchOutcome.DeniedByPolicy,
                    "Redirect would drop the request body (only 307/308 may redirect a body-bearing request).", requested, next, hops, redirect);
            }

            current = RewriteForRedirect(current, next, response.StatusCode);
            hops++;
            //The next hop's URL is re-validated by Evaluate at the top of the loop.
        }
    }


    /// <summary>Retains refusal provenance and any redirect response that led to the refusal.</summary>
    private static OutboundFetchResult Stopped(
        OutboundFetchOutcome outcome, string? reason, Uri requested, Uri final, int hops, OutboundRedirectRefusal? redirect) =>
        new()
        {
            Outcome = outcome,
            DenyReason = reason,
            RefusedRedirect = redirect,
            RequestedUri = requested,
            FinalUri = final,
            RedirectCount = hops,
        };


    /// <summary>Compares the scheme, host, and effective port of two redirect targets.</summary>
    private static bool SameOrigin(Uri a, Uri b) =>
        string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
        && a.Port == b.Port;


    /// <summary>Preserves a 307/308 request and rewrites other allowed redirects to a bodyless GET.</summary>
    //HTTP redirect method/body rewrite: 307/308 preserve the method and body;
    //303 (and the universal browser handling of 301/302) fall back to GET and
    //drop the body. Falling back to GET is the safe choice — it never re-sends a
    //body to a new location the original caller did not target.
    private static OutboundRequest RewriteForRedirect(OutboundRequest current, Uri next, int statusCode)
    {
        bool preserve = statusCode is 307 or 308;
        return preserve
            ? current with { Target = next }
            : current with { Target = next, Method = "GET", Body = null };
    }


    /// <summary>
    /// The sole response-size decision: rejects a declared excess before reading, or stops at the first
    /// observed byte over the limit. An exact-limit body needs an EOF read and remains acceptable.
    /// </summary>
    private static async ValueTask<OutboundTransportResult> ReadResponseAsync(
        int statusCode, HttpHeaderSet headers, Stream body, long? limit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);
        cancellationToken.ThrowIfCancellationRequested();

        if(limit is long maximum)
        {
            foreach(string value in headers.GetValues(WellKnownHttpHeaderNames.ContentLength))
            {
                if(long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long declared)
                    && declared > maximum)
                {
                    return new OutboundTransportResult(new OutboundResponseTooLarge(
                        maximum, declared, OutboundResponseLengthKind.Declared));
                }
            }
        }

        using MemoryStream buffered = new();
        byte[] buffer = new byte[8192];
        long observed = 0;
        while(true)
        {
            int count = buffer.Length;
            if(limit is long bound && bound - observed < count)
            {
                count = (int)(bound - observed) + 1;
            }

            int read = await body.ReadAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            if(read == 0)
            {
                return new OutboundTransportResult(new OutboundResponse
                {
                    StatusCode = statusCode,
                    Headers = headers,
                    Body = new TaggedMemory<byte>(buffered.ToArray(), Tag.Empty)
                });
            }

            observed += read;
            if(limit is long maximumBytes && observed > maximumBytes)
            {
                return new OutboundTransportResult(new OutboundResponseTooLarge(
                    maximumBytes, observed, OutboundResponseLengthKind.Observed));
            }

            await buffered.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }
}
