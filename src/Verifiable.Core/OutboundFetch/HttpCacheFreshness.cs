using System;
using System.Globalization;

namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// Cacheability and remaining freshness lifetime of an <see cref="OutboundResponse"/>,
/// computed purely from its headers per the subset of
/// <see href="https://www.rfc-editor.org/rfc/rfc9111">RFC 9111 (HTTP Caching)</see> a
/// shared-cache consumer needs: the <c>Cache-Control</c> <c>no-store</c>/<c>no-cache</c>/
/// <c>max-age</c>/<c>s-maxage</c> directives (RFC 9111 §5.2.2), the <c>Age</c> header
/// (RFC 9111 §5.1), and the <c>Expires</c>/<c>Date</c> fallback (RFC 9111 §5.3, §4.2.1).
/// Consumed by the Client ID Metadata Document cache described in
/// draft-ietf-oauth-client-id-metadata-document-02 §5.2, which respects HTTP cache
/// headers when caching client metadata.
/// </summary>
/// <remarks>
/// Deliberately <see cref="TimeProvider"/>-free: this is arithmetic over header values as
/// received, not a staleness decision against wall-clock time. A caller that stores the
/// result adds <see cref="FreshnessLifetime"/> to its own "stored at" instant (read from
/// an injected <see cref="TimeProvider"/>) to get the moment a cache entry goes stale.
/// Every unknown, absent, or malformed input resolves to zero freshness — fail-closed
/// toward re-fetching rather than serving a document longer than the headers actually
/// license.
/// </remarks>
[System.Diagnostics.DebuggerDisplay("{IsStorable ? \"Storable\" : \"NotStorable\",nq} {FreshnessLifetime}")]
public readonly record struct HttpCacheFreshness
{
    private HttpCacheFreshness(bool isStorable, TimeSpan freshnessLifetime, bool mustRevalidate)
    {
        IsStorable = isStorable;
        FreshnessLifetime = freshnessLifetime;
        MustRevalidate = mustRevalidate;
    }


    /// <summary>
    /// Whether a cache may retain the response at all. <see langword="false"/> only when
    /// <c>Cache-Control: no-store</c> is present (RFC 9111 §5.2.2.5). A response with
    /// <c>no-cache</c> (RFC 9111 §5.2.2.4) is still storable — it simply carries zero
    /// <see cref="FreshnessLifetime"/>, so a cache that revalidates on every use can keep
    /// the entry as a validation target.
    /// </summary>
    public bool IsStorable { get; }

    /// <summary>
    /// The remaining time, as of when this response was received, that it may be served
    /// without re-fetching (RFC 9111 §4.2). Zero when <see cref="IsStorable"/> is
    /// <see langword="false"/>, when <c>no-cache</c> is present, when no expiration signal
    /// was found, or when the only expiration signal present was malformed.
    /// </summary>
    public TimeSpan FreshnessLifetime { get; }

    /// <summary>
    /// Whether <c>Cache-Control: no-cache</c> requires the response to be revalidated before
    /// every reuse (RFC 9111 §5.2.2.4). When <see langword="true"/> the entry may be stored as
    /// a validation target but must never be served fresh — distinct from a merely zero
    /// <see cref="FreshnessLifetime"/> (an absent or short expiration signal), so a consumer that
    /// applies a lower cache-lifetime bound must not raise a no-cache response to that floor.
    /// </summary>
    public bool MustRevalidate { get; }


    /// <summary>The <c>Cache-Control</c> header name (RFC 9111 §5.2).</summary>
    private const string CacheControlHeaderName = "Cache-Control";

    /// <summary>The <c>Age</c> header name (RFC 9111 §5.1).</summary>
    private const string AgeHeaderName = "Age";

    /// <summary>The <c>Expires</c> header name (RFC 9111 §5.3).</summary>
    private const string ExpiresHeaderName = "Expires";

    /// <summary>The <c>Date</c> header name, used only as the Expires reference instant (RFC 9111 §4.2.1).</summary>
    private const string DateHeaderName = "Date";

    private const string NoStoreDirective = "no-store";
    private const string NoCacheDirective = "no-cache";
    private const string MaxAgeDirective = "max-age";
    private const string SharedMaxAgeDirective = "s-maxage";

    /// <summary>
    /// The delta-seconds overflow ceiling: a value too large to represent, or any
    /// larger-than-representable delta-seconds token, is treated as this value rather than
    /// as invalid (RFC 9111 §1.2.2).
    /// </summary>
    private const long MaxDeltaSeconds = 2_147_483_648L;

    /// <summary>The RFC 1123 / IMF-fixdate round-trip format recognized for <c>Expires</c> and <c>Date</c>.</summary>
    private const string HttpDateFormat = "r";


    /// <summary>
    /// Computes cacheability and remaining freshness lifetime for <paramref name="response"/>.
    /// Pure and total: never touches the network or a clock, and always returns a value —
    /// there is no exception path for malformed headers, only fail-closed results.
    /// </summary>
    /// <param name="response">The response whose caching headers are evaluated.</param>
    public static HttpCacheFreshness Compute(OutboundResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        response.TryGetHeader(CacheControlHeaderName, out string? cacheControlValue);
        CacheControlDirectives directives = ParseCacheControlDirectives(cacheControlValue);

        if(directives.HasNoStore)
        {
            return new HttpCacheFreshness(false, TimeSpan.Zero, mustRevalidate: false);
        }

        if(directives.HasNoCache)
        {
            return new HttpCacheFreshness(true, TimeSpan.Zero, mustRevalidate: true);
        }

        long? lifetimeSeconds = directives.SharedMaxAgeSeconds
            ?? directives.MaxAgeSeconds
            ?? ReadExpiresMinusDateSeconds(response);

        if(lifetimeSeconds is null)
        {
            return new HttpCacheFreshness(true, TimeSpan.Zero, mustRevalidate: false);
        }

        long remainingSeconds = Math.Max(0, lifetimeSeconds.Value - ReadAgeSeconds(response));

        return new HttpCacheFreshness(true, TimeSpan.FromSeconds(remainingSeconds), mustRevalidate: false);
    }


    //Walks the Cache-Control field value once, splitting on top-level commas (a
    //quoted-string argument, e.g. no-cache="Set-Cookie, X-Foo", is not split), and folding
    //each "name[=value]" token into the accumulated directive state via ApplyDirective.
    private static CacheControlDirectives ParseCacheControlDirectives(string? headerValue)
    {
        CacheControlDirectives directives = default;
        ReadOnlySpan<char> remaining = headerValue.AsSpan();

        while(!remaining.IsEmpty)
        {
            int commaIndex = FindTopLevelComma(remaining);
            ReadOnlySpan<char> token = (commaIndex >= 0 ? remaining[..commaIndex] : remaining).Trim();
            remaining = commaIndex >= 0 ? remaining[(commaIndex + 1)..] : ReadOnlySpan<char>.Empty;

            if(!token.IsEmpty)
            {
                directives = ApplyDirective(directives, token);
            }
        }

        return directives;
    }


    //Recognizes the four directives this subset tracks and folds a match into
    //directives via a non-destructive `with`; an unrecognized directive passes directives
    //through unchanged per RFC 9111 §5.2.3 ("a cache MUST ignore unrecognized cache
    //directives"). A max-age/s-maxage directive present with a value that fails to parse
    //as delta-seconds is folded to zero rather than left absent: RFC 9111 §4.2.1
    //encourages treating a response with invalid freshness information (its own example is
    //"a max-age directive with non-integer content") as stale.
    private static CacheControlDirectives ApplyDirective(CacheControlDirectives directives, ReadOnlySpan<char> token)
    {
        int equalsIndex = token.IndexOf('=');
        ReadOnlySpan<char> name = (equalsIndex >= 0 ? token[..equalsIndex] : token).Trim();
        ReadOnlySpan<char> value = equalsIndex >= 0 ? token[(equalsIndex + 1)..].Trim() : ReadOnlySpan<char>.Empty;

        return name switch
        {
            _ when name.Equals(NoStoreDirective, StringComparison.OrdinalIgnoreCase) =>
                directives with { HasNoStore = true },

            _ when name.Equals(NoCacheDirective, StringComparison.OrdinalIgnoreCase) =>
                directives with { HasNoCache = true },

            _ when name.Equals(MaxAgeDirective, StringComparison.OrdinalIgnoreCase) =>
                directives with { MaxAgeSeconds = TryParseDeltaSeconds(value, out long maxAgeSeconds) ? maxAgeSeconds : 0 },

            _ when name.Equals(SharedMaxAgeDirective, StringComparison.OrdinalIgnoreCase) =>
                directives with { SharedMaxAgeSeconds = TryParseDeltaSeconds(value, out long sharedMaxAgeSeconds) ? sharedMaxAgeSeconds : 0 },

            _ => directives
        };
    }


    //Cache directive arguments may use the quoted-string form (RFC 9111 §5.2: "recipients
    //ought to accept both forms, even if a specific form is required for generation"), and
    //a quoted-string argument can itself contain a comma; only a comma outside quotes
    //separates directives.
    private static int FindTopLevelComma(ReadOnlySpan<char> value)
    {
        bool isInsideQuotes = false;

        for(int i = 0; i < value.Length; ++i)
        {
            char current = value[i];
            if(current == '"')
            {
                isInsideQuotes = !isInsideQuotes;
            }
            else if(current == ',' && !isInsideQuotes)
            {
                return i;
            }
        }

        return -1;
    }


    //delta-seconds = 1*DIGIT (RFC 9111 §1.2.2): no sign, at least one digit. A value that
    //parses but exceeds the representable/overflow ceiling is clamped to MaxDeltaSeconds
    //rather than rejected, per the same section.
    private static bool TryParseDeltaSeconds(ReadOnlySpan<char> token, out long seconds)
    {
        token = Unquote(token.Trim());

        if(token.IsEmpty)
        {
            seconds = 0;
            return false;
        }

        foreach(char digit in token)
        {
            if(digit is < '0' or > '9')
            {
                seconds = 0;
                return false;
            }
        }

        if(!long.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out seconds))
        {
            seconds = MaxDeltaSeconds;
            return true;
        }

        seconds = Math.Min(seconds, MaxDeltaSeconds);

        return true;
    }


    private static ReadOnlySpan<char> Unquote(ReadOnlySpan<char> value) =>
        value.Length >= 2 && value[0] == '"' && value[^1] == '"' ? value[1..^1] : value;


    //RFC 9111 §5.1: the Age field is a delta-seconds; a list-based value uses only the
    //first member, and an invalid value is ignored (treated as absent, i.e. zero).
    private static long ReadAgeSeconds(OutboundResponse response)
    {
        if(!response.TryGetHeader(AgeHeaderName, out string? value) || value is not { Length: > 0 })
        {
            return 0;
        }

        ReadOnlySpan<char> span = value.AsSpan();
        int commaIndex = span.IndexOf(',');
        ReadOnlySpan<char> firstMember = (commaIndex >= 0 ? span[..commaIndex] : span).Trim();

        return TryParseDeltaSeconds(firstMember, out long seconds) ? seconds : 0;
    }


    //RFC 9111 §4.2.1 fallback: Expires minus Date, only when both are present and parse as
    //an RFC 1123 / IMF-fixdate HTTP-date. §5.3 requires an invalid Expires value to be
    //interpreted as already expired; a missing or unparsable Date leaves no reference
    //instant to compute a lifetime against — TimeProvider-free, so "use the time the
    //message was received" (the RFC's fallback for an absent Date) is not available here.
    private static long? ReadExpiresMinusDateSeconds(OutboundResponse response)
    {
        if(!response.TryGetHeader(ExpiresHeaderName, out string? expiresValue) || expiresValue is not { Length: > 0 })
        {
            return null;
        }

        if(!TryParseHttpDate(expiresValue, out DateTimeOffset expires))
        {
            return 0;
        }

        if(!response.TryGetHeader(DateHeaderName, out string? dateValue)
            || dateValue is not { Length: > 0 }
            || !TryParseHttpDate(dateValue, out DateTimeOffset date))
        {
            return null;
        }

        double totalSeconds = (expires - date).TotalSeconds;

        return totalSeconds > 0 ? (long)totalSeconds : 0;
    }


    //The obsolete RFC 850 and asctime HTTP-date forms are not recognized: only the RFC
    //1123 / IMF-fixdate form ("r") is; anything else is malformed for this component's
    //purposes, folding into the zero-lifetime fail-closed path.
    private static bool TryParseHttpDate(string value, out DateTimeOffset result) =>
        DateTimeOffset.TryParseExact(
            value,
            HttpDateFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out result);


    private readonly record struct CacheControlDirectives(
        bool HasNoStore,
        bool HasNoCache,
        long? MaxAgeSeconds,
        long? SharedMaxAgeSeconds);
}
