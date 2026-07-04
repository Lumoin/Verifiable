using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;

namespace Verifiable.WebFinger;

/// <summary>
/// The WebFinger client per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>:
/// constructs the query URI, issues it through the guarded outbound fetch, and parses the JSON Resource
/// Descriptor with a supplied deserializer. <see cref="Verifiable.WebFinger"/> takes no
/// <c>System.Net.Http</c> or JSON dependency, so the transport and the deserializer are injected.
/// </summary>
/// <remarks>
/// The query scheme is always <c>https</c> and there is no code path that constructs an <c>http</c> URL, so
/// the §4/§4.2/§9.1 "HTTPS only, never retry over a non-secure connection" rules hold by construction: a
/// failed HTTPS fetch returns a failure result rather than falling back.
/// </remarks>
public static class WebFingerClient
{
    /// <summary>
    /// Builds an <c>acct:</c> query target from a user part and a host per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7565#section-7">RFC 7565 §7</see>. Every user-part octet
    /// outside the RFC 3986 unreserved set — an <c>@</c>, <c>:</c>, <c>/</c>, a space, and so on — is
    /// percent-encoded, so the trailing <c>@</c> unambiguously delimits the host and the result is a
    /// syntactically valid <c>acct:</c> URI.
    /// </summary>
    /// <param name="userPart">The local part of the account (for example <c>alice</c>).</param>
    /// <param name="host">The host the account belongs to (for example <c>example.com</c>); a bare host.</param>
    /// <returns>The <c>acct:</c> URI, for example <c>acct:alice@example.com</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="host"/> is not a bare host.</exception>
    /// <remarks>
    /// A non-ASCII user part is escaped as percent-encoded UTF-8; the RFC 7565 §6 PRECIS normalization for
    /// internationalized user parts is a deferred, documented gap.
    /// </remarks>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "An acct: URI (RFC 7565) is a query-target identifier carried verbatim as a string; System.Uri does not model the acct: scheme.")]
    public static string CreateAccountResource(string userPart, string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userPart);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if(!IsBareHost(host))
        {
            throw new ArgumentException(
                $"The account host '{host}' is not a bare host (it contains a '/', '@', '#', '?', or whitespace).",
                nameof(host));
        }

        //RFC 7565 §7: the user part admits only unreserved and sub-delim octets literally; everything else
        //MUST be percent-encoded. Uri.EscapeDataString escapes every octet outside the RFC 3986 unreserved
        //set, which is a valid (if not minimal) user part, and encodes the '@' so the last '@' delimits the host.
        string encodedUserPart = Uri.EscapeDataString(userPart);

        return $"acct:{encodedUserPart}@{host}";
    }


    /// <summary>
    /// Computes the HTTPS WebFinger query URI for a query target and optional relation filters per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.1">RFC 7033 §4.1</see>: always
    /// <c>https</c>, always the <c>/.well-known/webfinger</c> path, the <c>resource</c> parameter exactly
    /// once, and one <c>rel</c> parameter per filter. All parameter values are percent-encoded, so no space
    /// is ever inserted into the query.
    /// </summary>
    /// <param name="host">The host the query is issued to: a bare authority (host, optionally <c>host:port</c>).</param>
    /// <param name="resource">The query target carried verbatim in the <c>resource</c> parameter.</param>
    /// <param name="relFilters">The relation types to request; empty requests the full descriptor.</param>
    /// <returns>The absolute HTTPS query URI.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="host"/> is not a bare authority — a <c>/</c>, <c>@</c>, <c>#</c>, <c>?</c>,
    /// or whitespace would let it re-anchor the URI authority (host confusion) or truncate the fixed path.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The WebFinger query target is any URI (RFC 7033 §4.5 is scheme-neutral, e.g. an acct: URI) carried verbatim as a string; System.Uri does not model all such schemes.")]
    public static Uri ComputeQueryUri(string host, string resource, IReadOnlyList<string> relFilters)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        ArgumentNullException.ThrowIfNull(relFilters);

        //A host is spliced into the authority position, so it MUST be a bare authority. Left unguarded,
        //"trusted.example@evil.example" re-anchors the connection to evil.example (RFC 3986 userinfo), and
        //"example.com#x" / "example.com/x" truncates or shifts the §4 fixed path — both silently.
        if(!IsBareHost(host))
        {
            throw new ArgumentException(
                $"The WebFinger host '{host}' is not a bare authority (it contains a '/', '@', '#', '?', or whitespace).",
                nameof(host));
        }

        StringBuilder builder = new();
        builder.Append(Uri.UriSchemeHttps).Append("://").Append(host).Append(WellKnownWebFingerValues.WellKnownPath);
        builder.Append('?').Append(WellKnownWebFingerValues.ResourceParameterName).Append('=').Append(Uri.EscapeDataString(resource));

        foreach(string relation in relFilters)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(relation);
            builder.Append('&').Append(WellKnownWebFingerValues.RelParameterName).Append('=').Append(Uri.EscapeDataString(relation));
        }

        Uri queryUri;
        try
        {
            queryUri = new Uri(builder.ToString(), UriKind.Absolute);
        }
        catch(UriFormatException exception)
        {
            //A host that satisfies IsBareHost can still fail to form a URI (e.g. a lone '%'); surface it as
            //the method's documented ArgumentException rather than leaking a UriFormatException.
            throw new ArgumentException(
                $"The WebFinger host '{host}' does not form a valid query URI.", nameof(host), exception);
        }

        //Defense in depth: IsBareHost blocks the known vectors, but the URI itself is the ground truth — the
        //host must not have introduced userinfo or moved the request off the §4 well-known path.
        if(!string.IsNullOrEmpty(queryUri.UserInfo)
            || !string.Equals(queryUri.AbsolutePath, WellKnownWebFingerValues.WellKnownPath, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The WebFinger host '{host}' produced a non-conforming query URI.", nameof(host));
        }

        return queryUri;
    }


    /// <summary>
    /// Whether <paramref name="host"/> is a bare host authority — a reg-name or IPv6 literal with an optional
    /// <c>:port</c>, and nothing that could re-anchor a URI authority (a <c>@</c>) or truncate a
    /// path/query/fragment (<c>/</c>, <c>#</c>, <c>?</c>, whitespace). Delegates to the source-generated
    /// <see cref="WebFingerHostRegex.BareHost"/> allowlist.
    /// </summary>
    private static bool IsBareHost(string host) => WebFingerHostRegex.BareHost().IsMatch(host);


    /// <summary>
    /// Returns the <c>href</c> of the first link whose relation equals <paramref name="relation"/>, or
    /// <see langword="null"/> when none matches or the matched link carries no <c>href</c>. The first match
    /// wins because <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4">RFC 7033 §4.4.4</see>
    /// says link order MAY be read as order of preference.
    /// </summary>
    /// <param name="descriptor">The resolved descriptor.</param>
    /// <param name="relation">
    /// The relation type to match. A URI relation (one carrying a scheme, i.e. containing <c>:</c>) is compared
    /// case-sensitively per RFC 3986 §6.2.1; a registered (bare-token) relation type is compared
    /// case-insensitively per <see href="https://www.rfc-editor.org/rfc/rfc8288#section-2.1.1">RFC 8288 §2.1.1</see>.
    /// </param>
    /// <returns>The matched link's <c>href</c>, or <see langword="null"/>.</returns>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "A link href may be any URI (including a DID) carried verbatim; System.Uri does not model every such scheme.")]
    public static string? FindLinkHref(JsonResourceDescriptor descriptor, string relation)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentException.ThrowIfNullOrWhiteSpace(relation);

        //RFC 7033 §4.4.4.1: a rel is either a URI or a registered relation type. A registered (bare-token)
        //type carries no scheme and is matched case-insensitively; a URI carries a scheme (a ':') and is
        //matched exactly.
        StringComparison comparison = relation.Contains(':', StringComparison.Ordinal)
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;

        foreach(WebFingerLink link in descriptor.Links)
        {
            if(string.Equals(link.Rel, relation, comparison))
            {
                return link.Href;
            }
        }

        return null;
    }


    /// <summary>
    /// Builds a <see cref="WebFingerResolveDelegate"/> that computes the query URI, fetches it through the
    /// guarded <see cref="OutboundFetch"/> chokepoint (SSRF policy off the <see cref="ExchangeContext"/>), and
    /// parses the JRD with <paramref name="descriptorDeserializer"/>.
    /// </summary>
    /// <param name="transport">
    /// The application-supplied single-hop transport the guarded fetch drives. <see cref="Verifiable.WebFinger"/>
    /// takes no <c>System.Net.Http</c> dependency, so the network primitive is injected.
    /// </param>
    /// <param name="descriptorDeserializer">Parses the fetched JRD bytes into a <see cref="JsonResourceDescriptor"/>.</param>
    /// <returns>A resolve delegate for a query target and host.</returns>
    public static WebFingerResolveDelegate BuildResolving(
        OutboundTransportDelegate transport,
        WebFingerJrdDeserializer descriptorDeserializer)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(descriptorDeserializer);

        return async (resource, host, relFilters, context, cancellationToken) =>
        {
            Uri target;
            try
            {
                target = ComputeQueryUri(host, resource, relFilters);
            }
            catch(ArgumentException)
            {
                return WebFingerResolutionResult.Failure(WebFingerResolutionErrors.InvalidResource);
            }

            OutboundRequest request = new() { Target = target, Method = "GET" };

            OutboundFetchResult fetch;
            try
            {
                //Fully qualified: within Verifiable.* the bare name binds to the OutboundFetch namespace, not
                //the static class of the same leaf name.
                fetch = await Verifiable.Core.OutboundFetch.OutboundFetch.FetchAsync(
                    request, context, transport, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //§4.2/§9.1: the HTTPS query failed; accept the failure and do not retry over a non-secure connection.
                return WebFingerResolutionResult.Failure(WebFingerResolutionErrors.TransportFailure);
            }

            if(!fetch.IsFetched)
            {
                //A guarded-fetch denial (an SSRF policy block, an unfollowed redirect, too many redirects) is a
                //security-relevant outcome distinct from a resource that answered "no information"; keep them apart.
                return WebFingerResolutionResult.Failure(
                    fetch.Outcome == OutboundFetchOutcome.DeniedByPolicy
                        ? WebFingerResolutionErrors.PolicyDenied
                        : WebFingerResolutionErrors.NotFound);
            }

            if(fetch.Response is null || fetch.Response.StatusCode != 200)
            {
                return WebFingerResolutionResult.Failure(WebFingerResolutionErrors.NotFound);
            }

            JsonResourceDescriptor? descriptor;
            try
            {
                descriptor = descriptorDeserializer(fetch.Response.Body.Span);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return WebFingerResolutionResult.Failure(WebFingerResolutionErrors.InvalidJrd);
            }

            return descriptor is null
                ? WebFingerResolutionResult.Failure(WebFingerResolutionErrors.InvalidJrd)
                : WebFingerResolutionResult.Success(descriptor);
        };
    }
}
