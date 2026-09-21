
namespace Verifiable.OAuth.Server;

/// <summary>
/// Exact-match comparison of a requested <c>redirect_uri</c> against a client's registered set,
/// per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see> and
/// draft-ietf-oauth-client-id-metadata-document-02 §4.2: "the authorization server MUST ensure
/// that the redirect URL in an authorization request is an exact match, using simple string
/// comparison, of a registered redirect URL." A companion loopback matcher
/// (<see cref="IsRegisteredLoopback"/>) implements the narrow native-app exception in
/// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>. Every call
/// site tries <see cref="IsRegisteredExact"/> first, for every client; only on its failure — and
/// only for a public client presenting PKCE <c>S256</c> — does <see cref="IsRegisteredLoopback"/>
/// run at all.
/// </summary>
/// <remarks>
/// <see cref="Uri.Equals(object?)"/> (and the <c>ImmutableHashSet&lt;Uri&gt;.Contains</c> lookup a
/// <c>Uri</c>-keyed set performs) is insufficient here: <see cref="Uri"/> normalizes a default port
/// out of its equality and identity computation (<c>https://app.example/cb</c> and
/// <c>https://app.example:443/cb</c> compare equal) and case-folds percent-encoded octets during
/// parsing, so two redirect URIs that differ only in port elision or percent-encoding case collapse
/// to the "same" <see cref="Uri"/> even though they are different octet sequences on the wire. RFC
/// 3986 §6.2.1 simple string comparison — and this specification's exact-match requirement — treats
/// them as distinct; an attacker registering (or a client presenting) the normalized-equivalent form
/// must not bypass the registered-redirect-URI allowlist. Comparison is therefore on
/// <see cref="Uri.OriginalString"/>, ordinally, never through <see cref="Uri"/> equality.
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see> states
/// "The redirection endpoint URI MUST be an absolute URI" and "The endpoint URI MUST NOT include a
/// fragment component"; <see cref="IsRegisteredExact"/> and <see cref="IsRegisteredLoopback"/>'s
/// canonical-form gate both refuse a candidate on either side — the requested value or any
/// registered entry — that violates either constraint outright, rather than accepting a match
/// against a mis-registered fragment-bearing or relative entry.
/// </remarks>
public static class RedirectUriMatching
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="requested"/>'s original string is an
    /// ordinal exact match of at least one entry in <paramref name="registered"/>'s original
    /// strings.
    /// </summary>
    /// <param name="registered">The client's registered redirect URIs.</param>
    /// <param name="requested">The redirect URI presented on the request.</param>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>
    /// requires the redirection endpoint URI to be "an absolute URI" and states "The endpoint URI
    /// MUST NOT include a fragment component." A candidate on either side — <paramref name="requested"/>
    /// or any entry in <paramref name="registered"/> — that is not <see cref="Uri.IsAbsoluteUri"/> or
    /// whose <see cref="Uri.Fragment"/> is non-empty never matches. <see cref="Uri.IsAbsoluteUri"/> is
    /// checked before any other component is read, because <see cref="Uri.Fragment"/> and every other
    /// <see cref="Uri"/> member throw <see cref="InvalidOperationException"/> on a relative
    /// <see cref="Uri"/>, so a relative registered entry is a silent non-match rather than a thrown
    /// exception. A registered entry that carries a fragment is a configuration defect surfaced as a
    /// permanent non-match, never silently stripped before comparison — the same posture
    /// <see cref="IsRegisteredLoopback"/>'s canonical-form gate already takes.
    /// </remarks>
    public static bool IsRegisteredExact(IReadOnlyCollection<Uri> registered, Uri requested)
    {
        ArgumentNullException.ThrowIfNull(registered);
        ArgumentNullException.ThrowIfNull(requested);

        if(!requested.IsAbsoluteUri || !string.IsNullOrEmpty(requested.Fragment))
        {
            return false;
        }

        foreach(Uri candidate in registered)
        {
            if(!candidate.IsAbsoluteUri || !string.IsNullOrEmpty(candidate.Fragment))
            {
                continue;
            }

            if(string.Equals(candidate.OriginalString, requested.OriginalString, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Names the loopback-interface host literals
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see> recognizes
    /// for the native-app redirect exception, and — for the <c>localhost</c> literal only — whether
    /// a deployment's policy has opted into it.
    /// </summary>
    private static class LoopbackHostLiterals
    {
        /// <summary>
        /// The IPv4 loopback literal, exactly as <see cref="Uri.Host"/> renders it for an IPv4
        /// host — RFC 8252 §7.3's <c>http://127.0.0.1:{port}/{path}</c> example.
        /// </summary>
        internal const string IPv4 = "127.0.0.1";

        /// <summary>
        /// The IPv6 loopback literal, bracketed exactly as
        /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986 §3.2.2</see>
        /// requires for an IP-literal host and exactly as <see cref="Uri.Host"/> renders it — RFC
        /// 8252 §7.3's <c>http://[::1]:{port}/{path}</c> example.
        /// </summary>
        internal const string IPv6 = "[::1]";

        /// <summary>
        /// The <c>localhost</c> name. <see cref="Uri.Host"/> always lower-cases a registered-name
        /// host, so an ordinal comparison against this lowercase literal is sufficient once the
        /// canonical-form gate in <see cref="IsCanonicalLoopbackCandidate"/> has already refused any
        /// wire text whose casing does not round-trip through <see cref="Uri.AbsoluteUri"/>.
        /// </summary>
        /// <remarks>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.3">RFC 8252 §8.3</see> states:
        /// "the use of localhost is NOT RECOMMENDED. Specifying a redirect URI with the loopback IP
        /// literal rather than localhost avoids inadvertently listening on network interfaces other
        /// than the loopback interface. It is also less susceptible to client-side firewalls and
        /// misconfigured host name resolution on the user's device." That NOT RECOMMENDED is an RFC
        /// 2119 keyword this library honors by refusing <c>localhost</c> by default: a caller must opt
        /// in via <c>ExchangeContext.IsLocalhostNameAcceptedForLoopbackRedirects</c> before this
        /// literal is recognized at all. Real native/agentic clients (e.g. MCP clients whose
        /// client-id metadata document declares a portless <c>http://localhost/callback</c> alongside
        /// <c>http://127.0.0.1/callback</c>) are the deployment-side reason to opt in; a hosts-file or
        /// resolver misconfiguration that maps <c>localhost</c> off-loopback is the residual risk the
        /// opt-in accepts on the deployment's behalf. <see cref="Uri.IsLoopback"/> is still required in
        /// addition (it is string-based, not resolution-based, so it says nothing about the accepting
        /// deployment's own resolver at runtime) — the opt-in is a documented policy choice, not a
        /// bypass of that guard.
        /// </remarks>
        internal const string Localhost = "localhost";


        /// <summary>
        /// Returns <see langword="true"/> when <paramref name="host"/> — already known to be
        /// <see cref="Uri.IsLoopback"/> and to have survived the canonical-form gate — is one of the
        /// literals this policy recognizes: the two IP literals unconditionally, and
        /// <see cref="Localhost"/> only when <paramref name="isLocalhostNameAccepted"/> is
        /// <see langword="true"/>.
        /// </summary>
        internal static bool IsRecognized(string host, bool isLocalhostNameAccepted) =>
            string.Equals(host, IPv4, StringComparison.Ordinal)
            || string.Equals(host, IPv6, StringComparison.Ordinal)
            || (isLocalhostNameAccepted && string.Equals(host, Localhost, StringComparison.Ordinal));
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="requested"/> is a loopback-interface
    /// redirect URI per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see> that
    /// matches at least one entry in <paramref name="registered"/> in every respect except port.
    /// </summary>
    /// <param name="registered">The client's registered redirect URIs.</param>
    /// <param name="requested">The redirect URI presented on the request.</param>
    /// <param name="isLocalhostNameAccepted">
    /// Whether the deployment's policy accepts the <c>localhost</c> host literal alongside the two
    /// IP literals — <c>PolicyExchangeContextExtensions.IsLocalhostNameAcceptedForLoopbackRedirects</c>,
    /// which defaults to <see langword="false"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.3">RFC 8252 §8.3</see>'s NOT
    /// RECOMMENDED. This method is a pure predicate over its three arguments; callers pass the
    /// resolved policy value rather than this method reading any ambient state.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Callers gate admission; this method only matches.</strong> This carries no opinion on
    /// when it is safe to call — it is not, by itself, the native-app exception.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.4">RFC 8252 §8.4</see> is the
    /// scoping clause: "native apps are classified as public clients ... they MUST be registered
    /// with the authorization server as such," and "Authorization servers MUST require clients to
    /// register their complete redirect URI (including the path component) and reject authorization
    /// requests that specify a redirect URI that doesn't exactly match the one that was registered;
    /// the exception is loopback redirects, where an exact match is required except for the port URI
    /// component." The library's call sites invoke this method only after
    /// <see cref="IsRegisteredExact"/> has failed, and only for a public client (no declared
    /// <c>token_endpoint_auth_method</c>) presenting PKCE <c>S256</c>. A confidential client or a
    /// non-PKCE request never reaches this method.
    /// </para>
    /// <para>
    /// <strong>Canonical-form gate, never a hand-rolled slice of the wire text.</strong> Both
    /// <paramref name="requested"/> and every candidate in <paramref name="registered"/> must satisfy
    /// <c>string.Equals(uri.OriginalString, uri.AbsoluteUri, StringComparison.Ordinal)</c> before any
    /// other component is trusted — the wire text must round-trip through <see cref="Uri"/>'s own
    /// parser byte for byte. This refuses, by construction and without a single substring scan of the
    /// wire text: leading or trailing whitespace; a non-canonical port spelling (<c>:080</c>) or an
    /// empty port (<c>host:</c>); the default port re-stated explicitly (<c>:80</c>, which
    /// <see cref="Uri.AbsoluteUri"/> elides); an uppercase or mixed-case host (<see cref="Uri.AbsoluteUri"/>
    /// lower-cases it); the IPv4 shorthand/octal/decimal/hex encodings <c>127.1</c>, <c>0177.0.0.1</c>,
    /// <c>2130706433</c>, and <c>0x7f000001</c> (each of which <see cref="Uri"/> silently canonicalizes
    /// onto the dotted-decimal <c>127.0.0.1</c>, so the wire spelling never matches the canonical
    /// rendering); the longhand IPv6 form <c>[0:0:0:0:0:0:0:1]</c> (canonicalized onto <c>[::1]</c>); a
    /// dot-segment in the path (<c>/cb/../x</c>, collapsed by <see cref="Uri"/> during parsing); and
    /// the bracketed-IPv6-plus-suffix trick <c>http://[::1]evil.example/cb</c> (<see cref="Uri"/> ends
    /// the authority at the closing bracket and folds the suffix into the path, so the canonical
    /// rendering inserts a <c>/</c> the wire text never had). Every one of these is a case where the
    /// validated string and the string a naive redirect would emit disagree; refusing the candidate
    /// outright — rather than trusting either parse alone — closes that class rather than patching
    /// each member of it individually.
    /// </para>
    /// <para>
    /// Once a candidate's wire text is confirmed canonical, its host must be exactly one of the
    /// literals <see cref="LoopbackHostLiterals.IsRecognized"/> accepts and
    /// <see cref="Uri.IsLoopback"/> must additionally hold — <see cref="Uri.IsLoopback"/> is never the
    /// sole admission, since it also answers <see langword="true"/> for the entire 127.0.0.0/8 block
    /// and for IPv4-mapped IPv6 forms this policy does not recognize as a literal.
    /// </para>
    /// <para>
    /// A matched candidate's <see cref="Uri.AbsolutePath"/> and <see cref="Uri.Query"/> must equal
    /// <paramref name="requested"/>'s ordinally; only the authority's port is the free variable RFC
    /// 8252 §7.3 grants. One consequence, pinned by test: a registered candidate that itself pins a
    /// concrete port (e.g. <c>http://127.0.0.1:9999/cb</c>) is matched by a request at any OTHER port
    /// too, once this fallback runs — registering a specific port buys nothing, because RFC 8252
    /// §7.3's "MUST allow any port" leaves no room for a registration to narrow it back down.
    /// </para>
    /// <para>
    /// <see cref="Uri.UserInfo"/> must be empty on both sides, and neither side may carry a fragment —
    /// a REQUESTED candidate's fragment is refused rather than rejected-with-a-different-error, and a
    /// REGISTERED candidate's fragment is refused rather than silently stripped before comparison
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>: "The
    /// endpoint URI MUST NOT include a fragment component."): a deployment that registered one has a
    /// configuration defect worth surfacing as a permanent non-match, not silently widening what a
    /// request must reproduce.
    /// </para>
    /// <para>
    /// A path-less loopback redirect (<c>http://127.0.0.1:5000</c>, with no trailing <c>/</c>) is
    /// refused too, on the same canonical-form gate: <see cref="Uri.AbsoluteUri"/> always renders an
    /// <c>http</c> authority with at least a <c>/</c> path, so its <c>OriginalString</c> and
    /// <c>AbsoluteUri</c> disagree and the candidate never reaches the host check. RFC 8252 §7.3 does
    /// not forbid the path-less form; a deployment that wants it registers the single-slash spelling.
    /// </para>
    /// </remarks>
    public static bool IsRegisteredLoopback(
        IReadOnlyCollection<Uri> registered, Uri requested, bool isLocalhostNameAccepted)
    {
        ArgumentNullException.ThrowIfNull(registered);
        ArgumentNullException.ThrowIfNull(requested);

        if(!IsCanonicalLoopbackCandidate(requested, isLocalhostNameAccepted, out string requestedHost))
        {
            return false;
        }

        foreach(Uri candidate in registered)
        {
            if(IsCanonicalLoopbackCandidate(candidate, isLocalhostNameAccepted, out string candidateHost)
                && string.Equals(candidateHost, requestedHost, StringComparison.Ordinal)
                && string.Equals(candidate.AbsolutePath, requested.AbsolutePath, StringComparison.Ordinal)
                && string.Equals(candidate.Query, requested.Query, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Returns <see langword="true"/> and the canonicalized loopback <paramref name="host"/> when
    /// <paramref name="uri"/> qualifies as a loopback redirect URI candidate per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see> — see the
    /// "Canonical-form gate" remarks on <see cref="IsRegisteredLoopback"/> for the full discipline
    /// this method applies. Used identically for both the requested URI and every registered
    /// candidate: neither side gets a laxer check than the other.
    /// </summary>
    /// <param name="uri">The URI to inspect.</param>
    /// <param name="isLocalhostNameAccepted">Whether the <c>localhost</c> literal is recognized.</param>
    /// <param name="host">The canonicalized loopback host literal on success; empty otherwise.</param>
    private static bool IsCanonicalLoopbackCandidate(Uri uri, bool isLocalhostNameAccepted, out string host)
    {
        host = string.Empty;

        //Absolute-URI checked FIRST, before any other member is read: RFC 6749 §3.1.2 requires "an
        //absolute URI", and Uri.Scheme, Uri.Fragment and every other component below throw
        //InvalidOperationException on a relative Uri, so a relative registered candidate must be a
        //silent non-match here rather than a thrown exception.
        if(!uri.IsAbsoluteUri)
        {
            return false;
        }

        //Scheme checked next, ordinally: on a platform where Uri.TryCreate(text, UriKind.Absolute,
        //...) treats a bare "/path" as an implicit file: URI (observed on non-Windows hosts — see
        //RedirectUriMatchingTests's file-scheme vector), this refuses the candidate before any other
        //component is inspected. RFC 3986 §3.1 treats scheme names as case-insensitive and Uri.Scheme
        //is always lower-cased by the parser regardless of wire casing, so this ordinal comparison
        //accepts "HTTP://" wire text with no separate case-insensitive branch; the canonical-form gate
        //directly below then refuses that uppercase wire spelling anyway, since Uri.AbsoluteUri
        //lower-cases the scheme and so an uppercase OriginalString never round-trips against it.
        if(!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal))
        {
            return false;
        }

        //The canonical-form gate: see the "Canonical-form gate" remarks on IsRegisteredLoopback for
        //the full list of wire-text attacks this one comparison refuses by construction.
        if(!string.Equals(uri.OriginalString, uri.AbsoluteUri, StringComparison.Ordinal))
        {
            return false;
        }

        if(!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        if(!uri.IsLoopback || !LoopbackHostLiterals.IsRecognized(uri.Host, isLocalhostNameAccepted))
        {
            return false;
        }

        host = uri.Host;

        return true;
    }
}
