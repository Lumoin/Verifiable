using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Adversarial vectors for <see cref="RedirectUriMatching.IsRegisteredExact"/> — RFC 9700 §2.1 /
/// draft-ietf-oauth-client-id-metadata-document-02 §4.2 exact-match, simple-string-comparison
/// redirect_uri enforcement — and for its RFC 8252 §7.3 loopback-interface companion,
/// <see cref="RedirectUriMatching.IsRegisteredLoopback"/>. Part A drives the exact matcher
/// directly; Part B proves the PAR endpoint (<see cref="WellKnownEndpointNames.AuthCodePar"/>)
/// rejects a <see cref="Uri"/>-equal-but-string-different <c>redirect_uri</c> end-to-end via the
/// real dispatcher (<c>TestHostShell.DispatchAtEndpointAsync</c>), never
/// <see cref="Uri.Equals(object?)"/>. Part C drives the loopback matcher directly, including the
/// canonical-form gate's adversarial vectors (leading whitespace, non-canonical port spellings,
/// alternate IPv4/IPv6 encodings, the bracketed-IPv6-plus-suffix trick, and the <c>localhost</c>
/// policy toggle); Part D proves the fallback wired at the AuthCode endpoints in-process — gated to
/// a public PKCE-S256 client, and bound at the token endpoint to the exact redirect_uri Authorize
/// persisted, never the registered entry. Part E proves the same clauses over TestHostShell's real
/// Kestrel-bound HTTPS loopback socket, including the direct-Authorize and JAR gates, the
/// <c>localhost</c> opt-in, and the RFC 6749 §4.1.3 / OAuth 2.1 §10.2 token-endpoint rule. Every
/// Part E test crosses <see cref="TestHostShell"/>'s real Kestrel-bound HTTPS loopback listener
/// (<c>TestHostShell.StartHttpHostAsync</c> / <c>SharedHttpClient</c> over a genuine TCP socket),
/// never <c>DispatchAtEndpointAsync</c>'s in-process composition. <see cref="AuthCodeFlowDriver"/>
/// and <see cref="OAuthClient"/> drive the legs a client abstraction can produce;
/// <see cref="RawAuthCodeWirePushers"/> drives the wire shapes it cannot (a non-S256
/// <c>code_challenge_method</c>, and an absent <c>redirect_uri</c> at the token endpoint).
/// </summary>
[TestClass]
internal sealed class RedirectUriMatchingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string ClientId = "https://client.example.com";
    private static Uri ClientBaseUri { get; } = new(ClientId);

    /// <summary>The redirect URI <see cref="TestHostShell.RegisterDpopClientAsync"/> registers by default.</summary>
    private static Uri RegisteredRedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>The authenticated subject Part D's Authorize dispatches assert as already signed in.</summary>
    private const string LoopbackSubjectId = "subject-loopback-fallback";


    /// <summary>
    /// The library's loopback fallback independently requires a verifier-concealing method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>:
    /// "When using PKCE, clients SHOULD use PKCE code challenge methods that do not expose
    /// the PKCE verifier in the authorization request." A public client's plain method is refused
    /// even when only the port differs under
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>.
    /// </summary>
    [TestMethod]
    public void LoopbackFallbackRefusesPlainPkceIndependently()
    {
        ExchangeContext context = [];

        bool isAccepted = Verifiable.OAuth.AuthCode.AuthCodeEndpoints.IsAcceptableRedirectUri(
            [new Uri("http://127.0.0.1/cb")], new Uri("http://127.0.0.1:49152/cb"),
            null, WellKnownCodeChallengeMethods.Plain, context);

        Assert.IsFalse(isAccepted, "The loopback fallback independently requires S256 for a public client.");
    }


    [TestMethod]
    public void ExactStringMatchIsAccepted()
    {
        Uri registered = new("https://app.example/cb");
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsTrue(isMatch);
    }


    /// <summary>
    /// draft-ietf-oauth-client-id-metadata-document-02 §3's own example: a registered URL with no
    /// explicit port and a requested URL carrying the DEFAULT https port (:443) are NOT equivalent
    /// under simple string comparison, even though <see cref="Uri"/> equality treats them as the
    /// same authority.
    /// </summary>
    [TestMethod]
    public void DefaultPortVariantIsRejected()
    {
        Uri registered = new("https://app.example/cb");
        Uri requested = new("https://app.example:443/cb");

        //Sanity: Uri equality DOES consider these the same — this is exactly the laxity
        //RedirectUriMatching exists to avoid.
        Assert.AreEqual(registered, requested);

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// A percent-encoding case variant (<c>%2F</c> vs <c>%2f</c>) is a different octet sequence on
    /// the wire per RFC 3986 §6.2.1 simple string comparison, even though some URI parsers
    /// case-normalize percent-encoded triplets.
    /// </summary>
    [TestMethod]
    public void PercentEncodingCaseVariantIsRejected()
    {
        Uri registered = new("https://app.example/a%2Fb");
        Uri requested = new("https://app.example/a%2fb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    [TestMethod]
    public void NoRegisteredUrisNeverMatch()
    {
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([], requested);

        Assert.IsFalse(isMatch);
    }


    [TestMethod]
    public void MatchesOneOfSeveralRegisteredUris()
    {
        Uri[] registered =
        [
            new Uri("https://app.example/a"),
            new Uri("https://app.example/cb"),
            new Uri("https://app.example/c")
        ];
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact(registered, requested);

        Assert.IsTrue(isMatch);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>: "The
    /// endpoint URI MUST NOT include a fragment component." A registered entry that itself carries a
    /// fragment never matches, even a byte-identical request — the defect is surfaced as a permanent
    /// non-match rather than accepted because the two strings happen to be ordinally equal.
    /// </summary>
    [TestMethod]
    public void RegisteredCandidateWithFragmentNeverMatchesIdenticalRequestExact()
    {
        Uri registered = new("https://app.example/cb#x");
        Uri requested = new("https://app.example/cb#x");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>'s
    /// fragment prohibition applies to the requested value too: a fragment-bearing requested URI
    /// never matches a fragment-less registered entry.
    /// </summary>
    [TestMethod]
    public void RequestedUriWithFragmentNeverMatchesExact()
    {
        Uri registered = new("https://app.example/cb");
        Uri requested = new("https://app.example/cb#frag");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>
    /// requires the redirection endpoint URI to be "an absolute URI." A relative registered entry is
    /// a configuration defect surfaced as a silent non-match, never a thrown exception:
    /// <see cref="Uri.IsAbsoluteUri"/> is checked before any other <see cref="Uri"/> member, since
    /// e.g. <see cref="Uri.Fragment"/> throws <see cref="InvalidOperationException"/> on a relative
    /// <see cref="Uri"/>.
    /// </summary>
    [TestMethod]
    public void RelativeRegisteredCandidateNeverMatchesNorThrowsExact()
    {
        Uri registered = new("/cb", UriKind.Relative);
        Uri requested = new("https://app.example/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredExact([registered], requested);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// The PAR endpoint rejects a <c>redirect_uri</c> that differs from the registered value only
    /// by an explicit default port — proving <see cref="RedirectUriMatching"/>, not
    /// <see cref="Uri.Equals(object?)"/>, governs the wire enforcement (RFC 9700 §2.1 /
    /// draft-ietf-oauth-client-id-metadata-document-02 §4.2).
    /// </summary>
    [TestMethod]
    public async Task ParRejectsDefaultPortVariantOfRegisteredRedirectUri()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //Same authority under Uri equality, different octets under simple string comparison.
        string portVariant = "https://client.example.com:443/callback";
        Assert.AreEqual(RegisteredRedirectUri, new Uri(portVariant),
            "Sanity: the :443 variant must be Uri-equal to the registered redirect_uri for this to be a meaningful adversarial vector.");

        ServerHttpResponse response = await PushAsync(
            host, material, redirectUri: portVariant).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal);
    }


    /// <summary>Sanity: the exact registered redirect_uri string is accepted by the same PAR path.</summary>
    [TestMethod]
    public async Task ParAcceptsExactRegisteredRedirectUri()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await PushAsync(
            host, material, redirectUri: RegisteredRedirectUri.OriginalString).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// The authorize redirect's <c>Location</c> is built from a registered redirect_uri's
    /// <see cref="Uri.OriginalString"/>, never <see cref="Uri.ToString()"/>: a redirect_uri that
    /// restates the HTTPS default port (<c>:443</c>) exposes the divergence, since
    /// <see cref="Uri.ToString()"/> elides the default port while <see cref="Uri.OriginalString"/>
    /// keeps it, and the token endpoint's
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>
    /// identical-value check binds to the persisted <c>OriginalString</c>.
    /// </summary>
    [TestMethod]
    public async Task AuthorizeRedirectEchoesOriginalStringSoADefaultPortRedirectUriRedeemsSuccessfully()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        const string portRestatedRedirectUri = "https://client.example.com:443/callback";
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri(portRestatedRedirectUri)), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = portRestatedRedirectUri,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(LoopbackSubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.StartsWith(portRestatedRedirectUri, authorizeResponse.Location, StringComparison.Ordinal);

        string code = ExtractCode(authorizeResponse.Location);
        ServerHttpResponse tokenResponse = await ExchangeLoopbackCodeAsync(
            host, material, code, portRestatedRedirectUri, pkce).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
    }


    private async Task<ServerHttpResponse> PushAsync(
        TestHostShell host, VerifierKeyMaterial material, string redirectUri)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            fields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives <see cref="RedirectUriMatching.IsRegisteredLoopback"/>'s canonical-form gate and host,
    /// path, query and fragment rules across the adversarial vector table:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>'s any-port
    /// allowance, its own port-elision consequence for a registered candidate, the
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.3">RFC 8252 §8.3</see>
    /// <c>localhost</c> opt-in, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>'s
    /// fragment refusal on either side.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><description>
    /// The positive rows (the 127.0.0.1 ephemeral-port, identical-port, and query-string rows, the
    /// <c>[::1]</c> row, and the accepted-<c>localhost</c> row): <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>
    /// any port, or none, matches a registered loopback entry regardless of whether the
    /// registration itself carries a port; path and query are preserved. The default http port is
    /// NOT re-stated explicitly on either side of a positive row — see the <c>:80</c> row below for
    /// why the canonical-form gate refuses it when it is.
    /// </description></item>
    /// <item><description>
    /// The registered-port row (<c>http://127.0.0.1:9999/cb</c> vs <c>http://127.0.0.1:1/cb</c>): a
    /// registered candidate's own port is ignored too, once the fallback runs — registering a
    /// specific port buys nothing against RFC 8252 §7.3's "MUST allow any port".
    /// </description></item>
    /// <item><description>
    /// The localhost-refused-by-default row: <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.3">RFC 8252 §8.3</see>
    /// "the use of localhost is NOT RECOMMENDED" is honored by refusing the literal by default; the
    /// positive row above passes <c>isLocalhostNameAccepted: true</c>.
    /// </description></item>
    /// <item><description>
    /// The uppercase-<c>LOCALHOST</c> row: <c>AbsoluteUri</c> lower-cases the host, so an uppercase
    /// wire spelling never round-trips through the canonical-form gate, REGARDLESS of the localhost
    /// policy.
    /// </description></item>
    /// <item><description>
    /// The <c>:80</c> row: it re-states the http default port, which <c>AbsoluteUri</c> elides; the
    /// wire text and the canonical rendering disagree, so this is refused by construction.
    /// </description></item>
    /// <item><description>
    /// The <c>:080</c> and empty-port (<c>:</c>) rows: a non-canonical port spelling and an empty
    /// port likewise never round-trip through <c>AbsoluteUri</c>.
    /// </description></item>
    /// <item><description>
    /// The leading-whitespace row: it is trimmed by <c>AbsoluteUri</c> but retained in
    /// <c>OriginalString</c>.
    /// </description></item>
    /// <item><description>
    /// The path-less requested-URI row (<c>http://127.0.0.1:1</c>): a path-less http authority never
    /// round-trips — <c>AbsoluteUri</c> always renders at least "/" for an http authority, so
    /// <c>OriginalString</c> and <c>AbsoluteUri</c> disagree.
    /// </description></item>
    /// <item><description>
    /// The path-less registered-URI row (<c>http://127.0.0.1</c>): the same path-less form is
    /// refused identically as a registered candidate.
    /// </description></item>
    /// <item><description>
    /// The <c>https://app.example</c> row: non-loopback traffic is untouched; only
    /// <see cref="RedirectUriMatching.IsRegisteredExact"/> governs it.
    /// </description></item>
    /// <item><description>
    /// The <c>/other</c>, trailing-slash, dot-segment (<c>/cb/../x</c>), and case (<c>/CB</c>) rows:
    /// path/query is ordinal, non-normalized equality with the registered entry.
    /// </description></item>
    /// <item><description>
    /// The <c>https://127.0.0.1</c> requested-scheme row: scheme must be http on both sides; https
    /// stays on <see cref="RedirectUriMatching.IsRegisteredExact"/> alone.
    /// </description></item>
    /// <item><description>
    /// The <c>file:///etc/passwd</c> row: a non-http scheme is refused by the scheme check first,
    /// exactly the guard that matters when <c>Uri.TryCreate(text, UriKind.Absolute, ...)</c> treats
    /// a bare "/path" as an implicit <c>file:</c> URI on a platform where that parsing quirk
    /// applies.
    /// </description></item>
    /// <item><description>
    /// The <c>127.0.0.1.evil.example</c> and <c>localhost.evil.example</c> rows: a host merely
    /// starting/ending with a loopback literal is not the literal.
    /// </description></item>
    /// <item><description>
    /// The two userinfo rows (<c>127.0.0.1@evil.example</c> and <c>evil@127.0.0.1</c>): userinfo on
    /// either side is refused, even when the host component genuinely is loopback.
    /// </description></item>
    /// <item><description>
    /// The IPv4 shorthand/octal/decimal/hex rows (<c>127.1</c>, <c>0177.0.0.1</c>,
    /// <c>2130706433</c>, <c>0x7f000001</c>): <c>Uri</c> silently canonicalizes each of these onto
    /// <c>Host == "127.0.0.1"</c>; the wire text never round-trips through <c>AbsoluteUri</c>, so
    /// the canonical-form gate refuses them (see
    /// <see cref="RedirectUriMatching.IsRegisteredLoopback"/>'s remarks).
    /// </description></item>
    /// <item><description>
    /// The <c>0.0.0.0</c> and <c>127.0.0.2</c> rows: <c>Uri.IsLoopback</c> is true for both, but
    /// neither is a recognized literal. These two pass the canonical-form gate
    /// (<c>OriginalString == AbsoluteUri</c>); <c>Uri.IsLoopback</c>/the recognized-literal check is
    /// what refuses them, so a future switch of the literal check alone must still fail these.
    /// </description></item>
    /// <item><description>
    /// The homoglyph (<c>localhoſt</c>) and trailing-dot FQDN (<c>localhost.</c>,
    /// <c>127.0.0.1.</c>) rows: a host homoglyph or a trailing-dot FQDN also passes the
    /// canonical-form gate (<c>OriginalString == AbsoluteUri</c>) but is refused only because it is
    /// not one of the recognized literals and <c>Uri.IsLoopback</c> is false for it — the
    /// literal/IsLoopback check, not the canonical gate, is what must keep refusing these if the
    /// literal check is ever widened.
    /// </description></item>
    /// <item><description>
    /// The IPv6 zone-id (<c>%25eth0</c>) row: <c>Uri.Host</c> strips the zone id (rendering
    /// <c>[::1]</c>, <c>IsLoopback</c> true) but <c>OriginalString</c> retains <c>%25eth0</c>, so the
    /// canonical-form gate refuses it — pinned so a future switch of the round-trip check must still
    /// fail this vector.
    /// </description></item>
    /// <item><description>
    /// The IPv4-mapped IPv6 rows (<c>[::ffff:127.0.0.1]</c>, <c>[::ffff:7f00:1]</c>): an IPv4-mapped
    /// IPv6 form is a different address-family encoding, not <c>[::1]</c>.
    /// </description></item>
    /// <item><description>
    /// The IPv6 longhand (<c>[0:0:0:0:0:0:0:1]</c>) row: pinned behavior — <c>Uri.Host</c>
    /// normalizes this longhand form to <c>[::1]</c> too, but <c>AbsoluteUri</c> renders the SHORT
    /// form while <c>OriginalString</c> keeps the longhand spelling, so the canonical-form gate
    /// refuses it — the same refuse-unless-canonical rule applied uniformly rather than carving out
    /// a special case for IPv6.
    /// </description></item>
    /// <item><description>
    /// The bracketed-IPv6-plus-suffix rows (<c>]evil.example</c>, <c>];x</c>, <c>]%00</c>): on this
    /// runtime, <c>Uri.TryCreate</c> refuses to construct an instance for a bracketed-IPv6 authority
    /// followed by trailing text (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC
    /// 3986 §3.2.2</see> IP-literal syntax), so the authority is refused at construction, before
    /// <see cref="RedirectUriMatching.IsRegisteredLoopback"/> ever runs; the helper below mirrors
    /// that refusal exactly as the endpoint's own <c>Uri.TryCreate</c> gate would.
    /// </description></item>
    /// <item><description>
    /// The registered-fragment (<c>#reg</c>) row: a registered candidate carrying a fragment is
    /// refused outright per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>
    /// ("The endpoint URI MUST NOT include a fragment component"), never silently stripped before
    /// comparison.
    /// </description></item>
    /// <item><description>
    /// The requested-fragment (<c>#frag</c>) row: a fragment on the requested URI is refused the
    /// same way.
    /// </description></item>
    /// <item><description>
    /// The cross-literal row (<c>localhost</c> registered vs <c>127.0.0.1</c> requested): no
    /// cross-matching between the recognized host literals.
    /// </description></item>
    /// </list>
    /// </remarks>
    [TestMethod]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:54321/cb", false, true)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1/cb", false, true)]
    [DataRow("http://[::1]/cb", "http://[::1]:8080/cb", false, true)]
    [DataRow("http://localhost/cb", "http://localhost:3000/cb", true, true)]
    [DataRow("http://127.0.0.1/cb?x=1", "http://127.0.0.1:9/cb?x=1", false, true)]
    [DataRow("http://127.0.0.1:9999/cb", "http://127.0.0.1:1/cb", false, true)]
    [DataRow("http://localhost/cb", "http://localhost:3000/cb", false, false)]
    [DataRow("http://localhost/cb", "http://LOCALHOST:3000/cb", true, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:80/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:080/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", " http://127.0.0.1:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:1", false, false)]
    [DataRow("http://127.0.0.1", "http://127.0.0.1:1/cb", false, false)]
    [DataRow("https://app.example/cb", "https://app.example:8443/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:1/other", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:1/cb/", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:1/cb/../x", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:1/CB", false, false)]
    [DataRow("http://127.0.0.1/cb", "https://127.0.0.1:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "file:///etc/passwd", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1.evil.example:1/cb", false, false)]
    [DataRow("http://localhost/cb", "http://localhost.evil.example:1/cb", true, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1@evil.example/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://evil@127.0.0.1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.1:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://0177.0.0.1:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://2130706433:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://0x7f000001:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://0.0.0.0:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.2:1/cb", false, false)]
    [DataRow("http://localhost/cb", "http://localhoſt:1/cb", true, false)]
    [DataRow("http://localhost/cb", "http://localhost.:1/cb", true, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1.:1/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[::1%25eth0]:1/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[::ffff:127.0.0.1]:1/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[::ffff:7f00:1]:1/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[0:0:0:0:0:0:0:1]:1/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[::1]evil.example/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[::1];x/cb", false, false)]
    [DataRow("http://[::1]/cb", "http://[::1]%00/cb", false, false)]
    [DataRow("http://127.0.0.1/cb#reg", "http://127.0.0.1:1/cb", false, false)]
    [DataRow("http://127.0.0.1/cb", "http://127.0.0.1:1/cb#frag", false, false)]
    [DataRow("http://localhost/cb", "http://127.0.0.1:1/cb", true, false)]
    public void LoopbackMatchProducesTheExpectedResultAcrossTheVectorTable(
        string registeredUri, string requestedUri, bool isLocalhostNameAccepted, bool expectedMatch)
    {
        bool isMatch = MatchesAsTheEndpointConstructsIt(registeredUri, requestedUri, isLocalhostNameAccepted);

        Assert.AreEqual(expectedMatch, isMatch, $"registered='{registeredUri}' requested='{requestedUri}'");
    }


    /// <summary>
    /// Mirrors the URI construction the authorization endpoint performs before matching a redirect_uri
    /// (<see cref="Verifiable.OAuth.AuthCode.AuthCodeEndpoints"/> constructs the requested value with
    /// <c>Uri.TryCreate(text, UriKind.Absolute, out _)</c> and refuses the request before any match is
    /// attempted when that construction fails): a wire value the runtime refuses to parse as an
    /// absolute <see cref="Uri"/> is refused here the same way, without ever reaching
    /// <see cref="RedirectUriMatching.IsRegisteredLoopback"/>. The registered value is a fixture-authored
    /// literal, expected to always parse, and is constructed directly rather than through the wire-value
    /// path so a malformed fixture fails loudly instead of silently returning false.
    /// </summary>
    private static bool MatchesAsTheEndpointConstructsIt(string registeredUri, string requestedUri, bool isLocalhostNameAccepted)
    {
        Uri registered = new(registeredUri);

        if(!Uri.TryCreate(requestedUri, UriKind.Absolute, out Uri? requested))
        {
            return false;
        }

        return RedirectUriMatching.IsRegisteredLoopback([registered], requested, isLocalhostNameAccepted);
    }


    /// <summary>A client with no loopback-shaped registration at all cannot use the fallback.</summary>
    [TestMethod]
    public void NoLoopbackRegistrationNeverMatchesALoopbackRequest()
    {
        Uri registered = new("https://client.example.com/callback");
        Uri requested = new("http://127.0.0.1:54321/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredLoopback([registered], requested, isLocalhostNameAccepted: false);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// An empty registered set admits no candidate, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>'s any-port
    /// allowance never has anything to match a request against.
    /// </summary>
    [TestMethod]
    public void EmptyRegisteredSetNeverMatchesTheLoopbackFallback()
    {
        Uri requested = new("http://127.0.0.1:54321/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredLoopback([], requested, isLocalhostNameAccepted: false);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>: "The
    /// endpoint URI MUST NOT include a fragment component." A registered entry that itself carries a
    /// fragment never matches, even a byte-identical request presented on the loopback path.
    /// </summary>
    [TestMethod]
    public void RegisteredCandidateWithFragmentNeverMatchesIdenticalRequestLoopback()
    {
        Uri registered = new("http://127.0.0.1/cb#x");
        Uri requested = new("http://127.0.0.1/cb#x");

        bool isMatch = RedirectUriMatching.IsRegisteredLoopback([registered], requested, isLocalhostNameAccepted: false);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>'s
    /// fragment prohibition applies to the requested value too on the loopback path: a
    /// fragment-bearing requested URI never matches a fragment-less registered entry.
    /// </summary>
    [TestMethod]
    public void RequestedUriWithFragmentNeverMatchesLoopback()
    {
        Uri registered = new("http://127.0.0.1/cb");
        Uri requested = new("http://127.0.0.1/cb#frag");

        bool isMatch = RedirectUriMatching.IsRegisteredLoopback([registered], requested, isLocalhostNameAccepted: false);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>
    /// requires the redirection endpoint URI to be "an absolute URI." A relative registered entry is
    /// a configuration defect surfaced as a silent non-match on the loopback path too, never a
    /// thrown exception — <see cref="Uri.IsAbsoluteUri"/> is the first member the canonical-form
    /// gate reads.
    /// </summary>
    [TestMethod]
    public void RelativeRegisteredCandidateNeverMatchesNorThrowsLoopback()
    {
        Uri registered = new("/cb", UriKind.Relative);
        Uri requested = new("http://127.0.0.1/cb");

        bool isMatch = RedirectUriMatching.IsRegisteredLoopback([registered], requested, isLocalhostNameAccepted: false);

        Assert.IsFalse(isMatch);
    }


    /// <summary>
    /// A public PKCE-S256 client registered with the portless loopback redirect_uri
    /// <c>http://127.0.0.1/cb</c> completes PAR → Authorize → Token using an ephemeral-port
    /// redirect_uri the registration never listed verbatim, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>. The code
    /// state Authorize persists carries that exact ephemeral URI — proving the token endpoint's
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see> check
    /// (<c>ServerCodeIssuedState.RedirectUri</c>) binds to what was actually presented, not to the
    /// registered, portless entry the loopback fallback matched it against.
    /// </summary>
    [TestMethod]
    public async Task PublicPkceClientCompletesFullJourneyWithEphemeralLoopbackPort()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        const string ephemeralRedirectUri = "http://127.0.0.1:54321/cb";

        (string code, PkceParameters pkce) = await DriveLoopbackParAndAuthorizeAsync(
            host, material, ephemeralRedirectUri).ConfigureAwait(false);

        ServerCodeIssuedState persisted = host.FlowStore.Values
            .Select(entry => entry.State)
            .OfType<ServerCodeIssuedState>()
            .Single();
        Assert.AreEqual(ephemeralRedirectUri, persisted.RedirectUri.OriginalString,
            "Authorize must persist the exact ephemeral redirect_uri actually presented at PAR, " +
            "never the registered portless entry the loopback fallback matched it against.");

        ServerHttpResponse tokenResponse = await ExchangeLoopbackCodeAsync(
            host, material, code, ephemeralRedirectUri, pkce).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.IsFalse(string.IsNullOrEmpty(ExtractFromBody(tokenResponse.Body, "access_token")));
        Assert.IsFalse(string.IsNullOrEmpty(ExtractFromBody(tokenResponse.Body, "refresh_token")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>: a
    /// token request naming a DIFFERENT loopback port than the one Authorize persisted for this
    /// code is refused <c>invalid_grant</c> — the check is an exact-string bind to the persisted
    /// value, never a re-run of the loopback fallback (which would accept any port and so would
    /// wrongly let this through).
    /// </summary>
    [TestMethod]
    public async Task TokenExchangePresentingADifferentPortThanAuthorizeIsInvalidGrant()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        (string code, PkceParameters pkce) = await DriveLoopbackParAndAuthorizeAsync(
            host, material, "http://127.0.0.1:54321/cb").ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await ExchangeLoopbackCodeAsync(
            host, material, code, "http://127.0.0.1:60999/cb", pkce).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, tokenResponse.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.4">RFC 8252 §8.4</see> scopes the
    /// loopback fallback to public clients: a confidential client (a declared
    /// <c>token_endpoint_auth_method</c>) registered with the same portless loopback redirect_uri
    /// is refused at PAR when it presents an ephemeral-port redirect_uri — the fallback never runs,
    /// so only the exact registered string would have been accepted.
    /// </summary>
    [TestMethod]
    public async Task ConfidentialClientCannotUseTheLoopbackFallbackAtPar()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material,
            ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")),
            tokenEndpointAuthMethod: ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);

        //RFC 9126 §2: the pushed request now authenticates the client before the redirect_uri check
        //this test is about; a validator that accepts unconditionally isolates that check the same
        //way the in-process dispatch this test already uses isolates it from real network I/O.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.ClientSecretBasic];
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        ServerHttpResponse parResponse = await PushAsync(
            host, material, redirectUri: "http://127.0.0.1:54321/cb").ConfigureAwait(false);

        Assert.AreEqual(400, parResponse.StatusCode, parResponse.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, parResponse.Body, StringComparison.Ordinal);
        Assert.Contains("not among the registered redirect URIs", parResponse.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// Drives PAR → Authorize for <paramref name="redirectUri"/> against the loopback-registered
    /// client and returns the authorization code from the wire redirect <c>Location</c>, together
    /// with the PKCE parameters used, so the caller drives the token step itself — letting the two
    /// negative tests above present a token-endpoint redirect_uri that deliberately differs from
    /// the one used here.
    /// </summary>
    private async Task<(string Code, PkceParameters Pkce)> DriveLoopbackParAndAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, string redirectUri)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body!, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(LoopbackSubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        return (ExtractCode(authorizeResponse.Location!), pkce);
    }


    /// <summary>
    /// Redeems <paramref name="code"/> at the token endpoint, presenting <paramref name="redirectUri"/>
    /// as the request's <c>redirect_uri</c> — the caller controls this independently of what was
    /// used at PAR/Authorize so the RFC 6749 §4.1.3 mismatch case can be driven.
    /// </summary>
    private async Task<ServerHttpResponse> ExchangeLoopbackCodeAsync(
        TestHostShell host, VerifierKeyMaterial material, string code, string redirectUri, PkceParameters pkce)
    {
        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Extracts a top-level string property from a JSON response body.</summary>
    private static string ExtractFromBody(string body, string property)
    {
        using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(body);

        return document.RootElement.GetProperty(property).GetString()!;
    }


    /// <summary>Extracts the <c>code</c> query parameter from an authorize redirect <c>Location</c>.</summary>
    private static string ExtractCode(string location)
    {
        Uri uri = new(location);
        string query = uri.Query.TrimStart('?');
        foreach(string pair in query.Split('&'))
        {
            string[] parts = pair.Split('=', 2);
            if(parts.Length == 2 && parts[0] == "code")
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        throw new InvalidOperationException($"No code in redirect: {location}");
    }


    /// <summary>The client identifier Part E's real-wire drives register and dispatch under.</summary>
    private const string LoopbackClientId = "https://loopback-client.example.com";

    /// <summary><see cref="LoopbackClientId"/> as a <see cref="Uri"/>, the shape client registration requires.</summary>
    private static Uri LoopbackClientBaseUri { get; } = new(LoopbackClientId);

    /// <summary>
    /// The capabilities Part E's registrations need to exercise every gated site: PAR, direct
    /// Authorize, and the JAR (RFC 9101 request-object) entry point.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> LoopbackCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>: "The
    /// authorization server MUST allow any port to be specified at the time of the request for
    /// loopback IP redirect URIs, to accommodate clients that obtain an available ephemeral port
    /// from the operating system at the time of the request." Two genuinely distinct OS-assigned
    /// ephemeral ports each complete PAR → authorize → token over the real wire against a
    /// registration carrying only the portless <c>http://127.0.0.1/cb</c> entry.
    /// </summary>
    [TestMethod]
    public async Task RealWireEphemeralLoopbackPortsCompleteTheFullJourney()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        int[] ports = BindEphemeralLoopbackPorts(IPAddress.Loopback, 2);
        int portA = ports[0];
        int portB = ports[1];
        Assert.AreNotEqual(portA, portB,
            "The two OS-assigned ephemeral ports must genuinely differ to prove the any-port allowance twice over.");

        foreach(int port in new[] { portA, portB })
        {
            Uri redirectUri = new($"http://127.0.0.1:{port}/cb");
            AuthCodeFlowDriveResult result = await DriveLoopbackJourneyOverRealWireAsync(
                host, material, redirectUri).ConfigureAwait(false);

            Assert.IsFalse(string.IsNullOrEmpty((string)result.TokenResult.Body![OAuthRequestParameterNames.AccessToken]));
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see>'s
    /// <c>http://[::1]:{port}/{path}</c> example: a genuinely bound
    /// <see cref="IPAddress.IPv6Loopback"/> ephemeral port completes PAR → authorize → token over
    /// the real wire. Reports <see cref="Assert.Inconclusive(string)"/> rather than failing when
    /// the host has no IPv6 loopback interface to bind.
    /// </summary>
    [TestMethod]
    public async Task RealWireIpv6LoopbackLiteralCompletesTheFullJourney()
    {
        int port = TryBindEphemeralLoopbackPort(IPAddress.IPv6Loopback, out int boundPort) ? boundPort : -1;
        if(port < 0)
        {
            Assert.Inconclusive("This host has no IPv6 loopback interface to bind ::1 on.");

            return;
        }

        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://[::1]/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        Uri redirectUri = new($"http://[::1]:{port}/cb");
        AuthCodeFlowDriveResult result = await DriveLoopbackJourneyOverRealWireAsync(
            host, material, redirectUri).ConfigureAwait(false);

        Assert.IsFalse(string.IsNullOrEmpty((string)result.TokenResult.Body![OAuthRequestParameterNames.AccessToken]));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-7.3">RFC 8252 §7.3</see> names the
    /// <c>http</c> scheme only; an <c>https</c> loopback redirect gets no any-port allowance at PAR
    /// over the real wire.
    /// </summary>
    [TestMethod]
    public async Task RealWireHttpsLoopbackRedirectGetsNoAnyPortAllowance()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        int port = BindEphemeralLoopbackPort(IPAddress.Loopback);
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            BuildLoopbackParFields(LoopbackClientId, $"https://127.0.0.1:{port}/cb", WellKnownCodeChallengeMethods.S256),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.3">RFC 8252 §8.3</see>: "the use
    /// of localhost is NOT RECOMMENDED." Refused at PAR over the real wire by default; accepted
    /// through the full PAR → authorize → token journey once the deployment opts in via
    /// <see cref="PolicyExchangeContextExtensions.SetIsLocalhostNameAcceptedForLoopbackRedirects"/>
    /// — the <see href="https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization">
    /// MCP authorization specification</see>'s "All redirect URIs MUST be either `localhost` or use
    /// HTTPS." is the deployment-side reason to opt in.
    /// </summary>
    [TestMethod]
    public async Task RealWireLocalhostIsRefusedByDefaultAndAcceptedUnderExplicitOptIn()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://localhost/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        int port = BindEphemeralLoopbackPort(IPAddress.Loopback);
        Uri redirectUri = new($"http://localhost:{port}/cb");

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            BuildLoopbackParFields(LoopbackClientId, redirectUri.OriginalString, WellKnownCodeChallengeMethods.S256),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolvePolicyAsync = (_, policyContext, _) =>
            {
                PolicyProfiles.ApplyRfc6749WithPkce(policyContext);
                policyContext.SetIsLocalhostNameAcceptedForLoopbackRedirects(true);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        AuthCodeFlowDriveResult accepted = await DriveLoopbackJourneyOverRealWireAsync(
            host, material, redirectUri).ConfigureAwait(false);

        Assert.IsFalse(string.IsNullOrEmpty((string)accepted.TokenResult.Body![OAuthRequestParameterNames.AccessToken]));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>'s
    /// exact-match discipline governs a non-loopback registration unconditionally: a different port
    /// on the registered host admits only the exact registered string, whatever the port, and is
    /// refused at PAR over the real wire.
    /// </summary>
    [TestMethod]
    public async Task RealWireNonLoopbackHostWithADifferentPortIsRefused()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            BuildLoopbackParFields(LoopbackClientId, $"{LoopbackClientId}:9443/callback", WellKnownCodeChallengeMethods.S256),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>: "The
    /// endpoint URI MUST NOT include a fragment component." A registered redirect_uri that itself
    /// carries a fragment is a configuration defect refused as a permanent non-match at PAR over the
    /// real wire — even a byte-identical request never receives the wire-level success it would
    /// under simple string comparison alone.
    /// </summary>
    [TestMethod]
    public async Task RealWireRegisteredRedirectUriWithFragmentIsRefusedAtPar()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        const string fragmentRedirectUri = "https://client.example.com/cb#x";
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri(fragmentRedirectUri)), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            BuildLoopbackParFields(LoopbackClientId, fragmentRedirectUri, WellKnownCodeChallengeMethods.S256),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);
        Assert.Contains("not among the registered redirect URIs", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>'s
    /// S256 gate on the loopback fallback, over the real wire, at the direct (non-PAR) authorize
    /// entry point: an ephemeral loopback port is accepted there exactly as it is at PAR.
    /// </summary>
    [TestMethod]
    public async Task RealWireDirectAuthorizeAcceptsEphemeralLoopbackPort()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        int port = BindEphemeralLoopbackPort(IPAddress.Loopback);
        string redirectUri = $"http://127.0.0.1:{port}/cb";

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(LoopbackClientId)}" +
            $"&{OAuthRequestParameterNames.ResponseType}={WellKnownResponseTypes.Code}" +
            $"&{OAuthRequestParameterNames.RedirectUri}={Uri.EscapeDataString(redirectUri)}" +
            $"&{OAuthRequestParameterNames.CodeChallenge}={pkce.EncodedChallenge}" +
            $"&{OAuthRequestParameterNames.CodeChallengeMethod}={WellKnownCodeChallengeMethods.S256}");

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, LoopbackSubjectId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)response.StatusCode,
            "RFC 8252 §7.3's any-port allowance must also govern the direct (non-PAR) authorize entry point.");
        Assert.StartsWith(redirectUri, response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>'s
    /// S256 gate on the loopback fallback, over the real wire, at the JAR (RFC 9101 request-object)
    /// entry point: an ephemeral loopback port carried inside a signed request object is accepted
    /// exactly as it is at PAR.
    /// </summary>
    [TestMethod]
    public async Task RealWireJarDispatchAcceptsEphemeralLoopbackPort()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using TestHostShell host = new(timeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, LoopbackCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        int port = BindEphemeralLoopbackPort(IPAddress.Loopback);
        Uri redirectUri = new($"http://127.0.0.1:{port}/cb");

        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, timeProvider.GetUtcNow(), LoopbackClientId, redirectUri,
            "state-loopback-jar", "nonce-loopback-jar");
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(LoopbackClientId)}" +
            $"&{OAuthRequestParameterNames.Request}={Uri.EscapeDataString(compactJar)}");

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, LoopbackSubjectId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)response.StatusCode,
            "The RFC 9101 request-object entry point must also honor the RFC 8252 §7.3 loopback fallback.");
        Assert.StartsWith(redirectUri.OriginalString, response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see> over
    /// the real wire: a token request whose <c>redirect_uri</c> is ordinal-identical to the value
    /// Authorize persisted is accepted; one naming a DIFFERENT loopback port is refused
    /// <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RealWireTokenRedirectUriIdenticalIsAcceptedAndPortSubstitutionIsInvalidGrant()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        int[] tokenPorts = BindEphemeralLoopbackPorts(IPAddress.Loopback, 2);
        int portA = tokenPorts[0];
        int portB = tokenPorts[1];
        Assert.AreNotEqual(portA, portB);

        Uri redirectUriA = new($"http://127.0.0.1:{portA}/cb");
        AuthorizationCodeReceivedState codeStateA = await DriveLoopbackCodeOverRealWireAsync(
            host, material, redirectUriA).ConfigureAwait(false);
        (int IdenticalStatus, string IdenticalBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildTokenFields(LoopbackClientId, codeStateA.Code, codeStateA.Pkce.EncodedVerifier, redirectUriA.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, IdenticalStatus, IdenticalBody);

        Uri redirectUriB = new($"http://127.0.0.1:{portB}/cb");
        AuthorizationCodeReceivedState codeStateB = await DriveLoopbackCodeOverRealWireAsync(
            host, material, redirectUriB).ConfigureAwait(false);
        (int MismatchStatus, string MismatchBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildTokenFields(LoopbackClientId, codeStateB.Code, codeStateB.Pkce.EncodedVerifier, redirectUriA.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, MismatchStatus, MismatchBody);
        Assert.Contains(OAuthErrors.InvalidGrant, MismatchBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §10.2</see>: "the authorization server MUST allow clients to send the redirect_uri parameter
    /// in the token request ... and MUST enforce the parameter as described in [RFC6749]" — the
    /// converse, a client that omits it, is accepted over the real wire when the code carries a
    /// PKCE challenge (which this library requires unconditionally), since
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see> only
    /// requires the parameter "if the redirect_uri parameter was included in the authorization
    /// request."
    /// </summary>
    [TestMethod]
    public async Task RealWireTokenRedirectUriAbsentWithPkceBoundCodeIsAccepted()
    {
        await using TestHostShell host = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            LoopbackClientId, LoopbackClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LoopbackCapabilities).ConfigureAwait(false);
        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);

        int port = BindEphemeralLoopbackPort(IPAddress.Loopback);
        Uri redirectUri = new($"http://127.0.0.1:{port}/cb");
        AuthorizationCodeReceivedState codeState = await DriveLoopbackCodeOverRealWireAsync(
            host, material, redirectUri).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildTokenFields(LoopbackClientId, codeState.Code, codeState.Pkce.EncodedVerifier, redirectUri: null),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, StatusCode, Body);
    }


    /// <summary>Binds a real ephemeral port on <paramref name="address"/> and immediately releases it.</summary>
    private static int BindEphemeralLoopbackPort(IPAddress address)
    {
        using TcpListener listener = new(address, 0);
        listener.Start();

        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }


    /// <summary>
    /// <see cref="BindEphemeralLoopbackPort"/>, reporting failure through <paramref name="port"/>
    /// and a <see langword="false"/> return instead of letting a <see cref="SocketException"/>
    /// (no such interface on this host) escape — the caller decides whether that is
    /// <see cref="Assert.Inconclusive(string)"/>, kept out of this method's own try/catch per
    /// MSTEST0058.
    /// </summary>
    private static bool TryBindEphemeralLoopbackPort(IPAddress address, out int port)
    {
        try
        {
            port = BindEphemeralLoopbackPort(address);

            return true;
        }
        catch(SocketException)
        {
            port = -1;

            return false;
        }
    }


    /// <summary>
    /// Binds <paramref name="count"/> loopback listeners on <paramref name="address"/> all AT THE
    /// SAME TIME, reads every bound port, and only then releases all of them: the operating system
    /// guarantees distinct ephemeral ports only among sockets that are bound concurrently, so binding
    /// and releasing one listener before requesting the next can hand back a port already given out.
    /// </summary>
    private static int[] BindEphemeralLoopbackPorts(IPAddress address, int count)
    {
        TcpListener?[] listeners = new TcpListener?[count];
        try
        {
            for(int i = 0; i < count; i++)
            {
                listeners[i] = new TcpListener(address, 0);
                listeners[i]!.Start();
            }

            int[] ports = new int[count];
            for(int i = 0; i < count; i++)
            {
                ports[i] = ((IPEndPoint)listeners[i]!.LocalEndpoint).Port;
            }

            return ports;
        }
        finally
        {
            foreach(TcpListener? listener in listeners)
            {
                listener?.Stop();
            }
        }
    }


    /// <summary>
    /// Drives the full real-wire PAR → authorize → token journey for <paramref name="redirectUri"/>
    /// against <paramref name="material"/>'s registration, returning the completed drive.
    /// </summary>
    private async Task<AuthCodeFlowDriveResult> DriveLoopbackJourneyOverRealWireAsync(
        TestHostShell host, VerifierKeyMaterial material, Uri redirectUri)
    {
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);

        return await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            host.Host("default"), client, registration, clientFlowStore,
            material.Registration.TenantId.Value, redirectUri, LoopbackSubjectId,
            browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the real-wire PAR → authorize → callback leg for <paramref name="redirectUri"/> and
    /// returns the client-side received-code state, ready for a hand-built token POST.
    /// </summary>
    private async Task<AuthorizationCodeReceivedState> DriveLoopbackCodeOverRealWireAsync(
        TestHostShell host, VerifierKeyMaterial material, Uri redirectUri)
    {
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            host.Host("default"), client, registration, clientFlowStore,
            material.Registration.TenantId.Value, redirectUri, LoopbackSubjectId,
            browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        return (AuthorizationCodeReceivedState)clientFlowStore[flowId];
    }


    /// <summary>Builds the PAR form fields for a fresh PKCE pair over <paramref name="redirectUri"/>.</summary>
    private static Dictionary<string, string> BuildLoopbackParFields(
        string clientId, string redirectUri, string codeChallengeMethod)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        return new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = codeChallengeMethod,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
    }
}
