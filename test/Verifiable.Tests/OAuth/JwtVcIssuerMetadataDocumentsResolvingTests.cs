using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="JwtVcIssuerMetadataDocuments.ResolveAsync"/> — the JWT VC Issuer Metadata
/// fetch-validate attempt per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#section-4">SD-JWT VC
/// draft-19, Section 4</see> — and for <see cref="JwtVcIssuerMetadataDocuments.SelectKeyAsync"/>, the
/// key-selection helper composed over its result. The single-hop transport is scripted, the
/// established outbound-fetch-consumer test pattern.
/// </summary>
[TestClass]
internal sealed class JwtVcIssuerMetadataDocumentsResolvingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string Issuer = "https://issuer.example.com";
    private const string MetadataUrl = "https://issuer.example.com/.well-known/jwt-vc-issuer";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// SD-JWT VC draft-19 §4.1's first worked example: a root issuer has no path insertion.
    /// </summary>
    [TestMethod]
    public async Task MetadataUrlForRootIssuerHasNoPathInsertion()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json");

        _ = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(MetadataUrl, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>
    /// §4.1's second worked example, with the "any terminating '/' MUST be removed" rule exercised
    /// through the attempt: a path-bearing issuer inserts the suffix before the path component.
    /// </summary>
    [TestMethod]
    public async Task MetadataUrlForPathIssuerInsertsSuffixBeforePath()
    {
        const string PathIssuer = "https://issuer.example.com/tenant/1234";
        const string ExpectedUrl = "https://issuer.example.com/.well-known/jwt-vc-issuer/tenant/1234";

        ScriptedTransport transport = new();
        transport.Enqueue(ExpectedUrl, 200, ValidDocumentJson(PathIssuer), contentType: "application/json");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(PathIssuer, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.HasCount(1, transport.Calls);
        Assert.AreEqual(ExpectedUrl, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>§4: "The iss MUST be a case-sensitive URL using the HTTPS scheme." A plain-<c>http</c> issuer never dials.</summary>
    [TestMethod]
    public async Task HttpIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync("http://issuer.example.com", transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.InvalidIssuer, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "A plain-http issuer must never reach the transport.");
    }


    /// <summary>
    /// §4: "The iss MUST be a case-sensitive URL using the HTTPS scheme that contains scheme, host
    /// and, optionally, port number and path components as defined in [RFC3986], but no query or
    /// fragment components." A query-bearing issuer never dials.
    /// </summary>
    [TestMethod]
    public async Task QueryBearingIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync("https://issuer.example.com?tenant=1", transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.InvalidIssuer, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "A query-bearing issuer must never reach the transport.");
    }


    /// <summary>
    /// §4: "The iss MUST be a case-sensitive URL using the HTTPS scheme that contains scheme, host
    /// and, optionally, port number and path components as defined in [RFC3986], but no query or
    /// fragment components." A fragment-bearing issuer never dials.
    /// </summary>
    [TestMethod]
    public async Task FragmentBearingIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync("https://issuer.example.com#tenant", transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.InvalidIssuer, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "A fragment-bearing issuer must never reach the transport.");
    }


    /// <summary>An SSRF-blocked target (a loopback IP literal) is denied before any transport call.</summary>
    [TestMethod]
    public async Task PolicyDeniedIssuerNeverDials()
    {
        ScriptedTransport transport = new();

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync("https://127.0.0.1", transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.PolicyDenied, resolution.Outcome);
        Assert.IsEmpty(transport.Calls, "SecureDefault MUST deny a loopback target before any transport call.");
    }


    /// <summary>A non-200 status is a fetch failure.</summary>
    [TestMethod]
    public async Task NonTwoHundredStatusIsFetchFailed()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 404);

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.FetchFailed, resolution.Outcome);
    }


    /// <summary>§4.2: "using the application/json media type." A different content type is refused.</summary>
    [TestMethod]
    public async Task WrongContentTypeIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "text/html");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>
    /// §4.3: "The issuer value returned MUST be identical to the iss value of the Issuer-signed JWT.
    /// If these values are not identical, the data contained in the response MUST NOT be used."
    /// </summary>
    [TestMethod]
    public async Task IssuerMemberDifferingFromIssIsIssuerMismatch()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson("https://not-the-issuer.example.com"), contentType: "application/json");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.IssuerMismatch, resolution.Outcome);
    }


    /// <summary>A resolved attempt reports the freshness a <c>max-age</c> response header implies (RFC 9111 §5.2).</summary>
    [TestMethod]
    public async Task ResolvedAttemptReportsMaxAgeFreshness()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, ValidDocumentJson(Issuer), contentType: "application/json",
            headers: Headers(("Cache-Control", "max-age=300")));

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsTrue(resolution.Freshness.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), resolution.Freshness.FreshnessLifetime);
    }


    /// <summary>§4.2: "MUST include either jwks_uri or jwks ..., but not both." Neither present is refused.</summary>
    [TestMethod]
    public async Task NeitherJwksNorJwksUriIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, $$"""{"issuer":"{{Issuer}}"}""", contentType: "application/json");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>§4.2: "MUST include either jwks_uri or jwks ..., but not both." Both present is refused.</summary>
    [TestMethod]
    public async Task BothJwksAndJwksUriIsInvalidDocument()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200,
            $$"""{"issuer":"{{Issuer}}","jwks":{"keys":[]},"jwks_uri":"https://issuer.example.com/keys.jwks"}""",
            contentType: "application/json");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.AreEqual(JwtVcIssuerMetadataResolutionOutcome.InvalidDocument, resolution.Outcome);
    }


    /// <summary>An inline <c>jwks</c> document resolves with the key set text carried on the resolution.</summary>
    [TestMethod]
    public async Task InlineJwksDocumentResolvesWithJwksText()
    {
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200, DocumentWithInlineJwks(Issuer, SoleKeyJwk), contentType: "application/json");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsNotNull(resolution.Jwks);
        Assert.IsNull(resolution.JwksUri);
        Assert.Contains(SoleKeyKid, resolution.Jwks, StringComparison.Ordinal);

        //The extracted text must be a self-contained JSON object (braces included) that
        //JwkJsonReader.SelectKeyByKeyId/SelectSoleKey can scan directly — not merely a substring
        //match, which a brace-exclusive extraction would also satisfy.
        byte[] jwksBytes = Encoding.UTF8.GetBytes(resolution.Jwks);
        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(jwksBytes),
            "The resolved jwks text must be well-formed JSON on its own, braces included.");
        Assert.IsTrue(JwkJsonReader.SelectSoleKey(jwksBytes).IsSelected,
            "The resolved jwks text must select through the same key-selection scan SelectKeyAsync uses.");
    }


    /// <summary>A <c>jwks_uri</c> document resolves with the URI carried on the resolution, unfetched by the attempt itself.</summary>
    [TestMethod]
    public async Task JwksUriDocumentResolvesWithJwksUri()
    {
        const string JwksUri = "https://jwks.issuer.example.com/keys.jwks";
        ScriptedTransport transport = new();
        transport.Enqueue(MetadataUrl, 200,
            $$"""{"issuer":"{{Issuer}}","jwks_uri":"{{JwksUri}}"}""",
            contentType: "application/json");

        JwtVcIssuerMetadataResolution resolution = await ResolveAsync(Issuer, transport).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsResolved, $"Defect: {resolution.Defect}");
        Assert.IsNull(resolution.Jwks);
        Assert.AreEqual(JwksUri, resolution.JwksUri?.OriginalString);
        Assert.HasCount(1, transport.Calls, "The attempt itself must not dereference jwks_uri.");
    }


    /// <summary>Inline <c>jwks</c> selection: the requested <c>kid</c> selects its matching key.</summary>
    [TestMethod]
    public async Task SelectKeyAsyncSelectsByKeyIdFromInlineJwks()
    {
        JwtVcIssuerMetadataResolution resolution = new()
        {
            Outcome = JwtVcIssuerMetadataResolutionOutcome.Resolved,
            Issuer = Issuer,
            Jwks = TwoKeyJwksJson
        };

        using PublicKeyMemory? key = await JwtVcIssuerMetadataDocuments.SelectKeyAsync(
            resolution, SecondKeyKid, NeverCalledJwksResolver, NewContext(), Pool, TestSetup.Base64UrlDecoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(key, "A kid present on exactly one key in the set must select it.");
    }


    /// <summary><c>jwks_uri</c> selection: the key set is fetched through the spy <see cref="ResolveJwksUriDelegate"/> and then selected.</summary>
    [TestMethod]
    public async Task SelectKeyAsyncSelectsThroughJwksUriResolver()
    {
        JwtVcIssuerMetadataResolution resolution = new()
        {
            Outcome = JwtVcIssuerMetadataResolutionOutcome.Resolved,
            Issuer = Issuer,
            JwksUri = new Uri("https://jwks.issuer.example.com/keys.jwks")
        };

        int calls = 0;
        ValueTask<JwksUriResolution> Spy(Uri jwksUri, ExchangeContext context, CancellationToken cancellationToken)
        {
            calls++;

            return ValueTask.FromResult(new JwksUriResolution
            {
                Outcome = JwksUriResolutionOutcome.Resolved,
                Jwks = SoleKeyJwk
            });
        }

        using PublicKeyMemory? key = await JwtVcIssuerMetadataDocuments.SelectKeyAsync(
            resolution, keyId: null, Spy, NewContext(), Pool, TestSetup.Base64UrlDecoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(key, "The sole key in the jwks_uri-fetched set must select with no kid presented.");
        Assert.AreEqual(1, calls, "The jwks_uri fetch seam must be called exactly once.");
    }


    /// <summary>RFC 7517 §4.5: a <c>kid</c> present on two keys in the set is refused rather than picking either.</summary>
    [TestMethod]
    public async Task SelectKeyAsyncRefusesADuplicateKeyId()
    {
        JwtVcIssuerMetadataResolution resolution = new()
        {
            Outcome = JwtVcIssuerMetadataResolutionOutcome.Resolved,
            Issuer = Issuer,
            Jwks = DuplicateKeyIdJwksJson
        };

        PublicKeyMemory? key = await JwtVcIssuerMetadataDocuments.SelectKeyAsync(
            resolution, DuplicateKid, NeverCalledJwksResolver, NewContext(), Pool, TestSetup.Base64UrlDecoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "A kid carried by two keys in the set must refuse rather than select either.");
    }


    /// <summary>No <c>kid</c> presented and exactly one key in the set selects it.</summary>
    [TestMethod]
    public async Task SelectKeyAsyncSelectsTheSoleKeyWhenNoKeyIdIsPresented()
    {
        JwtVcIssuerMetadataResolution resolution = new()
        {
            Outcome = JwtVcIssuerMetadataResolutionOutcome.Resolved,
            Issuer = Issuer,
            Jwks = SoleKeyJwk
        };

        using PublicKeyMemory? key = await JwtVcIssuerMetadataDocuments.SelectKeyAsync(
            resolution, keyId: null, NeverCalledJwksResolver, NewContext(), Pool, TestSetup.Base64UrlDecoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(key, "A set carrying exactly one key must select it when no kid is presented.");
    }


    /// <summary>No <c>kid</c> presented and two keys in the set refuses rather than picking either.</summary>
    [TestMethod]
    public async Task SelectKeyAsyncRefusesWhenNoKeyIdIsPresentedAndTwoKeysExist()
    {
        JwtVcIssuerMetadataResolution resolution = new()
        {
            Outcome = JwtVcIssuerMetadataResolutionOutcome.Resolved,
            Issuer = Issuer,
            Jwks = TwoKeyJwksJson
        };

        PublicKeyMemory? key = await JwtVcIssuerMetadataDocuments.SelectKeyAsync(
            resolution, keyId: null, NeverCalledJwksResolver, NewContext(), Pool, TestSetup.Base64UrlDecoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "A set carrying two keys must refuse rather than select either when no kid is presented.");
    }


    private static ResolveJwksUriDelegate NeverCalledJwksResolver { get; } = (_, _, _) =>
        throw new InvalidOperationException("The jwks_uri seam must not be called for an inline jwks selection.");


    private const string SoleKeyKid = "sole-key-1";
    private const string SecondKeyKid = "second-key-1";
    private const string DuplicateKid = "duplicate-key";

    private const string SoleKeyJwk =
        /*lang=json,strict*/ """
        {"keys":[{"kty":"EC","crv":"P-256","kid":"sole-key-1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}
        """;

    private const string TwoKeyJwksJson =
        /*lang=json,strict*/ """
        {"keys":[{"kty":"EC","crv":"P-256","kid":"first-key-1","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"},{"kty":"EC","crv":"P-256","kid":"second-key-1","x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8","y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"}]}
        """;

    private const string DuplicateKeyIdJwksJson =
        /*lang=json,strict*/ """
        {"keys":[{"kty":"EC","crv":"P-256","kid":"duplicate-key","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"},{"kty":"EC","crv":"P-256","kid":"duplicate-key","x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8","y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"}]}
        """;


    /// <summary>A conformant document body naming <paramref name="issuer"/> and carrying <paramref name="jwksJson"/> inline as <c>jwks</c>.</summary>
    private static string DocumentWithInlineJwks(string issuer, string jwksJson) =>
        $$"""{"issuer":"{{issuer}}","jwks":{{jwksJson}}}""";


    /// <summary>Runs the attempt once directly against a scripted transport, with no cache in front.</summary>
    private async Task<JwtVcIssuerMetadataResolution> ResolveAsync(
        string issuer, ScriptedTransport transport, JwtVcIssuerMetadataDocumentResolverOptions? options = null) =>
        await JwtVcIssuerMetadataDocuments.ResolveAsync(
            new Uri(issuer, UriKind.Absolute), NewContext(), transport.Delegate,
            options ?? new JwtVcIssuerMetadataDocumentResolverOptions(), TestContext.CancellationToken)
            .ConfigureAwait(false);


    /// <summary>A fresh <see cref="ExchangeContext"/> with the SecureDefault outbound-fetch policy.</summary>
    private static ExchangeContext NewContext()
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return context;
    }


    /// <summary>A minimal, otherwise-conformant metadata document body naming only <paramref name="issuer"/> and an empty <c>jwks</c>.</summary>
    private static string ValidDocumentJson(string issuer) =>
        $$$"""{"issuer":"{{{issuer}}}","jwks":{"keys":[]}}""";


    /// <summary>Builds a case-insensitive header map from name/value pairs, for a scripted response.</summary>
    private static Dictionary<string, string> Headers(params (string Name, string Value)[] headers)
    {
        Dictionary<string, string> result = new(StringComparer.OrdinalIgnoreCase);
        foreach((string name, string value) in headers)
        {
            result[name] = value;
        }

        return result;
    }


    /// <summary>
    /// A single-hop transport that plays back a scripted sequence of (status, body, headers) per
    /// absolute URL — each call to a routed URL dequeues the next scripted response, sticking to
    /// the last one once the sequence is exhausted; an unrouted URL is a 404. Bodies are carried as
    /// <see cref="TaggedMemory{T}"/>, mirroring the production <see cref="OutboundResponse"/> shape.
    /// Mirrors the private <c>ScriptedTransport</c> in <c>AuthorizationServerMetadataDocumentsResolvingTests</c>,
    /// which is file-private and not itself reusable across test files.
    /// </summary>
    private sealed class ScriptedTransport
    {
        private Dictionary<string, List<ScriptedResponse>> Routes { get; } = new(StringComparer.Ordinal);
        private Dictionary<string, int> CallIndex { get; } = new(StringComparer.Ordinal);


        public List<OutboundRequest> Calls { get; } = [];


        public void Enqueue(
            string url, int status, string? body = null, string? contentType = null,
            IReadOnlyDictionary<string, string>? headers = null)
        {
            Dictionary<string, string> merged = headers is null
                ? new(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

            if(contentType is not null)
            {
                merged["Content-Type"] = contentType;
            }

            byte[]? bodyBytes = body is null ? null : Encoding.UTF8.GetBytes(body);
            EnqueueRoute(url, status, bodyBytes, merged);
        }


        private void EnqueueRoute(string url, int status, byte[]? body, IReadOnlyDictionary<string, string> headers)
        {
            if(!Routes.TryGetValue(url, out List<ScriptedResponse>? list))
            {
                list = [];
                Routes[url] = list;
            }

            list.Add(new ScriptedResponse(status, body, headers));
        }


        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            string url = request.Target.AbsoluteUri;
            ScriptedResponse response;
            if(Routes.TryGetValue(url, out List<ScriptedResponse>? list) && list.Count > 0)
            {
                int index = CallIndex.TryGetValue(url, out int current) ? current : 0;
                response = list[Math.Min(index, list.Count - 1)];
                CallIndex[url] = index + 1;
            }
            else
            {
                response = new ScriptedResponse(404, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
            }

            TaggedMemory<byte> responseBody = response.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(response.Body, BufferTags.Json);

            var headerBuilder = new HttpHeaderSet.Builder();
            foreach(KeyValuePair<string, string> header in response.Headers)
            {
                _ = headerBuilder.Add(header.Key, header.Value);
            }

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = response.Status,
                Headers = headerBuilder.Build(),
                Body = responseBody
            });
        };


        private sealed record ScriptedResponse(int Status, byte[]? Body, IReadOnlyDictionary<string, string> Headers);
    }
}
