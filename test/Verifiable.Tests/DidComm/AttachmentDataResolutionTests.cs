using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Unit tests for <see cref="AttachmentDataResolutionExtensions.ResolveAsync(AttachmentData, ExchangeContext, OutboundTransportDelegate, DecodeDelegate, DecodeDelegate, HashFunctionSelector, JsonValueSerializer, MemoryPool{byte}, CancellationToken)"/>
/// — the general DIDComm attachment-payload resolver (DIDComm Messaging v2.1 §Attachments). Proves the
/// access-form precedence, the multihash integrity check, and — load-bearing — that an inline payload never
/// touches the transport and an SSRF-denied link is never contacted.
/// </summary>
[TestClass]
internal sealed class AttachmentDataResolutionTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;


    /// <summary>An inline base64url attachment resolves by value — the transport is never touched.</summary>
    [TestMethod]
    public async Task InlineBase64ResolvesWithoutFetch()
    {
        byte[] content = "Your hovercraft is full of eels"u8.ToArray();
        FakeTransport transport = new();

        var data = new AttachmentData { Base64 = TestSetup.Base64UrlEncoder(content) };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsTrue(result.IsResolved, $"Inline base64 MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(AttachmentResolutionSource.Inline, result.Source);
        Assert.IsTrue(result.Payload.Span.SequenceEqual(content), "The resolved payload MUST equal the inline content.");
        Assert.IsEmpty(transport.Calls, "An inline attachment MUST never reach the transport.");
    }


    /// <summary>An inline data.json attachment resolves via the leaf seam.</summary>
    [TestMethod]
    public async Task InlineJsonResolvesViaSeam()
    {
        FakeTransport transport = new();
        var jsonValue = new Dictionary<string, object> { ["greeting"] = "hello", ["count"] = 3L };

        var data = new AttachmentData { Json = jsonValue };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsTrue(result.IsResolved, $"Inline json MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(AttachmentResolutionSource.Inline, result.Source);

        byte[] expected = AttachmentJsonValueJson.Serializer(jsonValue, Pool).Memory.ToArray();
        Assert.IsTrue(result.Payload.Span.SequenceEqual(expected), "The json payload MUST be the serialized value.");
        Assert.IsEmpty(transport.Calls, "An inline json attachment MUST never reach the transport.");
    }


    /// <summary>A by-reference attachment (links + a valid multihash) fetches and verifies the content.</summary>
    [TestMethod]
    public async Task FetchedLinkResolvesAndVerifies()
    {
        byte[] content = "the linked attachment bytes"u8.ToArray();
        const string Url = "https://content.example/blob";

        FakeTransport transport = new(new() { [Url] = (200, content) });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = [Url]
        };

        //SecureDefault is HTTPS-only and blocks no public host: content.example resolves through the policy.
        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsTrue(result.IsResolved, $"A links+hash attachment MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(AttachmentResolutionSource.Fetched, result.Source);
        Assert.AreEqual(new Uri(Url), result.ResolvedFrom);
        Assert.IsTrue(result.Payload.Span.SequenceEqual(content), "The fetched payload MUST equal the served content.");
        Assert.HasCount(1, transport.Calls, "Exactly the one link MUST be fetched.");
        Assert.AreEqual(Url, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>A 200 fetch whose body does not match the multihash is rejected — the bytes are NOT returned.</summary>
    [TestMethod]
    public async Task FetchedHashMismatchIsRejected()
    {
        byte[] committed = "the bytes the hash commits to"u8.ToArray();
        byte[] served = "DIFFERENT bytes served by a hostile mirror"u8.ToArray();
        const string Url = "https://content.example/blob";

        FakeTransport transport = new(new() { [Url] = (200, served) });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(committed),
            Links = [Url]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved, "A hash mismatch MUST fail closed.");
        Assert.AreEqual(AttachmentResolutionError.AllLinksFailed, result.Error);
        Assert.IsTrue(result.Payload.IsEmpty, "A hash-mismatched fetched body MUST NOT be returned.");
        Assert.HasCount(1, transport.Calls, "The link was contacted but its body did not verify.");
    }


    /// <summary>
    /// The load-bearing SSRF assertion: a link to a loopback/metadata IP literal under SecureDefault is denied
    /// by policy BEFORE any network call — the transport is never contacted.
    /// </summary>
    [TestMethod]
    public async Task SsrfLinkIsDeniedAndNeverContacted()
    {
        byte[] content = "internal secret"u8.ToArray();
        const string Url = "https://169.254.169.254/latest/meta-data/";

        FakeTransport transport = new(new() { [Url] = (200, content) });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = [Url]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved, "An SSRF link MUST fail closed.");
        Assert.AreEqual(AttachmentResolutionError.FetchDenied, result.Error);
        Assert.IsEmpty(transport.Calls, "A policy-denied link MUST never reach the transport — the SSRF gate.");
    }


    /// <summary>
    /// DNS-rebinding defense for the attachment <c>links</c> fetch, mirroring the OAuth lane: a link whose
    /// host is a public NAME that resolves to a loopback address MUST be blocked at connection-time by the
    /// pinning transport — the URL gate cannot catch a rebinding host name (it does no DNS). The link is never
    /// dialed and resolves to no content. The mitigation lives in the host/app transport (the libraries carry
    /// no <c>System.Net</c>); this proves the DIDComm attachment-fetch surface exercises it, as OAuth does.
    /// </summary>
    [TestMethod]
    public async Task LinkHostRebindingToLoopbackIsBlockedAtConnectionTime()
    {
        //A public-looking host that "rebinds" to a loopback address on resolution — the DNS-rebinding attack.
        HostResolverDelegate rebindToLoopback = (host, cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);

        bool pinned = false;
        bool dialed = false;
        OutboundTransportDelegate transport = async (request, context, cancellationToken) =>
        {
            pinned = true;

            //ResolveAndPinAsync throws SsrfBlockedException when any resolved address is policy-blocked; the
            //resolver's fail-closed catch turns that into a non-fetched link, never a dial.
            _ = await SsrfHardenedTransport.ResolveAndPinAsync(
                request.Target.Host, context.OutboundFetchPolicy, rebindToLoopback, cancellationToken).ConfigureAwait(false);
            dialed = true;

            return new OutboundResponse { StatusCode = 200 };
        };

        byte[] content = "internal secret"u8.ToArray();
        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = ["https://rebinding.example/blob"]
        };

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        using AttachmentResolutionResult result = await data.ResolveAsync(
            context,
            transport,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base58Decoder,
            TestSetup.MultihashSha256Selector,
            AttachmentJsonValueJson.Serializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pinned, "The connection-time pin MUST run for an absolute, policy-permitted host name.");
        Assert.IsFalse(dialed, "A host name that rebinds to a loopback address MUST be blocked before the dial.");
        Assert.IsFalse(result.IsResolved, "A link whose host rebinds to loopback MUST NOT resolve to content.");
    }


    /// <summary>An empty data object (no access form) is MissingData.</summary>
    [TestMethod]
    public async Task MissingDataIsTyped()
    {
        FakeTransport transport = new();
        var data = new AttachmentData();

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved);
        Assert.AreEqual(AttachmentResolutionError.MissingData, result.Error);
        Assert.IsEmpty(transport.Calls);
    }


    /// <summary>Links without the REQUIRED hash is HashMissingForLinks — no fetch is attempted.</summary>
    [TestMethod]
    public async Task LinksWithoutHashIsTypedAndNotFetched()
    {
        FakeTransport transport = new(new() { ["https://content.example/blob"] = (200, "x"u8.ToArray()) });
        var data = new AttachmentData { Links = ["https://content.example/blob"] };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved);
        Assert.AreEqual(AttachmentResolutionError.HashMissingForLinks, result.Error);
        Assert.IsEmpty(transport.Calls, "Without the REQUIRED hash, no link is fetched.");
    }


    /// <summary>A data object whose only form is jws is JwsResolutionNotSupported, distinct from MissingData.</summary>
    [TestMethod]
    public async Task JwsOnlyIsTypedDistinctly()
    {
        FakeTransport transport = new();
        var data = new AttachmentData { Jws = new Dictionary<string, object> { ["signature"] = "..." } };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved);
        Assert.AreEqual(AttachmentResolutionError.JwsResolutionNotSupported, result.Error);
    }


    /// <summary>A malformed inline base64 is a HARD FAIL — it never falls back to fetch even when links exist.</summary>
    [TestMethod]
    public async Task MalformedInlineIsHardFailNotFallbackToFetch()
    {
        byte[] content = "would-be fetched content"u8.ToArray();
        const string Url = "https://content.example/blob";
        FakeTransport transport = new(new() { [Url] = (200, content) });

        var data = new AttachmentData
        {
            Base64 = "!!! not base64url !!!",
            Hash = MultibaseSha256Multihash(content),
            Links = [Url]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved, "A malformed inline MUST hard-fail.");
        Assert.AreEqual(AttachmentResolutionError.MalformedInline, result.Error);
        Assert.IsEmpty(transport.Calls, "A malformed inline MUST NOT fall back to fetching the links.");
    }


    /// <summary>An inline base64 with a present-but-mismatched hash is HashMismatch — the bytes are not returned.</summary>
    [TestMethod]
    public async Task InlineHashMismatchIsRejected()
    {
        byte[] content = "the actual inline bytes"u8.ToArray();
        byte[] other = "bytes the hash falsely commits to"u8.ToArray();

        var data = new AttachmentData
        {
            Base64 = TestSetup.Base64UrlEncoder(content),
            Hash = MultibaseSha256Multihash(other)
        };

        FakeTransport transport = new();
        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved, "An inline hash mismatch MUST fail closed.");
        Assert.AreEqual(AttachmentResolutionError.HashMismatch, result.Error);
        Assert.IsTrue(result.Payload.IsEmpty);
    }


    /// <summary>
    /// A multi-link attachment whose FIRST location is policy-denied (a metadata IP under SecureDefault) and
    /// whose SECOND is a valid 200: the resolver skips the denied location (never contacting it) and resolves
    /// the second, recording it as <see cref="AttachmentResolutionResult.ResolvedFrom"/>.
    /// </summary>
    [TestMethod]
    public async Task MultiLinkResolvesSecondWhenFirstDenied()
    {
        byte[] content = "served by the second location"u8.ToArray();
        const string DeniedUrl = "https://169.254.169.254/latest/meta-data/";
        const string ValidUrl = "https://content.example/blob";

        FakeTransport transport = new(new() { [ValidUrl] = (200, content) });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = [DeniedUrl, ValidUrl]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsTrue(result.IsResolved, $"The second link MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(AttachmentResolutionSource.Fetched, result.Source);
        Assert.AreEqual(new Uri(ValidUrl), result.ResolvedFrom, "The resolved-from MUST be the second link.");
        Assert.IsTrue(result.Payload.Span.SequenceEqual(content));
        Assert.HasCount(1, transport.Calls, "The denied first link MUST NOT be contacted; only the valid second is.");
        Assert.AreEqual(ValidUrl, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>
    /// A multi-link attachment whose FIRST location is a valid 200: the resolver resolves it and never
    /// contacts the second location (first-match wins).
    /// </summary>
    [TestMethod]
    public async Task MultiLinkResolvesFirstAndNeverContactsSecond()
    {
        byte[] content = "served by the first location"u8.ToArray();
        const string FirstUrl = "https://content.example/first";
        const string SecondUrl = "https://content.example/second";

        FakeTransport transport = new(new()
        {
            [FirstUrl] = (200, content),
            [SecondUrl] = (200, "the second body, never reached"u8.ToArray())
        });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = [FirstUrl, SecondUrl]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsTrue(result.IsResolved, $"The first link MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(new Uri(FirstUrl), result.ResolvedFrom);
        Assert.HasCount(1, transport.Calls, "The first verified link wins; the second MUST never be contacted.");
        Assert.AreEqual(FirstUrl, transport.Calls[0].Target.AbsoluteUri);
    }


    /// <summary>
    /// When EVERY link is policy-denied (all metadata IPs under SecureDefault) the result is FetchDenied — the
    /// SSRF gate — distinct from the all-reachable-but-failed case; the transport is never contacted.
    /// </summary>
    [TestMethod]
    public async Task AllLinksDeniedIsFetchDenied()
    {
        byte[] content = "internal"u8.ToArray();

        FakeTransport transport = new();

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = ["https://169.254.169.254/a", "https://127.0.0.1/b"]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved);
        Assert.AreEqual(AttachmentResolutionError.FetchDenied, result.Error, "Every link denied by policy MUST be FetchDenied.");
        Assert.IsEmpty(transport.Calls, "A policy-denied link set MUST never reach the transport.");
    }


    /// <summary>
    /// When EVERY link is reachable but returns 404 the result is AllLinksFailed — distinct from FetchDenied;
    /// each link was contacted.
    /// </summary>
    [TestMethod]
    public async Task AllLinks404IsAllLinksFailed()
    {
        byte[] content = "the committed bytes"u8.ToArray();

        //No routes -> every URL returns 404.
        FakeTransport transport = new();

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = ["https://content.example/a", "https://content.example/b"]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved);
        Assert.AreEqual(AttachmentResolutionError.AllLinksFailed, result.Error, "Reachable-but-404 links MUST be AllLinksFailed, not FetchDenied.");
        Assert.HasCount(2, transport.Calls, "Both reachable links MUST be contacted.");
    }


    /// <summary>
    /// A single reachable link that returns 500 is AllLinksFailed with the link contacted once — a non-200 is
    /// reached but yields no content.
    /// </summary>
    [TestMethod]
    public async Task ServerErrorIsAllLinksFailedContactedOnce()
    {
        byte[] content = "the committed bytes"u8.ToArray();
        const string Url = "https://content.example/blob";

        FakeTransport transport = new(new() { [Url] = (500, "error page"u8.ToArray()) });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = [Url]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved);
        Assert.AreEqual(AttachmentResolutionError.AllLinksFailed, result.Error);
        Assert.HasCount(1, transport.Calls);
    }


    /// <summary>
    /// A transport whose contact THROWS (a socket failure) is caught and fails closed as AllLinksFailed — the
    /// exception is never rethrown to the caller.
    /// </summary>
    [TestMethod]
    public async Task ThrowingTransportFailsClosedNotRethrown()
    {
        byte[] content = "the committed bytes"u8.ToArray();
        const string Url = "https://content.example/blob";

        FakeTransport transport = FakeTransport.Throwing();

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(content),
            Links = [Url]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved, "A throwing transport MUST fail closed, not propagate.");
        Assert.AreEqual(AttachmentResolutionError.AllLinksFailed, result.Error);
        Assert.HasCount(1, transport.Calls, "The link was contacted before the throw.");
    }


    /// <summary>
    /// A fetched body over <see cref="AttachmentDataResolutionExtensions.MaximumFetchedAttachmentLength"/> is
    /// rejected as AllLinksFailed and its bytes are NOT returned — the body length is bounded before it is
    /// accepted.
    /// </summary>
    [TestMethod]
    public async Task OversizedFetchedBodyIsBoundedAndNotReturned()
    {
        byte[] oversized = new byte[AttachmentDataResolutionExtensions.MaximumFetchedAttachmentLength + 1];
        const string Url = "https://content.example/blob";

        //The hash commits to the oversized body, so only the size bound (not a hash mismatch) rejects it.
        FakeTransport transport = new(new() { [Url] = (200, oversized) });

        var data = new AttachmentData
        {
            Hash = MultibaseSha256Multihash(oversized),
            Links = [Url]
        };

        using AttachmentResolutionResult result = await ResolveAsync(data, OutboundFetchPolicy.SecureDefault, transport);

        Assert.IsFalse(result.IsResolved, "An over-bound fetched body MUST fail closed.");
        Assert.AreEqual(AttachmentResolutionError.AllLinksFailed, result.Error);
        Assert.IsTrue(result.Payload.IsEmpty, "An over-bound body MUST NOT be returned.");
        Assert.HasCount(1, transport.Calls);
    }


    /// <summary>
    /// The registry-resolving overload resolves the two coders from <see cref="DefaultCoderSelector"/> and
    /// takes the hash selector / json serializer / transport as parameters: an inline base64 attachment with a
    /// matching multihash resolves through it, covering the registry-delegates-to-parameter path.
    /// </summary>
    [TestMethod]
    public async Task RegistryOverloadResolvesViaDefaultCoderSelector()
    {
        byte[] content = "resolved through the registry overload"u8.ToArray();

        var data = new AttachmentData
        {
            Base64 = TestSetup.Base64UrlEncoder(content),
            Hash = MultibaseSha256Multihash(content)
        };

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        using AttachmentResolutionResult result = await data.ResolveAsync(
            context,
            transport: null,
            TestSetup.MultihashSha256Selector,
            AttachmentJsonValueJson.Serializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsResolved, $"The registry overload MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(AttachmentResolutionSource.Inline, result.Source);
        Assert.IsTrue(result.Payload.Span.SequenceEqual(content));
    }


    //Resolves the attachment with the explicit-delegate overload: the test base64url/base58 coders, the
    //multihash sha2-256 hash-function selector, and the leaf json serializer, over a context carrying the
    //given policy.
    private async Task<AttachmentResolutionResult> ResolveAsync(AttachmentData data, OutboundFetchPolicy policy, FakeTransport transport)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(policy);

        return await data.ResolveAsync(
            context,
            transport.Delegate,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base58Decoder,
            TestSetup.MultihashSha256Selector,
            AttachmentJsonValueJson.Serializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Builds a multibase (z-prefixed base58btc) single-byte sha2-256 multihash over the content: 0x12 || 0x20
    //|| SHA-256(content), base58btc-encoded with a leading 'z'. The resolver strips the recognized multibase
    //prefix; this exercises the multibase path (not WebVhHash, which is internal and prefixless).
    private static string MultibaseSha256Multihash(ReadOnlySpan<byte> content)
    {
        Span<byte> multihash = stackalloc byte[1 + 1 + 32];
        multihash[0] = 0x12;
        multihash[1] = 0x20;
        SHA256.HashData(content, multihash[2..]);

        return "z" + TestSetup.Base58Encoder(multihash);
    }


    //A fake single-hop transport routing response bodies by absolute URL. A routed entry returns its status
    //and body; an unrouted URL returns 404 with an empty body. When constructed to throw, every contacted
    //request raises before returning (a socket/DNS failure stand-in). Records every contacted request so a
    //test can assert the transport was (or was NOT) reached.
    private sealed class FakeTransport
    {
        private readonly Dictionary<string, (int Status, byte[] Body)> routes;
        private readonly bool throwsOnContact;

        public FakeTransport() : this(new Dictionary<string, (int, byte[])>(StringComparer.Ordinal)) { }

        public FakeTransport(Dictionary<string, (int Status, byte[] Body)> routes) : this(routes, throwsOnContact: false) { }

        private FakeTransport(Dictionary<string, (int Status, byte[] Body)> routes, bool throwsOnContact)
        {
            this.routes = routes;
            this.throwsOnContact = throwsOnContact;
        }

        //A transport whose every contacted request throws — a socket failure the resolver must catch and
        //fail closed (AllLinksFailed), never rethrow.
        public static FakeTransport Throwing() => new(new Dictionary<string, (int, byte[])>(StringComparer.Ordinal), throwsOnContact: true);

        public List<OutboundRequest> Calls { get; } = [];

        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            if(throwsOnContact)
            {
                throw new System.Net.Sockets.SocketException();
            }

            if(!routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, byte[] Body) route))
            {
                route = (404, []);
            }

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = route.Status,
                Body = new TaggedMemory<byte>(route.Body, Tag.Empty)
            });
        };
    }
}
