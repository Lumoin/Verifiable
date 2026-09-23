using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Outbound;
using Verifiable.Core.Resolvers;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebDidResolver.BuildResolving"/> — the <c>did:web</c> resolver that fetches the
/// <c>did.json</c> through the guarded <see cref="OutboundFetch"/> chokepoint and parses it into a
/// <see cref="DidDocument"/>. The single-hop transport is faked (the established pattern for outbound-fetch
/// consumers), so resolution, the document-id binding, the SSRF policy gate, and the error mapping are
/// exercised deterministically without a live network.
/// </summary>
[TestClass]
internal sealed class WebDidResolverResolvingTests
{
    /// <summary>The MSTest context, whose cancellation token bounds every resolution these tests run.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The did:web identifier most tests resolve.</summary>
    private const string AliceDid = "did:web:example.com:alice";

    /// <summary>The <c>did.json</c> location the did:web method maps <see cref="AliceDid"/> to.</summary>
    private const string AliceDocumentUrl = "https://example.com/alice/did.json";


    /// <summary>A did:web whose did.json is served and declares the requested DID resolves to that document.</summary>
    [TestMethod]
    public async Task ResolvesServedDocumentToDocumentResult()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson(AliceDid))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:web MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.IsNotNull(result.Document);
        Assert.AreEqual(AliceDid, result.Document.Id?.ToString());
        Assert.IsNull(result.InvalidDocumentReason, "A successful resolution states no invalid-document reason.");
    }


    /// <summary>
    /// A document served at the did:web location but declaring a different subject is rejected, and the refusal
    /// states the identifier mismatch: <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID
    /// 1.0 §3.3</see> separates "If controllerDocument.id does not match the controllerDocumentUrl" (step 6,
    /// INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID) from a document that is not conforming (step 5).
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseIdDoesNotMatchTheDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson("did:web:example.com:eve"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.IdMismatch, result.InvalidDocumentReason);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#subjects">CID 1.0 §2.1.1</see>: "A controlled identifier document
    /// MUST contain an id value in the topmost map." A served document without one does not conform, so it is refused
    /// as missing that property (CID 1.0 §3.3 step 5) rather than as a document naming a different subject (step 6).
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWithoutId()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithoutId())
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.MissingRequiredProperty, result.InvalidDocumentReason);
    }


    /// <summary>
    /// Malformed JSON at the did:web location is an invalid DID document that could not be read, which
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see> step 5 covers:
    /// "If controllerDocument is not a conforming controlled identifier document".
    /// </summary>
    [TestMethod]
    public async Task RejectsMalformedDocument()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, "{ this is not a valid DID document")
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.Malformed, result.InvalidDocumentReason);
    }


    /// <summary>
    /// A document deserializer that throws on the fetched bytes leaves no readable document, so the resolver
    /// refuses it as an invalid DID document that could not be read instead of letting the fault escape
    /// resolution: <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see>
    /// step 5, "If controllerDocument is not a conforming controlled identifier document".
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseDeserializerThrows()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, "{ this is not a valid DID document")
        });

        DidResolutionResult result = await Resolve(AliceDid, transport,
            static _ => throw new JsonException("The fetched bytes are not a DID document.")).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.Malformed, result.InvalidDocumentReason);
    }


    /// <summary>A non-200 response at the did:web location is a not-found.</summary>
    [TestMethod]
    public async Task ReportsNotFoundForNon200()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (404, null)
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A did:web whose host is an IP literal is rejected at the method layer as an invalid DID — the
    /// did:web spec forbids an IP-address host — before any policy evaluation or network call, so the
    /// transport is never contacted. This is a stronger refusal than the downstream SSRF policy, which
    /// only classifies loopback/private ranges.
    /// </summary>
    [TestMethod]
    public async Task LoopbackTargetIsRejectedAsInvalidDidAndNotContacted()
    {
        var transport = new RoutingTransport(new(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:web:127.0.0.1", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "An IP-literal did:web MUST never reach the transport.");
    }


    /// <summary>A public IP-address host is rejected as an invalid DID just as a loopback literal is.</summary>
    [TestMethod]
    public async Task PublicIpAddressHostIsRejectedAsInvalidDid()
    {
        var transport = new RoutingTransport(new(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:web:8.8.8.8", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "A public IP-literal did:web MUST never reach the transport.");
    }


    /// <summary>An IPv6-literal host (bracketed, port colon percent-encoded) is rejected as an invalid DID.</summary>
    [TestMethod]
    public async Task Ipv6LiteralHostIsRejectedAsInvalidDid()
    {
        var transport = new RoutingTransport(new(StringComparer.Ordinal));

        //A bracketed IPv6 literal with its port colon percent-encoded: %5B[::1]%5D%3A3000.
        DidResolutionResult result = await Resolve("did:web:%5B%3A%3A1%5D%3A3000", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "An IPv6-literal did:web MUST never reach the transport.");
    }


    /// <summary>
    /// A path segment that percent-encodes a path separator (<c>%2F</c>) is rejected: the segment-to-path
    /// mapping happens on the undecoded segments, so an encoded slash cannot forge an extra path component.
    /// </summary>
    [TestMethod]
    public async Task EncodedSlashInSegmentIsRejected()
    {
        var transport = new RoutingTransport(new(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:web:example.com:path%2Fto", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "An encoded path separator MUST be rejected before any fetch.");
    }


    /// <summary>
    /// A resolved did:web document whose verification method id names a DIFFERENT DID is rejected as an
    /// invalid DID document — the key-confusion mitigation requiring embedded ids to resolve under the DID —
    /// and the refusal names that cause rather than an unreadable document or a mismatched document id.
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see> step 5,
    /// "If controllerDocument is not a conforming controlled identifier document", covers a document that
    /// binds another subject's key material this way.
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseVerificationMethodIdNamesAnotherDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithForeignVerificationMethod(AliceDid, "did:web:eve.example.com"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.EmbeddedIdentifierOutsideDid, result.InvalidDocumentReason);
    }


    /// <summary>
    /// A resolved did:web document whose verification method id names a FOREIGN DID but whose controller
    /// resolves UNDER the requested DID is still rejected. Here the controller equals the requested DID, so the
    /// controller branch is satisfied and ONLY the id-absoluteness branch can reject the document — isolating it
    /// from the combined-foreign fixture (where a foreign controller alone would already fail).
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseVerificationMethodIdIsForeignButControllerIsLocal()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithForeignIdLocalController(AliceDid, "did:web:eve.example.com"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.EmbeddedIdentifierOutsideDid, result.InvalidDocumentReason);
    }


    /// <summary>
    /// A resolved did:web document that names a foreign id itself (which alone would be a step-6 mismatch) AND embeds
    /// a verification method naming a third DID, outside the document's own id (the key-confusion shape), is refused
    /// for the step-5 conformance defect, never the step-6 id mismatch: acceptance never widens by letting a
    /// non-conforming document's foreign id take priority over its own embedded-key defect.
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see> runs
    /// its step 5 ("If controllerDocument is not a conforming controlled identifier document") before
    /// its step 6 ("If controllerDocument.id does not match the controllerDocumentUrl").
    /// </summary>
    [TestMethod]
    public async Task RejectsMalformedDocumentThatAlsoNamesAForeignId()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithForeignIdAndForeignVerificationMethod(
                "did:web:eve.example.com", "did:web:mallory.example.com"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.EmbeddedIdentifierOutsideDid, result.InvalidDocumentReason,
            "Conformance checks (step 5) run before the id comparison (step 6): a non-conforming document's "
            + "foreign id must never surface as an IdMismatch.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see> step 6: "If
    /// controllerDocument.id does not match the controllerDocumentUrl, an error MUST be raised and SHOULD convey an
    /// error type of INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID." A document served at the requested DID's location
    /// that is a conforming document for ANOTHER subject, its verification method id and controller under that
    /// subject's own id, passes step 5, whose conformance is judged against the document's own id, and is refused at
    /// step 6 as an id mismatch.
    /// </summary>
    [TestMethod]
    public async Task ConsistentDocumentForAnotherSubjectReportsIdMismatch()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonForSubject("did:web:example.com:eve"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
        Assert.AreEqual(InvalidDidDocumentReason.IdMismatch, result.InvalidDocumentReason,
            "A conforming document for another subject is a step 6 id mismatch, not a step 5 embedded-identifier defect.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see>: "Let
    /// controllerDocument be the result of dereferencing controllerDocumentUrl, according to the rules of the URL scheme
    /// and using the supplied options." The did:web resolver dereferences under a bound on the fetched document: its
    /// request carries <see cref="OutboundRequest.MaxResponseBytes"/>, and a body larger than that bound, from a
    /// transport that did not stop reading, is never handed to the document deserializer but reported as not found,
    /// exactly as a transport that abandoned the read is.
    /// </summary>
    [TestMethod]
    public async Task DocumentLargerThanTheFetchBoundIsRefusedUnparsed()
    {
        long? requestedBound = null;
        System.Buffers.IMemoryOwner<byte>? oversizedBody = null;
        ValueTask<OutboundResponse> ServeBodyOverTheBoundAsync(OutboundRequest request, ExchangeContext context, CancellationToken cancellationToken)
        {
            requestedBound = request.MaxResponseBytes;
            if(requestedBound is not { } bound)
            {
                //No bound requested: serve an ordinary document, which then resolves.
                return ValueTask.FromResult(new OutboundResponse
                {
                    StatusCode = 200,
                    Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(DidDocumentJson(AliceDid)), BufferTags.Json),
                    Headers = HttpHeaderSet.Empty
                });
            }

            //One byte more than the bound the resolver asked the transport to enforce.
            int size = checked((int)bound + 1);
            oversizedBody = BaseMemoryPool.Shared.Rent(size);
            oversizedBody.Memory.Span[..size].Fill((byte)' ');

            return ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = 200,
                Body = new TaggedMemory<byte>(oversizedBody.Memory[..size], BufferTags.Json),
                Headers = HttpHeaderSet.Empty
            });
        }

        bool hasDeserialized = false;
        DidDocument? DeserializeAndRecordCall(ReadOnlySpan<byte> jsonUtf8)
        {
            hasDeserialized = true;

            return DeserializeDocument(jsonUtf8);
        }

        ExchangeContext resolutionContext = [];
        resolutionContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);
        DidMethodResolverDelegate resolver = WebDidResolver.BuildResolving(ServeBodyOverTheBoundAsync, DeserializeAndRecordCall);
        DidResolutionResult result;
        try
        {
            result = await resolver(AliceDid, DidResolutionOptions.Empty, resolutionContext, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            oversizedBody?.Dispose();
        }

        Assert.IsNotNull(requestedBound, "The did:web fetch must ask the transport to bound the response.");
        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
        Assert.IsFalse(hasDeserialized, "A body over the bound must never reach the document deserializer.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3</see>: "Let
    /// controllerDocument be the result of dereferencing controllerDocumentUrl, according to the rules of the URL scheme
    /// and using the supplied options." A dereference whose transport ended on its own budget has not found the document
    /// absent: the transport reports that cancellation inside an exception of its own, as the inner exception of its own
    /// fault or among an aggregate's inner exceptions, and the did:web resolver lets it propagate as the cancellation it
    /// is, as it does a bare one, rather than answering not found, so its caller can tell a stalled fetch from a missing
    /// document.
    /// </summary>
    /// <param name="cancellationShape">How the transport carries the cancellation: <c>wrapped</c> or <c>aggregated</c>.</param>
    [TestMethod]
    [DataRow("wrapped")]
    [DataRow("aggregated")]
    public async Task TransportCancellationCarriedInsideItsOwnExceptionPropagates(string cancellationShape)
    {
        ValueTask<OutboundResponse> StallingTransportAsync(OutboundRequest request, ExchangeContext context, CancellationToken cancellationToken)
        {
            OperationCanceledException ownBudget = new("private-policy-host/path");
            Exception carrier = cancellationShape switch
            {
                "wrapped" => new IOException("private-policy-host/path", ownBudget),
                _ => new AggregateException(new IOException("private-policy-host/path"), ownBudget)
            };

            return ValueTask.FromException<OutboundResponse>(carrier);
        }

        ExchangeContext resolutionContext = [];
        resolutionContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);
        DidMethodResolverDelegate resolver = WebDidResolver.BuildResolving(StallingTransportAsync, DeserializeDocument);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () => await resolver(
            AliceDid, DidResolutionOptions.Empty, resolutionContext, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// A resolved did:web document with NO <c>@context</c> resolves successfully: the did:web spec makes
    /// <c>@context</c> OPTIONAL — an absent context is processed via the plain-JSON rules of DID Core §6.2.2,
    /// not rejected — and the result carries the <c>application/did+json</c> (non-JSON-LD) media type.
    /// </summary>
    [TestMethod]
    public async Task DocumentWithoutContextResolves()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithoutContext(AliceDid))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A context-less did:web document MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(AliceDid, result.Document!.Id?.ToString());
        Assert.AreEqual("application/did+json", result.ResolutionMetadata.ContentType,
            "A document without @context is the plain-JSON representation and MUST report application/did+json.");
    }


    /// <summary>
    /// A resolved did:web document that DOES carry an <c>@context</c> is the JSON-LD representation and reports
    /// the <c>application/did+ld+json</c> media type (the conditional counterpart to
    /// <see cref="DocumentWithoutContextResolves"/>).
    /// </summary>
    [TestMethod]
    public async Task ResolvedDocumentCarriesJsonLdContentType()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson(AliceDid))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("application/did+ld+json", result.ResolutionMetadata.ContentType);
    }


    /// <summary>
    /// A <c>did.json</c> response carrying <c>Cache-Control: max-age</c> reports that many seconds of
    /// storable freshness on the resolution metadata — the RFC 9111 §5.2 computation
    /// <see cref="Verifiable.Core.Outbound.HttpCacheFreshness.Compute"/> performs over the fetched
    /// response, per <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AMaxAgeResponseReportsThatManySecondsOfStorableFreshness()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson(AliceDid))
        });
        transport.ResponseHeaders[AliceDocumentUrl] = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.CacheControl, "max-age=300"));

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:web MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.IsTrue(result.ResolutionMetadata.Freshness.IsStorable, "A max-age response is storable.");
        Assert.AreEqual(TimeSpan.FromSeconds(300), result.ResolutionMetadata.Freshness.FreshnessLifetime,
            "The reported lifetime is exactly the max-age directive's delta-seconds.");
    }


    /// <summary>
    /// A non-200 <c>did.json</c> fetch reports non-storable freshness on the resolution metadata — there is
    /// no document a cache could keep, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ANon200ResponseReportsNonStorableFreshness()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (404, null)
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.IsFalse(result.ResolutionMetadata.Freshness.IsStorable,
            "A resolution that never reached a document reports no storable freshness.");
    }


    /// <summary>An identifier that is not a did:web is rejected as an invalid DID without any fetch.</summary>
    [TestMethod]
    public async Task RejectsNonWebDid()
    {
        var transport = new RoutingTransport(new(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:key:z6MkExample", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "A non-did:web identifier MUST never reach the transport.");
    }


    /// <summary>
    /// Runs the <see cref="WebDidResolver.BuildResolving"/> delegate against the faked transport under the
    /// secure-default policy, parsing with <paramref name="deserializer"/> or, when it is <see langword="null"/>,
    /// with <see cref="DeserializeDocument"/>.
    /// </summary>
    private async Task<DidResolutionResult> Resolve(string did, RoutingTransport transport, WebDidDocumentDeserializer? deserializer = null)
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidMethodResolverDelegate resolver = WebDidResolver.BuildResolving(transport.Delegate, deserializer ?? DeserializeDocument);

        return await resolver(did, DidResolutionOptions.Empty, context, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>The JSON layer supplies document deserialization; Verifiable.Core never parses the did.json itself.</summary>
    private static DidDocument? DeserializeDocument(ReadOnlySpan<byte> jsonUtf8)
    {
        try
        {
            return JsonSerializerExtensions.Deserialize<DidDocument>(Encoding.UTF8.GetString(jsonUtf8), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    /// <summary>
    /// Serializes a minimal did:web document with the given subject id, guaranteeing it round-trips through
    /// the same serializer the resolver's deserializer uses. The DID v1 @context is included because a resolved
    /// did:web document is a JSON-LD representation the resolver requires to carry it.
    /// </summary>
    private static string DidDocumentJson(string did)
    {
        var document = new DidDocument
        {
            Context = Verifiable.Core.Model.Common.Context.FromIris(Verifiable.Core.Model.Common.Context.DidCore10),
            Id = new GenericDidMethod(did)
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// Serializes a did:web document whose subject is the requested DID but whose verification method id points
    /// at a DIFFERENT DID — the key-confusion shape the absoluteness check rejects.
    /// </summary>
    private static string DidDocumentJsonWithForeignVerificationMethod(string did, string foreignDid)
    {
        var document = new DidDocument
        {
            Context = Verifiable.Core.Model.Common.Context.FromIris(Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10),
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{foreignDid}#key-1",
                    Type = "Multikey",
                    Controller = foreignDid,
                    KeyFormat = new PublicKeyMultibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                }
            ]
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// Serializes a did:web document whose OWN id names a foreign DID (a step-6 id mismatch on its own) AND
    /// whose verification method id also names a foreign DID (the step-5 key-confusion shape), for
    /// <see cref="RejectsMalformedDocumentThatAlsoNamesAForeignId"/>.
    /// </summary>
    private static string DidDocumentJsonWithForeignIdAndForeignVerificationMethod(string foreignDocumentId, string foreignVerificationMethodDid)
    {
        var document = new DidDocument
        {
            Context = Verifiable.Core.Model.Common.Context.FromIris(Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10),
            Id = new GenericDidMethod(foreignDocumentId),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{foreignVerificationMethodDid}#key-1",
                    Type = "Multikey",
                    Controller = foreignVerificationMethodDid,
                    KeyFormat = new PublicKeyMultibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                }
            ]
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// Serializes a did:web document whose subject AND verification-method controller are the requested DID, but
    /// whose verification method id names a DIFFERENT (foreign) DID. The controller check passes (controller ==
    /// did), so only the id-absoluteness branch can reject this — isolating that branch from the controller one.
    /// </summary>
    private static string DidDocumentJsonWithForeignIdLocalController(string did, string foreignDid)
    {
        var document = new DidDocument
        {
            Context = Verifiable.Core.Model.Common.Context.FromIris(Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10),
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{foreignDid}#key-1",
                    Type = "Multikey",
                    Controller = did,
                    KeyFormat = new PublicKeyMultibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                }
            ]
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// Serializes a conforming did:web document for <paramref name="subjectDid"/>: its id, its verification method id
    /// and that method's controller all name the subject, so the document is consistent with itself and differs from
    /// a requested DID only by its own id, for <see cref="ConsistentDocumentForAnotherSubjectReportsIdMismatch"/>.
    /// </summary>
    private static string DidDocumentJsonForSubject(string subjectDid)
    {
        var document = new DidDocument
        {
            Context = Verifiable.Core.Model.Common.Context.FromIris(Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10),
            Id = new GenericDidMethod(subjectDid),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{subjectDid}#key-1",
                    Type = "Multikey",
                    Controller = subjectDid,
                    KeyFormat = new PublicKeyMultibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                }
            ]
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// Serializes a document that carries the DID v1 <c>@context</c> but no <c>id</c>, through the same serializer the
    /// resolver's deserializer uses, so it parses to a <see cref="DidDocument"/> whose <see cref="DidDocument.Id"/> is absent.
    /// </summary>
    private static string DidDocumentJsonWithoutId()
    {
        var document = new DidDocument
        {
            Context = Verifiable.Core.Model.Common.Context.FromIris(Verifiable.Core.Model.Common.Context.DidCore10)
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// Serializes a did:web document that omits @context entirely — the did:web plain-JSON representation, which
    /// resolves successfully (the spec makes @context optional) and reports the application/did+json media type.
    /// </summary>
    private static string DidDocumentJsonWithoutContext(string did)
    {
        var document = new DidDocument { Id = new GenericDidMethod(did) };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    /// <summary>
    /// A single-hop transport returning a canned (status, body) per absolute URL; an unknown URL is a 404.
    /// Bodies are carried as TaggedMemory&lt;byte&gt;, mirroring the production OutboundResponse shape.
    /// </summary>
    private sealed class RoutingTransport
    {
        /// <summary>The canned (status, body) response registered per absolute URL.</summary>
        private Dictionary<string, (int Status, string? Body)> Routes { get; }


        /// <summary>Creates a transport that serves <paramref name="routes"/> and 404s every other URL.</summary>
        public RoutingTransport(Dictionary<string, (int Status, string? Body)> routes)
        {
            this.Routes = routes;
        }


        /// <summary>Every request this transport has served, in call order, for a test's own assertions.</summary>
        public List<OutboundRequest> Calls { get; } = [];

        /// <summary>
        /// Response headers per URL, consulted by <see cref="Delegate"/>; a URL without an entry is served with no
        /// headers.
        /// </summary>
        public Dictionary<string, HttpHeaderSet> ResponseHeaders { get; } = new(StringComparer.Ordinal);


        /// <summary>
        /// The transport delegate the resolver under test fetches through: it records each request in
        /// <see cref="Calls"/> and answers with the route registered for the request's absolute URL.
        /// </summary>
        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

            if(!Routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, string? Body) route))
            {
                route = (404, null);
            }

            TaggedMemory<byte> body = route.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(Encoding.UTF8.GetBytes(route.Body), BufferTags.Json);

            HttpHeaderSet headers = ResponseHeaders.TryGetValue(request.Target.AbsoluteUri, out HttpHeaderSet? configuredHeaders)
                ? configuredHeaders
                : HttpHeaderSet.Empty;

            return ValueTask.FromResult(new OutboundResponse { StatusCode = route.Status, Body = body, Headers = headers });
        };
    }
}
