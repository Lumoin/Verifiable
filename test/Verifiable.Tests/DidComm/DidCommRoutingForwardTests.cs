using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// End-to-end tests for the DIDComm v2.1 Routing Protocol 2.0 forward message
/// (<see cref="RoutingForwardExtensions"/>): the sender wraps a packed message in a forward onion for a
/// chain of mediators, each mediator peels one anoncrypt layer and recovers the next hop plus the still-
/// encrypted forwarded message, and the final recipient decrypts the innermost payload.
/// </summary>
/// <remarks>
/// The plumbing mirrors <see cref="DidCommPeerKeyAgreementE2ETests"/>: did:peer:2 minting/resolution, the
/// anoncrypt/authcrypt encryption layer, and the leaf JSON serializers. The mediators and the recipient are
/// distinct did:peer:2 DIDs, each carrying a single X25519 keyAgreement key; the recipient additionally
/// carries a <c>DIDCommMessaging</c> service whose <c>routingKeys</c> are the ordered mediator DIDs.
/// </remarks>
[TestClass]
internal sealed class DidCommRoutingForwardTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    private static readonly ExchangeContext Context = new();

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string MessageId = "msg-1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string BodyAttribute = "messagespecificattribute";
    private const string BodyValue = "and its value";
    private const string ForwardId = "forward-abc123xyz456";


    /// <summary>
    /// The load-bearing multi-hop case: an authcrypt inner message is wrapped for routingKeys=[m1,m2]; m1
    /// peels its layer and recovers next=m2 + N1; m2 peels next=recipient + the inner JWE; the recipient
    /// decrypts the original plaintext. The outermost forward is encrypted for m1.
    /// </summary>
    [TestMethod]
    public async Task MultiHopForwardWrapsUnwrapsAndRecoversOriginal()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out PeerParty m2, withService: true);

        using DidCommEncryptedMessage inner = await PackAuthcryptForBobAsync(resolver, alice, bob);

        //Wrap for the two mediators, in service order [m1, m2].
        using DidCommEncryptedMessage? outer = await inner.WrapInForwardAsync(
            bob.Did,
            [m1.Did, m2.Did],
            resolver,
            Context,
            BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            ForwardId,
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(outer, "Two routing keys MUST produce a wrapped forward.");

        //The outermost forward is encrypted for m1: only m1's key unpacks it, m2's must fail closed.
        DidCommEncryptedUnpackResult wrongHop = await outer!.UnpackAnoncryptAsync(
            m2.Kid, m2.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongHop.IsUnpacked, "The outermost forward MUST be encrypted for the first routing key only.");

        //Hop 1: m1 unpacks the outer forward → next=m2 + N1.
        using ForwardUnpackResult hop1 = await outer.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(hop1.IsForwarded, $"Hop 1 MUST unpack. Error: {hop1.Error}.");
        Assert.AreEqual(m2.Did, hop1.Next, "Hop 1 next MUST be the second mediator.");
        Assert.IsNotNull(hop1.ForwardedMessage);

        //Hop 2: m2 unpacks N1 → next=recipient + the inner JWE.
        using ForwardUnpackResult hop2 = await hop1.ForwardedMessage!.UnpackForwardAsync(
            m2.Kid, m2.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(hop2.IsForwarded, $"Hop 2 MUST unpack. Error: {hop2.Error}.");
        Assert.AreEqual(bob.Did, hop2.Next, "Hop 2 next MUST be the final recipient.");
        Assert.IsNotNull(hop2.ForwardedMessage);

        //data.base64 is byte-faithful: the inner JWE recovered after the last hop equals the original bytes.
        Assert.IsTrue(
            hop2.ForwardedMessage!.AsReadOnlySpan().SequenceEqual(inner.AsReadOnlySpan()),
            "The recovered forwarded message MUST equal the original inner JWE byte-for-byte.");

        //The recipient decrypts the innermost JWE recovered after the last hop.
        DidCommEncryptedUnpackResult final = await hop2.ForwardedMessage!.UnpackAuthcryptAsync(
            bob.Kid, bob.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(final.IsUnpacked, $"The recipient MUST decrypt the inner message. Error: {final.Error}.");
        Assert.IsTrue(final.IsSenderAuthenticated, "The inner message is authcrypt — the sender is authenticated.");
        AssertRecovered(final.Message, alice.Did, [bob.Did]);
    }


    /// <summary>A single routing key produces one forward wrapper the mediator peels to recover the inner JWE.</summary>
    [TestMethod]
    public async Task SingleRoutingKeyWrapsAndUnwraps()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out _, withService: false);

        using DidCommEncryptedMessage inner = await PackAuthcryptForBobAsync(resolver, alice, bob);

        using DidCommEncryptedMessage? outer = await inner.WrapInForwardAsync(
            bob.Did, [m1.Did], resolver, Context,
            BouncyCastleKeyMaterialCreator.CreateX25519Keys, ForwardId, DidCommMessageJson.Serializer, HeaderSerializer,
            TestSetup.Base64UrlEncoder, CryptoFormatConversions.DefaultTagToEpkCrvConverter, MicrosoftEntropyFunctions.GenerateNonce,
            Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(outer);

        using ForwardUnpackResult hop = await outer!.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(hop.IsForwarded, $"The single-hop forward MUST unpack. Error: {hop.Error}.");
        Assert.AreEqual(bob.Did, hop.Next, "The single hop's next MUST be the final recipient.");

        DidCommEncryptedUnpackResult final = await hop.ForwardedMessage!.UnpackAuthcryptAsync(
            bob.Kid, bob.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(final.IsUnpacked);
        AssertRecovered(final.Message, alice.Did, [bob.Did]);
    }


    /// <summary>Empty routingKeys means the forward protocol is not needed — wrapping returns null.</summary>
    [TestMethod]
    public async Task EmptyRoutingKeysReturnsNull()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out _, out _, withService: false);

        using DidCommEncryptedMessage inner = await PackAuthcryptForBobAsync(resolver, alice, bob);

        DidCommEncryptedMessage? outer = await inner.WrapInForwardAsync(
            bob.Did, [], resolver, Context,
            BouncyCastleKeyMaterialCreator.CreateX25519Keys, ForwardId, DidCommMessageJson.Serializer, HeaderSerializer,
            TestSetup.Base64UrlEncoder, CryptoFormatConversions.DefaultTagToEpkCrvConverter, MicrosoftEntropyFunctions.GenerateNonce,
            Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(outer, "Empty routingKeys MUST yield null — the forward protocol is not needed.");
    }


    /// <summary>
    /// The next chain is built in reverse: the OUTER forward (for m1) carries next=m2, and the inner
    /// forward (for m2) carries next=recipient. This asserts the reverse-loop next ordering directly.
    /// </summary>
    [TestMethod]
    public async Task ReverseOrderNextChainIsCorrect()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out PeerParty m2, withService: false);

        using DidCommEncryptedMessage inner = await PackAuthcryptForBobAsync(resolver, alice, bob);

        using DidCommEncryptedMessage? outer = await inner.WrapInForwardAsync(
            bob.Did, [m1.Did, m2.Did], resolver, Context,
            BouncyCastleKeyMaterialCreator.CreateX25519Keys, ForwardId, DidCommMessageJson.Serializer, HeaderSerializer,
            TestSetup.Base64UrlEncoder, CryptoFormatConversions.DefaultTagToEpkCrvConverter, MicrosoftEntropyFunctions.GenerateNonce,
            Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Decrypt the outer to a forward plaintext and read its next via the message accessor: it MUST be m2.
        DidCommEncryptedUnpackResult outerPlaintext = await outer!.UnpackAnoncryptAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outerPlaintext.IsUnpacked);
        Assert.IsTrue(outerPlaintext.Message!.IsForward(), "The outer plaintext MUST be a forward message.");
        Assert.AreEqual(m2.Did, outerPlaintext.Message!.GetForwardNext(), "The outer forward's next MUST be the second routing key.");
    }


    /// <summary>IsForward and GetForwardNext read the type and body.next of a built forward message.</summary>
    [TestMethod]
    public void IsForwardAndGetForwardNextReadTheForward()
    {
        using DidCommEncryptedMessage jwe = ForwardedMessageOf("{\"protected\":\"abc\",\"ciphertext\":\"def\"}"u8);
        DidCommMessage forward = RoutingForwardExtensions.CreateForward("did:example:next1234", ForwardId, jwe, TestSetup.Base64UrlEncoder);

        Assert.IsTrue(forward.IsForward(), "A built forward MUST report IsForward.");
        Assert.AreEqual("did:example:next1234", forward.GetForwardNext());

        var notForward = new DidCommMessage { Id = "x", Type = "https://example.com/other/1.0/msg" };
        Assert.IsFalse(notForward.IsForward(), "A non-forward type MUST NOT report IsForward.");
        Assert.IsNull(notForward.GetForwardNext(), "A message without body.next MUST yield null.");
    }


    /// <summary>
    /// IsForward uses the spec-mandated MTURI dispatch comparison (DIDComm v2.1 §Message Type URI / §Semver
    /// Rules), so a future minor version of the routing protocol still dispatches as a forward while a
    /// different major version does not.
    /// </summary>
    [TestMethod]
    public void IsForwardIsSemverCompatible()
    {
        var futureMinor = new DidCommMessage { Id = "x", Type = "https://didcomm.org/routing/2.5/forward" };
        Assert.IsTrue(futureMinor.IsForward(), "A higher minor version of routing/forward MUST still dispatch as a forward.");

        var nextMajor = new DidCommMessage { Id = "x", Type = "https://didcomm.org/routing/3.0/forward" };
        Assert.IsFalse(nextMajor.IsForward(), "A different major version of routing/forward MUST NOT dispatch as a 2.x forward.");
    }


    /// <summary>CreateForward rejects a next that is not a DID or DID URL — a producer-side guard.</summary>
    [TestMethod]
    public void CreateForwardRejectsNonDidNext()
    {
        using DidCommEncryptedMessage jwe = ForwardedMessageOf("{\"protected\":\"abc\"}"u8);

        Assert.ThrowsExactly<ArgumentException>(() => RoutingForwardExtensions.CreateForward("not-a-did", ForwardId, jwe, TestSetup.Base64UrlEncoder));
    }


    /// <summary>The service-resolution helper selects the didcomm/v2 service and reads its ordered routingKeys.</summary>
    [TestMethod]
    public async Task ServiceResolutionReadsRoutingKeys()
    {
        DidResolver resolver = CreateResolver(out _, out PeerParty bob, out PeerParty m1, out PeerParty m2, withService: true);

        IReadOnlyList<string> keys = await RoutingForwardExtensions.ResolveRoutingKeysAsync(
            bob.Did, resolver, Context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, keys);
        Assert.AreEqual(m1.Did, keys[0], "The first routing key MUST be the first mediator.");
        Assert.AreEqual(m2.Did, keys[1], "The second routing key MUST be the second mediator.");
    }


    /// <summary>The convenience overload resolves the recipient's service chain then wraps for those keys.</summary>
    [TestMethod]
    public async Task ServiceResolvingWrapOverloadWrapsForResolvedKeys()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out _, withService: true);

        using DidCommEncryptedMessage inner = await PackAuthcryptForBobAsync(resolver, alice, bob);

        using DidCommEncryptedMessage? outer = await inner.WrapInForwardAsync(
            bob.Did, resolver, Context, BouncyCastleKeyMaterialCreator.CreateX25519Keys,
            ForwardId, DidCommMessageJson.Serializer, HeaderSerializer, TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter, MicrosoftEntropyFunctions.GenerateNonce,
            Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(outer, "The recipient advertises routing keys, so a forward MUST be produced.");

        //The outermost is for m1: m1 unpacks it to a forward whose next is the second mediator.
        using ForwardUnpackResult hop = await outer!.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(hop.IsForwarded, $"The resolved-chain forward MUST unpack at the first mediator. Error: {hop.Error}.");
    }


    /// <summary>Unpacking with the wrong mediator key fails closed: the envelope does not decrypt.</summary>
    [TestMethod]
    public async Task WrongMediatorKeyFailsClosed()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out PeerParty m2, withService: false);

        using DidCommEncryptedMessage inner = await PackAuthcryptForBobAsync(resolver, alice, bob);

        using DidCommEncryptedMessage? outer = await inner.WrapInForwardAsync(
            bob.Did, [m1.Did], resolver, Context,
            BouncyCastleKeyMaterialCreator.CreateX25519Keys, ForwardId, DidCommMessageJson.Serializer, HeaderSerializer,
            TestSetup.Base64UrlEncoder, CryptoFormatConversions.DefaultTagToEpkCrvConverter, MicrosoftEntropyFunctions.GenerateNonce,
            Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //m2's key cannot decrypt a forward encrypted for m1.
        using ForwardUnpackResult result = await outer!.UnpackForwardAsync(
            m2.Kid, m2.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsForwarded, "The wrong mediator key MUST fail closed.");
        Assert.AreEqual(ForwardUnpackError.EnvelopeUnpackFailed, result.Error);
    }


    /// <summary>A non-forward message that decrypts is rejected as NotAForwardMessage — no throw.</summary>
    [TestMethod]
    public async Task NonForwardMessageFailsClosed()
    {
        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out _, withService: false);

        //Anoncrypt an ordinary (non-forward) message FOR m1, then try to unpack it as a forward.
        DidDocument m1Document = await ResolveDocumentAsync(resolver, m1.Did).ConfigureAwait(false);
        (string m1Kid, VerificationMethod m1Method) = SingleKeyAgreement(m1Document, m1.Did);
        using PublicKeyMemory m1Key = m1Method.ToPublicKeyMemory(Pool);

        using DidCommEncryptedMessage notForward = await PackAnoncryptAsync(
            NewMessage(alice.Did, [m1.Did]), m1Kid, m1Key).ConfigureAwait(false);

        using ForwardUnpackResult result = await notForward.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsForwarded);
        Assert.AreEqual(ForwardUnpackError.NotAForwardMessage, result.Error);
    }


    /// <summary>A forward whose body lacks next is rejected as MissingNext — no throw.</summary>
    [TestMethod]
    public async Task ForwardMissingNextFailsClosed()
    {
        await AssertHandCraftedForwardFailsAsync(
            mutate: forward => forward.Body = new Dictionary<string, object>(),
            expected: ForwardUnpackError.MissingNext).ConfigureAwait(false);
    }


    /// <summary>A forward with zero attachments is rejected as MissingForwardedMessage — no throw.</summary>
    [TestMethod]
    public async Task ForwardWithNoAttachmentFailsClosed()
    {
        await AssertHandCraftedForwardFailsAsync(
            mutate: forward => forward.Attachments = null,
            expected: ForwardUnpackError.MissingForwardedMessage).ConfigureAwait(false);
    }


    /// <summary>A forward with multiple attachments is rejected as MissingForwardedMessage — no throw.</summary>
    [TestMethod]
    public async Task ForwardWithMultipleAttachmentsFailsClosed()
    {
        await AssertHandCraftedForwardFailsAsync(
            mutate: forward =>
            {
                var second = new Attachment { Data = new AttachmentData { Base64 = TestSetup.Base64UrlEncoder("xy"u8) } };
                forward.Attachments = [forward.Attachments![0], second];
            },
            expected: ForwardUnpackError.MissingForwardedMessage).ConfigureAwait(false);
    }


    /// <summary>A forward whose only attachment has no data.base64 is rejected as MissingForwardedMessage — no throw.</summary>
    [TestMethod]
    public async Task ForwardWithMissingDataBase64FailsClosed()
    {
        await AssertHandCraftedForwardFailsAsync(
            mutate: forward => forward.Attachments![0].Data = new AttachmentData { Hash = "deadbeef" },
            expected: ForwardUnpackError.MissingForwardedMessage).ConfigureAwait(false);
    }


    /// <summary>A forward whose data.base64 is not valid base64url is rejected as MalformedForwardedMessage — no throw.</summary>
    [TestMethod]
    public async Task ForwardWithMalformedBase64FailsClosed()
    {
        await AssertHandCraftedForwardFailsAsync(
            mutate: forward => forward.Attachments![0].Data = new AttachmentData { Base64 = "!!!notbase64!!!" },
            expected: ForwardUnpackError.MalformedForwardedMessage).ConfigureAwait(false);
    }


    /// <summary>
    /// A forward whose data.base64 length exceeds <see cref="RoutingForwardExtensions.MaximumForwardedMessageLength"/>
    /// is rejected as MalformedForwardedMessage — the bound is checked BEFORE decoding so a hostile forward cannot
    /// drive an unbounded allocation — with no throw. The bound is proven directly against
    /// <see cref="RoutingForwardExtensions.InterpretForward"/> because a multi-MiB forward cannot be round-tripped
    /// through the anoncrypt envelope (the envelope unpack rejects it first).
    /// </summary>
    [TestMethod]
    public async Task OversizedBase64IsBoundedBeforeDecoding()
    {
        var oversized = new DidCommMessage
        {
            Id = ForwardId,
            Type = WellKnownRoutingNames.ForwardType,
            Body = new Dictionary<string, object> { [WellKnownRoutingNames.Next] = "did:example:next1234" },
            Attachments =
            [
                new Attachment
                {
                    Data = new AttachmentData { Base64 = new string('A', RoutingForwardExtensions.MaximumForwardedMessageLength + 1) }
                }
            ]
        };

        using ForwardUnpackResult result = await RoutingForwardExtensions.InterpretForwardAsync(
            oversized, Context, TestSetup.Base64UrlDecoder, transport: null, hashFunctionSelector: null,
            jsonValueSerializer: null, hashBase58Decoder: null, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsForwarded, "An oversized data.base64 MUST fail closed.");
        Assert.AreEqual(ForwardUnpackError.MalformedForwardedMessage, result.Error);
    }


    /// <summary>
    /// A forward whose attachment is by reference (<c>links</c> + a valid multihash <c>hash</c>): the
    /// mediator resolves it through the SSRF-policed outbound fetch, the stub transport serves the inner JWE
    /// bytes the hash commits to, and the verified bytes are returned as the still-encrypted forwarded
    /// message — the mediator never decrypts it (DIDComm v2.1 §Routing Protocol 2.0; §Attachments by reference).
    /// </summary>
    [TestMethod]
    public async Task ForwardOverLinksResolvesAndReturnsForwardedMessage()
    {
        DidResolver resolver = CreateResolver(out _, out PeerParty bob, out PeerParty m1, out _, withService: false);

        DidDocument m1Document = await ResolveDocumentAsync(resolver, m1.Did).ConfigureAwait(false);
        (string m1Kid, VerificationMethod m1Method) = SingleKeyAgreement(m1Document, m1.Did);
        using PublicKeyMemory m1Key = m1Method.ToPublicKeyMemory(Pool);

        byte[] innerJwe = "{\"protected\":\"abc\",\"ciphertext\":\"linked-forward\"}"u8.ToArray();
        const string Url = "https://mediator.example/blobs/inner";

        //Hand-craft a forward whose single attachment references the inner JWE by links + multihash hash.
        var forward = new DidCommMessage
        {
            Id = ForwardId,
            Type = WellKnownRoutingNames.ForwardType,
            Body = new Dictionary<string, object> { [WellKnownRoutingNames.Next] = bob.Did },
            Attachments =
            [
                new Attachment
                {
                    Data = new AttachmentData { Hash = MultibaseSha256Multihash(innerJwe), Links = [Url] }
                }
            ]
        };

        using DidCommEncryptedMessage envelope = await PackAnoncryptAsync(forward, m1Kid, m1Key).ConfigureAwait(false);

        ForwardTransport transport = new(new() { [Url] = (200, innerJwe) });
        ExchangeContext fetchContext = new();
        fetchContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        using ForwardUnpackResult result = await envelope.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, fetchContext, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            transport.Delegate, TestSetup.MultihashSha256Selector, AttachmentJsonValueJson.Serializer, TestSetup.Base58Decoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsForwarded, $"A links-referenced forward MUST resolve. Error: {result.Error}.");
        Assert.AreEqual(bob.Did, result.Next);
        Assert.IsTrue(result.ForwardedMessage!.AsReadOnlySpan().SequenceEqual(innerJwe),
            "The resolved forwarded message MUST equal the linked inner JWE byte-for-byte.");
        Assert.HasCount(1, transport.Calls, "Exactly the one link MUST be fetched.");
    }


    /// <summary>
    /// A forward whose attachment carries the inner JWE inline as <c>data.json</c> (the interop-in form): the
    /// mediator resolves it through the leaf json seam, fetch-free, and returns the serialized bytes as the
    /// still-encrypted forwarded message.
    /// </summary>
    [TestMethod]
    public async Task ForwardOverDataJsonResolvesViaSeam()
    {
        DidResolver resolver = CreateResolver(out _, out PeerParty bob, out PeerParty m1, out _, withService: false);

        DidDocument m1Document = await ResolveDocumentAsync(resolver, m1.Did).ConfigureAwait(false);
        (string m1Kid, VerificationMethod m1Method) = SingleKeyAgreement(m1Document, m1.Did);
        using PublicKeyMemory m1Key = m1Method.ToPublicKeyMemory(Pool);

        var jsonValue = new Dictionary<string, object> { ["protected"] = "abc", ["ciphertext"] = "json-forward" };

        var forward = new DidCommMessage
        {
            Id = ForwardId,
            Type = WellKnownRoutingNames.ForwardType,
            Body = new Dictionary<string, object> { [WellKnownRoutingNames.Next] = bob.Did },
            Attachments = [new Attachment { Data = new AttachmentData { Json = jsonValue } }]
        };

        using DidCommEncryptedMessage envelope = await PackAnoncryptAsync(forward, m1Kid, m1Key).ConfigureAwait(false);

        ForwardTransport transport = new();

        using ForwardUnpackResult result = await envelope.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            transport.Delegate, TestSetup.MultihashSha256Selector, AttachmentJsonValueJson.Serializer, TestSetup.Base58Decoder,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsForwarded, $"A data.json forward MUST resolve via the seam. Error: {result.Error}.");
        Assert.AreEqual(bob.Did, result.Next);

        byte[] expected = AttachmentJsonValueJson.Serializer(jsonValue, Pool).Memory.ToArray();
        Assert.IsTrue(result.ForwardedMessage!.AsReadOnlySpan().SequenceEqual(expected),
            "The resolved forwarded message MUST be the serialized data.json value.");
        Assert.IsEmpty(transport.Calls, "A data.json forward MUST resolve fetch-free.");
    }


    //Builds a multibase (z-prefixed base58btc) single-byte sha2-256 multihash over the content.
    private static string MultibaseSha256Multihash(ReadOnlySpan<byte> content)
    {
        Span<byte> multihash = stackalloc byte[1 + 1 + 32];
        multihash[0] = 0x12;
        multihash[1] = 0x20;
        SHA256.HashData(content, multihash[2..]);

        return "z" + TestSetup.Base58Encoder(multihash);
    }


    //A fake single-hop transport routing inner-JWE bodies by absolute URL for the forward-over-links E2E.
    private sealed class ForwardTransport
    {
        private readonly Dictionary<string, (int Status, byte[] Body)> routes;

        public ForwardTransport() : this(new Dictionary<string, (int, byte[])>(StringComparer.Ordinal)) { }

        public ForwardTransport(Dictionary<string, (int Status, byte[] Body)> routes)
        {
            this.routes = routes;
        }

        public List<OutboundRequest> Calls { get; } = [];

        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

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


    //Builds a real forward for m1, mutates the plaintext, re-anoncrypts it for m1, and asserts the unpack
    //yields the expected fail-closed error without throwing.
    private async Task AssertHandCraftedForwardFailsAsync(Action<DidCommMessage> mutate, ForwardUnpackError expected)
    {
        DidResolver resolver = CreateResolver(out _, out PeerParty bob, out PeerParty m1, out _, withService: false);

        DidDocument m1Document = await ResolveDocumentAsync(resolver, m1.Did).ConfigureAwait(false);
        (string m1Kid, VerificationMethod m1Method) = SingleKeyAgreement(m1Document, m1.Did);
        using PublicKeyMemory m1Key = m1Method.ToPublicKeyMemory(Pool);

        using DidCommEncryptedMessage jwe = ForwardedMessageOf("{\"protected\":\"abc\",\"ciphertext\":\"def\"}"u8);
        DidCommMessage forward = RoutingForwardExtensions.CreateForward(bob.Did, ForwardId, jwe, TestSetup.Base64UrlEncoder);
        mutate(forward);

        using DidCommEncryptedMessage envelope = await PackAnoncryptAsync(forward, m1Kid, m1Key).ConfigureAwait(false);

        using ForwardUnpackResult result = await envelope.UnpackForwardAsync(
            m1.Kid, m1.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsForwarded, $"The hand-crafted forward MUST fail closed; got next={result.Next}.");
        Assert.AreEqual(expected, result.Error);
    }


    //Mints a throwaway DidCommEncryptedMessage owning a pooled copy of the given opaque bytes — a stand-in for
    //a packed JWE in unit tests that only need a forwarded message to carry, never decrypt.
    private static DidCommEncryptedMessage ForwardedMessageOf(ReadOnlySpan<byte> bytes)
    {
        return DidCommEncryptedMessage.Create(bytes, BufferTags.Json, Pool);
    }


    /// <summary>
    /// The §3 sender→receiver flow over a REAL HTTP socket: Alice packs an authcrypt message for Bob, transmits it as
    /// an HTTPS-shaped POST (chunk H) over a genuine HttpClient/Kestrel hop to Bob's inbox, and Bob decrypts exactly
    /// what crossed the wire — the message types, the encryption layer, the transport convention, and the Verified&lt;T&gt;
    /// authenticity proof all exercised end to end on a real socket (loopback, plain HTTP — verification is over the
    /// envelope, not the transport).
    /// </summary>
    [TestMethod]
    public async Task CrossWireAuthcryptDeliveryOverRealSocket()
    {
        //Bob's inbox: a real Kestrel loopback host that captures the one POST it receives and accepts it (202).
        string? receivedContentType = null;
        string? receivedBody = null;
        await using MinimalHttpHost inbox = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) =>
            {
                receivedContentType = request.ContentType;
                receivedBody = request.Body;

                return Task.FromResult(new MinimalHttpResponse { StatusCode = 202 });
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(out PeerParty alice, out PeerParty bob, out _, out _, withService: false);
        using DidCommEncryptedMessage packed = await PackAuthcryptForBobAsync(resolver, alice, bob).ConfigureAwait(false);

        //Transmit over a genuine socket to Bob's loopback inbox (the policy allows http loopback for the test host).
        using HttpClient httpClient = new();
        ExchangeContext loopbackContext = NewLoopbackContext();
        DidCommTransmitResult transmit = await packed.TransmitAsync(
            inbox.BaseAddress, loopbackContext, DidCommHttpTransport.CreateSendDelegate(BuildPostTransport(httpClient)), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(transmit.IsAccepted, $"Bob's inbox MUST accept the POST. Status: {transmit.TransportStatusCode}, error: {transmit.Error}.");
        Assert.AreEqual(202, transmit.TransportStatusCode);
        Assert.AreEqual(DidCommEncryptedMessage.MediaType, receivedContentType, "The receiver MUST see the encrypted media type as Content-Type.");
        Assert.IsNotNull(receivedBody);
        Assert.IsTrue(
            Encoding.UTF8.GetBytes(receivedBody!).AsSpan().SequenceEqual(packed.AsReadOnlySpan()),
            "The bytes that crossed the socket MUST equal the packed encrypted message byte-for-byte.");

        //Bob decrypts exactly what arrived over the wire.
        using DidCommEncryptedMessage received = DidCommEncryptedMessage.Create(Encoding.UTF8.GetBytes(receivedBody!), BufferTags.Json, Pool);
        DidCommEncryptedUnpackResult unpacked = await received.UnpackAuthcryptAsync(
            bob.Kid, bob.Private, resolver, Context, DidCommMessageJson.Parser, DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(unpacked.IsUnpacked, $"Bob MUST decrypt the message that crossed the wire. Error: {unpacked.Error}.");
        Assert.IsTrue(unpacked.IsSenderAuthenticated, "The authcrypt message authenticates Alice.");
        Assert.IsTrue(unpacked.Verified.HasValue, "The authenticated cross-wire message MUST carry the Verified<T> authenticity proof.");
        AssertRecovered(unpacked.Message, alice.Did, [bob.Did]);
    }


    //A fresh context whose policy permits http loopback so the genuine http://127.0.0.1:{port}/ inbox URL is allowed;
    //production keeps SecureDefault, which denies a loopback target before any network contact.
    private static ExchangeContext NewLoopbackContext()
    {
        var context = new ExchangeContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            AllowedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https" },
            BlockPrivateAndLoopback = false
        });

        return context;
    }


    //A single-hop HttpClient transport for the POST: it carries the body and Content-Type and does not follow
    //redirects (OutboundFetch owns the redirect loop). Test glue — the library carries no System.Net. The request
    //body is sent straight from the message's pooled memory (ReadOnlyMemoryContent, no array copy), and the response
    //body is never read into a buffer — a DIDComm POST is one-way, so only the status matters (§HTTPS).
    private static OutboundTransportDelegate BuildPostTransport(HttpClient httpClient)
    {
        return async (request, context, cancellationToken) =>
        {
            using var httpRequest = new HttpRequestMessage(new HttpMethod(request.Method), request.Target);
            if(request.Body is { } body)
            {
                var content = new ReadOnlyMemoryContent(body.Memory);
                if(request.Headers.TryGetValue("Content-Type", out string? contentType))
                {
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
                }

                httpRequest.Content = content;
            }

            using HttpResponseMessage httpResponse = await httpClient
                .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            return new OutboundResponse { StatusCode = (int)httpResponse.StatusCode };
        };
    }


    //Packs an authcrypt message from Alice for Bob, resolving Bob's recipient key from his peer document.
    private async Task<DidCommEncryptedMessage> PackAuthcryptForBobAsync(DidResolver resolver, PeerParty alice, PeerParty bob)
    {
        DidDocument aliceDocument = await ResolveDocumentAsync(resolver, alice.Did).ConfigureAwait(false);
        (string aliceSkid, _) = SingleKeyAgreement(aliceDocument, alice.Did);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bob.Did).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bob.Did);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        var recipients = new List<GeneralJweRecipientInput> { new(bobKid, bobResolvedKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        return await NewMessage(alice.Did, [bob.Did]).PackAuthcryptAsync(
            recipients,
            aliceSkid,
            alice.Private,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Anoncrypts a message for a single recipient with the registry overload (A256GCM).
    private async Task<DidCommEncryptedMessage> PackAnoncryptAsync(DidCommMessage message, string recipientKid, PublicKeyMemory recipientKey)
    {
        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        return await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Mints four parties (alice, bob, m1, m2), each a did:peer:2 with one X25519 keyAgreement key, and wires
    //one resolver over all four. When withService is true, bob's peer DID carries a DIDCommMessaging service
    //whose routingKeys are [m1, m2] and whose accept is [didcomm/v2].
    private static DidResolver CreateResolver(out PeerParty alice, out PeerParty bob, out PeerParty m1, out PeerParty m2, bool withService)
    {
        alice = PeerParty.Mint(services: null);
        m1 = PeerParty.Mint(services: null);
        m2 = PeerParty.Mint(services: null);

        List<Service>? bobServices = withService
            ? [BuildDidCommService(m1.Did, m2.Did)]
            : null;
        bob = PeerParty.Mint(bobServices);

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(Pool, DeserializeDidDocument, SHA256.HashData))));

        //Resolve each party's single keyAgreement kid once the resolver exists; the absolute kid is read
        //from the resolved document, the same way a real sender/mediator reads it.
        FillKid(resolver, alice);
        FillKid(resolver, bob);
        FillKid(resolver, m1);
        FillKid(resolver, m2);

        return resolver;
    }


    //Resolves a party's document and sets its absolute keyAgreement kid.
    private static void FillKid(DidResolver resolver, PeerParty party)
    {
        DidResolutionResult resolution = resolver.ResolveAsync(party.Did, Context).AsTask().GetAwaiter().GetResult();
        Assert.IsTrue(resolution.IsSuccessful, $"'{party.Did}' MUST resolve.");

        (string kid, _) = SingleKeyAgreement(resolution.Document!, party.Did);
        party.Kid = kid;
    }


    //A DIDCommMessaging service whose serviceEndpoint carries a non-DID uri, the didcomm/v2 accept profile,
    //and the ordered mediator DIDs as routingKeys.
    private static Service BuildDidCommService(string firstMediator, string secondMediator)
    {
        return new Service
        {
            Type = "DIDCommMessaging",
            ServiceEndpointMap = new Dictionary<string, object>
            {
                ["uri"] = "https://example.com/didcomm",
                ["accept"] = new List<string> { WellKnownRoutingNames.Profile },
                ["routingKeys"] = new List<string> { firstMediator, secondMediator }
            }
        };
    }


    private static DidDocument? DeserializeDidDocument(ReadOnlySpan<byte> jsonUtf8)
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


    private async ValueTask<DidDocument> ResolveDocumentAsync(DidResolver resolver, string did)
    {
        DidResolutionResult resolution = await resolver
            .ResolveAsync(did, Context, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(resolution.IsSuccessful, $"'{did}' MUST resolve.");
        Assert.IsNotNull(resolution.Document);

        return resolution.Document!;
    }


    private static (string Kid, VerificationMethod Method) SingleKeyAgreement(DidDocument document, string did)
    {
        VerificationMethod[] methods = document.GetLocalKeyAgreementMethods();
        Assert.HasCount(1, methods);

        VerificationMethod method = methods[0];
        Assert.IsNotNull(method.Id);

        string kid = method.Id!.StartsWith('#') ? did + method.Id : method.Id;

        return (kid, method);
    }


    private static DidCommMessage NewMessage(string from, IList<string> to)
    {
        return new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = from,
            To = to,
            Body = new Dictionary<string, object> { [BodyAttribute] = BodyValue }
        };
    }


    private static void AssertRecovered(DidCommMessage? recovered, string expectedFrom, IList<string> expectedTo)
    {
        Assert.IsNotNull(recovered);
        Assert.AreEqual(MessageId, recovered!.Id);
        Assert.AreEqual(MessageType, recovered.Type);
        Assert.AreEqual(expectedFrom, recovered.From);

        Assert.IsNotNull(recovered.To);
        Assert.HasCount(expectedTo.Count, recovered.To!);
        for(int i = 0; i < expectedTo.Count; ++i)
        {
            Assert.AreEqual(expectedTo[i], recovered.To![i]);
        }

        Assert.IsNotNull(recovered.Body);
        Assert.IsTrue(recovered.Body!.TryGetValue(BodyAttribute, out object? value));
        Assert.AreEqual(BodyValue, value as string);
    }


    //A minted did:peer:2 party: its DID, its absolute keyAgreement kid (filled after the resolver exists),
    //and its private key. The keypair is long-lived for the test's duration; the test framework process
    //teardown returns the pooled buffers.
    private sealed class PeerParty
    {
        private PeerParty(string did, PrivateKeyMemory privateKey)
        {
            Did = did;
            Private = privateKey;
        }

        public string Did { get; }

        public string Kid { get; set; } = string.Empty;

        public PrivateKeyMemory Private { get; }

        public static PeerParty Mint(IReadOnlyList<Service>? services)
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
            using PublicKeyMemory keyAgreementPublic = material.PublicKey;

            var keys = new List<PeerDidPurposedKey> { new(keyAgreementPublic, PeerDidPurpose.KeyAgreement) };
            string did = PeerDidGenerator.GenerateNumalgo2(keys, services is null ? [] : [.. services], Pool);

            return new PeerParty(did, material.PrivateKey);
        }
    }
}
