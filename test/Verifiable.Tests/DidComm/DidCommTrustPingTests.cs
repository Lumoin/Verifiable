using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.DidComm.TrustPing;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm Trust Ping Protocol 2.0 (<see cref="TrustPingExtensions"/>): the
/// <c>ping</c>/<c>ping-response</c> build + wire shape, the responder flow with <c>thid</c> correlation, the
/// <c>response_requested</c> default/explicit/malformed semantics, the semver-aware discriminator dispatch,
/// and a firewalled authcrypt connectivity check that exercises the protocol's actual purpose — proving a
/// channel works end to end — over real did:peer key agreement.
/// </summary>
[TestClass]
internal sealed class DidCommTrustPingTests
{
    /// <summary>Provides the per-test cancellation token for the asynchronous encrypted e2e.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //The protected-header serializer the JWE layer hands a Dictionary<string, object> to produce UTF-8 JSON.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string Alice = "did:example:alice";


    [TestMethod]
    public void PingRoundTripsAndCarriesResponseRequested()
    {
        DidCommMessage ping = TrustPingExtensions.CreatePing("ping-1", from: Alice);

        Assert.IsTrue(ping.IsTrustPing());
        Assert.IsFalse(ping.IsTrustPingResponse());
        Assert.AreEqual(WellKnownTrustPingNames.PingType, ping.Type);

        string json = PackToJson(ping);
        Assert.Contains("trust-ping/2.0/ping", json, "The ping type URI.");
        Assert.Contains("\"response_requested\":true", json, "response_requested is emitted on the wire.");

        DidCommMessage parsed = RoundTrip(ping);
        Assert.IsTrue(parsed.IsTrustPing());
        Assert.IsTrue(parsed.IsPingResponseRequested(), "A ping built with the default requests a response.");
    }


    [TestMethod]
    public void ResponderFlowCorrelatesPingResponseToPingThread()
    {
        //Receive a ping, decide a response is wanted, and reply on the ping's thread.
        DidCommMessage ping = TrustPingExtensions.CreatePing("ping-2", from: Alice);
        DidCommMessage received = RoundTrip(ping);

        Assert.IsTrue(received.IsPingResponseRequested());

        DidCommMessage response = received.CreatePingResponse("resp-2", from: "did:example:bob");

        Assert.IsTrue(response.IsTrustPingResponse());
        Assert.AreEqual(WellKnownTrustPingNames.PingResponseType, response.Type);
        Assert.AreEqual("ping-2", response.ThreadId, "The ping-response MUST continue the ping's thread (thid echoes the ping id).");

        string json = PackToJson(response);
        Assert.Contains("trust-ping/2.0/ping-response", json, "The ping-response type URI.");
        Assert.Contains("\"thid\":\"ping-2\"", json, "The ping-response thid echoes the ping id.");
        Assert.DoesNotContain("\"body\"", json, "A ping-response carries no body (spec shape: type, id, thid).");

        DidCommMessage parsedResponse = RoundTrip(response);
        Assert.IsTrue(parsedResponse.IsTrustPingResponse());
        Assert.AreEqual("ping-2", parsedResponse.ThreadId);
    }


    [TestMethod]
    public void ResponseRequestedFalseIsHonoredAndOmitsResponseIntent()
    {
        DidCommMessage ping = TrustPingExtensions.CreatePing("ping-3", from: Alice, responseRequested: false);

        string json = PackToJson(ping);
        Assert.Contains("\"response_requested\":false", json, "An explicit false is emitted.");

        Assert.IsFalse(RoundTrip(ping).IsPingResponseRequested(), "An explicit response_requested=false declines a response.");
    }


    [TestMethod]
    public void ResponseRequestedDefaultsTrueWhenAbsentOrMalformed()
    {
        //Absent member -> default true (didcomm.org/trust-ping/2.0 §ping).
        var noMember = new DidCommMessage { Id = "p", Type = WellKnownTrustPingNames.PingType, Body = new Dictionary<string, object>() };
        Assert.IsTrue(noMember.IsPingResponseRequested(), "Absent response_requested defaults to true.");

        //No body at all -> default true.
        var noBody = new DidCommMessage { Id = "p", Type = WellKnownTrustPingNames.PingType };
        Assert.IsTrue(noBody.IsPingResponseRequested());

        //A malformed (non-boolean) value does not silently suppress the response: only an explicit false does.
        var malformed = new DidCommMessage
        {
            Id = "p",
            Type = WellKnownTrustPingNames.PingType,
            Body = new Dictionary<string, object> { [WellKnownTrustPingNames.ResponseRequested] = "false" }
        };
        Assert.IsTrue(malformed.IsPingResponseRequested(), "A non-boolean response_requested is not an explicit decline, so the default (true) stands.");
    }


    [TestMethod]
    public void DiscriminatorsAreSemverAwareAndTypeDistinct()
    {
        //A future minor of the same major still dispatches (DIDComm v2.1 §Semver Rules).
        var ping21 = new DidCommMessage { Id = "p", Type = "https://didcomm.org/trust-ping/2.1/ping" };
        Assert.IsTrue(ping21.IsTrustPing(), "A 2.1 ping dispatches to the 2.0 handler (same major version).");

        //A different major does not dispatch.
        var ping30 = new DidCommMessage { Id = "p", Type = "https://didcomm.org/trust-ping/3.0/ping" };
        Assert.IsFalse(ping30.IsTrustPing(), "A 3.0 ping is a different major version and does not dispatch.");

        //ping and ping-response are distinct message types.
        DidCommMessage ping = TrustPingExtensions.CreatePing("p", from: Alice);
        Assert.IsFalse(ping.IsTrustPingResponse());

        DidCommMessage response = ping.CreatePingResponse("r");
        Assert.IsFalse(response.IsTrustPing());

        //A non-trust-ping message is neither.
        var other = new DidCommMessage { Id = "x", Type = "https://didcomm.org/basicmessage/2.0/message" };
        Assert.IsFalse(other.IsTrustPing());
        Assert.IsFalse(other.IsTrustPingResponse());
    }


    [TestMethod]
    public void BuildValidationThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => TrustPingExtensions.CreatePing(""));

        //A ping-response can only be built from an actual ping.
        var notAPing = new DidCommMessage { Id = "x", Type = "https://didcomm.org/basicmessage/2.0/message" };
        Assert.ThrowsExactly<ArgumentException>(() => notAPing.CreatePingResponse("r"));

        //The response id is required.
        DidCommMessage ping = TrustPingExtensions.CreatePing("p", from: Alice);
        Assert.ThrowsExactly<ArgumentException>(() => ping.CreatePingResponse(""));
    }


    [TestMethod]
    public async Task EncryptedConnectivityCheckRoundTripsPingAndResponse()
    {
        //Trust Ping's actual purpose: prove the channel works end to end. Alice authcrypts a ping to Bob; Bob
        //reconstructs from the wire bytes, decrypts, interprets, and authcrypts a ping-response back; Alice
        //decrypts it and confirms the correlation. Each party only ever sees the wire bytes the other emitted.
        DidResolver resolver = CreateResolver();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory alicePublic = alice.PublicKey;
        using PrivateKeyMemory alicePrivate = alice.PrivateKey;
        string aliceDid = MintPeerDidWithKeyAgreement(alicePublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobPublic = bob.PublicKey;
        using PrivateKeyMemory bobPrivate = bob.PrivateKey;
        string bobDid = MintPeerDidWithKeyAgreement(bobPublic);

        DidDocument aliceDocument = await ResolveDocumentAsync(resolver, aliceDid).ConfigureAwait(false);
        (string aliceSkid, VerificationMethod aliceMethod) = SingleKeyAgreement(aliceDocument, aliceDid);
        using PublicKeyMemory aliceResolvedKey = aliceMethod.ToPublicKeyMemory(Pool);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        //Alice builds and authcrypts the ping for Bob.
        DidCommMessage ping = TrustPingExtensions.CreatePing("ping-e2e", from: aliceDid);
        ping.To = [bobDid];

        using DidCommEncryptedMessage encryptedPing = await PackAuthcryptAsync(ping, aliceSkid, alicePrivate, bobKid, bobResolvedKey);

        //Bob receives only the wire bytes, decrypts, and interprets.
        using DidCommEncryptedMessage wirePing = FromWire(encryptedPing);
        DidCommEncryptedUnpackResult bobUnpacked = await UnpackAuthcryptAsync(wirePing, bobKid, bobPrivate, resolver);
        Assert.IsTrue(bobUnpacked.IsUnpacked, $"Bob MUST decrypt the ping. Error: {bobUnpacked.Error}.");
        Assert.IsTrue(bobUnpacked.IsSenderAuthenticated, "Authcrypt authenticates Alice as the ping sender.");

        DidCommMessage receivedPing = bobUnpacked.Message!;
        Assert.IsTrue(receivedPing.IsTrustPing(), "Bob recognizes the decrypted message as a ping.");
        Assert.IsTrue(receivedPing.IsPingResponseRequested(), "The ping requests a response.");

        //Bob builds and authcrypts the ping-response back to Alice.
        DidCommMessage response = receivedPing.CreatePingResponse("resp-e2e", from: bobDid);
        response.To = [aliceDid];

        using DidCommEncryptedMessage encryptedResponse = await PackAuthcryptAsync(response, bobKid, bobPrivate, aliceSkid, aliceResolvedKey);

        //Alice receives only the wire bytes, decrypts, and confirms the connectivity check completed.
        using DidCommEncryptedMessage wireResponse = FromWire(encryptedResponse);
        DidCommEncryptedUnpackResult aliceUnpacked = await UnpackAuthcryptAsync(wireResponse, aliceSkid, alicePrivate, resolver);
        Assert.IsTrue(aliceUnpacked.IsUnpacked, $"Alice MUST decrypt the ping-response. Error: {aliceUnpacked.Error}.");

        DidCommMessage receivedResponse = aliceUnpacked.Message!;
        Assert.IsTrue(receivedResponse.IsTrustPingResponse(), "Alice recognizes the decrypted message as a ping-response.");
        Assert.AreEqual("ping-e2e", receivedResponse.ThreadId, "The ping-response is correlated to Alice's original ping.");
    }


    [TestMethod]
    public async Task EncryptedAnoncryptConnectivityCheckRoundTripsPingAndResponse()
    {
        //The anoncrypt variant: Alice anoncrypts a ping to Bob — anoncrypt proves the CHANNEL works, not the
        //sender, so Bob's unpack is NOT sender-authenticated. Bob reconstructs from the wire bytes, decrypts,
        //interprets, and anoncrypts a ping-response back; Alice decrypts it and confirms the correlation. The
        //ping's `from` tells Bob whom to address the response to.
        DidResolver resolver = CreateResolver();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory alicePublic = alice.PublicKey;
        using PrivateKeyMemory alicePrivate = alice.PrivateKey;
        string aliceDid = MintPeerDidWithKeyAgreement(alicePublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobPublic = bob.PublicKey;
        using PrivateKeyMemory bobPrivate = bob.PrivateKey;
        string bobDid = MintPeerDidWithKeyAgreement(bobPublic);

        DidDocument aliceDocument = await ResolveDocumentAsync(resolver, aliceDid).ConfigureAwait(false);
        (string aliceKid, VerificationMethod aliceMethod) = SingleKeyAgreement(aliceDocument, aliceDid);
        using PublicKeyMemory aliceResolvedKey = aliceMethod.ToPublicKeyMemory(Pool);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        //Alice builds and anoncrypts the ping for Bob.
        DidCommMessage ping = TrustPingExtensions.CreatePing("ping-anon", from: aliceDid);
        ping.To = [bobDid];

        using DidCommEncryptedMessage encryptedPing = await PackAnoncryptAsync(ping, bobKid, bobResolvedKey);

        //Bob receives only the wire bytes, decrypts, and interprets.
        using DidCommEncryptedMessage wirePing = FromWire(encryptedPing);
        DidCommEncryptedUnpackResult bobUnpacked = await UnpackAnoncryptAsync(wirePing, bobKid, bobPrivate, resolver);
        Assert.IsTrue(bobUnpacked.IsUnpacked, $"Bob MUST decrypt the ping. Error: {bobUnpacked.Error}.");
        Assert.IsFalse(bobUnpacked.IsSenderAuthenticated, "Anoncrypt does NOT authenticate the sender.");

        DidCommMessage receivedPing = bobUnpacked.Message!;
        Assert.IsTrue(receivedPing.IsTrustPing(), "Bob recognizes the decrypted message as a ping.");
        Assert.IsTrue(receivedPing.IsPingResponseRequested(), "The ping requests a response.");

        //Bob builds and anoncrypts the ping-response back to Alice (addressed via the ping's `from`).
        DidCommMessage response = receivedPing.CreatePingResponse("resp-anon", from: bobDid);
        response.To = [aliceDid];

        using DidCommEncryptedMessage encryptedResponse = await PackAnoncryptAsync(response, aliceKid, aliceResolvedKey);

        using DidCommEncryptedMessage wireResponse = FromWire(encryptedResponse);
        DidCommEncryptedUnpackResult aliceUnpacked = await UnpackAnoncryptAsync(wireResponse, aliceKid, alicePrivate, resolver);
        Assert.IsTrue(aliceUnpacked.IsUnpacked, $"Alice MUST decrypt the ping-response. Error: {aliceUnpacked.Error}.");

        DidCommMessage receivedResponse = aliceUnpacked.Message!;
        Assert.IsTrue(receivedResponse.IsTrustPingResponse(), "Alice recognizes the decrypted message as a ping-response.");
        Assert.AreEqual("ping-anon", receivedResponse.ThreadId, "The ping-response is correlated to Alice's original ping.");
    }


    //Authcrypts a message for a single recipient with a fresh ephemeral key, mirroring the encrypted e2e harness.
    private async ValueTask<DidCommEncryptedMessage> PackAuthcryptAsync(
        DidCommMessage message, string senderSkid, PrivateKeyMemory senderPrivate, string recipientKid, PublicKeyMemory recipientKey)
    {
        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        return await message.PackAuthcryptAsync(
            recipients,
            senderSkid,
            senderPrivate,
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


    //Unpacks an authcrypt envelope with the recipient's private key, resolving the sender key from its DID.
    private async ValueTask<DidCommEncryptedUnpackResult> UnpackAuthcryptAsync(
        DidCommEncryptedMessage envelope, string recipientKid, PrivateKeyMemory recipientPrivate, DidResolver resolver)
    {
        return await envelope.UnpackAuthcryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Anoncrypts a message for a single recipient with a fresh ephemeral key (no sender authentication).
    private async ValueTask<DidCommEncryptedMessage> PackAnoncryptAsync(DidCommMessage message, string recipientKid, PublicKeyMemory recipientKey)
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


    //Unpacks an anoncrypt envelope with the recipient's private key.
    private async ValueTask<DidCommEncryptedUnpackResult> UnpackAnoncryptAsync(
        DidCommEncryptedMessage envelope, string recipientKid, PrivateKeyMemory recipientPrivate, DidResolver resolver)
    {
        return await envelope.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Reconstructs an encrypted message from another party's wire bytes — the firewall: the receiver only ever
    //holds the serialized envelope, never the sender's in-memory object.
    private static DidCommEncryptedMessage FromWire(DidCommEncryptedMessage message) =>
        DidCommEncryptedMessage.Create(message.AsReadOnlySpan(), BufferTags.Json, Pool);


    //A did:peer resolver: the synthetic numalgo-2 resolution wired onto the did:peer method prefix.
    private static DidResolver CreateResolver() =>
        new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(Pool, DeserializeDidDocument))));


    //The did:peer:4 embedded document is deserialized by the JSON layer; Verifiable.Core never parses it.
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


    //Mints a did:peer:2 carrying a single X25519 keyAgreement key and no services.
    private static string MintPeerDidWithKeyAgreement(PublicKeyMemory keyAgreementPublicKey)
    {
        var keys = new List<PeerDidPurposedKey> { new(keyAgreementPublicKey, PeerDidPurpose.KeyAgreement) };

        return PeerDidGenerator.GenerateNumalgo2(keys, [], Pool);
    }


    //Resolves a DID through the resolver and asserts a successful document result.
    private async ValueTask<DidDocument> ResolveDocumentAsync(DidResolver resolver, string did)
    {
        DidResolutionResult resolution = await resolver
            .ResolveAsync(did, Context, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(resolution.IsSuccessful, $"'{did}' MUST resolve.");
        Assert.IsNotNull(resolution.Document);

        return resolution.Document!;
    }


    //Reads the single keyAgreement verification method from a resolved document and returns it with its kid.
    private static (string Kid, VerificationMethod Method) SingleKeyAgreement(DidDocument document, string did)
    {
        VerificationMethod[] methods = document.GetLocalKeyAgreementMethods();
        Assert.HasCount(1, methods);

        VerificationMethod method = methods[0];
        Assert.IsNotNull(method.Id);

        string kid = method.Id!.StartsWith('#') ? did + method.Id : method.Id;

        return (kid, method);
    }


    private static DidCommMessage RoundTrip(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return packed.UnpackPlaintext(DidCommMessageJson.Parser);
    }


    private static string PackToJson(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return Encoding.UTF8.GetString(packed.AsReadOnlySpan());
    }
}
