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
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// End-to-end tests that drive the DIDComm v2.1 encrypted pack/unpack pipeline
/// (<see cref="DidCommEncryptedExtensions"/>) entirely from resolved DID documents, joining two
/// previously independent streams: did:peer minting/resolution (<see cref="PeerDidGenerator"/> /
/// <see cref="PeerDidResolver"/>) and the JWE encryption layer.
/// </summary>
/// <remarks>
/// <para>
/// The bridge from a resolved DID to an encryption key is general DID functionality, not did:peer
/// specific: a <see cref="DidResolver"/> yields a <see cref="DidDocument"/>, the
/// <c>keyAgreement</c> verification method is read with <see cref="VerificationMethodResolutionExtensions"/>
/// (<see cref="DidDocument"/>'s <c>GetLocalKeyAgreementMethods</c>), and that method is converted to a
/// correctly-tagged <see cref="PublicKeyMemory"/> with <c>VerificationMethod.ToPublicKeyMemory</c>. The
/// same flow works for any DID method whose <c>keyAgreement</c> verification method the default converter
/// can decode; did:peer:2 is the concrete method exercised here because it is the connectionless,
/// ledger-less method DIDComm is designed for.
/// </para>
/// <para>
/// The authcrypt case is the load-bearing one: the recipient's unpack resolves the SENDER's
/// <c>keyAgreement</c> key from the sender's minted-and-resolved did:peer document through the
/// production <see cref="DidResolver"/> seam, exercising the real resolution path against a real peer
/// document rather than a hand-built fixture.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DidCommPeerKeyAgreementE2ETests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //The protected-header serializer: the JWE layer hands a Dictionary<string, object> to this delegate
    //to produce the UTF-8 JSON bytes.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string BodyAttribute = "messagespecificattribute";
    private const string BodyValue = "and its value";


    /// <summary>
    /// Anoncrypt round trips when the recipient's keyAgreement key is resolved from its minted did:peer
    /// document and the recipient unpacks with its own keyAgreement private key.
    /// </summary>
    [TestMethod]
    public async Task AnoncryptRoundTripsThroughResolvedPeerKeyAgreement()
    {
        DidResolver resolver = CreateResolver();

        //Alice and Bob each mint a did:peer:2 carrying a single X25519 keyAgreement key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory aliceKeyAgreementPublic = alice.PublicKey;
        using PrivateKeyMemory aliceKeyAgreementPrivate = alice.PrivateKey;
        string aliceDid = MintPeerDidWithKeyAgreement(aliceKeyAgreementPublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobKeyAgreementPublic = bob.PublicKey;
        using PrivateKeyMemory bobKeyAgreementPrivate = bob.PrivateKey;
        string bobDid = MintPeerDidWithKeyAgreement(bobKeyAgreementPublic);

        //Alice resolves Bob's did:peer and extracts his keyAgreement key with the general DID surface.
        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        var recipients = new List<GeneralJweRecipientInput> { new(bobKid, bobResolvedKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        DidCommMessage message = NewMessage(aliceDid, [bobDid]);

        using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
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

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            bobKid,
            bobKeyAgreementPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"The anoncrypt message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Anoncrypt, result.Mode);
        Assert.IsFalse(result.IsSenderAuthenticated, "Anoncrypt MUST NOT authenticate the sender.");
        Assert.IsNull(result.SenderKeyId, "Anoncrypt carries no sender key id.");
        AssertRecovered(result.Message, aliceDid, [bobDid]);
    }


    /// <summary>
    /// Authcrypt round trips when the recipient's unpack resolves the sender's keyAgreement key from the
    /// sender's minted did:peer document through the <see cref="DidResolver"/> seam, authenticating the
    /// sender against its resolved peer key.
    /// </summary>
    [TestMethod]
    public async Task AuthcryptRoundTripsThroughResolvedPeerKeyAgreement()
    {
        DidResolver resolver = CreateResolver();

        //Alice (the sender) and Bob (the recipient) each mint a did:peer:2 with an X25519 keyAgreement key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> alice = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory aliceKeyAgreementPublic = alice.PublicKey;
        using PrivateKeyMemory aliceKeyAgreementPrivate = alice.PrivateKey;
        string aliceDid = MintPeerDidWithKeyAgreement(aliceKeyAgreementPublic);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bob = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory bobKeyAgreementPublic = bob.PublicKey;
        using PrivateKeyMemory bobKeyAgreementPrivate = bob.PrivateKey;
        string bobDid = MintPeerDidWithKeyAgreement(bobKeyAgreementPublic);

        //Alice derives her skid from her own resolved keyAgreement method id and resolves Bob's recipient key.
        DidDocument aliceDocument = await ResolveDocumentAsync(resolver, aliceDid).ConfigureAwait(false);
        (string aliceSkid, _) = SingleKeyAgreement(aliceDocument, aliceDid);

        DidDocument bobDocument = await ResolveDocumentAsync(resolver, bobDid).ConfigureAwait(false);
        (string bobKid, VerificationMethod bobMethod) = SingleKeyAgreement(bobDocument, bobDid);
        using PublicKeyMemory bobResolvedKey = bobMethod.ToPublicKeyMemory(Pool);

        var recipients = new List<GeneralJweRecipientInput> { new(bobKid, bobResolvedKey) };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        //The message `from` MUST equal the base DID of the authcrypt skid.
        DidCommMessage message = NewMessage(aliceDid, [bobDid]);

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            aliceSkid,
            aliceKeyAgreementPrivate,
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

        //Bob unpacks with his own private key; the library resolves Alice's sender key from her did:peer.
        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            bobKid,
            bobKeyAgreementPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"The authcrypt message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Authcrypt, result.Mode);
        Assert.IsTrue(result.IsSenderAuthenticated, "Authcrypt MUST authenticate the sender.");
        Assert.AreEqual(aliceSkid, result.SenderKeyId);
        AssertRecovered(result.Message, aliceDid, [bobDid]);
    }


    //A did:peer resolver: the synthetic numalgo-2/4 resolution wired onto the did:peer method prefix. The
    //numalgo-4 document deserializer and the SHA-256 hash function are required by the resolver builder; the
    //numalgo-2 documents exercised here use neither.
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


    //Reads the single keyAgreement verification method from a resolved document via the general DID surface
    //and returns it together with its fully-qualified key id.
    private static (string Kid, VerificationMethod Method) SingleKeyAgreement(DidDocument document, string did)
    {
        VerificationMethod[] methods = document.GetLocalKeyAgreementMethods();
        Assert.HasCount(1, methods);

        VerificationMethod method = methods[0];
        Assert.IsNotNull(method.Id);

        string kid = method.Id!.StartsWith('#') ? did + method.Id : method.Id;

        return (kid, method);
    }


    //A fresh DIDComm message with the shared id/type/body, the given `from`, and the given `to` list.
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


    //Asserts the recovered plaintext round-trips the original id/type/from/to/body.
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
        Assert.IsTrue(recovered.Body!.TryGetValue(BodyAttribute, out object? value), "The recovered body MUST carry the attribute.");
        Assert.AreEqual(BodyValue, value as string);
    }
}
