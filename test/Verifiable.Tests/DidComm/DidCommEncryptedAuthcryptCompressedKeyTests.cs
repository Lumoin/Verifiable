using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Proves the DIDComm v2.1 authcrypt (ECDH-1PU) <em>encrypt</em>-side NIST key-agreement decompression: a
/// P-256 recipient public key handed to <see cref="DidCommEncryptedExtensions.PackAuthcryptAsync(DidCommMessage, IReadOnlyList{GeneralJweRecipientInput}, string, PrivateKeyMemory, string, string, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, DidCommMessageSerializer, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MultiRecipientAuthenticatedKeyAgreementEncryptDelegate, AuthenticatedKeyDerivationDelegate, KeyWrapDelegate, AeadEncryptDelegate, MemoryPool{byte}, CancellationToken)"/>
/// as a COMPRESSED SEC1 point (<c>0x02/0x03 || X</c>, tagged <see cref="EncodingScheme.EcCompressed"/>) — the
/// shape the DID-document converter yields for a resolved EC key — still round-trips. The NIST agreement must
/// decompress the recipient point (curve from the tag) before slicing it into the agreement, so a DID-doc-resolved
/// NIST recipient encrypts correctly, not just one passed as an already-uncompressed point.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAuthcryptCompressedKeyTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //The protected-header serializer: the headers are a Dictionary<string, object> the JWE layer hands to
    //this delegate to produce the UTF-8 JSON bytes.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string ExampleDidPrefix = "did:example";
    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string AliceP256Skid = "did:example:alice#key-p256-1";
    private const string AliceP384Skid = "did:example:alice#key-p384-1";
    private const string AliceP521Skid = "did:example:alice#key-p521-1";
    private const string BobDid = "did:example:bob";
    private const string BobP256Kid = "did:example:bob#key-p256-1";
    private const string BobP384Kid = "did:example:bob#key-p384-1";
    private const string BobP521Kid = "did:example:bob#key-p521-1";


    /// <summary>
    /// A P-256 authcrypt round trip where the RECIPIENT public key passed to the producer is a COMPRESSED SEC1
    /// point (simulating a DID-document-resolved recipient EC key). The pack-side NIST key agreement decompresses
    /// the recipient point before deriving the shared secret, and the recipient — holding the matching private
    /// key — unpacks and authenticates the sender. This pins the encrypt-side decompression: without it, the
    /// agreement would slice the compressed bytes as if uncompressed and produce a wrong KEK.
    /// </summary>
    [TestMethod]
    public async Task CompressedRecipientKeyRoundTripsP256()
    {
        await AssertCompressedRecipientRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys,
            CryptoAlgorithm.P256,
            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP256Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            AliceP256Skid,
            BobP256Kid).ConfigureAwait(false);
    }


    /// <summary>
    /// The P-384 analogue of <see cref="CompressedRecipientKeyRoundTripsP256"/>. A 49-byte compressed recipient
    /// point (0x02/0x03 || 48-byte X) exercises the per-curve DECOMPRESSION branch for P-384: the agreement must
    /// recover the 48-byte Y from the tag's curve before slicing, so a DID-doc-resolved P-384 recipient still
    /// round-trips and authenticates the sender.
    /// </summary>
    [TestMethod]
    public async Task CompressedRecipientKeyRoundTripsP384()
    {
        await AssertCompressedRecipientRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP384ExchangeKeys,
            CryptoAlgorithm.P384,
            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP384Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP384Async,
            AliceP384Skid,
            BobP384Kid).ConfigureAwait(false);
    }


    /// <summary>
    /// The P-521 analogue of <see cref="CompressedRecipientKeyRoundTripsP256"/>. A 67-byte compressed recipient
    /// point (0x02/0x03 || 66-byte X) exercises the per-curve DECOMPRESSION branch for P-521: the agreement must
    /// recover the 66-byte Y from the tag's curve before slicing, so a DID-doc-resolved P-521 recipient still
    /// round-trips and authenticates the sender.
    /// </summary>
    [TestMethod]
    public async Task CompressedRecipientKeyRoundTripsP521()
    {
        await AssertCompressedRecipientRoundTripAsync(
            MicrosoftKeyMaterialCreator.CreateP521ExchangeKeys,
            CryptoAlgorithm.P521,
            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP521Async,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP521Async,
            AliceP521Skid,
            BobP521Kid).ConfigureAwait(false);
    }


    /// <summary>
    /// Resolving the sender DID/<c>skid</c> to a DIFFERENT (freshly generated) P-256 key under keyAgreement at the
    /// correct skid MUST fail the unpack with <see cref="DidCommDecryptionError.DecryptionFailed"/>. The resolved
    /// JWK x/y are re-encoded by the converter to a COMPRESSED SEC1 point that the NIST agreement decompresses to
    /// the wrong sender point, so the ECDH-1PU agreement derives a wrong <c>Zs</c>, the KEK is wrong, and the
    /// RFC 3394 unwrap fails. This is the NIST analogue of the X25519-only WrongResolvedSenderKeyRejected: a wrong
    /// DID-doc-resolved NIST sender key — going through the compress/decompress path — fails closed.
    /// </summary>
    [TestMethod]
    public async Task WrongResolvedSenderKeyRejectedP256()
    {
        //A valid P-256 authcrypt to Bob, signed-in with the real sender static key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobP256Kid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            AliceP256Skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            MicrosoftKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptP256Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Correct DID and skid, but a DIFFERENT P-256 key under keyAgreement than the one that signed-in the 1PU
        //agreement at pack time. SenderVerificationMethod re-encodes its x/y, which the converter decodes to a
        //compressed point the agreement decompresses to the wrong static sender point.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrong = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory wrongPublic = wrong.PublicKey;
        using PrivateKeyMemory wrongPrivate = wrong.PrivateKey;

        DidResolver resolver = CreateResolver(wrongPublic, AliceP256Skid, AliceDid);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            BobP256Kid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "A wrong DID-doc-resolved NIST sender key MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a wrong resolved NIST sender key yields no plaintext.");
    }


    //A single-recipient authcrypt pack→unpack where the RECIPIENT public key passed to the producer is a
    //COMPRESSED SEC1 point (what the DID-doc converter yields for a resolved EC key), parameterized over the
    //curve. The pack-side NIST agreement decompresses the recipient point (curve from the tag) before deriving
    //the shared secret; the recipient — holding the matching private key — unpacks and authenticates the sender.
    //Per curve this hits the 33/49/67-byte compressed-point decompression branch, not just P-256.
    private async Task AssertCompressedRecipientRoundTripAsync(
        Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        CryptoAlgorithm algorithm,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate encryptAgreement,
        AuthenticatedKeyAgreementDecryptDelegate decryptAgreement,
        string skid,
        string recipientKid)
    {
        //Sender + recipient keypairs for the curve under test.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = createKeys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = createKeys(Pool);
        using PublicKeyMemory recipientUncompressed = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        //Build a COMPRESSED recipient public key (what the DID-doc converter yields for a resolved EC key),
        //tagged honestly as EcCompressed. The agreement decides to decompress from the SEC1 prefix byte and
        //takes the curve from the tag's CryptoAlgorithm; the EcCompressed tag here asserts the honest-tag
        //invariant (bytes and tag agree), it is not itself the decompression trigger.
        ReadOnlySpan<byte> uncompressed = recipientUncompressed.AsReadOnlySpan();
        byte[] compressedBytes = EllipticCurveUtilities.Compress(
            EllipticCurveUtilities.SliceXCoordinate(uncompressed),
            EllipticCurveUtilities.SliceYCoordinate(uncompressed));

        Tag compressedTag = Tag.Create(
            (typeof(CryptoAlgorithm), algorithm),
            (typeof(Purpose), Purpose.Exchange),
            (typeof(EncodingScheme), EncodingScheme.EcCompressed));

        IMemoryOwner<byte> compressedOwner = Pool.Rent(compressedBytes.Length);
        compressedBytes.CopyTo(compressedOwner.Memory.Span);
        using PublicKeyMemory compressedRecipient = new PublicKeyMemory(compressedOwner, compressedTag);

        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = createKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, compressedRecipient) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            skid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            encryptAgreement,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(senderPublic, skid, AliceDid);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            decryptAgreement,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsUnpacked, $"A compressed-recipient authcrypt message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Authcrypt, result.Mode);
        Assert.IsTrue(result.IsSenderAuthenticated, "Authcrypt MUST authenticate the sender.");
        Assert.AreEqual(skid, result.SenderKeyId, "The authenticated sender key id MUST be the skid.");
        AssertRecoveredMessage(result.Message, [BobDid]);
    }


    //A fresh DIDComm message with the shared id/type/from and the given `to` list (null for no header).
    private static DidCommMessage NewMessage(IList<string>? to)
    {
        return new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = AliceDid,
            To = to,
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "and its value" }
        };
    }


    //Asserts the recovered plaintext message round-trips the original id/type/from/to/body.
    private static void AssertRecoveredMessage(DidCommMessage? recovered, IList<string>? expectedTo)
    {
        Assert.IsNotNull(recovered);
        Assert.AreEqual(MessageId, recovered!.Id);
        Assert.AreEqual(MessageType, recovered.Type);
        Assert.AreEqual(AliceDid, recovered.From);

        if(expectedTo is null)
        {
            Assert.IsNull(recovered.To);
        }
        else
        {
            Assert.IsNotNull(recovered.To);
            Assert.HasCount(expectedTo.Count, recovered.To!);
            for(int i = 0; i < expectedTo.Count; ++i)
            {
                Assert.AreEqual(expectedTo[i], recovered.To![i]);
            }
        }

        Assert.IsNotNull(recovered.Body);
        Assert.IsTrue(recovered.Body!.TryGetValue("messagespecificattribute", out object? value), "The recovered body MUST carry the attribute.");
        Assert.AreEqual("and its value", value as string);
    }


    //Builds a resolver returning a sender DID document whose keyAgreement key is the sender's public key.
    private static DidResolver CreateResolver(PublicKeyMemory senderPublic, string skid, string did)
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(did),
            VerificationMethod = [SenderVerificationMethod(skid, did, senderPublic)],
            KeyAgreement = [new KeyAgreementMethod(skid)]
        };

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //Builds a keyAgreement verification method JWK from the sender's public key bytes: an OKP/X25519 key
    //carries the raw 32-byte x; an EC key carries the x/y halves of the uncompressed SEC1 point
    //(0x04||X||Y). For EC the converter re-encodes these coordinates to a compressed point that the NIST
    //agreement must decompress, so this exercises the real DID-doc resolution path end to end.
    private static VerificationMethod SenderVerificationMethod(string kid, string did, PublicKeyMemory senderPublic)
    {
        CryptoAlgorithm algorithm = senderPublic.Tag.Get<CryptoAlgorithm>();
        ReadOnlySpan<byte> keySpan = senderPublic.AsReadOnlySpan();

        Dictionary<string, object> jwk;
        if(algorithm.Equals(CryptoAlgorithm.X25519))
        {
            //OKP carries the raw 32-byte key as x (no SEC1 prefix, so no coordinate slicing).
            jwk = new Dictionary<string, object>
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp,
                [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.X25519,
                [WellKnownJwkMemberNames.X] = TestSetup.Base64UrlEncoder(keySpan)
            };
        }
        else
        {
            //EC splits the uncompressed SEC1 point into its x/y halves via the shared utility rather than
            //hand-rolled offsets.
            string curve = algorithm.Equals(CryptoAlgorithm.P256) ? WellKnownCurveValues.P256
                : algorithm.Equals(CryptoAlgorithm.P384) ? WellKnownCurveValues.P384
                : WellKnownCurveValues.P521;

            jwk = new Dictionary<string, object>
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Ec,
                [WellKnownJwkMemberNames.Crv] = curve,
                [WellKnownJwkMemberNames.X] = TestSetup.Base64UrlEncoder(EllipticCurveUtilities.SliceXCoordinate(keySpan)),
                [WellKnownJwkMemberNames.Y] = TestSetup.Base64UrlEncoder(EllipticCurveUtilities.SliceYCoordinate(keySpan))
            };
        }

        return new VerificationMethod
        {
            Id = kid,
            Type = "JsonWebKey2020",
            Controller = did,
            KeyFormat = new PublicKeyJwk { Header = jwk }
        };
    }
}
