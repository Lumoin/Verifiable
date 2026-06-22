using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Round-trips the DIDComm v2.1 nested sign-then-encrypt combinations
/// (<c>anoncrypt(sign(plaintext))</c> and <c>authcrypt(sign(plaintext))</c>): the message is signed with
/// <see cref="DidCommSignedExtensions.PackSignedAsync(DidCommMessage, PrivateKeyMemory, string, DidCommMessageSerializer, JwtPartEncoder{JwtHeader}, JwsMessageSerializer, EncodeDelegate, MemoryPool{byte}, JoseSerializationFormat, System.Threading.CancellationToken)"/>
/// and the signed JWM bytes are then encrypted through the <see cref="DidCommSignedMessage"/> pack
/// overloads (sign-before-encrypt, DIDComm v2.1 §Message Signing). Unpack detects the signed inner JWM,
/// verifies the inner signature against the signer's resolved DID document, enforces the inner <c>to</c>
/// MUST and (for authcrypt) the signer↔sender MUST, and surfaces the verified inner signer.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedNestedRoundTripTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //The protected-header serializer: the headers are a Dictionary<string, object> the JWE layer hands to
    //this delegate to produce the UTF-8 JSON bytes (mirrors the other encrypted round-trip tests).
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string ExampleDidPrefix = "did:example";
    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string AliceSignerKid = "did:example:alice#key-1";
    private const string AliceKeyAgreementSkid = "did:example:alice#key-x25519-1";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-x25519-1";

    //Alice's Appendix A.1 Ed25519 signing key (key-1): the inner signer for both nestings.
    private const string AliceEd25519PrivateD = "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY";
    private const string AliceEd25519PublicX = "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww";


    /// <summary>
    /// An <c>anoncrypt(sign(plaintext))</c> round trip: sign with Alice's Ed25519 key, anoncrypt the signed
    /// JWM to Bob over X25519 / A256CBC-HS512, and unpack — recovering the plaintext, verifying the inner
    /// signature against Alice's resolved <c>authentication</c> key, and surfacing the verified inner signer.
    /// </summary>
    [TestMethod]
    public async Task AnoncryptSignRoundTrip()
    {
        using PrivateKeyMemory signingKey = AliceSigningKey();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        using DidCommSignedMessage signed = await PackSignedAsync(NewMessage(), signingKey).ConfigureAwait(false);

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await signed.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Only the inner signer must be resolvable for anoncrypt; the recipient key is supplied directly.
        DidResolver resolver = CreateResolver(senderKeyAgreement: null, signerPublicX: AliceEd25519PublicX);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            BobKid,
            recipientPrivate,
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertNestedSuccess(result, DidCommEncryptionMode.Anoncrypt);
    }


    /// <summary>
    /// An <c>authcrypt(sign(plaintext))</c> round trip via the delegate-taking overloads: sign with Alice's
    /// Ed25519 key, authcrypt the signed JWM to Bob over ECDH-1PU X25519 / A256CBC-HS512 with Alice's
    /// X25519 <c>keyAgreement</c> key as the <c>skid</c>, and unpack — the inner signer and the authcrypt
    /// sender share Alice's DID, so the signer↔sender MUST holds and the verified inner signer is surfaced.
    /// </summary>
    [TestMethod]
    public async Task AuthcryptSignDelegateRoundTrip()
    {
        DidCommEncryptedUnpackResult result = await AuthcryptSignRoundTripAsync(useRegistryOverload: false).ConfigureAwait(false);

        AssertNestedSuccess(result, DidCommEncryptionMode.Authcrypt);
    }


    /// <summary>The same <c>authcrypt(sign(plaintext))</c> round trip through the registry-resolving pack and unpack overloads.</summary>
    [TestMethod]
    public async Task AuthcryptSignRegistryRoundTrip()
    {
        DidCommEncryptedUnpackResult result = await AuthcryptSignRoundTripAsync(useRegistryOverload: true).ConfigureAwait(false);

        AssertNestedSuccess(result, DidCommEncryptionMode.Authcrypt);
    }


    //An authcrypt(sign) round trip over X25519 / A256CBC-HS512, exercising either the delegate-taking or the
    //registry-resolving pack and unpack overloads.
    private async Task<DidCommEncryptedUnpackResult> AuthcryptSignRoundTripAsync(bool useRegistryOverload)
    {
        using PrivateKeyMemory signingKey = AliceSigningKey();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        using DidCommSignedMessage signed = await PackSignedAsync(NewMessage(), signingKey).ConfigureAwait(false);

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };
        var ephemeralKey = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate);

        using DidCommEncryptedMessage encrypted = useRegistryOverload
            ? await signed.PackAuthcryptAsync(
                recipients,
                AliceKeyAgreementSkid,
                senderPrivate,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                ephemeralKey,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false)
            : await signed.PackAuthcryptAsync(
                recipients,
                AliceKeyAgreementSkid,
                senderPrivate,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                ephemeralKey,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Both the authcrypt sender (skid, keyAgreement) and the inner signer (authentication) resolve to Alice.
        DidResolver resolver = CreateResolver(senderKeyAgreement: senderPublic, signerPublicX: AliceEd25519PublicX);

        return useRegistryOverload
            ? await encrypted.UnpackAuthcryptAsync(
                BobKid,
                recipientPrivate,
                resolver,
                Context,
                DidCommMessageJson.Parser,
                DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false)
            : await encrypted.UnpackAuthcryptAsync(
                BobKid,
                recipientPrivate,
                resolver,
                Context,
                DidCommMessageJson.Parser,
                DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                BouncyCastleKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptX25519Async,
                ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Signs the given message with Alice's Ed25519 key-1 in General JSON form.
    private ValueTask<DidCommSignedMessage> PackSignedAsync(DidCommMessage message, PrivateKeyMemory signingKey)
    {
        return message.PackSignedAsync(
            signingKey,
            AliceSignerKid,
            DidCommMessageJson.Serializer,
            DidCommSignedMessageJson.ProtectedHeaderEncoder,
            DidCommSignedMessageJson.Serializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            JoseSerializationFormat.GeneralJson,
            TestContext.CancellationToken);
    }


    //Asserts a successful nested (signed-inner) unpack recovering the original message with the inner
    //signature verified and the inner signer surfaced.
    private static void AssertNestedSuccess(DidCommEncryptedUnpackResult result, DidCommEncryptionMode expectedMode)
    {
        Assert.IsTrue(result.IsUnpacked, $"The nested message MUST unpack. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(expectedMode, result.Mode);
        Assert.IsTrue(result.IsSignedInner, "A sign-then-encrypt message MUST be flagged as signed-inner.");
        Assert.IsTrue(result.IsSenderAuthenticated, "A verified inner signature authenticates the sender.");
        Assert.AreEqual(AliceSignerKid, result.SenderKeyId, "The authenticated sender key id MUST be the verified inner signer kid.");
        Assert.IsTrue(result.Verified.HasValue, "A verified inner signature MUST surface a Verified<T> authenticity proof for BOTH nestings — including anoncrypt(sign), where Mode is Anoncrypt yet the sender is authenticated (the proof tracks authentication, not the encryption mode).");
        Assert.AreSame(result.Message, result.Verified.GetValueOrDefault().Value, "The Verified proof MUST wrap the recovered message.");
        Assert.IsTrue(result.IsRecipientAddressedInTo, "Bob is listed in the inner 'to' and MUST be flagged as addressed.");

        Assert.IsNotNull(result.Message);
        DidCommMessage message = result.Message!;
        Assert.AreEqual(MessageId, message.Id);
        Assert.AreEqual(MessageType, message.Type);
        Assert.AreEqual(AliceDid, message.From);
        Assert.IsNotNull(message.To);
        Assert.HasCount(1, message.To!);
        Assert.AreEqual(BobDid, message.To![0]);
        Assert.IsNotNull(message.Body);
        Assert.IsTrue(message.Body!.TryGetValue("messagespecificattribute", out object? value), "The recovered body MUST carry the attribute.");
        Assert.AreEqual("and its value", value as string);
    }


    //A fresh DIDComm message from Alice to Bob carrying a `to` header (required for the inner signed JWM).
    private static DidCommMessage NewMessage()
    {
        return new DidCommMessage
        {
            Id = MessageId,
            Type = MessageType,
            From = AliceDid,
            To = [BobDid],
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "and its value" }
        };
    }


    //Alice's Ed25519 signing key from its Appendix A.1 seed; ownership transfers to the PrivateKeyMemory.
    private static PrivateKeyMemory AliceSigningKey()
    {
        IMemoryOwner<byte> seed = TestSetup.Base64UrlDecoder(AliceEd25519PrivateD, Pool);

        return new PrivateKeyMemory(seed, CryptoTags.Ed25519PrivateKey);
    }


    //Builds a resolver returning Alice's DID document. The Ed25519 signer key is authorized for
    //authentication (verifies the inner signature); when senderKeyAgreement is non-null its raw X25519
    //public key is authorized for keyAgreement under the skid (resolves the authcrypt sender).
    private static DidResolver CreateResolver(PublicKeyMemory? senderKeyAgreement, string signerPublicX)
    {
        var verificationMethods = new List<VerificationMethod>
        {
            Ed25519VerificationMethod(AliceSignerKid, signerPublicX)
        };

        var document = new DidDocument
        {
            Id = new GenericDidMethod(AliceDid),
            Authentication = [new AuthenticationMethod(AliceSignerKid)]
        };

        if(senderKeyAgreement is not null)
        {
            verificationMethods.Add(X25519VerificationMethod(AliceKeyAgreementSkid, senderKeyAgreement));
            document.KeyAgreement = [new KeyAgreementMethod(AliceKeyAgreementSkid)];
        }

        document.VerificationMethod = [.. verificationMethods];

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //An Ed25519 authentication verification method (OKP) from the signer's base64url public x.
    private static VerificationMethod Ed25519VerificationMethod(string id, string publicKeyX)
    {
        return new VerificationMethod
        {
            Id = id,
            Type = "JsonWebKey2020",
            Controller = AliceDid,
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp,
                    [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.Ed25519,
                    [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.EdDsa,
                    [WellKnownJwkMemberNames.X] = publicKeyX
                }
            }
        };
    }


    //An X25519 keyAgreement verification method (OKP) carrying the raw 32-byte public key as x.
    private static VerificationMethod X25519VerificationMethod(string id, PublicKeyMemory publicKey)
    {
        return new VerificationMethod
        {
            Id = id,
            Type = "JsonWebKey2020",
            Controller = AliceDid,
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp,
                    [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.X25519,
                    [WellKnownJwkMemberNames.X] = TestSetup.Base64UrlEncoder(publicKey.AsReadOnlySpan())
                }
            }
        };
    }
}
