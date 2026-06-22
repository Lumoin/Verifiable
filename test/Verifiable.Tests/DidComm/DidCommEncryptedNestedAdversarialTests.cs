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
using Verifiable.Cryptography.Context;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Adversarial, fail-closed tests for the DIDComm v2.1 nested (signed-then-encrypted) unpack path: the two
/// nesting MUSTs that the outer decrypt and the inner signature verification do not themselves cover — the
/// inner signed JWM MUST carry a <c>to</c> header (DIDComm v2.1 §DIDComm Signed Messages — the
/// surreptitious-forwarding defense), and for <c>authcrypt(sign)</c> the inner signer MUST share the
/// authcrypt sender's DID (DIDComm v2.1 §Message Types). The envelopes are produced through the real pack
/// API; each unpack still decrypts successfully and verifies the inner signature, so it is the nesting
/// MUST itself — not a crypto failure — that rejects the message.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedNestedAdversarialTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

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
    private const string MalloryDid = "did:example:mallory";
    private const string MallorySkid = "did:example:mallory#key-x25519-1";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-x25519-1";

    private const string AliceEd25519PrivateD = "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY";
    private const string AliceEd25519PublicX = "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww";


    /// <summary>
    /// An <c>authcrypt(sign)</c> message whose inner signer (Alice) differs from the authcrypt-layer sender
    /// (Mallory's <c>skid</c>) MUST be rejected with <see cref="DidCommDecryptionError.SignerSenderMismatch"/>
    /// — even though the outer authcrypt decrypts and the inner Alice signature verifies (DIDComm v2.1
    /// §Message Types: "MUST emit an error if the signer of the plaintext is different from the sender
    /// identified by the authcrypt layer").
    /// </summary>
    [TestMethod]
    public async Task AuthcryptSignSignerSenderMismatchRejected()
    {
        using PrivateKeyMemory signingKey = AliceSigningKey();

        //Mallory is the authcrypt sender (skid); Alice is the inner signer — distinct DIDs.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mallory = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory malloryPublic = mallory.PublicKey;
        using PrivateKeyMemory malloryPrivate = mallory.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        using DidCommSignedMessage signed = await PackSignedAsync(NewMessage([BobDid]), signingKey).ConfigureAwait(false);

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await signed.PackAuthcryptAsync(
            recipients,
            MallorySkid,
            malloryPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
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

        //alice -> authentication(key-1) for the inner verify; mallory -> keyAgreement(skid) for the authcrypt sender.
        DidResolver resolver = CreateMultiResolver(malloryPublic);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
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

        Assert.IsFalse(result.IsUnpacked, "authcrypt(sign) with inner signer != authcrypt sender MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.SignerSenderMismatch, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a signer/sender mismatch yields no plaintext.");
    }


    /// <summary>
    /// An <c>anoncrypt(sign)</c> message whose inner signed JWM lacks a <c>to</c> header MUST be rejected
    /// with <see cref="DidCommDecryptionError.NestedSignedMessageMissingTo"/> — even though the outer
    /// decrypt succeeds and the inner signature verifies (DIDComm v2.1 §DIDComm Signed Messages: "the inner
    /// (signed) JWM being signed MUST contain a to header").
    /// </summary>
    [TestMethod]
    public async Task AnoncryptSignInnerMissingToRejected()
    {
        using PrivateKeyMemory signingKey = AliceSigningKey();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        //The signed inner JWM carries no `to` header (legal for a bare signed message, illegal once nested).
        using DidCommSignedMessage signed = await PackSignedAsync(NewMessage(to: null), signingKey).ConfigureAwait(false);

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

        DidResolver resolver = CreateAliceResolver();

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

        Assert.IsFalse(result.IsUnpacked, "A nested message whose inner signed JWM lacks a 'to' header MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.NestedSignedMessageMissingTo, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a missing inner 'to' yields no plaintext.");
    }


    /// <summary>
    /// The same inner-<c>to</c>-missing MUST (L220) pinned independently on the authcrypt(sign) path: Alice
    /// is both the inner signer and the authcrypt sender (so the signer↔sender check passes), and it is the
    /// absent inner <c>to</c> that rejects the message with
    /// <see cref="DidCommDecryptionError.NestedSignedMessageMissingTo"/>.
    /// </summary>
    [TestMethod]
    public async Task AuthcryptSignInnerMissingToRejected()
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

        using DidCommSignedMessage signed = await PackSignedAsync(NewMessage(to: null), signingKey).ConfigureAwait(false);

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await signed.PackAuthcryptAsync(
            recipients,
            AliceKeyAgreementSkid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
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

        DidResolver resolver = CreateAliceWithKeyAgreementResolver(senderPublic);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
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

        Assert.IsFalse(result.IsUnpacked, "authcrypt(sign) whose inner signed JWM lacks a 'to' header MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.NestedSignedMessageMissingTo, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a missing inner 'to' yields no plaintext.");
    }


    /// <summary>
    /// A nested message whose inner signed JWM carries a wire-type-invalid plaintext (here a
    /// <c>created_time</c> encoded as a JSON string, which the leaf parser surfaces as a
    /// <see cref="System.Text.Json.JsonException"/>) MUST fail CLOSED — the unpack returns a result rather
    /// than letting the parser exception escape (the fail-closed contract). The inner content is JWS-shaped
    /// so it routes down the nested path, and the malformed plaintext is rejected before any signature
    /// verification, so no valid inner signature is needed to reach the defect.
    /// </summary>
    [TestMethod]
    public async Task NestedInnerMalformedPlaintextFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        //A hand-built JWS-shaped inner whose payload decodes to JSON with `created_time` as a STRING (a
        //wire-type violation the leaf parser raises as JsonException). The signature value is irrelevant —
        //the plaintext parse fails before verification.
        string protectedHeader = TestSetup.Base64UrlEncoder(
            Encoding.UTF8.GetBytes("""{"typ":"application/didcomm-signed+json","alg":"EdDSA"}"""));
        string malformedPayload = TestSetup.Base64UrlEncoder(
            Encoding.UTF8.GetBytes("""{"id":"1234567890","type":"http://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice","to":["did:example:bob"],"created_time":"oops"}"""));
        string innerJws = $$$"""
            {"payload":"{{{malformedPayload}}}","signatures":[{"protected":"{{{protectedHeader}}}","signature":"AAAA","header":{"kid":"{{{AliceSignerKid}}}"}}]}
            """;

        using DidCommSignedMessage signed = DidCommSignedMessage.Create(Encoding.UTF8.GetBytes(innerJws), BufferTags.Json, Pool);

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

        DidResolver resolver = CreateAliceResolver();

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

        Assert.IsFalse(result.IsUnpacked, "A nested inner JWM with a wire-type-invalid plaintext MUST fail closed, not throw.");
        Assert.AreEqual(DidCommDecryptionError.NestedSignatureInvalid, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a malformed inner plaintext yields no plaintext.");
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


    //A fresh DIDComm message from Alice with the given `to` list (null for no `to` header).
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


    //Alice's Ed25519 signing key from its Appendix A.1 seed; ownership transfers to the PrivateKeyMemory.
    private static PrivateKeyMemory AliceSigningKey()
    {
        IMemoryOwner<byte> seed = TestSetup.Base64UrlDecoder(AliceEd25519PrivateD, Pool);

        return new PrivateKeyMemory(seed, CryptoTags.Ed25519PrivateKey);
    }


    //A resolver serving only Alice's document (authentication key-1 Ed25519) for the inner signature verify.
    private static DidResolver CreateAliceResolver()
    {
        DidDocument alice = AliceDocument();

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(alice, new DidDocumentMetadata())))));
    }


    //A resolver serving Alice's document with BOTH her Ed25519 authentication key (the inner signer) and
    //her X25519 keyAgreement key under the skid (the authcrypt sender), so authcrypt(sign) by Alice resolves
    //on both relationships.
    private static DidResolver CreateAliceWithKeyAgreementResolver(PublicKeyMemory senderPublic)
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(AliceDid),
            VerificationMethod =
            [
                Ed25519VerificationMethod(AliceSignerKid, AliceDid, AliceEd25519PublicX),
                X25519VerificationMethod(AliceKeyAgreementSkid, AliceDid, senderPublic)
            ],
            Authentication = [new AuthenticationMethod(AliceSignerKid)],
            KeyAgreement = [new KeyAgreementMethod(AliceKeyAgreementSkid)]
        };

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //A resolver dispatching by DID: Alice (authentication key-1, the inner signer) and Mallory
    //(keyAgreement skid, the authcrypt sender). Resolving any other did:example identifier fails.
    private static DidResolver CreateMultiResolver(PublicKeyMemory mallorySenderPublic)
    {
        DidDocument alice = AliceDocument();
        DidDocument mallory = MalloryDocument(mallorySenderPublic);

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (did, _, _, _) =>
            {
                DidDocument? document = string.Equals(did, AliceDid, System.StringComparison.Ordinal)
                    ? alice
                    : string.Equals(did, MalloryDid, System.StringComparison.Ordinal)
                        ? mallory
                        : null;

                return ValueTask.FromResult(document is null
                    ? DidResolutionResult.Failure(DidResolutionErrors.NotFound)
                    : DidResolutionResult.Success(document, new DidDocumentMetadata()));
            })));
    }


    //Alice's document: her Ed25519 key-1 authorized for authentication (verifies the inner signature).
    private static DidDocument AliceDocument()
    {
        return new DidDocument
        {
            Id = new GenericDidMethod(AliceDid),
            VerificationMethod = [Ed25519VerificationMethod(AliceSignerKid, AliceDid, AliceEd25519PublicX)],
            Authentication = [new AuthenticationMethod(AliceSignerKid)]
        };
    }


    //Mallory's document: her X25519 key authorized for keyAgreement under the skid (the authcrypt sender).
    private static DidDocument MalloryDocument(PublicKeyMemory senderPublic)
    {
        return new DidDocument
        {
            Id = new GenericDidMethod(MalloryDid),
            VerificationMethod = [X25519VerificationMethod(MallorySkid, MalloryDid, senderPublic)],
            KeyAgreement = [new KeyAgreementMethod(MallorySkid)]
        };
    }


    //An Ed25519 authentication verification method (OKP) from a base64url public x.
    private static VerificationMethod Ed25519VerificationMethod(string id, string controller, string publicKeyX)
    {
        return new VerificationMethod
        {
            Id = id,
            Type = "JsonWebKey2020",
            Controller = controller,
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
    private static VerificationMethod X25519VerificationMethod(string id, string controller, PublicKeyMemory publicKey)
    {
        return new VerificationMethod
        {
            Id = id,
            Type = "JsonWebKey2020",
            Controller = controller,
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
