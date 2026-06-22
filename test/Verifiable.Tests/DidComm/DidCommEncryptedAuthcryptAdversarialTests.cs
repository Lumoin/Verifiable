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
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Adversarial, fail-closed tests for the DIDComm v2.1 authcrypt (ECDH-1PU) unpack
/// (<see cref="DidCommEncryptedExtensions.UnpackAuthcryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, AuthenticatedKeyAgreementDecryptDelegate, AuthenticatedKeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, System.Threading.CancellationToken)"/>).
/// Each test packs a valid X25519 / A256CBC-HS512 authcrypt message, tampers or rebuilds the wire envelope,
/// and asserts that unpack returns <see cref="DidCommEncryptedUnpackResult.IsUnpacked"/> = <see langword="false"/>
/// with the specific <see cref="DidCommDecryptionError"/> — and that a tampered ciphertext/tag never
/// yields plaintext. The adversarial envelopes are hand-mutated (a real attacker does not use the
/// producer), so each verifier check is proven independently of pack-side behavior. The sender's public
/// key is resolved from Alice's DID document <c>keyAgreement</c> relationship through a stub
/// <see cref="DidResolver"/>, exactly as the authcrypt vector tests exercise it.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAuthcryptAdversarialTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //The protected-header serializer, mirroring the anoncrypt adversarial tests: the headers are a
    //Dictionary<string, object> the JWE layer hands to this delegate to produce the UTF-8 JSON bytes.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string AliceSkid = "did:example:alice#key-x25519-1";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-x25519-1";
    private const string ExampleDidPrefix = "did:example";


    /// <summary>A tampered <c>ciphertext</c> fails the AEAD tag check — no plaintext is recovered (DIDComm v2.1 ECDH-1PU).</summary>
    [TestMethod]
    public async Task TamperedCiphertextRejected()
    {
        await AssertTamperedTopLevelMemberRejectedAsync("ciphertext", DidCommDecryptionError.DecryptionFailed).ConfigureAwait(false);
    }


    /// <summary>A tampered authentication <c>tag</c> fails the AEAD tag check — no plaintext is recovered (DIDComm v2.1 ECDH-1PU).</summary>
    [TestMethod]
    public async Task TamperedTagRejected()
    {
        await AssertTamperedTopLevelMemberRejectedAsync("tag", DidCommDecryptionError.DecryptionFailed).ConfigureAwait(false);
    }


    /// <summary>A tampered <c>iv</c> fails the AEAD tag check — no plaintext is recovered (DIDComm v2.1 ECDH-1PU).</summary>
    [TestMethod]
    public async Task TamperedIvRejected()
    {
        await AssertTamperedTopLevelMemberRejectedAsync("iv", DidCommDecryptionError.DecryptionFailed).ConfigureAwait(false);
    }


    /// <summary>
    /// A tampered <c>protected</c> header is rejected. <c>apv</c> (the recipient binding) and <c>apu</c>
    /// (<c>base64url(skid)</c>) live inside the base64url <c>protected</c> member, which is also the AEAD's
    /// additional authenticated data, so flipping a character of the whole <c>protected</c> value changes
    /// both the bound AAD and the header. Unpack MUST fail: with
    /// <see cref="DidCommDecryptionError.DecryptionFailed"/> when the tampered header still decodes/parses
    /// but mismatches the AAD, or <see cref="DidCommDecryptionError.MalformedEnvelope"/> when the tampered
    /// value no longer decodes or parses (DIDComm v2.1 ECDH-1PU key wrapping).
    /// </summary>
    [TestMethod]
    public async Task TamperedProtectedHeaderRejected()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            string tampered = TamperTopLevelMember(packed.WireJson, "protected");
            using DidCommEncryptedMessage message = WireToMessage(tampered);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A tampered 'protected' header (and thus AAD) MUST NOT unpack.");
            Assert.IsTrue(
                result.Error is DidCommDecryptionError.DecryptionFailed or DidCommDecryptionError.MalformedEnvelope,
                $"A tampered 'protected' header MUST be rejected as DecryptionFailed or MalformedEnvelope. Actual: {result.Error}.");
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>A <c>kid</c> that no <c>recipients</c> entry carries is rejected as <see cref="DidCommDecryptionError.NoMatchingRecipient"/> (DIDComm v2.1 ECDH-1PU).</summary>
    [TestMethod]
    public async Task WrongRecipientKidRejected()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            using DidCommEncryptedMessage message = WireToMessage(packed.WireJson);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, "did:example:bob#key-99", packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A kid absent from 'recipients' MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.NoMatchingRecipient, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// Unpacking the untampered message under the VALID kid but with a DIFFERENT private key fails the
    /// authenticated key-agreement / CEK-unwrap / AEAD chain — <see cref="DidCommDecryptionError.DecryptionFailed"/>
    /// (DIDComm v2.1 ECDH-1PU).
    /// </summary>
    [TestMethod]
    public async Task WrongPrivateKeyRejected()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            using DidCommEncryptedMessage message = WireToMessage(packed.WireJson);

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> outsider = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
            using PublicKeyMemory outsiderPublic = outsider.PublicKey;
            using PrivateKeyMemory outsiderPrivate = outsider.PrivateKey;

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, outsiderPrivate, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A different private key for a valid kid MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// A protected <c>typ</c> rewritten to a non-encrypted media type (the signed media type) is rejected
    /// as <see cref="DidCommDecryptionError.UnexpectedMediaType"/> — the media-type gate fires before any
    /// cryptographic work, so the rewrite is detected regardless of the otherwise intact envelope (DIDComm
    /// v2.1 ECDH-1PU).
    /// </summary>
    [TestMethod]
    public async Task TypRewrittenToSignedMediaTypeRejected()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //The real protected header carries `typ`:`application/didcomm-encrypted+json`. Rewrite only the
            //typ value, inside the decoded header JSON, then re-encode and splice it back. Every other
            //envelope member (epk/apv/apu/skid/enc/alg/recipients/iv/ciphertext/tag) is unchanged.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "typ", DidCommMediaTypes.Signed);
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A protected 'typ' that is not the encrypted media type MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.UnexpectedMediaType, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// An envelope whose protected <c>alg</c> is an anoncrypt algorithm (<c>ECDH-ES+A256KW</c>) is rejected
    /// by the authcrypt unpack path as <see cref="DidCommDecryptionError.UnsupportedAlgorithm"/> — the
    /// authcrypt unpack only handles ECDH-1PU key wrapping. The alg gate fires before the JWE is parsed
    /// (DIDComm v2.1 ECDH-1PU key wrapping).
    /// </summary>
    [TestMethod]
    public async Task AnoncryptAlgRejectedByAuthcryptUnpack()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Rewrite only the alg value from ECDH-1PU+A256KW to ECDH-ES+A256KW inside the decoded header.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "alg", WellKnownJweAlgorithms.EcdhEsA256Kw);
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "An anoncrypt (ECDH-ES) alg MUST NOT unpack via the authcrypt path.");
            Assert.AreEqual(DidCommDecryptionError.UnsupportedAlgorithm, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// An envelope whose protected <c>enc</c> is a non-committing content algorithm (<c>A256GCM</c>) is
    /// rejected by the authcrypt unpack path as <see cref="DidCommDecryptionError.UnsupportedAlgorithm"/>. The
    /// 1PU draft (§2.1) mandates the compactly-committing AES_CBC_HMAC_SHA2 content family for authcrypt; the
    /// consume-side enc-family gate fires after the alg gate and before any cryptographic work, so a
    /// substituted non-committing enc is detected regardless of the otherwise intact envelope (DIDComm v2.1
    /// §ECDH-1PU key wrapping).
    /// </summary>
    [TestMethod]
    public async Task NonCommittingEncRejectedByAuthcryptUnpack()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Rewrite only the enc value from A256CBC-HS512 to A256GCM (a non-committing AEAD) inside the header.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "enc", WellKnownJweEncryptionAlgorithms.A256Gcm);
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A non-committing (A256GCM) enc MUST NOT unpack via the authcrypt path.");
            Assert.AreEqual(DidCommDecryptionError.UnsupportedAlgorithm, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// An <c>epk.crv</c> rewritten to an unmapped curve makes the injected crv→tag converter throw
    /// <see cref="NotSupportedException"/> during envelope parsing; the authcrypt unpack MUST fail CLOSED
    /// (<see cref="DidCommDecryptionError.MalformedEnvelope"/>) rather than let the exception escape — the
    /// <c>kty</c> gate does not constrain <c>crv</c>, so an unknown curve is a malformed envelope, not a crash.
    /// </summary>
    [TestMethod]
    public async Task UnmappedEpkCurveRejectedFailClosed()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Rewrite only the epk `crv` value (the sole `crv` member in the header) to an unmapped curve token.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "crv", "X-NotACurve");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "An unmapped epk curve MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext and never throws.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>Input that is not JSON at all is rejected as <see cref="DidCommDecryptionError.MalformedEnvelope"/> (DIDComm v2.1 ECDH-1PU).</summary>
    [TestMethod]
    public async Task NonJsonInputRejected()
    {
        using DidCommEncryptedMessage message = DidCommEncryptedMessage.Create(
            Encoding.UTF8.GetBytes("not json"), BufferTags.Json, Pool);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory senderPublic = sender.PublicKey;

        DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, recipientPrivate, CreateResolver(senderPublic)).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "Non-JSON input MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
    }


    /// <summary>
    /// A JSON envelope missing the <c>protected</c> member is rejected as
    /// <see cref="DidCommDecryptionError.MalformedEnvelope"/> — the alg/enc peek cannot find the
    /// integrity-protected header (DIDComm v2.1 ECDH-1PU).
    /// </summary>
    [TestMethod]
    public async Task MissingProtectedMemberRejected()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            string mutated = RemoveTopLevelStringMember(packed.WireJson, "protected");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "An envelope without a 'protected' member MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// A recipient <c>encrypted_key</c> tampered to a misaligned wrapped-key length still fails CLOSED with
    /// <see cref="DidCommDecryptionError.DecryptionFailed"/> — never an unhandled exception. AES key unwrap
    /// throws <see cref="System.ArgumentException"/> (not a cryptographic exception) for a wrapped key shorter
    /// than the RFC 3394 minimum or not a multiple of eight bytes; the unpack contract maps it to a decryption
    /// failure like any other, honouring the documented "every failure returns a result" guarantee (DIDComm
    /// v2.1 ECDH-1PU).
    /// </summary>
    [TestMethod]
    public async Task MisalignedWrappedKeyRejected()
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //"AAAA" decodes to three bytes — below the RFC 3394 minimum and not a multiple of eight, the input
            //that makes AES key unwrap throw ArgumentException rather than a cryptographic integrity failure.
            string mutated = ReplaceJsonStringValue(packed.WireJson, "encrypted_key", "AAAA");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A misaligned wrapped key MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a misaligned wrapped key yields no plaintext and never throws.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    //Packs a valid X25519 / A256CBC-HS512 authcrypt single-recipient (BobKid) message with the given plaintext
    //`to` list, tampers the named top-level base64url member, rebuilds the wire artifact, unpacks under the
    //valid kid + private key (with Alice's sender public key resolvable), and asserts the fail-closed
    //rejection with the expected error.
    private async Task AssertTamperedTopLevelMemberRejectedAsync(string member, DidCommDecryptionError expectedError)
    {
        AuthcryptWire packed = await PackAuthcryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            string tampered = TamperTopLevelMember(packed.WireJson, member);
            using DidCommEncryptedMessage message = WireToMessage(tampered);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey, CreateResolver(packed.SenderPublicKey)).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, $"A tampered '{member}' MUST NOT unpack.");
            Assert.AreEqual(expectedError, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a tampered ciphertext/tag/iv yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    //Packs a valid X25519 / A256CBC-HS512 authcrypt single-recipient (BobKid) message, returning its General
    //JSON wire string, the recipient private key, and the sender PUBLIC key. The ephemeral keys and the
    //recipient public key are disposed here; the recipient private key and the sender public key are owned by
    //the returned AuthcryptWire and disposed via DisposeKeys. The sender public key is what the resolver doc
    //must carry under keyAgreement so unpack can resolve and authenticate the sender (skid).
    private async Task<AuthcryptWire> PackAuthcryptWireAsync(IList<string>? to)
    {
        DidCommMessage message = NewMessage(to);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> sender = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PrivateKeyMemory senderPrivate = sender.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        string wireJson;
        using(DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            AliceSkid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false))
        {
            wireJson = Encoding.UTF8.GetString(encrypted.AsReadOnlySpan());
        }

        //The resolver doc must carry the sender PUBLIC key under keyAgreement so unpack can resolve it.
        return new AuthcryptWire(wireJson, recipient.PrivateKey, sender.PublicKey);
    }


    //Unpacks via the delegate-taking authcrypt overload (X25519 / A256CBC-HS512), resolving the sender's
    //public key from the given resolver and the shared non-network exchange context.
    private ValueTask<DidCommEncryptedUnpackResult> UnpackAsync(DidCommEncryptedMessage message, string recipientKid, PrivateKeyMemory recipientPrivateKey, DidResolver resolver)
    {
        return message.UnpackAuthcryptAsync(
            recipientKid,
            recipientPrivateKey,
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
            TestContext.CancellationToken);
    }


    //Builds Alice's DID document from the sender PUBLIC key (the x coordinate is base64url of the raw
    //32-byte X25519 public key) and returns a resolver that serves it for any did:example identifier, so the
    //authcrypt unpack can resolve and authenticate the sender (skid) under the keyAgreement relationship.
    private static DidResolver CreateResolver(PublicKeyMemory senderPublic)
    {
        string x = TestSetup.Base64UrlEncoder(senderPublic.AsReadOnlySpan());
        var document = new DidDocument
        {
            Id = new GenericDidMethod(AliceDid),
            VerificationMethod = [X25519VerificationMethod(AliceSkid, x)],
            KeyAgreement = [new KeyAgreementMethod(AliceSkid)]
        };

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //An X25519 keyAgreement verification method (OKP, no JWA alg — the curve alone identifies it).
    private static VerificationMethod X25519VerificationMethod(string id, string publicKeyX)
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
                    [WellKnownJwkMemberNames.X] = publicKeyX
                }
            }
        };
    }


    //Rebuilds a DidCommEncryptedMessage from a (possibly mutated) UTF-8 General JSON wire string.
    private static DidCommEncryptedMessage WireToMessage(string wireJson) =>
        DidCommEncryptedMessage.Create(Encoding.UTF8.GetBytes(wireJson), BufferTags.Json, Pool);


    //A fresh DIDComm message with the shared id/type/from and the given `to` list (null for no header).
    //Authcrypt authenticates the sender, so `from` MUST be present and MUST match the skid's DID.
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


    //Flips the first character of a top-level base64url member value to corrupt it while keeping it valid
    //base64url and the same length (the GeneralJweTests.TamperJsonValue technique). The serializer emits
    //members with no insignificant whitespace, so the "<member>":"<value>" token is exact.
    private static string TamperTopLevelMember(string wireJson, string member)
    {
        string token = $"\"{member}\":\"";
        int valueStart = wireJson.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = wireJson.IndexOf('"', valueStart);
        string originalValue = wireJson[valueStart..valueEnd];

        char[] chars = originalValue.ToCharArray();
        chars[0] = chars[0] == 'A' ? 'B' : 'A';

        return wireJson[..valueStart] + new string(chars) + wireJson[valueEnd..];
    }


    //Removes a top-level string member ("<member>":"<value>") together with one adjacent comma. The
    //serializer emits members in a fixed order with no insignificant whitespace, so this is an exact excision.
    private static string RemoveTopLevelStringMember(string json, string member)
    {
        string token = $"\"{member}\":";
        int memberStart = json.IndexOf(token, StringComparison.Ordinal);
        int valueQuoteStart = json.IndexOf('"', memberStart + token.Length);
        int valueQuoteEnd = json.IndexOf('"', valueQuoteStart + 1);
        int afterValue = valueQuoteEnd + 1;

        if(afterValue < json.Length && json[afterValue] == ',')
        {
            return json[..memberStart] + json[(afterValue + 1)..];
        }

        int commaPrev = json.LastIndexOf(',', memberStart);

        return json[..commaPrev] + json[afterValue..];
    }


    //Decodes the base64url `protected` header, replaces the JSON string value of a top-level member inside
    //it (e.g. typ/alg), re-encodes the header, and splices it back into the `protected` envelope member.
    //Only string-valued members are handled, which is what typ/alg/enc are. Mirrors the robust
    //decode→edit→re-encode approach in GeneralJweParsingRejectionTests.
    private static string RewriteProtectedHeaderStringValue(string wireJson, string member, string newValue)
    {
        string headerJson = DecodeProtectedHeader(wireJson, out string protectedEncoded);
        string newHeaderJson = ReplaceJsonStringValue(headerJson, member, newValue);
        string newProtectedEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(newHeaderJson));

        return wireJson.Replace(
            $"\"protected\":\"{protectedEncoded}\"",
            $"\"protected\":\"{newProtectedEncoded}\"",
            StringComparison.Ordinal);
    }


    //Replaces the value of a top-level JSON string member with a new raw string value.
    private static string ReplaceJsonStringValue(string json, string member, string newValue)
    {
        string token = $"\"{member}\":\"";
        int valueStart = json.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = json.IndexOf('"', valueStart);

        return json[..valueStart] + newValue + json[valueEnd..];
    }


    //Extracts and base64url-decodes the wire's `protected` member to its UTF-8 JSON header string, also
    //returning the raw base64url value so the caller can splice a re-encoded header back in.
    private static string DecodeProtectedHeader(string wireJson, out string protectedEncoded)
    {
        const string token = "\"protected\":\"";
        int valueStart = wireJson.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = wireJson.IndexOf('"', valueStart);
        protectedEncoded = wireJson[valueStart..valueEnd];

        using IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(protectedEncoded, Pool);

        return Encoding.UTF8.GetString(decoded.Memory.Span);
    }


    //A packed authcrypt wire string plus the recipient's private key and the sender's PUBLIC key. The caller
    //disposes both keys via DisposeKeys.
    private sealed class AuthcryptWire
    {
        private readonly PrivateKeyMemory recipientPrivate;
        private readonly PublicKeyMemory senderPublic;

        public AuthcryptWire(string wireJson, PrivateKeyMemory recipientPrivate, PublicKeyMemory senderPublic)
        {
            WireJson = wireJson;
            this.recipientPrivate = recipientPrivate;
            this.senderPublic = senderPublic;
        }

        public string WireJson { get; }

        public PrivateKeyMemory RecipientPrivateKey => recipientPrivate;

        public PublicKeyMemory SenderPublicKey => senderPublic;

        public void DisposeKeys()
        {
            recipientPrivate.Dispose();
            senderPublic.Dispose();
        }
    }
}
