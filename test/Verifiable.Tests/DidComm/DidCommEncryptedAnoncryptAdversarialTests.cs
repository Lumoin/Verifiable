using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
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
/// Adversarial, fail-closed tests for the DIDComm v2.1 anoncrypt unpack
/// (<see cref="DidCommEncryptedExtensions.UnpackAnoncryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, KeyAgreementDecryptDelegate, KeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, System.Threading.CancellationToken)"/>).
/// Each test packs a valid P-256 / A256GCM anoncrypt message, tampers or rebuilds the wire envelope,
/// and asserts that unpack returns <see cref="DidCommEncryptedUnpackResult.IsUnpacked"/> = <see langword="false"/>
/// with the specific <see cref="DidCommDecryptionError"/> — and that a tampered ciphertext/tag never
/// yields plaintext. The adversarial envelopes are hand-mutated (a real attacker does not use the
/// producer), so each verifier check is proven independently of pack-side behavior.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAnoncryptAdversarialTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //A non-nested anoncrypt message never triggers nested-signature resolution, so this resolver is never
    //invoked; it satisfies the unpack overload's resolver parameter.
    private static readonly DidResolver NestedSignerResolver = new DidResolver(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    //The protected-header serializer, mirroring DidCommEncryptedAnoncryptRoundTripTests: the headers
    //are a Dictionary<string, object> the JWE layer hands to this delegate to produce the UTF-8 JSON bytes.
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private const string MessageId = "1234567890";
    private const string MessageType = "https://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string AliceDid = "did:example:alice";
    private const string BobDid = "did:example:bob";
    private const string BobKid = "did:example:bob#key-1";


    /// <summary>A tampered <c>ciphertext</c> fails the AEAD tag check — no plaintext is recovered.</summary>
    [TestMethod]
    public async Task TamperedCiphertextRejected()
    {
        await AssertTamperedTopLevelMemberRejectedAsync("ciphertext", DidCommDecryptionError.DecryptionFailed).ConfigureAwait(false);
    }


    /// <summary>A tampered authentication <c>tag</c> fails the AEAD tag check — no plaintext is recovered.</summary>
    [TestMethod]
    public async Task TamperedTagRejected()
    {
        await AssertTamperedTopLevelMemberRejectedAsync("tag", DidCommDecryptionError.DecryptionFailed).ConfigureAwait(false);
    }


    /// <summary>A tampered <c>iv</c> fails the AEAD tag check — no plaintext is recovered.</summary>
    [TestMethod]
    public async Task TamperedIvRejected()
    {
        await AssertTamperedTopLevelMemberRejectedAsync("iv", DidCommDecryptionError.DecryptionFailed).ConfigureAwait(false);
    }


    /// <summary>
    /// A tampered <c>protected</c> header is rejected. <c>apv</c> (the recipient binding) lives inside the
    /// base64url <c>protected</c> member, which is also the AEAD's additional authenticated data, so
    /// flipping a character of the whole <c>protected</c> value changes both the bound AAD and the header.
    /// Unpack MUST fail: with <see cref="DidCommDecryptionError.DecryptionFailed"/> when the tampered
    /// header still decodes/parses but mismatches the AAD, or <see cref="DidCommDecryptionError.MalformedEnvelope"/>
    /// when the tampered value no longer decodes or parses.
    /// </summary>
    [TestMethod]
    public async Task TamperedProtectedHeaderRejected()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            string tampered = TamperTopLevelMember(packed.WireJson, "protected");
            using DidCommEncryptedMessage message = WireToMessage(tampered);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

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


    /// <summary>A <c>kid</c> that no <c>recipients</c> entry carries is rejected as <see cref="DidCommDecryptionError.NoMatchingRecipient"/>.</summary>
    [TestMethod]
    public async Task WrongRecipientKidRejected()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            using DidCommEncryptedMessage message = WireToMessage(packed.WireJson);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, "did:example:bob#key-99", packed.RecipientPrivateKey).ConfigureAwait(false);

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
    /// key-agreement / CEK-unwrap / AEAD chain — <see cref="DidCommDecryptionError.DecryptionFailed"/>.
    /// </summary>
    [TestMethod]
    public async Task WrongPrivateKeyRejected()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            using DidCommEncryptedMessage message = WireToMessage(packed.WireJson);

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> outsider = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
            using PublicKeyMemory outsiderPublic = outsider.PublicKey;
            using PrivateKeyMemory outsiderPrivate = outsider.PrivateKey;

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, outsiderPrivate).ConfigureAwait(false);

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
    /// cryptographic work, so the rewrite is detected regardless of the otherwise intact envelope.
    /// </summary>
    [TestMethod]
    public async Task TypRewrittenToSignedMediaTypeRejected()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //The real protected header carries `typ`:`application/didcomm-encrypted+json`. Rewrite only the
            //typ value, inside the decoded header JSON, then re-encode and splice it back. Every other
            //envelope member (epk/apv/enc/alg/recipients/iv/ciphertext/tag) is unchanged.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "typ", DidCommMediaTypes.Signed);
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

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
    /// An <c>epk.crv</c> rewritten to an unmapped curve makes the injected crv→tag converter throw
    /// <see cref="NotSupportedException"/> during envelope parsing; the anoncrypt unpack MUST fail CLOSED
    /// (<see cref="DidCommDecryptionError.MalformedEnvelope"/>) rather than let the exception escape — the
    /// <c>kty</c> gate does not constrain <c>crv</c>, so an unknown curve is a malformed envelope, not a crash.
    /// </summary>
    [TestMethod]
    public async Task UnmappedEpkCurveRejectedFailClosed()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Rewrite only the epk `crv` value (the sole `crv` member in the header) to an unmapped curve token.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "crv", "X-NotACurve");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "An unmapped epk curve MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext and never throws.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// Injecting an extra recipient into the unprotected <c>recipients[]</c> array (leaving the protected
    /// <c>apv</c> unchanged) MUST fail closed. The recipient set is bound only by <c>apv</c>; the legitimate
    /// recipient's entry is still present and the KDF binds the (untampered) header apv, so the CEK would
    /// still unwrap — but the decryptor re-derives apv from <c>recipients[]</c> and the mismatch is detected
    /// (DIDComm v2.1 §ECDH-ES key wrapping, the recipient binding). The recipients array is not part of the
    /// AEAD-protected header, so this is the only check that binds it.
    /// </summary>
    [TestMethod]
    public async Task InjectedRecipientFailsApvBinding()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Add a second (attacker) recipient to recipients[] without touching the protected-header apv.
            JsonObject wire = JsonNode.Parse(packed.WireJson)!.AsObject();
            var recipients = (JsonArray)wire["recipients"]!;
            recipients.Add(new JsonObject
            {
                ["header"] = new JsonObject { ["kid"] = "did:example:mallory#key-1" },
                ["encrypted_key"] = "AAAA"
            });
            using DidCommEncryptedMessage message = WireToMessage(wire.ToJsonString());

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A recipients[] altered from the apv-committed set MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a tampered recipient set yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// An envelope whose protected <c>alg</c> is an authcrypt algorithm (<c>ECDH-1PU+A256KW</c>) is rejected
    /// by the anoncrypt unpack path as <see cref="DidCommDecryptionError.UnsupportedAlgorithm"/> — the
    /// anoncrypt unpack only handles ECDH-ES key wrapping. The alg gate fires before the JWE is parsed.
    /// </summary>
    [TestMethod]
    public async Task AuthcryptAlgRejectedByAnoncryptUnpack()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Rewrite only the alg value from ECDH-ES+A256KW to ECDH-1PU+A256KW inside the decoded header.
            string mutated = RewriteProtectedHeaderStringValue(packed.WireJson, "alg", WellKnownJweAlgorithms.Ecdh1PuA256Kw);
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "An authcrypt (ECDH-1PU) alg MUST NOT unpack via the anoncrypt path.");
            Assert.AreEqual(DidCommDecryptionError.UnsupportedAlgorithm, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>Input that is not JSON at all is rejected as <see cref="DidCommDecryptionError.MalformedEnvelope"/>.</summary>
    [TestMethod]
    public async Task NonJsonInputRejected()
    {
        using DidCommEncryptedMessage message = DidCommEncryptedMessage.Create(
            Encoding.UTF8.GetBytes("not json"), BufferTags.Json, Pool);

        using PrivateKeyMemory recipientPrivate = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool).PrivateKey;

        DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, recipientPrivate).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "Non-JSON input MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a rejected message yields no plaintext.");
    }


    /// <summary>
    /// A JSON envelope missing the <c>protected</c> member is rejected as
    /// <see cref="DidCommDecryptionError.MalformedEnvelope"/> — the alg/enc peek cannot find the
    /// integrity-protected header.
    /// </summary>
    [TestMethod]
    public async Task MissingProtectedMemberRejected()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            string mutated = RemoveTopLevelStringMember(packed.WireJson, "protected");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

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
    /// A message whose plaintext <c>to</c> does NOT list the decrypting recipient still unpacks (a blind-copy
    /// recipient is legitimate, DIDComm v2.1 §Message Headers), with <see cref="DidCommEncryptedUnpackResult.IsRecipientAddressedInTo"/>
    /// cleared. This guards against a regression where the to-mismatch wrongly hard-fails decryption.
    /// </summary>
    [TestMethod]
    public async Task ToMismatchStillUnpacksAndIsAdvisoryOnly()
    {
        //Pack with `to` = [carol] but deliver to Bob's kid: Bob is a blind-copy recipient absent from `to`.
        AnoncryptWire packed = await PackAnoncryptWireAsync(["did:example:carol"]).ConfigureAwait(false);
        try
        {
            using DidCommEncryptedMessage message = WireToMessage(packed.WireJson);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsTrue(result.IsUnpacked, $"A blind-copy recipient absent from 'to' MUST still unpack. Error: {result.Error}.");
            Assert.AreEqual(DidCommDecryptionError.None, result.Error);
            Assert.IsFalse(result.IsRecipientAddressedInTo, "The recipient is absent from 'to' and MUST NOT be flagged as addressed.");
            Assert.IsNotNull(result.Message, "A successful unpack yields the recovered plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>
    /// An epk whose coordinate is not on the declared NIST curve is rejected as
    /// <see cref="DidCommDecryptionError.MalformedEnvelope"/> before any key agreement — the invalid-curve /
    /// weak-point check DIDComm v2.1 requires of NIST-curve decryptors: "implementations that decrypt
    /// messages from a NIST curve MUST verify that the received public key (contained in the JWE protected
    /// header) is on the curve in question."
    /// </summary>
    [TestMethod]
    public async Task OffCurveEpkRejected()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //Flip a character of the epk 'y' coordinate inside the decoded protected header so (x, y') is no
            //longer on P-256, then re-encode and splice. The epk is parsed and curve-checked before any ECDH.
            string mutated = FlipProtectedHeaderMemberFirstChar(packed.WireJson, "y");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "An off-curve epk MUST NOT unpack (DIDComm v2.1 §invalid curve and weak point attacks).");
            Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: an off-curve epk yields no plaintext.");
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
    /// failure like any other, honouring the documented "every failure returns a result" guarantee.
    /// </summary>
    [TestMethod]
    public async Task MisalignedWrappedKeyFailsClosed()
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            //"AAAA" decodes to three bytes — below the RFC 3394 minimum and not a multiple of eight, the input
            //that makes AES key unwrap throw ArgumentException rather than a cryptographic integrity failure.
            string mutated = ReplaceJsonStringValue(packed.WireJson, "encrypted_key", "AAAA");
            using DidCommEncryptedMessage message = WireToMessage(mutated);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, "A misaligned wrapped key MUST NOT unpack.");
            Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a misaligned wrapped key yields no plaintext and never throws.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    /// <summary>Packing with an empty recipient list is rejected — anoncrypt requires at least one recipient.</summary>
    [TestMethod]
    public async Task EmptyRecipientsPackRejected()
    {
        DidCommMessage message = NewMessage([BobDid]);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await message.PackAnoncryptAsync(
                [],
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                DidCommMessageJson.Serializer,
                HeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                MicrosoftEntropyFunctions.GenerateNonce,
                BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    //Packs a valid P-256 / A256GCM anoncrypt single-recipient (BobKid) message with the given plaintext
    //`to` list, tampers the named top-level base64url member, rebuilds the wire artifact, unpacks under
    //the valid kid + private key, and asserts the fail-closed rejection with the expected error.
    private async Task AssertTamperedTopLevelMemberRejectedAsync(string member, DidCommDecryptionError expectedError)
    {
        AnoncryptWire packed = await PackAnoncryptWireAsync([BobDid]).ConfigureAwait(false);
        try
        {
            string tampered = TamperTopLevelMember(packed.WireJson, member);
            using DidCommEncryptedMessage message = WireToMessage(tampered);

            DidCommEncryptedUnpackResult result = await UnpackAsync(message, BobKid, packed.RecipientPrivateKey).ConfigureAwait(false);

            Assert.IsFalse(result.IsUnpacked, $"A tampered '{member}' MUST NOT unpack.");
            Assert.AreEqual(expectedError, result.Error);
            Assert.IsNull(result.Message, "Fail-closed: a tampered ciphertext/tag/iv yields no plaintext.");
        }
        finally
        {
            packed.DisposeKeys();
        }
    }


    //Packs a valid P-256 / A256GCM anoncrypt single-recipient (BobKid) message, returning its General JSON
    //wire string and the recipient private key. The ephemeral and recipient public keys are disposed here;
    //the recipient private key is owned by the returned AnoncryptWire and disposed via DisposeKeys.
    private async Task<AnoncryptWire> PackAnoncryptWireAsync(IList<string>? to)
    {
        DidCommMessage message = NewMessage(to);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;

        var recipients = new List<GeneralJweRecipientInput> { new(BobKid, recipientPublic) };

        string wireJson;
        using(DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            wireJson = Encoding.UTF8.GetString(encrypted.AsReadOnlySpan());
        }

        return new AnoncryptWire(wireJson, recipient.PrivateKey);
    }


    //Unpacks via the delegate-taking anoncrypt overload (P-256 / A256GCM).
    private ValueTask<DidCommEncryptedUnpackResult> UnpackAsync(DidCommEncryptedMessage message, string recipientKid, PrivateKeyMemory recipientPrivateKey)
    {
        return message.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivateKey,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken);
    }


    //Rebuilds a DidCommEncryptedMessage from a (possibly mutated) UTF-8 General JSON wire string.
    private static DidCommEncryptedMessage WireToMessage(string wireJson) =>
        DidCommEncryptedMessage.Create(Encoding.UTF8.GetBytes(wireJson), BufferTags.Json, Pool);


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


    //Flips the first character of a string member's value INSIDE the decoded protected header (e.g. the epk
    //'y' coordinate), re-encodes the header, and splices it back into the `protected` envelope member —
    //producing an off-curve epk while keeping the value valid base64url of the same length.
    private static string FlipProtectedHeaderMemberFirstChar(string wireJson, string member)
    {
        string headerJson = DecodeProtectedHeader(wireJson, out string protectedEncoded);

        string token = $"\"{member}\":\"";
        int valueStart = headerJson.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = headerJson.IndexOf('"', valueStart);
        string originalValue = headerJson[valueStart..valueEnd];

        char[] chars = originalValue.ToCharArray();
        chars[0] = chars[0] == 'A' ? 'B' : 'A';
        string newHeaderJson = headerJson[..valueStart] + new string(chars) + headerJson[valueEnd..];

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


    //A packed anoncrypt wire string plus the recipient's private key. The caller disposes via DisposeKeys.
    private sealed class AnoncryptWire
    {
        private readonly PrivateKeyMemory recipientPrivate;

        public AnoncryptWire(string wireJson, PrivateKeyMemory recipientPrivate)
        {
            WireJson = wireJson;
            this.recipientPrivate = recipientPrivate;
        }

        public string WireJson { get; }

        public PrivateKeyMemory RecipientPrivateKey => recipientPrivate;

        public void DisposeKeys()
        {
            recipientPrivate.Dispose();
        }
    }
}
