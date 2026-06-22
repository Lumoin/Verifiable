using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for the JWE Flattened JSON Serialization (RFC 7516 §7.2.2): the single-recipient
/// optimization of the General JSON Serialization where the <c>recipients</c> array is removed
/// and that one recipient's <c>header</c> and <c>encrypted_key</c> are hoisted to the top level.
/// Covers <see cref="FlattenedJweMessage.FromGeneral"/> (the single-recipient gate and the
/// ownership-transfer neutralization that makes a double-<c>using</c> safe),
/// <see cref="FlattenedJweMessage.ToFlattenedJson"/>, and the
/// <see cref="GeneralJweParsing.ParseFlattenedJson"/> round trip and rejection points, including
/// the §7.2.2 equivalence: a single-recipient message decrypts identically whether serialized as
/// General or Flattened.
/// </summary>
[TestClass]
internal sealed class FlattenedJweMessageTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly byte[] Plaintext =
        Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"type\":\"https://didcomm.org/basicmessage/2.0/message\"}");

    private const string RecipientKid = "did:example:recipient-0#key-1";


    [TestMethod]
    public async Task ToFlattenedJson_EmitsNoRecipientsMember()
    {
        using AnoncryptSingleRecipient single = await EncryptAnoncryptSingleRecipientAsync().ConfigureAwait(false);

        using GeneralJweMessage general = single.Message;
        using FlattenedJweMessage flattened = FlattenedJweMessage.FromGeneral(general);

        string flattenedJson = flattened.ToFlattenedJson(TestSetup.Base64UrlEncoder);

        Assert.Contains("\"protected\":", flattenedJson, "Flattened serialization carries the protected header.");
        Assert.Contains("\"header\":{\"kid\":", flattenedJson, "Flattened serialization hoists the recipient header.kid to the top level.");
        Assert.Contains(RecipientKid, flattenedJson, "The single recipient's kid must appear in the flattened header.");
        Assert.Contains("\"encrypted_key\":", flattenedJson, "Flattened serialization hoists encrypted_key to the top level.");
        Assert.Contains("\"iv\":", flattenedJson, "Flattened serialization carries the shared iv.");
        Assert.Contains("\"ciphertext\":", flattenedJson, "Flattened serialization carries the shared ciphertext.");
        Assert.Contains("\"tag\":", flattenedJson, "Flattened serialization carries the shared tag.");
        Assert.DoesNotContain("recipients", flattenedJson, StringComparison.Ordinal,
            "RFC 7516 §7.2.2: the 'recipients' member MUST NOT be present in the flattened syntax.");
    }


    [TestMethod]
    public async Task FromGeneral_ThrowsWhenNotExactlyOneRecipient()
    {
        //Encrypt to two recipients, then attempt the flattened adaptation: the flattened
        //syntax is single-recipient only (RFC 7516 §7.2.2).
        using TwoRecipientGeneral two = await EncryptAnoncryptTwoRecipientsAsync().ConfigureAwait(false);

        using GeneralJweMessage general = two.Message;

        Assert.ThrowsExactly<ArgumentException>(() => FlattenedJweMessage.FromGeneral(general),
            "FromGeneral must reject a message that does not have exactly one recipient.");
    }


    [TestMethod]
    public async Task FromGeneral_NeutralizesSourceSoDoubleUsingIsSafe()
    {
        //The D8 fix: FromGeneral marks the source transferred so its Dispose becomes a no-op,
        //making the idiomatic double-using safe. The shared components are disposed exactly once
        //(by the flattened message) at scope exit. Completing the using scope without throwing is
        //the disposal assertion; the explicit Assert proves the flattened components are still
        //live after the transfer by serializing it.
        using AnoncryptSingleRecipient single = await EncryptAnoncryptSingleRecipientAsync().ConfigureAwait(false);

        string flattenedJson;
        using(GeneralJweMessage general = single.Message)
        using(FlattenedJweMessage flattened = FlattenedJweMessage.FromGeneral(general))
        {
            //The flattened message's components must still be live: serialization reads the
            //ephemeral key, encrypted_key, iv, ciphertext, and tag spans.
            flattenedJson = flattened.ToFlattenedJson(TestSetup.Base64UrlEncoder);
            Assert.Contains("\"ciphertext\":", flattenedJson,
                "The flattened message's components must remain live after the ownership transfer.");
        }

        //Reaching here means both Dispose calls ran without a double-dispose throw.
        Assert.IsFalse(string.IsNullOrEmpty(flattenedJson), "The flattened serialization must have been produced.");
    }


    [TestMethod]
    public async Task ParseFlattenedJson_RoundTripDecrypts()
    {
        using AnoncryptSingleRecipient single = await EncryptAnoncryptSingleRecipientAsync().ConfigureAwait(false);

        string flattenedJson;
        using(GeneralJweMessage general = single.Message)
        using(FlattenedJweMessage flattened = FlattenedJweMessage.FromGeneral(general))
        {
            flattenedJson = flattened.ToFlattenedJson(TestSetup.Base64UrlEncoder);
        }

        using AeadGeneralMessage parsed = GeneralJweParsing.ParseFlattenedJson(
            flattenedJson,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        Assert.HasCount(1, parsed.Recipients, "A flattened message parses to exactly one recipient.");

        using PrivateKeyMemory recipientPrivate = single.RecipientPrivateKey;
        using DecryptedContent decrypted = await parsed.DecryptAnoncryptAsync(
            RecipientKid,
            recipientPrivate,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(decrypted.AsReadOnlySpan().SequenceEqual(Plaintext),
            "ParseFlattenedJson followed by DecryptAnoncryptAsync must recover the original plaintext.");
    }


    [TestMethod]
    public async Task FlattenedDecryptsIdenticallyToSingleRecipientGeneral()
    {
        //RFC 7516 §7.2.2: "Other than this syntax difference, JWE JSON Serialization objects
        //using the flattened syntax are processed identically to those using the general
        //syntax." Serialize the SAME single-recipient message both ways and assert byte-identical
        //recovered plaintext.
        using AnoncryptSingleRecipient single = await EncryptAnoncryptSingleRecipientAsync().ConfigureAwait(false);

        string generalJson;
        string flattenedJson;
        using(GeneralJweMessage general = single.Message)
        {
            generalJson = general.ToGeneralJson(TestSetup.Base64UrlEncoder);
            using FlattenedJweMessage flattened = FlattenedJweMessage.FromGeneral(general);
            flattenedJson = flattened.ToFlattenedJson(TestSetup.Base64UrlEncoder);
        }

        using AeadGeneralMessage parsedGeneral = GeneralJweParsing.ParseGeneralJson(
            generalJson,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using AeadGeneralMessage parsedFlattened = GeneralJweParsing.ParseFlattenedJson(
            flattenedJson,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        using PrivateKeyMemory privateForGeneral = single.RecipientPrivateKey;
        using PrivateKeyMemory privateForFlattened = single.RecipientPrivateKeyCopy;

        using DecryptedContent fromGeneral = await parsedGeneral.DecryptAnoncryptAsync(
            RecipientKid,
            privateForGeneral,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using DecryptedContent fromFlattened = await parsedFlattened.DecryptAnoncryptAsync(
            RecipientKid,
            privateForFlattened,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(fromGeneral.AsReadOnlySpan().SequenceEqual(fromFlattened.AsReadOnlySpan()),
            "RFC 7516 §7.2.2: the general and flattened serializations of one message must decrypt to byte-identical plaintext.");
        Assert.IsTrue(fromFlattened.AsReadOnlySpan().SequenceEqual(Plaintext),
            "Both serializations must recover the original plaintext.");
    }


    [TestMethod]
    public async Task ParseFlattenedJson_RejectsRecipientsMemberPresent()
    {
        //RFC 7516 §7.2.2: "The 'recipients' member MUST NOT be present when using this syntax."
        //Inject a recipients member into an otherwise-valid flattened serialization.
        using AnoncryptSingleRecipient single = await EncryptAnoncryptSingleRecipientAsync().ConfigureAwait(false);

        string flattenedJson;
        using(GeneralJweMessage general = single.Message)
        using(FlattenedJweMessage flattened = FlattenedJweMessage.FromGeneral(general))
        {
            flattenedJson = flattened.ToFlattenedJson(TestSetup.Base64UrlEncoder);
        }

        //Insert a recipients member right after the opening brace.
        string injected = "{\"recipients\":[]," + flattenedJson[1..];

        Assert.ThrowsExactly<FormatException>(() => GeneralJweParsing.ParseFlattenedJson(
                injected,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "A flattened serialization carrying a 'recipients' member must be rejected (RFC 7516 §7.2.2).");
    }


    [TestMethod]
    [DataRow("encrypted_key", DisplayName = "Missing top-level encrypted_key")]
    [DataRow("header", DisplayName = "Missing header (so header.kid is absent)")]
    [DataRow("protected", DisplayName = "Missing protected")]
    [DataRow("iv", DisplayName = "Missing iv")]
    [DataRow("ciphertext", DisplayName = "Missing ciphertext")]
    [DataRow("tag", DisplayName = "Missing tag")]
    public async Task ParseFlattenedJson_RejectsMissingMembers(string memberToRemove)
    {
        using AnoncryptSingleRecipient single = await EncryptAnoncryptSingleRecipientAsync().ConfigureAwait(false);

        string flattenedJson;
        using(GeneralJweMessage general = single.Message)
        using(FlattenedJweMessage flattened = FlattenedJweMessage.FromGeneral(general))
        {
            flattenedJson = flattened.ToFlattenedJson(TestSetup.Base64UrlEncoder);
        }

        string mutated = RemoveTopLevelMember(flattenedJson, memberToRemove);

        Assert.ThrowsExactly<FormatException>(() => GeneralJweParsing.ParseFlattenedJson(
                mutated,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            $"A flattened serialization missing the '{memberToRemove}' member must be rejected (RFC 7516 §7.2.2).");
    }


    //Encrypts an anoncrypt (ECDH-ES+A256KW / A256GCM, X25519) single-recipient message and
    //returns it with the recipient key material the caller decrypts with. Mirrors the canonical
    //GeneralJweTests anoncrypt setup but with exactly one recipient.
    private async Task<AnoncryptSingleRecipient> EncryptAnoncryptSingleRecipientAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);

        GeneralJweMessage message = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
            Plaintext,
            new List<GeneralJweRecipientInput> { new(RecipientKid, recipient.PublicKey) },
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            protectedHeaderExtras: null,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return new AnoncryptSingleRecipient(message, recipient.PublicKey, recipient.PrivateKey, Pool);
    }


    private async Task<TwoRecipientGeneral> EncryptAnoncryptTwoRecipientsAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> first = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> second = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);

        GeneralJweMessage message = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
            Plaintext,
            new List<GeneralJweRecipientInput>
            {
                new("did:example:recipient-0#key-1", first.PublicKey),
                new("did:example:recipient-1#key-1", second.PublicKey)
            },
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            protectedHeaderExtras: null,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return new TwoRecipientGeneral(message, first.PublicKey, first.PrivateKey, second.PublicKey, second.PrivateKey);
    }


    //Removes a top-level string-or-object member from a flat JWE JSON object produced by
    //ToFlattenedJson. The serializer emits members in a fixed order with no insignificant
    //whitespace, so a targeted substring excision is exact: it deletes the member and its
    //trailing comma (or, for the last member, the leading comma).
    private static string RemoveTopLevelMember(string json, string member)
    {
        if(string.Equals(member, "header", StringComparison.Ordinal))
        {
            //header is an object member: "header":{"kid":"..."}.
            int headerStart = json.IndexOf("\"header\":{", StringComparison.Ordinal);
            int objectEnd = json.IndexOf('}', headerStart);
            //objectEnd closes the header object; remove from the comma before "header" through it.
            int commaBefore = json.LastIndexOf(',', headerStart);

            return json[..commaBefore] + json[(objectEnd + 1)..];
        }

        //String members: "<member>":"<value>". Remove the member and one adjacent comma.
        string token = $"\"{member}\":";
        int memberStart = json.IndexOf(token, StringComparison.Ordinal);
        int valueQuoteStart = json.IndexOf('"', memberStart + token.Length);
        int valueQuoteEnd = json.IndexOf('"', valueQuoteStart + 1);

        //Prefer to consume the comma that follows the member; if it is the last member,
        //consume the comma that precedes it.
        int afterValue = valueQuoteEnd + 1;
        if(afterValue < json.Length && json[afterValue] == ',')
        {
            return json[..memberStart] + json[(afterValue + 1)..];
        }

        int commaPrev = json.LastIndexOf(',', memberStart);

        return json[..commaPrev] + json[afterValue..];
    }


    //Carries a single-recipient anoncrypt message together with the recipient key material the
    //tests decrypt with. The message is NOT owned here — each test disposes it via its own
    //'using'. Dispose releases the recipient public key and, unless it was handed out (and so is
    //owned by the test's own 'using'), the recipient private key. SensitiveMemory.Dispose is
    //idempotent, so any overlap is harmless.
    private sealed class AnoncryptSingleRecipient: IDisposable
    {
        private readonly PublicKeyMemory recipientPublic;
        private readonly PrivateKeyMemory recipientPrivate;
        private readonly MemoryPool<byte> pool;
        private bool isPrivateConsumed;

        public AnoncryptSingleRecipient(
            GeneralJweMessage message,
            PublicKeyMemory recipientPublic,
            PrivateKeyMemory recipientPrivate,
            MemoryPool<byte> pool)
        {
            Message = message;
            this.recipientPublic = recipientPublic;
            this.recipientPrivate = recipientPrivate;
            this.pool = pool;
        }

        public GeneralJweMessage Message { get; }

        //The recipient's private key, handed out for the decrypt path. Once handed out the test's
        //own 'using' owns its disposal, so Dispose here must not release it again.
        public PrivateKeyMemory RecipientPrivateKey
        {
            get
            {
                isPrivateConsumed = true;

                return recipientPrivate;
            }
        }

        //A second independent private key carrier built from the same key bytes, so a test that
        //decrypts twice (general and flattened) can dispose each via its own 'using'.
        public PrivateKeyMemory RecipientPrivateKeyCopy
        {
            get
            {
                ReadOnlySpan<byte> bytes = recipientPrivate.AsReadOnlySpan();
                IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
                bytes.CopyTo(owner.Memory.Span);

                return new PrivateKeyMemory(owner, recipientPrivate.Tag);
            }
        }

        public void Dispose()
        {
            recipientPublic.Dispose();
            if(!isPrivateConsumed)
            {
                recipientPrivate.Dispose();
            }
        }
    }


    //Carries a two-recipient anoncrypt message. The message is NOT owned here — the test disposes
    //it via its own 'using'. Dispose releases the two recipients' key material.
    private sealed class TwoRecipientGeneral: IDisposable
    {
        private readonly PublicKeyMemory firstPublic;
        private readonly PrivateKeyMemory firstPrivate;
        private readonly PublicKeyMemory secondPublic;
        private readonly PrivateKeyMemory secondPrivate;

        public TwoRecipientGeneral(
            GeneralJweMessage message,
            PublicKeyMemory firstPublic,
            PrivateKeyMemory firstPrivate,
            PublicKeyMemory secondPublic,
            PrivateKeyMemory secondPrivate)
        {
            Message = message;
            this.firstPublic = firstPublic;
            this.firstPrivate = firstPrivate;
            this.secondPublic = secondPublic;
            this.secondPrivate = secondPrivate;
        }

        public GeneralJweMessage Message { get; }

        public void Dispose()
        {
            firstPublic.Dispose();
            firstPrivate.Dispose();
            secondPublic.Dispose();
            secondPrivate.Dispose();
        }
    }
}
