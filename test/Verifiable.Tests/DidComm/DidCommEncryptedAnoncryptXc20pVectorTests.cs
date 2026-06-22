using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Anchors the DIDComm v2.1 anoncrypt UNPACK (decrypt) path with XChaCha20-Poly1305 (<c>XC20P</c>) content
/// encryption to the DIDComm Messaging v2.1 Appendix C.3 example 1 vector: ECDH-ES over X25519 with
/// <c>XC20P</c>, to three of Bob's <c>keyAgreement</c> keys. This is the last of the five C.3 vectors and the
/// only one exercising the XChaCha20-Poly1305 content cipher (a 24-byte extended nonce, a 16-byte Poly1305
/// tag). Each recipient decrypts with Bob's Appendix A.2 X25519 static private key and MUST recover the
/// Appendix C.1 plaintext. The vector is the first external validation of the XC20P content decryption — the
/// HChaCha20 subkey derivation, the RFC 8439 nonce split, and the Poly1305 tag — so a successful decrypt to
/// the byte-exact C.1 message proves the whole chain against the spec's own interop bytes.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAnoncryptXc20pVectorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //A non-nested anoncrypt message never triggers nested-signature resolution, so this resolver is never
    //invoked; it satisfies the unpack overload's resolver parameter.
    private static readonly DidResolver NestedSignerResolver = new DidResolver(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    //Appendix C.1 plaintext (the message every C.3 vector encrypts). The C.3/C.2 vector bytes use the "http"
    //scheme even though the C.1 prose shows "https" — the recovered plaintext is byte-exact, so the assertion
    //tracks the vector's real content (a spec erratum, mirrored in the other anoncrypt vector tests).
    private const string ExpectedId = "1234567890";
    private const string ExpectedType = "http://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string ExpectedFrom = "did:example:alice";
    private const string ExpectedTo = "did:example:bob";
    private const long ExpectedCreatedTime = 1516269022;
    private const long ExpectedExpiresTime = 1516385931;

    private const string BobKid1 = "did:example:bob#key-x25519-1";
    private const string BobKid2 = "did:example:bob#key-x25519-2";
    private const string BobKid3 = "did:example:bob#key-x25519-3";

    //Bob's Appendix A.2 X25519 static keyAgreement private scalars ("d" coordinate, base64url).
    private const string BobD1 = "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0";
    private const string BobD2 = "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk";
    private const string BobD3 = "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0";

    //The apv embedded in this vector's protected header — base64url-nopad(SHA-256(sorted kids joined ".")).
    private const string ExpectedApv = "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA";

    //Appendix C.3 example 1: anoncrypt ECDH-ES X25519 + XC20P (DIDComm Messaging v2.1). The iv is 24 bytes
    //(the XChaCha20 extended nonce) and the tag is 16 bytes (Poly1305).
    private const string VectorJson =
        /*lang=json,strict*/ """
        {"ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p","protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0","recipients":[{"encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A","header":{"kid":"did:example:bob#key-x25519-1"}},{"encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ","header":{"kid":"did:example:bob#key-x25519-2"}},{"encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A","header":{"kid":"did:example:bob#key-x25519-3"}}],"tag":"6ylC_iAs4JvDQzXeY6MuYQ","iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"}
        """;


    /// <summary>
    /// The Appendix C.3 example 1 (ECDH-ES X25519, XC20P) vector decrypts via the delegate-taking overload for
    /// each of Bob's three <c>keyAgreement</c> recipients, recovering the Appendix C.1 plaintext — the CEK is
    /// wrapped once per recipient under the shared ECDH-ES agreement and the content is XChaCha20-Poly1305.
    /// </summary>
    [TestMethod]
    [DataRow(BobKid1, BobD1)]
    [DataRow(BobKid2, BobD2)]
    [DataRow(BobKid3, BobD3)]
    public async Task AppendixC3Example1DecryptsForRecipient(string recipientKid, string recipientD)
    {
        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(recipientD);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The same Appendix C.3 example 1 vector decrypts through the REGISTRY-resolving overload, which peeks the
    /// wire <c>enc</c> (<c>XC20P</c>) and resolves the XChaCha20-Poly1305 content delegate from it, and the
    /// ECDH-ES agreement / derivation / unwrap from the recipient key's curve.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3Example1DecryptsViaRegistryOverload()
    {
        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            BobKid1,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The <c>apv</c> re-derived from the example 1 recipient kid list equals the <c>apv</c> embedded in the
    /// vector's protected header. apv = base64url-nopad(SHA-256(UTF8(sorted ordinal kids joined with "."))).
    /// </summary>
    [TestMethod]
    public void AppendixC3Example1ApvReDerivationMatchesVector()
    {
        string[] kids = [BobKid1, BobKid2, BobKid3];
        string apv = JweAgreementInfo.ComputeApvFromRecipientKeyIds(kids, TestSetup.Base64UrlEncoder, Pool);

        Assert.AreEqual(ExpectedApv, apv, "The re-derived apv MUST equal the vector's embedded apv.");
        Assert.AreEqual(ExtractProtectedHeaderApv(VectorJson), apv, "The re-derived apv MUST equal the protected header's 'apv'.");
    }


    /// <summary>
    /// A single flipped character in the Poly1305 <c>tag</c> makes the C.3 example 1 vector fail CLOSED with
    /// <see cref="DidCommDecryptionError.DecryptionFailed"/> and no recovered message. This pins the fail-closed
    /// path of the new XChaCha20-Poly1305 decryption: BouncyCastle signals a tag mismatch with an
    /// <see cref="System.Security.Cryptography.CryptographicException">CryptographicException</see> (translated
    /// from its <c>InvalidCipherTextException</c>), which the unpack contract turns into a closed failure rather
    /// than letting an exception escape.
    /// </summary>
    [TestMethod]
    public async Task TamperedTagFailsClosed()
    {
        const string tamperedVector = /*tag's first char 6 -> 7*/
            """{"ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p","protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0","recipients":[{"encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A","header":{"kid":"did:example:bob#key-x25519-1"}},{"encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ","header":{"kid":"did:example:bob#key-x25519-2"}},{"encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A","header":{"kid":"did:example:bob#key-x25519-3"}}],"tag":"7ylC_iAs4JvDQzXeY6MuYQ","iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"}""";

        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(tamperedVector);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            BobKid1,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "A tampered Poly1305 tag MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.DecryptionFailed, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a tag-verification failure yields no plaintext.");
    }


    /// <summary>
    /// An <c>iv</c> that is not the 24-byte XChaCha20 extended nonce (here the 12-byte nonce from another C.3
    /// vector) makes the example 1 envelope fail CLOSED at the parse boundary with
    /// <see cref="DidCommDecryptionError.MalformedEnvelope"/>: the parser validates the wire <c>iv</c> length
    /// against the <c>XC20P</c> descriptor (24 bytes) before any decryption is attempted.
    /// </summary>
    [TestMethod]
    public async Task WrongIvLengthFailsClosed()
    {
        const string wrongIvVector = /*iv replaced with a 12-byte nonce*/
            """{"ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p","protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0","recipients":[{"encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A","header":{"kid":"did:example:bob#key-x25519-1"}},{"encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ","header":{"kid":"did:example:bob#key-x25519-2"}},{"encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A","header":{"kid":"did:example:bob#key-x25519-3"}}],"tag":"6ylC_iAs4JvDQzXeY6MuYQ","iv":"lGKCvg2xrvi8Qa_D"}""";

        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(wrongIvVector);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            BobKid1,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.XChaCha20Poly1305DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "An iv that is not the 24-byte XChaCha20 nonce MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.MalformedEnvelope, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a wrong-length iv yields no plaintext.");
    }


    //Asserts a successful anoncrypt unpack recovering the Appendix C.1 plaintext.
    private static void AssertRecoveredC1Message(DidCommEncryptedUnpackResult result)
    {
        Assert.IsTrue(result.IsUnpacked, $"The XC20P vector MUST unpack to the C.1 plaintext. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Anoncrypt, result.Mode);
        Assert.IsFalse(result.IsSenderAuthenticated, "Anoncrypt MUST NOT authenticate the sender.");
        Assert.IsNull(result.SenderKeyId, "Anoncrypt carries no sender key id.");

        Assert.IsNotNull(result.Message);
        DidCommMessage message = result.Message!;
        Assert.AreEqual(ExpectedId, message.Id);
        Assert.AreEqual(ExpectedType, message.Type);
        Assert.AreEqual(ExpectedFrom, message.From);
        Assert.AreEqual<long?>(ExpectedCreatedTime, message.CreatedTime);
        Assert.AreEqual<long?>(ExpectedExpiresTime, message.ExpiresTime);

        Assert.IsNotNull(message.To);
        Assert.HasCount(1, message.To!);
        Assert.AreEqual(ExpectedTo, message.To![0]);

        Assert.IsNotNull(message.Body);
        Assert.IsTrue(message.Body!.TryGetValue("messagespecificattribute", out object? value), "The recovered body MUST carry the attribute.");
        Assert.AreEqual("and its value", value as string);
    }


    //Encodes the wire JSON to UTF-8 and wraps it in a pooled, named encrypted-message artifact.
    private static DidCommEncryptedMessage CreateEncryptedMessage(string wireJson)
    {
        return DidCommEncryptedMessage.Create(Encoding.UTF8.GetBytes(wireJson), BufferTags.Json, Pool);
    }


    //Decodes the wire's base64url `protected` member and reads its `apv` string value.
    private static string? ExtractProtectedHeaderApv(string wireJson)
    {
        ReadOnlySpan<byte> wire = Encoding.UTF8.GetBytes(wireJson);
        string? protectedEncoded = JwkJsonReader.ExtractStringValue(wire, "protected"u8);
        Assert.IsNotNull(protectedEncoded, "The vector MUST carry a 'protected' member.");

        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(protectedEncoded!, Pool);

        return JwkJsonReader.ExtractStringValue(headerOwner.Memory.Span, "apv"u8);
    }


    //Imports an X25519 ECDH exchange private key from its JWK "d" base64url scalar. The decoder returns an
    //exact-size owner; ownership transfers to the PrivateKeyMemory, which the caller disposes.
    private static PrivateKeyMemory X25519ExchangePrivateKey(string dBase64Url)
    {
        IMemoryOwner<byte> d = TestSetup.Base64UrlDecoder(dBase64Url, Pool);

        return new PrivateKeyMemory(d, CryptoTags.X25519PrivateKey);
    }
}
