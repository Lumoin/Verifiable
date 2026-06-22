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
/// Anchors the DIDComm v2.1 authcrypt UNPACK (decrypt) path
/// (<see cref="DidCommEncryptedExtensions.UnpackAuthcryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, AuthenticatedKeyAgreementDecryptDelegate, AuthenticatedKeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, System.Threading.CancellationToken)"/>)
/// to the DIDComm Messaging v2.1 Appendix C.3 example 4 vector: ECDH-1PU over X25519 with A256CBC-HS512,
/// sent from <c>did:example:alice#key-x25519-1</c> (the <c>skid</c>) to three of Bob's <c>keyAgreement</c>
/// keys. Each recipient decrypts with Bob's Appendix A.2 static private key and MUST recover the
/// Appendix C.1 plaintext while authenticating Alice as the sender. The sender's public key is resolved
/// from Alice's DID document <c>keyAgreement</c> relationship through a stub <see cref="DidResolver"/>.
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAuthcryptVectorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    private const string ExampleDidPrefix = "did:example";

    //Appendix C.1 plaintext (the message the C.3 example 4 vector encrypts). The C.3/C.2 vector bytes use
    //the "http" scheme even though the C.1 prose shows "https" — the recovered plaintext is byte-exact, so
    //the assertion tracks the vector's real content (a spec erratum, mirrored in the anoncrypt vector tests).
    private const string ExpectedId = "1234567890";
    private const string ExpectedType = "http://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string ExpectedFrom = "did:example:alice";
    private const string ExpectedTo = "did:example:bob";
    private const long ExpectedCreatedTime = 1516269022;
    private const long ExpectedExpiresTime = 1516385931;

    //The sender key id carried as `skid` in the vector's protected header (apu = base64url of this value).
    private const string AliceSkid = "did:example:alice#key-x25519-1";

    //Alice's Appendix A.1 X25519 sender public coordinate (her keyAgreement key-x25519-1 "x").
    private const string AliceX25519PublicX = "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs";

    //Bob's Appendix A.2 X25519 static keyAgreement private scalars ("d" coordinate, base64url).
    private const string BobKid1 = "did:example:bob#key-x25519-1";
    private const string BobKid2 = "did:example:bob#key-x25519-2";
    private const string BobKid3 = "did:example:bob#key-x25519-3";
    private const string BobD1 = "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0";
    private const string BobD2 = "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk";
    private const string BobD3 = "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0";

    //The apv embedded in this vector's protected header — base64url-nopad(SHA-256(sorted kids joined ".")).
    private const string ExpectedApv = "NcsuAnrRfPK69A-rkZ0L9XWUG4jMvNC3Zg74BPz53PA";

    //Appendix C.3 example 4: authcrypt ECDH-1PU X25519 + A256CBC-HS512 (DIDComm Messaging v2.1).
    private const string VectorJson =
        /*lang=json,strict*/ """
        {"ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR","protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ","recipients":[{"encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB","header":{"kid":"did:example:bob#key-x25519-1"}},{"encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK","header":{"kid":"did:example:bob#key-x25519-2"}},{"encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo","header":{"kid":"did:example:bob#key-x25519-3"}}],"tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U","iv":"o02OXDQ6_-sKz2PX_6oyJg"}
        """;


    /// <summary>
    /// The Appendix C.3 example 4 vector decrypts for each of Bob's three <c>keyAgreement</c> recipients via
    /// the delegate-taking overload, recovering the Appendix C.1 plaintext and authenticating Alice (the
    /// <c>skid</c>) as the sender — the CEK is wrapped once per recipient under the shared ECDH-1PU agreement.
    /// </summary>
    [TestMethod]
    [DataRow(BobKid1, BobD1)]
    [DataRow(BobKid2, BobD2)]
    [DataRow(BobKid3, BobD3)]
    public async Task AppendixC3Example4DecryptsForRecipient(string recipientKid, string recipientD)
    {
        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(recipientD);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);
        DidResolver resolver = CreateResolver(CreateAliceDidDocument());

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            recipientKid,
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

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The same Appendix C.3 example 4 vector decrypts through the REGISTRY-resolving overload, which selects
    /// the AES_CBC_HMAC_SHA2 content delegate from the wire <c>enc</c> qualifier and the authenticated
    /// agreement / derivation / unwrap from the recipient key's curve.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3Example4DecryptsViaRegistryOverload()
    {
        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);
        DidResolver resolver = CreateResolver(CreateAliceDidDocument());

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            BobKid1,
            recipientPrivate,
            resolver,
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
    /// The <c>apv</c> re-derived from the vector's recipient kid list equals the <c>apv</c> embedded in the
    /// protected header — base64url-nopad(SHA-256(UTF8(sorted ordinal kids joined with "."))).
    /// </summary>
    [TestMethod]
    public void AppendixC3Example4ApvReDerivationMatchesVector()
    {
        string[] kids = [BobKid1, BobKid2, BobKid3];
        string apv = JweAgreementInfo.ComputeApvFromRecipientKeyIds(kids, TestSetup.Base64UrlEncoder, Pool);

        Assert.AreEqual(ExpectedApv, apv, "The re-derived apv MUST equal the vector's embedded apv.");
        Assert.AreEqual(ExtractProtectedHeaderValue(VectorJson, "apv"u8), apv, "The re-derived apv MUST equal the protected header's 'apv'.");
    }


    /// <summary>
    /// The vector's <c>apu</c> protected header is the base64url-nopad encoding of the <c>skid</c> value
    /// (DIDComm v2.1 §ECDH-1PU key wrapping: "apu ... MUST contain the skid value base64 RawURL encoded").
    /// </summary>
    [TestMethod]
    public void AppendixC3Example4ApuIsBase64UrlOfSkid()
    {
        string expectedApu = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(AliceSkid));

        Assert.AreEqual(expectedApu, ExtractProtectedHeaderValue(VectorJson, "apu"u8), "apu MUST be base64url(skid).");
    }


    /// <summary>
    /// When the sender (skid) DID cannot be resolved, the vector fails CLOSED with
    /// <see cref="DidCommDecryptionError.SenderResolutionFailed"/> and yields no plaintext — the sender's
    /// public key is required before any authenticated decryption.
    /// </summary>
    [TestMethod]
    public async Task SenderResolutionFailureFailsClosed()
    {
        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);

        DidCommEncryptedUnpackResult result = await UnpackWithResolverAsync(encrypted, recipientPrivate, CreateFailingResolver()).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "An unresolvable skid DID MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.SenderResolutionFailed, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: an unresolvable sender yields no plaintext.");
    }


    /// <summary>
    /// When the resolved sender DID document does not authorize the <c>skid</c> for the <c>keyAgreement</c>
    /// relationship, the vector fails CLOSED with <see cref="DidCommDecryptionError.SenderResolutionFailed"/>.
    /// </summary>
    [TestMethod]
    public async Task SkidNotInKeyAgreementFailsClosed()
    {
        using PrivateKeyMemory recipientPrivate = X25519ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);

        //Alice's document carries the verification method but does NOT list it under keyAgreement.
        DidResolver resolver = CreateResolver(CreateAliceDidDocument(authorizeKeyAgreement: false));

        DidCommEncryptedUnpackResult result = await UnpackWithResolverAsync(encrypted, recipientPrivate, resolver).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "A skid absent from keyAgreement MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.SenderResolutionFailed, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: an unauthorized skid yields no plaintext.");
    }


    //Unpacks the vector for Bob's recipient 1 via the delegate-taking overload against the given resolver.
    private ValueTask<DidCommEncryptedUnpackResult> UnpackWithResolverAsync(
        DidCommEncryptedMessage encrypted, PrivateKeyMemory recipientPrivate, DidResolver resolver)
    {
        return encrypted.UnpackAuthcryptAsync(
            BobKid1,
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
            TestContext.CancellationToken);
    }


    //Asserts a successful authcrypt unpack recovering the Appendix C.1 plaintext with Alice authenticated.
    private static void AssertRecoveredC1Message(DidCommEncryptedUnpackResult result)
    {
        Assert.IsTrue(result.IsUnpacked, $"The vector MUST unpack to the C.1 plaintext. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Authcrypt, result.Mode);
        Assert.IsTrue(result.IsSenderAuthenticated, "Authcrypt MUST authenticate the sender.");
        Assert.AreEqual(AliceSkid, result.SenderKeyId, "The authenticated sender key id MUST be the skid.");
        Assert.IsFalse(result.IsSignedInner, "The C.3 example 4 vector is not a nested signed message.");
        Assert.IsTrue(result.IsRecipientAddressedInTo, "The C.3 example 4 recipient (did:example:bob) is listed in 'to' and MUST be flagged as addressed.");

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
    private static DidCommEncryptedMessage CreateEncryptedMessage(string wireJson) =>
        DidCommEncryptedMessage.Create(Encoding.UTF8.GetBytes(wireJson), BufferTags.Json, Pool);


    //Decodes the wire's base64url `protected` member and reads a named string value from it.
    private static string? ExtractProtectedHeaderValue(string wireJson, ReadOnlySpan<byte> member)
    {
        ReadOnlySpan<byte> wire = Encoding.UTF8.GetBytes(wireJson);
        string? protectedEncoded = JwkJsonReader.ExtractStringValue(wire, "protected"u8);
        Assert.IsNotNull(protectedEncoded, "The vector MUST carry a 'protected' member.");

        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(protectedEncoded!, Pool);

        return JwkJsonReader.ExtractStringValue(headerOwner.Memory.Span, member);
    }


    //Imports an X25519 ECDH exchange private key from its JWK "d" base64url scalar. The decoder returns an
    //exact-size owner; ownership transfers to the PrivateKeyMemory, which the caller disposes.
    private static PrivateKeyMemory X25519ExchangePrivateKey(string dBase64Url)
    {
        IMemoryOwner<byte> d = TestSetup.Base64UrlDecoder(dBase64Url, Pool);

        return new PrivateKeyMemory(d, CryptoTags.X25519PrivateKey);
    }


    //A resolver that returns the given document for any did:example identifier.
    private static DidResolver CreateResolver(DidDocument document)
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //A resolver that fails to resolve any did:example identifier.
    private static DidResolver CreateFailingResolver()
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));
    }


    //Alice's DID document carrying her X25519 keyAgreement key. When authorizeKeyAgreement is false the
    //key remains in verificationMethod but is not listed under the keyAgreement relationship, so a sender
    //resolution that requires keyAgreement authorization fails.
    private static DidDocument CreateAliceDidDocument(bool authorizeKeyAgreement = true)
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(ExpectedFrom),
            VerificationMethod =
            [
                X25519VerificationMethod(AliceSkid, AliceX25519PublicX)
            ]
        };

        if(authorizeKeyAgreement)
        {
            document.KeyAgreement = [new KeyAgreementMethod(AliceSkid)];
        }

        return document;
    }


    //An X25519 keyAgreement verification method (OKP, no JWA alg — the curve alone identifies it).
    private static VerificationMethod X25519VerificationMethod(string id, string publicKeyX)
    {
        return new VerificationMethod
        {
            Id = id,
            Type = "JsonWebKey2020",
            Controller = ExpectedFrom,
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
}
