using System.Buffers;
using System.Text;
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
/// Anchors the DIDComm v2.1 anoncrypt UNPACK (decrypt) path (<see cref="DidCommEncryptedExtensions.UnpackAnoncryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, KeyAgreementDecryptDelegate, KeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, System.Threading.CancellationToken)"/>)
/// to the two NIST-curve anoncrypt vectors from DIDComm Messaging v2.1 Appendix C.3: example 2
/// (ECDH-ES P-384, A256CBC-HS512) and example 3 (ECDH-ES P-521, A256GCM). Each vector is decrypted with
/// Bob's Appendix A static <c>keyAgreement</c> private keys and MUST recover the Appendix C.1 plaintext.
/// The vectors are the first external validation of the anoncrypt ECDH-ES KDF + content decryption, so
/// every assertion states the spec-correct expected outcome (a successful decrypt to the C.1 message).
/// </summary>
[TestClass]
internal sealed class DidCommEncryptedAnoncryptVectorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    //A non-nested anoncrypt message never triggers nested-signature resolution, so this resolver is never
    //invoked; it satisfies the unpack overload's resolver parameter.
    private static readonly DidResolver NestedSignerResolver = new DidResolver(DidMethodSelectors.FromResolvers(
        ("did:example", (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

    //Appendix C.1 plaintext (the message every C.3 vector encrypts).
    private const string ExpectedId = "1234567890";

    //The spec's C.1 prose shows the plaintext type as "https://example.com/..." but the bytes actually
    //encrypted into the C.3 vectors (and signed into the C.2 vectors — the base64url payload there
    //decodes to "type":"http://example.com/...") use the "http" scheme. The recovered plaintext is
    //byte-exact, so the conformance assertion tracks the vector's real content, not the prose example.
    private const string ExpectedType = "http://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string ExpectedFrom = "did:example:alice";
    private const string ExpectedTo = "did:example:bob";
    private const long ExpectedCreatedTime = 1516269022;
    private const long ExpectedExpiresTime = 1516385931;

    //----- Appendix C.3 example 2: ECDH-ES P-384 + A256CBC-HS512 -----

    private const string P384Kid1 = "did:example:bob#key-p384-1";
    private const string P384Kid2 = "did:example:bob#key-p384-2";

    //Bob's Appendix A P-384 static keyAgreement private scalars ("d" coordinate, base64url).
    private const string BobP384D1 = "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY";
    private const string BobP384D2 = "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T";

    //The apv embedded in this vector's protected header (DIDComm v2.1 §ECDH-ES: base64url-nopad(SHA-256(sorted kids joined with "."))).
    private const string P384ExpectedApv = "LJA9Eoks5tamUFVBalMwBhJ6DkDcJ8HK4SlXZWqDqno";

    private const string P384VectorJson =
        /*lang=json,strict*/ """
        {"ciphertext":"HPnc9w7jK0T73Spifq_dcVJnONbT9MZ9oorDJFEBJAfmwYRqvs1rKue-udrNLTTH0qjjbeuji01xPRF5JiWyy-gSMX4LHdLhPxHxjjQCTkThY0kapofU85EjLPlI4ytbHiGcrPIezqCun4iDkmb50pwiLvL7XY1Ht6zPUUdhiV6qWoPP4qeY_8pfH74Q5u7K4TQ0uU3KP8CVZQuafrkOBbqbqpJV-lWpWIKxil44f1IT_GeIpkWvmkYxTa1MxpYBgOYa5_AUxYBumcIFP-b6g7GQUbN-1SOoP76EzxZU_louspzQ2HdEH1TzXw2LKclN8GdxD7kB0H6lZbZLT3ScDzSVSbvO1w1fXHXOeOzywuAcismmoEXQGbWZm7wJJJ2r","protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTM4NCIsIngiOiIxNjFhZ0dlYWhHZW1IZ25qSG1RX0JfU09OeUJWZzhWTGRoVGdWNVc1NFZiYWJ5bGxpc3NuWjZXNzc5SW9VcUtyIiwieSI6ImNDZXFlRmdvYm9fY1ItWTRUc1pCWlg4dTNCa2l5TnMyYi12ZHFPcU9MeUNuVmdPMmpvN25zQV9JQzNhbnQ5T1gifSwiYXB2IjoiTEpBOUVva3M1dGFtVUZWQmFsTXdCaEo2RGtEY0o4SEs0U2xYWldxRHFubyIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ","recipients":[{"encrypted_key":"SlyWCiOaHMMH9CqSs2CHpRd2XwbueZ1-MfYgKVepXWpgmTgtsgNOAaYwV5pxK3D67HV51F-vLBFlAHke7RYp_GeGDFYhAf5s","header":{"kid":"did:example:bob#key-p384-1"}},{"encrypted_key":"5e7ChtaRgIlV4yS4NSD7kEo0iJfFmL_BFgRh3clDKBG_QoPd1eOtFlTxFJh-spE0khoaw8vEEYTcQIg4ReeFT3uQ8aayz1oY","header":{"kid":"did:example:bob#key-p384-2"}}],"tag":"bkodXkuuwRbqksnQNsCM2YLy9f0v0xNgnhSUAoFGtmE","iv":"aE1XaH767m7LY0JTN7RsAA"}
        """;

    //----- Appendix C.3 example 3: ECDH-ES P-521 + A256GCM -----

    private const string P521Kid1 = "did:example:bob#key-p521-1";
    private const string P521Kid2 = "did:example:bob#key-p521-2";

    //Bob's Appendix A P-521 static keyAgreement private scalars ("d" coordinate, base64url).
    private const string BobP521D1 = "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6";
    private const string BobP521D2 = "ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk";

    //The apv embedded in this vector's protected header.
    private const string P521ExpectedApv = "GOeo76ym6NCg9WWMEYfW0eVDT5668zEhl2uAIW-E-HE";

    private const string P521VectorJson =
        /*lang=json,strict*/ """
        {"ciphertext":"mxnFl4s8FRsIJIBVcRLv4gj4ru5R0H3BdvyBWwXV3ILhtl_moqzx9COINGomP4ueuApuY5xdMDvRHm2mLo6N-763wjNSjAibNrqVZC-EG24jjYk7RPZ26fEW4z87LHuLTicYCD4yHqilRbRgbOCT0Db5221Kec0HDZTXLzBqVwC2UMyDF4QT6Uz3fE4f_6BXTwjD-sEgM67wWTiWbDJ3Q6WyaOL3W4ukYANDuAR05-SXVehnd3WR0FOg1hVcNRao5ekyWZw4Z2ekEB1JRof3Lh6uq46K0KXpe9Pc64UzAxEID93SoJ0EaV_Sei8CXw2aJFmZUuCf8YISWKUz6QZxRvFKUfYeflldUm9U2tY96RicWgUhuXgv","protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBRWtrc09abW1oZkZYdU90MHMybVdFYlVybVQ3OXc1SFRwUm9TLTZZNXpkYlk5T0I5b2RHb2hDYm1PeGpqY2VhWUU5ZnNaX3RaNmdpTGFBNUFEUnBrWE5VIiwieSI6IkFDaWJnLXZEMmFHVEpHbzlmRUl6Q1dXT2hSVUlObFg3Q1hGSTJqeDlKVDZmTzJfMGZ3SzM2WTctNHNUZTRpRVVSaHlnU1hQOW9TVFczTkdZTXVDMWlPQ3AifSwiYXB2IjoiR09lbzc2eW02TkNnOVdXTUVZZlcwZVZEVDU2Njh6RWhsMnVBSVctRS1IRSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMjU2S1cifQ","recipients":[{"encrypted_key":"W4KOy5W88iPPsDEdhkJN2krZ2QAeDxOIxW-4B21H9q89SHWexocCrw","header":{"kid":"did:example:bob#key-p521-1"}},{"encrypted_key":"uxKPkF6-sIiEkdeJcUPJY4lvsRg_bvtLPIn7eIycxLJML2KM6-Llag","header":{"kid":"did:example:bob#key-p521-2"}}],"tag":"aPZeYfwht2Nx9mfURv3j3g","iv":"lGKCvg2xrvi8Qa_D"}
        """;


    /// <summary>
    /// The Appendix C.3 example 2 (ECDH-ES P-384, A256CBC-HS512) vector decrypts for recipient
    /// <c>key-p384-1</c> and recovers the Appendix C.1 plaintext.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3P384VectorDecryptsForRecipient1()
    {
        using PrivateKeyMemory recipientPrivate = P384ExchangePrivateKey(BobP384D1);

        DidCommEncryptedUnpackResult result = await UnpackP384Async(P384Kid1, recipientPrivate).ConfigureAwait(false);

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The same Appendix C.3 example 2 vector decrypts for the second recipient <c>key-p384-2</c> and
    /// recovers the same Appendix C.1 plaintext — the CEK is wrapped once per recipient.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3P384VectorDecryptsForRecipient2()
    {
        using PrivateKeyMemory recipientPrivate = P384ExchangePrivateKey(BobP384D2);

        DidCommEncryptedUnpackResult result = await UnpackP384Async(P384Kid2, recipientPrivate).ConfigureAwait(false);

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The Appendix C.3 example 3 (ECDH-ES P-521, A256GCM) vector decrypts for recipient
    /// <c>key-p521-1</c> and recovers the Appendix C.1 plaintext.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3P521VectorDecryptsForRecipient1()
    {
        using PrivateKeyMemory recipientPrivate = P521ExchangePrivateKey(BobP521D1);

        DidCommEncryptedUnpackResult result = await UnpackP521Async(P521Kid1, recipientPrivate).ConfigureAwait(false);

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The same Appendix C.3 example 3 vector decrypts for the second recipient <c>key-p521-2</c> and
    /// recovers the same Appendix C.1 plaintext.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3P521VectorDecryptsForRecipient2()
    {
        using PrivateKeyMemory recipientPrivate = P521ExchangePrivateKey(BobP521D2);

        DidCommEncryptedUnpackResult result = await UnpackP521Async(P521Kid2, recipientPrivate).ConfigureAwait(false);

        AssertRecoveredC1Message(result);
    }


    /// <summary>
    /// The <c>apv</c> re-derived from the example 2 recipient kid list equals the <c>apv</c> embedded in the
    /// vector's protected header. apv = base64url-nopad(SHA-256(UTF8(sorted ordinal kids joined with "."))).
    /// Expected (from the vector): <c>LJA9Eoks5tamUFVBalMwBhJ6DkDcJ8HK4SlXZWqDqno</c>.
    /// </summary>
    [TestMethod]
    public void AppendixC3P384ApvReDerivationMatchesVector()
    {
        string[] kids = [P384Kid1, P384Kid2];
        string apv = JweAgreementInfo.ComputeApvFromRecipientKeyIds(kids, TestSetup.Base64UrlEncoder, Pool);

        Assert.AreEqual(P384ExpectedApv, apv, "The re-derived apv MUST equal the vector's embedded apv.");
        Assert.AreEqual(ExtractProtectedHeaderApv(P384VectorJson), apv, "The re-derived apv MUST equal the protected header's 'apv'.");
    }


    /// <summary>
    /// The <c>apv</c> re-derived from the example 3 recipient kid list equals the <c>apv</c> embedded in the
    /// vector's protected header. Expected (from the vector): <c>GOeo76ym6NCg9WWMEYfW0eVDT5668zEhl2uAIW-E-HE</c>.
    /// </summary>
    [TestMethod]
    public void AppendixC3P521ApvReDerivationMatchesVector()
    {
        string[] kids = [P521Kid1, P521Kid2];
        string apv = JweAgreementInfo.ComputeApvFromRecipientKeyIds(kids, TestSetup.Base64UrlEncoder, Pool);

        Assert.AreEqual(P521ExpectedApv, apv, "The re-derived apv MUST equal the vector's embedded apv.");
        Assert.AreEqual(ExtractProtectedHeaderApv(P521VectorJson), apv, "The re-derived apv MUST equal the protected header's 'apv'.");
    }


    /// <summary>
    /// Unpacking the P-384 / A256CBC-HS512 vector through the REGISTRY-resolving overload recovers the
    /// Appendix C.1 plaintext: the overload peeks the wire <c>enc</c> (<c>A256CBC-HS512</c>) and resolves the
    /// AES_CBC_HMAC_SHA2 content delegate from it — the same enc-aware resolution the authcrypt registry
    /// overload uses — so anoncrypt's "any content algorithm MAY be used" holds across the registry path, not
    /// only the delegate-taking one.
    /// </summary>
    [TestMethod]
    public async Task RegistryUnpackOfCbcVectorResolvesByEnc()
    {
        using PrivateKeyMemory recipientPrivate = P384ExchangePrivateKey(BobP384D1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(P384VectorJson);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAnoncryptAsync(
            P384Kid1,
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


    //Unpacks the P-384 / A256CBC-HS512 vector for the given recipient using the delegate-taking overload.
    private async Task<DidCommEncryptedUnpackResult> UnpackP384Async(string recipientKid, PrivateKeyMemory recipientPrivate)
    {
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(P384VectorJson);

        return await encrypted.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP384Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Unpacks the P-521 / A256GCM vector for the given recipient using the delegate-taking overload.
    private async Task<DidCommEncryptedUnpackResult> UnpackP521Async(string recipientKid, PrivateKeyMemory recipientPrivate)
    {
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(P521VectorJson);

        return await encrypted.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            NestedSignerResolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP521Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Asserts a successful anoncrypt unpack recovering the Appendix C.1 plaintext.
    private static void AssertRecoveredC1Message(DidCommEncryptedUnpackResult result)
    {
        Assert.IsTrue(result.IsUnpacked, $"The vector MUST unpack to the C.1 plaintext. Error: {result.Error}.");
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


    //Imports a P-384 ECDH exchange private key from its JWK "d" base64url scalar. The decoder returns an
    //exact-size owner; ownership transfers to the PrivateKeyMemory, which the caller disposes.
    private static PrivateKeyMemory P384ExchangePrivateKey(string dBase64Url)
    {
        IMemoryOwner<byte> d = TestSetup.Base64UrlDecoder(dBase64Url, Pool);

        return new PrivateKeyMemory(d, CryptoTags.P384ExchangePrivateKey);
    }


    //Imports a P-521 ECDH exchange private key from its JWK "d" base64url scalar.
    private static PrivateKeyMemory P521ExchangePrivateKey(string dBase64Url)
    {
        IMemoryOwner<byte> d = TestSetup.Base64UrlDecoder(dBase64Url, Pool);

        return new PrivateKeyMemory(d, CryptoTags.P521ExchangePrivateKey);
    }
}
