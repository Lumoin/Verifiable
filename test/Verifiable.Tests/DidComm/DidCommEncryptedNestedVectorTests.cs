using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
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
/// Anchors the DIDComm v2.1 nested <c>authcrypt(sign(plaintext))</c> UNPACK path
/// (<see cref="DidCommEncryptedExtensions.UnpackAuthcryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, AuthenticatedKeyAgreementDecryptDelegate, AuthenticatedKeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, System.Threading.CancellationToken)"/>)
/// to the DIDComm Messaging v2.1 Appendix C.3 example 5 vector: the Appendix C.1 plaintext signed with
/// EdDSA (Alice's <c>key-1</c>) and then authcrypted with ECDH-1PU over NIST P-256 and A256CBC-HS512,
/// sent from <c>did:example:alice#key-p256-1</c> (the <c>skid</c>) to two of Bob's P-256
/// <c>keyAgreement</c> keys.
/// </summary>
/// <remarks>
/// The spec prose for this example mislabels the curve as P-521, but the vector's own protected header,
/// <c>skid</c>, and recipient kids are all P-256 (an erratum, like the <c>http</c>/<c>https</c> scheme
/// slip in the other C.3 vectors); the assertions track the vector's real bytes. Each recipient decrypts
/// with Bob's Appendix A.2 static P-256 private key. After decryption the recovered content is a signed
/// JWM, so the unpack recurses into the signed-message path: it resolves Alice's DID document, verifies
/// the inner EdDSA signature against her <c>authentication</c> key <c>key-1</c>, requires the inner
/// <c>to</c> header, and enforces that the inner signer shares the authcrypt sender's DID (DIDComm v2.1
/// §Message Types). The single stub <see cref="DidResolver"/> serves a document carrying both Alice's
/// P-256 <c>keyAgreement</c> key (the authcrypt sender) and her Ed25519 <c>authentication</c> key (the
/// inner signer).
/// </remarks>
[TestClass]
internal sealed class DidCommEncryptedNestedVectorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    private const string ExampleDidPrefix = "did:example";
    private const string AliceDid = "did:example:alice";

    //Appendix C.1 plaintext (the message the C.3 example 5 vector signs then encrypts). The C.3/C.2 vector
    //bytes use the "http" scheme even though the C.1 prose shows "https" — the recovered plaintext is
    //byte-exact, so the assertion tracks the vector's real content (a spec erratum).
    private const string ExpectedId = "1234567890";
    private const string ExpectedType = "http://example.com/protocols/lets_do_lunch/1.0/proposal";
    private const string ExpectedFrom = "did:example:alice";
    private const string ExpectedTo = "did:example:bob";
    private const long ExpectedCreatedTime = 1516269022;
    private const long ExpectedExpiresTime = 1516385931;

    //The authcrypt sender key id carried as `skid` (a P-256 keyAgreement key) and the inner EdDSA signer
    //key id (an Ed25519 authentication key); both resolve to did:example:alice, so the inner signer shares
    //the authcrypt sender's DID (DIDComm v2.1 §Message Types).
    private const string AliceSkid = "did:example:alice#key-p256-1";
    private const string AliceSignerKid = "did:example:alice#key-1";

    //Alice's Appendix A P-256 keyAgreement public coordinates (key-p256-1) — the resolved authcrypt sender key.
    private const string AliceP256PublicX = "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE";
    private const string AliceP256PublicY = "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo";

    //Alice's Appendix A.1 Ed25519 authentication public coordinate (key-1) — the inner signer's key.
    private const string AliceEd25519PublicX = "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww";

    //Bob's Appendix A.2 P-256 static keyAgreement private scalars ("d" coordinate, base64url).
    private const string BobKid1 = "did:example:bob#key-p256-1";
    private const string BobKid2 = "did:example:bob#key-p256-2";
    private const string BobD1 = "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ";
    private const string BobD2 = "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU";

    //Appendix C.3 example 5: authcrypt(sign) — EdDSA inner signature, then ECDH-1PU P-256 + A256CBC-HS512.
    private const string VectorJson =
        /*lang=json,strict*/ """
        {"ciphertext":"WCufCs2lMZfkxQ0JCK92lPtLFgwWk_FtRWOMj52bQISa94nEbIYqHDUohIbvLMgbSjRcJVusZO04UthDuOpSSTcV5GBi3O0cMrjyI_PZnTb1yikLXpXma1bT10D2r5TPtzRMxXF3nFsr9y0JKV1TsMtn70Df2fERx2bAGxcflmd-A2sMlSTT8b7QqPtn17Yb-pA8gr4i0Bqb2WfDzwnbfewbukpRmPA2hsEs9oLKypbniAafSpoiQjfb19oDfsYaWWXqsdjTYMflqH__DqSmW52M-SUp6or0xU0ujbHmOkRkcdh9PsR5YsPuIWAqYa2hfjz_KIrGTxvCos0DMiZ4Lh_lPIYQqBufSdFH5AGChoekFbQ1vcyIyYMFugzOHOgZ2TwEzv94GCgokBHQR4_qaU_f4Mva64KPwqOYdm5f4KX16afTJa-IV7ar7__2L-A-LyxmC5KIHeGOedV9kzZBLC7TuzRAuE3vY7pkhLB1jPE6XpTeKXldljaeOSEVcbFUQtsHOSPz9JXuhqZ1fdAx8qV7hUnSAd_YMMDR3S6SXtem8ak2m98WPvKIxhCbcto7W2qoNYMT7MPvvid-QzUvTdKtyovCvLzhyYJzMjZxmn9-EnGhZ5ITPL_xFfLyKxhSSUVz3kSwK9xuOj3KpJnrrD7xrp5FKzEaJVIHWrUW90V_9QVLjriThZ36fA3ipvs8ZJ8QSTnGAmuIQ6Z2u_r4KsjL_mGAgn47qyqRm-OSLEUE4_2qB0Q9Z7EBKakCH8VPt09hTMDR62aYZYwtmpNs9ISu0VPvFjh8UmKbFcQsVrz90-x-r-Q1fTX9JaIFcDy7aqKcI-ai3tVF_HDR60Jaiw","protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJObHJ3UHZ0SUluZWNpeUVrYTRzMi00czhPalRidEZFQVhmTC12Z2x5enFvIiwieSI6ImhiMnZkWE5zSzVCQ2U3LVhaQ0dfLTY0R21UT19rNUlNWFBaQ00xdGFUQmcifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFsZyI6IkVDREgtMVBVK0EyNTZLVyJ9","recipients":[{"encrypted_key":"ZIL6Leligq1Xps_229nlo1xB_tGxOEVoEEMF-XTOltI0QXjyUoq_pFQBCAnVdcWNH5bmaiuzCYOmZ9lkyXBkfHO90KkGgODG","header":{"kid":"did:example:bob#key-p256-1"}},{"encrypted_key":"sOjs0A0typIRSshhQoiJPoM4o7YpR5LA8SSieHZzmMyIDdD8ww-4JyyQhqFYuvfS4Yt37VF4z7Nd0OjYVNRL-iqPnoJ3iCOr","header":{"kid":"did:example:bob#key-p256-2"}}],"tag":"nIpa3EQ29hgCkA2cBPde2HpKXK4_bvmL2x7h39rtVEc","iv":"mLqi1bZLz7VwqtVVFsDiLg"}
        """;


    /// <summary>
    /// The Appendix C.3 example 5 vector decrypts for each of Bob's two P-256 <c>keyAgreement</c> recipients
    /// via the delegate-taking overload, verifies the inner EdDSA signature against Alice's
    /// <c>authentication</c> key, and surfaces the verified inner signer — the nested
    /// <c>authcrypt(sign(plaintext))</c> combination.
    /// </summary>
    [TestMethod]
    [DataRow(BobKid1, BobD1)]
    [DataRow(BobKid2, BobD2)]
    public async Task AppendixC3Example5DecryptsForRecipient(string recipientKid, string recipientD)
    {
        using PrivateKeyMemory recipientPrivate = P256ExchangePrivateKey(recipientD);
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
            MicrosoftKeyAgreementFunctions.Ecdh1PuKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AssertRecoveredNestedC1Message(result);
    }


    /// <summary>
    /// The same Appendix C.3 example 5 vector decrypts through the REGISTRY-resolving overload, which selects
    /// the AES_CBC_HMAC_SHA2 content delegate from the wire <c>enc</c> qualifier and the authenticated
    /// agreement / derivation / unwrap from the recipient key's P-256 curve, and recurses into the same
    /// inner-signature verification.
    /// </summary>
    [TestMethod]
    public async Task AppendixC3Example5DecryptsViaRegistryOverload()
    {
        using PrivateKeyMemory recipientPrivate = P256ExchangePrivateKey(BobD1);
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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AssertRecoveredNestedC1Message(result);
    }


    /// <summary>
    /// When the inner signer's <c>authentication</c> key is absent from the resolved DID document, the inner
    /// signature cannot be verified and the nested message fails CLOSED with
    /// <see cref="DidCommDecryptionError.NestedSignatureInvalid"/> — even though the outer authcrypt layer
    /// decrypted successfully.
    /// </summary>
    [TestMethod]
    public async Task InnerSignerNotAuthenticatedFailsClosed()
    {
        using PrivateKeyMemory recipientPrivate = P256ExchangePrivateKey(BobD1);
        using DidCommEncryptedMessage encrypted = CreateEncryptedMessage(VectorJson);

        //Alice's document keeps her keyAgreement key (the authcrypt layer decrypts) but does NOT authorize
        //the Ed25519 signer key for authentication, so the inner signature verification fails closed.
        DidResolver resolver = CreateResolver(CreateAliceDidDocument(authorizeSignerAuthentication: false));

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            BobKid1,
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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnpacked, "A nested message whose inner signer is not authenticated MUST NOT unpack.");
        Assert.AreEqual(DidCommDecryptionError.NestedSignatureInvalid, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: an unverifiable inner signature yields no plaintext.");
    }


    //Asserts a successful nested authcrypt(sign) unpack recovering the Appendix C.1 plaintext with the inner
    //EdDSA signature verified and the inner signer surfaced.
    private static void AssertRecoveredNestedC1Message(DidCommEncryptedUnpackResult result)
    {
        Assert.IsTrue(result.IsUnpacked, $"The C.3 example 5 vector MUST unpack to the C.1 plaintext. Error: {result.Error}.");
        Assert.AreEqual(DidCommDecryptionError.None, result.Error);
        Assert.AreEqual(DidCommEncryptionMode.Authcrypt, result.Mode);
        Assert.IsTrue(result.IsSignedInner, "The C.3 example 5 vector is a nested signed (authcrypt(sign)) message.");
        Assert.IsTrue(result.IsSenderAuthenticated, "A verified inner signature authenticates the sender.");
        Assert.AreEqual(AliceSignerKid, result.SenderKeyId, "The authenticated sender key id MUST be the verified inner signer kid.");
        Assert.IsTrue(result.Verified.HasValue, "The verified inner signature MUST surface a Verified<T> authenticity proof.");
        Assert.AreSame(result.Message, result.Verified.GetValueOrDefault().Value, "The Verified proof MUST wrap the recovered message.");
        Assert.IsTrue(result.IsRecipientAddressedInTo, "The C.3 example 5 recipient (did:example:bob) is listed in the inner 'to' and MUST be flagged as addressed.");

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


    //Imports a P-256 ECDH exchange private key from its JWK "d" base64url scalar. The decoder returns an
    //exact-size owner; ownership transfers to the PrivateKeyMemory, which the caller disposes.
    private static PrivateKeyMemory P256ExchangePrivateKey(string dBase64Url)
    {
        IMemoryOwner<byte> d = TestSetup.Base64UrlDecoder(dBase64Url, Pool);

        return new PrivateKeyMemory(d, CryptoTags.P256ExchangePrivateKey);
    }


    //A resolver that returns the given document for any did:example identifier.
    private static DidResolver CreateResolver(DidDocument document)
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    //Alice's DID document carrying both her P-256 keyAgreement key (the authcrypt sender, key-p256-1) and
    //her Ed25519 authentication key (the inner EdDSA signer, key-1). When authorizeSignerAuthentication is
    //false the signer key remains in verificationMethod but is not listed under authentication, so the
    //inner signature verification fails closed.
    private static DidDocument CreateAliceDidDocument(bool authorizeSignerAuthentication = true)
    {
        var document = new DidDocument
        {
            Id = new GenericDidMethod(AliceDid),
            VerificationMethod =
            [
                Ed25519VerificationMethod(AliceSignerKid, AliceEd25519PublicX),
                P256VerificationMethod(AliceSkid, AliceP256PublicX, AliceP256PublicY)
            ],
            KeyAgreement = [new KeyAgreementMethod(AliceSkid)]
        };

        if(authorizeSignerAuthentication)
        {
            document.Authentication = [new AuthenticationMethod(AliceSignerKid)];
        }

        return document;
    }


    //An Ed25519 authentication verification method (OKP), used to verify the inner EdDSA signature.
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


    //A P-256 keyAgreement verification method (EC), used to resolve the authcrypt sender's public key.
    private static VerificationMethod P256VerificationMethod(string id, string publicKeyX, string publicKeyY)
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
                    [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Ec,
                    [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.P256,
                    [WellKnownJwkMemberNames.X] = publicKeyX,
                    [WellKnownJwkMemberNames.Y] = publicKeyY
                }
            }
        };
    }
}
