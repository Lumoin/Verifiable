using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Verifies the DIDComm signed-message pack/unpack pipeline (<see cref="DidCommSignedExtensions"/>):
/// the DIDComm v2.1 Appendix C.2 signed vectors (EdDSA / ES256 / ES256K), pack→unpack round trips,
/// and the fail-closed adversarial rejections (addressing-consistency, authentication relationship,
/// signer resolution, tampering, and malformed input).
/// </summary>
[TestClass]
internal sealed class DidCommSignedMessageTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //A non-network resolution context; it only satisfies the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext Context = new();

    private const string ExampleDidPrefix = "did:example";

    //DIDComm v2.1 Appendix C.1 plaintext payload, Base64Url-encoded — shared by all three C.2 vectors.
    private const string PayloadBase64Url =
        "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19";

    //C.2 EdDSA (Ed25519) vector.
    private const string EdDsaProtectedBase64Url = "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ";
    private const string EdDsaSignatureBase64Url = "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ";
    private const string EdDsaKid = "did:example:alice#key-1";

    //C.2 ES256 (P-256) vector.
    private const string Es256ProtectedBase64Url = "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ";
    private const string Es256SignatureBase64Url = "gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg";
    private const string Es256Kid = "did:example:alice#key-2";

    //C.2 ES256K (secp256k1) vector.
    private const string Es256kProtectedBase64Url = "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0";
    private const string Es256kSignatureBase64Url = "EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw";
    private const string Es256kKid = "did:example:alice#key-3";

    //Appendix A.1 sender secrets / public coordinates for Alice's three signing keys.
    private const string AliceKey1PrivateD = "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY";
    private const string AliceKey1PublicX = "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww";
    private const string AliceKey2PublicX = "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY";
    private const string AliceKey2PublicY = "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w";
    private const string AliceKey3PublicX = "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk";
    private const string AliceKey3PublicY = "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk";


    /// <summary>
    /// The three DIDComm v2.1 Appendix C.2 signed vectors (EdDSA / ES256 / ES256K) verify against
    /// Alice's resolved DID document, surfacing the verified plaintext and signer.
    /// </summary>
    [TestMethod]
    [DataRow(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid)]
    [DataRow(Es256ProtectedBase64Url, Es256SignatureBase64Url, Es256Kid)]
    [DataRow(Es256kProtectedBase64Url, Es256kSignatureBase64Url, Es256kKid)]
    public async Task AppendixC2VectorVerifies(string protectedBase64Url, string signatureBase64Url, string expectedKid)
    {
        using DidCommSignedMessage signed = GeneralJsonSigned(protectedBase64Url, signatureBase64Url, expectedKid);
        DidResolver resolver = CreateResolver(CreateAliceDidDocument());

        DidCommSignedVerificationResult result = await UnpackAsync(signed, resolver).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"Appendix C.2 vector for '{expectedKid}' MUST verify. Error: {result.Error}.");
        Assert.AreEqual(expectedKid, result.SignerKid);
        Assert.IsTrue(result.Verified.HasValue, "A verified signed message MUST carry a Verified<T> authenticity proof.");
        Assert.AreSame(result.Message, result.Verified.GetValueOrDefault().Value, "The Verified proof MUST wrap the verified message.");
        Assert.IsNotNull(result.Message);
        Assert.AreEqual("1234567890", result.Message!.Id);
        Assert.AreEqual("did:example:alice", result.Message.From);
        Assert.IsTrue(result.IsToHeaderPresent);
    }


    /// <summary>An EdDSA pack→unpack round trip in General JSON form verifies.</summary>
    [TestMethod]
    public async Task RoundTripGeneralJsonVerifies()
    {
        await AssertRoundTripVerifiesAsync(JoseSerializationFormat.GeneralJson).ConfigureAwait(false);
    }


    /// <summary>An EdDSA pack→unpack round trip in Flattened JSON form verifies (recipients MUST handle both forms).</summary>
    [TestMethod]
    public async Task RoundTripFlattenedJsonVerifies()
    {
        await AssertRoundTripVerifiesAsync(JoseSerializationFormat.FlattenedJson).ConfigureAwait(false);
    }


    /// <summary>
    /// A plaintext <c>from</c> that does not match the signer kid's DID is rejected (addressing-consistency
    /// MUST). The adversarial envelope is hand-built — a real attacker does not use the producer — so the
    /// verifier's check is proven independently of pack-side enforcement.
    /// </summary>
    [TestMethod]
    public async Task FromKidMismatchRejected()
    {
        //Bob's plaintext, but the signature header claims Alice's kid. The binding check fires before
        //any cryptographic verification, so the signature value is irrelevant here.
        string bobPayload = RawPayloadBase64Url(
            """{"id":"1234567890","type":"https://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:bob","to":["did:example:carol"]}""");
        using DidCommSignedMessage signed = GeneralJsonSigned(bobPayload, EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.FromKidMismatch, result.Error);

        //Fail-closed: a rejected message yields neither a payload nor a signer.
        Assert.IsNull(result.Message);
        Assert.IsNull(result.SignerKid);
    }


    /// <summary>The producer also refuses to emit a signed message whose <c>from</c> disagrees with the signer kid's DID.</summary>
    [TestMethod]
    public async Task PackRejectsFromKidMismatch()
    {
        var message = new DidCommMessage
        {
            Id = "1234567890",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = "did:example:bob"
        };

        using PrivateKeyMemory signingKey = AliceKey1Private();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await PackAsync(message, signingKey, EdDsaKid, JoseSerializationFormat.GeneralJson).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>A kid that is not authorized for the <c>authentication</c> relationship is rejected regardless of cryptographic validity.</summary>
    [TestMethod]
    public async Task KidNotAuthenticatedRejected()
    {
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        //key-1 is present as a verification method but is NOT in the authentication relationship.
        DidResolver resolver = CreateResolver(CreateAliceDidDocument(authenticateKey1: false));

        DidCommSignedVerificationResult result = await UnpackAsync(signed, resolver).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.KidNotAuthenticated, result.Error);

        //Fail-closed: a rejected message yields neither a payload nor a signer.
        Assert.IsNull(result.Message);
        Assert.IsNull(result.SignerKid);
    }


    /// <summary>A signer DID that cannot be resolved is rejected (fail closed).</summary>
    [TestMethod]
    public async Task SignerResolutionFailedRejected()
    {
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateFailingResolver()).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.SignerResolutionFailed, result.Error);
    }


    /// <summary>A tampered signature is rejected by the cryptographic check.</summary>
    [TestMethod]
    public async Task TamperedSignatureRejected()
    {
        //Flip the leading character of the Base64Url signature (still valid Base64Url, wrong bytes).
        string tamperedSignature = (EdDsaSignatureBase64Url[0] == 'F' ? 'G' : 'F') + EdDsaSignatureBase64Url[1..];
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, tamperedSignature, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.SignatureInvalid, result.Error);
    }


    /// <summary>A signature lacking a <c>kid</c> in its unprotected header is rejected — the signing key cannot be located.</summary>
    [TestMethod]
    public async Task MissingKidRejected()
    {
        string json = $$"""
            {"payload":"{{PayloadBase64Url}}","signatures":[{"protected":"{{EdDsaProtectedBase64Url}}","signature":"{{EdDsaSignatureBase64Url}}"}]}
            """;
        using DidCommSignedMessage signed = DidCommSignedMessage.Create(Encoding.UTF8.GetBytes(json), BufferTags.Json, Pool);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.MissingKid, result.Error);
    }


    /// <summary>A protected <c>typ</c> that is not <c>application/didcomm-signed+json</c> is rejected.</summary>
    [TestMethod]
    public async Task UnexpectedMediaTypeRejected()
    {
        //A protected header claiming the plaintext media type instead of the signed one.
        string plainProtected = TestSetup.Base64UrlEncoder(
            Encoding.UTF8.GetBytes("""{"typ":"application/didcomm-plain+json","alg":"EdDSA"}"""));
        using DidCommSignedMessage signed = GeneralJsonSigned(plainProtected, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.UnexpectedMediaType, result.Error);
    }


    /// <summary>Input that is not a JWS JSON serialization is rejected as a malformed envelope.</summary>
    [TestMethod]
    public async Task MalformedEnvelopeRejected()
    {
        using DidCommSignedMessage signed = DidCommSignedMessage.Create(
            Encoding.UTF8.GetBytes("this is not a JWS"), BufferTags.Json, Pool);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.MalformedEnvelope, result.Error);
    }


    private async Task AssertRoundTripVerifiesAsync(JoseSerializationFormat format)
    {
        var message = new DidCommMessage
        {
            Id = "1234567890",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = "did:example:alice",
            To = ["did:example:bob"],
            Body = new Dictionary<string, object> { ["messagespecificattribute"] = "and its value" }
        };

        using PrivateKeyMemory signingKey = AliceKey1Private();
        using DidCommSignedMessage signed = await PackAsync(message, signingKey, EdDsaKid, format).ConfigureAwait(false);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"Round trip ({format}) MUST verify. Error: {result.Error}.");
        Assert.AreEqual(EdDsaKid, result.SignerKid);
        Assert.IsNotNull(result.Message);
        Assert.AreEqual("1234567890", result.Message!.Id);
        Assert.AreEqual("did:example:alice", result.Message.From);
    }


    private ValueTask<DidCommSignedMessage> PackAsync(DidCommMessage message, PrivateKeyMemory signingKey, string keyId, JoseSerializationFormat format)
    {
        return message.PackSignedAsync(
            signingKey,
            keyId,
            DidCommMessageJson.Serializer,
            DidCommSignedMessageJson.ProtectedHeaderEncoder,
            DidCommSignedMessageJson.Serializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            format,
            TestContext.CancellationToken);
    }


    private ValueTask<DidCommSignedVerificationResult> UnpackAsync(DidCommSignedMessage signed, DidResolver resolver)
    {
        return signed.UnpackSignedAsync(
            resolver,
            Context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken);
    }


    //Assembles a General JSON signed message over the shared Appendix C.1 payload into a pooled artifact.
    private static DidCommSignedMessage GeneralJsonSigned(string protectedBase64Url, string signatureBase64Url, string kid) =>
        GeneralJsonSigned(PayloadBase64Url, protectedBase64Url, signatureBase64Url, kid);


    //Assembles a General JSON signed message from explicit Base64Url parts into a pooled artifact.
    private static DidCommSignedMessage GeneralJsonSigned(string payloadBase64Url, string protectedBase64Url, string signatureBase64Url, string kid)
    {
        string json = $$$"""
            {"payload":"{{{payloadBase64Url}}}","signatures":[{"protected":"{{{protectedBase64Url}}}","signature":"{{{signatureBase64Url}}}","header":{"kid":"{{{kid}}}"}}]}
            """;

        return DidCommSignedMessage.Create(Encoding.UTF8.GetBytes(json), BufferTags.Json, Pool);
    }


    //Assembles a Flattened JSON signed message from explicit Base64Url parts into a pooled artifact.
    private static DidCommSignedMessage FlattenedJsonSigned(string payloadBase64Url, string protectedBase64Url, string signatureBase64Url, string kid)
    {
        string json = $$$"""
            {"payload":"{{{payloadBase64Url}}}","protected":"{{{protectedBase64Url}}}","signature":"{{{signatureBase64Url}}}","header":{"kid":"{{{kid}}}"}}
            """;

        return DidCommSignedMessage.Create(Encoding.UTF8.GetBytes(json), BufferTags.Json, Pool);
    }


    //Base64Url-encodes a raw plaintext JWM JSON string (used to craft adversarial payloads the
    //validated PackPlaintext path would otherwise reject or normalize).
    private static string RawPayloadBase64Url(string plaintextJson) =>
        TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(plaintextJson));


    private static PrivateKeyMemory AliceKey1Private()
    {
        //The decoder returns an exact-size owner; ownership transfers to the PrivateKeyMemory.
        IMemoryOwner<byte> seed = TestSetup.Base64UrlDecoder(AliceKey1PrivateD, Pool);

        return new PrivateKeyMemory(seed, CryptoTags.Ed25519PrivateKey);
    }


    private static DidResolver CreateResolver(DidDocument document)
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    private static DidResolver CreateFailingResolver()
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));
    }


    private static DidDocument CreateAliceDidDocument(bool authenticateKey1 = true)
    {
        var authentication = new List<AuthenticationMethod>
        {
            new(Es256Kid),
            new(Es256kKid)
        };

        if(authenticateKey1)
        {
            authentication.Insert(0, new AuthenticationMethod(EdDsaKid));
        }

        return new DidDocument
        {
            Id = new GenericDidMethod("did:example:alice"),
            VerificationMethod =
            [
                VerificationMethodFor(EdDsaKid, "OKP", "Ed25519", "EdDSA", AliceKey1PublicX, publicKeyY: null),
                VerificationMethodFor(Es256Kid, "EC", "P-256", "ES256", AliceKey2PublicX, AliceKey2PublicY),
                VerificationMethodFor(Es256kKid, "EC", "secp256k1", "ES256K", AliceKey3PublicX, AliceKey3PublicY)
            ],
            Authentication = [.. authentication]
        };
    }


    private static VerificationMethod VerificationMethodFor(string id, string keyType, string curve, string algorithm, string publicKeyX, string? publicKeyY)
    {
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = keyType,
            ["crv"] = curve,
            ["alg"] = algorithm,
            ["x"] = publicKeyX
        };

        if(publicKeyY is not null)
        {
            jwk["y"] = publicKeyY;
        }

        return new VerificationMethod
        {
            Id = id,
            Type = "JsonWebKey2020",
            Controller = "did:example:alice",
            KeyFormat = new PublicKeyJwk { Header = jwk }
        };
    }


    /// <summary>
    /// A genuine EdDSA C.2 signature whose protected header is rewritten to claim <c>ES256</c> is
    /// rejected — the protected header is integrity-protected and the verifier resolves the algorithm
    /// from the key, never from the attacker-controlled <c>alg</c> (algorithm-substitution defense).
    /// </summary>
    [TestMethod]
    public async Task ForgedProtectedAlgorithmRejected()
    {
        string forgedProtected = TestSetup.Base64UrlEncoder(
            Encoding.UTF8.GetBytes("""{"typ":"application/didcomm-signed+json","alg":"ES256"}"""));
        using DidCommSignedMessage signed = GeneralJsonSigned(forgedProtected, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.SignatureInvalid, result.Error);
    }


    /// <summary>The EdDSA C.2 vector verifies when its key is an EMBEDDED authentication method (the Appendix A.1 shape).</summary>
    [TestMethod]
    public async Task EmbeddedAuthenticationMethodVerifies()
    {
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocumentEmbeddedKey1())).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"An embedded authentication method MUST verify. Error: {result.Error}.");
        Assert.AreEqual(EdDsaKid, result.SignerKid);
    }


    /// <summary>The EdDSA C.2 vector verifies when the DID document uses relative <c>#key-1</c> ids (normalized against the document DID).</summary>
    [TestMethod]
    public async Task RelativeVerificationMethodIdVerifies()
    {
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocumentRelativeIds())).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"A relative '#key-1' id MUST normalize and verify. Error: {result.Error}.");
        Assert.AreEqual(EdDsaKid, result.SignerKid);
    }


    /// <summary>An envelope carrying more than one signature is outside the single-sender profile and is rejected.</summary>
    [TestMethod]
    public async Task MultipleSignaturesRejected()
    {
        string json = $$$"""
            {"payload":"{{{PayloadBase64Url}}}","signatures":[{"protected":"{{{EdDsaProtectedBase64Url}}}","signature":"{{{EdDsaSignatureBase64Url}}}","header":{"kid":"{{{EdDsaKid}}}"}},{"protected":"{{{Es256ProtectedBase64Url}}}","signature":"{{{Es256SignatureBase64Url}}}","header":{"kid":"{{{Es256Kid}}}"}}]}
            """;
        using DidCommSignedMessage signed = DidCommSignedMessage.Create(Encoding.UTF8.GetBytes(json), BufferTags.Json, Pool);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.MultipleSignatures, result.Error);
    }


    /// <summary>A signed-over payload that is not a structurally valid plaintext message is rejected.</summary>
    [TestMethod]
    public async Task InvalidPlaintextRejected()
    {
        //Missing the required `id` header — UnpackPlaintext rejects it before any signature check.
        string invalidPlaintext = RawPayloadBase64Url(
            """{"type":"https://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice"}""");
        using DidCommSignedMessage signed = GeneralJsonSigned(invalidPlaintext, EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.InvalidPlaintext, result.Error);
    }


    /// <summary>A signed-over plaintext that carries no <c>from</c> is rejected — the signer cannot be bound.</summary>
    [TestMethod]
    public async Task MissingFromRejected()
    {
        string noFrom = RawPayloadBase64Url(
            """{"id":"1234567890","type":"https://example.com/protocols/lets_do_lunch/1.0/proposal","to":["did:example:bob"]}""");
        using DidCommSignedMessage signed = GeneralJsonSigned(noFrom, EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.MissingFrom, result.Error);
    }


    /// <summary>A well-formed compact JWS is rejected — a DIDComm signed message MUST use the JSON serialization.</summary>
    [TestMethod]
    public async Task CompactSerializationRejected()
    {
        string compact = $"{EdDsaProtectedBase64Url}.{PayloadBase64Url}.{EdDsaSignatureBase64Url}";
        using DidCommSignedMessage signed = DidCommSignedMessage.Create(Encoding.UTF8.GetBytes(compact), BufferTags.Json, Pool);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.MalformedEnvelope, result.Error);
    }


    /// <summary>The producer refuses to emit a compact-serialized signed message.</summary>
    [TestMethod]
    public async Task PackRejectsCompactFormat()
    {
        var message = new DidCommMessage
        {
            Id = "1234567890",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = "did:example:alice",
            To = ["did:example:bob"]
        };

        using PrivateKeyMemory signingKey = AliceKey1Private();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await PackAsync(message, signingKey, EdDsaKid, JoseSerializationFormat.Compact).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>A different (still structurally valid) payload paired with a C.2 signature is rejected — the payload is part of the signed input.</summary>
    [TestMethod]
    public async Task TamperedPayloadRejected()
    {
        string otherPayload = RawPayloadBase64Url(
            """{"id":"1234567890","typ":"application/didcomm-plain+json","type":"https://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice","to":["did:example:bob"],"body":{"messagespecificattribute":"tampered"}}""");
        using DidCommSignedMessage signed = GeneralJsonSigned(otherPayload, EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified);
        Assert.AreEqual(DidCommSignatureVerificationError.SignatureInvalid, result.Error);
    }


    /// <summary>A verified signed message without a <c>to</c> header surfaces <c>IsToHeaderPresent=false</c> (the surreptitious-forwarding SHOULD signal) without failing.</summary>
    [TestMethod]
    public async Task RoundTripWithoutToHeaderSignalsAbsent()
    {
        var message = new DidCommMessage
        {
            Id = "1234567890",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = "did:example:alice"
        };

        using PrivateKeyMemory signingKey = AliceKey1Private();
        using DidCommSignedMessage signed = await PackAsync(message, signingKey, EdDsaKid, JoseSerializationFormat.GeneralJson).ConfigureAwait(false);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"Error: {result.Error}.");
        Assert.IsFalse(result.IsToHeaderPresent);
    }


    /// <summary>The EdDSA Appendix C.2 vector reshaped into Flattened JSON form verifies (anchors the Flattened parser to spec bytes).</summary>
    [TestMethod]
    public async Task AppendixC2EdDsaFlattenedVerifies()
    {
        using DidCommSignedMessage signed = FlattenedJsonSigned(PayloadBase64Url, EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocument())).ConfigureAwait(false);

        Assert.IsTrue(result.IsVerified, $"The Flattened C.2 vector MUST verify. Error: {result.Error}.");
        Assert.AreEqual(EdDsaKid, result.SignerKid);
    }


    //Alice's document with key-1 carried as an EMBEDDED authentication method (the Appendix A.1 shape),
    //present only inside the authentication relationship and not in the top-level verificationMethod array.
    private static DidDocument CreateAliceDidDocumentEmbeddedKey1()
    {
        VerificationMethod key1 = VerificationMethodFor(EdDsaKid, "OKP", "Ed25519", "EdDSA", AliceKey1PublicX, publicKeyY: null);

        return new DidDocument
        {
            Id = new GenericDidMethod("did:example:alice"),
            VerificationMethod =
            [
                VerificationMethodFor(Es256Kid, "EC", "P-256", "ES256", AliceKey2PublicX, AliceKey2PublicY),
                VerificationMethodFor(Es256kKid, "EC", "secp256k1", "ES256K", AliceKey3PublicX, AliceKey3PublicY)
            ],
            Authentication =
            [
                new AuthenticationMethod(key1),
                new AuthenticationMethod(Es256Kid),
                new AuthenticationMethod(Es256kKid)
            ]
        };
    }


    //Alice's document whose verification-method and authentication ids are relative ('#key-1'),
    //resolved against the document's own DID.
    private static DidDocument CreateAliceDidDocumentRelativeIds()
    {
        return new DidDocument
        {
            Id = new GenericDidMethod("did:example:alice"),
            VerificationMethod =
            [
                VerificationMethodFor("#key-1", "OKP", "Ed25519", "EdDSA", AliceKey1PublicX, publicKeyY: null),
                VerificationMethodFor("#key-2", "EC", "P-256", "ES256", AliceKey2PublicX, AliceKey2PublicY),
                VerificationMethodFor("#key-3", "EC", "secp256k1", "ES256K", AliceKey3PublicX, AliceKey3PublicY)
            ],
            Authentication =
            [
                new AuthenticationMethod("#key-1"),
                new AuthenticationMethod("#key-2"),
                new AuthenticationMethod("#key-3")
            ]
        };
    }


    /// <summary>
    /// A resolved authentication verification method that is structurally malformed (an OKP JWK with no
    /// <c>x</c>) makes the key-material converter throw; verification MUST fail CLOSED with
    /// <see cref="DidCommSignatureVerificationError.SignerResolutionFailed"/> and never let the exception
    /// escape — the signer DID is reached via the attacker-controlled <c>kid</c>, so a malicious signer's
    /// malformed document must not crash the verifier (the same guard keeps the nested encrypted-unpack
    /// path, which calls this verify, fail-closed).
    /// </summary>
    [TestMethod]
    public async Task MalformedAuthenticationKeyRejected()
    {
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocumentMalformedKey1())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A malformed resolved authentication key MUST NOT verify and MUST NOT throw.");
        Assert.AreEqual(DidCommSignatureVerificationError.SignerResolutionFailed, result.Error);
        Assert.IsNull(result.Message, "Fail-closed: a malformed signer key yields no message.");
    }


    /// <summary>
    /// A resolved <c>publicKeyMultibase</c> carrying a non-ASCII char makes the injected SimpleBase base58
    /// decoder throw <see cref="IndexOutOfRangeException"/>; signer resolution MUST fail closed with
    /// <see cref="DidCommSignatureVerificationError.SignerResolutionFailed"/> and never let the exception escape.
    /// </summary>
    [TestMethod]
    public async Task NonAsciiPublicKeyMultibaseFailsClosed()
    {
        //A resolved publicKeyMultibase carrying a non-ASCII char makes the injected SimpleBase base58 decoder
        //throw IndexOutOfRangeException; signer resolution MUST fail closed, never let the exception escape.
        using DidCommSignedMessage signed = GeneralJsonSigned(EdDsaProtectedBase64Url, EdDsaSignatureBase64Url, EdDsaKid);

        DidCommSignedVerificationResult result = await UnpackAsync(signed, CreateResolver(CreateAliceDidDocumentNonAsciiMultibaseKey1())).ConfigureAwait(false);

        Assert.IsFalse(result.IsVerified, "A non-ASCII publicKeyMultibase MUST NOT verify and MUST NOT throw.");
        Assert.AreEqual(DidCommSignatureVerificationError.SignerResolutionFailed, result.Error);
        Assert.IsNull(result.Message);
    }


    //Alice's document whose key-1 authentication method is structurally malformed (an OKP JWK with no x
    //coordinate), so the key-material converter throws when the verifier resolves the signing key.
    private static DidDocument CreateAliceDidDocumentMalformedKey1()
    {
        var malformed = new VerificationMethod
        {
            Id = EdDsaKid,
            Type = "JsonWebKey2020",
            Controller = "did:example:alice",
            KeyFormat = new PublicKeyJwk { Header = new Dictionary<string, object> { ["kty"] = "OKP", ["crv"] = "Ed25519" } }
        };

        return new DidDocument
        {
            Id = new GenericDidMethod("did:example:alice"),
            VerificationMethod = [malformed],
            Authentication = [new AuthenticationMethod(EdDsaKid)]
        };
    }


    //Alice's document whose key-1 authentication method is a publicKeyMultibase carrying a non-ASCII char
    //outside the base58 alphabet, so the injected base58 decoder throws when the verifier resolves the key.
    private static DidDocument CreateAliceDidDocumentNonAsciiMultibaseKey1()
    {
        var key = new VerificationMethod
        {
            Id = EdDsaKid,
            Type = "Multikey",
            Controller = "did:example:alice",
            //'z' multibase prefix + a non-ASCII char (U+00E4) outside the base58 alphabet table.
            KeyFormat = new PublicKeyMultibase("z6MkäAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        };

        return new DidDocument
        {
            Id = new GenericDidMethod("did:example:alice"),
            VerificationMethod = [key],
            Authentication = [new AuthenticationMethod(EdDsaKid)]
        };
    }
}
