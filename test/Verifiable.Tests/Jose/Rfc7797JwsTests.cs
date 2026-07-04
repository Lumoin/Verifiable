using System;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;


namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for the RFC 7797 JWS Unencoded Payload Option (<c>b64:false</c>): the signing-input construction
/// (Appendix A vector), the <c>b64</c> header reader, and a detached unencoded-payload sign/verify roundtrip.
/// </summary>
[TestClass]
internal sealed class Rfc7797JwsTests
{
    /// <summary>Test context for the cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Encodes a protected-header JSON string to its UTF-8 bytes (the exact bytes are base64url'd into the JWS).</summary>
    private static TaggedMemory<byte> EncodeHeader(string headerJson)
    {
        return new TaggedMemory<byte>(Encoding.UTF8.GetBytes(headerJson), BufferTags.Json);
    }


    /// <summary>
    /// RFC 7797 Appendix A: with the protected header
    /// <c>{"alg":"HS256","b64":false,"crit":["b64"]}</c> and payload <c>$.02</c>, the JWS Signing Input is the
    /// protected segment, a period, then the raw payload bytes (the payload is NOT base64url-encoded).
    /// </summary>
    [TestMethod]
    public void AppendixASigningInputAppendsRawPayload()
    {
        const string protectedSegment = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
        byte[] payload = Encoding.ASCII.GetBytes("$.02");
        const string expected = protectedSegment + ".$.02";

        using IMemoryOwner<byte> owner = Jws.RentSigningInput(
            protectedSegment, payload, base64UrlPayload: false, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, out int length);

        Assert.AreEqual(expected, Encoding.ASCII.GetString(owner.Memory.Span[..length]));
    }


    /// <summary>The <c>b64</c> header parameter selects unencoded payload only when explicitly <c>false</c>; absent or <c>true</c> keep the default base64url encoding.</summary>
    [TestMethod]
    public void B64HeaderControlsPayloadEncoding()
    {
        Assert.IsFalse(Jws.IsPayloadBase64UrlEncoded(Encoding.UTF8.GetBytes("""{"alg":"HS256","b64":false,"crit":["b64"]}""")), "b64:false ⇒ unencoded payload.");
        Assert.IsTrue(Jws.IsPayloadBase64UrlEncoded(Encoding.UTF8.GetBytes("""{"alg":"HS256"}""")), "absent b64 ⇒ default encoded.");
        Assert.IsTrue(Jws.IsPayloadBase64UrlEncoded(Encoding.UTF8.GetBytes("""{"alg":"HS256","b64":true}""")), "b64:true ⇒ encoded.");
    }


    /// <summary>A detached unencoded-payload (<c>b64:false</c>) JWS signs and verifies over the raw payload; the wrong <c>b64</c> interpretation and a tampered payload both fail.</summary>
    [TestMethod]
    public async Task DetachedUnencodedPayloadSignAndVerifyRoundtrips()
    {
        const string protectedHeader = """{"alg":"ES256","b64":false,"crit":["b64"]}""";
        //Non-ASCII octets prove the payload is signed as raw bytes, not as a base64url string.
        byte[] payload = Encoding.UTF8.GetBytes("did:webplus proof payload éñ✓");

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage message = await Jws.SignAsync(
            protectedHeader,
            (ReadOnlyMemory<byte>)payload,
            EncodeHeader,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            unprotectedHeader: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        JwsSignatureComponent signature = message.Signatures[0];

        bool valid = await Jws.VerifySignatureAsync(
            signature.Protected,
            payload,
            base64UrlPayload: false,
            signature.SignatureBytes,
            TestSetup.Base64UrlEncoder,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            publicKey.AsReadOnlyMemory(),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(valid, "The unencoded-payload signature must verify over the raw payload.");

        bool wrongInterpretation = await Jws.VerifySignatureAsync(
            signature.Protected,
            payload,
            base64UrlPayload: true,
            signature.SignatureBytes,
            TestSetup.Base64UrlEncoder,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            publicKey.AsReadOnlyMemory(),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongInterpretation, "Treating the payload as base64url-encoded is the wrong b64 interpretation and must fail.");

        byte[] tampered = (byte[])payload.Clone();
        tampered[0] ^= 0xFF;
        bool tamperedResult = await Jws.VerifySignatureAsync(
            signature.Protected,
            tampered,
            base64UrlPayload: false,
            signature.SignatureBytes,
            TestSetup.Base64UrlEncoder,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            publicKey.AsReadOnlyMemory(),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(tamperedResult, "A tampered payload must not verify.");
    }
}
