using System.Buffers;
using System.Buffers.Text;
using System.Text;
using Verifiable.DidComm;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Verifies the inbound classifier (<see cref="DidCommInbound.Classify"/>) on BOTH its paths. With a media
/// type, it splits plaintext / signed / encrypted (DIDComm v2.1 §IANA Media Types), and for the shared
/// encrypted media type the protected-header <c>alg</c> splits anoncrypt (ECDH-ES) from authcrypt (ECDH-1PU);
/// an unrecognized media type or an encrypted envelope with no/foreign <c>alg</c> is
/// <see cref="DidCommMessageClass.Unknown"/> — the receiver rejects rather than guesses. Without one (a raw
/// WebSocket frame conveys none), it classifies by envelope shape instead: a top-level <c>ciphertext</c>
/// member means JWE (dispatched through the same <c>alg</c> split), a top-level <c>payload</c> plus
/// <c>signatures</c>/<c>signature</c> means JWS, neither means a plaintext JWM, and both at once is
/// structurally ambiguous — refused as <see cref="DidCommMessageClass.Unknown"/> rather than guessed.
/// </summary>
[TestClass]
internal sealed class DidCommInboundClassifyTests
{
    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    [TestMethod]
    public void PlaintextMediaTypeClassifiesAsPlaintext()
    {
        Assert.AreEqual(
            DidCommMessageClass.Plaintext,
            DidCommInbound.Classify(DidCommMediaTypes.Plaintext, default, TestSetup.Base64UrlDecoder, Pool));
    }


    [TestMethod]
    public void SignedMediaTypeClassifiesAsSigned()
    {
        Assert.AreEqual(
            DidCommMessageClass.Signed,
            DidCommInbound.Classify(DidCommMediaTypes.Signed, default, TestSetup.Base64UrlDecoder, Pool));
    }


    [TestMethod]
    public void EcdhEsEnvelopeClassifiesAsAnoncrypt()
    {
        byte[] envelope = EncryptedEnvelopeWithAlg("ECDH-ES+A256KW");

        Assert.AreEqual(
            DidCommMessageClass.Anoncrypt,
            DidCommInbound.Classify(DidCommMediaTypes.Encrypted, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    [TestMethod]
    public void Ecdh1PuEnvelopeClassifiesAsAuthcrypt()
    {
        byte[] envelope = EncryptedEnvelopeWithAlg("ECDH-1PU+A256KW");

        Assert.AreEqual(
            DidCommMessageClass.Authcrypt,
            DidCommInbound.Classify(DidCommMediaTypes.Encrypted, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    [TestMethod]
    public void UnrecognizedEncryptedAlgClassifiesAsUnknown()
    {
        byte[] envelope = EncryptedEnvelopeWithAlg("RSA-OAEP");

        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(DidCommMediaTypes.Encrypted, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    [TestMethod]
    public void EncryptedEnvelopeWithoutProtectedHeaderClassifiesAsUnknown()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("{\"ciphertext\":\"x\"}");

        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(DidCommMediaTypes.Encrypted, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    [TestMethod]
    public void UnknownMediaTypeClassifiesAsUnknown()
    {
        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify("application/json", default, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>
    /// No media type AND bytes that do not even look like a JSON object (here, none at all) fall through
    /// <see cref="DidCommInbound.Classify"/>'s envelope-shape path with nothing to classify — distinct from
    /// <see cref="NullMediaTypeWithARealEnvelopeClassifiesByShape"/>, where the bytes DO carry a shape.
    /// </summary>
    [TestMethod]
    public void NullMediaTypeWithNonObjectBytesClassifiesAsUnknown()
    {
        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(null, default, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-7.2">RFC 7516 §7.2 (JWE JSON Serialization)</see>
    /// (<c>ciphertext</c> is the member every JWE JSON serialization carries): no media type but a genuine
    /// anoncrypt-shaped envelope — <see cref="DidCommInbound.Classify"/> falls back to envelope shape and
    /// still recovers the right class, the content-type-absent path this seam's unsolicited dispatch relies
    /// on for a raw WebSocket frame.
    /// </summary>
    [TestMethod]
    public void NullMediaTypeWithARealEnvelopeClassifiesByShape()
    {
        byte[] envelope = EncryptedEnvelopeWithAlg("ECDH-ES+A256KW");

        Assert.AreEqual(
            DidCommMessageClass.Anoncrypt,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>No media type, ECDH-1PU envelope: the envelope-shape path splits authcrypt from anoncrypt by <c>alg</c> exactly like the media-typed path does.</summary>
    [TestMethod]
    public void NullMediaTypeWithEcdh1PuEnvelopeClassifiesAsAuthcrypt()
    {
        byte[] envelope = EncryptedEnvelopeWithAlg("ECDH-1PU+A256KW");

        Assert.AreEqual(
            DidCommMessageClass.Authcrypt,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1">RFC 7515 §7.2.1 (General JWS JSON Serialization)</see>:
    /// "The following members are defined for use in top-level JSON objects ... payload ... signatures" — a
    /// general JWS JSON serialization classifies Signed with no media type.
    /// </summary>
    [TestMethod]
    public void NullMediaTypeWithGeneralJwsShapeClassifiesAsSigned()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("{\"payload\":\"x\",\"signatures\":[{\"protected\":\"y\",\"signature\":\"z\"}]}");

        Assert.AreEqual(
            DidCommMessageClass.Signed,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2">RFC 7515 §7.2.2 (Flattened JWS JSON Serialization)</see>:
    /// "The flattened JWS JSON Serialization ... signature" — a flattened serialization's singular top-level
    /// <c>signature</c> member classifies Signed with no media type.
    /// </summary>
    [TestMethod]
    public void NullMediaTypeWithFlattenedJwsShapeClassifiesAsSigned()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("{\"payload\":\"x\",\"signature\":\"z\"}");

        Assert.AreEqual(
            DidCommMessageClass.Signed,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>A plain JWM object — none of <c>ciphertext</c>/<c>payload</c>/<c>signature(s)</c> at top level — classifies Plaintext with no media type: the legitimate common case, not a malformed input.</summary>
    [TestMethod]
    public void NullMediaTypeWithPlainJwmShapeClassifiesAsPlaintext()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("{\"id\":\"msg-1\",\"type\":\"https://example.com/protocols/lets_do_lunch/1.0/proposal\",\"body\":{}}");

        Assert.AreEqual(
            DidCommMessageClass.Plaintext,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>Whitespace-only bytes never look like a JSON object, so they classify Unknown with no media type — nothing to classify, not a JWM.</summary>
    [TestMethod]
    public void NullMediaTypeWithWhitespaceOnlyBytesClassifiesAsUnknown()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("   \t\r\n  ");

        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>Non-<c>{</c> bytes (here, a JSON array) never look like a JSON object either, so they classify Unknown with no media type.</summary>
    [TestMethod]
    public void NullMediaTypeWithNonObjectJsonClassifiesAsUnknown()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("[\"ciphertext\",\"payload\",\"signature\"]");

        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>
    /// An envelope carrying BOTH a top-level <c>ciphertext</c> member (JWE) AND a JWS shape (<c>payload</c> plus
    /// <c>signature</c>) at once is structurally ambiguous — no legitimate DIDComm envelope is both — so it
    /// classifies Unknown with no media type rather than guessing which one it is (the adjudicated divergence
    /// from the serde-untagged, ciphertext-tried-first precedent <see cref="DidCommInbound"/>'s remarks describe).
    /// </summary>
    [TestMethod]
    public void NullMediaTypeWithPolyglotJweAndJwsShapeClassifiesAsUnknown()
    {
        byte[] envelope = Encoding.UTF8.GetBytes("{\"ciphertext\":\"x\",\"payload\":\"y\",\"signature\":\"z\"}");

        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    /// <summary>
    /// A plaintext JWM whose OWN body/attachments happen to nest fields literally named <c>ciphertext</c>,
    /// <c>payload</c>, and <c>signature</c> still classifies Plaintext with no media type: envelope-shape
    /// classification matches those members at depth 0 only (<c>JwkJsonReader.ContainsKey</c>), so a message's
    /// own application-level content can never masquerade as an envelope shape it is not.
    /// </summary>
    [TestMethod]
    public void NullMediaTypeWithNestedJoseLookingFieldsStillClassifiesAsPlaintext()
    {
        byte[] envelope = Encoding.UTF8.GetBytes(
            "{\"id\":\"msg-1\",\"type\":\"https://example.com/protocols/lets_do_lunch/1.0/proposal\"," +
            "\"body\":{\"ciphertext\":\"not-really\",\"payload\":\"not-really\",\"signature\":\"not-really\"}," +
            "\"attachments\":[{\"data\":{\"ciphertext\":\"not-really\"}}]}");

        Assert.AreEqual(
            DidCommMessageClass.Plaintext,
            DidCommInbound.Classify(null, envelope, TestSetup.Base64UrlDecoder, Pool));
    }


    //An encrypted envelope whose protected header carries the given alg; enc is present but unused by Classify.
    private static byte[] EncryptedEnvelopeWithAlg(string algorithm)
    {
        string header = $"{{\"alg\":\"{algorithm}\",\"enc\":\"A256CBC-HS512\"}}";
        string protectedEncoded = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header));

        return Encoding.UTF8.GetBytes($"{{\"protected\":\"{protectedEncoded}\",\"ciphertext\":\"x\"}}");
    }
}
