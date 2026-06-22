using System.Buffers;
using System.Buffers.Text;
using System.Text;
using Verifiable.DidComm;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Verifies the inbound classifier (<see cref="DidCommInbound.Classify"/>): the media type the transport conveys
/// splits plaintext / signed / encrypted (DIDComm v2.1 §IANA Media Types), and for the shared encrypted media type
/// the protected-header <c>alg</c> splits anoncrypt (ECDH-ES) from authcrypt (ECDH-1PU). An unrecognized media type
/// or an encrypted envelope with no/foreign <c>alg</c> is <see cref="DidCommMessageClass.Unknown"/> — the receiver
/// rejects rather than guesses.
/// </summary>
[TestClass]
internal sealed class DidCommInboundClassifyTests
{
    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;


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


    [TestMethod]
    public void NullMediaTypeClassifiesAsUnknown()
    {
        Assert.AreEqual(
            DidCommMessageClass.Unknown,
            DidCommInbound.Classify(null, default, TestSetup.Base64UrlDecoder, Pool));
    }


    //An encrypted envelope whose protected header carries the given alg; enc is present but unused by Classify.
    private static byte[] EncryptedEnvelopeWithAlg(string algorithm)
    {
        string header = $"{{\"alg\":\"{algorithm}\",\"enc\":\"A256CBC-HS512\"}}";
        string protectedEncoded = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header));

        return Encoding.UTF8.GetBytes($"{{\"protected\":\"{protectedEncoded}\",\"ciphertext\":\"x\"}}");
    }
}
