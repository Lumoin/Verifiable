using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="RegistrationResponseJsonReader"/>: the W3C WebAuthn Level 3
/// <c>RegistrationResponseJSON</c> envelope reader. Byte-exact positive vectors, then the reader's
/// malformed-input rejections — each a <see cref="Fido2FormatException"/>.
/// </summary>
[TestClass]
internal sealed class RegistrationResponseJsonReaderTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fully populated, spec-shaped <c>RegistrationResponseJSON</c> document.</summary>
    private const string FullyPopulatedDocument =
        """{"id":"AQIDBAUGBwg","rawId":"AQIDBAUGBwg","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2MiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIn0","attestationObject":"oWNmbXQ"},"authenticatorAttachment":"platform","clientExtensionResults":{},"type":"public-key"}""";

    /// <summary>
    /// A fully populated document parses every member byte-exactly: <c>rawId</c>,
    /// <c>response.clientDataJSON</c>, <c>response.attestationObject</c>, and <c>authenticatorAttachment</c>.
    /// </summary>
    [TestMethod]
    public void FullyPopulatedDocumentParsesEveryMemberByteExactly()
    {
        byte[] expectedRawId = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] expectedClientDataJson =
            Encoding.UTF8.GetBytes("""{"type":"webauthn.create","challenge":"AAECAwQFBgc","origin":"https://example.com"}""");
        byte[] expectedAttestationObject = [0xA1, 0x63, 0x66, 0x6D, 0x74];

        using WebAuthnRegistrationResponseEnvelope envelope = RegistrationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(FullyPopulatedDocument), BaseMemoryPool.Shared);

        Assert.IsTrue(envelope.RawId.AsReadOnlySpan().SequenceEqual(expectedRawId));
        Assert.IsTrue(envelope.ClientDataJson.AsReadOnlySpan().SequenceEqual(expectedClientDataJson));
        Assert.IsTrue(envelope.AttestationObject.AsReadOnlySpan().SequenceEqual(expectedAttestationObject));
        Assert.AreEqual(WellKnownAuthenticatorAttachments.Platform, envelope.AuthenticatorAttachment);
    }


    /// <summary>
    /// <c>authenticatorAttachment</c> is optional: a document omitting it parses with the envelope's
    /// member left <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void MissingOptionalAuthenticatorAttachmentLeavesMemberNull()
    {
        string json = FullyPopulatedDocument.Replace("\"authenticatorAttachment\":\"platform\",", string.Empty, System.StringComparison.Ordinal);

        using WebAuthnRegistrationResponseEnvelope envelope = RegistrationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared);

        Assert.IsNull(envelope.AuthenticatorAttachment);
    }


    /// <summary>
    /// <c>AuthenticatorAttestationResponseJSON</c>'s <c>transports</c>/<c>publicKey</c>/
    /// <c>publicKeyAlgorithm</c> members — genuine spec members this reader does not model — are
    /// tolerated rather than rejected, since a real client's response carries them.
    /// </summary>
    [TestMethod]
    public void UnmodeledResponseMembersAreTolerated()
    {
        byte[] expectedAttestationObject = [0xA1, 0x63, 0x66, 0x6D, 0x74];
        string json = FullyPopulatedDocument.Replace(
            "\"attestationObject\":\"oWNmbXQ\"",
            "\"attestationObject\":\"oWNmbXQ\",\"transports\":[\"usb\",\"nfc\"],\"publicKey\":\"AQ\",\"publicKeyAlgorithm\":-7",
            System.StringComparison.Ordinal);

        using WebAuthnRegistrationResponseEnvelope envelope = RegistrationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared);

        Assert.IsTrue(envelope.AttestationObject.AsReadOnlySpan().SequenceEqual(expectedAttestationObject));
    }


    /// <summary>An unrecognised top-level member is tolerated, not rejected — this reader parses an externally-authored document.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsTolerated()
    {
        byte[] expectedRawId = [1, 2, 3, 4, 5, 6, 7, 8];
        string json = FullyPopulatedDocument.Replace("\"type\":\"public-key\"", "\"type\":\"public-key\",\"clientExtensionResults2\":{}", System.StringComparison.Ordinal);

        using WebAuthnRegistrationResponseEnvelope envelope = RegistrationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared);

        Assert.IsTrue(envelope.RawId.AsReadOnlySpan().SequenceEqual(expectedRawId));
    }


    /// <summary>A document missing the required <c>response</c> member is rejected.</summary>
    [TestMethod]
    public void MissingResponseMemberIsRejected()
    {
        string json = """{"id":"AQIDBAUGBwg","rawId":"AQIDBAUGBwg","clientExtensionResults":{},"type":"public-key"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document missing the required <c>clientExtensionResults</c> member is rejected.</summary>
    [TestMethod]
    public void MissingClientExtensionResultsMemberIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"clientExtensionResults\":{},", string.Empty, System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A <c>type</c> value other than <c>public-key</c> is rejected.</summary>
    [TestMethod]
    public void WrongTypeValueIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"type\":\"public-key\"", "\"type\":\"webauthn.create\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A padded <c>rawId</c> — base64url MUST NOT carry trailing '=' — is rejected.</summary>
    [TestMethod]
    public void PaddedBase64UrlRawIdIsRejected()
    {
        string json = FullyPopulatedDocument
            .Replace("\"id\":\"AQIDBAUGBwg\"", "\"id\":\"AQIDBAUGBwg==\"", System.StringComparison.Ordinal)
            .Replace("\"rawId\":\"AQIDBAUGBwg\"", "\"rawId\":\"AQIDBAUGBwg==\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An invalid base64url <c>response.clientDataJSON</c> — an illegal character — is rejected.</summary>
    [TestMethod]
    public void InvalidBase64UrlClientDataJsonIsRejected()
    {
        string json = FullyPopulatedDocument.Replace(
            "\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2MiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIn0\"",
            "\"clientDataJSON\":\"not base64url!!\"",
            System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary><c>rawId</c> disagreeing with <c>id</c> is rejected — they MUST encode the same identifier.</summary>
    [TestMethod]
    public void RawIdNotEqualToIdIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"rawId\":\"AQIDBAUGBwg\"", "\"rawId\":\"CQkJ\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A repeated top-level member name is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"type\":\"public-key\"", "\"type\":\"public-key\",\"type\":\"public-key\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>Trailing content after an otherwise well-formed top-level object is rejected.</summary>
    [TestMethod]
    public void TrailingContentAfterTheObjectIsRejected()
    {
        string json = FullyPopulatedDocument + " garbage";

        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A top-level JSON array, rather than an object, is rejected.</summary>
    [TestMethod]
    public void TopLevelJsonArrayIsRejected()
    {
        Assert.ThrowsExactly<Fido2FormatException>(() => RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes("[1,2,3]"), BaseMemoryPool.Shared));
    }
}
