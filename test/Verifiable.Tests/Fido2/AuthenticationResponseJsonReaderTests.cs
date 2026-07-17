using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="AuthenticationResponseJsonReader"/>: the W3C WebAuthn Level 3
/// <c>AuthenticationResponseJSON</c> envelope reader. Byte-exact positive vectors, then the reader's
/// malformed-input rejections — each a <see cref="Fido2FormatException"/>.
/// </summary>
[TestClass]
internal sealed class AuthenticationResponseJsonReaderTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fully populated, spec-shaped <c>AuthenticationResponseJSON</c> document, including <c>userHandle</c>.</summary>
    private const string FullyPopulatedDocument =
        """{"id":"AQIDBAUGBwg","rawId":"AQIDBAUGBwg","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2MiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIn0","authenticatorData":"CgsMDQ4PEBESExQ","signature":"Hh8gISIjJCUmJygpKg","userHandle":"MjM0NQ"},"authenticatorAttachment":"cross-platform","clientExtensionResults":{},"type":"public-key"}""";

    /// <summary>
    /// A fully populated document parses every member byte-exactly: <c>rawId</c>,
    /// <c>response.clientDataJSON</c>, <c>response.authenticatorData</c>, <c>response.signature</c>,
    /// <c>response.userHandle</c>, and <c>authenticatorAttachment</c>.
    /// </summary>
    [TestMethod]
    public void FullyPopulatedDocumentParsesEveryMemberByteExactly()
    {
        byte[] expectedRawId = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] expectedClientDataJson =
            Encoding.UTF8.GetBytes("""{"type":"webauthn.get","challenge":"AAECAwQFBgc","origin":"https://example.com"}""");
        byte[] expectedAuthenticatorData = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        byte[] expectedSignature = [30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42];
        byte[] expectedUserHandle = [50, 51, 52, 53];

        using WebAuthnAssertionResponseEnvelope envelope = AuthenticationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(FullyPopulatedDocument), BaseMemoryPool.Shared);

        Assert.IsTrue(envelope.RawId.AsReadOnlySpan().SequenceEqual(expectedRawId));
        Assert.IsTrue(envelope.ClientDataJson.AsReadOnlySpan().SequenceEqual(expectedClientDataJson));
        Assert.IsTrue(envelope.AuthenticatorData.AsReadOnlySpan().SequenceEqual(expectedAuthenticatorData));
        Assert.IsTrue(envelope.Signature.AsReadOnlySpan().SequenceEqual(expectedSignature));
        Assert.IsNotNull(envelope.UserHandle);
        Assert.IsTrue(envelope.UserHandle!.AsReadOnlySpan().SequenceEqual(expectedUserHandle));
        Assert.AreEqual(WellKnownAuthenticatorAttachments.CrossPlatform, envelope.AuthenticatorAttachment);
    }


    /// <summary>
    /// <c>response.userHandle</c> is optional: a document omitting it (the non-discoverable-credential
    /// path) parses with <see cref="WebAuthnAssertionResponseEnvelope.UserHandle"/> left <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void MissingOptionalUserHandleLeavesMemberNull()
    {
        string json = FullyPopulatedDocument.Replace(",\"userHandle\":\"MjM0NQ\"", string.Empty, System.StringComparison.Ordinal);

        using WebAuthnAssertionResponseEnvelope envelope = AuthenticationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared);

        Assert.IsNull(envelope.UserHandle);
    }


    /// <summary>An unrecognised top-level member is tolerated, not rejected — this reader parses an externally-authored document.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsTolerated()
    {
        byte[] expectedRawId = [1, 2, 3, 4, 5, 6, 7, 8];
        string json = FullyPopulatedDocument.Replace("\"type\":\"public-key\"", "\"type\":\"public-key\",\"extra\":{\"nested\":[1,2,3]}", System.StringComparison.Ordinal);

        using WebAuthnAssertionResponseEnvelope envelope = AuthenticationResponseJsonReader.Read(
            Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared);

        Assert.IsTrue(envelope.RawId.AsReadOnlySpan().SequenceEqual(expectedRawId));
    }


    /// <summary>A document missing the required <c>response</c> member is rejected.</summary>
    [TestMethod]
    public void MissingResponseMemberIsRejected()
    {
        string json = """{"id":"AQIDBAUGBwg","rawId":"AQIDBAUGBwg","clientExtensionResults":{},"type":"public-key"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document missing the required <c>response.signature</c> member is rejected.</summary>
    [TestMethod]
    public void MissingSignatureMemberIsRejected()
    {
        string json = FullyPopulatedDocument.Replace(",\"signature\":\"Hh8gISIjJCUmJygpKg\"", string.Empty, System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A <c>type</c> value other than <c>public-key</c> is rejected.</summary>
    [TestMethod]
    public void WrongTypeValueIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"type\":\"public-key\"", "\"type\":\"webauthn.get\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A padded <c>rawId</c> — base64url MUST NOT carry trailing '=' — is rejected.</summary>
    [TestMethod]
    public void PaddedBase64UrlRawIdIsRejected()
    {
        string json = FullyPopulatedDocument
            .Replace("\"id\":\"AQIDBAUGBwg\"", "\"id\":\"AQIDBAUGBwg==\"", System.StringComparison.Ordinal)
            .Replace("\"rawId\":\"AQIDBAUGBwg\"", "\"rawId\":\"AQIDBAUGBwg==\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An invalid base64url <c>response.signature</c> — an illegal character — is rejected.</summary>
    [TestMethod]
    public void InvalidBase64UrlSignatureIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"signature\":\"Hh8gISIjJCUmJygpKg\"", "\"signature\":\"not base64url!!\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary><c>rawId</c> disagreeing with <c>id</c> is rejected — they MUST encode the same identifier.</summary>
    [TestMethod]
    public void RawIdNotEqualToIdIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"rawId\":\"AQIDBAUGBwg\"", "\"rawId\":\"CQkJ\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A repeated top-level member name is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        string json = FullyPopulatedDocument.Replace("\"type\":\"public-key\"", "\"type\":\"public-key\",\"type\":\"public-key\"", System.StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>Trailing content after an otherwise well-formed top-level object is rejected.</summary>
    [TestMethod]
    public void TrailingContentAfterTheObjectIsRejected()
    {
        string json = FullyPopulatedDocument + " garbage";

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }
}
