using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2CredentialRecordJsonWriter"/>/<see cref="Fido2CredentialRecordJsonReader"/>:
/// byte-equality round-tripping of every <see cref="Fido2CredentialRecord"/> member for both an EC2 and
/// an RSA <see cref="CoseKey"/>, and the strict-reader rejections (unknown member, duplicate member,
/// malformed base64url, missing required member, and the nesting-depth bound) required for a document
/// shape this codebase itself defines rather than a WebAuthn wire format.
/// </summary>
[TestClass]
internal sealed class Fido2CredentialRecordJsonTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Every member of a record carrying an EC2 (P-256) public key round-trips byte-for-byte,
    /// including the <see cref="CoseKey.EncodedYCompressionSign"/> flag.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created inline transfers to the Fido2CredentialRecord constructed on the same statement, which the 'using' declaration disposes.")]
    public void Ec2RecordRoundTripsEveryMember()
    {
        byte[] idBytes = [1, 2, 3, 4, 5, 6, 7, 8];

        using IMemoryOwner<byte> xOwner = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> yOwner = BaseMemoryPool.Shared.Rent(32);
        for(int i = 0; i < 32; i++)
        {
            xOwner.Memory.Span[i] = (byte)i;
            yOwner.Memory.Span[i] = (byte)(32 + i);
        }

        using Fido2CredentialRecord original = new(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            CredentialId.Create(idBytes, BaseMemoryPool.Shared),
            new CoseKey(CoseKeyTypes.Ec2, alg: -7, curve: CoseKeyCurves.P256, x: xOwner.Memory[..32], y: yOwner.Memory[..32], encodedYCompressionSign: false),
            SignCount: 42,
            UvInitialized: true,
            Transports: ["usb", "nfc"],
            BackupEligible: true,
            BackupState: false);

        ArrayBufferWriter<byte> buffer = new();
        Fido2CredentialRecordJsonWriter.Write(original, buffer);

        using Fido2CredentialRecord roundTripped = Fido2CredentialRecordJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original, roundTripped);
        Assert.IsTrue(original.PublicKey.X!.Value.Span.SequenceEqual(roundTripped.PublicKey.X!.Value.Span));
        Assert.IsTrue(original.PublicKey.Y!.Value.Span.SequenceEqual(roundTripped.PublicKey.Y!.Value.Span));
        Assert.AreEqual(original.PublicKey.EncodedYCompressionSign, roundTripped.PublicKey.EncodedYCompressionSign);
    }


    /// <summary>
    /// Every member of a record carrying an RSA public key (<c>n</c>/<c>e</c>, no <c>crv</c>/<c>x</c>/<c>y</c>)
    /// round-trips byte-for-byte.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created inline transfers to the Fido2CredentialRecord constructed on the same statement, which the 'using' declaration disposes.")]
    public void RsaRecordRoundTripsEveryMember()
    {
        byte[] idBytes = [9, 9, 9];

        using IMemoryOwner<byte> modulusOwner = BaseMemoryPool.Shared.Rent(256);
        for(int i = 0; i < 256; i++)
        {
            modulusOwner.Memory.Span[i] = (byte)i;
        }

        using IMemoryOwner<byte> exponentOwner = BaseMemoryPool.Shared.Rent(3);
        exponentOwner.Memory.Span[0] = 0x01;
        exponentOwner.Memory.Span[1] = 0x00;
        exponentOwner.Memory.Span[2] = 0x01;

        using Fido2CredentialRecord original = new(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            CredentialId.Create(idBytes, BaseMemoryPool.Shared),
            new CoseKey(CoseKeyTypes.Rsa, alg: -257, n: modulusOwner.Memory[..256], e: exponentOwner.Memory[..3]),
            SignCount: 0,
            UvInitialized: false,
            Transports: [],
            BackupEligible: false,
            BackupState: false);

        ArrayBufferWriter<byte> buffer = new();
        Fido2CredentialRecordJsonWriter.Write(original, buffer);

        using Fido2CredentialRecord roundTripped = Fido2CredentialRecordJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original, roundTripped);
        Assert.IsTrue(original.PublicKey.N!.Value.Span.SequenceEqual(roundTripped.PublicKey.N!.Value.Span));
        Assert.IsTrue(original.PublicKey.E!.Value.Span.SequenceEqual(roundTripped.PublicKey.E!.Value.Span));
        Assert.IsNull(roundTripped.PublicKey.X);
        Assert.IsNull(roundTripped.PublicKey.Y);
    }


    /// <summary>
    /// A record carrying a populated <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/>
    /// round-trips it byte-for-byte, and the written document carries the member.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created inline transfers to the Fido2CredentialRecord constructed on the same statement, which the 'using' declaration disposes.")]
    public void AuthenticatorAttachmentRoundTripsWhenPresent()
    {
        using IMemoryOwner<byte> xOwner = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> yOwner = BaseMemoryPool.Shared.Rent(32);

        using Fido2CredentialRecord original = new(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            CredentialId.Create([1, 2, 3, 4], BaseMemoryPool.Shared),
            new CoseKey(CoseKeyTypes.Ec2, alg: -7, curve: CoseKeyCurves.P256, x: xOwner.Memory[..32], y: yOwner.Memory[..32]),
            SignCount: 0,
            UvInitialized: false,
            Transports: ["usb"],
            BackupEligible: false,
            BackupState: false,
            AuthenticatorAttachment: WellKnownAuthenticatorAttachments.Platform);

        ArrayBufferWriter<byte> buffer = new();
        Fido2CredentialRecordJsonWriter.Write(original, buffer);
        string json = Encoding.UTF8.GetString(buffer.WrittenSpan);

        Assert.Contains("\"authenticatorAttachment\":\"platform\"", json, StringComparison.Ordinal);

        using Fido2CredentialRecord roundTripped = Fido2CredentialRecordJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original, roundTripped);
        Assert.AreEqual(WellKnownAuthenticatorAttachments.Platform, roundTripped.AuthenticatorAttachment);
    }


    /// <summary>
    /// A record with a <see langword="null"/> <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/>
    /// omits the member entirely on write (not a written <c>null</c> literal) and round-trips to
    /// <see langword="null"/> on read.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created inline transfers to the Fido2CredentialRecord constructed on the same statement, which the 'using' declaration disposes.")]
    public void AuthenticatorAttachmentAbsentOmitsMemberAndRoundTripsToNull()
    {
        using IMemoryOwner<byte> xOwner = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> yOwner = BaseMemoryPool.Shared.Rent(32);

        using Fido2CredentialRecord original = new(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            CredentialId.Create([1, 2, 3, 4], BaseMemoryPool.Shared),
            new CoseKey(CoseKeyTypes.Ec2, alg: -7, curve: CoseKeyCurves.P256, x: xOwner.Memory[..32], y: yOwner.Memory[..32]),
            SignCount: 0,
            UvInitialized: false,
            Transports: ["usb"],
            BackupEligible: false,
            BackupState: false);

        ArrayBufferWriter<byte> buffer = new();
        Fido2CredentialRecordJsonWriter.Write(original, buffer);
        string json = Encoding.UTF8.GetString(buffer.WrittenSpan);

        Assert.DoesNotContain("authenticatorAttachment", json, StringComparison.Ordinal);

        using Fido2CredentialRecord roundTripped = Fido2CredentialRecordJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original, roundTripped);
        Assert.IsNull(roundTripped.AuthenticatorAttachment);
    }


    /// <summary>
    /// A wave-4-shaped document with no <c>authenticatorAttachment</c> member at all — the exact shape
    /// every document written before this wave has — still parses under the CURRENT version: adding
    /// the member was purely additive, with no version bump.
    /// </summary>
    [TestMethod]
    public void MinimalDocumentWithoutAuthenticatorAttachmentStillParsesUnderCurrentVersion()
    {
        using Fido2CredentialRecord record = Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(MinimalValidDocument()), BaseMemoryPool.Shared);

        Assert.IsNull(record.AuthenticatorAttachment);
        Assert.AreEqual(WellKnownPublicKeyCredentialTypes.PublicKey, record.Type);
    }


    /// <summary>An unrecognised top-level member is rejected rather than silently skipped.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"backupState\":false", "\"backupState\":false,\"unexpected\":1", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An unrecognised <c>publicKey</c> sub-object member is rejected.</summary>
    [TestMethod]
    public void UnknownPublicKeyMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"kty\":2", "\"kty\":2,\"unexpected\":1", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A repeated top-level member name is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"version\":1,", "\"version\":1,\"version\":1,", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A malformed base64url value for the <c>id</c> member is rejected.</summary>
    [TestMethod]
    public void MalformedBase64UrlIdIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"id\":\"AQIDBA\"", "\"id\":\"not base64url!!\"", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document missing the required <c>signCount</c> member is rejected.</summary>
    [TestMethod]
    public void MissingRequiredMemberIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"signCount\":0,", "", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>A document exceeding this reader's nesting-depth bound is rejected.</summary>
    [TestMethod]
    public void ExcessiveNestingDepthIsRejected()
    {
        const string json = """{"version":1,"type":"public-key","id":"AQIDBA","publicKey":{"kty":{"nested":{"deeper":{"deepest":1}}}},"signCount":0,"uvInitialized":false,"transports":[],"backupEligible":false,"backupState":false}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>An unsupported <c>version</c> value is rejected.</summary>
    [TestMethod]
    public void UnsupportedVersionIsRejected()
    {
        string json = MinimalValidDocument().Replace("\"version\":1", "\"version\":999", StringComparison.Ordinal);

        Assert.ThrowsExactly<Fido2FormatException>(() => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A minimal, structurally valid document — the base every negative test derives its fixture from
    /// via a single targeted string replacement.
    /// </summary>
    private static string MinimalValidDocument() =>
        """{"version":1,"type":"public-key","id":"AQIDBA","publicKey":{"kty":2,"alg":-7,"crv":1,"x":"AQIDBA","y":"AQIDBA"},"signCount":0,"uvInitialized":false,"transports":[],"backupEligible":false,"backupState":false}""";
}
