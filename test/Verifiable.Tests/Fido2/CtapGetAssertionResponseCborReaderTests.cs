using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapGetAssertionResponseCborReader"/>: round-tripping against the paired
/// writer, every Required-member negative, and the section 8 forward-compatibility rule that
/// unrecognized member keys are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapGetAssertionResponseCborReaderTests
{
    /// <summary>A fixed 2-byte credential identifier pattern.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];

    /// <summary>A fixed 3-byte authData pattern.</summary>
    private static byte[] AuthDataBytes => [0x01, 0x02, 0x03];

    /// <summary>A fixed 2-byte signature pattern.</summary>
    private static byte[] SignatureBytes => [0x30, 0x44];

    /// <summary>A fixed 4-byte user handle pattern.</summary>
    private static byte[] UserHandleBytes => [0x11, 0x22, 0x33, 0x44];


    /// <summary>Round-tripping a response with only the Required members recovers them exactly, with every optional member left <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsRequiredMembersOnly()
    {
        using CredentialId credentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        var written = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            AuthDataBytes,
            SignatureBytes);

        TaggedMemory<byte> encoded = CtapGetAssertionResponseCborWriter.Write(written);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual(WellKnownPublicKeyCredentialTypes.PublicKey, decoded.Credential.Type);
            Assert.IsTrue(decoded.Credential.Id.AsReadOnlySpan().SequenceEqual(ShortCredentialIdBytes));
            Assert.IsTrue(decoded.AuthData.Span.SequenceEqual(AuthDataBytes));
            Assert.IsTrue(decoded.Signature.Span.SequenceEqual(SignatureBytes));
            Assert.IsNull(decoded.User);
            Assert.IsNull(decoded.NumberOfCredentials);
            Assert.IsNull(decoded.UserSelected);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
        }
    }


    /// <summary>Round-tripping a response carrying every optional member recovers each one exactly.</summary>
    [TestMethod]
    public void RoundTripsEveryOptionalMember()
    {
        using CredentialId credentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);
        using UserHandle userHandle = UserHandle.Create(UserHandleBytes, BaseMemoryPool.Shared);

        byte[] largeBlobKeyBytes = [0x99, 0x88];

        var written = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            AuthDataBytes,
            SignatureBytes,
            User: new CtapPublicKeyCredentialUserEntity(userHandle, "alice", "Alice Example"),
            NumberOfCredentials: 2,
            UserSelected: true,
            LargeBlobKey: largeBlobKeyBytes);

        TaggedMemory<byte> encoded = CtapGetAssertionResponseCborWriter.Write(written);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNotNull(decoded.User);
            Assert.IsTrue(decoded.User!.Id.AsReadOnlySpan().SequenceEqual(UserHandleBytes));
            Assert.AreEqual("alice", decoded.User!.Name);
            Assert.AreEqual("Alice Example", decoded.User!.DisplayName);
            Assert.AreEqual(2, decoded.NumberOfCredentials);
            Assert.IsTrue(decoded.UserSelected!.Value);
            Assert.IsTrue(decoded.LargeBlobKey!.Value.Span.SequenceEqual(largeBlobKeyBytes));
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User!.Id.Dispose();
        }
    }


    /// <summary>A response missing the Required <c>credential</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenCredentialMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.AuthData);
        writer.WriteByteString(AuthDataBytes);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Signature);
        writer.WriteByteString(SignatureBytes);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionResponseCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));

        Assert.Contains("credential", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A response missing the Required <c>authData</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenAuthDataMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Credential);
        writer.WriteStartMap(2);
        writer.WriteTextString("id");
        writer.WriteByteString(ShortCredentialIdBytes);
        writer.WriteTextString("type");
        writer.WriteTextString(WellKnownPublicKeyCredentialTypes.PublicKey);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Signature);
        writer.WriteByteString(SignatureBytes);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionResponseCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));

        Assert.Contains("authData", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A response missing the Required <c>signature</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenSignatureMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Credential);
        writer.WriteStartMap(2);
        writer.WriteTextString("id");
        writer.WriteByteString(ShortCredentialIdBytes);
        writer.WriteTextString("type");
        writer.WriteTextString(WellKnownPublicKeyCredentialTypes.PublicKey);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.AuthData);
        writer.WriteByteString(AuthDataBytes);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionResponseCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));

        Assert.Contains("signature", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A <c>credential</c> encoded as a byte string rather than the required map is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenCredentialHasWrongCborType()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Credential);
        writer.WriteByteString([0x01]);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.AuthData);
        writer.WriteByteString(AuthDataBytes);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Signature);
        writer.WriteByteString(SignatureBytes);
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionResponseCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));
    }


    /// <summary>A payload carrying the same top-level key twice is rejected.</summary>
    [TestMethod]
    public void ThrowsOnDuplicateTopLevelKey()
    {
        //Hand-built rather than produced by CborWriter (which enforces canonical key ordering at write
        //time and would refuse to emit this): {1: h'', 1: h''} — a duplicate top-level key.
        byte[] duplicateKeyMap = [0xA2, 0x01, 0x40, 0x01, 0x40];

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionResponseCborReader.Read(duplicateKeyMap, BaseMemoryPool.Shared));
    }


    /// <summary>An indefinite-length top-level map is rejected, per the CTAP2 canonical CBOR encoding form.</summary>
    [TestMethod]
    public void ThrowsOnIndefiniteLengthTopLevelMap()
    {
        //Major type 5 (map) with additional info 31 (indefinite length), one entry, then the break byte.
        byte[] indefiniteLengthMap = [0xBF, 0x01, 0x40, 0xFF];

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionResponseCborReader.Read(indefiniteLengthMap, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A response carrying an unrecognized member key (here <c>0x08</c>, the not-modeled
    /// <c>unsignedExtensionOutputs</c>) decodes successfully with the unknown member ignored, per CTAP
    /// 2.3 section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Credential);
        writer.WriteStartMap(2);
        writer.WriteTextString("id");
        writer.WriteByteString(ShortCredentialIdBytes);
        writer.WriteTextString("type");
        writer.WriteTextString(WellKnownPublicKeyCredentialTypes.PublicKey);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.AuthData);
        writer.WriteByteString(AuthDataBytes);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Signature);
        writer.WriteByteString(SignatureBytes);
        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.UnsignedExtensionOutputs);
        writer.WriteByteString([0x01, 0x02]);
        writer.WriteEndMap();

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(writer.Encode(), BaseMemoryPool.Shared);

        try
        {
            Assert.IsTrue(decoded.Signature.Span.SequenceEqual(SignatureBytes));
        }
        finally
        {
            decoded.Credential.Id.Dispose();
        }
    }


    /// <summary>Round-tripping a response carrying <c>largeBlobKey</c> (<c>0x07</c>, wavelb R8) recovers the key bytes verbatim.</summary>
    [TestMethod]
    public void RoundTripsWithLargeBlobKey()
    {
        using CredentialId credentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);
        byte[] largeBlobKeyBytes = [0xD0, 0xD1, 0xD2, 0xD3];

        var written = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            AuthDataBytes,
            SignatureBytes,
            LargeBlobKey: largeBlobKeyBytes);

        TaggedMemory<byte> encoded = CtapGetAssertionResponseCborWriter.Write(written);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsTrue(decoded.LargeBlobKey!.Value.Span.SequenceEqual(largeBlobKeyBytes));
        }
        finally
        {
            decoded.Credential.Id.Dispose();
        }
    }
}
