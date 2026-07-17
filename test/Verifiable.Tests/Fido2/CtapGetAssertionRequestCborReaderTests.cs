using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapGetAssertionRequestCborReader"/>: round-tripping against the paired
/// writer, every Required-member negative, and the section 8 forward-compatibility rule that unknown
/// top-level keys are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapGetAssertionRequestCborReaderTests
{
    /// <summary>A fixed 32-byte clientDataHash pattern.</summary>
    private static byte[] ClientDataHashBytes
    {
        get
        {
            byte[] bytes = new byte[32];
            for(int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)i;
            }

            return bytes;
        }
    }

    /// <summary>A fixed 2-byte credential identifier pattern.</summary>
    private static byte[] ShortCredentialIdBytes => [0xAA, 0xBB];


    /// <summary>Round-tripping a request with only the two Required members recovers them exactly, with every optional member left <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsRequiredMembersOnly()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);

        var written = new CtapGetAssertionRequest("rp.co", clientDataHash);

        TaggedMemory<byte> encoded = CtapGetAssertionRequestCborWriter.Write(written);
        CtapGetAssertionRequest decoded = CtapGetAssertionRequestCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual("rp.co", decoded.RpId);
            Assert.IsTrue(decoded.ClientDataHash.AsReadOnlySpan().SequenceEqual(ClientDataHashBytes));
            Assert.IsNull(decoded.AllowList);
            Assert.IsNull(decoded.Extensions);
            Assert.IsNull(decoded.Options);
            Assert.IsNull(decoded.PinUvAuthParam);
            Assert.IsNull(decoded.PinUvAuthProtocol);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
        }
    }


    /// <summary>
    /// Round-tripping a request carrying every optional member recovers each one exactly, including a
    /// wire-illegal <c>rk</c> option value (which a conformant platform never sends, but the codec must
    /// still decode faithfully so the authenticator-side handler can reject it).
    /// </summary>
    [TestMethod]
    public void RoundTripsEveryOptionalMember()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);
        using CredentialId allowCredentialId = CredentialId.Create(ShortCredentialIdBytes, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> extensionsOwner = BaseMemoryPool.Shared.Rent(1);
        extensionsOwner.Memory.Span[0] = NoneAttestation.CanonicalEmptyMap;

        using IMemoryOwner<byte> pinUvAuthParamOwner = BaseMemoryPool.Shared.Rent(4);
        Span<byte> pinUvAuthParamSpan = pinUvAuthParamOwner.Memory.Span[..4];
        pinUvAuthParamSpan[0] = 0xDE;
        pinUvAuthParamSpan[1] = 0xAD;
        pinUvAuthParamSpan[2] = 0xBE;
        pinUvAuthParamSpan[3] = 0xEF;

        var written = new CtapGetAssertionRequest(
            "rp.co",
            clientDataHash,
            AllowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = allowCredentialId, Transports = ["usb"] }],
            Extensions: extensionsOwner.Memory[..1],
            Options: new CtapCommandOptions(ResidentKey: true, UserPresence: false, UserVerification: true),
            PinUvAuthParam: pinUvAuthParamOwner.Memory[..4],
            PinUvAuthProtocol: 1);

        TaggedMemory<byte> encoded = CtapGetAssertionRequestCborWriter.Write(written);
        CtapGetAssertionRequest decoded = CtapGetAssertionRequestCborReader.Read(encoded.Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.HasCount(1, decoded.AllowList!);
            Assert.IsTrue(decoded.AllowList![0].Id.AsReadOnlySpan().SequenceEqual(ShortCredentialIdBytes));
            Assert.HasCount(1, decoded.AllowList![0].Transports!);
            Assert.AreEqual("usb", decoded.AllowList![0].Transports![0]);
            Assert.IsTrue(decoded.Extensions!.Value.Span.SequenceEqual(new byte[] { NoneAttestation.CanonicalEmptyMap }));
            Assert.IsTrue(decoded.Options!.ResidentKey!.Value);
            Assert.IsFalse(decoded.Options!.UserPresence!.Value);
            Assert.IsTrue(decoded.Options!.UserVerification!.Value);
            Assert.IsTrue(decoded.PinUvAuthParam!.Value.Span.SequenceEqual(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));
            Assert.AreEqual(1, decoded.PinUvAuthProtocol);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();

            foreach(PublicKeyCredentialDescriptor descriptor in decoded.AllowList!)
            {
                descriptor.Id.Dispose();
            }
        }
    }


    /// <summary>
    /// A <c>largeBlobKey:true</c> extensions map decodes <see cref="CtapGetAssertionRequest.LargeBlobKey"/>
    /// — one of this request type's two pre-decoded known-key convenience members (wavelb R8's scalar
    /// precedent; <see cref="CtapGetAssertionRequest.HmacSecret"/> is the compound sibling).
    /// </summary>
    [TestMethod]
    public void DecodesLargeBlobKeyFromExtensionsMap()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);

        var extensionsWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        extensionsWriter.WriteStartMap(1);
        extensionsWriter.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
        extensionsWriter.WriteBoolean(true);
        extensionsWriter.WriteEndMap();

        var written = new CtapGetAssertionRequest("rp.co", clientDataHash, Extensions: extensionsWriter.Encode());

        CtapGetAssertionRequest decoded = CtapGetAssertionRequestCborReader.Read(CtapGetAssertionRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsTrue(decoded.LargeBlobKey);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
        }
    }


    /// <summary>An extensions map present but carrying no <c>largeBlobKey</c> key leaves <see cref="CtapGetAssertionRequest.LargeBlobKey"/> <see langword="null"/>.</summary>
    [TestMethod]
    public void LeavesLargeBlobKeyNullWhenExtensionsMapOmitsIt()
    {
        using DigestValue clientDataHash = Fido2TestVectors.WrapRpIdHash(ClientDataHashBytes, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> extensionsOwner = BaseMemoryPool.Shared.Rent(1);
        extensionsOwner.Memory.Span[0] = NoneAttestation.CanonicalEmptyMap;

        var written = new CtapGetAssertionRequest("rp.co", clientDataHash, Extensions: extensionsOwner.Memory[..1]);

        CtapGetAssertionRequest decoded = CtapGetAssertionRequestCborReader.Read(CtapGetAssertionRequestCborWriter.Write(written).Memory, BaseMemoryPool.Shared);

        try
        {
            Assert.IsNull(decoded.LargeBlobKey);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
        }
    }


    /// <summary>A request missing the Required <c>rpId</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenRpIdMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.ClientDataHash);
        writer.WriteByteString(ClientDataHashBytes);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionRequestCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));

        Assert.Contains("rpId", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A request missing the Required <c>clientDataHash</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenClientDataHashMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.RpId);
        writer.WriteTextString("rp.co");
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionRequestCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));

        Assert.Contains("clientDataHash", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A <c>rpId</c> encoded as a byte string rather than the required text string is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenRpIdHasWrongCborType()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.RpId);
        writer.WriteByteString([0x01]);
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.ClientDataHash);
        writer.WriteByteString(ClientDataHashBytes);
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionRequestCborReader.Read(writer.Encode(), BaseMemoryPool.Shared));
    }


    /// <summary>A parameter map carrying the same top-level key twice is rejected.</summary>
    [TestMethod]
    public void ThrowsOnDuplicateTopLevelKey()
    {
        //Hand-built rather than produced by CborWriter (which enforces canonical key ordering at write
        //time and would refuse to emit this): {1: h'', 1: h''} — a duplicate top-level key.
        byte[] duplicateKeyMap = [0xA2, 0x01, 0x40, 0x01, 0x40];

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionRequestCborReader.Read(duplicateKeyMap, BaseMemoryPool.Shared));
    }


    /// <summary>An indefinite-length top-level map is rejected, per the CTAP2 canonical CBOR encoding form.</summary>
    [TestMethod]
    public void ThrowsOnIndefiniteLengthTopLevelMap()
    {
        //Major type 5 (map) with additional info 31 (indefinite length), one entry, then the break byte.
        byte[] indefiniteLengthMap = [0xBF, 0x01, 0x40, 0xFF];

        Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapGetAssertionRequestCborReader.Read(indefiniteLengthMap, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A request carrying an unrecognized top-level member key (here <c>0xFF</c>, sorted after
    /// <c>pinUvAuthProtocol</c>) decodes successfully with the unknown member ignored, per CTAP 2.3
    /// section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.RpId);
        writer.WriteTextString("rp.co");
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.ClientDataHash);
        writer.WriteByteString(ClientDataHashBytes);
        writer.WriteInt32(0xFF);
        writer.WriteBoolean(true);
        writer.WriteEndMap();

        CtapGetAssertionRequest decoded = CtapGetAssertionRequestCborReader.Read(writer.Encode(), BaseMemoryPool.Shared);

        try
        {
            Assert.AreEqual("rp.co", decoded.RpId);
        }
        finally
        {
            decoded.ClientDataHash.Dispose();
        }
    }
}
