using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapMakeCredentialResponseCborReader"/>: round-tripping against the paired
/// writer, the two Required-member negatives, and the section 8 forward-compatibility rule that
/// unrecognized member keys are ignored rather than rejected.
/// </summary>
[TestClass]
internal sealed class CtapMakeCredentialResponseCborReaderTests
{
    /// <summary>Rents a pooled fixed 4-byte authData pattern from <see cref="BaseMemoryPool.Shared"/>.</summary>
    /// <returns>A four-byte pooled owner holding the fixed pattern; the caller owns it and must dispose it.</returns>
    private static IMemoryOwner<byte> RentAuthDataBytes()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(4);
        Span<byte> span = owner.Memory.Span[..4];
        span[0] = 0xAA;
        span[1] = 0xBB;
        span[2] = 0xCC;
        span[3] = 0xDD;

        return owner;
    }


    /// <summary>Round-tripping a response with only the Required members recovers them exactly, with <c>attStmt</c> left <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsRequiredMembersOnly()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        ReadOnlyMemory<byte> authData = authDataOwner.Memory[..4];
        var written = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, authData);

        TaggedMemory<byte> encoded = CtapMakeCredentialResponseCborWriter.Write(written);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(encoded.Memory);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, decoded.Fmt);
        Assert.IsTrue(decoded.AuthData.Span.SequenceEqual(authData.Span));
        Assert.IsNull(decoded.AttStmt);
    }


    /// <summary>Round-tripping a response carrying <c>attStmt</c> recovers the attestation statement bytes verbatim.</summary>
    [TestMethod]
    public void RoundTripsWithAttStmt()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        using IMemoryOwner<byte> attStmtOwner = BaseMemoryPool.Shared.Rent(1);
        attStmtOwner.Memory.Span[0] = NoneAttestation.CanonicalEmptyMap;

        var written = new CtapMakeCredentialResponse(
            WellKnownWebAuthnAttestationFormats.None, authDataOwner.Memory[..4], attStmtOwner.Memory[..1]);

        TaggedMemory<byte> encoded = CtapMakeCredentialResponseCborWriter.Write(written);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(encoded.Memory);

        Assert.IsTrue(decoded.AttStmt!.Value.Span.SequenceEqual(new byte[] { NoneAttestation.CanonicalEmptyMap }));
    }


    /// <summary>Round-tripping a response carrying <c>largeBlobKey</c> (<c>0x05</c>, wavelb R8) recovers the 32-byte key verbatim.</summary>
    [TestMethod]
    public void RoundTripsWithLargeBlobKey()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        using IMemoryOwner<byte> largeBlobKeyOwner = BaseMemoryPool.Shared.Rent(32);
        Span<byte> largeBlobKeyBytes = largeBlobKeyOwner.Memory.Span[..32];
        for(int i = 0; i < largeBlobKeyBytes.Length; i++)
        {
            largeBlobKeyBytes[i] = (byte)(0xF0 + (i % 16));
        }

        var written = new CtapMakeCredentialResponse(
            WellKnownWebAuthnAttestationFormats.None, authDataOwner.Memory[..4], AttStmt: null, LargeBlobKey: largeBlobKeyOwner.Memory[..32]);

        TaggedMemory<byte> encoded = CtapMakeCredentialResponseCborWriter.Write(written);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(encoded.Memory);

        Assert.IsNull(decoded.AttStmt);
        Assert.IsTrue(decoded.LargeBlobKey!.Value.Span.SequenceEqual(largeBlobKeyBytes));
    }


    /// <summary>A response missing the Required <c>fmt</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenFmtMemberIsMissing()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.AuthData);
        writer.WriteByteString(authDataOwner.Memory.Span[..4]);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialResponseCborReader.Read(writer.Encode()));

        Assert.Contains("fmt", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A response missing the Required <c>authData</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenAuthDataMemberIsMissing()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.Fmt);
        writer.WriteTextString(WellKnownWebAuthnAttestationFormats.None);
        writer.WriteEndMap();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapMakeCredentialResponseCborReader.Read(writer.Encode()));

        Assert.Contains("authData", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A <c>fmt</c> encoded as a byte string rather than the required text string is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenFmtHasWrongCborType()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.Fmt);
        writer.WriteByteString([0x01]);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.AuthData);
        writer.WriteByteString(authDataOwner.Memory.Span[..4]);
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapMakeCredentialResponseCborReader.Read(writer.Encode()));
    }


    /// <summary>A payload carrying the same top-level key twice is rejected.</summary>
    [TestMethod]
    public void ThrowsOnDuplicateTopLevelKey()
    {
        //Hand-built rather than produced by CborWriter (which enforces canonical key ordering at write
        //time and would refuse to emit this): {1: h'', 1: h''} — a duplicate top-level key.
        byte[] duplicateKeyMap = [0xA2, 0x01, 0x40, 0x01, 0x40];

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapMakeCredentialResponseCborReader.Read(duplicateKeyMap));
    }


    /// <summary>An indefinite-length top-level map is rejected, per the CTAP2 canonical CBOR encoding form.</summary>
    [TestMethod]
    public void ThrowsOnIndefiniteLengthTopLevelMap()
    {
        //Major type 5 (map) with additional info 31 (indefinite length), one entry, then the break byte.
        byte[] indefiniteLengthMap = [0xBF, 0x01, 0x40, 0xFF];

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapMakeCredentialResponseCborReader.Read(indefiniteLengthMap));
    }


    /// <summary>
    /// A response carrying an unrecognized member key (here <c>0x06</c>, the not-modeled
    /// <c>unsignedExtensionOutputs</c>) decodes successfully with the unknown member ignored, per CTAP
    /// 2.3 section 8's forward-compatibility rule. <c>epAtt</c> (<c>0x04</c>) IS modeled from waveep
    /// on (see <see cref="RoundTripsWithEpAttTrue"/>), so it no longer serves as this test's example.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.Fmt);
        writer.WriteTextString(WellKnownWebAuthnAttestationFormats.None);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.AuthData);
        writer.WriteByteString(authDataOwner.Memory.Span[..4]);
        writer.WriteInt32(WellKnownCtapMakeCredentialResponseKeys.UnsignedExtensionOutputs);
        writer.WriteBoolean(true);
        writer.WriteEndMap();

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(writer.Encode());

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, decoded.Fmt);
    }


    /// <summary>
    /// Round-tripping a response carrying <c>epAtt: true</c> (<c>0x04</c>, waveep R9) recovers the
    /// boolean value exactly — the enterprise-attestation-granted encoding.
    /// </summary>
    [TestMethod]
    public void RoundTripsWithEpAttTrue()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        var written = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.Packed, authDataOwner.Memory[..4], EpAtt: true);

        TaggedMemory<byte> encoded = CtapMakeCredentialResponseCborWriter.Write(written);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(encoded.Memory);

        Assert.IsTrue(decoded.EpAtt!.Value, "epAtt: true must round-trip exactly.");
    }


    /// <summary>
    /// Round-tripping a response carrying an EXPLICIT <c>epAtt: false</c> recovers present-false, not
    /// absence — the codec faithfulness half of trap 18: this authenticator itself never emits an
    /// explicit false (see <c>CtapAuthenticatorSimulator</c>'s response-build site), but the CODEC must
    /// still round-trip a foreign one exactly, since both encodings are spec-legal for "not returned"
    /// (CTAP 2.3 lines 3623-3625).
    /// </summary>
    [TestMethod]
    public void RoundTripsWithEpAttFalseFaithfully()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        var written = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.Packed, authDataOwner.Memory[..4], EpAtt: false);

        TaggedMemory<byte> encoded = CtapMakeCredentialResponseCborWriter.Write(written);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(encoded.Memory);

        Assert.IsTrue(decoded.EpAtt.HasValue, "an explicit epAtt: false must round-trip as present-false, not absence.");
        Assert.IsFalse(decoded.EpAtt!.Value);
    }


    /// <summary>
    /// Round-tripping a response carrying <c>attStmt</c>, <c>epAtt</c>, AND <c>largeBlobKey</c> together
    /// (the genuinely reachable "enterprise-attested resident credential with a largeBlobKey" combination,
    /// trap 2/5) recovers all three members exactly, proving the reader's key-order-independent decode
    /// loop handles the full three-optional-member case.
    /// </summary>
    [TestMethod]
    public void RoundTripsWithAttStmtEpAttAndLargeBlobKeyTogether()
    {
        using IMemoryOwner<byte> authDataOwner = RentAuthDataBytes();
        using IMemoryOwner<byte> attStmtOwner = BaseMemoryPool.Shared.Rent(1);
        attStmtOwner.Memory.Span[0] = NoneAttestation.CanonicalEmptyMap;

        using IMemoryOwner<byte> largeBlobKeyOwner = BaseMemoryPool.Shared.Rent(32);
        Span<byte> largeBlobKeyBytes = largeBlobKeyOwner.Memory.Span[..32];
        for(int i = 0; i < largeBlobKeyBytes.Length; i++)
        {
            largeBlobKeyBytes[i] = (byte)(0xE0 + (i % 16));
        }

        var written = new CtapMakeCredentialResponse(
            WellKnownWebAuthnAttestationFormats.Packed, authDataOwner.Memory[..4], attStmtOwner.Memory[..1], EpAtt: true, LargeBlobKey: largeBlobKeyOwner.Memory[..32]);

        TaggedMemory<byte> encoded = CtapMakeCredentialResponseCborWriter.Write(written);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(encoded.Memory);

        Assert.IsTrue(decoded.AttStmt!.Value.Span.SequenceEqual(new byte[] { NoneAttestation.CanonicalEmptyMap }));
        Assert.IsTrue(decoded.EpAtt!.Value);
        Assert.IsTrue(decoded.LargeBlobKey!.Value.Span.SequenceEqual(largeBlobKeyBytes));
    }
}
