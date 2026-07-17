using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Direct tests of <see cref="CtapCommandEntityCborCodec"/>, the shared nested-entity CBOR codec every
/// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>/<c>authenticatorCredentialManagement</c>
/// reader/writer composes: the CTAP2 canonical integer-width bands (TORN rows 8709/8712/8715/8725) and
/// the <c>icon</c> forward-compatibility tolerance (TORN rows, spec line 2912's MAY/MUST-NOT pair).
/// </summary>
[TestClass]
internal sealed class CtapCommandEntityCborCodecTests
{
    /// <summary>
    /// TORN row 8709: an <c>alg</c> value in [24, 255] (100) is written as the exact 2-byte
    /// <c>0x18 0x64</c> form — RFC 8949 §4.2.1's minimal-width rule for this band, hand-verified against
    /// the byte offset <see cref="CtapCommandEntityCborCodec.WriteParameters"/>'s own fixed member order
    /// (<c>alg</c> then <c>type</c>) places it at: <c>0xA2 0x63 'a' 'l' 'g'</c> (5 bytes) precedes the
    /// integer.
    /// </summary>
    [TestMethod]
    public void WriteParametersEncodesAlgIn24To255BandAsExactTwoByteForm()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        var parameters = new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = 100 };
        CtapCommandEntityCborCodec.WriteParameters(writer, parameters);
        byte[] encoded = writer.Encode();

        Assert.AreEqual(0x18, encoded[5]);
        Assert.AreEqual(0x64, encoded[6]);

        PublicKeyCredentialParameters decoded = CtapCommandEntityCborCodec.ReadParameters(new CborReader(encoded, CborConformanceMode.Ctap2Canonical));
        Assert.AreEqual(100, decoded.Alg);
    }


    /// <summary>
    /// TORN row 8712: an <c>alg</c> value in [256, 65535] (1000) is written as the exact 3-byte
    /// <c>0x19 0x03 0xE8</c> form.
    /// </summary>
    [TestMethod]
    public void WriteParametersEncodesAlgIn256To65535BandAsExactThreeByteForm()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        var parameters = new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = 1000 };
        CtapCommandEntityCborCodec.WriteParameters(writer, parameters);
        byte[] encoded = writer.Encode();

        Assert.AreEqual(0x19, encoded[5]);
        Assert.AreEqual(0x03, encoded[6]);
        Assert.AreEqual(0xE8, encoded[7]);

        PublicKeyCredentialParameters decoded = CtapCommandEntityCborCodec.ReadParameters(new CborReader(encoded, CborConformanceMode.Ctap2Canonical));
        Assert.AreEqual(1000, decoded.Alg);
    }


    /// <summary>
    /// TORN row 8715: an <c>alg</c> value in [65536, 4294967295] (100000) is written as the exact 5-byte
    /// <c>0x1A 0x00 0x01 0x86 0xA0</c> form.
    /// </summary>
    [TestMethod]
    public void WriteParametersEncodesAlgIn65536To4294967295BandAsExactFiveByteForm()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        var parameters = new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = 100000 };
        CtapCommandEntityCborCodec.WriteParameters(writer, parameters);
        byte[] encoded = writer.Encode();

        Assert.AreEqual(0x1A, encoded[5]);
        Assert.AreEqual(0x00, encoded[6]);
        Assert.AreEqual(0x01, encoded[7]);
        Assert.AreEqual(0x86, encoded[8]);
        Assert.AreEqual(0xA0, encoded[9]);

        PublicKeyCredentialParameters decoded = CtapCommandEntityCborCodec.ReadParameters(new CborReader(encoded, CborConformanceMode.Ctap2Canonical));
        Assert.AreEqual(100000, decoded.Alg);
    }


    /// <summary>
    /// TORN row 8725: a 24-element <c>PublicKeyCredentialParameters</c> array's own length prefix is the
    /// exact 2-byte <c>0x98 0x18</c> form (major type 4, additional-info 24, followed by the literal
    /// count byte <c>0x18</c> = 24) — not a longer form, and not the 1-byte immediate form small counts
    /// use.
    /// </summary>
    [TestMethod]
    public void WriteParametersArrayEncodesTwentyFourElementLengthAsExactTwoByteForm()
    {
        var entries = new List<PublicKeyCredentialParameters>();
        for(int i = 0; i < 24; i++)
        {
            entries.Add(new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 });
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        CtapCommandEntityCborCodec.WriteParametersArray(writer, entries);
        byte[] encoded = writer.Encode();

        Assert.AreEqual(0x98, encoded[0]);
        Assert.AreEqual(0x18, encoded[1]);

        List<PublicKeyCredentialParameters> decoded = CtapCommandEntityCborCodec.ReadParametersArray(new CborReader(encoded, CborConformanceMode.Ctap2Canonical));
        Assert.HasCount(24, decoded);
    }


    /// <summary>
    /// TORN rows (spec line 2912, both the MAY and MUST-NOT halves of "Authenticators MUST NOT error if
    /// the icon member is present, they MAY not store this value"): an <c>rp</c>/<c>user</c> entity CBOR
    /// map carrying an unrecognized <c>icon</c> member alongside the required <c>id</c> decodes without
    /// throwing (the MUST-NOT-error half), and <see cref="CtapPublicKeyCredentialRpEntity"/>/
    /// <see cref="CtapPublicKeyCredentialUserEntity"/> expose no icon-shaped member at all to store one
    /// into (the MAY-not-store half, proven by the type's own structural absence combined with the
    /// no-throw assertion, exactly as the closing proposal for these rows describes).
    /// </summary>
    [TestMethod]
    public void ReadRpAndUserEntityToleratesUnrecognizedIconMemberAlongsideRequiredId()
    {
        //Canonical CBOR map-key order is length-first: "id" (2 chars) precedes "icon" (4 chars)
        //regardless of content, so both maps below write "id" first.
        var rpWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        rpWriter.WriteStartMap(2);
        rpWriter.WriteTextString("id");
        rpWriter.WriteTextString("waveclose-icon.example");
        rpWriter.WriteTextString("icon");
        rpWriter.WriteTextString("https://example.com/icon.png");
        rpWriter.WriteEndMap();

        CtapPublicKeyCredentialRpEntity rp = CtapCommandEntityCborCodec.ReadRpEntity(new CborReader(rpWriter.Encode(), CborConformanceMode.Ctap2Canonical));
        Assert.AreEqual("waveclose-icon.example", rp.Id);

        var userWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        userWriter.WriteStartMap(2);
        userWriter.WriteTextString("id");
        userWriter.WriteByteString([0x01, 0x02, 0x03]);
        userWriter.WriteTextString("icon");
        userWriter.WriteTextString("https://example.com/user-icon.png");
        userWriter.WriteEndMap();

        CtapPublicKeyCredentialUserEntity user = CtapCommandEntityCborCodec.ReadUserEntity(
            new CborReader(userWriter.Encode(), CborConformanceMode.Ctap2Canonical), BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual(3, user.Id.AsReadOnlySpan().Length);
        }
        finally
        {
            user.Id.Dispose();
        }
    }
}
