using System;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates EF.DG14 parsing: the SET OF SecurityInfo is walked, the ChipAuthenticationInfo (key
/// agreement, cipher, version, key id) and ChipAuthenticationPublicKeyInfo (the chip's static ECDH
/// public key and its curve) are extracted, other SecurityInfos are skipped, and the curve is resolved
/// from both a named-curve OID and explicit domain parameters. Synthetic SecurityInfos are used so the
/// test is owned and committable; the BSI ReferenceDataSet DG14 is a local-only real-data cross-check.
/// </summary>
[TestClass]
internal sealed class DataGroup14Tests
{
    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ParsesChipAuthenticationInfoAndPublicKeyWithNamedCurve()
    {
        byte[] point = BuildUncompressedPoint(0x11);
        byte[] dataGroup14 = Tlv(0x6E, Tlv(0x31,
            ChipAuthenticationInfoSecurityInfo("04007F00070202030202", version: 1),
            ChipAuthenticationPublicKeyInfoSecurityInfo(NamedCurveAlgorithmIdentifier("2B2403030208010107"), point),
            TerminalAuthenticationInfoSecurityInfo()));

        using DataGroup14 parsed = DataGroup14.Parse(dataGroup14, BaseMemoryPool.Shared);

        Assert.HasCount(1, parsed.ChipAuthenticationInfos, "Exactly one ChipAuthenticationInfo is present.");
        ChipAuthenticationInfo info = parsed.ChipAuthenticationInfos[0];
        Assert.IsTrue(info.IsEllipticCurve, "id-CA-ECDH-* is an elliptic-curve protocol.");
        Assert.AreEqual(ChipAuthenticationCipher.Aes128, info.Cipher, "The OID arc 0x02 selects AES-128.");
        Assert.AreEqual(1, info.Version, "The version is 1.");
        Assert.IsNull(info.KeyId, "A single-key chip omits the key identifier.");

        Assert.HasCount(1, parsed.ChipAuthenticationPublicKeyInfos, "Exactly one ChipAuthenticationPublicKeyInfo is present.");
        ChipAuthenticationPublicKeyInfo publicKeyInfo = parsed.ChipAuthenticationPublicKeyInfos[0];
        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(publicKeyInfo.PublicKey.AsReadOnlySpan()),
            "The extracted public key must equal the SubjectPublicKeyInfo point.");
        Assert.IsTrue(publicKeyInfo.PublicKey.Tag.TryGet(out CryptoAlgorithm curve), "The public key carries a curve algorithm.");
        Assert.IsTrue(curve == CryptoAlgorithm.BrainpoolP256r1, "The named-curve OID resolves to brainpoolP256r1.");
        Assert.IsNull(publicKeyInfo.KeyId, "A single-key chip omits the key identifier.");
    }


    [TestMethod]
    public void ResolvesCurveFromExplicitDomainParametersAndDecodesTripleDes()
    {
        //Mirrors the real BSI sample DG14 shape: explicit prime-field domain parameters and a
        //3DES Chip Authentication protocol (id-CA-ECDH-3DES-CBC-CBC, OID arc 0x01).
        byte[] point = BuildUncompressedPoint(0x22);
        byte[] dataGroup14 = Tlv(0x6E, Tlv(0x31,
            ChipAuthenticationPublicKeyInfoSecurityInfo(ExplicitP256AlgorithmIdentifier(), point),
            ChipAuthenticationInfoSecurityInfo("04007F00070202030201", version: 1)));

        using DataGroup14 parsed = DataGroup14.Parse(dataGroup14, BaseMemoryPool.Shared);

        Assert.AreEqual(ChipAuthenticationCipher.TripleDes, parsed.ChipAuthenticationInfos[0].Cipher, "The OID arc 0x01 selects Triple-DES.");

        ChipAuthenticationPublicKeyInfo publicKeyInfo = parsed.ChipAuthenticationPublicKeyInfos[0];
        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(publicKeyInfo.PublicKey.AsReadOnlySpan()),
            "The point must be located after the explicit domain parameters.");
        Assert.IsTrue(publicKeyInfo.PublicKey.Tag.TryGet(out CryptoAlgorithm curve), "The public key carries a curve algorithm.");
        Assert.IsTrue(curve == CryptoAlgorithm.P256, "The explicit prime resolves to NIST P-256.");
    }


    [TestMethod]
    public void RejectsDataWithoutTheDataGroup14Template()
    {
        byte[] notDataGroup14 = Convert.FromHexString("6105310300000A");

        bool threw = false;
        try
        {
            using DataGroup14 _ = DataGroup14.Parse(notDataGroup14, BaseMemoryPool.Shared);
        }
        catch(InvalidOperationException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "Parsing must reject data that is not a DG14 template.");
    }


    /// <summary>Builds a 65-byte SEC1 uncompressed P-256/brainpoolP256r1 point: <c>0x04</c> then 64 filler bytes.</summary>
    private static byte[] BuildUncompressedPoint(byte fill)
    {
        byte[] point = new byte[65];
        point[0] = 0x04;
        point.AsSpan(1).Fill(fill);

        return point;
    }


    /// <summary>Builds a ChipAuthenticationInfo SecurityInfo: <c>SEQUENCE { OID, version }</c>.</summary>
    private static byte[] ChipAuthenticationInfoSecurityInfo(string oidHex, int version)
    {
        return Tlv(0x30, Tlv(0x06, Convert.FromHexString(oidHex)), Tlv(0x02, [(byte)version]));
    }


    /// <summary>Builds a ChipAuthenticationPublicKeyInfo SecurityInfo: <c>SEQUENCE { id-PK-ECDH, SubjectPublicKeyInfo }</c>.</summary>
    private static byte[] ChipAuthenticationPublicKeyInfoSecurityInfo(byte[] algorithmIdentifier, byte[] point)
    {
        byte[] subjectPublicKeyInfo = Tlv(0x30, algorithmIdentifier, Tlv(0x03, Concat([0x00], point)));

        return Tlv(0x30, Tlv(0x06, Convert.FromHexString("04007F000702020102")), subjectPublicKeyInfo);
    }


    /// <summary>Builds an AlgorithmIdentifier with a named-curve OID: <c>SEQUENCE { id-ecPublicKey, namedCurveOid }</c>.</summary>
    private static byte[] NamedCurveAlgorithmIdentifier(string namedCurveOidHex)
    {
        return Tlv(0x30, Tlv(0x06, Convert.FromHexString("2A8648CE3D0201")), Tlv(0x06, Convert.FromHexString(namedCurveOidHex)));
    }


    /// <summary>
    /// Builds an AlgorithmIdentifier with explicit NIST P-256 prime-field domain parameters. Only the
    /// prime is canonical (the curve/base/order/cofactor are placeholders the parser skips by length).
    /// </summary>
    private static byte[] ExplicitP256AlgorithmIdentifier()
    {
        byte[] prime = Concat([0x00], EllipticCurveConstants.P256.PrimeBytes.ToArray());
        byte[] fieldId = Tlv(0x30, Tlv(0x06, Convert.FromHexString("2A8648CE3D0101")), Tlv(0x02, prime));
        byte[] curve = Tlv(0x30, Tlv(0x04, [0x00]), Tlv(0x04, [0x07]));
        byte[] ecParameters = Tlv(0x30,
            Tlv(0x02, [0x01]), fieldId, curve, Tlv(0x04, [0x04]), Tlv(0x02, [0x01]), Tlv(0x02, [0x01]));

        return Tlv(0x30, Tlv(0x06, Convert.FromHexString("2A8648CE3D0201")), ecParameters);
    }


    /// <summary>Builds a TerminalAuthenticationInfo SecurityInfo (id-TA, version 1) — extracted by no consumer here.</summary>
    private static byte[] TerminalAuthenticationInfoSecurityInfo()
    {
        return Tlv(0x30, Tlv(0x06, Convert.FromHexString("04007F0007020202")), Tlv(0x02, [0x01]));
    }


    /// <summary>Wraps the concatenation of <paramref name="content"/> in a BER-TLV element (definite length).</summary>
    private static byte[] Tlv(int tag, params byte[][] content)
    {
        byte[] body = Concat(content);
        byte[] tagBytes = tag > 0xFF ? [(byte)(tag >> 8), (byte)tag] : [(byte)tag];
        byte[] length = EncodeLength(body.Length);

        return Concat(tagBytes, length, body);
    }


    /// <summary>Encodes a BER-TLV definite length (short form, or long form with 0x81 / 0x82).</summary>
    private static byte[] EncodeLength(int length)
    {
        if(length <= 0x7F) { return [(byte)length]; }
        if(length <= 0xFF) { return [0x81, (byte)length]; }

        return [0x82, (byte)(length >> 8), (byte)length];
    }


    /// <summary>Concatenates byte arrays.</summary>
    private static byte[] Concat(params byte[][] arrays)
    {
        int length = 0;
        foreach(byte[] a in arrays) { length += a.Length; }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] a in arrays)
        {
            a.CopyTo(result, offset);
            offset += a.Length;
        }

        return result;
    }
}
