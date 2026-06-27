using System;
using System.Security.Cryptography;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG15 writer: it mints a DG15 carrying the chip's Active Authentication public key,
/// which round-trips through <see cref="DataGroup15.Parse"/> with the point and curve intact. This is the
/// owned producer for the data the Active Authentication tests read, mirroring <see cref="DataGroup14"/>'s
/// SubjectPublicKeyInfo handling.
/// </summary>
[TestClass]
internal sealed class DataGroup15WriterTests
{
    [TestMethod]
    public void RoundTripsP256ActiveAuthenticationPublicKey()
    {
        byte[] point = BuildUncompressedPoint(coordinateSize: 32, fill: 0x33);
        using EncodedEcPoint publicKey = EncodedEcPoint.FromBytes(point, CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup15 = DataGroup15.Write(publicKey, BaseMemoryPool.Shared);

        Assert.AreEqual(DataGroup15.FileIdentifier, dataGroup15.FileIdentifier, "DG15 is written under file identifier 0x010F.");

        using DataGroup15 parsed = DataGroup15.Parse(dataGroup15.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(parsed.EllipticCurvePublicKey.AsReadOnlySpan()),
            "The Active Authentication public key point must round-trip.");
        Assert.IsTrue(parsed.EllipticCurvePublicKey.Tag.TryGet(out CryptoAlgorithm curve) && curve == CryptoAlgorithm.P256,
            "The curve must round-trip via its named-curve OID.");
    }


    [TestMethod]
    public void RoundTripsBrainpoolP224r1ActiveAuthenticationPublicKey()
    {
        //brainpoolP224r1 is the curve the BSI eMRTD reference chips use; its 28-byte coordinates make a
        //57-byte uncompressed point, exercising the named-curve OID added with the curve.
        byte[] point = BuildUncompressedPoint(coordinateSize: 28, fill: 0x44);
        using EncodedEcPoint publicKey = EncodedEcPoint.FromBytes(point, CryptoTags.BrainpoolP224r1ExchangePublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup15 = DataGroup15.Write(publicKey, BaseMemoryPool.Shared);

        using DataGroup15 parsed = DataGroup15.Parse(dataGroup15.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(parsed.EllipticCurvePublicKey.AsReadOnlySpan()),
            "The brainpoolP224r1 Active Authentication public key point must round-trip.");
        Assert.IsTrue(parsed.EllipticCurvePublicKey.Tag.TryGet(out CryptoAlgorithm curve) && curve == CryptoAlgorithm.BrainpoolP224r1,
            "The brainpoolP224r1 curve must round-trip via its named-curve OID.");
    }


    [TestMethod]
    public void RoundTripsAnRsaActiveAuthenticationPublicKey()
    {
        //A real RSA public key in DER RSAPublicKey form (modulus + exponent), minted with an independent oracle.
        using RSA rsa = RSA.Create(2048);
        byte[] derRsaPublicKey = rsa.ExportRSAPublicKey();

        using RsaPublicKey rsaPublicKey = RsaPublicKey.FromBytes(derRsaPublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup15 = DataGroup15.Write(rsaPublicKey, BaseMemoryPool.Shared);

        Assert.AreEqual(DataGroup15.FileIdentifier, dataGroup15.FileIdentifier, "DG15 is written under file identifier 0x010F.");

        using DataGroup15 parsed = DataGroup15.Parse(dataGroup15.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(ActiveAuthenticationKeyType.Rsa, parsed.KeyType, "DG15 reports the RSA key type.");
        Assert.AreEqual(Convert.ToHexString(derRsaPublicKey), Convert.ToHexString(parsed.RsaPublicKey.AsReadOnlySpan()),
            "The DER RSAPublicKey (modulus and exponent) must round-trip.");
    }


    /// <summary>Builds a SEC1 uncompressed point: <c>0x04</c> then two filler coordinates of the given size.</summary>
    private static byte[] BuildUncompressedPoint(int coordinateSize, byte fill)
    {
        byte[] point = new byte[1 + (2 * coordinateSize)];
        point[0] = 0x04;
        point.AsSpan(1).Fill(fill);

        return point;
    }
}
