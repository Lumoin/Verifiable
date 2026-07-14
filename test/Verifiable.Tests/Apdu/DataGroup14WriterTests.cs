using System;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG14 writer: it mints a DG14 announcing one ECDH Chip Authentication protocol and
/// one static public key, which round-trips through <see cref="DataGroup14.Parse"/> with the point,
/// curve, cipher, version, and key identifier intact. This is the owned producer for the data the Chip
/// Authentication tests read.
/// </summary>
[TestClass]
internal sealed class DataGroup14WriterTests
{
    [TestMethod]
    public void RoundTripsChipAuthenticationInfoAndKey()
    {
        byte[] point = ApduWireFixtures.BuildUncompressedPoint(0x11);
        using EncodedEcPoint chipPublicKey = EncodedEcPoint.FromBytes(point, CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup14 = DataGroup14.Write(chipPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);

        using DataGroup14 parsed = DataGroup14.Parse(dataGroup14.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.HasCount(1, parsed.ChipAuthenticationPublicKeyInfos, "One ChipAuthenticationPublicKeyInfo.");
        ChipAuthenticationPublicKeyInfo publicKeyInfo = parsed.ChipAuthenticationPublicKeyInfos[0];
        Assert.AreEqual(Convert.ToHexString(point), Convert.ToHexString(publicKeyInfo.PublicKey.AsReadOnlySpan()),
            "The chip public key point must round-trip.");
        Assert.IsTrue(publicKeyInfo.PublicKey.Tag.TryGet(out CryptoAlgorithm curve) && curve == CryptoAlgorithm.BrainpoolP256r1,
            "The curve must round-trip via its named-curve OID.");
        Assert.IsNull(publicKeyInfo.KeyId, "A single-key chip omits the key identifier.");

        Assert.HasCount(1, parsed.ChipAuthenticationInfos, "One ChipAuthenticationInfo.");
        ChipAuthenticationInfo info = parsed.ChipAuthenticationInfos[0];
        Assert.IsTrue(info.IsEllipticCurve, "id-CA-ECDH-* is elliptic-curve.");
        Assert.AreEqual(ChipAuthenticationCipher.Aes128, info.Cipher, "The cipher must round-trip.");
        Assert.AreEqual(1, info.Version, "The version must round-trip.");
        Assert.IsNull(info.KeyId, "A single-key chip omits the key identifier.");
    }


    [TestMethod]
    public void RoundTripsTripleDesWithKeyIdentifier()
    {
        byte[] point = ApduWireFixtures.BuildUncompressedPoint(0x22);
        using EncodedEcPoint chipPublicKey = EncodedEcPoint.FromBytes(point, CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup14 = DataGroup14.Write(chipPublicKey, ChipAuthenticationCipher.TripleDes, version: 1, keyId: 5, BaseMemoryPool.Shared);

        using DataGroup14 parsed = DataGroup14.Parse(dataGroup14.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(ChipAuthenticationCipher.TripleDes, parsed.ChipAuthenticationInfos[0].Cipher, "Triple-DES cipher must round-trip.");
        Assert.AreEqual(5, parsed.ChipAuthenticationInfos[0].KeyId, "The ChipAuthenticationInfo key id must round-trip.");
        Assert.AreEqual(5, parsed.ChipAuthenticationPublicKeyInfos[0].KeyId, "The ChipAuthenticationPublicKeyInfo key id must round-trip.");
    }
}
