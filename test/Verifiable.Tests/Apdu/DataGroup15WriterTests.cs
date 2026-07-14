using System;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

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
        byte[] point = ApduWireFixtures.BuildUncompressedPoint(coordinateSize: 32, fill: 0x33);
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
        byte[] point = ApduWireFixtures.BuildUncompressedPoint(coordinateSize: 28, fill: 0x44);
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
        //A real RSA public key in DER RSAPublicKey form (modulus + exponent) is mere fixture material here: the
        //test proves DG15 round-tripping, not RSA key generation, so the shared provider key's DER encoding
        //(RsaUtilities.Encode's modulus-plus-fixed-65537-exponent SEQUENCE) already matches the wire shape DG15 expects.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> rsaKeyMaterial = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using PublicKeyMemory rsaPublicKeyMemory = rsaKeyMaterial.PublicKey;
        using PrivateKeyMemory rsaPrivateKeyMemory = rsaKeyMaterial.PrivateKey;
        ReadOnlySpan<byte> derRsaPublicKey = rsaPublicKeyMemory.AsReadOnlySpan();

        using RsaPublicKey rsaPublicKey = RsaPublicKey.FromBytes(derRsaPublicKey, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup15 = DataGroup15.Write(rsaPublicKey, BaseMemoryPool.Shared);

        Assert.AreEqual(DataGroup15.FileIdentifier, dataGroup15.FileIdentifier, "DG15 is written under file identifier 0x010F.");

        using DataGroup15 parsed = DataGroup15.Parse(dataGroup15.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(ActiveAuthenticationKeyType.Rsa, parsed.KeyType, "DG15 reports the RSA key type.");
        Assert.AreEqual(Convert.ToHexString(derRsaPublicKey), Convert.ToHexString(parsed.RsaPublicKey.AsReadOnlySpan()),
            "The DER RSAPublicKey (modulus and exponent) must round-trip.");
    }
}
