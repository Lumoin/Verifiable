using SimpleBase;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Pins the honest-tag invariant on the base58/multicodec decode path: a NIST EC public key encoded as a
/// did:key base58btc multicodec multibase string decodes through
/// <see cref="CryptoFormatConversions.DefaultBase58ToAlgorithmConverter"/> to its expected curve AND carries
/// <see cref="EncodingScheme.EcCompressed"/> — the multicodec EC encoding is a compressed SEC1 point, so the
/// returned tag MUST say so. Downstream NIST key agreement relies on this tag to decide it must decompress the
/// resolved point before slicing.
/// </summary>
[TestClass]
internal sealed class CryptoFormatConversionsBase58EncodingSchemeTests
{
    [TestMethod]
    public void P256MulticodecDecodesToCompressedEcKey()
    {
        AssertNistMulticodecKeyTaggedCompressed(EllipticCurveTheoryData.EllipticP256, CryptoAlgorithm.P256);
    }


    [TestMethod]
    public void P384MulticodecDecodesToCompressedEcKey()
    {
        AssertNistMulticodecKeyTaggedCompressed(EllipticCurveTheoryData.EllipticP384, CryptoAlgorithm.P384);
    }


    [TestMethod]
    public void P521MulticodecDecodesToCompressedEcKey()
    {
        AssertNistMulticodecKeyTaggedCompressed(EllipticCurveTheoryData.EllipticP521, CryptoAlgorithm.P521);
    }


    //Builds a base58btc multicodec multibase public key string for the given NIST curve from generated test
    //key material (the compressed SEC1 point under the curve's public-key multicodec header), decodes it via
    //DefaultBase58ToAlgorithmConverter, and asserts the resolved curve and the EcCompressed scheme.
    private static void AssertNistMulticodecKeyTaggedCompressed(string humanReadableCurve, CryptoAlgorithm expectedAlgorithm)
    {
        EllipticCurveTestData testData = GetTestData(humanReadableCurve);

        byte[] compressed = EllipticCurveUtilities.Compress(testData.PublicKeyMaterialX, testData.PublicKeyMaterialY);

        string multibaseKey = MultibaseSerializer.Encode(
            compressed,
            testData.PublicKeyMulticodecHeader,
            MultibaseAlgorithms.Base58Btc,
            Base58.Bitcoin.Encode);

        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
            CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(multibaseKey, BaseMemoryPool.Shared, TestSetup.Base58Decoder);

        try
        {
            Assert.AreEqual(expectedAlgorithm, algorithm, "The multicodec header MUST resolve to the expected NIST curve.");
            Assert.AreEqual(Purpose.Verification, purpose);
            Assert.AreEqual(EncodingScheme.EcCompressed, scheme,
                "A NIST EC multicodec public key is a compressed SEC1 point, so the decoded tag MUST be EcCompressed.");
            Assert.IsNotNull(keyMaterial);
            Assert.IsTrue(keyMaterial.Memory.Span.SequenceEqual(compressed),
                "The decoded key material MUST be the compressed SEC1 point carried by the multicodec encoding.");
        }
        finally
        {
            keyMaterial.Dispose();
        }
    }


    //Returns the even-Y generated test key material for the given curve from the shared theory-data generator.
    private static EllipticCurveTestData GetTestData(string humanReadableCurve)
    {
        foreach(object[] row in EllipticCurveTheoryData.GetEllipticCurveTestData())
        {
            if(row[0] is EllipticCurveTestData candidate && candidate.CurveIdentifier == humanReadableCurve)
            {
                return candidate;
            }
        }

        throw new NotSupportedException($"No generated test data for curve {humanReadableCurve}.");
    }
}
