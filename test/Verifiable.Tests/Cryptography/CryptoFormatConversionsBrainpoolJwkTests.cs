using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// JWK round-trip tests for the four Brainpool r1 curves through
/// <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/> →
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>.
/// </summary>
/// <remarks>
/// <para>
/// The emission path runs the stored compressed public key through
/// <see cref="EllipticCurveUtilities.ExtractCoordinates"/>, which dispatches
/// to <see cref="EllipticCurveUtilities.Decompress"/> for Brainpool — so this
/// suite exercises the Q.2.X math end-to-end. The crv string matches the
/// BouncyCastle / RFC 5639 curve name (e.g., <c>brainpoolP256r1</c>).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CryptoFormatConversionsBrainpoolJwkTests
{
    [TestMethod]
    public void BrainpoolP256r1RoundTripsThroughJwkAndBack()
    {
        AssertJwkRoundTripsToOriginalAlgorithm(
            TestKeyMaterialProvider.CreateBrainpoolP256r1KeyMaterial(),
            CryptoAlgorithm.BrainpoolP256r1,
            WellKnownCurveValues.BrainpoolP256r1,
            WellKnownJwaValues.Esb256);
    }


    [TestMethod]
    public void BrainpoolP320r1RoundTripsThroughJwkAndBack()
    {
        AssertJwkRoundTripsToOriginalAlgorithm(
            TestKeyMaterialProvider.CreateBrainpoolP320r1KeyMaterial(),
            CryptoAlgorithm.BrainpoolP320r1,
            WellKnownCurveValues.BrainpoolP320r1,
            WellKnownJwaValues.Esb320);
    }


    [TestMethod]
    public void BrainpoolP384r1RoundTripsThroughJwkAndBack()
    {
        AssertJwkRoundTripsToOriginalAlgorithm(
            TestKeyMaterialProvider.CreateBrainpoolP384r1KeyMaterial(),
            CryptoAlgorithm.BrainpoolP384r1,
            WellKnownCurveValues.BrainpoolP384r1,
            WellKnownJwaValues.Esb384);
    }


    [TestMethod]
    public void BrainpoolP512r1RoundTripsThroughJwkAndBack()
    {
        AssertJwkRoundTripsToOriginalAlgorithm(
            TestKeyMaterialProvider.CreateBrainpoolP512r1KeyMaterial(),
            CryptoAlgorithm.BrainpoolP512r1,
            WellKnownCurveValues.BrainpoolP512r1,
            WellKnownJwaValues.Esb512);
    }


    private static void AssertJwkRoundTripsToOriginalAlgorithm(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial,
        CryptoAlgorithm expectedAlgorithm,
        string expectedCrv,
        string expectedAlg)
    {
        try
        {
            //Emit the public key as a JWK. The converter takes the compressed
            //SEC1 storage tagged with EncodingScheme.EcCompressed and produces
            //the JWK {kty, crv, alg, x, y} object expected by RFC 7518.
            JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                expectedAlgorithm,
                Purpose.Verification,
                keyMaterial.PublicKey.AsReadOnlySpan(),
                TestSetup.Base64UrlEncoder);

            Assert.AreEqual(WellKnownKeyTypeValues.Ec, jwk.Kty);
            Assert.AreEqual(expectedCrv, jwk.Crv);
            Assert.AreEqual(expectedAlg, jwk.Alg);
            Assert.IsNotNull(jwk.X);
            Assert.IsNotNull(jwk.Y);

            //Round-trip back via DefaultJwkToAlgorithmConverter — it must
            //resolve the Brainpool crv string to the original CryptoAlgorithm.
            var jwkDictionary = new Dictionary<string, object>
            {
                [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
                [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
                [WellKnownJwkMemberNames.Alg] = jwk.Alg!,
                [WellKnownJwkMemberNames.X] = jwk.X!,
                [WellKnownJwkMemberNames.Y] = jwk.Y!
            };

            (CryptoAlgorithm roundTrippedAlgorithm, Purpose roundTrippedPurpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterialOwner) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                    jwkDictionary,
                    BaseMemoryPool.Shared,
                    TestSetup.Base64UrlDecoder);

            try
            {
                Assert.AreEqual(expectedAlgorithm, roundTrippedAlgorithm,
                    "JWK crv resolution must return the Brainpool algorithm we started with.");
                Assert.AreEqual(Purpose.Verification, roundTrippedPurpose);
                Assert.AreEqual(EncodingScheme.EcCompressed, scheme);

                //The compressed form produced by the round-trip must match the
                //original — proving the JWK {x, y} → compressed SEC1 path round-trips
                //through the Brainpool decompression math added in Q.2.X.
                Assert.IsTrue(
                    keyMaterialOwner.Memory.Span.SequenceEqual(keyMaterial.PublicKey.AsReadOnlySpan()),
                    "Compressed key material recovered from JWK x/y must match the original compressed public key.");
            }
            finally
            {
                keyMaterialOwner.Dispose();
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }
}
