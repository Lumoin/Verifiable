using System.Reflection;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.DataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for Elliptic curve utilities.
    /// </summary>
    [TestClass]
    public sealed class EllipticCurveUtilitiesTests
    {
        /// <summary>
        /// Some elliptic curve exceptions need to contain this parameter name, so that
        /// the source and reason of the exception are clearer.
        /// </summary>
        private const string XParameterNameInExceptionMessage = "xPoint";

        /// <summary>
        /// Some elliptic curve exceptions need to contain this parameter name, so that
        /// the source and reason of the exception are clearer.
        /// </summary>
        private const string YParameterNameInExceptionMessage = "yPoint";


        [TestMethod]
        public void PrimeCurveCompressThrowsWithCorrectMessageIfEitherOrBothParametersNull()
        {
            using(var key = ECDsa.Create())
            {
                var keyParams = key.ExportParameters(includePrivateParameters: false);

                var exception1 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(null, keyParams.Q.Y));
                Assert.AreEqual(XParameterNameInExceptionMessage, exception1.ParamName);

                var exception2 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams.Q.X, null));
                Assert.AreEqual(YParameterNameInExceptionMessage, exception2.ParamName);

                var exception3 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(null, null));
                Assert.AreEqual(XParameterNameInExceptionMessage, exception3.ParamName);
            }
        }


        [TestMethod]
        public void CompressThrowsWithCorrectMessageIfPointsDifferentLength()
        {
            using(var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                using(var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                {
                    var keyParams1 = key1.ExportParameters(includePrivateParameters: false);
                    var keyParams2 = key2.ExportParameters(includePrivateParameters: false);

                    const string ExceptionMessage = $"Parameters '{XParameterNameInExceptionMessage}' and '{YParameterNameInExceptionMessage}' need to be of the same length.";
                    var exception = Assert.ThrowsExactly<ArgumentException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!, keyParams2.Q.Y));
                    Assert.AreEqual(ExceptionMessage, exception.Message);
                }
            }
        }


        [TestMethod]
        public void CompressThrowsWithCorrectMessageIfPointsWrongLength()
        {
            using(var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var keyParams1 = key1.ExportParameters(includePrivateParameters: false);

                string xPointExceptionMessage = $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'. (Parameter 'xPoint')";
                var xException = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!.Concat(new byte[] { 0x00 }).ToArray(), keyParams1.Q.Y));
                Assert.AreEqual(XParameterNameInExceptionMessage, xException.ParamName);
                Assert.AreEqual(xPointExceptionMessage, xException.Message);

                string yPointExceptionMessage = $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'. (Parameter 'yPoint')";
                var yException = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!, keyParams1.Q.Y!.Concat(new byte[] { 0x00 }).ToArray()));
                Assert.AreEqual(YParameterNameInExceptionMessage, yException.ParamName);
                Assert.AreEqual(yPointExceptionMessage, yException.Message);
            }
        }

        [TestMethod]
        [DynamicData(nameof(EllipticCurveTheoryData.GetEllipticCurveTestData), typeof(EllipticCurveTheoryData))]
        public void PrimeCurvesRoundtripCompressAndDecompressSucceeds(EllipticCurveTestCase testCase)
        {
            if(OperatingSystem.IsMacOS() && testCase.CurveIdentifier == CryptoAlgorithm.Secp256k1)
            {
                return; // The secP256k1 curve is not supported on macOS.
            }

            var td = EllipticCurveTheoryData.CreateEllipticCurveTestData(testCase);
            var curveType = td.CurveIdentifier == CryptoAlgorithm.Secp256k1
                ? EllipticCurveTypes.Secp256k1
                : EllipticCurveTypes.NistCurves;

            byte[] evenCompressedPoint = EllipticCurveUtilities.Compress(td.PublicKeyMaterialX, td.PublicKeyMaterialY);
            byte[] evenUncompressedY = EllipticCurveUtilities.Decompress(evenCompressedPoint, curveType);
            CollectionAssert.AreEqual(td.PublicKeyMaterialY, evenUncompressedY);
        }

        [TestMethod]
        [DynamicData(nameof(EllipticCurveTheoryData.GetEllipticCurveTestData), typeof(EllipticCurveTheoryData))]
        public void EllipticPointOnCurveCheckSucceeds(EllipticCurveTestCase testCase)
        {
            if(OperatingSystem.IsMacOS() && testCase.CurveIdentifier == CryptoAlgorithm.Secp256k1)
            {
                return; // The secP256k1 curve is not supported on macOS.
            }

            var td = EllipticCurveTheoryData.CreateEllipticCurveTestData(testCase);

            ReadOnlySpan<byte> primeBytes = td.CurveIdentifier switch
            {
                var a when a == CryptoAlgorithm.P256 => EllipticCurveConstants.P256.PrimeBytes,
                var a when a == CryptoAlgorithm.P384 => EllipticCurveConstants.P384.PrimeBytes,
                var a when a == CryptoAlgorithm.P521 => EllipticCurveConstants.P521.PrimeBytes,
                var a when a == CryptoAlgorithm.Secp256k1 => EllipticCurveConstants.Secp256k1.PrimeBytes,
                _ => throw new NotSupportedException($"Unsupported curve identifier: {td.CurveIdentifier}.")
            };

            var curveType = td.CurveIdentifier == CryptoAlgorithm.Secp256k1
                ? EllipticCurveTypes.Secp256k1
                : EllipticCurveTypes.NistCurves;

            CheckPointOnCurveForEvenAndOdd(td.PublicKeyMaterialX, td.PublicKeyMaterialY, curveType, primeBytes, isEven: td.IsEven);
        }

        private static void CheckPointOnCurveForEvenAndOdd(
            ReadOnlySpan<byte> publicKeyX,
            ReadOnlySpan<byte> publicKeyY,
            EllipticCurveTypes curveType,
            ReadOnlySpan<byte> primeBytes,
            bool isEven)
        {
            bool isValid = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, publicKeyY, curveType);
            Assert.IsTrue(isValid, $"A known valid key should be valid. IsEven = {isEven}.");

            //Test with an invalid public key where X is point at infinity.
            bool isInfinityX = EllipticCurveUtilities.CheckPointOnCurve(ReadOnlySpan<byte>.Empty, publicKeyY, curveType);
            Assert.IsFalse(isInfinityX, $"Public key X parameter was set to infinity. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key where Y is point at infinity.
            bool isInfinityY = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, ReadOnlySpan<byte>.Empty, curveType);
            Assert.IsFalse(isInfinityY, $"Public key Y parameter was set to infinity. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key where X is out of range.
            var invalidPublicKeyX = primeBytes;
            bool isInvalidX = EllipticCurveUtilities.CheckPointOnCurve(invalidPublicKeyX, publicKeyY, curveType);
            Assert.IsFalse(isInvalidX, $"Public key X parameter was set to out of range value. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key where Y is out of range.
            var invalidPublicKeyY = primeBytes;
            bool isInvalidY = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, invalidPublicKeyY, curveType);
            Assert.IsFalse(isInvalidY, $"Public key Y parameter was set to out of range value. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key, i.e. the public key point is not on an elliptic curve: y^2 != x^3 + ax + b (mod p).
            //Change the first byte to make the X coordinate invalid.
            byte[] modifiedPublicKeyArrayX = publicKeyX.ToArray();
            modifiedPublicKeyArrayX[0] ^= 1;
            ReadOnlySpan<byte> modifiedPublicKeyX = modifiedPublicKeyArrayX;
            bool isInvalidPointX = EllipticCurveUtilities.CheckPointOnCurve(modifiedPublicKeyX, publicKeyY, EllipticCurveTypes.NistCurves);
            Assert.IsFalse(isInvalidPointX, $"Public key X parameter was made invalid. Check should notice it. IsEven = {isEven}.");

            //Change the first byte to make the Y coordinate invalid.
            byte[] modifiedPublicKeyArrayY = publicKeyY.ToArray();
            modifiedPublicKeyArrayY[0] ^= 1;
            ReadOnlySpan<byte> modifiedPublicKeyY = modifiedPublicKeyArrayY;
            bool isInvalidPointY = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, modifiedPublicKeyY, curveType);
            Assert.IsFalse(isInvalidPointY, $"Public key Y parameter was made invalid. Check should notice it. IsEven = {isEven}.");
        }
    }
}
