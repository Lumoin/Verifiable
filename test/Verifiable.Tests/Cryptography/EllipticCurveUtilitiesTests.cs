using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for Elliptic curve utilities.
    /// </summary>
    [TestClass]
    internal sealed class EllipticCurveUtilitiesTests
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


        [SkipOnMacOSTestMethod(Reason = "Elliptic curve compression is not supported on macOS.")]
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


        [SkipOnMacOSTestMethod(Reason = "Elliptic curve compression is not supported on macOS.")]
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


        [SkipOnMacOSTestMethod(Reason = "Elliptic curve compression is not supported on macOS.")]
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


        [SkipOnMacOSTestMethod(Reason = "Elliptic curve operations are not fully supported on macOS.")]
        [DynamicData(nameof(EllipticCurveTheoryData.GetEllipticCurveTestData), typeof(EllipticCurveTheoryData))]
        public void PrimeCurvesRoundtripCompressAndDecompressSucceeds(EllipticCurveTestData td)
        {
            var curveType = td.CurveIdentifier.Equals(EllipticCurveTheoryData.EllipticSecP256k1, StringComparison.OrdinalIgnoreCase)
                ? EllipticCurveTypes.Secp256k1
                : EllipticCurveTypes.NistCurves;

            byte[] evenCompressedPoint = EllipticCurveUtilities.Compress(td.PublicKeyMaterialX, td.PublicKeyMaterialY);
            byte[] evenUncompressedY = EllipticCurveUtilities.Decompress(evenCompressedPoint, curveType);
            CollectionAssert.AreEqual(td.PublicKeyMaterialY, evenUncompressedY);
        }


        [SkipOnMacOSTestMethod(Reason = "Elliptic curve operations are not fully supported on macOS.")]
        [DynamicData(nameof(EllipticCurveTheoryData.GetEllipticCurveTestData), typeof(EllipticCurveTheoryData))]
        public void EllipticPointOnCurveCheckSucceeds(EllipticCurveTestData td)
        {
            ReadOnlySpan<byte> primeBytes = td.CurveIdentifier switch
            {
                EllipticCurveTheoryData.EllipticP256 => EllipticCurveConstants.P256.PrimeBytes,
                EllipticCurveTheoryData.EllipticP384 => EllipticCurveConstants.P384.PrimeBytes,
                EllipticCurveTheoryData.EllipticP521 => EllipticCurveConstants.P521.PrimeBytes,
                EllipticCurveTheoryData.EllipticSecP256k1 => EllipticCurveConstants.Secp256k1.PrimeBytes,
                _ => throw new NotSupportedException($"Unsupported curve identifier: {td.CurveIdentifier}.")
            };

            var curveType = td.CurveIdentifier.Equals(EllipticCurveTheoryData.EllipticSecP256k1, StringComparison.OrdinalIgnoreCase)
                ? EllipticCurveTypes.Secp256k1
                : EllipticCurveTypes.NistCurves;

            CheckPointOnCurveForEvenAndOdd(td.PublicKeyMaterialX, td.PublicKeyMaterialY, curveType, primeBytes, isEven: td.IsEven);
        }


        [TestMethod]
        public void SliceXCoordinateReturnsCorrectBytesForP256()
        {
            byte[] point = new byte[EllipticCurveConstants.P256.UncompressedPointByteCount];
            point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            for(int i = 1; i <= EllipticCurveConstants.P256.PointArrayLength; i++)
            {
                point[i] = (byte)i;
            }

            ReadOnlySpan<byte> x = EllipticCurveUtilities.SliceXCoordinate(point);

            Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, x.Length,
                "X coordinate length must match P-256 point array length.");
            Assert.IsTrue(x.SequenceEqual(point.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength)),
                "X coordinate bytes must match bytes 1 to 32.");
        }

        [TestMethod]
        public void SliceYCoordinateReturnsCorrectBytesForP256()
        {
            byte[] point = new byte[EllipticCurveConstants.P256.UncompressedPointByteCount];
            point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            for(int i = 1 + EllipticCurveConstants.P256.PointArrayLength; i < point.Length; i++)
            {
                point[i] = (byte)i;
            }

            ReadOnlySpan<byte> y = EllipticCurveUtilities.SliceYCoordinate(point);

            Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, y.Length,
                "Y coordinate length must match P-256 point array length.");
            Assert.IsTrue(y.SequenceEqual(point.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength)),
                "Y coordinate bytes must match bytes 33 to 64.");
        }

        [TestMethod]
        public void SliceXCoordinateReturnsCorrectBytesForP384()
        {
            byte[] point = new byte[EllipticCurveConstants.P384.UncompressedPointByteCount];
            point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            for(int i = 1; i <= EllipticCurveConstants.P384.PointArrayLength; i++)
            {
                point[i] = (byte)i;
            }

            ReadOnlySpan<byte> x = EllipticCurveUtilities.SliceXCoordinate(point);

            Assert.AreEqual(EllipticCurveConstants.P384.PointArrayLength, x.Length,
                "X coordinate length must match P-384 point array length.");
            Assert.IsTrue(x.SequenceEqual(point.AsSpan(1, EllipticCurveConstants.P384.PointArrayLength)),
                "X coordinate bytes must match bytes 1 to 48.");
        }

        [TestMethod]
        public void SliceYCoordinateReturnsCorrectBytesForP384()
        {
            byte[] point = new byte[EllipticCurveConstants.P384.UncompressedPointByteCount];
            point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            for(int i = 1 + EllipticCurveConstants.P384.PointArrayLength; i < point.Length; i++)
            {
                point[i] = (byte)i;
            }

            ReadOnlySpan<byte> y = EllipticCurveUtilities.SliceYCoordinate(point);

            Assert.AreEqual(EllipticCurveConstants.P384.PointArrayLength, y.Length,
                "Y coordinate length must match P-384 point array length.");
            Assert.IsTrue(y.SequenceEqual(point.AsSpan(1 + EllipticCurveConstants.P384.PointArrayLength, EllipticCurveConstants.P384.PointArrayLength)),
                "Y coordinate bytes must match bytes 49 to 96.");
        }

        [TestMethod]
        public void SliceXCoordinateThrowsForCompressedPoint()
        {
            byte[] compressedPoint = new byte[EllipticCurveConstants.P256.CompressedPointByteCount];
            compressedPoint[0] = EllipticCurveUtilities.EvenYCoordinate;
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.SliceXCoordinate(compressedPoint));
        }

        [TestMethod]
        public void SliceYCoordinateThrowsForCompressedPoint()
        {
            byte[] compressedPoint = new byte[EllipticCurveConstants.P256.CompressedPointByteCount];
            compressedPoint[0] = EllipticCurveUtilities.EvenYCoordinate;
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.SliceYCoordinate(compressedPoint));
        }

        [TestMethod]
        public void SliceXCoordinateThrowsForWrongLength()
        {
            byte[] point = new byte[10];
            point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.SliceXCoordinate(point));
        }

        [TestMethod]
        public void SliceYCoordinateThrowsForWrongLength()
        {
            byte[] point = new byte[10];
            point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.SliceYCoordinate(point));
        }

        [TestMethod]
        public void CombineToUncompressedPointProducesCorrectEncodingForP256()
        {
            byte[] x = new byte[EllipticCurveConstants.P256.PointArrayLength];
            byte[] y = new byte[EllipticCurveConstants.P256.PointArrayLength];
            x[0] = 0xAB;
            y[0] = 0xCD;

            byte[] result = EllipticCurveUtilities.CombineToUncompressedPoint(x, y);

            Assert.HasCount(EllipticCurveConstants.P256.UncompressedPointByteCount, result,
                "Combined P-256 point must be 65 bytes.");
            Assert.AreEqual(EllipticCurveUtilities.UncompressedCoordinateFormat, result[0],
                "First byte must be the uncompressed coordinate format prefix 0x04.");
            Assert.IsTrue(result.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength).SequenceEqual(x),
                "X coordinate bytes must appear at offset 1.");
            Assert.IsTrue(result.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength).SequenceEqual(y),
                "Y coordinate bytes must appear after X.");
        }

        [TestMethod]
        public void CombineToUncompressedPointProducesCorrectEncodingForP384()
        {
            byte[] x = new byte[EllipticCurveConstants.P384.PointArrayLength];
            byte[] y = new byte[EllipticCurveConstants.P384.PointArrayLength];
            x[0] = 0x11;
            y[0] = 0x22;

            byte[] result = EllipticCurveUtilities.CombineToUncompressedPoint(x, y);

            Assert.HasCount(EllipticCurveConstants.P384.UncompressedPointByteCount, result,
                "Combined P-384 point must be 97 bytes.");
            Assert.AreEqual(EllipticCurveUtilities.UncompressedCoordinateFormat, result[0],
                "First byte must be the uncompressed coordinate format prefix 0x04.");
        }

        [TestMethod]
        public void CombineToUncompressedPointIsInverseOfSliceCoordinates()
        {
            byte[] x = new byte[EllipticCurveConstants.P256.PointArrayLength];
            byte[] y = new byte[EllipticCurveConstants.P256.PointArrayLength];
            RandomNumberGenerator.Fill(x);
            RandomNumberGenerator.Fill(y);

            byte[] combined = EllipticCurveUtilities.CombineToUncompressedPoint(x, y);
            ReadOnlySpan<byte> slicedX = EllipticCurveUtilities.SliceXCoordinate(combined);
            ReadOnlySpan<byte> slicedY = EllipticCurveUtilities.SliceYCoordinate(combined);

            Assert.IsTrue(slicedX.SequenceEqual(x),
                "SliceXCoordinate must recover the original X after CombineToUncompressedPoint.");
            Assert.IsTrue(slicedY.SequenceEqual(y),
                "SliceYCoordinate must recover the original Y after CombineToUncompressedPoint.");
        }

        [TestMethod]
        public void CombineToUncompressedPointThrowsWhenLengthsDiffer()
        {
            byte[] x = new byte[EllipticCurveConstants.P256.PointArrayLength];
            byte[] y = new byte[EllipticCurveConstants.P384.PointArrayLength];
            Assert.ThrowsExactly<ArgumentException>(() =>
                EllipticCurveUtilities.CombineToUncompressedPoint(x, y));
        }

        [TestMethod]
        public void CombineToUncompressedPointThrowsWhenLengthIsUnsupported()
        {
            byte[] x = new byte[10];
            byte[] y = new byte[10];
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                EllipticCurveUtilities.CombineToUncompressedPoint(x, y));
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
