using CsCheck;
using System;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Verifiable.Core.Cryptography;
using Verifiable.Tests.DataProviders;
using Verifiable.Tests.TestInfrastructure;
using Xunit;

namespace Verifiable.Core
{
    /// <summary>
    /// Tests for Elliptic curve utilities.
    /// </summary>
    public class EllipticCurveUtilitiesTests
    {
        /// <summary>
        /// Some elliptic curve exceptions need to contain this parameter name, so that
        /// the source and reason of the exception are clearer.
        /// </summary>
        const string XParameterNameInExceptionMessage = "xPoint";

        /// <summary>
        /// Some elliptic curve exceptions need to contain this parameter name, so that
        /// the source and reason of the exception are clearer.
        /// </summary>
        const string YParameterNameInExceptionMessage = "yPoint";


        [RunOnlyOnPlatformFact(Platforms.Windows, Platforms.Linux)]
        public void PrimeCurveCompressThrowsWithCorrectMessageIfEitherOrBothParametersNull()
        {
            using(var key = ECDsa.Create())
            {
                var keyParams = key.ExportParameters(includePrivateParameters: false);

                var exception1 = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(null, keyParams.Q.Y));
                Assert.Equal(XParameterNameInExceptionMessage, exception1.ParamName);

                var exception2 = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams.Q.X, null));
                Assert.Equal(YParameterNameInExceptionMessage, exception2.ParamName);

                var exception3 = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(null, null));
                Assert.Equal(XParameterNameInExceptionMessage, exception3.ParamName);
            }
        }


        [RunOnlyOnPlatformFact(Platforms.Windows, Platforms.Linux)]
        public void CompressThrowsWithCorrectMessageIfPointsDifferentLength()
        {
            using(var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                using(var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                {
                    var keyParams1 = key1.ExportParameters(includePrivateParameters: false);
                    var keyParams2 = key2.ExportParameters(includePrivateParameters: false);

                    const string ExceptionMessage = $"Parameters '{XParameterNameInExceptionMessage}' and '{YParameterNameInExceptionMessage}' need to be of the same length.";
                    var exception = Assert.Throws<ArgumentException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!, keyParams2.Q.Y));
                    Assert.Equal(ExceptionMessage, exception.Message);
                }
            }
        }


        [RunOnlyOnPlatformFact(Platforms.Windows, Platforms.Linux)]
        public void CompressThrowsWithCorrectMessageIfPointsWrongLength()
        {
            using(var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var keyParams1 = key1.ExportParameters(includePrivateParameters: false);

                string xPointExceptionMessage = $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'. (Parameter 'xPoint')";
                var xException = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!.Concat(new byte[] { 0x00 }).ToArray(), keyParams1.Q.Y));
                Assert.Equal(XParameterNameInExceptionMessage, xException.ParamName);
                Assert.Equal(xPointExceptionMessage, xException.Message);

                string yPointExceptionMessage = $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'. (Parameter 'yPoint')";
                var yException = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!, keyParams1.Q.Y!.Concat(new byte[] { 0x00 }).ToArray()));
                Assert.Equal(YParameterNameInExceptionMessage, yException.ParamName);
                Assert.Equal(yPointExceptionMessage, yException.Message);
            }
        }

        [Theory]
        [ClassData(typeof(EllipticCurveTheoryData))]
        public void PrimeCurvesRoundtripCompressAndDecompressSucceeds(EllipticCurveTestData td)
        {
            RunOnlyOnPlatformFactAttribute.SkipTestIfNotOnWindowsOrLinux();

            var curveType = td.CurveIdentifier.Equals(EllipticCurveTheoryData.EllipticSecP256k1, StringComparison.OrdinalIgnoreCase) ? EllipticCurveTypes.Secp256k1 : EllipticCurveTypes.NistCurves;

            byte[] evenCompressedPoint = EllipticCurveUtilities.Compress(td.PublicKeyMaterialX, td.PublicKeyMaterialY);
            byte[] evenUncompressedY = EllipticCurveUtilities.Decompress(evenCompressedPoint, curveType);
            Assert.Equal(td.PublicKeyMaterialY, evenUncompressedY);
        }


        [Theory]
        [ClassData(typeof(EllipticCurveTheoryData))]
        public void EllipticPointOnCurveCheckSucceeds(EllipticCurveTestData td)
        {
            RunOnlyOnPlatformFactAttribute.SkipTestIfNotOnWindowsOrLinux();

            ReadOnlySpan<byte> primeBytes = td.CurveIdentifier switch
            {
                EllipticCurveTheoryData.EllipticP256 => EllipticCurveConstants.P256.PrimeBytes,
                EllipticCurveTheoryData.EllipticP384 => EllipticCurveConstants.P384.PrimeBytes,
                EllipticCurveTheoryData.EllipticP521 => EllipticCurveConstants.P521.PrimeBytes,
                EllipticCurveTheoryData.EllipticSecP256k1 => EllipticCurveConstants.Secp256k1.PrimeBytes,
                _ => throw new NotSupportedException()
            };

            var curveType = td.CurveIdentifier.Equals(EllipticCurveTheoryData.EllipticSecP256k1, StringComparison.OrdinalIgnoreCase) ? EllipticCurveTypes.Secp256k1 : EllipticCurveTypes.NistCurves;
            CheckPointOnCurveForEvenAndOdd(td.PublicKeyMaterialX, td.PublicKeyMaterialY, curveType, primeBytes, isEven: td.IsEven);            
        }
        

        private static void CheckPointOnCurveForEvenAndOdd(ReadOnlySpan<byte> publicKeyX, ReadOnlySpan<byte> publicKeyY, EllipticCurveTypes curveType, ReadOnlySpan<byte> primeBytes, bool isEven)
        {
            bool isValid = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, publicKeyY, curveType);
            Assert.True(isValid, $"A known valid key should be valid. IsEven = {isEven}.");

            //Test with an invalid public key (point at infinity).                
            bool isInfinityX = EllipticCurveUtilities.CheckPointOnCurve(ReadOnlySpan<byte>.Empty, publicKeyY, curveType);
            Assert.False(isInfinityX, $"Public key X parameter was set to infinity. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key (point at infinity).                
            bool isInfinityY = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, ReadOnlySpan<byte>.Empty, curveType);
            Assert.False(isInfinityY, $"Public key Y parameter was set to infinity. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key (x out of range).
            var invalidPublicKeyX = primeBytes;
            bool isInvalidX = EllipticCurveUtilities.CheckPointOnCurve(invalidPublicKeyX, publicKeyY, curveType);
            Assert.False(isInvalidX, $"Public key X parameter was set to out of range value. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key (y out of range).
            var invalidPublicKeyY = primeBytes;
            bool isInvalidY = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, invalidPublicKeyY, curveType);
            Assert.False(isInvalidY, $"Public key Y parameter was set to out of range value. Check should notice it. IsEven = {isEven}.");

            //Test with an invalid public key, i.e. the public key point is not on an elliptic curve: y^2 != x^3 + ax + b (mod p).
            //Change the first byte to make the X coordinate invalid.
            byte[] modifiedPublicKeyArrayX = publicKeyX.ToArray();
            modifiedPublicKeyArrayX[0] ^= 1;
            ReadOnlySpan<byte> modifiedPublicKeyX = modifiedPublicKeyArrayX;
            bool isInvalidPointX = EllipticCurveUtilities.CheckPointOnCurve(modifiedPublicKeyX, publicKeyY, EllipticCurveTypes.NistCurves);
            Assert.False(isInvalidPointX, $"Public key X parameter was made invalid. Check should notice it. IsEven = {isEven}.");

            //Change the first byte to make the Y coordinate invalid.
            byte[] modifiedPublicKeyArrayY = publicKeyY.ToArray();
            modifiedPublicKeyArrayY[0] ^= 1;
            ReadOnlySpan<byte> modifiedPublicKeyY = modifiedPublicKeyArrayY;
            bool isInvalidPointY = EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, modifiedPublicKeyY, curveType);
            Assert.False(isInvalidPointY, $"Public key Y parameter was made invalid. Check should notice it. IsEven = {isEven}.");
        }
    }    
}
