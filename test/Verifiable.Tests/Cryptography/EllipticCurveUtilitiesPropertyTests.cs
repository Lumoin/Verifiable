using CsCheck;
using Verifiable.Core.Cryptography;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Property based tests on elliptic curve utilities.
    /// </summary>
    [TestClass]
    public sealed class EllipticCurveUtilitiesPropertyTests
    {
        [TestMethod]
        public void CompressionDecompressionShouldBeInverseIfOnTheCurve()
        {            
            var curveTypeGen = Gen.Enum<EllipticCurveTypes>().Where(curve => curve != EllipticCurveTypes.None && curve != EllipticCurveTypes.Curve25519);

            //Generator for random elliptic curve points.
            var pointGen = Gen.Byte.Array[32].SelectMany(x => Gen.Byte.Array[32], (x, y) => (X: x, Y: y));

            //Combines the curve type generator with the point generator.
            var testDataGen = curveTypeGen.SelectMany(curveType => pointGen,
                (curveType, point) =>
                {
                    return (curveType, point.X, point.Y);
                });
            
            testDataGen.Sample(testData =>
            {
                var curveType = testData.curveType;
                byte[] publicKeyX = testData.X;
                byte[] publicKeyY = testData.Y;

                //Check the pont is on the curve. If not, there is no point in testing compression/decompression.
                if(EllipticCurveUtilities.CheckPointOnCurve(publicKeyX, publicKeyY, curveType))
                {
                    //Compress the elliptic curve point.
                    byte[] compressedPoint = EllipticCurveUtilities.Compress(publicKeyX, publicKeyY);

                    //Decompress the point.
                    byte[] decompressedY = EllipticCurveUtilities.Decompress(compressedPoint, curveType);

                    //Ensure the decompressed Y matches the original Y.
                    Assert.AreEqual(publicKeyY, decompressedY);
                }
            });
        }
    }
}
