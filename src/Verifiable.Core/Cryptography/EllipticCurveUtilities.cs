using System;
using System.Numerics;
using static Verifiable.Core.Cryptography.EllipticCurveConstants;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// The elliptic curve types Verifiable supports.
    /// More at <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">Draft NIST Special Publication 800-186
    /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see>.
    /// </summary>
    [Flags]
    public enum EllipticCurveTypes
    {
        /// <summary>
        /// No curve defined.
        /// </summary>
        None = 0,

        /// <summary>
        /// NIST P-256.
        /// </summary>
        P256 = 1 << 0,

        /// <summary>
        /// NIST P-384.
        /// </summary>
        P384 = 1 << 1,

        /// <summary>
        /// NIST P-521.
        /// </summary>
        P521 = 1 << 2,

        /// <summary>
        /// NIST Seckp256k1.
        /// </summary>
        Secp256k1 = 1 << 3,

        /// <summary>
        /// All NIST curves.
        /// </summary>
        NistCurves = P256 | P384 | P521,
        
        /// <summary>
        /// Curve25519. More at <see href="https://safecurves.cr.yp.to/">SafeCurves: choosing safe curves for elliptic-curve cryptography</see>.
        /// </summary>
        Curve25519 = 1 << 4
    }


    /// <summary>
    /// These are some helper bit functions to work with elliptic key material.
    /// </summary>
    public static class EllipticCurveUtilities
    {
        /// <summary>
        /// The compressed P-256 byte array length.
        /// </summary>
        private const int P256CompressedByteCount = 33;

        /// <summary>
        /// The compressed Secp256k1 byte array length.
        /// </summary>
        private const int Secp256k1CompressedByteCount = 33;

        /// <summary>
        /// The compressed P-384 byte array length.
        /// </summary>
        private const int P384CompressedByteCount = 49;

        /// <summary>
        /// The compressed P-521 byte array length.
        /// </summary>
        private const int P521CompressedByteCount = 67;

        /// <summary>
        /// Even Y coordinate. See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography</see> page 11.
        /// </summary>
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        public static byte EvenYCoordinate => 0x02;

        /// <summary>
        /// Odd Y coordinate. See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography [pdf]</see> page 11.
        /// </summary>
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        public static byte OddYCoordinate => 0x03;

        /// <summary>
        /// Uncompressed format for elliptic curve points that are concated. Not supported.
        /// </summary>
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        public static byte UncompressedCoordinateFormat => 0x04;


        /// <summary>
        /// Decompresses a given point on the elliptic curve that is compressed on X point.
        /// </summary>
        /// <param name="compressedPoint">The X point to which the y point is compressed.</param>
        /// <returns>The y point matching the <paramref name="compressedPoint"/> on the given elliptic curve.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> must start with 0x02 or 0x03
        /// and be either 33 (P-256), 49 (P-384) or 67 (P-521) bytes</exception>.
        /// <remarks>This returns fixed length points for P-256 (33 bytes), P-384 (48 bytes) and P-521 (66 bytes).
        /// For P-521 this means padding with 0x00. This is not suitable for length-prepended structures such as
        /// certificate SubjectPublicKeyInfo fields.</remarks>
        public static byte[] Decompress(ReadOnlySpan<byte> compressedPoint, EllipticCurveTypes curveType)
        {
            if(compressedPoint[0] == UncompressedCoordinateFormat)
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint), "This method supports only compressed X coordinate (must start with 0x02 or 0x03).");
            }

            if(compressedPoint[0] != EvenYCoordinate && compressedPoint[0] != OddYCoordinate)
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint), $"Value must start with 0x02 or 0x03. Now 0x{compressedPoint[0]:2}.");
            }

            //For Secp256k1 the length is the same as for P-256.
            if(!(compressedPoint.Length == P256CompressedByteCount
                || compressedPoint.Length == P384CompressedByteCount
                || compressedPoint.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint), $"Length must be {P256CompressedByteCount}, {P384CompressedByteCount} or {P521CompressedByteCount}.");
            }

            //These local methods are used to make the code easier to follow by naming
            //the key operations.            
            static BigInteger CalcuateYPoint(BigInteger x, BigInteger coefficientB, BigInteger pIdentity, BigInteger prime, EllipticCurveTypes curveType)
            {
                //The difference between secp256k1 and NIST curves lies in the curve equation's form: y^2 = x^3 + Ax + B (mod p).
                //For NIST curves, A = -3: y^2 = x^2 - 3x + B (mod p)
                //For secp256k1, A = 0: y^2 = x^3 + B (mod p).                
                if(curveType.HasFlag(EllipticCurveTypes.Secp256k1))
                {
                    return BigInteger.ModPow(BigInteger.Pow(x, 3) + coefficientB, pIdentity, prime);
                }
                else
                {
                    return BigInteger.ModPow(BigInteger.Pow(x, 3) - x * 3 + coefficientB, pIdentity, prime);
                }
            }
            
            static bool CalculateIsPositiveSign(ReadOnlySpan<byte> compressedXPoint, BigInteger calculatedYPoint)
            {
                int isPositiveY = compressedXPoint[0] - 2;
                return isPositiveY == calculatedYPoint % 2;
            }

            //This function writes to yPointBytes. The return value is used to smoothen code.
            static byte[] WriteYPointBytes(BigInteger point, byte[] yPointBytes, int start)
            {
                //Writing these bytes should never fail. The output size is known and the buffer is already reserved.
                //Plus tests check the guards checking function data check other options are not possible.
                _ = point.TryWriteBytes(((Span<byte>)yPointBytes)[start..], out _, isUnsigned: true, isBigEndian: true);
                return yPointBytes;
            }

            //The first byte is to choose either y or -y. So, it's not the actual point payload data
            //and consequently needs to be sliced off.
            var x = new BigInteger(compressedPoint[1..], isUnsigned: true, isBigEndian: true);

            //The function guards checking parameters check one of the cases are the only valid ones.
            //Hence the last else branch needs to be 512 if it is not something else and the variables
            //will always be initialized.
            BigInteger coefficientB;
            BigInteger pIdent;
            BigInteger prime;
            int pointArrayLength;
            if(compressedPoint.Length == P256CompressedByteCount || compressedPoint.Length == Secp256k1CompressedByteCount)                
            {
                if(curveType.HasFlag(EllipticCurveTypes.P256) || curveType.HasFlag(EllipticCurveTypes.NistCurves))
                {
                    coefficientB = P256.CoefficientB;
                    pIdent = P256.PIdentity;
                    prime = P256.Prime;
                    pointArrayLength = P256.PointArrayLength;
                }
                else
                {
                    coefficientB = Secp256k1.CoefficientB;
                    pIdent = Secp256k1.PIdentity;
                    prime = Secp256k1.Prime;
                    pointArrayLength = Secp256k1.PointArrayLength;
                }
            }
            else if(compressedPoint.Length == P384CompressedByteCount)
            {
                coefficientB = P384.CoefficientB;
                pIdent = P384.PIdentity;
                prime = P384.Prime;
                pointArrayLength = P384.PointArrayLength;
            }
            else
            {
                coefficientB = P521.CoefficientB;
                pIdent = P521.PIdentity;
                prime = P521.Prime;
                pointArrayLength = P521.PointArrayLength;
            }

            var oneYPointCandinate = CalcuateYPoint(x, coefficientB, pIdent, prime, curveType);
            var anotherYPointCandinate = prime - oneYPointCandinate;
            bool isPositive = CalculateIsPositiveSign(compressedPoint, oneYPointCandinate);

            var returnYPointBytes = new byte[pointArrayLength];
            int returnYPointByteCount = isPositive ? oneYPointCandinate.GetByteCount(isUnsigned: true) : anotherYPointCandinate.GetByteCount(isUnsigned: true);
            int startIndexAfterPadding = pointArrayLength - returnYPointByteCount;

            //This is not 100 % constant time in all cases. In P-521 Y coordinate may have a leading zeroes which
            //BigInteger removes. In this case startIndexAfterPadding > 0 and consequently WriteYPointBytes assumes zero
            //initialized array, which it starts filling from that index onwards. There is no guarantee BigInteger
            //operations are constant time either.
            return isPositive ?
                WriteYPointBytes(oneYPointCandinate, returnYPointBytes, startIndexAfterPadding) :
                WriteYPointBytes(anotherYPointCandinate, returnYPointBytes, startIndexAfterPadding);
        }

        /// <summary>
        /// Compresses elliptic curve points. See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography [pdf]</see> page 11.
        /// </summary>
        /// <param name="xPoint">The X point.</param>
        /// <param name="yPoint">The Y point.</param>
        /// <returns>The compressed elliptic point coordinates.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> must start with 0x02 or 0x03
        /// and be either 32 (P-256), 42 (P-384) or 66 (P-521) bytes</exception>.
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>        
        public static byte[] Compress(ReadOnlySpan<byte> xPoint, ReadOnlySpan<byte> yPoint)
        {                                    
            if(!(xPoint.Length == P256.PointArrayLength
                || xPoint.Length == P384.PointArrayLength
                || xPoint.Length == P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(xPoint),
                    $"Length must be '{P256.PointArrayLength}', '{P384.PointArrayLength}' or '{P521.PointArrayLength}'.");
            }

            if(!(yPoint.Length == P256.PointArrayLength
                || yPoint.Length == P384.PointArrayLength
                || yPoint.Length == P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint),
                    $"Length must be '{P256.PointArrayLength}', '{P384.PointArrayLength}' or '{P521.PointArrayLength}'.");
            }

            if(xPoint.Length != yPoint.Length)
            {
                throw new ArgumentException($"Parameters '{nameof(xPoint)}' and '{nameof(yPoint)}' need to be of the same length.");
            }

            //Y point will be checked within Y point sign function.
            /*
            if(!(yPoint.Length == EllipticCurveConstants.P256.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P384.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint),
                    $"Length must be {EllipticCurveConstants.P256.PointArrayLength}, {EllipticCurveConstants.P384.PointArrayLength} or {EllipticCurveConstants.P521.PointArrayLength}.");
            }*/

            var compressedPointData = new byte[xPoint.Length + 1];
            compressedPointData[0] = CompressionSignByte(yPoint);
            xPoint.CopyTo(compressedPointData.AsSpan(start: 1));

            return compressedPointData;
        }


        /// <summary>
        /// Calculates the sign byte for the point that is added to the compressed
        /// point. This is used to choose either positive (0x02) or negative (0x03) point
        /// when the curve is again decompressed.
        /// See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography [pdf]</see> page 11.
        /// </summary>
        /// <param name="yPoint">The y parameter from which to deduce the sign.</param>
        /// <returns>The compression sign byte. Either 0x02 (positive) or 0x03 (negative)</returns>.
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> must start with 0x02 or 0x03
        /// and be either 32 (P-256), 42 (P-384) or 66 (P-521) bytes</exception>.
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>        
        public static byte CompressionSignByte(ReadOnlySpan<byte> yPoint)
        {
            if(!(yPoint.Length == P256.PointArrayLength
                || yPoint.Length == P384.PointArrayLength
                || yPoint.Length == P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint), $"Length must be {P256.PointArrayLength}, {P384.PointArrayLength} or {P521.PointArrayLength}.");
            }

            return (byte)(2 + (yPoint![^1] & 1));
        }


        public static ReadOnlySpan<byte> SliceXCoordindate(ReadOnlySpan<byte> uncomporessedCoordinates)
        {
            if(uncomporessedCoordinates[0] != UncompressedCoordinateFormat)
            {
                throw new ArgumentOutOfRangeException(nameof(uncomporessedCoordinates), "This method supports only uncompressed coordinates (must start with 0x04).");
            }

            if(!(uncomporessedCoordinates.Length == P256CompressedByteCount
                || uncomporessedCoordinates.Length == P384CompressedByteCount
                || uncomporessedCoordinates.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(uncomporessedCoordinates), $"Length must be {P256CompressedByteCount}, {P384CompressedByteCount} or {P521CompressedByteCount}.");
            }

            return uncomporessedCoordinates.Slice(1, uncomporessedCoordinates.Length / 2);
        }


        public static ReadOnlySpan<byte> SliceYCoordindate(ReadOnlySpan<byte> uncomporessedCoordinates)
        {
            if(uncomporessedCoordinates[0] != UncompressedCoordinateFormat)
            {
                throw new ArgumentOutOfRangeException(nameof(uncomporessedCoordinates), "This method supports only uncompressed coordinates (must start with 0x04).");
            }

            if(!(uncomporessedCoordinates.Length == P256CompressedByteCount
                || uncomporessedCoordinates.Length == P384CompressedByteCount
                || uncomporessedCoordinates.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(uncomporessedCoordinates), $"Length must be {P256CompressedByteCount}, {P384CompressedByteCount} or {P521CompressedByteCount}.");
            }

            return uncomporessedCoordinates.Slice(uncomporessedCoordinates.Length / 2, uncomporessedCoordinates.Length);
        }


        /// <summary>
        /// Checks if the given elliptic curve point is encoded in compressed form or not.
        /// </summary>
        /// <param name="maybeCompressedCoordinates">The point to check.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> must start with 0x02 or 0x03
        /// and be either 32 (P-256), 42 (P-384) or 66 (P-521) bytes</exception>.
        public static bool IsCompressed(ReadOnlySpan<byte> maybeCompressedCoordinates)
        {
            if(!(maybeCompressedCoordinates.Length == P256CompressedByteCount
                || maybeCompressedCoordinates.Length == P384CompressedByteCount
                || maybeCompressedCoordinates.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(maybeCompressedCoordinates), $"Length must be {P256CompressedByteCount}, {P384CompressedByteCount} or {P521CompressedByteCount}.");
            }

            return maybeCompressedCoordinates[0] == EvenYCoordinate || maybeCompressedCoordinates[0] == OddYCoordinate;
        }


        /// <summary>
        /// Checks if a given elliptic curve point is on the curve or not.
        /// </summary>
        /// <param name="publicKeyX">The public key material.</param>
        /// <param name="publicKeyY">The private key material.</param>
        /// <param name="curveType">The curve type (this is to separate P-256 from Secp256k1).</param>
        /// <returns></returns>
        /// <remarks>The steps are defined in <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">NIST Special Publication 800-186
        /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see>
        /// D.1.1.1. Partial Public Key Validation (Short-Weierstrass Form) page 42. This holds also for secp256k1.</remarks>
        public static bool CheckPointOnCurve(ReadOnlySpan<byte> publicKeyX, ReadOnlySpan<byte> publicKeyY, EllipticCurveTypes curveType)
        {            
            static bool ValiteParametersInRange(BigInteger x, BigInteger y, BigInteger prime)
            {
                return !(x < BigInteger.Zero || x >= prime || y < BigInteger.Zero || y >= prime);
            }
            
            static bool ValidateCurve(BigInteger x, BigInteger y, BigInteger coefficientA, BigInteger coefficientB, BigInteger prime)
            {
                //Verify that y ^ 2 == x ^ 3 + ax + b(mod p).
                BigInteger ySquared = BigInteger.ModPow(y, 2, prime);
                BigInteger xCubedPlusAXPlusB = (BigInteger.ModPow(x, 3, prime) + coefficientA * x + coefficientB) % prime;
                return ySquared == xCubedPlusAXPlusB;
            }

            //Step 1: Verify public key is not point at infinity. Basically this means either
            //of the parameters is null or empty.
            if(publicKeyX.IsEmpty && publicKeyY.IsEmpty)
            {
                return false;
            }

            //Step 2: Verify x and y are in range [0, p - 1]
            //Step 3: Verify that the point is on an elliptic curve, e.g. y^2 == x^3 + ax + b (mod p).
            BigInteger x = new(publicKeyX, isUnsigned: true, isBigEndian: true);
            BigInteger y = new(publicKeyY, isUnsigned: true, isBigEndian: true);
            return (publicKeyX.Length, curveType) switch
            {
                (P256.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.P256) || curveType.HasFlag(EllipticCurveTypes.NistCurves) =>
                    ValiteParametersInRange(x, y, P256.Prime) && ValidateCurve(x, y, P256.CoefficientA, P256.CoefficientB, P256.Prime),

                (Secp256k1.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.Secp256k1) =>
                    ValiteParametersInRange(x, y, Secp256k1.Prime) && ValidateCurve(x, y, Secp256k1.CoefficientA, Secp256k1.CoefficientB, Secp256k1.Prime),

                (P384.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.P384) =>
                    ValiteParametersInRange(x, y, P384.Prime) && ValidateCurve(x, y, P384.CoefficientA, P384.CoefficientB, P384.Prime),

                (P521.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.P521) =>
                    ValiteParametersInRange(x, y, P521.Prime) && ValidateCurve(x, y, P521.CoefficientA, P521.CoefficientB, P521.Prime),

                _ => false
            };

            // According to the specification there would still be Step 4 for secp256k1.
            // Verify that nQ = 0, where n is the order of the curve and Q is the public key.
            // As per http://www.secg.org/sec1-v2.pdf section 3.2.2:
            // "In Step 4, it may not be necessary to compute the point nQ. For example, if h = 1, then nQ = O is implied
            // by the checks in Steps 2 and 3, because this property holds for all points Q belonging to E"
            // All the NIST curves used here define h = 1.
            /*if(new BigInteger(curve.Cofactor!) != 1)
            {
                throw new NotSupportedException("Only curves with cofactor 1 are supported.");
            }*/
        }
    }
}
