using System.Numerics;
using Verifiable.Cryptography.Context;
using static Verifiable.Cryptography.EllipticCurveConstants;

namespace Verifiable.Cryptography
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
        Curve25519 = 1 << 4,

        /// <summary>
        /// Brainpool P-256r1 per RFC 5639. 256-bit prime field, 32-byte coordinates.
        /// </summary>
        BrainpoolP256r1 = 1 << 5,

        /// <summary>
        /// Brainpool P-320r1 per RFC 5639. 320-bit prime field, 40-byte coordinates.
        /// </summary>
        BrainpoolP320r1 = 1 << 6,

        /// <summary>
        /// Brainpool P-384r1 per RFC 5639. 384-bit prime field, 48-byte coordinates.
        /// </summary>
        BrainpoolP384r1 = 1 << 7,

        /// <summary>
        /// Brainpool P-512r1 per RFC 5639. 512-bit prime field, 64-byte coordinates.
        /// </summary>
        BrainpoolP512r1 = 1 << 8,

        /// <summary>
        /// Brainpool P-224r1 per RFC 5639. 224-bit prime field, 28-byte coordinates.
        /// </summary>
        BrainpoolP224r1 = 1 << 9,

        /// <summary>
        /// All five Brainpool r1 curves combined. Mirrors the NistCurves family flag.
        /// </summary>
        BrainpoolCurves = BrainpoolP224r1 | BrainpoolP256r1 | BrainpoolP320r1 | BrainpoolP384r1 | BrainpoolP512r1
    }


    /// <summary>
    /// These are some helper bit functions to work with elliptic key material.
    /// </summary>
    public static class EllipticCurveUtilities
    {
        //Compressed-point byte lengths by field size. The 33-byte length is shared by
        //P-256, secp256k1, and BrainpoolP256r1; the 49-byte length by P-384 and
        //BrainpoolP384r1. The curveType flag disambiguates within Decompress and
        //CheckPointOnCurve. The BP-320 (41) and BP-512 (65) lengths are unique on
        //length alone.

        /// <summary>The compressed P-256 / secp256k1 / Brainpool P-256r1 byte array length.</summary>
        private const int P256CompressedByteCount = 33;

        /// <summary>The compressed Brainpool P-224r1 byte array length.</summary>
        private const int BrainpoolP224r1CompressedByteCount = 29;

        /// <summary>The compressed Brainpool P-320r1 byte array length.</summary>
        private const int BrainpoolP320r1CompressedByteCount = 41;

        /// <summary>The compressed P-384 / Brainpool P-384r1 byte array length.</summary>
        private const int P384CompressedByteCount = 49;

        /// <summary>The compressed Brainpool P-512r1 byte array length.</summary>
        private const int BrainpoolP512r1CompressedByteCount = 65;

        /// <summary>The compressed P-521 byte array length.</summary>
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
        /// Uncompressed format for elliptic curve points that are concatenated. Not supported.
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

            //All four Brainpool curves added in Q.2.X round out the supported compressed
            //lengths to {33, 41, 49, 65, 67}. The 33-byte length is shared by P-256,
            //secp256k1, and BP-256r1; the 49-byte length is shared by P-384 and BP-384r1.
            //The curveType flag disambiguates in those cases — see ResolveCurveParameters.
            if(!(compressedPoint.Length == BrainpoolP224r1CompressedByteCount
                || compressedPoint.Length == P256CompressedByteCount
                || compressedPoint.Length == BrainpoolP320r1CompressedByteCount
                || compressedPoint.Length == P384CompressedByteCount
                || compressedPoint.Length == BrainpoolP512r1CompressedByteCount
                || compressedPoint.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint),
                    $"Length must be one of {BrainpoolP224r1CompressedByteCount}, {P256CompressedByteCount}, {BrainpoolP320r1CompressedByteCount}, {P384CompressedByteCount}, {BrainpoolP512r1CompressedByteCount}, {P521CompressedByteCount}.");
            }

            //Y is recovered from x via the general short-Weierstrass form
            //y^2 = x^3 + a*x + b (mod p). NIST P-curves use a = -3 (encoded as p-3),
            //secp256k1 uses a = 0, and Brainpool curves use arbitrary a per RFC 5639;
            //the general formula subsumes all three cases without special-casing.
            static BigInteger CalculateYPoint(BigInteger x, BigInteger coefficientA, BigInteger coefficientB, BigInteger pIdentity, BigInteger prime)
            {
                BigInteger rhs = (BigInteger.ModPow(x, 3, prime) + coefficientA * x + coefficientB) % prime;
                if(rhs.Sign < 0)
                {
                    rhs += prime;
                }

                return BigInteger.ModPow(rhs, pIdentity, prime);
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

            (BigInteger coefficientA, BigInteger coefficientB, BigInteger pIdent, BigInteger prime, int pointArrayLength) =
                ResolveCurveParameters(compressedPoint.Length, curveType);

            var oneYPointCandidate = CalculateYPoint(x, coefficientA, coefficientB, pIdent, prime);
            var anotherYPointCandidate = prime - oneYPointCandidate;
            bool isPositive = CalculateIsPositiveSign(compressedPoint, oneYPointCandidate);

            var returnYPointBytes = new byte[pointArrayLength];
            int returnYPointByteCount = isPositive ? oneYPointCandidate.GetByteCount(isUnsigned: true) : anotherYPointCandidate.GetByteCount(isUnsigned: true);
            int startIndexAfterPadding = pointArrayLength - returnYPointByteCount;

            //This is not 100 % constant time in all cases. In P-521 Y coordinate may have a leading zeroes which
            //BigInteger removes. In this case startIndexAfterPadding > 0 and consequently WriteYPointBytes assumes zero
            //initialized array, which it starts filling from that index onwards. There is no guarantee BigInteger
            //operations are constant time either.
            return isPositive ?
                WriteYPointBytes(oneYPointCandidate, returnYPointBytes, startIndexAfterPadding) :
                WriteYPointBytes(anotherYPointCandidate, returnYPointBytes, startIndexAfterPadding);
        }


        /// <summary>
        /// Maps a <see cref="CryptoAlgorithm"/> to its <see cref="EllipticCurveTypes"/> flag. Only the
        /// elliptic curves carrying SEC1 point material are mapped; a non-EC algorithm throws, since the
        /// mapping exists to interpret EC point bytes (compressed-point lengths are shared across curves,
        /// so the curve — not the byte length — disambiguates decompression).
        /// </summary>
        /// <param name="algorithm">The key's algorithm, as carried by its <c>Tag</c>.</param>
        /// <returns>The matching <see cref="EllipticCurveTypes"/> flag.</returns>
        /// <exception cref="NotSupportedException"><paramref name="algorithm"/> is not an EC curve.</exception>
        public static EllipticCurveTypes CurveTypeFor(CryptoAlgorithm algorithm)
        {
            return algorithm switch
            {
                var a when a.Equals(CryptoAlgorithm.P256) => EllipticCurveTypes.P256,
                var a when a.Equals(CryptoAlgorithm.P384) => EllipticCurveTypes.P384,
                var a when a.Equals(CryptoAlgorithm.P521) => EllipticCurveTypes.P521,
                var a when a.Equals(CryptoAlgorithm.Secp256k1) => EllipticCurveTypes.Secp256k1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP224r1) => EllipticCurveTypes.BrainpoolP224r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP256r1) => EllipticCurveTypes.BrainpoolP256r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP320r1) => EllipticCurveTypes.BrainpoolP320r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP384r1) => EllipticCurveTypes.BrainpoolP384r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP512r1) => EllipticCurveTypes.BrainpoolP512r1,
                _ => throw new NotSupportedException(
                    $"CryptoAlgorithm '{algorithm}' is not an elliptic curve with SEC1 point encoding.")
            };
        }


        /// <summary>
        /// Recognises an elliptic curve unambiguously from its field prime p — the curve's defining
        /// parameter, unlike point length which several same-field-size curves share (33-byte points cover
        /// P-256, secp256k1, and brainpoolP256r1). This complements the length-plus-hint recognition used
        /// by <see cref="NormalizeToUncompressed"/>: it identifies the curve of a SubjectPublicKeyInfo that
        /// carries explicit domain parameters — the common encoding for eMRTD chip-authentication and PACE keys.
        /// </summary>
        /// <param name="prime">The field prime p as unsigned big-endian bytes (a leading DER sign byte is ignored).</param>
        /// <returns>The matching <see cref="EllipticCurveTypes"/>, or <see cref="EllipticCurveTypes.None"/> when no supported curve matches.</returns>
        public static EllipticCurveTypes CurveTypeFromPrime(ReadOnlySpan<byte> prime)
        {
            var value = new BigInteger(prime, isUnsigned: true, isBigEndian: true);

            return value switch
            {
                _ when value == P256.Prime => EllipticCurveTypes.P256,
                _ when value == P384.Prime => EllipticCurveTypes.P384,
                _ when value == P521.Prime => EllipticCurveTypes.P521,
                _ when value == Secp256k1.Prime => EllipticCurveTypes.Secp256k1,
                _ when value == BrainpoolP224r1.Prime => EllipticCurveTypes.BrainpoolP224r1,
                _ when value == BrainpoolP256r1.Prime => EllipticCurveTypes.BrainpoolP256r1,
                _ when value == BrainpoolP320r1.Prime => EllipticCurveTypes.BrainpoolP320r1,
                _ when value == BrainpoolP384r1.Prime => EllipticCurveTypes.BrainpoolP384r1,
                _ when value == BrainpoolP512r1.Prime => EllipticCurveTypes.BrainpoolP512r1,
                _ => EllipticCurveTypes.None
            };
        }


        /// <summary>
        /// Recognises an elliptic curve from its named-curve object identifier — the DER value bytes of the
        /// curve OID in a SubjectPublicKeyInfo's AlgorithmIdentifier parameters. The OID is decoded with the
        /// framework codec and matched against the <see cref="WellKnownOids"/> curve identifiers.
        /// </summary>
        /// <param name="curveOid">The named-curve OID value bytes (after the 0x06 tag and length).</param>
        /// <returns>The matching <see cref="EllipticCurveTypes"/>, or <see cref="EllipticCurveTypes.None"/> when no supported curve matches.</returns>
        public static EllipticCurveTypes CurveTypeFromCurveOid(ReadOnlySpan<byte> curveOid)
        {
            return WellKnownOids.OidFromDerValue(curveOid) switch
            {
                WellKnownOids.EcP256 => EllipticCurveTypes.P256,
                WellKnownOids.EcP384 => EllipticCurveTypes.P384,
                WellKnownOids.EcP521 => EllipticCurveTypes.P521,
                WellKnownOids.EcSecp256k1 => EllipticCurveTypes.Secp256k1,
                WellKnownOids.EcBrainpoolP224r1 => EllipticCurveTypes.BrainpoolP224r1,
                WellKnownOids.EcBrainpoolP256r1 => EllipticCurveTypes.BrainpoolP256r1,
                WellKnownOids.EcBrainpoolP320r1 => EllipticCurveTypes.BrainpoolP320r1,
                WellKnownOids.EcBrainpoolP384r1 => EllipticCurveTypes.BrainpoolP384r1,
                WellKnownOids.EcBrainpoolP512r1 => EllipticCurveTypes.BrainpoolP512r1,
                _ => EllipticCurveTypes.None
            };
        }


        /// <summary>
        /// The named-curve object identifier (DER value bytes) of a supported curve — the inverse of
        /// <see cref="CurveTypeFromCurveOid"/>, for encoding a curve into a SubjectPublicKeyInfo.
        /// </summary>
        /// <param name="curve">The curve.</param>
        /// <returns>The named-curve OID value bytes (after the 0x06 tag and length).</returns>
        /// <exception cref="NotSupportedException">Thrown when no named-curve OID is known for <paramref name="curve"/>.</exception>
        public static ReadOnlySpan<byte> CurveOidDerValue(EllipticCurveTypes curve) => curve switch
        {
            EllipticCurveTypes.P256 => WellKnownOids.EcP256DerValue,
            EllipticCurveTypes.P384 => WellKnownOids.EcP384DerValue,
            EllipticCurveTypes.P521 => WellKnownOids.EcP521DerValue,
            EllipticCurveTypes.Secp256k1 => WellKnownOids.EcSecp256k1DerValue,
            EllipticCurveTypes.BrainpoolP224r1 => WellKnownOids.EcBrainpoolP224r1DerValue,
            EllipticCurveTypes.BrainpoolP256r1 => WellKnownOids.EcBrainpoolP256r1DerValue,
            EllipticCurveTypes.BrainpoolP320r1 => WellKnownOids.EcBrainpoolP320r1DerValue,
            EllipticCurveTypes.BrainpoolP384r1 => WellKnownOids.EcBrainpoolP384r1DerValue,
            EllipticCurveTypes.BrainpoolP512r1 => WellKnownOids.EcBrainpoolP512r1DerValue,
            _ => throw new NotSupportedException($"No named-curve OID is known for '{curve}'.")
        };


        /// <summary>
        /// Normalizes a SEC1 elliptic-curve public point to uncompressed form (<c>0x04 || X || Y</c>). An
        /// already-uncompressed point is returned as a copy; a compressed point (<c>0x02/0x03 || X</c>) is
        /// decompressed using <paramref name="curveType"/> to recover Y. The curve is required because
        /// compressed-point lengths are shared (33 bytes: P-256/secp256k1/BP-256r1; 49 bytes:
        /// P-384/BP-384r1), so the curve — not the byte length — disambiguates the decompression.
        /// </summary>
        /// <param name="point">The SEC1 public point, compressed or uncompressed.</param>
        /// <param name="curveType">The curve the point lies on (from the key's <c>Tag</c>).</param>
        /// <returns>The uncompressed point <c>0x04 || X || Y</c>.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="point"/> is empty or lacks a valid SEC1 prefix (0x02/0x03/0x04).</exception>
        public static byte[] NormalizeToUncompressed(ReadOnlySpan<byte> point, EllipticCurveTypes curveType)
        {
            if(point.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(point), "An elliptic-curve point must not be empty.");
            }

            if(point[0] == UncompressedCoordinateFormat)
            {
                return point.ToArray();
            }

            if(point[0] != EvenYCoordinate && point[0] != OddYCoordinate)
            {
                throw new ArgumentOutOfRangeException(nameof(point), $"Value must start with 0x02, 0x03 or 0x04. Now 0x{point[0]:x2}.");
            }

            //Compressed: X is the payload after the sign byte; Y is recovered from the curve equation. The
            //recovered Y is the same coordinate length as X, so the assembled point is 0x04 || X || Y.
            ReadOnlySpan<byte> x = point[1..];
            byte[] y = Decompress(point, curveType);

            byte[] uncompressed = new byte[1 + x.Length + y.Length];
            uncompressed[0] = UncompressedCoordinateFormat;
            x.CopyTo(uncompressed.AsSpan(1));
            y.CopyTo(uncompressed.AsSpan(1 + x.Length));

            return uncompressed;
        }


        /// <summary>
        /// Resolves the (a, b, (p+1)/4, p, byte-length) tuple for a curve given its
        /// compressed-point byte length and a caller-provided <see cref="EllipticCurveTypes"/>
        /// flag set. Disambiguates the 33-byte case (P-256 / secp256k1 / BrainpoolP256r1)
        /// and the 49-byte case (P-384 / BrainpoolP384r1) by examining flags.
        /// </summary>
        private static (BigInteger CoefficientA, BigInteger CoefficientB, BigInteger PIdentity, BigInteger Prime, int PointArrayLength) ResolveCurveParameters(
            int compressedPointLength, EllipticCurveTypes curveType)
        {
            return compressedPointLength switch
            {
                BrainpoolP224r1CompressedByteCount =>
                    (BrainpoolP224r1.CoefficientA, BrainpoolP224r1.CoefficientB, BrainpoolP224r1.PIdentity, BrainpoolP224r1.Prime, BrainpoolP224r1.PointArrayLength),

                P256CompressedByteCount when curveType.HasFlag(EllipticCurveTypes.BrainpoolP256r1) =>
                    (BrainpoolP256r1.CoefficientA, BrainpoolP256r1.CoefficientB, BrainpoolP256r1.PIdentity, BrainpoolP256r1.Prime, BrainpoolP256r1.PointArrayLength),
                P256CompressedByteCount when curveType.HasFlag(EllipticCurveTypes.Secp256k1) =>
                    (Secp256k1.CoefficientA, Secp256k1.CoefficientB, Secp256k1.PIdentity, Secp256k1.Prime, Secp256k1.PointArrayLength),
                P256CompressedByteCount =>
                    //P-256 path covers explicit P256, NistCurves family, and the no-flag
                    //default — matches the original Decompress fallback semantics.
                    (P256.CoefficientA, P256.CoefficientB, P256.PIdentity, P256.Prime, P256.PointArrayLength),

                BrainpoolP320r1CompressedByteCount =>
                    (BrainpoolP320r1.CoefficientA, BrainpoolP320r1.CoefficientB, BrainpoolP320r1.PIdentity, BrainpoolP320r1.Prime, BrainpoolP320r1.PointArrayLength),

                P384CompressedByteCount when curveType.HasFlag(EllipticCurveTypes.BrainpoolP384r1) =>
                    (BrainpoolP384r1.CoefficientA, BrainpoolP384r1.CoefficientB, BrainpoolP384r1.PIdentity, BrainpoolP384r1.Prime, BrainpoolP384r1.PointArrayLength),
                P384CompressedByteCount =>
                    (P384.CoefficientA, P384.CoefficientB, P384.PIdentity, P384.Prime, P384.PointArrayLength),

                BrainpoolP512r1CompressedByteCount =>
                    (BrainpoolP512r1.CoefficientA, BrainpoolP512r1.CoefficientB, BrainpoolP512r1.PIdentity, BrainpoolP512r1.Prime, BrainpoolP512r1.PointArrayLength),

                P521CompressedByteCount =>
                    (P521.CoefficientA, P521.CoefficientB, P521.PIdentity, P521.Prime, P521.PointArrayLength),

                _ => throw new ArgumentOutOfRangeException(nameof(compressedPointLength),
                    $"No curve parameters known for compressed length {compressedPointLength}.")
            };
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
            if(!IsSupportedCoordinateLength(xPoint.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(xPoint),
                    $"Length must be one of {BrainpoolP224r1.PointArrayLength}, {P256.PointArrayLength}, {BrainpoolP320r1.PointArrayLength}, {P384.PointArrayLength}, {BrainpoolP512r1.PointArrayLength}, {P521.PointArrayLength}.");
            }

            if(!IsSupportedCoordinateLength(yPoint.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint),
                    $"Length must be one of {BrainpoolP224r1.PointArrayLength}, {P256.PointArrayLength}, {BrainpoolP320r1.PointArrayLength}, {P384.PointArrayLength}, {BrainpoolP512r1.PointArrayLength}, {P521.PointArrayLength}.");
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
            if(!IsSupportedCoordinateLength(yPoint.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint),
                    $"Length must be one of {BrainpoolP224r1.PointArrayLength}, {P256.PointArrayLength}, {BrainpoolP320r1.PointArrayLength}, {P384.PointArrayLength}, {BrainpoolP512r1.PointArrayLength}, {P521.PointArrayLength}.");
            }

            return (byte)(2 + (yPoint![^1] & 1));
        }


        //P-256, secp256k1, and BrainpoolP256r1 all use 32-byte coordinates; P-384 and
        //BrainpoolP384r1 share 48-byte; BrainpoolP320r1 (40), BrainpoolP512r1 (64), and
        //P-521 (66) are unambiguous on length. Curve parameters disambiguate where length
        //alone cannot.
        private static bool IsSupportedCoordinateLength(int length) =>
            length == BrainpoolP224r1.PointArrayLength
            || length == P256.PointArrayLength
            || length == BrainpoolP320r1.PointArrayLength
            || length == P384.PointArrayLength
            || length == BrainpoolP512r1.PointArrayLength
            || length == P521.PointArrayLength;


        /// <summary>
        /// Combines separate X and Y coordinate byte spans into an uncompressed point encoding
        /// (0x04 || X || Y). Both spans must be the same length and correspond to a supported curve.
        /// </summary>
        /// <param name="x">The X coordinate bytes, big-endian, zero-padded to the field element length.</param>
        /// <param name="y">The Y coordinate bytes, big-endian, zero-padded to the field element length.</param>
        /// <returns>A new byte array containing the uncompressed point encoding.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="x"/> and <paramref name="y"/> have different lengths.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the length does not correspond to a supported curve.</exception>
        public static byte[] CombineToUncompressedPoint(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
        {
            if(x.Length != y.Length)
            {
                throw new ArgumentException($"Parameters '{nameof(x)}' and '{nameof(y)}' must have the same length.");
            }

            if(!IsSupportedCoordinateLength(x.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(x),
                    $"Length must be one of {BrainpoolP224r1.PointArrayLength}, {P256.PointArrayLength}, {BrainpoolP320r1.PointArrayLength}, {P384.PointArrayLength}, {BrainpoolP512r1.PointArrayLength}, {P521.PointArrayLength}.");
            }

            byte[] result = new byte[1 + x.Length + y.Length];
            result[0] = UncompressedCoordinateFormat;
            x.CopyTo(result.AsSpan(1));
            y.CopyTo(result.AsSpan(1 + x.Length));

            return result;
        }


        public static ReadOnlySpan<byte> SliceXCoordinate(ReadOnlySpan<byte> uncompressedCoordinates)
        {
            if(uncompressedCoordinates[0] != UncompressedCoordinateFormat)
            {
                throw new ArgumentOutOfRangeException(nameof(uncompressedCoordinates), "This method supports only uncompressed coordinates (must start with 0x04).");
            }

            if(!IsSupportedUncompressedLength(uncompressedCoordinates.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(uncompressedCoordinates),
                    $"Length must be one of {BrainpoolP224r1.UncompressedPointByteCount}, {P256.UncompressedPointByteCount}, {BrainpoolP320r1.UncompressedPointByteCount}, {P384.UncompressedPointByteCount}, {BrainpoolP512r1.UncompressedPointByteCount}, {P521.UncompressedPointByteCount}.");
            }

            int coordinateLength = (uncompressedCoordinates.Length - 1) / 2;
            return uncompressedCoordinates.Slice(1, coordinateLength);
        }


        public static ReadOnlySpan<byte> SliceYCoordinate(ReadOnlySpan<byte> uncompressedCoordinates)
        {
            if(uncompressedCoordinates[0] != UncompressedCoordinateFormat)
            {
                throw new ArgumentOutOfRangeException(nameof(uncompressedCoordinates), "This method supports only uncompressed coordinates (must start with 0x04).");
            }

            if(!IsSupportedUncompressedLength(uncompressedCoordinates.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(uncompressedCoordinates),
                    $"Length must be one of {BrainpoolP224r1.UncompressedPointByteCount}, {P256.UncompressedPointByteCount}, {BrainpoolP320r1.UncompressedPointByteCount}, {P384.UncompressedPointByteCount}, {BrainpoolP512r1.UncompressedPointByteCount}, {P521.UncompressedPointByteCount}.");
            }

            int coordinateLength = (uncompressedCoordinates.Length - 1) / 2;

            return uncompressedCoordinates.Slice(1 + coordinateLength, coordinateLength);
        }


        //Companion to IsSupportedCoordinateLength for the 0x04-prefixed full-point form
        //(length 1 + 2 × field byte size).
        private static bool IsSupportedUncompressedLength(int length) =>
            length == BrainpoolP224r1.UncompressedPointByteCount
            || length == P256.UncompressedPointByteCount
            || length == BrainpoolP320r1.UncompressedPointByteCount
            || length == P384.UncompressedPointByteCount
            || length == BrainpoolP512r1.UncompressedPointByteCount
            || length == P521.UncompressedPointByteCount;


        /// <summary>
        /// Extracts the X and Y coordinates from an elliptic curve public key point,
        /// regardless of whether it is stored in compressed or uncompressed SEC1 encoding.
        /// </summary>
        /// <param name="point">
        /// The key material. Either compressed (<c>0x02/0x03 || X</c>) or uncompressed
        /// (<c>0x04 || X || Y</c>) SEC1 encoding. The encoding is detected from the first byte.
        /// </param>
        /// <param name="curveType">
        /// The elliptic curve type. Required only for the compressed path to recover Y via
        /// <see cref="Decompress"/>. Ignored for uncompressed input.
        /// </param>
        /// <param name="x">
        /// On return, a span over the X coordinate bytes. When <paramref name="point"/> is
        /// uncompressed this is a slice into <paramref name="point"/>; when compressed it is
        /// a slice into <paramref name="point"/> after the prefix byte.
        /// </param>
        /// <param name="y">
        /// On return, a span over the Y coordinate bytes. When <paramref name="point"/> is
        /// uncompressed this is a slice into <paramref name="point"/>; when compressed it is
        /// a freshly allocated array returned by <see cref="Decompress"/>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when the first byte is not a valid SEC1 prefix (0x02, 0x03, or 0x04).
        /// </exception>
        public static void ExtractCoordinates(
            ReadOnlySpan<byte> point,
            EllipticCurveTypes curveType,
            out ReadOnlySpan<byte> x,
            out ReadOnlySpan<byte> y)
        {
            if(point[0] == UncompressedCoordinateFormat)
            {
                x = SliceXCoordinate(point);
                y = SliceYCoordinate(point);
                return;
            }

            if(point[0] == EvenYCoordinate || point[0] == OddYCoordinate)
            {
                x = point.Slice(1);
                y = Decompress(point, curveType);
                return;
            }

            throw new ArgumentOutOfRangeException(
                nameof(point),
                $"First byte 0x{point[0]:X2} is not a valid SEC1 prefix. Expected 0x02, 0x03, or 0x04.");
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
                || maybeCompressedCoordinates.Length == BrainpoolP320r1CompressedByteCount
                || maybeCompressedCoordinates.Length == P384CompressedByteCount
                || maybeCompressedCoordinates.Length == BrainpoolP512r1CompressedByteCount
                || maybeCompressedCoordinates.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(maybeCompressedCoordinates),
                    $"Length must be one of {P256CompressedByteCount}, {BrainpoolP320r1CompressedByteCount}, {P384CompressedByteCount}, {BrainpoolP512r1CompressedByteCount}, {P521CompressedByteCount}.");
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
            //Brainpool 32-byte and 48-byte cases are checked first because their byte
            //length collides with P-256/secp256k1 and P-384 respectively. The order is
            //specificity-first: a caller passing the Brainpool flag wants Brainpool
            //parameters even though the raw length would also match a NIST curve.
            return (publicKeyX.Length, curveType) switch
            {
                (BrainpoolP224r1.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.BrainpoolP224r1) =>
                    ValiteParametersInRange(x, y, BrainpoolP224r1.Prime) && ValidateCurve(x, y, BrainpoolP224r1.CoefficientA, BrainpoolP224r1.CoefficientB, BrainpoolP224r1.Prime),

                (BrainpoolP256r1.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.BrainpoolP256r1) =>
                    ValiteParametersInRange(x, y, BrainpoolP256r1.Prime) && ValidateCurve(x, y, BrainpoolP256r1.CoefficientA, BrainpoolP256r1.CoefficientB, BrainpoolP256r1.Prime),

                (BrainpoolP320r1.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.BrainpoolP320r1) =>
                    ValiteParametersInRange(x, y, BrainpoolP320r1.Prime) && ValidateCurve(x, y, BrainpoolP320r1.CoefficientA, BrainpoolP320r1.CoefficientB, BrainpoolP320r1.Prime),

                (BrainpoolP384r1.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.BrainpoolP384r1) =>
                    ValiteParametersInRange(x, y, BrainpoolP384r1.Prime) && ValidateCurve(x, y, BrainpoolP384r1.CoefficientA, BrainpoolP384r1.CoefficientB, BrainpoolP384r1.Prime),

                (BrainpoolP512r1.PointArrayLength, _) when curveType.HasFlag(EllipticCurveTypes.BrainpoolP512r1) =>
                    ValiteParametersInRange(x, y, BrainpoolP512r1.Prime) && ValidateCurve(x, y, BrainpoolP512r1.CoefficientA, BrainpoolP512r1.CoefficientB, BrainpoolP512r1.Prime),

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
