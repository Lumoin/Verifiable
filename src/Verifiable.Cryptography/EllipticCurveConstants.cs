using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;

namespace Verifiable.Cryptography;

/// <summary>
/// Constants to work with Elliptic curve function.
/// </summary>
public static class EllipticCurveConstants
{
    //NOTE: The lenghts of the constant byte arrays are well known. They are explicitly marked in the definitions to catch typing errors.
    //See https://csrc.nist.gov/publications/detail/fips/186/5/final and https://csrc.nist.gov/publications/detail/sp/800-186/final
    //for in-depth material.

    /// <summary>
    /// These are precomputed constants for P-256 elliptic curve. The source of definitions is at
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">NIST Special Publication 800-186
    /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see> page 10.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class P256
    {
        /// <summary>
        /// The length of a P-256 byte array.
        /// </summary>
        public const int PointArrayLength = 32;

        // <summary>
        /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 224) + BigInteger.Pow(2, 192) + BigInteger.Pow(2, 96) - 1;
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>115792089210356248762697446949407573530086143415290314195533631308867097853951</description>.
        ///     </item>
        ///     <item>            
        ///         <term>Hexadecimal</term>
        ///         <description>0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

        /// <summary>
        /// This is a constant from the NIST document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>115792089210356248762697446949407573530086143415290314195533631308867097853951</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>            
        ///         <description>0XFFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };

        /// <summary>
        /// This is a constant from the NIST document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>41058363725152142129326129780047268409114441015993725554835256314039467401291</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0x5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b };

        /// <summary>
        /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>115792089210356248762697446949407573530086143415290314195533631308867097853951</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        /// </summary>
        public static ReadOnlySpan<byte> PIdentityBytes => new byte[PointArrayLength] { 0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        /// <summary>
        /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>
        /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger PIdentity => new(PIdentityBytes, true, true);

        /// <summary>
        /// The group order q of P-256: the number of points on the curve.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0xffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> OrderBytes => new byte[PointArrayLength] { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };

        /// <summary>
        /// The x-coordinate of the base point G of P-256.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0x6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> BasePointXBytes => new byte[PointArrayLength] { 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96 };

        /// <summary>
        /// The y-coordinate of the base point G of P-256.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0x4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> BasePointYBytes => new byte[PointArrayLength] { 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5 };

        /// <summary>
        /// The byte length of an uncompressed P-256 point encoding: 0x04 prefix + X + Y.
        /// </summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>
        /// The byte length of a compressed P-256 point encoding: 0x02/0x03 prefix + X.
        /// </summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>
        /// Turns <see cref="OrderBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger Order => new(OrderBytes, true, true);

        /// <summary>
        /// Turns <see cref="BasePointXBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger BasePointX => new(BasePointXBytes, true, true);

        /// <summary>
        /// Turns <see cref="BasePointYBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger BasePointY => new(BasePointYBytes, true, true);
    }

    /// <summary>
    /// These are precomputed constants for P-384 elliptic curve. The source of definitions is at
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">Draft NIST Special Publication 800-186
    /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see> page 11.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class P384
    {
        /// <summary>
        /// The length of a P-384 byte array.
        /// </summary>
        public const int PointArrayLength = 48;

        /// <summary>
        /// The byte length of an uncompressed P-384 point encoding: 0x04 prefix + X + Y.
        /// </summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>
        /// The byte length of a compressed P-384 point encoding: 0x02/0x03 prefix + X.
        /// </summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>
        /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 384) - BigInteger.Pow(2, 128) - BigInteger.Pow(2, 96) + BigInteger.Pow(2, 32) - 1;
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff 606 ffffffff fffffffe ffffffff 00000000 00000000 ffffffff</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };

        /// <summary>
        /// This is a constant for Coefficient A of the P-384 curve.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC };

        /// <summary>
        /// This is a constant from the NIST document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0xb3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 623 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef };

        /// <summary>
        /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>9850501549098619803069760025035903451269934817616361666987073351061430442874217582261816522064734500465401743278080</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0x3fffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffff ffffffff ffffbfff ffffc000 00000000 00004000 0000</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        /// </summary>
        public static ReadOnlySpan<byte> PIdentityBytes => new byte[PointArrayLength] { 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 };

        /// <summary>
        /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>
        /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger PIdentity => new(PIdentityBytes, true, true);
    }

    /// <summary>
    /// These are precomputed constants for P-521 elliptic curve. The source of definitions is at
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">Draft NIST Special Publication 800-186
    /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see> page 12.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class P521
    {
        /// <summary>
        /// The length of a P-521 byte array.
        /// </summary>
        public const int PointArrayLength = 66;

        /// <summary>
        /// The byte length of an uncompressed P-521 point encoding: 0x04 prefix + X + Y.
        /// </summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>
        /// The byte length of a compressed P-521 point encoding: 0x02/0x03 prefix + X.
        /// </summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>
        /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 521) - 1;
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151</description>.
        ///     </item>
        ///     <item>            
        ///         <term>Hexadecimal</term>
        ///         <description>0x1ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

        /// <summary>
        /// This is a constant from the NIST document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0x1ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc };

        /// <summary>
        /// This is a constant from the NIST document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>0x051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00, };

        /// <summary>
        /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>115792089237316195423570985008687907853269984665640564039457584007908834671663</description>.
        ///     </item>
        ///     <item>            
        ///         <term>Hexadecimal</term>            
        ///         <description>0x3FFFFC2F 00000000 00000000 00000000 00000000 00000000 00000000 00000001</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        /// </summary>
        public static ReadOnlySpan<byte> PIdentityBytes => new byte[PointArrayLength] { 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        /// <summary>
        /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>
        /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger PIdentity => new(PIdentityBytes, true, true);
    }

    /// <summary>
    /// These are precomputed constants for P-521 elliptic curve. The source of definitions is at
    /// <see href="https://www.secg.org/sec2-v2.pdf">SEC 2: Recommended Elliptic Curve Domain Parameters</see> page 9.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class Secp256k1
    {
        /// <summary>
        /// The length of a secp256k1 byte array.
        /// </summary>
        public const int PointArrayLength = 32;

        /// <summary>
        /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 32) - BigInteger.Pow(2, 9) - BigInteger.Pow(2, 8) - BigInteger.Pow(2, 7) - BigInteger.Pow(2, 6) - BigInteger.Pow(2, 4) - 1;
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>115792089237316195423570985008687907853269984665640564039457584007908834671663</description>.
        ///     </item>
        ///     <item>            
        ///         <term>Hexadecimal</term>
        ///         <description>0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE FFFF FFFF FFFF FFFF FFFF FFFF FFFF FC2F</description>.            
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F };

        /// <summary>
        /// This is a constant from the SEC 2 document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>0</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        /// <summary>
        /// This is a constant from the SEC 2 document.
        /// </summary>
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>7</description>.
        ///     </item>
        ///     <item>
        ///         <term>Hexadecimal</term>
        ///         <description>00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07 };

        /// <summary>
        /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
        /// <remarks>
        /// <list type="table">
        ///     <item>
        ///         <term>Decimal</term>
        ///         <description>30873997988253182731593460482201281715646543533720394220132759688881729956016</description>.
        ///     </item>
        ///     <item>            
        ///         <term>Hexadecimal</term>            
        ///         <description>0x3FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF EAAAB773 D952A02F DFE29763 F3461050</description>.
        ///     </item>
        /// </list>
        /// </remarks>
        /// </summary>
        public static ReadOnlySpan<byte> PIdentityBytes => new byte[PointArrayLength] { 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0x0C };

        /// <summary>
        /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>
        /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>
        /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
        /// </summary>
        public static BigInteger PIdentity => new(PIdentityBytes, true, true);
    }


    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class Curve25519
    {
        public const int PointArrayLength = 32;

        public static readonly BigInteger Prime = BigInteger.Parse("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        public static readonly BigInteger A = 486662;
        public static readonly BigInteger B = 1;
    }


    //Brainpool prime r1 curves per RFC 5639. Unlike NIST P-curves (a = -3) and
    //secp256k1 (a = 0), Brainpool curves use general short-Weierstrass form
    //y^2 = x^3 + ax + b (mod p) with arbitrary a. The Curve25519-style hex
    //parsing is used here both because the byte literals would be unwieldy
    //(64 hex digits per constant × 4 constants × 4 curves) and because each
    //prime is ≡ 3 (mod 4) so PIdentity = (p + 1) / 4 falls out by computation.


    /// <summary>
    /// Pre-computed constants for the Brainpool P-256r1 elliptic curve per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639 §3.4</see>.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class BrainpoolP256r1
    {
        /// <summary>The length of a Brainpool P-256r1 field element in bytes.</summary>
        public const int PointArrayLength = 32;

        /// <summary>The byte length of an uncompressed Brainpool P-256r1 point encoding: 0x04 prefix + X + Y.</summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>The byte length of a compressed Brainpool P-256r1 point encoding: 0x02/0x03 prefix + X.</summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>The curve prime p per RFC 5639 §3.4.</summary>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x72, 0x6e, 0x3b, 0xf6, 0x23, 0xd5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1d, 0x1f, 0x6e, 0x53, 0x77 };

        /// <summary>The curve a coefficient per RFC 5639 §3.4.</summary>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x7d, 0x5a, 0x09, 0x75, 0xfc, 0x2c, 0x30, 0x57, 0xee, 0xf6, 0x75, 0x30, 0x41, 0x7a, 0xff, 0xe7, 0xfb, 0x80, 0x55, 0xc1, 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, 0x30, 0xb5, 0xd9 };

        /// <summary>The curve b coefficient per RFC 5639 §3.4.</summary>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, 0x30, 0xb5, 0xd9, 0xbb, 0xd7, 0x7c, 0xbf, 0x95, 0x84, 0x16, 0x29, 0x5c, 0xf7, 0xe1, 0xce, 0x6b, 0xcc, 0xdc, 0x18, 0xff, 0x8c, 0x07, 0xb6 };

        /// <summary>Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>The square-root exponent (Prime + 1) / 4 for Tonelli–Shanks shortcut when p ≡ 3 (mod 4).</summary>
        public static BigInteger PIdentity => (Prime + 1) / 4;
    }


    /// <summary>
    /// Pre-computed constants for the Brainpool P-224r1 elliptic curve per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639 §3.3</see>.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class BrainpoolP224r1
    {
        /// <summary>The length of a Brainpool P-224r1 field element in bytes.</summary>
        public const int PointArrayLength = 28;

        /// <summary>The byte length of an uncompressed Brainpool P-224r1 point encoding: 0x04 prefix + X + Y.</summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>The byte length of a compressed Brainpool P-224r1 point encoding: 0x02/0x03 prefix + X.</summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>The curve prime p per RFC 5639 §3.3.</summary>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xd7, 0xc1, 0x34, 0xaa, 0x26, 0x43, 0x66, 0x86, 0x2a, 0x18, 0x30, 0x25, 0x75, 0xd1, 0xd7, 0x87, 0xb0, 0x9f, 0x07, 0x57, 0x97, 0xda, 0x89, 0xf5, 0x7e, 0xc8, 0xc0, 0xff };

        /// <summary>The curve a coefficient per RFC 5639 §3.3.</summary>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x68, 0xa5, 0xe6, 0x2c, 0xa9, 0xce, 0x6c, 0x1c, 0x29, 0x98, 0x03, 0xa6, 0xc1, 0x53, 0x0b, 0x51, 0x4e, 0x18, 0x2a, 0xd8, 0xb0, 0x04, 0x2a, 0x59, 0xca, 0xd2, 0x9f, 0x43 };

        /// <summary>The curve b coefficient per RFC 5639 §3.3.</summary>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x25, 0x80, 0xf6, 0x3c, 0xcf, 0xe4, 0x41, 0x38, 0x87, 0x07, 0x13, 0xb1, 0xa9, 0x23, 0x69, 0xe3, 0x3e, 0x21, 0x35, 0xd2, 0x66, 0xdb, 0xb3, 0x72, 0x38, 0x6c, 0x40, 0x0b };

        /// <summary>Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>The square-root exponent (Prime + 1) / 4 for Tonelli–Shanks shortcut when p ≡ 3 (mod 4).</summary>
        public static BigInteger PIdentity => (Prime + 1) / 4;
    }


    /// <summary>
    /// Pre-computed constants for the Brainpool P-320r1 elliptic curve per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639 §3.5</see>.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class BrainpoolP320r1
    {
        /// <summary>The length of a Brainpool P-320r1 field element in bytes.</summary>
        public const int PointArrayLength = 40;

        /// <summary>The byte length of an uncompressed Brainpool P-320r1 point encoding: 0x04 prefix + X + Y.</summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>The byte length of a compressed Brainpool P-320r1 point encoding: 0x02/0x03 prefix + X.</summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>The curve prime p per RFC 5639 §3.5.</summary>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xd3, 0x5e, 0x47, 0x20, 0x36, 0xbc, 0x4f, 0xb7, 0xe1, 0x3c, 0x78, 0x5e, 0xd2, 0x01, 0xe0, 0x65, 0xf9, 0x8f, 0xcf, 0xa6, 0xf6, 0xf4, 0x0d, 0xef, 0x4f, 0x92, 0xb9, 0xec, 0x78, 0x93, 0xec, 0x28, 0xfc, 0xd4, 0x12, 0xb1, 0xf1, 0xb3, 0x2e, 0x27 };

        /// <summary>The curve a coefficient per RFC 5639 §3.5.</summary>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x3e, 0xe3, 0x0b, 0x56, 0x8f, 0xba, 0xb0, 0xf8, 0x83, 0xcc, 0xeb, 0xd4, 0x6d, 0x3f, 0x3b, 0xb8, 0xa2, 0xa7, 0x35, 0x13, 0xf5, 0xeb, 0x79, 0xda, 0x66, 0x19, 0x0e, 0xb0, 0x85, 0xff, 0xa9, 0xf4, 0x92, 0xf3, 0x75, 0xa9, 0x7d, 0x86, 0x0e, 0xb4 };

        /// <summary>The curve b coefficient per RFC 5639 §3.5.</summary>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x52, 0x08, 0x83, 0x94, 0x9d, 0xfd, 0xbc, 0x42, 0xd3, 0xad, 0x19, 0x86, 0x40, 0x68, 0x8a, 0x6f, 0xe1, 0x3f, 0x41, 0x34, 0x95, 0x54, 0xb4, 0x9a, 0xcc, 0x31, 0xdc, 0xcd, 0x88, 0x45, 0x39, 0x81, 0x6f, 0x5e, 0xb4, 0xac, 0x8f, 0xb1, 0xf1, 0xa6 };

        /// <summary>Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>The square-root exponent (Prime + 1) / 4 for Tonelli–Shanks shortcut when p ≡ 3 (mod 4).</summary>
        public static BigInteger PIdentity => (Prime + 1) / 4;
    }


    /// <summary>
    /// Pre-computed constants for the Brainpool P-384r1 elliptic curve per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639 §3.6</see>.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class BrainpoolP384r1
    {
        /// <summary>The length of a Brainpool P-384r1 field element in bytes.</summary>
        public const int PointArrayLength = 48;

        /// <summary>The byte length of an uncompressed Brainpool P-384r1 point encoding: 0x04 prefix + X + Y.</summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>The byte length of a compressed Brainpool P-384r1 point encoding: 0x02/0x03 prefix + X.</summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>The curve prime p per RFC 5639 §3.6.</summary>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6, 0x41, 0xdf, 0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb4, 0x12, 0xb1, 0xda, 0x19, 0x7f, 0xb7, 0x11, 0x23, 0xac, 0xd3, 0xa7, 0x29, 0x90, 0x1d, 0x1a, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xec, 0x53 };

        /// <summary>The curve a coefficient per RFC 5639 §3.6.</summary>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x7b, 0xc3, 0x82, 0xc6, 0x3d, 0x8c, 0x15, 0x0c, 0x3c, 0x72, 0x08, 0x0a, 0xce, 0x05, 0xaf, 0xa0, 0xc2, 0xbe, 0xa2, 0x8e, 0x4f, 0xb2, 0x27, 0x87, 0x13, 0x91, 0x65, 0xef, 0xba, 0x91, 0xf9, 0x0f, 0x8a, 0xa5, 0x81, 0x4a, 0x50, 0x3a, 0xd4, 0xeb, 0x04, 0xa8, 0xc7, 0xdd, 0x22, 0xce, 0x28, 0x26 };

        /// <summary>The curve b coefficient per RFC 5639 §3.6.</summary>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x04, 0xa8, 0xc7, 0xdd, 0x22, 0xce, 0x28, 0x26, 0x8b, 0x39, 0xb5, 0x54, 0x16, 0xf0, 0x44, 0x7c, 0x2f, 0xb7, 0x7d, 0xe1, 0x07, 0xdc, 0xd2, 0xa6, 0x2e, 0x88, 0x0e, 0xa5, 0x3e, 0xeb, 0x62, 0xd5, 0x7c, 0xb4, 0x39, 0x02, 0x95, 0xdb, 0xc9, 0x94, 0x3a, 0xb7, 0x86, 0x96, 0xfa, 0x50, 0x4c, 0x11 };

        /// <summary>Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>The square-root exponent (Prime + 1) / 4 for Tonelli–Shanks shortcut when p ≡ 3 (mod 4).</summary>
        public static BigInteger PIdentity => (Prime + 1) / 4;
    }


    /// <summary>
    /// Pre-computed constants for the Brainpool P-512r1 elliptic curve per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639 §3.7</see>.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The curve constants are organized like this on purpose.")]
    public static class BrainpoolP512r1
    {
        /// <summary>The length of a Brainpool P-512r1 field element in bytes.</summary>
        public const int PointArrayLength = 64;

        /// <summary>The byte length of an uncompressed Brainpool P-512r1 point encoding: 0x04 prefix + X + Y.</summary>
        public const int UncompressedPointByteCount = 1 + 2 * PointArrayLength;

        /// <summary>The byte length of a compressed Brainpool P-512r1 point encoding: 0x02/0x03 prefix + X.</summary>
        public const int CompressedPointByteCount = 1 + PointArrayLength;

        /// <summary>The curve prime p per RFC 5639 §3.7.</summary>
        public static ReadOnlySpan<byte> PrimeBytes => new byte[PointArrayLength] { 0xaa, 0xdd, 0x9d, 0xb8, 0xdb, 0xe9, 0xc4, 0x8b, 0x3f, 0xd4, 0xe6, 0xae, 0x33, 0xc9, 0xfc, 0x07, 0xcb, 0x30, 0x8d, 0xb3, 0xb3, 0xc9, 0xd2, 0x0e, 0xd6, 0x63, 0x9c, 0xca, 0x70, 0x33, 0x08, 0x71, 0x7d, 0x4d, 0x9b, 0x00, 0x9b, 0xc6, 0x68, 0x42, 0xae, 0xcd, 0xa1, 0x2a, 0xe6, 0xa3, 0x80, 0xe6, 0x28, 0x81, 0xff, 0x2f, 0x2d, 0x82, 0xc6, 0x85, 0x28, 0xaa, 0x60, 0x56, 0x58, 0x3a, 0x48, 0xf3 };

        /// <summary>The curve a coefficient per RFC 5639 §3.7.</summary>
        public static ReadOnlySpan<byte> CoefficientABytes => new byte[PointArrayLength] { 0x78, 0x30, 0xa3, 0x31, 0x8b, 0x60, 0x3b, 0x89, 0xe2, 0x32, 0x71, 0x45, 0xac, 0x23, 0x4c, 0xc5, 0x94, 0xcb, 0xdd, 0x8d, 0x3d, 0xf9, 0x16, 0x10, 0xa8, 0x34, 0x41, 0xca, 0xea, 0x98, 0x63, 0xbc, 0x2d, 0xed, 0x5d, 0x5a, 0xa8, 0x25, 0x3a, 0xa1, 0x0a, 0x2e, 0xf1, 0xc9, 0x8b, 0x9a, 0xc8, 0xb5, 0x7f, 0x11, 0x17, 0xa7, 0x2b, 0xf2, 0xc7, 0xb9, 0xe7, 0xc1, 0xac, 0x4d, 0x77, 0xfc, 0x94, 0xca };

        /// <summary>The curve b coefficient per RFC 5639 §3.7.</summary>
        public static ReadOnlySpan<byte> CoefficientBBytes => new byte[PointArrayLength] { 0x3d, 0xf9, 0x16, 0x10, 0xa8, 0x34, 0x41, 0xca, 0xea, 0x98, 0x63, 0xbc, 0x2d, 0xed, 0x5d, 0x5a, 0xa8, 0x25, 0x3a, 0xa1, 0x0a, 0x2e, 0xf1, 0xc9, 0x8b, 0x9a, 0xc8, 0xb5, 0x7f, 0x11, 0x17, 0xa7, 0x2b, 0xf2, 0xc7, 0xb9, 0xe7, 0xc1, 0xac, 0x4d, 0x77, 0xfc, 0x94, 0xca, 0xdc, 0x08, 0x3e, 0x67, 0x98, 0x40, 0x50, 0xb7, 0x5e, 0xba, 0xe5, 0xdd, 0x28, 0x09, 0xbd, 0x63, 0x80, 0x16, 0xf7, 0x23 };

        /// <summary>Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger Prime => new(PrimeBytes, true, true);

        /// <summary>Turns <see cref="CoefficientABytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientA => new(CoefficientABytes, true, true);

        /// <summary>Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.</summary>
        public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

        /// <summary>The square-root exponent (Prime + 1) / 4 for Tonelli–Shanks shortcut when p ≡ 3 (mod 4).</summary>
        public static BigInteger PIdentity => (Prime + 1) / 4;
    }
}