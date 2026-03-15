using System;
using System.Numerics;
using System.Security.Cryptography;
using static Verifiable.Cryptography.EllipticCurveConstants;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Elliptic curve math utilities for P-256 (secp256r1) used in the SECDSA protocol.
/// </summary>
/// <remarks>
/// Provides the scalar and point operations required by Algorithms 1, 2, 3, 4,
/// 19, and 20 of the SECDSA specification at https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf.
/// All arithmetic is pure .NET using <see cref="BigInteger"/>. Curve constants are
/// sourced from <see cref="EllipticCurveConstants.P256"/>. No external crypto
/// library references are permitted in this namespace.
/// </remarks>
public static class EcMath
{
    /// <summary>
    /// Gets the prime field modulus p of P-256.
    /// </summary>
    public static BigInteger P => P256.Prime;

    /// <summary>
    /// Gets the group order q of P-256.
    /// </summary>
    public static BigInteger Q => P256.Order;

    /// <summary>
    /// Gets the curve coefficient a of P-256.
    /// </summary>
    public static BigInteger A => P256.CoefficientA;

    /// <summary>
    /// Gets the curve coefficient b of P-256.
    /// </summary>
    public static BigInteger B => P256.CoefficientB;

    /// <summary>
    /// Gets the base point G of P-256.
    /// </summary>
    public static EcPoint G { get; } = new EcPoint(P256.BasePointX, P256.BasePointY);

    /// <summary>
    /// Generates a cryptographically random non-zero scalar in [1, q-1].
    /// </summary>
    /// <returns>A random scalar suitable for use as a private key or nonce.</returns>
    public static BigInteger RandomScalar()
    {
        BigInteger result;
        byte[] bytes = new byte[P256.PointArrayLength];
        do
        {
            RandomNumberGenerator.Fill(bytes);
            bytes[0] &= 0x7F;
            result = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }
        while(result.IsZero || result >= Q);
        return result;
    }

    /// <summary>
    /// Computes the modular inverse of a scalar: result = scalar^(-1) mod q.
    /// </summary>
    /// <param name="scalar">The scalar to invert. Must be non-zero.</param>
    /// <returns>The modular inverse of the scalar.</returns>
    public static BigInteger ModInverse(BigInteger scalar)
    {
        return BigInteger.ModPow(((scalar % Q) + Q) % Q, Q - 2, Q);
    }

    /// <summary>
    /// Computes scalar multiplication of the base point G: result = scalar * G.
    /// </summary>
    /// <param name="scalar">The scalar multiplier.</param>
    /// <returns>The resulting EC point.</returns>
    public static EcPoint BasePointMultiply(BigInteger scalar)
    {
        return Multiply(G, scalar);
    }

    /// <summary>
    /// Computes scalar multiplication of an arbitrary point: result = scalar * point.
    /// </summary>
    /// <param name="point">The EC point to multiply.</param>
    /// <param name="scalar">The scalar multiplier.</param>
    /// <returns>The resulting EC point.</returns>
    public static EcPoint Multiply(EcPoint point, BigInteger scalar)
    {
        ArgumentNullException.ThrowIfNull(point);
        BigInteger k = ((scalar % Q) + Q) % Q;
        EcPoint result = EcPoint.Infinity;
        EcPoint addend = point;

        while(k > BigInteger.Zero)
        {
            if(!k.IsEven)
            {
                result = Add(result, addend);
            }

            addend = Double(addend);
            k >>= 1;
        }

        return result;
    }

    /// <summary>
    /// Computes point addition: result = point1 + point2.
    /// </summary>
    /// <param name="point1">The first EC point.</param>
    /// <param name="point2">The second EC point.</param>
    /// <returns>The resulting EC point.</returns>
    public static EcPoint Add(EcPoint point1, EcPoint point2)
    {
        ArgumentNullException.ThrowIfNull(point1);
        ArgumentNullException.ThrowIfNull(point2);
        if(point1.IsInfinity)
        {
            return point2;
        }

        if(point2.IsInfinity)
        {
            return point1;
        }

        if(point1.X == point2.X)
        {
            if(point1.Y != point2.Y)
            {
                return EcPoint.Infinity;
            }

            return Double(point1);
        }

        BigInteger lambda = (((point2.Y - point1.Y) % P + P) * BigInteger.ModPow((point2.X - point1.X + P) % P, P - 2, P)) % P;
        BigInteger xR = (lambda * lambda % P - point1.X - point2.X % P + 2 * P) % P;
        BigInteger yR = (lambda * ((point1.X - xR + P) % P) % P - point1.Y + P) % P;

        return new EcPoint(xR, yR);
    }

    /// <summary>
    /// Validates whether a point lies on the P-256 curve: y² ≡ x³ + ax + b (mod p).
    /// </summary>
    /// <param name="point">The point to validate.</param>
    /// <returns><see langword="true"/> if the point is on the curve; otherwise <see langword="false"/>.</returns>
    public static bool IsValidPoint(EcPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);
        if(point.IsInfinity)
        {
            return false;
        }

        BigInteger lhs = point.Y * point.Y % P;
        BigInteger rhs = (BigInteger.ModPow(point.X, 3, P) + A * point.X % P + B) % P;
        return lhs == rhs;
    }

    /// <summary>
    /// Encodes a point in uncompressed form using
    /// <see cref="EllipticCurveUtilities.UncompressedCoordinateFormat"/> as prefix
    /// (<see cref="P256.UncompressedPointByteCount"/> bytes for P-256).
    /// </summary>
    /// <param name="point">The EC point to encode.</param>
    /// <returns>The uncompressed encoding.</returns>
    public static byte[] EncodePointUncompressed(EcPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);
        byte[] result = new byte[P256.UncompressedPointByteCount];
        result[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        ScalarToBytes(point.X).CopyTo(result, 1);
        ScalarToBytes(point.Y).CopyTo(result, 1 + P256.PointArrayLength);
        return result;
    }

    /// <summary>
    /// Encodes a point in compressed form using <see cref="EllipticCurveUtilities.EvenYCoordinate"/>
    /// or <see cref="EllipticCurveUtilities.OddYCoordinate"/> as prefix
    /// (<see cref="P256.CompressedPointByteCount"/> bytes for P-256).
    /// </summary>
    /// <param name="point">The EC point to encode.</param>
    /// <returns>The compressed encoding.</returns>
    public static byte[] EncodePointCompressed(EcPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);
        byte[] result = new byte[P256.CompressedPointByteCount];
        result[0] = point.Y.IsEven ? EllipticCurveUtilities.EvenYCoordinate : EllipticCurveUtilities.OddYCoordinate;
        ScalarToBytes(point.X).CopyTo(result, 1);
        return result;
    }

    /// <summary>
    /// Decodes a point from uncompressed encoding
    /// (<see cref="EllipticCurveUtilities.UncompressedCoordinateFormat"/> || X || Y).
    /// </summary>
    /// <param name="encoded">The uncompressed point encoding.</param>
    /// <returns>The decoded EC point.</returns>
    public static EcPoint DecodePointUncompressed(ReadOnlySpan<byte> encoded)
    {
        BigInteger x = new BigInteger(
            encoded.Slice(1, P256.PointArrayLength),
            isUnsigned: true, isBigEndian: true);
        BigInteger y = new BigInteger(
            encoded.Slice(1 + P256.PointArrayLength, P256.PointArrayLength),
            isUnsigned: true, isBigEndian: true);
        return new EcPoint(x, y);
    }

    /// <summary>
    /// Converts a hash to a <see cref="BigInteger"/> suitable for ECDSA operations.
    /// </summary>
    /// <param name="hash">The hash bytes.</param>
    /// <returns>The hash as a non-negative integer reduced modulo q.</returns>
    public static BigInteger HashToInteger(ReadOnlySpan<byte> hash)
    {
        return new BigInteger(hash, isUnsigned: true, isBigEndian: true) % Q;
    }

    /// <summary>
    /// Encodes a scalar as a big-endian byte array zero-padded to exactly
    /// <see cref="P256.PointArrayLength"/> bytes.
    /// </summary>
    /// <param name="scalar">The scalar to encode.</param>
    /// <returns>The fixed-length encoding.</returns>
    public static byte[] ScalarToBytes(BigInteger scalar)
    {
        byte[] raw = scalar.ToByteArray(isUnsigned: true, isBigEndian: true);
        if(raw.Length == P256.PointArrayLength)
        {
            return raw;
        }

        byte[] padded = new byte[P256.PointArrayLength];
        if(raw.Length > P256.PointArrayLength)
        {
            raw.AsSpan(raw.Length - P256.PointArrayLength).CopyTo(padded);
        }
        else
        {
            raw.CopyTo(padded, P256.PointArrayLength - raw.Length);
        }

        return padded;
    }

    private static EcPoint Double(EcPoint point)
    {
        if(point.IsInfinity)
        {
            return EcPoint.Infinity;
        }

        BigInteger lambda = (3 * point.X % P * point.X % P + A) % P * BigInteger.ModPow(2 * point.Y % P, P - 2, P) % P;
        BigInteger xR = (lambda * lambda % P - 2 * point.X % P + 2 * P) % P;
        BigInteger yR = (lambda * ((point.X - xR + P) % P) % P - point.Y + P) % P;

        return new EcPoint(xR, yR);
    }
}