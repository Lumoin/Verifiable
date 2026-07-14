using Lumoin.Base;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Verifiable.BouncyCastle;

/// <summary>
/// Elliptic-curve point arithmetic backed by BouncyCastle, implementing the backend-agnostic
/// <see cref="EcMultiplyGeneratorDelegate"/> / <see cref="EcMultiplyPointDelegate"/> /
/// <see cref="EcAddPointsDelegate"/> seam over encoded points and scalars.
/// </summary>
/// <remarks>
/// <para>
/// Points cross the boundary in SEC1 uncompressed form (<c>0x04 || X || Y</c>) and scalars as
/// unsigned big-endian bytes; the curve is named by the <see cref="CryptoAlgorithm"/> in the tag and
/// resolved through BouncyCastle's <see cref="ECNamedCurveTable"/> (which covers the brainpool and
/// NIST prime curves ICAO Doc 9303 PACE uses). Private scalars pass to BouncyCastle through a span
/// constructor that copies into its own immutable magnitude — no naked byte[] of private-key material
/// for this layer to track and zero.
/// </para>
/// </remarks>
public static class BouncyCastleEcPointFunctions
{
    /// <summary>
    /// Computes k·G, the scalar multiple of the curve's standard generator.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned EncodedEcPoint is owned and disposed by the caller.")]
    public static ValueTask<EncodedEcPoint> MultiplyGeneratorAsync(
        ReadOnlyMemory<byte> scalar,
        Tag curve,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters parameters = ResolveCurve(curve);
        ECPoint result = parameters.G.Multiply(ToScalar(scalar));

        return ValueTask.FromResult(Encode(result, curve, pool));
    }


    /// <summary>
    /// Computes k·P, the scalar multiple of an encoded point (also the ECDH operation).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned EncodedEcPoint is owned and disposed by the caller.")]
    public static ValueTask<EncodedEcPoint> MultiplyPointAsync(
        ReadOnlyMemory<byte> scalar,
        ReadOnlyMemory<byte> point,
        Tag curve,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters parameters = ResolveCurve(curve);
        ECPoint decoded = DecodeValidPublicPoint(parameters, curve, point);
        ECPoint result = decoded.Multiply(ToScalar(scalar));

        return ValueTask.FromResult(Encode(result, curve, pool));
    }


    /// <summary>
    /// Computes P + Q, the sum of two encoded points.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned EncodedEcPoint is owned and disposed by the caller.")]
    public static ValueTask<EncodedEcPoint> AddPointsAsync(
        ReadOnlyMemory<byte> point,
        ReadOnlyMemory<byte> addend,
        Tag curve,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters parameters = ResolveCurve(curve);
        ECPoint left = parameters.Curve.DecodePoint(point.ToArray());
        ECPoint right = parameters.Curve.DecodePoint(addend.ToArray());
        ECPoint result = left.Add(right);

        return ValueTask.FromResult(Encode(result, curve, pool));
    }


    /// <summary>
    /// Maps a pseudo-random octet string to a curve point in the prime-order subgroup — the point encoding
    /// <c>f_G</c> of PACE Integrated Mapping (Doc 9303 Appendix B.2, affine coordinates; the constant-time
    /// map of Brier et al.). The octet string is reduced modulo the field prime <c>p</c> to a field element
    /// <c>t</c> (<c>0 &lt; t &lt; p</c>), then encoded; the result is multiplied by the cofactor so it lies
    /// in the prime-order subgroup. The curves PACE uses satisfy <c>p ≡ 3 (mod 4)</c>, which the
    /// modular-square-root exponent relies on.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned EncodedEcPoint is owned and disposed by the caller.")]
    public static ValueTask<EncodedEcPoint> Map2PointAsync(
        ReadOnlyMemory<byte> pseudoRandom,
        Tag curve,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters parameters = ResolveCurve(curve);
        BigInteger p = parameters.Curve.Field.Characteristic;
        BigInteger a = parameters.Curve.A.ToBigInteger();
        BigInteger b = parameters.Curve.B.ToBigInteger();

        BigInteger one = BigInteger.One;
        BigInteger three = BigInteger.Three;
        BigInteger four = BigInteger.ValueOf(4);

        //Doc 9303 Appendix B.2 over GF(p). The input t is the pseudo-random octet string reduced mod p.
        BigInteger t = ToScalar(pseudoRandom).Mod(p);
        BigInteger alpha = t.Multiply(t).Negate().Mod(p);                                     // alpha = -t^2
        BigInteger alphaSum = alpha.Add(alpha.Multiply(alpha)).Mod(p);                        // alpha + alpha^2
        BigInteger x2 = b.Negate().Multiply(a.ModInverse(p)).Mod(p)
            .Multiply(one.Add(alphaSum.ModInverse(p))).Mod(p);                                // X2 = -b a^-1 (1 + (alpha+alpha^2)^-1)
        BigInteger x3 = alpha.Multiply(x2).Mod(p);                                            // X3 = alpha X2
        BigInteger h2 = x2.ModPow(three, p).Add(a.Multiply(x2)).Add(b).Mod(p);                // h2 = X2^3 + a X2 + b
        BigInteger u = t.ModPow(three, p).Multiply(h2).Mod(p);                                // U = t^3 h2
        BigInteger exponent = p.Subtract(one).Subtract(p.Add(one).Divide(four));             // p - 1 - (p+1)/4
        BigInteger sqrtFactor = h2.ModPow(exponent, p);                                       // A = h2^(p-1-(p+1)/4)

        BigInteger x;
        BigInteger y;
        if(sqrtFactor.Multiply(sqrtFactor).Multiply(h2).Mod(p).Equals(one))                   // A^2 h2 == 1 ?
        {
            x = x2;
            y = sqrtFactor.Multiply(h2).Mod(p);
        }
        else
        {
            x = x3;
            y = sqrtFactor.Multiply(u).Mod(p);
        }

        ECPoint mapped = parameters.Curve.CreatePoint(x, y);
        BigInteger cofactor = parameters.H;
        if(!cofactor.Equals(one))
        {
            mapped = mapped.Multiply(cofactor);
        }

        return ValueTask.FromResult(Encode(mapped, curve, pool));
    }


    /// <summary>
    /// Computes the PACE Chip Authentication Mapping authentication data
    /// <c>CA_IC = s_IC⁻¹ · s_Map,IC mod n</c> (Doc 9303 Part 11 §4.4.3.5.1), encoded to the group-order width
    /// (<c>FE2OS</c>, §4.4.5.6) in pinned, zeroized memory because it is derived from the static private key.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned buffer is owned and disposed by the caller.")]
    public static ValueTask<IMemoryOwner<byte>> ChipAuthenticationDataAsync(
        ReadOnlyMemory<byte> staticPrivateKey,
        ReadOnlyMemory<byte> ephemeralMappingPrivateKey,
        Tag curve,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        X9ECParameters parameters = ResolveCurve(curve);
        BigInteger order = parameters.N;
        BigInteger staticScalar = ToScalar(staticPrivateKey);
        BigInteger mappingScalar = ToScalar(ephemeralMappingPrivateKey);

        BigInteger chipAuthenticationData = staticScalar.ModInverse(order).Multiply(mappingScalar).Mod(order);
        int orderLength = (order.BitLength + 7) / 8;

        return ValueTask.FromResult(EncodeScalar(chipAuthenticationData, orderLength, pool));
    }


    /// <summary>
    /// Encodes a scalar as a fixed-width unsigned big-endian value into a pinned, zeroized buffer (when the
    /// pool supports it), clearing the transient BouncyCastle array.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned buffer is owned and disposed by the caller.")]
    private static IMemoryOwner<byte> EncodeScalar(BigInteger value, int length, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool is BaseMemoryPool basePool
            ? basePool.Rent(length, AllocationKind.Pinned)
            : pool.Rent(length);
        try
        {
            byte[] magnitude = BigIntegers.AsUnsignedByteArray(length, value);
            try
            {
                magnitude.AsSpan().CopyTo(owner.Memory.Span);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(magnitude);
            }

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Converts unsigned big-endian scalar bytes to a positive <see cref="BigInteger"/>. The span ctor
    /// copies the scalar into BouncyCastle's own immutable magnitude — no naked byte[] of private-key
    /// material for us to track and zero.
    /// </summary>
    private static BigInteger ToScalar(ReadOnlyMemory<byte> scalar)
    {
        return new BigInteger(1, scalar.Span);
    }


    /// <summary>
    /// Encodes a point in SEC1 uncompressed form into a freshly rented <see cref="EncodedEcPoint"/>
    /// carrying the curve tag.
    /// </summary>
    private static EncodedEcPoint Encode(ECPoint point, Tag curve, MemoryPool<byte> pool)
    {
        byte[] encoded = point.Normalize().GetEncoded(false);

        return EncodedEcPoint.FromBytes(encoded, curve, pool);
    }


    /// <summary>
    /// Decodes an encoded peer-supplied elliptic-curve point and validates it as a usable public key before it is
    /// used in a key agreement (an ECDH scalar multiplication). Skipping this check lets a hostile peer send the
    /// SEC1 point-at-infinity encoding (a single <c>0x00</c> byte), which multiplies to the identity for any scalar
    /// and collapses the shared secret to a fixed, key-independent value — a full PACE / Chip Authentication bypass.
    /// Validation runs the shared partial public-key check (NIST SP 800-186 D.1.1.1, the identity/range/on-curve
    /// steps): <see cref="EllipticCurveUtilities.ExtractCoordinates"/> rejects the point at infinity and any non-SEC1
    /// or wrong-length encoding, and <see cref="EllipticCurveUtilities.CheckPointOnCurve"/> rejects an off-curve or
    /// out-of-range point. The ICAO curves have cofactor 1, so on-curve and non-identity is full public-key validation.
    /// </summary>
    private static ECPoint DecodeValidPublicPoint(X9ECParameters parameters, Tag curve, ReadOnlyMemory<byte> point)
    {
        if(!curve.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new ArgumentException("The tag must carry a CryptoAlgorithm to select the curve.", nameof(curve));
        }

        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(algorithm);
        bool onCurve;
        try
        {
            EllipticCurveUtilities.ExtractCoordinates(point.Span, curveType, out ReadOnlySpan<byte> x, out ReadOnlySpan<byte> y);
            onCurve = EllipticCurveUtilities.CheckPointOnCurve(x, y, curveType);
        }
        catch(ArgumentOutOfRangeException exception)
        {
            //ExtractCoordinates throws for the point at infinity (a single 0x00 byte) and any non-SEC1 or
            //wrong-length encoding; surface every invalid-point rejection as one ArgumentException.
            throw new ArgumentException(
                "The supplied elliptic-curve point is not a valid public key: it is the point at infinity, out of range, or a malformed encoding.", nameof(point), exception);
        }

        if(!onCurve)
        {
            throw new ArgumentException(
                "The supplied elliptic-curve point is not a valid public key: it is not on the expected curve.", nameof(point));
        }

        return parameters.Curve.DecodePoint(point.ToArray());
    }


    /// <summary>
    /// Resolves the curve domain parameters named by the <see cref="CryptoAlgorithm"/> in the tag.
    /// </summary>
    private static X9ECParameters ResolveCurve(Tag curve)
    {
        if(!curve.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new ArgumentException("The tag must carry a CryptoAlgorithm to select the curve.", nameof(curve));
        }

        string name = CurveName(algorithm);

        return ECNamedCurveTable.GetByName(name)
            ?? throw new ArgumentException($"BouncyCastle has no named curve '{name}'.", nameof(curve));
    }


    /// <summary>
    /// Maps a <see cref="CryptoAlgorithm"/> curve identifier to its BouncyCastle named-curve name.
    /// </summary>
    private static string CurveName(CryptoAlgorithm algorithm)
    {
        if(algorithm == CryptoAlgorithm.BrainpoolP224r1) { return "brainpoolP224r1"; }
        if(algorithm == CryptoAlgorithm.BrainpoolP256r1) { return "brainpoolP256r1"; }
        if(algorithm == CryptoAlgorithm.BrainpoolP320r1) { return "brainpoolP320r1"; }
        if(algorithm == CryptoAlgorithm.BrainpoolP384r1) { return "brainpoolP384r1"; }
        if(algorithm == CryptoAlgorithm.BrainpoolP512r1) { return "brainpoolP512r1"; }
        if(algorithm == CryptoAlgorithm.P256) { return "P-256"; }
        if(algorithm == CryptoAlgorithm.P384) { return "P-384"; }
        if(algorithm == CryptoAlgorithm.P521) { return "P-521"; }

        throw new ArgumentException($"EC point arithmetic is not implemented for algorithm '{algorithm}'.", nameof(algorithm));
    }
}
