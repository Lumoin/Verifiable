using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// Low-level elliptic-curve point arithmetic, expressed as a backend-agnostic seam: every operation
/// takes and returns <em>encoded</em> points (SEC1 uncompressed, <c>0x04 || X || Y</c>) and scalars
/// (unsigned big-endian bytes), so no backend's native point type crosses the boundary.
/// </summary>
/// <remarks>
/// <para>
/// These primitives exist for protocols that need raw curve arithmetic beyond a single ECDH — most
/// immediately ICAO Doc 9303 PACE Generic Mapping, whose mapped generator is <c>Ĝ = s·G + H</c> and
/// whose key agreement runs over that custom generator. Standard ECDH on the curve's own generator
/// is already covered by the key-agreement functions; this seam adds scalar multiplication of the
/// generator, scalar multiplication of an arbitrary point (which also performs ECDH), and point
/// addition.
/// </para>
/// <para>
/// Because the seam speaks only encoded bytes, the implementation is freely swappable — a
/// BouncyCastle backend today, a managed backend later — and an algorithm built on it can be
/// re-hosted to a different library without changing its protocol logic. The curve is selected by
/// the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> carried in the
/// <paramref name="curve"/> tag.
/// </para>
/// </remarks>
/// <param name="scalar">The scalar k as unsigned big-endian bytes.</param>
/// <param name="curve">A tag carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the curve.</param>
/// <param name="pool">Memory pool for the encoded result point.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The point k·G as an <see cref="EncodedEcPoint"/>. The caller owns and disposes it.</returns>
public delegate ValueTask<EncodedEcPoint> EcMultiplyGeneratorDelegate(
    ReadOnlyMemory<byte> scalar,
    Tag curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Multiplies an encoded curve point by a scalar: <c>k·P</c>. With a private scalar and the other
/// party's public point this is the ECDH operation; the shared secret is the X-coordinate of the result.
/// </summary>
/// <param name="scalar">The scalar k as unsigned big-endian bytes.</param>
/// <param name="point">The point P, SEC1 uncompressed (<c>0x04 || X || Y</c>).</param>
/// <param name="curve">A tag carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the curve.</param>
/// <param name="pool">Memory pool for the encoded result point.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The point k·P as an <see cref="EncodedEcPoint"/>. The caller owns and disposes it.</returns>
public delegate ValueTask<EncodedEcPoint> EcMultiplyPointDelegate(
    ReadOnlyMemory<byte> scalar,
    ReadOnlyMemory<byte> point,
    Tag curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Adds two encoded curve points: <c>P + Q</c>.
/// </summary>
/// <param name="point">The point P, SEC1 uncompressed (<c>0x04 || X || Y</c>).</param>
/// <param name="addend">The point Q, SEC1 uncompressed (<c>0x04 || X || Y</c>).</param>
/// <param name="curve">A tag carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the curve.</param>
/// <param name="pool">Memory pool for the encoded result point.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The point P + Q as an <see cref="EncodedEcPoint"/>. The caller owns and disposes it.</returns>
public delegate ValueTask<EncodedEcPoint> EcAddPointsDelegate(
    ReadOnlyMemory<byte> point,
    ReadOnlyMemory<byte> addend,
    Tag curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Maps a pseudo-random octet string to a curve point in the prime-order subgroup — the point encoding
/// <c>f_G</c> of ICAO Doc 9303 Part 11 PACE Integrated Mapping (the constant-time map of
/// <see href="https://eprint.iacr.org/2009/340">Brier et al.</see>, informatively described in Doc 9303
/// Appendix B). The octet string is first reduced modulo the field prime <c>p</c> to a field element
/// (the <c>mod p</c> that completes the Integrated Mapping pseudo-random function <c>R_p</c>), then
/// encoded to a point; the curve coefficients and prime are needed, so this is an EC-arithmetic primitive
/// rather than pure octet-string work.
/// </summary>
/// <param name="pseudoRandom">The pseudo-random octet string from the Integrated Mapping PRF, big-endian.</param>
/// <param name="curve">A tag carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the curve.</param>
/// <param name="pool">Memory pool for the encoded result point.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The mapped point as an <see cref="EncodedEcPoint"/> (SEC1 uncompressed). The caller owns and disposes it.</returns>
public delegate ValueTask<EncodedEcPoint> EcMap2PointDelegate(
    ReadOnlyMemory<byte> pseudoRandom,
    Tag curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Computes the PACE Chip Authentication Mapping authentication data (ICAO Doc 9303 Part 11 §4.4.3.5.1): the
/// scalar <c>CA_IC = s_IC⁻¹ · s_Map,IC mod n</c>, where <c>s_IC</c> is the chip's static private key,
/// <c>s_Map,IC</c> is the ephemeral mapping private key from the Generic Mapping round, and <c>n</c> is the
/// curve's group order. Knowing the group order is what makes this an EC-arithmetic primitive rather than pure
/// octet-string work; the terminal later recovers <c>CA_IC</c> and checks <c>PK_Map,IC = CA_IC · PK_IC</c>
/// (an ordinary scalar multiplication) to authenticate the chip.
/// </summary>
/// <remarks>
/// The result is a scalar rather than a point, so it crosses the boundary as unsigned big-endian bytes the
/// width of the group order (<c>FE2OS</c> with leading zeros as needed, Doc 9303 Part 11 §4.4.5.6). It is
/// derived from the static private key and so is sensitive; the backend returns it in pinned, zeroized memory.
/// </remarks>
/// <param name="staticPrivateKey">The chip's static Chip Authentication private key <c>s_IC</c>, unsigned big-endian.</param>
/// <param name="ephemeralMappingPrivateKey">The chip's ephemeral mapping private key <c>s_Map,IC</c> from the Generic Mapping round, unsigned big-endian.</param>
/// <param name="curve">A tag carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the curve.</param>
/// <param name="pool">Memory pool for the result scalar.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The chip authentication data scalar <c>CA_IC</c> as owned, pinned bytes. The caller owns and disposes it.</returns>
public delegate ValueTask<IMemoryOwner<byte>> EcChipAuthenticationDataDelegate(
    ReadOnlyMemory<byte> staticPrivateKey,
    ReadOnlyMemory<byte> ephemeralMappingPrivateKey,
    Tag curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
