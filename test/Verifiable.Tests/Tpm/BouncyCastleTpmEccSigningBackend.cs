using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// A BouncyCastle-backed <see cref="TpmEccSigningBackend"/> for the in-house <see cref="TpmSimulator"/>: it
/// mints the key a <c>TPM2_CreatePrimary()</c> returns and signs the digest a <c>TPM2_Sign()</c> presents,
/// modelling what a hardware TPM does internally.
/// </summary>
/// <remarks>
/// <para>
/// The asymmetric crypto lives on the test side so the production <c>Verifiable.Tpm</c> assembly stays
/// provider-agnostic (it references no concrete crypto backend), and BouncyCastle is chosen for the
/// key-under-test because its elliptic-curve private-scalar handling is reliable across platforms, unlike
/// the .NET EC private-key import. This keeps the firewall intact: the signer (this backend, the "TPM") and
/// the verifier (the test's off-TPM <c>ECDsa.VerifyHash</c>) agree only on the exported public point and the
/// signature bytes, never on in-memory key state.
/// </para>
/// <para>
/// <c>TPM2_Sign()</c> over an externally-computed digest signs that digest directly, so the digest signer
/// uses <see cref="ECDsaSigner.GenerateSignature(byte[])"/> — which signs the supplied value without hashing
/// it again — rather than a message-signing function that would re-hash.
/// </para>
/// </remarks>
internal static class BouncyCastleTpmEccSigningBackend
{
    /// <summary>The fixed width in bytes of a NIST P-256 scalar, point coordinate, or ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>
    /// Creates a signing backend whose key generation and digest signing run on BouncyCastle. The backend
    /// models NIST P-256 (<see cref="TpmEccCurveConstants.TPM_ECC_NIST_P256"/>); any other curve throws.
    /// </summary>
    /// <returns>The signing backend to inject into a <see cref="TpmSimulator"/>.</returns>
    public static TpmEccSigningBackend Create() => new(GenerateKeyAsync, SignDigestAsync, ComputeSharedSecretAsync);

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented scalar and point buffers transfers to the returned carriers, which the simulator disposes.")]
    private static ValueTask<TpmGeneratedEccKey> GenerateKeyAsync(TpmEccCurveConstants curve, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        X9ECParameters parameters = ResolveCurve(curve);
        var domain = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H, parameters.GetSeed());

        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        //SEC1 uncompressed public point (0x04 || X || Y) and the unsigned big-endian scalar at field width.
        byte[] uncompressedPoint = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(compressed: false);
        byte[] scalar = ToFixed(((ECPrivateKeyParameters)keyPair.Private).D.ToByteArrayUnsigned(), P256ComponentSize);

        var privateScalar = new PrivateKeyMemory(CopyToPooled(scalar, pool), CryptoTags.P256PrivateKey);
        var publicPoint = new EncodedEcPoint(CopyToPooled(uncompressedPoint, pool), CryptoTags.P256ExchangePublicKey);

        Array.Clear(scalar);

        return ValueTask.FromResult(new TpmGeneratedEccKey(privateScalar, publicPoint));
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented signature buffer transfers to the returned Signature, which the simulator disposes.")]
    private static ValueTask<Signature> SignDigestAsync(
        ReadOnlyMemory<byte> privateScalar, ReadOnlyMemory<byte> digest, TpmEccCurveConstants curve, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        X9ECParameters parameters = ResolveCurve(curve);
        var domain = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H, parameters.GetSeed());

        var key = new ECPrivateKeyParameters(new BigInteger(1, privateScalar.ToArray()), domain);
        var signer = new ECDsaSigner();
        signer.Init(forSigning: true, new ParametersWithRandom(key, new SecureRandom()));

        //GenerateSignature signs the supplied digest directly — no re-hashing — exactly as TPM2_Sign() over an
        //externally-computed digest with a NULL ticket does.
        BigInteger[] signature = signer.GenerateSignature(digest.ToArray());

        byte[] p1363 = new byte[2 * P256ComponentSize];
        ToFixed(signature[0].ToByteArrayUnsigned(), P256ComponentSize).CopyTo(p1363, 0);
        ToFixed(signature[1].ToByteArrayUnsigned(), P256ComponentSize).CopyTo(p1363, P256ComponentSize);

        var result = new Signature(CopyToPooled(p1363, pool), CryptoTags.P256Signature);

        Array.Clear(p1363);

        return ValueTask.FromResult(result);
    }

    /// <summary>
    /// Computes the ECDH shared value <c>Z</c> — the affine x-coordinate of <c>privateScalar · peerPublicPoint</c>,
    /// left-padded to the P-256 field width — modelling the seed exchange of the TPM's credential protection (TPM
    /// 2.0 Library Part 1, clause 24). The modelled curve has cofactor one, so the plain multiplication yields the
    /// same shared point both the make and activate sides compute.
    /// </summary>
    /// <param name="privateScalar">The local party's private scalar, unsigned big-endian.</param>
    /// <param name="peerPublicPoint">The peer's public point, SEC1 uncompressed (<c>0x04 || X || Y</c>).</param>
    /// <param name="curve">The ECC curve both points live on.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The shared value <c>Z</c> (the affine x-coordinate at the field width). The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented shared-value buffer transfers to the caller, which zeroes and disposes it.")]
    private static ValueTask<IMemoryOwner<byte>> ComputeSharedSecretAsync(
        ReadOnlyMemory<byte> privateScalar, ReadOnlyMemory<byte> peerPublicPoint, TpmEccCurveConstants curve, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        X9ECParameters parameters = ResolveCurve(curve);
        var scalar = new BigInteger(1, privateScalar.ToArray());
        Org.BouncyCastle.Math.EC.ECPoint peer = parameters.Curve.DecodePoint(peerPublicPoint.ToArray());

        //Z = the affine x-coordinate of scalar · peer (the standard ECDH product for a cofactor-one curve).
        Org.BouncyCastle.Math.EC.ECPoint product = peer.Multiply(scalar).Normalize();
        byte[] sharedX = ToFixed(product.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(), P256ComponentSize);

        IMemoryOwner<byte> owner = CopyToPooled(sharedX, pool);
        Array.Clear(sharedX);

        return ValueTask.FromResult(owner);
    }

    private static X9ECParameters ResolveCurve(TpmEccCurveConstants curve) => curve switch
    {
        TpmEccCurveConstants.TPM_ECC_NIST_P256 => SecNamedCurves.GetByName("secp256r1"),
        _ => throw new NotSupportedException($"The in-house signing backend models only NIST P-256; '{curve}' is not supported.")
    };

    /// <summary>
    /// Copies bytes into an exact-sized pooled buffer. The carriers wrap the whole owner, so the rented length
    /// must equal the data length — the discipline <c>BaseMemoryPool</c> guarantees and which is asserted here.
    /// </summary>
    /// <param name="bytes">The bytes to copy.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pooled buffer holding a copy of <paramref name="bytes"/>.</returns>
    private static IMemoryOwner<byte> CopyToPooled(byte[] bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        if(owner.Memory.Length != bytes.Length)
        {
            owner.Dispose();

            throw new InvalidOperationException("The rented buffer size does not match the requested size.");
        }

        bytes.AsSpan().CopyTo(owner.Memory.Span);

        return owner;
    }

    /// <summary>
    /// Left-pads (or trims leading bytes from) a big-endian value to a fixed width, as the SEC1 coordinate and
    /// IEEE P1363 component encodings require. BouncyCastle's unsigned encoding may omit leading zero bytes.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to produce.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] ToFixed(byte[] value, int length)
    {
        if(value.Length == length)
        {
            return value;
        }

        byte[] result = new byte[length];
        if(value.Length < length)
        {
            value.CopyTo(result, length - value.Length);
        }
        else
        {
            value.AsSpan(value.Length - length, length).CopyTo(result);
        }

        return result;
    }
}
