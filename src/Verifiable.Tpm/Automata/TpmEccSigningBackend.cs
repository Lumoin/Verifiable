using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// Generates the elliptic-curve key pair a simulated <c>TPM2_CreatePrimary()</c> returns: the private
/// scalar the TPM retains and the public point it exports in <c>outPublic</c> (TPM 2.0 Library Part 3,
/// clause 24.1).
/// </summary>
/// <remarks>
/// The simulator models a TPM's key generation, not a real entropy source, so the actual key creation is
/// supplied through this seam rather than baked in — exactly as the device's RNG is supplied through
/// <see cref="FillEntropyDelegate"/>. <see cref="Verifiable.Tpm"/> stays backend-agnostic (it references no
/// concrete crypto provider); a caller composes a backend over its provider of choice.
/// </remarks>
/// <param name="curve">The ECC curve to generate the key on.</param>
/// <param name="pool">The memory pool backing the returned key material.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The generated key. The caller owns and disposes it.</returns>
public delegate ValueTask<TpmGeneratedEccKey> TpmEccKeyGenerationDelegate(
    TpmEccCurveConstants curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);

/// <summary>
/// Signs a pre-computed digest with an ECC private scalar, modelling <c>TPM2_Sign()</c> over an
/// externally-computed digest with a NULL validation ticket (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <remarks>
/// The digest is signed <strong>directly</strong> — the backend must not hash it again, since the caller
/// has already reduced the message to the digest the scheme's hash algorithm produces. The signature is
/// returned in IEEE P1363 form (<c>r ‖ s</c>, each component the curve field width), which the simulator
/// splits into the <c>TPMS_SIGNATURE_ECDSA</c> <c>r</c> and <c>s</c> parameters.
/// </remarks>
/// <param name="privateScalar">The signing key's private scalar, unsigned big-endian.</param>
/// <param name="digest">The pre-computed digest to sign.</param>
/// <param name="curve">The ECC curve the scalar lives on.</param>
/// <param name="pool">The memory pool backing the returned signature.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The signature as IEEE P1363 <c>r ‖ s</c>. The caller owns and disposes it.</returns>
public delegate ValueTask<Signature> TpmEccDigestSignDelegate(
    ReadOnlyMemory<byte> privateScalar,
    ReadOnlyMemory<byte> digest,
    TpmEccCurveConstants curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);

/// <summary>
/// Computes an elliptic-curve Diffie-Hellman shared value: the x-coordinate of the point
/// <c>privateScalar · peerPublicPoint</c>, modelling the secret exchange a TPM performs for the credential
/// protection of <c>TPM2_MakeCredential</c> / <c>TPM2_ActivateCredential</c> (TPM 2.0 Library Part 1, clause 24;
/// the shared value <c>Z</c> then seeds <c>KDFe</c>, Part 1, clause 9.4.10.3).
/// </summary>
/// <remarks>
/// The curves the backend models have cofactor one, so the plain point multiplication yields the same shared
/// point both parties compute (<c>ephemeralPriv · EK_pub</c> on the make side equals <c>EK_priv · ephemeralPub</c>
/// on the activate side). The returned value is the affine x-coordinate as unsigned big-endian, left-padded to the
/// curve field width — the raw <c>Z</c> the TPM feeds to <c>KDFe</c>.
/// </remarks>
/// <param name="privateScalar">The local party's private scalar, unsigned big-endian.</param>
/// <param name="peerPublicPoint">The peer's public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
/// <param name="curve">The ECC curve both points live on.</param>
/// <param name="pool">The memory pool backing the returned shared value.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// A pool-owned buffer holding the shared value <c>Z</c> (the affine x-coordinate at the curve field width). The
/// value is secret; the caller must zero and dispose it.
/// </returns>
public delegate ValueTask<IMemoryOwner<byte>> TpmEccSharedSecretDelegate(
    ReadOnlyMemory<byte> privateScalar,
    ReadOnlyMemory<byte> peerPublicPoint,
    TpmEccCurveConstants curve,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);

/// <summary>
/// The elliptic-curve signing backend the simulator drives for <c>TPM2_CreatePrimary()</c> and
/// <c>TPM2_Sign()</c>: a key generator paired with a digest signer and an ECDH shared-secret function.
/// </summary>
/// <remarks>
/// A seam-bundle the constructor of <see cref="TpmSimulator"/> takes as one optional dependency, the same
/// way the RNG backend is supplied. When absent, the simulator answers the object/signing commands with
/// <c>TPM_RC_COMMAND_CODE</c> (the faithful "command unsupported"), so the lifecycle, NV, and entropy
/// surfaces work without any asymmetric backend.
/// </remarks>
/// <param name="GenerateKey">Generates the primary key a <c>TPM2_CreatePrimary()</c> returns.</param>
/// <param name="SignDigest">Signs a digest with a retained key for <c>TPM2_Sign()</c>.</param>
/// <param name="ComputeSharedSecret">
/// Computes the ECDH shared value the credential protection of <c>TPM2_MakeCredential</c> /
/// <c>TPM2_ActivateCredential</c> transports the seed with (TPM 2.0 Library Part 1, clause 24).
/// </param>
public sealed record TpmEccSigningBackend(
    TpmEccKeyGenerationDelegate GenerateKey,
    TpmEccDigestSignDelegate SignDigest,
    TpmEccSharedSecretDelegate ComputeSharedSecret);

/// <summary>
/// The key material a <see cref="TpmEccKeyGenerationDelegate"/> produces: the private scalar the TPM
/// retains and the public point it exports. The simulator copies what it needs into its durable model
/// state and then disposes this carrier.
/// </summary>
/// <param name="PrivateScalar">The generated private scalar, unsigned big-endian at the curve field width.</param>
/// <param name="PublicPoint">The generated public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
public sealed record TpmGeneratedEccKey(PrivateKeyMemory PrivateScalar, EncodedEcPoint PublicPoint): IDisposable
{
    /// <summary>
    /// Releases the key material backing the scalar and the public point.
    /// </summary>
    public void Dispose()
    {
        PrivateScalar.Dispose();
        PublicPoint.Dispose();
    }
}
