using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// Generates the RSA key pair a simulated <c>TPM2_CreatePrimary()</c> returns: the private key the TPM
/// retains and the public modulus it exports in <c>outPublic</c> (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <remarks>
/// The simulator models a TPM's key generation, not a real entropy source, so the actual key creation is
/// supplied through this seam — exactly as the ECC backend and the RNG backend are — keeping
/// <see cref="Verifiable.Tpm"/> backend-agnostic.
/// </remarks>
/// <param name="keyBits">The RSA modulus size in bits.</param>
/// <param name="pool">The memory pool backing the returned key material.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The generated key. The caller owns and disposes it.</returns>
public delegate ValueTask<TpmGeneratedRsaKey> TpmRsaKeyGenerationDelegate(
    ushort keyBits,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);

/// <summary>
/// Signs a pre-computed digest with an RSA private key, modelling <c>TPM2_Sign()</c> over an
/// externally-computed digest with a NULL validation ticket (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <remarks>
/// The digest is signed <strong>directly</strong> under the requested padding scheme — the backend must not
/// hash it again. The result is the raw RSA signature octets, which the simulator frames as the
/// <c>TPMS_SIGNATURE_RSA</c> signature value.
/// </remarks>
/// <param name="privateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="digest">The pre-computed digest to sign.</param>
/// <param name="scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="hashAlg">The scheme's hash algorithm.</param>
/// <param name="pool">The memory pool backing the returned signature.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The raw RSA signature. The caller owns and disposes it.</returns>
public delegate ValueTask<Signature> TpmRsaDigestSignDelegate(
    ReadOnlyMemory<byte> privateKey,
    ReadOnlyMemory<byte> digest,
    TpmAlgIdConstants scheme,
    TpmAlgIdConstants hashAlg,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);

/// <summary>
/// The RSA signing backend the simulator drives for <c>TPM2_CreatePrimary()</c> and <c>TPM2_Sign()</c>: a
/// key generator paired with a digest signer. The RSA counterpart of <see cref="TpmEccSigningBackend"/>.
/// </summary>
/// <remarks>
/// A seam-bundle the constructor of <see cref="TpmSimulator"/> takes as one optional dependency, alongside
/// the ECC backend. When neither asymmetric backend is supplied, the simulator answers the object/signing
/// commands with <c>TPM_RC_COMMAND_CODE</c>.
/// </remarks>
/// <param name="GenerateKey">Generates the primary RSA key a <c>TPM2_CreatePrimary()</c> returns.</param>
/// <param name="SignDigest">Signs a digest with a retained RSA key for <c>TPM2_Sign()</c>.</param>
public sealed record TpmRsaSigningBackend(
    TpmRsaKeyGenerationDelegate GenerateKey,
    TpmRsaDigestSignDelegate SignDigest);

/// <summary>
/// The key material a <see cref="TpmRsaKeyGenerationDelegate"/> produces: the private key the TPM retains
/// and the public modulus it exports. The simulator copies what it needs into its durable model state and
/// then disposes this carrier.
/// </summary>
/// <param name="PrivateKey">The generated private key, in the backend's own encoding.</param>
/// <param name="Modulus">The generated public modulus (big-endian).</param>
public sealed record TpmGeneratedRsaKey(PrivateKeyMemory PrivateKey, PublicKeyMemory Modulus): IDisposable
{
    /// <summary>
    /// Releases the key material backing the private key and the public modulus.
    /// </summary>
    public void Dispose()
    {
        PrivateKey.Dispose();
        Modulus.Dispose();
    }
}
