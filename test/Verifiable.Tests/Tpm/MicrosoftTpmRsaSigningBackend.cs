using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// A framework-RSA-backed <see cref="TpmRsaSigningBackend"/> for the in-house <see cref="TpmSimulator"/>: it
/// mints the RSA key a <c>TPM2_CreatePrimary()</c> returns and signs the digest a <c>TPM2_Sign()</c> presents,
/// modelling what a hardware TPM does internally.
/// </summary>
/// <remarks>
/// <para>
/// The asymmetric crypto lives on the test side so the production <c>Verifiable.Tpm</c> assembly stays
/// provider-agnostic. RSA private-key import/export is reliable across platforms — unlike the elliptic-curve
/// case, which is why the ECC backend uses BouncyCastle — so the framework RSA implementation is used directly.
/// The firewall stays intact: the signer (this backend, the "TPM") and the verifier (the test's off-TPM
/// <see cref="RSA.VerifyHash(byte[], byte[], HashAlgorithmName, RSASignaturePadding)"/>) agree only on the
/// exported modulus and the signature bytes, never on in-memory key state.
/// </para>
/// <para>
/// <c>TPM2_Sign()</c> over an externally-computed digest signs that digest directly, so the digest signer uses
/// <see cref="RSA.SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/> — which signs a pre-computed hash
/// without re-hashing it.
/// </para>
/// </remarks>
internal static class MicrosoftTpmRsaSigningBackend
{
    /// <summary>
    /// Creates a signing backend whose key generation and digest signing run on the framework RSA implementation.
    /// </summary>
    /// <returns>The signing backend to inject into a <see cref="TpmSimulator"/>.</returns>
    public static TpmRsaSigningBackend Create() => new(GenerateKeyAsync, SignDigestAsync);

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented private-key and modulus buffers transfers to the returned carriers, which the simulator disposes.")]
    private static ValueTask<TpmGeneratedRsaKey> GenerateKeyAsync(ushort keyBits, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Not test fixture material: this is the simulated TPM's own TPM2_CreatePrimary() key-generation step,
        //invoked with whatever keyBits the exercised template requests, and its output is what SignDigestAsync
        //below re-imports and signs with — a canned provider key would fix both the size and the identity of
        //every simulated primary regardless of what a test's template asks for.
        using RSA rsa = RSA.Create(keyBits);

        //The retained private key is the PKCS#1 RSAPrivateKey DER the signer re-imports; the exported public
        //value is the raw modulus (big-endian) — the TPM2B_PUBLIC_KEY_RSA the outPublic carries.
        byte[] privateKey = rsa.ExportRSAPrivateKey();
        byte[] modulus = rsa.ExportParameters(includePrivateParameters: false).Modulus!;

        var privateKeyMemory = new PrivateKeyMemory(CopyToPooled(privateKey, pool), CryptoTags.Rsa2048PrivateKey);
        var modulusMemory = new PublicKeyMemory(CopyToPooled(modulus, pool), CryptoTags.Rsa2048PublicKey);

        CryptographicOperations.ZeroMemory(privateKey);

        return ValueTask.FromResult(new TpmGeneratedRsaKey(privateKeyMemory, modulusMemory));
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented signature buffer transfers to the returned Signature, which the simulator disposes.")]
    private static ValueTask<Signature> SignDigestAsync(
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> digest, TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Not test fixture material: privateKey is whatever key GenerateKeyAsync retained for this specific
        //simulated object, handed back by the simulator per TPM2_Sign() — there is no fixed key to substitute.
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(privateKey.Span, out _);

        RSASignaturePadding padding = ResolvePadding(scheme);
        HashAlgorithmName hashName = ResolveHash(hashAlg);

        //SignHash signs the supplied digest directly — no re-hashing — exactly as TPM2_Sign() over an
        //externally-computed digest with a NULL ticket does.
        byte[] signatureBytes = rsa.SignHash(digest.ToArray(), hashName, padding);

        return ValueTask.FromResult(new Signature(CopyToPooled(signatureBytes, pool), CryptoTags.Rsa2048Signature));
    }

    private static RSASignaturePadding ResolvePadding(TpmAlgIdConstants scheme) => scheme switch
    {
        TpmAlgIdConstants.TPM_ALG_RSASSA => RSASignaturePadding.Pkcs1,
        TpmAlgIdConstants.TPM_ALG_RSAPSS => RSASignaturePadding.Pss,
        _ => throw new NotSupportedException($"The in-house RSA signing backend models only RSASSA and RSAPSS; '{scheme}' is not supported.")
    };

    private static HashAlgorithmName ResolveHash(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
        TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
        TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"The in-house RSA signing backend models SHA-256/384/512; '{hashAlg}' is not supported.")
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
}
