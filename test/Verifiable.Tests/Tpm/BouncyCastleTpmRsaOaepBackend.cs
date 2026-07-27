using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// A BouncyCastle-backed <see cref="TpmRsaOaepEncryptDelegate"/>/<see cref="TpmRsaOaepDecryptDelegate"/> pair for
/// the in-house <see cref="TpmSimulator"/>: the RSA arm of credential-protection seed transport (TPM 2.0 Library
/// Part 1, Annex B.4 "RSAES_OAEP", B.10.3, B.10.4).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="System.Security.Cryptography.RSA"/>'s public OAEP surface
/// (<see cref="RSAEncryptionPadding.OaepSHA256"/> and siblings) exposes no custom label parameter, so it cannot
/// reproduce the <c>"IDENTITY"</c>-labelled encoding TPM 2.0 credential protection requires — only
/// BouncyCastle's <see cref="OaepEncoding"/>, constructed with an explicit <c>encodingParams</c> byte array,
/// supports an arbitrary OAEP label. The label is threaded through as a delegate parameter, never hardcoded
/// here, so this backend stays a faithful mirror of the generic OAEP primitive Annex B.4 describes.
/// </para>
/// <para>
/// <see cref="MicrosoftTpmRsaSigningBackend"/> supplies key generation and digest sign/verify (framework RSA is
/// reliable for those); this backend supplies only the two OAEP delegates, composed alongside it into one
/// <see cref="TpmRsaSigningBackend"/> at <see cref="MicrosoftTpmRsaSigningBackend.Create"/>. The retained
/// private key it decrypts with is the PKCS#1 DER <see cref="MicrosoftTpmRsaSigningBackend"/> generates
/// (<c>RSA.ExportRSAPrivateKey()</c>), parsed here into BouncyCastle CRT parameters.
/// </para>
/// </remarks>
internal static class BouncyCastleTpmRsaOaepBackend
{
    /// <summary>
    /// Creates the OAEP-encrypt delegate: encrypt-to-public-key drives <see cref="OaepEncoding"/> in
    /// encryption mode against an RSA public key built from the caller-supplied modulus and exponent.
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaOaepEncryptDelegate EncryptOaep => EncryptOaepAsync;

    /// <summary>
    /// Creates the OAEP-decrypt delegate: decrypt-with-private-key drives <see cref="OaepEncoding"/> in
    /// decryption mode against the retained RSA private key, mapping any decode failure to
    /// <see langword="null"/> (TPM 2.0 Library Part 1, Annex B.10.3).
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaOaepDecryptDelegate DecryptOaep => DecryptOaepAsync;

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented ciphertext buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> EncryptOaepAsync(
        ReadOnlyMemory<byte> modulus,
        uint exponent,
        ReadOnlyMemory<byte> plaintext,
        ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg,
        TpmAlgIdConstants mgfHashAlg,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var oaep = new OaepEncoding(new RsaEngine(), ResolveDigest(lhashAlg), ResolveDigest(mgfHashAlg), label.ToArray());
        var publicKey = new RsaKeyParameters(isPrivate: false, new BigInteger(1, modulus.ToArray()), BigInteger.ValueOf(exponent));
        oaep.Init(forEncryption: true, publicKey);

        byte[] plaintextBytes = plaintext.ToArray();
        byte[] ciphertext;
        try
        {
            ciphertext = oaep.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        IMemoryOwner<byte> owner = CopyToPooled(ciphertext, pool);

        return ValueTask.FromResult(owner);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented plaintext buffer transfers to the returned owner, which the simulator disposes; the null (decode-failure) path rents nothing.")]
    private static ValueTask<IMemoryOwner<byte>?> DecryptOaepAsync(
        ReadOnlyMemory<byte> privateKey,
        ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg,
        TpmAlgIdConstants mgfHashAlg,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var oaep = new OaepEncoding(new RsaEngine(), ResolveDigest(lhashAlg), ResolveDigest(mgfHashAlg), label.ToArray());
        RsaPrivateCrtKeyParameters privateKeyParameters = ParseRsaPrivateKey(privateKey.Span);
        oaep.Init(forEncryption: false, privateKeyParameters);

        byte[] ciphertextBytes = ciphertext.ToArray();
        try
        {
            byte[] decoded = oaep.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);
            try
            {
                return ValueTask.FromResult<IMemoryOwner<byte>?>(CopyToPooled(decoded, pool));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
        }
        catch(CryptoException)
        {
            //OAEP decode failed: a non-zero leading octet, an lhash mismatch, malformed padding, a missing 0x01
            //separator, or (equivalently) a ciphertext whose length does not match the modulus width. None of
            //these are surfaced as a distinct outcome — the null return lets the caller substitute an invalid
            //seed and defer the failure to the outer integrity HMAC (TPM 2.0 Library Part 1, Annex B.10.3), so
            //this backend cannot become a padding oracle.
            return ValueTask.FromResult<IMemoryOwner<byte>?>(null);
        }
    }

    /// <summary>
    /// Maps a TPM hash algorithm identifier to the BouncyCastle digest instance OAEP drives it with.
    /// </summary>
    /// <param name="hashAlg">The TPM hash algorithm identifier.</param>
    /// <returns>A freshly constructed digest instance (BouncyCastle digests are stateful and not reusable across calls).</returns>
    private static IDigest ResolveDigest(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => new Sha1Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA256 => new Sha256Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA384 => new Sha384Digest(),
        TpmAlgIdConstants.TPM_ALG_SHA512 => new Sha512Digest(),
        _ => throw new NotSupportedException($"The in-house RSA-OAEP backend models SHA-1/256/384/512; '{hashAlg}' is not supported.")
    };

    /// <summary>
    /// Parses a PKCS#1 DER-encoded RSA private key (<c>RSAPrivateKey</c>) — the encoding
    /// <see cref="MicrosoftTpmRsaSigningBackend"/> retains (<c>RSA.ExportRSAPrivateKey()</c>) — into BouncyCastle
    /// CRT key parameters, mirroring the production key-material creator's identical parsing step.
    /// </summary>
    /// <param name="privateKeyBytes">The PKCS#1 DER-encoded private key.</param>
    /// <returns>The parsed private key parameters with CRT components.</returns>
    private static RsaPrivateCrtKeyParameters ParseRsaPrivateKey(ReadOnlySpan<byte> privateKeyBytes)
    {
        byte[] derBytes = privateKeyBytes.ToArray();
        try
        {
            RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(derBytes));

            return new RsaPrivateCrtKeyParameters(
                rsa.Modulus,
                rsa.PublicExponent,
                rsa.PrivateExponent,
                rsa.Prime1,
                rsa.Prime2,
                rsa.Exponent1,
                rsa.Exponent2,
                rsa.Coefficient);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derBytes);
        }
    }

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
