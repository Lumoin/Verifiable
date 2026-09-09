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
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// A BouncyCastle-backed <see cref="TpmRsaOaepEncryptDelegate"/>/<see cref="TpmRsaOaepDecryptDelegate"/> pair for
/// the in-house <see cref="TpmSimulator"/>: the RSA arm of credential-protection seed transport (TPM 2.0 Library
/// Part 1, clause 43.4 "RSAES_OAEP", 20.3.2.3, 21.3).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="System.Security.Cryptography.RSA"/>'s public OAEP surface
/// (<see cref="RSAEncryptionPadding.OaepSHA256"/> and siblings) exposes no custom label parameter, so it cannot
/// reproduce the <c>"IDENTITY"</c>-labelled encoding TPM 2.0 credential protection requires — only
/// BouncyCastle's <see cref="OaepEncoding"/>, constructed with an explicit <c>encodingParams</c> byte array,
/// supports an arbitrary OAEP label. The label is threaded through as a delegate parameter, never hardcoded
/// here, so this backend stays a faithful mirror of the generic OAEP primitive clause 43.4 describes.
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
    /// <see langword="null"/> (TPM 2.0 Library Part 1, clause 20.3.2.3).
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaOaepDecryptDelegate DecryptOaep => DecryptOaepAsync;

    /// <summary>
    /// OAEP-encrypts <paramref name="plaintext"/> to the public key built from
    /// <paramref name="modulus"/>/<paramref name="exponent"/>, driving <see cref="OaepEncoding"/> in encryption
    /// mode with <paramref name="label"/> as the explicit <c>encodingParams</c>.
    /// </summary>
    /// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
    /// <param name="exponent">The RSA public exponent.</param>
    /// <param name="plaintext">The plaintext value to encrypt.</param>
    /// <param name="label">The OAEP label octets (<c>L</c>), fed to the <c>lhash</c> digest verbatim.</param>
    /// <param name="lhashAlg">The hash algorithm computing <c>lhash = H(L)</c>.</param>
    /// <param name="mgfHashAlg">The hash algorithm driving MGF1 for <c>dbMask</c>/<c>seedMask</c>.</param>
    /// <param name="pool">The memory pool backing the returned ciphertext.</param>
    /// <param name="cancellationToken">A cancellation token, unused: BouncyCastle's synchronous encoder offers no cancellable step.</param>
    /// <returns>The OAEP ciphertext, the same octet width as the modulus.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented ciphertext buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> EncryptOaepAsync(
        ReadOnlyMemory<byte> modulus,
        uint exponent,
        ReadOnlyMemory<byte> plaintext,
        ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg,
        TpmAlgIdConstants mgfHashAlg,
        BaseMemoryPool pool,
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

    /// <summary>
    /// OAEP-decrypts <paramref name="ciphertext"/> with the retained private key, driving
    /// <see cref="OaepEncoding"/> in decryption mode with <paramref name="label"/> as the explicit
    /// <c>encodingParams</c>; any decode failure answers <see langword="null"/> rather than throwing, so this
    /// backend cannot become a padding oracle.
    /// </summary>
    /// <param name="privateKey">The decrypting key's retained private key, the PKCS#1 DER encoding <see cref="ParseRsaPrivateKey"/> parses.</param>
    /// <param name="ciphertext">The OAEP ciphertext, the same octet width as the modulus.</param>
    /// <param name="label">The OAEP label octets (<c>L</c>), matching the value the encrypt side used.</param>
    /// <param name="lhashAlg">The hash algorithm computing <c>lhash = H(L)</c>.</param>
    /// <param name="mgfHashAlg">The hash algorithm driving MGF1 for <c>dbMask</c>/<c>seedMask</c>.</param>
    /// <param name="pool">The memory pool backing the returned plaintext.</param>
    /// <param name="cancellationToken">A cancellation token, unused: BouncyCastle's synchronous decoder offers no cancellable step.</param>
    /// <returns>The recovered plaintext on success; <see langword="null"/> when OAEP decoding failed.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented plaintext buffer transfers to the returned owner, which the simulator disposes; the null (decode-failure) path rents nothing.")]
    private static ValueTask<IMemoryOwner<byte>?> DecryptOaepAsync(
        ReadOnlyMemory<byte> privateKey,
        ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> label,
        TpmAlgIdConstants lhashAlg,
        TpmAlgIdConstants mgfHashAlg,
        BaseMemoryPool pool,
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
            //seed and defer the failure to the outer integrity HMAC (the v184 TPM 2.0 Library Part 1, clause A.10.3
            //rule; v185 keeps its rationale at Part 3, clause 13.3.1), so
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
    internal static RsaPrivateCrtKeyParameters ParseRsaPrivateKey(ReadOnlySpan<byte> privateKeyBytes)
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
    /// An empty result is the shared <see cref="EmptyMemoryOwner.Instance"/>, since a pool rents no zero-length
    /// buffer: an RSAES or OAEP decryption of an empty message (RFC 8017 §7.1.2 and §7.2.2 admit
    /// <c>mLen = 0</c>) answers a zero-length owner the caller adopts or releases like any other.
    /// </summary>
    /// <param name="bytes">The bytes to copy.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pooled buffer holding a copy of <paramref name="bytes"/>, or the shared empty owner for no bytes.</returns>
    internal static IMemoryOwner<byte> CopyToPooled(byte[] bytes, BaseMemoryPool pool)
    {
        if(bytes.Length == 0)
        {
            return EmptyMemoryOwner.Instance;
        }

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
