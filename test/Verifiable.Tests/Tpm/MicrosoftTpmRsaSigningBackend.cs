using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

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
/// <para>
/// The two OAEP delegates (credential-protection seed transport) are NOT implemented here: the framework RSA
/// OAEP surface exposes no custom label parameter, so it cannot reproduce TPM 2.0's <c>"IDENTITY"</c>-labelled
/// encoding (TPM 2.0 Library Part 1, clause 43.4, 20.3.2.3, 21.3). <see cref="Create"/> composes them in from
/// <see cref="BouncyCastleTpmRsaOaepBackend"/> instead, so every caller of this factory gets a complete,
/// five-delegate <see cref="TpmRsaSigningBackend"/> without needing to know that split.
/// </para>
/// </remarks>
internal static class MicrosoftTpmRsaSigningBackend
{
    /// <summary>
    /// Creates a signing backend whose key generation and digest sign/verify run on the framework RSA
    /// implementation, and whose OAEP encrypt/decrypt run on <see cref="BouncyCastleTpmRsaOaepBackend"/> (the
    /// framework RSA OAEP surface cannot carry TPM 2.0's custom label, see the class remarks).
    /// </summary>
    /// <returns>The signing backend to inject into a <see cref="TpmSimulator"/>.</returns>
    public static TpmRsaSigningBackend Create() => new(
        GenerateKeyAsync, SignDigestAsync, BouncyCastleTpmRsaOaepBackend.EncryptOaep, BouncyCastleTpmRsaOaepBackend.DecryptOaep, VerifyDigestAsync, ImportPrivateKeyAsync,
        BouncyCastleTpmRsaEsBackend.EncryptRsaes, BouncyCastleTpmRsaEsBackend.DecryptRsaes, BouncyCastleTpmRsaEsBackend.EncryptRaw, BouncyCastleTpmRsaEsBackend.DecryptRaw);

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented private-key and modulus buffers transfers to the returned carriers, which the simulator disposes.")]
    private static ValueTask<TpmGeneratedRsaKey> GenerateKeyAsync(ushort keyBits, BaseMemoryPool pool, CancellationToken cancellationToken)
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
        ReadOnlyMemory<byte> privateKey, ReadOnlyMemory<byte> digest, TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg, BaseMemoryPool pool, CancellationToken cancellationToken)
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

    /// <summary>
    /// Verifies a signature over a pre-computed digest against an RSA public modulus and exponent, modelling
    /// the public-key operation <c>TPM2_VerifySignature()</c> performs (TPM 2.0 Library Part 3, clause 20.1).
    /// Public inputs only — works unchanged for a public-only object <c>TPM2_LoadExternal()</c> loads. Never
    /// re-hashes the digest, mirroring <see cref="SignDigestAsync"/>.
    /// </summary>
    /// <param name="modulus">The verifying key's public modulus, unsigned big-endian.</param>
    /// <param name="exponent">The verifying key's public exponent.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>).</param>
    /// <param name="hashAlg">The scheme's hash algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the signature verifies; otherwise <see langword="false"/>.</returns>
    private static ValueTask<bool> VerifyDigestAsync(
        ReadOnlyMemory<byte> modulus, uint exponent, ReadOnlyMemory<byte> digest, ReadOnlyMemory<byte> signature, TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg, CancellationToken cancellationToken)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus.ToArray(),
            Exponent = EncodeExponent(exponent)
        });

        RSASignaturePadding padding = ResolvePadding(scheme);
        HashAlgorithmName hashName = ResolveHash(hashAlg);

        //VerifyHash checks the supplied digest directly — no re-hashing — exactly as TPM2_VerifySignature() over a
        //caller-supplied TPM2B_DIGEST does.
        bool verified = rsa.VerifyHash(digest.Span, signature.Span, hashName, padding);

        return ValueTask.FromResult(verified);
    }

    /// <summary>
    /// Imports an RSA private key from its public modulus, public exponent, and one prime factor, modelling
    /// <c>TPM2_LoadExternal()</c>'s public/private key pair consistency check over an RSA sensitive area (TPM
    /// 2.0 Library Part 3, clause 12.3.1: "the private exponent is computed using the two prime factors of the
    /// public modulus"). Reconstructs the CRT parameters over <see cref="BigInteger"/> and exports the same
    /// PKCS#1 <c>RSAPrivateKey</c> DER encoding <see cref="GenerateKeyAsync"/> produces, so both paths feed
    /// <see cref="SignDigestAsync"/>/<see cref="VerifyDigestAsync"/> identically.
    /// </summary>
    /// <param name="modulus">The public modulus, unsigned big-endian.</param>
    /// <param name="exponent">The public exponent (zero meaning the default 65537).</param>
    /// <param name="prime">The supplied prime factor <c>P</c>, unsigned big-endian.</param>
    /// <param name="pool">The memory pool backing the returned key.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The imported private key in the backend's PKCS#1 encoding; <see langword="null"/> when <paramref name="prime"/>
    /// does not divide <paramref name="modulus"/> or the two prime factors' bit sizes differ.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented private-key buffer transfers to the returned PrivateKeyMemory, which the simulator disposes.")]
    private static ValueTask<PrivateKeyMemory?> ImportPrivateKeyAsync(
        ReadOnlyMemory<byte> modulus, uint exponent, ReadOnlyMemory<byte> prime, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var n = new BigInteger(modulus.Span, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(exponent == 0 ? TpmsRsaParms.DefaultExponent : exponent);
        var p = new BigInteger(prime.Span, isUnsigned: true, isBigEndian: true);

        if(BigInteger.Remainder(n, p) != BigInteger.Zero)
        {
            //P does not divide the public modulus — not a valid prime factor of N.
            return ValueTask.FromResult<PrivateKeyMemory?>(null);
        }

        BigInteger q = n / p;
        if(p.GetBitLength() != q.GetBitLength())
        {
            //Part 2, clause 11.2.4.8: "All primes are required to have exactly half the number of significant
            //bits as the public modulus" — a bit-length mismatch between the two factors fails closed.
            return ValueTask.FromResult<PrivateKeyMemory?>(null);
        }

        //The CRT decrypt algorithm's convergence assumes P > Q; the supplied prime may be the smaller factor,
        //so the pair is oriented here rather than trusting which one the caller called "P".
        (BigInteger largerFactor, BigInteger smallerFactor) = p > q ? (p, q) : (q, p);

        BigInteger pMinusOne = largerFactor - BigInteger.One;
        BigInteger qMinusOne = smallerFactor - BigInteger.One;
        BigInteger phi = pMinusOne * qMinusOne;
        BigInteger? d = ModularInverse(e, phi);
        BigInteger? qInv = ModularInverse(smallerFactor, largerFactor);
        if(d is null || qInv is null)
        {
            //The exponent has no inverse modulo φ(N), or the two factors are not coprime — a caller-chosen
            //modulus that divides by the supplied prime without being an RSA key at all.
            return ValueTask.FromResult<PrivateKeyMemory?>(null);
        }

        BigInteger dp = BigInteger.Remainder(d.Value, pMinusOne);
        BigInteger dq = BigInteger.Remainder(d.Value, qMinusOne);

        int modulusWidth = modulus.Length;
        int factorWidth = modulusWidth / 2;

        byte[] nBytes = ToFixedBigEndian(n, modulusWidth);
        byte[] dBytes = ToFixedBigEndian(d.Value, modulusWidth);
        byte[] pBytes = ToFixedBigEndian(largerFactor, factorWidth);
        byte[] qBytes = ToFixedBigEndian(smallerFactor, factorWidth);
        byte[] dpBytes = ToFixedBigEndian(dp, factorWidth);
        byte[] dqBytes = ToFixedBigEndian(dq, factorWidth);
        byte[] qInvBytes = ToFixedBigEndian(qInv.Value, factorWidth);

        PrivateKeyMemory? result;
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = nBytes,
                Exponent = EncodeExponent(exponent),
                D = dBytes,
                P = pBytes,
                Q = qBytes,
                DP = dpBytes,
                DQ = dqBytes,
                InverseQ = qInvBytes
            });

            byte[] privateKey = rsa.ExportRSAPrivateKey();
            result = new PrivateKeyMemory(CopyToPooled(privateKey, pool), CryptoTags.Rsa2048PrivateKey);
            CryptographicOperations.ZeroMemory(privateKey);
        }
        catch(CryptographicException)
        {
            //The provider refused the reconstructed parameters: a pair the arithmetic above could not tell
            //apart from a key (a composite cofactor, for one) is no key, answered as an unbound pair rather than
            //an exception out of the command.
            result = null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dBytes);
            CryptographicOperations.ZeroMemory(pBytes);
            CryptographicOperations.ZeroMemory(qBytes);
            CryptographicOperations.ZeroMemory(dpBytes);
            CryptographicOperations.ZeroMemory(dqBytes);
            CryptographicOperations.ZeroMemory(qInvBytes);
        }

        return ValueTask.FromResult(result);
    }

    /// <summary>
    /// Encodes a TPM-wire RSA exponent (zero meaning the default) as the minimal big-endian octets
    /// <see cref="RSAParameters.Exponent"/> expects.
    /// </summary>
    /// <param name="exponent">The wire exponent (zero meaning 65537).</param>
    /// <returns>The minimal big-endian encoding.</returns>
    private static byte[] EncodeExponent(uint exponent) =>
        new BigInteger(exponent == 0 ? TpmsRsaParms.DefaultExponent : exponent).ToByteArray(isUnsigned: true, isBigEndian: true);

    /// <summary>
    /// Computes the modular inverse of <paramref name="value"/> modulo <paramref name="modulus"/> via the
    /// extended Euclidean algorithm — <see cref="BigInteger"/> carries no built-in modular inverse.
    /// </summary>
    /// <param name="value">The value to invert.</param>
    /// <param name="modulus">The modulus.</param>
    /// <returns>The inverse, in <c>[0, modulus)</c>; <see langword="null"/> when the two are not coprime, so no inverse exists.</returns>
    private static BigInteger? ModularInverse(BigInteger value, BigInteger modulus)
    {
        BigInteger oldR = value;
        BigInteger r = modulus;
        BigInteger oldS = BigInteger.One;
        BigInteger s = BigInteger.Zero;

        while(r != BigInteger.Zero)
        {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
        }

        if(oldR != BigInteger.One)
        {
            return null;
        }

        BigInteger inverse = oldS % modulus;

        return inverse < BigInteger.Zero ? inverse + modulus : inverse;
    }

    /// <summary>
    /// Encodes a non-negative <see cref="BigInteger"/> as exactly <paramref name="width"/> big-endian octets,
    /// left-padded with zeros — the fixed field widths <see cref="RSAParameters"/>' CRT members require.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <param name="width">The fixed width to produce.</param>
    /// <returns>A new array of exactly <paramref name="width"/> bytes.</returns>
    internal static byte[] ToFixedBigEndian(BigInteger value, int width)
    {
        byte[] minimal = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if(minimal.Length == width)
        {
            return minimal;
        }

        if(minimal.Length > width)
        {
            return minimal[(minimal.Length - width)..];
        }

        byte[] result = new byte[width];
        minimal.CopyTo(result, width - minimal.Length);

        return result;
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
    private static IMemoryOwner<byte> CopyToPooled(byte[] bytes, BaseMemoryPool pool)
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
