using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Verifiable.Tpm.Automata;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// A BouncyCastle-backed <see cref="TpmRsaEsEncryptDelegate"/>/<see cref="TpmRsaEsDecryptDelegate"/>/
/// <see cref="TpmRsaPublicOperationDelegate"/>/<see cref="TpmRsaPrivateOperationDelegate"/> quartet for the
/// in-house <see cref="TpmSimulator"/>: RSAES (PKCS#1 v1.5, TPM 2.0 Library Part 1, clause 43.5) and the raw
/// RSAEP/RSADP primitives (clauses 43.2/43.3) <c>TPM2_RSA_Encrypt()</c>/<c>TPM2_RSA_Decrypt()</c> select
/// alongside the OAEP pair <see cref="BouncyCastleTpmRsaOaepBackend"/> already supplies.
/// </summary>
/// <remarks>
/// <para>
/// RSAES drives BouncyCastle's <see cref="Pkcs1Encoding"/> the same way
/// <see cref="BouncyCastleTpmRsaOaepBackend"/> drives <see cref="OaepEncoding"/> — both wrap a bare
/// <see cref="RsaEngine"/> — so the RSA public/private key construction stays identical between the two
/// backends. The raw primitives run <see cref="BigInteger.ModPow(BigInteger, BigInteger)"/> over the integers
/// directly, bypassing <see cref="RsaEngine"/> — whose own policy refuses the values 0, 1, and n − 1 — and
/// their minimal big-endian result is left-padded to the modulus width here, mirroring
/// <see cref="MicrosoftTpmRsaSigningBackend.ToFixedBigEndian"/>'s fixed-width encoding.
/// </para>
/// <para>
/// The retained private key this backend parses is the same PKCS#1 DER <see cref="MicrosoftTpmRsaSigningBackend"/>
/// generates, through <see cref="BouncyCastleTpmRsaOaepBackend.ParseRsaPrivateKey"/> — the identical parsing
/// step the OAEP backend uses, shared rather than re-minted.
/// </para>
/// </remarks>
internal static class BouncyCastleTpmRsaEsBackend
{
    /// <summary>
    /// Creates the RSAES-encrypt delegate: encrypt-to-public-key drives <see cref="Pkcs1Encoding"/> in
    /// encryption mode.
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaEsEncryptDelegate EncryptRsaes => EncryptRsaesAsync;

    /// <summary>
    /// Creates the RSAES-decrypt delegate: decrypt-with-private-key drives <see cref="Pkcs1Encoding"/> in
    /// decryption mode, mapping a padding failure to <see langword="null"/> (TPM 2.0 Library Part 3, clause
    /// 14.3.1: "If the padding checks fail, TPM_RC_VALUE is returned").
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaEsDecryptDelegate DecryptRsaes => DecryptRsaesAsync;

    /// <summary>
    /// Creates the raw RSAEP delegate: a bare <see cref="RsaEngine"/> in encryption mode, its minimal result
    /// left-padded to the modulus width.
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaPublicOperationDelegate EncryptRaw => EncryptRawAsync;

    /// <summary>
    /// Creates the raw RSADP delegate: a bare <see cref="RsaEngine"/> in decryption mode, its minimal result
    /// left-padded to the modulus width.
    /// </summary>
    /// <returns>The delegate to compose into a <see cref="TpmRsaSigningBackend"/>.</returns>
    public static TpmRsaPrivateOperationDelegate DecryptRaw => DecryptRawAsync;

    /// <summary>
    /// RSAES (PKCS#1 v1.5) encrypts <paramref name="message"/> to the public key built from
    /// <paramref name="modulus"/>/<paramref name="exponent"/>, driving <see cref="Pkcs1Encoding"/> in encryption
    /// mode.
    /// </summary>
    /// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
    /// <param name="exponent">The RSA public exponent.</param>
    /// <param name="message">The message to encrypt.</param>
    /// <param name="pool">The memory pool backing the returned ciphertext.</param>
    /// <param name="cancellationToken">A cancellation token, unused: BouncyCastle's synchronous encoder offers no cancellable step.</param>
    /// <returns>The RSAES ciphertext, exactly <c>k</c> octets (the modulus width).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented ciphertext buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> EncryptRsaesAsync(
        ReadOnlyMemory<byte> modulus,
        uint exponent,
        ReadOnlyMemory<byte> message,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var pkcs1 = new Pkcs1Encoding(new RsaEngine());
        var publicKey = new RsaKeyParameters(isPrivate: false, new BigInteger(1, modulus.ToArray()), BigInteger.ValueOf(exponent));
        pkcs1.Init(forEncryption: true, publicKey);

        byte[] messageBytes = message.ToArray();
        byte[] ciphertext;
        try
        {
            ciphertext = pkcs1.ProcessBlock(messageBytes, 0, messageBytes.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageBytes);
        }

        IMemoryOwner<byte> owner = CopyToPooled(ciphertext, pool);
        CryptographicOperations.ZeroMemory(ciphertext);

        return ValueTask.FromResult(owner);
    }

    /// <summary>
    /// RSAES (PKCS#1 v1.5) decrypts <paramref name="ciphertext"/> with the retained private key, driving
    /// <see cref="Pkcs1Encoding"/> in decryption mode; a padding decode failure answers <see langword="null"/>
    /// rather than throwing (TPM 2.0 Library Part 3, clause 14.3.1: "If the padding checks fail, TPM_RC_VALUE
    /// is returned").
    /// </summary>
    /// <param name="privateKey">The decrypting key's retained private key, the PKCS#1 DER encoding <see cref="BouncyCastleTpmRsaOaepBackend.ParseRsaPrivateKey"/> parses.</param>
    /// <param name="ciphertext">The RSAES ciphertext, exactly <c>k</c> octets (the modulus width).</param>
    /// <param name="pool">The memory pool backing the returned message.</param>
    /// <param name="cancellationToken">A cancellation token, unused: BouncyCastle's synchronous decoder offers no cancellable step.</param>
    /// <returns>The recovered message on success; <see langword="null"/> when PKCS#1 v1.5 decoding failed.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented message buffer transfers to the returned owner, which the simulator disposes; the null (decode-failure) path rents nothing.")]
    private static ValueTask<IMemoryOwner<byte>?> DecryptRsaesAsync(
        ReadOnlyMemory<byte> privateKey,
        ReadOnlyMemory<byte> ciphertext,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var pkcs1 = new Pkcs1Encoding(new RsaEngine());
        RsaPrivateCrtKeyParameters privateKeyParameters = BouncyCastleTpmRsaOaepBackend.ParseRsaPrivateKey(privateKey.Span);
        pkcs1.Init(forEncryption: false, privateKeyParameters);

        byte[] ciphertextBytes = ciphertext.ToArray();
        try
        {
            byte[] decoded;
            try
            {
                decoded = pkcs1.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);
            }
            catch(CryptoException)
            {
                //PKCS#1 v1.5 decode failed: a wrong 00 02 header, no 00 separator, or fewer than 8 padding
                //octets — TPM 2.0 Library Part 3, clause 14.3.1's own sentence makes this an immediate,
                //distinguishable TPM_RC_VALUE rather than a deferred credential-path substitution.
                return ValueTask.FromResult<IMemoryOwner<byte>?>(null);
            }

            IMemoryOwner<byte> owner = CopyToPooled(decoded, pool);
            CryptographicOperations.ZeroMemory(decoded);

            return ValueTask.FromResult<IMemoryOwner<byte>?>(owner);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertextBytes);
        }
    }

    /// <summary>
    /// RSAEP, the raw RSA public-key primitive: <paramref name="value"/> is exponentiated directly, with no
    /// padding wrapper. BouncyCastle's <see cref="RsaEngine"/> refuses 0, 1 and n − 1 as a policy of its own, so
    /// this method runs <see cref="BigInteger.ModPow(BigInteger, BigInteger)"/> over the integers instead, then
    /// left-pads the minimal big-endian result to the modulus width.
    /// </summary>
    /// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
    /// <param name="exponent">The RSA public exponent.</param>
    /// <param name="value">The value to exponentiate, exactly <c>k</c> octets (the modulus width).</param>
    /// <param name="pool">The memory pool backing the returned result.</param>
    /// <param name="cancellationToken">A cancellation token, unused: the modular exponentiation runs synchronously.</param>
    /// <returns>The exponentiation result <c>m^e mod n</c>, exactly <c>k</c> octets (left-padded here).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented result buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> EncryptRawAsync(
        ReadOnlyMemory<byte> modulus,
        uint exponent,
        ReadOnlyMemory<byte> value,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //RSAEP is the bare modular exponentiation c = m^e mod n over 0 <= m < n (RFC 8017 §5.1.1; the
        //simulator judges the range before the call). BouncyCastle's RsaEngine refuses 0, 1 and n - 1 as a
        //policy of its own, so the primitive runs over the integers directly.
        var n = new BigInteger(1, modulus.ToArray());
        byte[] valueBytes = value.ToArray();
        byte[] result;
        try
        {
            result = new BigInteger(1, valueBytes).ModPow(BigInteger.ValueOf(exponent), n).ToByteArrayUnsigned();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(valueBytes);
        }

        byte[] padded = LeftPad(result, modulus.Length);
        CryptographicOperations.ZeroMemory(result);

        IMemoryOwner<byte> owner = CopyToPooled(padded, pool);
        CryptographicOperations.ZeroMemory(padded);

        return ValueTask.FromResult(owner);
    }

    /// <summary>
    /// RSADP, the raw RSA private-key primitive: <paramref name="value"/> is exponentiated directly with the
    /// retained private exponent, with no padding wrapper, for the same reason
    /// <see cref="EncryptRawAsync"/> avoids <see cref="RsaEngine"/> — this method runs
    /// <see cref="BigInteger.ModPow(BigInteger, BigInteger)"/> over the integers instead, then left-pads the
    /// minimal big-endian result to the modulus width.
    /// </summary>
    /// <param name="privateKey">The decrypting key's retained private key, the PKCS#1 DER encoding <see cref="BouncyCastleTpmRsaOaepBackend.ParseRsaPrivateKey"/> parses.</param>
    /// <param name="value">The value to exponentiate, exactly <c>k</c> octets (the modulus width).</param>
    /// <param name="pool">The memory pool backing the returned result.</param>
    /// <param name="cancellationToken">A cancellation token, unused: the modular exponentiation runs synchronously.</param>
    /// <returns>The exponentiation result <c>c^d mod n</c>, exactly <c>k</c> octets (left-padded here).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented result buffer transfers to the returned owner, which the simulator disposes.")]
    private static ValueTask<IMemoryOwner<byte>> DecryptRawAsync(
        ReadOnlyMemory<byte> privateKey,
        ReadOnlyMemory<byte> value,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //RSADP is m = c^d mod n over 0 <= c < n (RFC 8017 §5.1.2), run over the integers for the same
        //reason EncryptRawAsync avoids RsaEngine; the private exponent comes from the retained PKCS#1 key.
        RsaPrivateCrtKeyParameters privateKeyParameters = BouncyCastleTpmRsaOaepBackend.ParseRsaPrivateKey(privateKey.Span);
        byte[] valueBytes = value.ToArray();
        byte[] result;
        try
        {
            result = new BigInteger(1, valueBytes).ModPow(privateKeyParameters.Exponent, privateKeyParameters.Modulus).ToByteArrayUnsigned();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(valueBytes);
        }

        byte[] padded = LeftPad(result, value.Length);
        CryptographicOperations.ZeroMemory(result);

        IMemoryOwner<byte> owner = CopyToPooled(padded, pool);
        CryptographicOperations.ZeroMemory(padded);

        return ValueTask.FromResult(owner);
    }

    /// <summary>
    /// Left-pads <paramref name="value"/> with zero octets to exactly <paramref name="width"/> bytes — the raw
    /// RSAEP/RSADP primitives' minimal big-endian result is narrower than the modulus whenever the numeric
    /// result has leading zero octets, and TPM 2.0 Library Part 1, clauses 43.2/43.3 both return exactly the
    /// modulus width. A local twin of <see cref="MicrosoftTpmRsaSigningBackend.ToFixedBigEndian"/> operating on
    /// a plain octet array rather than a <see cref="System.Numerics.BigInteger"/>, since BouncyCastle's engine
    /// already hands back octets. The result is always a fresh array, never <paramref name="value"/> itself,
    /// so a caller zeroing its input after the call cannot erase the padded copy it is about to pool.
    /// </summary>
    /// <param name="value">The minimal big-endian result.</param>
    /// <param name="width">The fixed width to produce (the modulus width, <c>k</c>).</param>
    /// <returns>A new array of exactly <paramref name="width"/> bytes holding the low-order <paramref name="width"/> octets of <paramref name="value"/>.</returns>
    private static byte[] LeftPad(byte[] value, int width)
    {
        byte[] result = new byte[width];
        int copied = Math.Min(value.Length, width);
        value.AsSpan(value.Length - copied, copied).CopyTo(result.AsSpan(width - copied, copied));

        return result;
    }

    /// <summary>
    /// Copies bytes into an exact-sized pooled buffer through the OAEP backend's shared helper, so the two
    /// backends produce identically shaped owners (an empty result included).
    /// </summary>
    /// <param name="bytes">The bytes to copy.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pooled buffer holding a copy of <paramref name="bytes"/>.</returns>
    private static IMemoryOwner<byte> CopyToPooled(byte[] bytes, BaseMemoryPool pool) =>
        BouncyCastleTpmRsaOaepBackend.CopyToPooled(bytes, pool);
}
