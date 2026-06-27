using System;
using System.Buffers;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure.Sessions;

/// <summary>
/// Session-based parameter encryption primitives (TPM 2.0 Library Part 1, Section 19).
/// </summary>
/// <remarks>
/// <para>
/// Parameter encryption protects the data portion of the first parameter of a command or response. The
/// mandatory-to-implement method is XOR obfuscation (<see cref="XorAsync"/>); a block cipher in CFB mode is
/// platform specific and is provided here for AES (<see cref="CfbAsync"/>). Both methods leave the size field
/// of the parameter unprotected and do not change the parameter length (Part 1, Section 19.1).
/// </para>
/// <para>
/// The caller assembles <c>sessionValue</c> (Part 1, Section 19.1: <c>sessionKey</c>, or
/// <c>sessionKey ∥ authValue</c> when the session also authorizes an entity) and supplies the nonces in the
/// command/response order. This type performs no nonce ordering or key assembly of its own.
/// </para>
/// </remarks>
public static class TpmParameterEncryption
{
    /// <summary>
    /// Applies XOR obfuscation in place over <paramref name="data"/> per TPM 2.0 Library Part 1,
    /// Section 9.4.7.3, equation (4).
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm associated with the session (drives the KDF).</param>
    /// <param name="key">
    /// The <c>sessionValue</c> used as the KDF key. XOR is a self-inverse operation, so the same call both
    /// obfuscates plaintext and recovers it from obfuscated data.
    /// </param>
    /// <param name="contextU">
    /// The first context field: <c>nonceNewer</c> (Part 1, Section 19.2). For a command this is the caller
    /// nonce; for a response this is the TPM nonce.
    /// </param>
    /// <param name="contextV">
    /// The second context field: <c>nonceOlder</c>. For a command this is the TPM nonce; for a response this
    /// is the caller nonce.
    /// </param>
    /// <param name="data">The parameter data to obfuscate or recover, modified in place.</param>
    /// <param name="pool">The memory pool for the transient mask.</param>
    /// <param name="cancellationToken">A token observed across the KDF computations.</param>
    /// <returns>A task that completes when <paramref name="data"/> has been XORed with the derived mask.</returns>
    /// <remarks>
    /// <para>
    /// The mask is <c>KDFa(hashAlgorithm, key, "XOR", contextU, contextV, data.Length · 8)</c>; its octets are
    /// XORed with the octets of <paramref name="data"/>. The mask buffer is zeroed before being returned to the
    /// pool. An empty <paramref name="data"/> is a no-op (KDFa requires a positive output length).
    /// </para>
    /// </remarks>
    public static async ValueTask XorAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> contextU,
        ReadOnlyMemory<byte> contextV,
        Memory<byte> data,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(data.IsEmpty)
        {
            return;
        }

        int length = data.Length;
        using IMemoryOwner<byte> mask = await Kdfa.DeriveAsync(
            hashAlgorithm,
            key,
            "XOR",
            contextU,
            contextV,
            length * 8,
            pool,
            cancellationToken).ConfigureAwait(false);

        try
        {
            Span<byte> dataSpan = data.Span;
            ReadOnlySpan<byte> maskSpan = mask.Memory.Span[..length];
            for(int i = 0; i < length; i++)
            {
                dataSpan[i] ^= maskSpan[i];
            }
        }
        finally
        {
            mask.Memory.Span[..length].Clear();
        }
    }

    /// <summary>
    /// Encrypts or decrypts <paramref name="data"/> in place with AES in CFB mode, deriving the key and IV per
    /// TPM 2.0 Library Part 1, Section 19.3, equation (32).
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm associated with the session (drives the KDF).</param>
    /// <param name="keyBits">The AES key size in bits (128, 192, or 256), from the session's TPMT_SYM_DEF.</param>
    /// <param name="key">The <c>sessionValue</c> used as the KDF key (Part 1, Section 19.1).</param>
    /// <param name="contextU">The first context field: <c>nonceNewer</c> (nonceCaller for a command, nonceTPM for a response).</param>
    /// <param name="contextV">The second context field: <c>nonceOlder</c> (nonceTPM for a command, nonceCaller for a response).</param>
    /// <param name="data">The parameter data to encrypt or decrypt, modified in place.</param>
    /// <param name="encrypting"><see langword="true"/> to encrypt, <see langword="false"/> to decrypt.</param>
    /// <param name="pool">The memory pool for the transient key/IV material.</param>
    /// <param name="cancellationToken">A token observed across the KDF computations.</param>
    /// <returns>A task that completes when <paramref name="data"/> has been transformed.</returns>
    /// <remarks>
    /// <para>
    /// <c>KDFa(hashAlgorithm, key, "CFB", contextU, contextV, keyBits + blockBits)</c> produces the key (the
    /// most-significant octets) followed by the IV (the cipher block size, 16 octets for AES). The derived
    /// material buffer is zeroed before being returned to the pool. An empty <paramref name="data"/> is a no-op.
    /// </para>
    /// <para>
    /// Unlike XOR obfuscation, CFB is not self-inverse, so <paramref name="encrypting"/> selects the direction;
    /// the key/IV derivation is identical for both.
    /// </para>
    /// <para>
    /// AES is unsupported on the browser platform (there is no managed AES there), so this method is restricted
    /// accordingly; the XOR obfuscation path (<see cref="XorAsync"/>) remains browser-clean.
    /// </para>
    /// </remarks>
    [UnsupportedOSPlatform("browser")]
    public static async ValueTask CfbAsync(
        HashAlgorithmName hashAlgorithm,
        int keyBits,
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> contextU,
        ReadOnlyMemory<byte> contextV,
        Memory<byte> data,
        bool encrypting,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(data.IsEmpty)
        {
            return;
        }

        int keySize = (keyBits + 7) / 8;
        int materialBytes = keySize + AesBlockSize;

        using IMemoryOwner<byte> keyIv = await Kdfa.DeriveAsync(
            hashAlgorithm,
            key,
            "CFB",
            contextU,
            contextV,
            materialBytes * 8,
            pool,
            cancellationToken).ConfigureAwait(false);

        try
        {
            //Most-significant octets are the key; the remaining block-size octets are the IV (Part 1 §19.3).
            AesCfb(keyIv.Memory.Span[..keySize], keyIv.Memory.Span.Slice(keySize, AesBlockSize), data.Span, encrypting);
        }
        finally
        {
            keyIv.Memory.Span[..materialBytes].Clear();
        }
    }

    /// <summary>
    /// The AES cipher block size in octets (the CFB feedback width and IV size).
    /// </summary>
    private const int AesBlockSize = 16;

    /// <summary>
    /// Transforms <paramref name="data"/> in place with AES in full-block CFB mode (CFB-128) using the supplied
    /// key and IV.
    /// </summary>
    /// <param name="key">The AES key (16, 24, or 32 octets).</param>
    /// <param name="iv">The initialization vector; its first <see cref="AesBlockSize"/> octets are used.</param>
    /// <param name="data">The data to transform in place.</param>
    /// <param name="encrypting"><see langword="true"/> to encrypt, <see langword="false"/> to decrypt.</param>
    /// <remarks>
    /// <para>
    /// CFB-128 with full-block feedback is built directly on the AES forward (encrypt) transform of the feedback
    /// register so it handles arbitrary data lengths with no padding (Part 1, Section 19.1: the encrypted and
    /// plaintext sizes are equal), mirroring the reference TPM's <c>CryptSymmetricEncrypt</c> with
    /// <c>TPM_ALG_CFB</c>. The final partial block uses the leading octets of the keystream. ECB single-block
    /// encryption of the feedback register is used because it is supported on every platform, unlike the
    /// platform-variable native CFB-128 mode.
    /// </para>
    /// </remarks>
    [UnsupportedOSPlatform("browser")]
    public static void AesCfb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, Span<byte> data, bool encrypting)
    {
        if(data.IsEmpty)
        {
            return;
        }

        //Aes exposes only a byte[] key property (no span-key API for ECB/CFB, unlike AesGcm). The KDF-derived
        //transport key is copied into a transient array that is zeroed immediately after use; Aes.Dispose clears
        //its own internal copy.
        byte[] keyArray = key.ToArray();

        try
        {
            using Aes aes = Aes.Create();
            aes.Key = keyArray;

            Span<byte> feedback = stackalloc byte[AesBlockSize];
            Span<byte> keystream = stackalloc byte[AesBlockSize];
            Span<byte> consumedCipher = stackalloc byte[AesBlockSize];
            iv[..AesBlockSize].CopyTo(feedback);

            try
            {
                int offset = 0;
                while(offset < data.Length)
                {
                    int blockLength = Math.Min(AesBlockSize, data.Length - offset);

                    //keystream = AES(feedback). CFB XORs the data with this forward-cipher output.
                    _ = aes.EncryptEcb(feedback, keystream, PaddingMode.None);

                    Span<byte> chunk = data.Slice(offset, blockLength);

                    if(!encrypting)
                    {
                        //Decryption feeds back the ciphertext it consumes, so capture it before the XOR overwrites it.
                        chunk.CopyTo(consumedCipher);
                    }

                    for(int i = 0; i < blockLength; i++)
                    {
                        chunk[i] ^= keystream[i];
                    }

                    //A full ciphertext block becomes the next feedback register; the final partial block has no successor.
                    if(blockLength == AesBlockSize)
                    {
                        if(encrypting)
                        {
                            chunk.CopyTo(feedback);
                        }
                        else
                        {
                            consumedCipher.CopyTo(feedback);
                        }
                    }

                    offset += blockLength;
                }
            }
            finally
            {
                feedback.Clear();
                keystream.Clear();
                consumedCipher.Clear();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyArray);
        }
    }
}
