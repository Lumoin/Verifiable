using System;
using System.Buffers;
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
/// mandatory-to-implement method is XOR obfuscation; a block cipher in CFB mode is platform specific and is
/// not provided here yet. Both methods leave the size field of the parameter unprotected and do not change the
/// parameter length (Part 1, Section 19.1).
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
}
