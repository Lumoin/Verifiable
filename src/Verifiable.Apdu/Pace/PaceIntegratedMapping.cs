using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The cryptographic steps of ICAO Doc 9303 Part 11 PACE with Integrated Mapping (§4.4.3.3.2): mapping the
/// nonce to an ephemeral group generator without a Diffie-Hellman exchange. The terminal draws an extra
/// nonce <c>t</c> and sends it in the clear; both sides then compute the mapped generator
/// <c>Ĝ = f_G(R_p(s,t))</c> independently from the shared nonce <c>s</c> and the public nonce <c>t</c>.
/// </summary>
/// <remarks>
/// <para>
/// Integrated Mapping replaces Generic Mapping's ephemeral ECDH (which derived <c>Ĝ = s·G + H</c>) with a
/// direct map of a pseudo-random field element to the group. The pseudo-random function <c>R_p(s,t)</c>
/// (Doc 9303 Figure 2) maps the two nonces to an octet string <c>R</c> through a CBC-cipher cascade; the
/// point encoding <c>f_G</c> (the constant-time map of Brier et al., Doc 9303 Appendix B) reduces <c>R</c>
/// modulo the field prime and encodes the result to a curve point. Only the AES-128 profile
/// (<c>id-PACE-ECDH-IM-AES-CBC-CMAC-128</c>) is modelled here — the cipher cascade uses the curve's standard
/// AES-128 single-block CBC encryption with a zero IV, the same primitive the encrypted-nonce round uses.
/// </para>
/// <para>
/// Once <c>Ĝ</c> is mapped, the key agreement, session-key derivation, and authentication tokens are identical
/// to Generic Mapping, so this type covers only the mapping; the rest routes through
/// <see cref="PaceGenericMapping"/> and <see cref="PaceKeyDerivation"/>. The mod-<c>p</c> reduction that
/// completes <c>R_p</c> is performed inside the <see cref="EcMap2PointDelegate"/> (which holds the curve
/// prime); the PRF here produces only the octet string <c>R</c>.
/// </para>
/// </remarks>
public static class PaceIntegratedMapping
{
    /// <summary>The AES block size in bytes (also the AES-128 key size): each cipher step is one block.</summary>
    private const int BlockLength = 16;

    /// <summary>The AES block size in bits, the length <c>l</c> of each pseudo-random output block in the PRF.</summary>
    private const int BlockBitLength = 128;

    /// <summary>The pseudo-random output security margin in bits: <c>n·l ≥ log2(p) + 64</c> (Doc 9303 §4.4.3.3.2).</summary>
    private const int SecurityMarginBits = 64;

    /// <summary>
    /// The PRF constant <c>c0</c> for 3DES and AES-128 (<c>l=128</c>), from Doc 9303 Part 11 §4.4.3.3.2:
    /// <c>0xA668892A7C41E3CA739F40B057D85904</c>.
    /// </summary>
    private static ReadOnlySpan<byte> ConstantC0 =>
        [0xA6, 0x68, 0x89, 0x2A, 0x7C, 0x41, 0xE3, 0xCA, 0x73, 0x9F, 0x40, 0xB0, 0x57, 0xD8, 0x59, 0x04];

    /// <summary>
    /// The PRF constant <c>c1</c> for 3DES and AES-128 (<c>l=128</c>), from Doc 9303 Part 11 §4.4.3.3.2:
    /// <c>0xA4E136AC725F738B01C1F60217C188AD</c>.
    /// </summary>
    private static ReadOnlySpan<byte> ConstantC1 =>
        [0xA4, 0xE1, 0x36, 0xAC, 0x72, 0x5F, 0x73, 0x8B, 0x01, 0xC1, 0xF6, 0x02, 0x17, 0xC1, 0x88, 0xAD];


    /// <summary>
    /// Maps the nonces to the ephemeral group generator <c>Ĝ = f_G(R_p(s,t))</c>.
    /// </summary>
    /// <remarks>
    /// Direction-neutral: both the terminal and the chip compute the same <c>Ĝ</c> from the shared nonce
    /// <c>s</c> and the public nonce <c>t</c>, with no key exchange. The pseudo-random function produces the
    /// octet string <c>R</c>; the <see cref="EcMap2PointDelegate"/> reduces it modulo the field prime and
    /// encodes the result.
    /// </remarks>
    /// <param name="nonce">The decrypted nonce <c>s</c> as unsigned big-endian bytes (16 bytes for AES-128).</param>
    /// <param name="additionalNonce">The terminal's public nonce <c>t</c> as unsigned big-endian bytes (16 bytes for AES-128).</param>
    /// <param name="curve">A tag carrying the curve <see cref="CryptoAlgorithm"/>; it both selects the map and sizes the PRF output.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The mapped generator <c>Ĝ</c> as an <see cref="EncodedEcPoint"/>. The caller disposes it.</returns>
    public static async ValueTask<EncodedEcPoint> MapNonceAsync(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> additionalNonce,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        EcMap2PointDelegate map2Point = Resolve<EcMap2PointDelegate>();

        using IMemoryOwner<byte> pseudoRandom = await ComputePseudoRandomAsync(
            nonce, additionalNonce, FieldBitLength(curve), pool, cancellationToken).ConfigureAwait(false);

        return await map2Point(pseudoRandom.Memory, curve, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Computes the Integrated Mapping pseudo-random function <c>R(s,t)</c> (Doc 9303 Part 11 Figure 2): the
    /// AES-128 cipher cascade <c>k0 = E(t, s)</c>, then <c>x_i = E(k_{i-1}, c1)</c> and
    /// <c>k_i = E(k_{i-1}, c0)</c> for <c>i = 1..n</c>, yielding <c>R = x_1 ‖ … ‖ x_n</c>. The constant feeding
    /// each output block is <c>c1</c> and the key cascade advances with <c>c0</c>, as the Appendix H.1 vector
    /// fixes (the figure's two boxes are otherwise symmetric).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>E</c> is single-block AES-128 in CBC mode with a zero IV — the registered
    /// <see cref="SymmetricEncryptDelegate"/> over one block, the same primitive
    /// <see cref="PaceCardResponder.EncryptNonceAsync"/> uses for the nonce. The number of blocks <c>n</c> is
    /// the smallest with <c>n·128 ≥ fieldBitLength + 64</c>; for brainpoolP256r1 that is 3, so <c>R</c> is 48
    /// octets. The result feeds the <see cref="EcMap2PointDelegate"/>, which performs the <c>mod p</c> reduction
    /// that completes <c>R_p(s,t)</c>.
    /// </para>
    /// <para>
    /// The running key <c>k_{i-1}</c> derives from the secret nonce <c>s</c>, so it lives in pinned memory, as
    /// does the output <c>R</c>; both are cleared on disposal.
    /// </para>
    /// </remarks>
    /// <param name="nonce">The decrypted nonce <c>s</c> as unsigned big-endian bytes (16 bytes for AES-128).</param>
    /// <param name="additionalNonce">The terminal's public nonce <c>t</c> as unsigned big-endian bytes (the AES-128 key, 16 bytes).</param>
    /// <param name="fieldBitLength">The bit length of the curve's field prime <c>p</c>, sizing the output to <c>n</c> blocks.</param>
    /// <param name="pool">The sensitive-memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pseudo-random octet string <c>R</c> (exactly <c>n·16</c> bytes), in pinned memory. The caller disposes it.</returns>
    public static async ValueTask<IMemoryOwner<byte>> ComputePseudoRandomAsync(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> additionalNonce,
        int fieldBitLength,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fieldBitLength);

        //n is the smallest count with n·l ≥ log2(p) + 64, where l is the cipher block size in bits.
        int blockCount = (fieldBitLength + SecurityMarginBits + BlockBitLength - 1) / BlockBitLength;
        SymmetricEncryptDelegate encrypt = Resolve<SymmetricEncryptDelegate>();

        //R derives from the secret nonce s, so it is held in pinned memory and cleared on disposal.
        IMemoryOwner<byte> pseudoRandom = pool.Rent(blockCount * BlockLength, AllocationKind.Pinned);
        try
        {
            //Each E() is a single-block CBC encryption with an all-zero IV; the constants c0/c1 are public.
            using IMemoryOwner<byte> zeroIv = pool.Rent(BlockLength);
            using IMemoryOwner<byte> constantC0 = pool.Rent(BlockLength);
            using IMemoryOwner<byte> constantC1 = pool.Rent(BlockLength);
            ConstantC0.CopyTo(constantC0.Memory.Span);
            ConstantC1.CopyTo(constantC1.Memory.Span);

            //The running key k_{i-1}; seeded with k0 = E(t, s). Secret (derived from s), so pinned.
            using IMemoryOwner<byte> runningKey = pool.Rent(BlockLength, AllocationKind.Pinned);
            await EncryptBlockAsync(encrypt, nonce, additionalNonce, zeroIv.Memory, runningKey.Memory, pool, cancellationToken).ConfigureAwait(false);

            for(int i = 0; i < blockCount; i++)
            {
                //x_i = E(k_{i-1}, c1): read the current running key before it is replaced.
                Memory<byte> outputBlock = pseudoRandom.Memory.Slice(i * BlockLength, BlockLength);
                await EncryptBlockAsync(encrypt, constantC1.Memory, runningKey.Memory, zeroIv.Memory, outputBlock, pool, cancellationToken).ConfigureAwait(false);

                //k_i = E(k_{i-1}, c0): advance the running key for the next block.
                await EncryptBlockAsync(encrypt, constantC0.Memory, runningKey.Memory, zeroIv.Memory, runningKey.Memory, pool, cancellationToken).ConfigureAwait(false);
            }

            return pseudoRandom;
        }
        catch
        {
            pseudoRandom.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Encrypts a single block under <paramref name="key"/> with a zero IV and copies the cipher block into
    /// <paramref name="destination"/>. The encryption completes before the copy, so <paramref name="destination"/>
    /// may alias <paramref name="key"/> (the running-key advance does exactly that).
    /// </summary>
    private static async ValueTask EncryptBlockAsync(
        SymmetricEncryptDelegate encrypt,
        ReadOnlyMemory<byte> plaintext,
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> zeroIv,
        Memory<byte> destination,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (Ciphertext block, _) = await encrypt(
            plaintext, key, zeroIv, CryptoTags.Aes128Cbc, pool, null, cancellationToken).ConfigureAwait(false);
        using(block)
        {
            block.AsReadOnlySpan().CopyTo(destination.Span);
        }
    }


    /// <summary>
    /// The bit length of the field prime <c>p</c> for the curve the tag names — the size the PRF uses to pick
    /// the number of output blocks <c>n</c>.
    /// </summary>
    private static int FieldBitLength(Tag curve)
    {
        if(!curve.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new ArgumentException("The tag must carry a CryptoAlgorithm to select the curve.", nameof(curve));
        }

        if(algorithm == CryptoAlgorithm.BrainpoolP224r1) { return 224; }
        if(algorithm == CryptoAlgorithm.BrainpoolP256r1) { return 256; }
        if(algorithm == CryptoAlgorithm.BrainpoolP320r1) { return 320; }
        if(algorithm == CryptoAlgorithm.BrainpoolP384r1) { return 384; }
        if(algorithm == CryptoAlgorithm.BrainpoolP512r1) { return 512; }
        if(algorithm == CryptoAlgorithm.P256) { return 256; }
        if(algorithm == CryptoAlgorithm.P384) { return 384; }
        if(algorithm == CryptoAlgorithm.P521) { return 521; }

        throw new ArgumentException($"PACE Integrated Mapping is not implemented for curve '{algorithm}'.", nameof(curve));
    }


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
