using System;
using System.Buffers.Binary;
using Verifiable.Cryptography;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The suite's deterministic entropy source.
/// </summary>
/// <remarks>
/// Byte-exact test pins on values minted from entropy (nonces, salts, TPM2_GetRandom() draws) need a
/// reproducible fill, never the platform CSPRNG. <see cref="NewCounterStream"/> returns a fresh
/// <see cref="FillEntropyDelegate"/> per call, each closing over its own counter starting at zero — a
/// construction never shares its stream with another, so two devices built in the same test draw the
/// same reproducible sequence independently rather than racing over shared mutable state.
/// </remarks>
internal static class TestEntropy
{
    /// <summary>
    /// Returns a fresh deterministic entropy stream: a per-instance counter, little-endian-encoded eight
    /// octets at a time, advancing once per block drawn. A <c>new TpmSimulator(…, rng:
    /// TestEntropy.NewCounterStream(), …)</c> (or a <c>CardSimulator</c>) therefore answers
    /// <c>TPM2_GetRandom()</c> and mints its nonces with the exact byte sequence the suite's byte-exact
    /// pins state.
    /// </summary>
    /// <returns>A new <see cref="FillEntropyDelegate"/> closing over its own zero-based counter.</returns>
    public static FillEntropyDelegate NewCounterStream()
    {
        ulong counter = 0;

        return destination =>
        {
            Span<byte> block = stackalloc byte[sizeof(ulong)];
            for(int i = 0; i < destination.Length; i += sizeof(ulong))
            {
                BinaryPrimitives.WriteUInt64LittleEndian(block, counter);
                counter++;

                int take = Math.Min(sizeof(ulong), destination.Length - i);
                block[..take].CopyTo(destination.Slice(i, take));
            }
        };
    }
}
