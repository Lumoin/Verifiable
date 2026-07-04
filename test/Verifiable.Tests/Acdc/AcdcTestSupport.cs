using System;
using System.Buffers;
using System.Text;
using Lumoin.Base;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Shared support for the ACDC tests: an independent digest oracle and a pooled carrier for a serialization's
/// bytes, so the ACDC tests do not each redefine them.
/// </summary>
internal static class AcdcTestSupport
{
    /// <summary>
    /// An algorithm-agile digest oracle: a BLAKE3 request routes to the BouncyCastle backend, every other to the
    /// Microsoft backend. Independent of the production registry, so a verifier reconstructs from bytes alone.
    /// </summary>
    public static ComputeDigestDelegate AgileDigest { get; } = (input, outputByteLength, tag, pool, context, cancellationToken) =>
        tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
            ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
            : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// Encodes a serialization's UTF-8 bytes into a pooled buffer the returned carrier owns and disposes, rather
    /// than leaving them as a naked array a verifier reads.
    /// </summary>
    /// <param name="serialization">The serialization text.</param>
    /// <returns>The carrier of the serialization's pooled bytes.</returns>
    public static EncodedSerialization Encode(string serialization)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return new EncodedSerialization(owner, length);
    }


    /// <summary>
    /// A serialization's bytes, carried in a pooled buffer the test owns and disposes.
    /// </summary>
    internal sealed class EncodedSerialization: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;

        /// <summary>
        /// Creates the carrier over a pooled buffer.
        /// </summary>
        /// <param name="owner">The pooled buffer owner.</param>
        /// <param name="length">The number of bytes written.</param>
        public EncodedSerialization(IMemoryOwner<byte> owner, int length)
        {
            this.owner = owner;
            Length = length;
        }

        /// <summary>The number of serialization bytes.</summary>
        public int Length { get; }

        /// <summary>The serialization bytes as memory.</summary>
        public ReadOnlyMemory<byte> Memory => owner.Memory[..Length];

        /// <summary>The serialization bytes as a span.</summary>
        public ReadOnlySpan<byte> Bytes => owner.Memory.Span[..Length];

        /// <summary>Returns the pooled buffer.</summary>
        public void Dispose() => owner.Dispose();
    }
}
