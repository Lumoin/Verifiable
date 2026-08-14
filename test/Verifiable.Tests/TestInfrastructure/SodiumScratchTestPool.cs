using System;
using System.Buffers;
using Lumoin.Base.Libsodium;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// A minimal <see cref="MemoryPool{T}"/> adapter over <see cref="SodiumBacking.Allocate(int)"/>, used as
    /// the <c>scratchPool</c> argument wherever a test drives libsodium's Ed25519-to-X25519 secret-key
    /// expansion — mirroring the production <c>SodiumGuardedScratchPool</c> that
    /// <c>Verifiable.Libsodium</c> keeps internal to its own assembly.
    /// </summary>
    /// <remarks>
    /// The expanded 64-byte libsodium secret-key form must be reachable only through sodium-guarded native
    /// memory (guard pages, mlock, zero-on-free); a caller supplying a plain <see cref="BaseMemoryPool"/>'s
    /// Managed tier here would silently drop that protection while the secret key is live.
    /// </remarks>
    internal sealed class SodiumScratchTestPool: MemoryPool<byte>
    {
        /// <summary>
        /// The shared instance every test call site uses: the adapter holds no state of its own, so one
        /// instance serves every caller.
        /// </summary>
        public static SodiumScratchTestPool Instance { get; } = new();

        /// <inheritdoc/>
        public override int MaxBufferSize => int.MaxValue;

        /// <summary>
        /// Rents <paramref name="minBufferSize"/> bytes of sodium-guarded native memory via
        /// <see cref="SodiumBacking.Allocate(int)"/>.
        /// </summary>
        /// <param name="minBufferSize">The number of bytes to allocate.</param>
        public override IMemoryOwner<byte> Rent(int minBufferSize = -1) =>
            SodiumBacking.Allocate(minBufferSize);


        /// <summary>
        /// No-op: this adapter owns no unmanaged resources of its own — every rental it hands out is
        /// disposed independently by its caller.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
        }
    }
}
