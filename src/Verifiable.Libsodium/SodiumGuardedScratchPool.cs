using System;
using System.Buffers;

namespace Verifiable.Libsodium;

/// <summary>
/// A minimal <see cref="MemoryPool{T}"/> adapter over <see cref="SodiumBacking.Allocate(int)"/>, used
/// exclusively as the <c>scratchPool</c> argument to <see cref="LibsodiumCrypto.AllocateSecretKeyScratch"/>.
/// </summary>
/// <remarks>
/// <see cref="LibsodiumCrypto.AllocateSecretKeyScratch"/> rents from whatever pool it is given via that
/// pool's plain <see cref="MemoryPool{T}.Rent(int)"/> — it does not itself route through
/// <see cref="SodiumBacking"/>. Passing a caller's general-purpose key-material pool (for example a
/// <see cref="BaseMemoryPool"/> whose plain <c>Rent(int)</c> defaults to its Managed tier) would silently
/// drop the guard-page/mlock/zero-on-free protection libsodium's expanded 64-byte Ed25519 secret-key form
/// needs while it is reachable only through a pinned native pointer. This adapter guarantees every scratch
/// rental made through it is sodium-guarded, independent of which pool the caller supplied for the
/// surrounding public/private key material.
/// </remarks>
internal sealed class SodiumGuardedScratchPool: MemoryPool<byte>
{
    /// <summary>
    /// The shared instance used by every call site in this assembly that needs sodium-guarded scratch
    /// memory: the adapter holds no state of its own, so one instance serves every caller.
    /// </summary>
    public static SodiumGuardedScratchPool Instance { get; } = new();

    /// <inheritdoc/>
    public override int MaxBufferSize => int.MaxValue;

    /// <summary>
    /// Rents <paramref name="minBufferSize"/> bytes of sodium-guarded native memory via
    /// <see cref="SodiumBacking.Allocate(int)"/>.
    /// </summary>
    /// <param name="minBufferSize">The number of bytes to allocate.</param>
    /// <exception cref="InvalidOperationException">
    /// The native libsodium library is unavailable, or the family allocator failed.
    /// </exception>
    public override IMemoryOwner<byte> Rent(int minBufferSize = -1) =>
        SodiumBacking.Allocate(minBufferSize);


    /// <summary>
    /// No-op: this adapter owns no unmanaged resources of its own: every rental it hands out is disposed
    /// independently by its caller.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
    }
}
