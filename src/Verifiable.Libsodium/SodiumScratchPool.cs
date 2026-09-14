using System.Buffers;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Verifiable.Libsodium;

/// <summary>
/// A minimal <see cref="MemoryPool{T}"/> adapter used exclusively as the <c>scratchPool</c> argument
/// to <see cref="LibsodiumCrypto.AllocateSecretKeyScratch"/>, splitting on <see cref="OperatingSystem.IsBrowser"/>:
/// off browser-wasm every rental is <see cref="SodiumBacking.Allocate(int)"/> (sodium-guarded native
/// memory — canary, guard pages, best-effort mlock, zero on free); on browser-wasm every rental
/// is a pinned, zero-on-return managed buffer, because WebAssembly's linear memory is one flat
/// JS-visible <c>ArrayBuffer</c> with no per-page permission primitive — guard pages and memory locking
/// do not exist there for any binding to provide. A future toolchain that makes real guarded memory
/// available on browser-wasm is the signal to revisit this split; <see cref="IsGuardedNativeMemory"/>
/// is the guard a caller (or a browser-wasm smoke test) checks to confirm which branch is in effect.
/// </summary>
/// <remarks>
/// <see cref="LibsodiumCrypto.AllocateSecretKeyScratch"/> rents from whatever pool it is given via that
/// pool's plain <see cref="MemoryPool{T}.Rent(int)"/> — it does not itself route through
/// <see cref="SodiumBacking"/>. Passing a caller's general-purpose key-material pool (for example a
/// <see cref="BaseMemoryPool"/> whose plain <c>Rent(int)</c> defaults to its Managed tier) would silently
/// drop the off-browser guard-page/mlock/zero-on-free protection libsodium's expanded 64-byte Ed25519
/// secret-key form needs while it is reachable only through a pinned native pointer. This adapter
/// guarantees every scratch rental made through it gets the strongest posture the running platform can
/// offer, independent of which pool the caller supplied for the surrounding public/private key material.
/// </remarks>
internal sealed class SodiumScratchPool: MemoryPool<byte>
{
    /// <summary>
    /// The shared instance used by every call site in this assembly that needs Ed25519 secret-key
    /// scratch memory: the adapter holds no state of its own, so one instance serves every caller.
    /// </summary>
    public static SodiumScratchPool Instance { get; } = new();

    /// <summary>
    /// <see langword="true"/> off browser-wasm, where every rental from this pool is sodium-guarded
    /// native memory; <see langword="false"/> on browser-wasm, where every rental is a pinned,
    /// zero-on-return managed buffer because the platform has no guard-page or memory-locking
    /// primitive. Read by <see cref="LibsodiumCryptographicFunctions.UsesSodiumGuardedScratchMemory"/>
    /// and asserted by the browser-wasm smoke as a guard against the posture silently flipping either
    /// way. Marked <see cref="UnsupportedOSPlatformGuardAttribute"/> for <c>browser</c> so this property
    /// is also the platform-compatibility analyzer's guard for calling <see cref="SodiumBacking.Allocate(int)"/>
    /// (itself <c>[UnsupportedOSPlatform("browser")]</c>) from <see cref="Rent(int)"/>: the analyzer then
    /// enforces that every call to it in this class is reached only through this same condition, so the
    /// platform split cannot be reordered or dropped without a build error.
    /// </summary>
    [UnsupportedOSPlatformGuard("browser")]
    public static bool IsGuardedNativeMemory => !OperatingSystem.IsBrowser();

    /// <inheritdoc/>
    public override int MaxBufferSize => int.MaxValue;

    /// <summary>
    /// Rents <paramref name="minBufferSize"/> bytes of scratch memory: sodium-guarded native memory
    /// via <see cref="SodiumBacking.Allocate(int)"/> off browser-wasm, or a pinned, zero-on-return
    /// managed buffer on browser-wasm.
    /// </summary>
    /// <param name="minBufferSize">The number of bytes to allocate.</param>
    /// <exception cref="InvalidOperationException">
    /// Off browser-wasm: the native libsodium library is unavailable, or the family allocator failed.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// On browser-wasm: <paramref name="minBufferSize"/> is not positive.
    /// </exception>
    public override IMemoryOwner<byte> Rent(int minBufferSize = -1) =>
        IsGuardedNativeMemory
            ? SodiumBacking.Allocate(minBufferSize)
            : new PinnedZeroOnReturnMemoryOwner(minBufferSize);


    /// <summary>
    /// No-op: this adapter owns no unmanaged resources of its own; every rental it hands out is disposed
    /// independently by its caller.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
    }


    /// <summary>
    /// The browser-wasm scratch owner: a pinned-object-heap buffer of exactly the requested length,
    /// never GC-relocated (so zeroing on dispose actually wipes the bytes that held the secret) but
    /// reachable, for as long as it lives, from any JavaScript running in the same page — WebAssembly's
    /// linear memory carries no OS-level guard pages or memory locking, so this is the strongest
    /// posture the platform can offer. Internal rather than private so the off-browser test suite can
    /// assert <see cref="Rent(int)"/> never hands one out there, observing the actual owner rather than
    /// restating <see cref="IsGuardedNativeMemory"/>.
    /// </summary>
    internal sealed class PinnedZeroOnReturnMemoryOwner: IMemoryOwner<byte>
    {
        /// <summary>The pinned backing buffer, or <see langword="null"/> once disposed.</summary>
        private byte[]? buffer;

        /// <summary>
        /// Allocates a pinned-object-heap buffer of exactly <paramref name="size"/> bytes.
        /// </summary>
        /// <param name="size">The exact number of bytes to allocate.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="size"/> is not positive.</exception>
        public PinnedZeroOnReturnMemoryOwner(int size)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);

            buffer = GC.AllocateArray<byte>(size, pinned: true);
        }

        /// <inheritdoc/>
        public Memory<byte> Memory => buffer ?? throw new ObjectDisposedException(nameof(PinnedZeroOnReturnMemoryOwner));

        /// <summary>
        /// Zeroes the buffer via <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> — a wipe
        /// the JIT cannot elide — before releasing it. Idempotent.
        /// </summary>
        public void Dispose()
        {
            if(buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
                buffer = null;
            }
        }
    }
}
