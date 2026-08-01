using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Verifiable.Libsodium;

/// <summary>
/// Converts between Ed25519 (signing) and X25519 (key-exchange) key material using libsodium's
/// birational Edwards-to-Montgomery curve mapping.
/// </summary>
public static class LibsodiumKeyConversion
{
    /// <summary>
    /// Converts an Ed25519 public key to its birationally equivalent X25519 public key.
    /// </summary>
    /// <param name="ed25519PublicKey">The 32-byte Ed25519 public key.</param>
    /// <param name="memoryPool">The pool to allocate the returned X25519 public key from.</param>
    /// <returns>A pooled buffer containing the 32-byte X25519 public key. The caller owns disposal.</returns>
    /// <exception cref="ArgumentException"><paramref name="ed25519PublicKey"/> is not exactly 32 bytes.</exception>
    /// <exception cref="CryptographicException">libsodium rejected the conversion (<c>ret != 0</c>).</exception>
    public static IMemoryOwner<byte> ConvertEd25519PublicKeyToCurve25519PublicKey(ReadOnlySpan<byte> ed25519PublicKey, BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        LibsodiumNativeMethods.EnsureInitialized();

        if(ed25519PublicKey.Length != LibsodiumNativeMethods.Ed25519PublicKeyLength)
        {
            throw new ArgumentException(
                $"An Ed25519 public key must be exactly {LibsodiumNativeMethods.Ed25519PublicKeyLength} bytes.",
                nameof(ed25519PublicKey));
        }

        IMemoryOwner<byte> curve25519PublicKeyOwner = memoryPool.Rent(LibsodiumNativeMethods.X25519PointLength);
        int result = LibsodiumNativeMethods.crypto_sign_ed25519_pk_to_curve25519(
            curve25519PublicKeyOwner.Memory.Span[..LibsodiumNativeMethods.X25519PointLength], ed25519PublicKey);
        if(result != 0)
        {
            curve25519PublicKeyOwner.Dispose();
            throw new CryptographicException("libsodium failed to convert the Ed25519 public key to its X25519 form.");
        }

        return curve25519PublicKeyOwner;
    }


    /// <summary>
    /// Converts an Ed25519 private key (the 32-byte RFC 8032 seed) to its birationally equivalent
    /// X25519 private scalar.
    /// </summary>
    /// <param name="ed25519PrivateKeySeed">The 32-byte RFC 8032 Ed25519 seed.</param>
    /// <param name="memoryPool">The pool to allocate the returned X25519 private scalar from.</param>
    /// <returns>A pooled buffer containing the 32-byte X25519 private scalar. The caller owns disposal.</returns>
    /// <exception cref="ArgumentException"><paramref name="ed25519PrivateKeySeed"/> is not exactly 32 bytes.</exception>
    /// <exception cref="InvalidOperationException">libsodium failed to allocate secure scratch memory.</exception>
    /// <exception cref="CryptographicException">
    /// libsodium failed to expand the seed into a keypair, or failed the conversion (<c>ret != 0</c>).
    /// </exception>
    /// <remarks>
    /// The seed is expanded into libsodium's 64-byte secret-key form inside a guarded scratch owner from
    /// <see cref="LibsodiumNativeMethods.AllocateSecretKeyScratch"/> (mirroring
    /// <see cref="LibsodiumCryptographicFunctions.SignEd25519Async"/>); the expanded form never touches
    /// managed memory — it is reached only by pinning the owner's native memory — and the scratch owner
    /// is disposed (wiped and freed) before this method returns.
    /// </remarks>
    public static IMemoryOwner<byte> ConvertEd25519PrivateKeyToCurve25519PrivateKey(ReadOnlySpan<byte> ed25519PrivateKeySeed, BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        LibsodiumNativeMethods.EnsureInitialized();

        if(ed25519PrivateKeySeed.Length != LibsodiumNativeMethods.Ed25519SeedLength)
        {
            throw new ArgumentException(
                $"An Ed25519 private key must be the {LibsodiumNativeMethods.Ed25519SeedLength}-byte RFC 8032 seed.",
                nameof(ed25519PrivateKeySeed));
        }

        IMemoryOwner<byte> curve25519PrivateKeyOwner = memoryPool.Rent(LibsodiumNativeMethods.X25519ScalarLength, AllocationKind.Pinned);

        try
        {
            using IMemoryOwner<byte> secretKeyScratchOwner = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                "libsodium failed to allocate secure scratch memory for the Ed25519-to-X25519 key conversion.");
            using MemoryHandle secretKeyScratchHandle = secretKeyScratchOwner.Memory.Pin();

            nint secretKeyScratch;
            unsafe
            {
                secretKeyScratch = (nint)secretKeyScratchHandle.Pointer;
            }

            Span<byte> publicKeyScratch = stackalloc byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];
            int keypairResult = LibsodiumNativeMethods.crypto_sign_seed_keypair(publicKeyScratch, secretKeyScratch, ed25519PrivateKeySeed);
            if(keypairResult != 0)
            {
                throw new CryptographicException("libsodium failed to expand the Ed25519 seed into a keypair.");
            }

            int conversionResult = LibsodiumNativeMethods.crypto_sign_ed25519_sk_to_curve25519(
                curve25519PrivateKeyOwner.Memory.Span[..LibsodiumNativeMethods.X25519ScalarLength], secretKeyScratch);
            if(conversionResult != 0)
            {
                throw new CryptographicException("libsodium failed to convert the Ed25519 private key to its X25519 form.");
            }
        }
        catch
        {
            curve25519PrivateKeyOwner.Dispose();
            throw;
        }

        return curve25519PrivateKeyOwner;
    }
}
