using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Libsodium;

/// <summary>
/// Adapter functions for libsodium Ed25519 cryptographic operations matching <see cref="SigningDelegate"/>
/// and <see cref="VerificationDelegate"/> signatures.
/// </summary>
public static class LibsodiumCryptographicFunctions
{
    /// <summary>
    /// Identifies this assembly (name and version) as the provider library for CBOM/telemetry attribution.
    /// </summary>
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(LibsodiumCryptographicFunctions).Assembly.GetName().Name ?? "Verifiable.Libsodium",
        typeof(LibsodiumCryptographicFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");

    /// <summary>
    /// Identifies the native libsodium library for CBOM/telemetry attribution. The native libsodium binary
    /// is wrapped directly by this project's own binding rather than by an intermediate managed wrapper, so
    /// the native library's own version string (not a managed-wrapper assembly version) is the meaningful
    /// CBOM identifier.
    /// </summary>
    private static CryptoLibraryInfo CryptoLib { get; } = new("libsodium", LibsodiumNativeMethods.GetVersionString());

    /// <summary>
    /// Identifies this class as the provider class for CBOM/telemetry attribution.
    /// </summary>
    private static ProviderClass ProviderCls { get; } = new(nameof(LibsodiumCryptographicFunctions));


    /// <summary>
    /// Signs data using Ed25519 via libsodium.
    /// </summary>
    /// <param name="privateKeyBytes">The 32-byte RFC 8032 Ed25519 seed.</param>
    /// <param name="dataToSign">The data to be signed.</param>
    /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
    /// <param name="context">Optional context (unused).</param>
    /// <param name="cancellationToken">A token to observe for cancellation requests.</param>
    /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="privateKeyBytes"/> is not a 32-byte seed.</exception>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEd25519Async(
        ReadOnlyMemory<byte> privateKeyBytes,
        ReadOnlyMemory<byte> dataToSign,
        BaseMemoryPool signaturePool,
        FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signaturePool);
        LibsodiumNativeMethods.EnsureInitialized();

        if(privateKeyBytes.Length != LibsodiumNativeMethods.Ed25519SeedLength)
        {
            throw new ArgumentException(
                $"An Ed25519 private key must be the {LibsodiumNativeMethods.Ed25519SeedLength}-byte RFC 8032 seed.",
                nameof(privateKeyBytes));
        }

        ProviderOperation operation = new(nameof(SignEd25519Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
        }

        IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(LibsodiumNativeMethods.Ed25519SignatureLength);
        SignWithSeed(privateKeyBytes.Span, dataToSign.Span, memoryPooledSignature.Memory.Span[..LibsodiumNativeMethods.Ed25519SignatureLength]);

        var signatureResult = new Signature(memoryPooledSignature, CryptoTags.Ed25519Signature);
        CryptoEvent evt = SignatureProducedEvent.Create(
            CryptoAlgorithm.Ed25519, dataToSign.Length, LibsodiumNativeMethods.Ed25519SignatureLength, CryptoLib.Name);

        return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));

        /// <summary>
        /// Expands the 32-byte seed into libsodium's 64-byte secret key form inside a guarded scratch
        /// owner from <see cref="LibsodiumNativeMethods.AllocateSecretKeyScratch"/>, signs, and disposes
        /// the owner (which wipes and frees it) before this method returns. The expanded 64-byte form
        /// never touches managed memory: it is reached only by pinning the owner's native memory and
        /// passing the raw pointer to the crypto imports.
        /// </summary>
        /// <param name="seed">The 32-byte RFC 8032 Ed25519 seed.</param>
        /// <param name="message">The data to sign.</param>
        /// <param name="signature">The buffer that receives the 64-byte detached signature.</param>
        static void SignWithSeed(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, Span<byte> signature)
        {
            using IMemoryOwner<byte> secretKeyScratchOwner = LibsodiumNativeMethods.AllocateSecretKeyScratch(
                "libsodium failed to allocate secure scratch memory for Ed25519 signing.");
            using MemoryHandle secretKeyScratchHandle = secretKeyScratchOwner.Memory.Pin();

            nint secretKeyScratch;
            unsafe
            {
                secretKeyScratch = (nint)secretKeyScratchHandle.Pointer;
            }

            Span<byte> publicKeyScratch = stackalloc byte[LibsodiumNativeMethods.Ed25519PublicKeyLength];
            int keypairResult = LibsodiumNativeMethods.crypto_sign_seed_keypair(publicKeyScratch, secretKeyScratch, seed);
            if(keypairResult != 0)
            {
                throw new CryptographicException("libsodium failed to expand the Ed25519 seed into a keypair.");
            }

            int signResult = LibsodiumNativeMethods.crypto_sign_detached(signature, 0, message, (ulong)message.Length, secretKeyScratch);
            if(signResult != 0)
            {
                throw new CryptographicException("libsodium failed to produce an Ed25519 signature.");
            }
        }
    }


    /// <summary>
    /// Verifies an Ed25519 signature via libsodium.
    /// </summary>
    /// <param name="dataToVerify">The data that was signed.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="publicKeyMaterial">The public key bytes.</param>
    /// <param name="context">Optional context (unused).</param>
    /// <param name="cancellationToken">A token to observe for cancellation requests.</param>
    /// <returns>
    /// <see langword="true"/> if verification succeeds; <see langword="false"/> if the signature is
    /// well-formed but cryptographically invalid.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="publicKeyMaterial"/> or <paramref name="signature"/> has a malformed length.
    /// </exception>
    /// <remarks>
    /// Malformed input lengths fail closed via <see cref="ArgumentException"/> rather than returning
    /// <see langword="false"/> — a caller that receives <see langword="false"/> must be able to treat it
    /// as "cryptographically rejected", not "the caller passed garbage". A prior managed Ed25519 binding
    /// used by this repository instead threw <see cref="FormatException"/> on a malformed public-key
    /// length; the exception type here is <see cref="ArgumentException"/> because the malformed argument
    /// is what is actually wrong.
    /// </remarks>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEd25519Async(
        ReadOnlyMemory<byte> dataToVerify,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
    {
        LibsodiumNativeMethods.EnsureInitialized();

        if(publicKeyMaterial.Length != LibsodiumNativeMethods.Ed25519PublicKeyLength)
        {
            throw new ArgumentException(
                $"An Ed25519 public key must be exactly {LibsodiumNativeMethods.Ed25519PublicKeyLength} bytes.",
                nameof(publicKeyMaterial));
        }

        if(signature.Length != LibsodiumNativeMethods.Ed25519SignatureLength)
        {
            throw new ArgumentException(
                $"An Ed25519 signature must be exactly {LibsodiumNativeMethods.Ed25519SignatureLength} bytes.",
                nameof(signature));
        }

        ProviderOperation operation = new(nameof(VerifyEd25519Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
        }

        int verifyResult = LibsodiumNativeMethods.crypto_sign_verify_detached(
            signature.Span, dataToVerify.Span, (ulong)dataToVerify.Length, publicKeyMaterial.Span);
        bool isVerified = verifyResult == 0;

        CryptoEvent evt = VerificationCompletedEvent.Create(
            CryptoAlgorithm.Ed25519, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

        return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
    }
}
