using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Verifiable.Libsodium;

/// <summary>
/// P/Invoke bindings for the subset of the native libsodium library that
/// <see cref="Verifiable.Libsodium"/> uses. Every binding marshals secret material through
/// <see cref="Span{T}"/>/<see cref="ReadOnlySpan{T}"/> or a raw pointer into sodium-guarded
/// memory — never through a naked <c>byte[]</c> — and resolves the bare library name
/// <c>"libsodium"</c>, which the <c>libsodium</c> NuGet package's native asset satisfies on
/// every supported runtime identifier. Guarded scratch allocation itself is delegated to
/// <see cref="SodiumBacking.Allocate(int)"/> (<see cref="AllocateSecretKeyScratch"/>) rather than
/// bound here: this type P/Invokes only the crypto primitives and the one-time init gate.
/// </summary>
internal static partial class LibsodiumNativeMethods
{
    /// <summary>The length in bytes of an Ed25519 public key (<c>crypto_sign_PUBLICKEYBYTES</c>).</summary>
    internal const int Ed25519PublicKeyLength = 32;

    /// <summary>
    /// The length in bytes of libsodium's expanded Ed25519 secret key form (<c>crypto_sign_SECRETKEYBYTES</c>)
    /// — the RFC 8032 seed concatenated with the public key. This form is internal to this binding: it is
    /// produced and consumed only inside sodium-guarded scratch memory and never returned, stored, or exposed.
    /// </summary>
    internal const int Ed25519SecretKeyLength = 64;

    /// <summary>
    /// The length in bytes of an Ed25519 seed (<c>crypto_sign_SEEDBYTES</c>) — the Ed25519 private-key wire
    /// format used throughout this repository (matching <c>Ed25519PrivateKeyParameters.GetEncoded()</c>).
    /// </summary>
    internal const int Ed25519SeedLength = 32;

    /// <summary>The length in bytes of a detached Ed25519 signature (<c>crypto_sign_BYTES</c>).</summary>
    internal const int Ed25519SignatureLength = 64;

    /// <summary>
    /// The length in bytes of an X25519 private scalar (<c>crypto_scalarmult_SCALARBYTES</c>).
    /// </summary>
    internal const int X25519ScalarLength = 32;

    /// <summary>
    /// The length in bytes of an X25519 curve point, public key or shared secret
    /// (<c>crypto_scalarmult_BYTES</c>).
    /// </summary>
    internal const int X25519PointLength = 32;


    /// <summary>
    /// Gets a value confirming libsodium has completed its one-time <c>sodium_init</c> initialization.
    /// </summary>
    /// <remarks>
    /// This property has a non-trivial initializer, so the C# compiler emits an explicit static
    /// constructor for this type. The CLR guarantees that constructor runs exactly once, is mutually
    /// exclusive across threads, and completes before the first access to any static member of this
    /// type — giving <c>sodium_init</c> the thread-safe, run-once gate libsodium requires without any
    /// additional manual locking. <see cref="EnsureInitialized"/> is the call-site-friendly entry point.
    /// </remarks>
    private static bool Initialized { get; } = InitializeSodium();


    /// <summary>
    /// Forces libsodium's one-time initialization gate (<see cref="Initialized"/>) to run before any
    /// other native call. Every public entry point in <see cref="Verifiable.Libsodium"/> calls this first.
    /// </summary>
    internal static void EnsureInitialized()
    {
        _ = Initialized;
    }


    /// <summary>
    /// Calls <c>sodium_init</c> and fails closed if it reports an error.
    /// </summary>
    /// <returns><see langword="true"/> once libsodium is confirmed initialized.</returns>
    /// <exception cref="InvalidOperationException"><c>sodium_init</c> returned a negative status.</exception>
    private static bool InitializeSodium()
    {
        int result = sodium_init();
        if(result < 0)
        {
            throw new InvalidOperationException($"libsodium failed to initialize: sodium_init() returned {result}.");
        }

        return true;
    }


    /// <summary>
    /// Returns libsodium's compiled-in version string (e.g. <c>"1.0.22"</c>), used as the CBOM
    /// <see cref="Verifiable.Cryptography.Provider.CryptoLibrary"/> version identifier. Safe to call
    /// before <see cref="EnsureInitialized"/>: the underlying native call returns a compiled-in constant
    /// and touches no library state.
    /// </summary>
    /// <returns>The version string, or <c>"unknown"</c> if the native call returned no data.</returns>
    internal static string GetVersionString()
    {
        return Marshal.PtrToStringUTF8(sodium_version_string()) ?? "unknown";
    }


    /// <summary>
    /// Allocates <see cref="Ed25519SecretKeyLength"/> bytes of libsodium-guarded scratch memory via
    /// the family <see cref="SodiumBacking.Allocate(int)"/> allocator, for expanding an RFC 8032 seed
    /// into libsodium's internal 64-byte secret-key form. The 64-byte form produced inside the
    /// returned owner is never copied into managed memory: callers <c>Pin</c> the owner's
    /// <see cref="IMemoryOwner{T}.Memory"/> to obtain the raw pointer the <c>nint sk</c> crypto
    /// imports expect, then dispose the owner (which wipes and frees the region) once
    /// signing/keygen/conversion completes.
    /// </summary>
    /// <param name="failureMessage">
    /// The message to surface if the native library is unavailable or the family allocator fails,
    /// matching this binding's established wording at each call site.
    /// </param>
    /// <returns>A guarded scratch owner exactly <see cref="Ed25519SecretKeyLength"/> bytes long.</returns>
    /// <exception cref="InvalidOperationException">
    /// The native libsodium library is unavailable, or the family package failed to allocate the region.
    /// </exception>
    internal static IMemoryOwner<byte> AllocateSecretKeyScratch(string failureMessage)
    {
        EnsureInitialized();
        if(!SodiumBacking.IsAvailable)
        {
            throw new InvalidOperationException(failureMessage);
        }

        try
        {
            return SodiumBacking.Allocate(Ed25519SecretKeyLength);
        }
        catch(InvalidOperationException ex)
        {
            throw new InvalidOperationException(failureMessage, ex);
        }
    }


    /// <summary>
    /// Initializes libsodium. Documented as thread-safe and idempotent: safe to call multiple times
    /// and from multiple threads, with no effect after the first successful call.
    /// </summary>
    /// <returns>0 on first successful initialization, 1 if already initialized, -1 on failure.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int sodium_init();


    /// <summary>
    /// Returns a pointer to libsodium's static, null-terminated, UTF-8 version string. The pointer
    /// refers to library-owned static storage and must not be freed by the caller.
    /// </summary>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial nint sodium_version_string();


    /// <summary>
    /// Fills <paramref name="buf"/> with cryptographically secure random bytes drawn from
    /// libsodium's random number generator.
    /// </summary>
    /// <param name="buf">The buffer to fill.</param>
    /// <param name="size">The number of bytes to fill; must equal <paramref name="buf"/>'s length.</param>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial void randombytes_buf(Span<byte> buf, nuint size);


    /// <summary>
    /// Expands an <see cref="Ed25519SeedLength"/>-byte RFC 8032 seed into an Ed25519 public key and
    /// libsodium's <see cref="Ed25519SecretKeyLength"/>-byte secret key form (seed || public key).
    /// </summary>
    /// <param name="pk">Receives the <see cref="Ed25519PublicKeyLength"/>-byte public key.</param>
    /// <param name="sk">
    /// A pointer to <see cref="Ed25519SecretKeyLength"/> bytes of scratch memory (normally pinned
    /// from <see cref="AllocateSecretKeyScratch"/>) that receives libsodium's expanded secret key
    /// form. This form must never be copied into managed memory.
    /// </param>
    /// <param name="seed">The <see cref="Ed25519SeedLength"/>-byte RFC 8032 seed.</param>
    /// <returns>0 on success.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_sign_seed_keypair(Span<byte> pk, nint sk, ReadOnlySpan<byte> seed);


    /// <summary>
    /// Produces a detached Ed25519 signature per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</see>.
    /// </summary>
    /// <param name="sig">Receives the <see cref="Ed25519SignatureLength"/>-byte signature.</param>
    /// <param name="siglenP">
    /// Optional pointer to receive the actual signature length; pass zero since Ed25519 signatures
    /// are always exactly <see cref="Ed25519SignatureLength"/> bytes.
    /// </param>
    /// <param name="m">The message to sign.</param>
    /// <param name="mlen">The message length in bytes.</param>
    /// <param name="sk">A pointer to the <see cref="Ed25519SecretKeyLength"/>-byte expanded secret key.</param>
    /// <returns>0 on success.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_sign_detached(Span<byte> sig, nint siglenP, ReadOnlySpan<byte> m, ulong mlen, nint sk);


    /// <summary>
    /// Verifies a detached Ed25519 signature per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</see>.
    /// </summary>
    /// <param name="sig">The <see cref="Ed25519SignatureLength"/>-byte signature.</param>
    /// <param name="m">The message that was signed.</param>
    /// <param name="mlen">The message length in bytes.</param>
    /// <param name="pk">The <see cref="Ed25519PublicKeyLength"/>-byte public key.</param>
    /// <returns>0 if the signature is valid; -1 otherwise.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_sign_verify_detached(ReadOnlySpan<byte> sig, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> pk);


    /// <summary>
    /// Computes the X25519 public point for a private scalar — <c>q = n * basepoint</c> — per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748</see> §6.1.
    /// </summary>
    /// <param name="q">Receives the <see cref="X25519PointLength"/>-byte public point.</param>
    /// <param name="n">The <see cref="X25519ScalarLength"/>-byte private scalar.</param>
    /// <returns>0 on success.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_scalarmult_base(Span<byte> q, ReadOnlySpan<byte> n);


    /// <summary>
    /// Computes an X25519 Diffie-Hellman shared point — <c>q = n * p</c> — per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748</see> §6.1.
    /// </summary>
    /// <param name="q">Receives the <see cref="X25519PointLength"/>-byte shared point.</param>
    /// <param name="n">The <see cref="X25519ScalarLength"/>-byte private scalar.</param>
    /// <param name="p">The <see cref="X25519PointLength"/>-byte peer public point.</param>
    /// <returns>0 on success; -1 if the result is the all-zero point (a low-order input).</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_scalarmult(Span<byte> q, ReadOnlySpan<byte> n, ReadOnlySpan<byte> p);


    /// <summary>
    /// Converts an Ed25519 public key to its birationally equivalent Montgomery-curve (X25519)
    /// public key.
    /// </summary>
    /// <param name="curve25519Pk">Receives the <see cref="X25519PointLength"/>-byte X25519 public key.</param>
    /// <param name="ed25519Pk">The <see cref="Ed25519PublicKeyLength"/>-byte Ed25519 public key.</param>
    /// <returns>0 on success.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_sign_ed25519_pk_to_curve25519(Span<byte> curve25519Pk, ReadOnlySpan<byte> ed25519Pk);


    /// <summary>
    /// Converts libsodium's expanded Ed25519 secret key form to its birationally equivalent
    /// Montgomery-curve (X25519) private scalar.
    /// </summary>
    /// <param name="curve25519Sk">Receives the <see cref="X25519ScalarLength"/>-byte X25519 private scalar.</param>
    /// <param name="ed25519Sk">
    /// A pointer to the <see cref="Ed25519SecretKeyLength"/>-byte expanded Ed25519 secret key
    /// (normally sodium-guarded scratch memory from <see cref="AllocateSecretKeyScratch"/>, matching
    /// how <see cref="crypto_sign_seed_keypair"/> and <see cref="crypto_sign_detached"/> receive it).
    /// </param>
    /// <returns>0 on success.</returns>
    [LibraryImport("libsodium")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int crypto_sign_ed25519_sk_to_curve25519(Span<byte> curve25519Sk, nint ed25519Sk);
}
