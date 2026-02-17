using NSec.Cryptography;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using PublicKey = NSec.Cryptography.PublicKey;

namespace Verifiable.NSec;

/// <summary>
/// Adapter functions for NSec cryptographic operations matching <see cref="SigningDelegate"/>
/// and <see cref="VerificationDelegate"/> signatures.
/// </summary>
public static class NSecCryptographicFunctions
{
    /// <summary>
    /// Signs data using Ed25519 via NSec.
    /// </summary>
    /// <param name="privateKeyBytes">The private key bytes.</param>
    /// <param name="dataToSign">The data to be signed.</param>
    /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
    /// <param name="context">Optional context (unused).</param>
    /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
    public static ValueTask<Signature> SignEd25519Async(
        ReadOnlyMemory<byte> privateKeyBytes,
        ReadOnlyMemory<byte> dataToSign,
        MemoryPool<byte> signaturePool,
        FrozenDictionary<string, object>? context = null)
    {
        ArgumentNullException.ThrowIfNull(signaturePool);

        var algorithm = SignatureAlgorithm.Ed25519;
        _ = Key.TryImport(algorithm, privateKeyBytes.Span, KeyBlobFormat.RawPrivateKey, out Key? signingKey);

        var signature = (ReadOnlySpan<byte>)algorithm.Sign(signingKey!, dataToSign.Span);
        var memoryPooledSignature = signaturePool.Rent(signature.Length);
        signature.CopyTo(memoryPooledSignature.Memory.Span);

        return ValueTask.FromResult(new Signature(memoryPooledSignature, CryptoTags.Ed25519Signature));
    }


    /// <summary>
    /// Verifies an Ed25519 signature via NSec.
    /// </summary>
    /// <param name="dataToVerify">The data that was signed.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="publicKeyMaterial">The public key bytes.</param>
    /// <param name="context">Optional context (unused).</param>
    /// <returns>True if verification succeeds, false otherwise.</returns>
    public static ValueTask<bool> VerifyEd25519Async(
        ReadOnlyMemory<byte> dataToVerify,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null)
    {
        var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyMaterial.Span, KeyBlobFormat.RawPublicKey);
        return ValueTask.FromResult(SignatureAlgorithm.Ed25519.Verify(publicKey, dataToVerify.Span, signature.Span));
    }
}