using NSec.Cryptography;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;
using PublicKey = NSec.Cryptography.PublicKey;

namespace Verifiable.NSec;

/// <summary>
/// Adapter functions for NSec cryptographic operations matching <see cref="SigningDelegate"/>
/// and <see cref="VerificationDelegate"/> signatures.
/// </summary>
public static class NSecCryptographicFunctions
{
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(NSecCryptographicFunctions).Assembly.GetName().Name ?? "Verifiable.NSec",
        typeof(NSecCryptographicFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");

    //NSec wraps the native libsodium binary; its assembly version is the meaningful CBOM identifier.
    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "NSec.Cryptography",
        typeof(global::NSec.Cryptography.SignatureAlgorithm).Assembly.GetName().Version?.ToString() ?? "Unknown");

    private static ProviderClass ProviderCls { get; } = new(nameof(NSecCryptographicFunctions));


    /// <summary>
    /// Signs data using Ed25519 via NSec.
    /// </summary>
    /// <param name="privateKeyBytes">The private key bytes.</param>
    /// <param name="dataToSign">The data to be signed.</param>
    /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
    /// <param name="context">Optional context (unused).</param>
    /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEd25519Async(
        ReadOnlyMemory<byte> privateKeyBytes,
        ReadOnlyMemory<byte> dataToSign,
        MemoryPool<byte> signaturePool,
        FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signaturePool);

        ProviderOperation operation = new(nameof(SignEd25519Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
        }

        var algorithm = SignatureAlgorithm.Ed25519;
        _ = Key.TryImport(algorithm, privateKeyBytes.Span, KeyBlobFormat.RawPrivateKey, out Key? signingKey);

        var signature = (ReadOnlySpan<byte>)algorithm.Sign(signingKey!, dataToSign.Span);
        var memoryPooledSignature = signaturePool.Rent(signature.Length);
        signature.CopyTo(memoryPooledSignature.Memory.Span);

        var signatureResult = new Signature(memoryPooledSignature, CryptoTags.Ed25519Signature);
        CryptoEvent evt = SignatureProducedEvent.Create(
            CryptoAlgorithm.Ed25519, dataToSign.Length, signature.Length, CryptoLib.Name);

        return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
    }


    /// <summary>
    /// Verifies an Ed25519 signature via NSec.
    /// </summary>
    /// <param name="dataToVerify">The data that was signed.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <param name="publicKeyMaterial">The public key bytes.</param>
    /// <param name="context">Optional context (unused).</param>
    /// <returns>True if verification succeeds, false otherwise.</returns>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEd25519Async(
        ReadOnlyMemory<byte> dataToVerify,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
    {
        ProviderOperation operation = new(nameof(VerifyEd25519Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
        }

        var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyMaterial.Span, KeyBlobFormat.RawPublicKey);
        bool isVerified = SignatureAlgorithm.Ed25519.Verify(publicKey, dataToVerify.Span, signature.Span);
        CryptoEvent evt = VerificationCompletedEvent.Create(
            CryptoAlgorithm.Ed25519, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name);

        return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
    }
}