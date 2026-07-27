using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle;

/// <summary>
/// Entropy functions backed by the BouncyCastle library: cryptographically strong
/// random generation for <see cref="Nonce"/> and <see cref="Salt"/>.
/// </summary>
/// <remarks>
/// <para>
/// Register these functions at application startup when the BouncyCastle
/// backend is preferred for entropy operations:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateNonceDelegate),
///     BouncyCastleEntropyFunctions.GenerateNonce,
///     qualifier: "bouncy-castle");
/// </code>
/// <para>
/// Each operation uses <see cref="CryptoProviderInstrumentation"/> to stamp the
/// <see cref="Tag"/> with provenance entries and set standard
/// <see cref="CryptoTelemetry"/> attributes on the OTel activity.
/// </para>
/// <para>
/// Digest computation is not here — hashing is deterministic over its input, not entropy,
/// so it lives with the rest of this provider's cryptographic functions on
/// <see cref="BouncyCastleCryptographicFunctions.ComputeDigest"/> and
/// <see cref="BouncyCastleCryptographicFunctions.ComputeBlake3DigestAsync"/>.
/// </para>
/// </remarks>
public static class BouncyCastleEntropyFunctions
{
    private static SecureRandom SecureRandom { get; } = new();

    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(BouncyCastleEntropyFunctions).Assembly.GetName().Name
            ?? "Verifiable.BouncyCastle",
        typeof(BouncyCastleEntropyFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    //BouncyCastle is an independently versioned NuGet package — its assembly
    //version is the most meaningful CBOM identifier.
    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "Org.BouncyCastle.Cryptography",
        typeof(SecureRandom).Assembly.GetName().Version?.ToString() ?? "Unknown");

    private static ProviderClass ProviderCls { get; } =
        new(nameof(BouncyCastleEntropyFunctions));


    /// <summary>
    /// Generates a <see cref="Nonce"/> using BouncyCastle's <see cref="SecureRandom"/>.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate.</param>
    /// <param name="tag">Metadata identifying the purpose and entropy source.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>
    /// The generated <see cref="Nonce"/> and an <see cref="EntropyConsumedEvent"/>.
    /// </returns>
    public static (Nonce Result, CryptoEvent? Event) GenerateNonce(
        int byteLength,
        Tag tag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(GenerateNonce));
        Tag stamped = CryptoProviderInstrumentation.StampTag(
            tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(
            CryptoTelemetry.ActivityNames.Nonce);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(
                activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.ByteLength, byteLength);
            activity.SetTag(CryptoTelemetry.Purpose,
                stamped.TryGet<Purpose>(out Purpose p) ? p.ToString() : string.Empty);
        }

        Nonce result = Nonce.Generate(byteLength, stamped, SecureRandom.NextBytes,
            EntropyHealthObservation.Unknown, pool, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose ep)
            ? ep : Purpose.Nonce;
        CryptoEvent evt = EntropyConsumedEvent.Create(
            EntropySource.Csprng, byteLength, evtPurpose, EntropyHealthObservation.Unknown);

        return (result, evt);
    }


    /// <summary>
    /// Generates a <see cref="Salt"/> using BouncyCastle's <see cref="SecureRandom"/>.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate.</param>
    /// <param name="tag">Metadata identifying the purpose and entropy source.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>
    /// The generated <see cref="Salt"/> and an <see cref="EntropyConsumedEvent"/>.
    /// </returns>
    public static (Salt Result, CryptoEvent? Event) GenerateSalt(
        int byteLength,
        Tag tag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(GenerateSalt));
        Tag stamped = CryptoProviderInstrumentation.StampTag(tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Salt);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.ByteLength, byteLength);
            activity.SetTag(CryptoTelemetry.Purpose, stamped.TryGet<Purpose>(out Purpose p) ? p.ToString() : string.Empty);
        }

        Salt result = Salt.Generate(byteLength, stamped, SecureRandom.NextBytes, EntropyHealthObservation.Unknown, pool, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose ep) ? ep : Purpose.Salt;
        CryptoEvent evt = EntropyConsumedEvent.Create(EntropySource.Csprng, byteLength, evtPurpose, EntropyHealthObservation.Unknown);

        return (result, evt);
    }
}