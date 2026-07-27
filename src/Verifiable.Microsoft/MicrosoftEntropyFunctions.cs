using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Microsoft;

/// <summary>
/// Entropy functions backed by .NET platform cryptography: cryptographically strong
/// random generation for <see cref="Nonce"/> and <see cref="Salt"/>.
/// </summary>
/// <remarks>
/// <para>
/// Register these functions at application startup:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateNonceDelegate),
///     (GenerateNonceDelegate)MicrosoftEntropyFunctions.GenerateNonce);
///
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateSaltDelegate),
///     (GenerateSaltDelegate)MicrosoftEntropyFunctions.GenerateSalt);
/// </code>
/// <para>
/// Digest computation is not here — hashing is deterministic over its input, not entropy,
/// so it lives with the rest of this provider's cryptographic functions on
/// <see cref="MicrosoftCryptographicFunctions.ComputeDigestAsync"/>.
/// </para>
/// </remarks>
public static class MicrosoftEntropyFunctions
{
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(MicrosoftEntropyFunctions).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftEntropyFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "System.Security.Cryptography",
        typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static ProviderClass ProviderCls { get; } =
        new(nameof(MicrosoftEntropyFunctions));


    /// <summary>
    /// Generates a <see cref="Nonce"/> using <see cref="RandomNumberGenerator.Fill"/>.
    /// </summary>
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

        Nonce result = Nonce.Generate(byteLength, stamped, RandomNumberGenerator.Fill,
            EntropyHealthObservation.Unknown, pool, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose ep)
            ? ep : Purpose.Nonce;
        CryptoEvent evt = EntropyConsumedEvent.Create(
            EntropySource.Csprng, byteLength, evtPurpose, EntropyHealthObservation.Unknown);

        return (result, evt);
    }


    /// <summary>
    /// Generates a <see cref="Salt"/> using <see cref="RandomNumberGenerator.Fill"/>.
    /// </summary>
    public static (Salt Result, CryptoEvent? Event) GenerateSalt(
        int byteLength,
        Tag tag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        ProviderOperation operation = new(nameof(GenerateSalt));
        Tag stamped = CryptoProviderInstrumentation.StampTag(
            tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(
            CryptoTelemetry.ActivityNames.Salt);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(
                activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.ByteLength, byteLength);
            activity.SetTag(CryptoTelemetry.Purpose,
                stamped.TryGet<Purpose>(out Purpose p) ? p.ToString() : string.Empty);
        }

        Salt result = Salt.Generate(byteLength, stamped, RandomNumberGenerator.Fill,
            EntropyHealthObservation.Unknown, pool, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose ep)
            ? ep : Purpose.Salt;
        CryptoEvent evt = EntropyConsumedEvent.Create(
            EntropySource.Csprng, byteLength, evtPurpose, EntropyHealthObservation.Unknown);

        return (result, evt);
    }
}