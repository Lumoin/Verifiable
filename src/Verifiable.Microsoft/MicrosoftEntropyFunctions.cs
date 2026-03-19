using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Microsoft;

/// <summary>
/// Entropy and digest functions backed by .NET platform cryptography.
/// </summary>
/// <remarks>
/// <para>
/// Register these functions at application startup:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateNonceDelegate),
///     MicrosoftEntropyFunctions.GenerateNonce);
///
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateSaltDelegate),
///     MicrosoftEntropyFunctions.GenerateSalt);
///
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(ComputeDigestDelegate),
///     MicrosoftEntropyFunctions.ComputeDigest);
/// </code>
/// <para>
/// Each operation uses <see cref="CryptoProviderInstrumentation"/> to stamp the
/// <see cref="Tag"/> with <see cref="ProviderLibrary"/>, <see cref="CryptoLibrary"/>,
/// <see cref="ProviderClass"/>, and <see cref="ProviderOperation"/> entries, and to
/// set standard <see cref="CryptoTelemetry"/> attributes on the OTel activity.
/// The activity spans the full lifetime of the returned value and is stopped on disposal.
/// If no OTel listener is configured the activity is <see langword="null"/> and the
/// entire instrumentation path is zero-cost.
/// </para>
/// </remarks>
public static class MicrosoftEntropyFunctions
{
    //Resolved once at class initialization — AOT-safe, zero cost at operation time.
    private static readonly ProviderLibrary ProviderLib = new(
        typeof(MicrosoftEntropyFunctions).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftEntropyFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    //System.Security.Cryptography lives in the .NET runtime assembly.
    //Its version equals the runtime version — the most meaningful CBOM identifier.
    private static readonly CryptoLibraryInfo CryptoLib = new(
        "System.Security.Cryptography",
        typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static readonly ProviderClass ProviderCls =
        new(nameof(MicrosoftEntropyFunctions));


    /// <summary>
    /// Generates a <see cref="Nonce"/> using <see cref="RandomNumberGenerator.Fill"/>.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate.</param>
    /// <param name="tag">Metadata identifying the purpose and entropy source.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>
    /// The generated <see cref="Nonce"/> and an <see cref="EntropyConsumedEvent"/>
    /// identifying the OS CSPRNG as the entropy source.
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
    /// <param name="byteLength">The number of random bytes to generate.</param>
    /// <param name="tag">Metadata identifying the purpose and entropy source.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>
    /// The generated <see cref="Salt"/> and an <see cref="EntropyConsumedEvent"/>
    /// identifying the OS CSPRNG as the entropy source.
    /// </returns>
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
            ? ep : Purpose.Data;
        CryptoEvent evt = EntropyConsumedEvent.Create(
            EntropySource.Csprng, byteLength, evtPurpose, EntropyHealthObservation.Unknown);

        return (result, evt);
    }


    /// <summary>
    /// Computes a <see cref="DigestValue"/> using the .NET platform hash implementation
    /// identified by the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>.
    /// Supports SHA-256, SHA-384, and SHA-512.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="outputByteLength">The expected digest length in bytes.</param>
    /// <param name="tag">Metadata identifying the algorithm and purpose.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>
    /// The computed <see cref="DigestValue"/> and a <see cref="DigestComputedEvent"/>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the tag does not carry a supported <see cref="HashAlgorithmName"/>.
    /// </exception>
    public static (DigestValue Result, CryptoEvent? Event) ComputeDigest(
        ReadOnlySpan<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        if(!tag.TryGet<HashAlgorithmName>(out HashAlgorithmName algorithmName))
        {
            throw new ArgumentException(
                "The tag must carry a HashAlgorithmName to select the hash function.",
                nameof(tag));
        }

        HashFunctionDelegate hashFunction = algorithmName switch
        {
            var a when a == HashAlgorithmName.SHA256 => SHA256.HashData,
            var a when a == HashAlgorithmName.SHA384 => SHA384.HashData,
            var a when a == HashAlgorithmName.SHA512 => SHA512.HashData,
            _ => throw new ArgumentException(
                $"Unsupported hash algorithm: {algorithmName.Name}.", nameof(tag))
        };

        ProviderOperation operation = new(nameof(ComputeDigest));
        Tag stamped = CryptoProviderInstrumentation.StampTag(
            tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(
            CryptoTelemetry.ActivityNames.Digest);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(
                activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Digest.Algorithm, algorithmName.Name);
            activity.SetTag(CryptoTelemetry.Digest.InputLength, input.Length);
            activity.SetTag(CryptoTelemetry.Digest.OutputLength, outputByteLength);
        }

        DigestValue result = DigestValue.Compute(
            input, hashFunction, outputByteLength, stamped, pool, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose p)
            ? p : Purpose.Digest;
        CryptoEvent evt = DigestComputedEvent.Create(
            algorithmName.Name ?? "Unknown", input.Length, outputByteLength, evtPurpose);

        return (result, evt);
    }
}