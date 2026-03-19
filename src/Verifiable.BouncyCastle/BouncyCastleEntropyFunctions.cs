using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle;

/// <summary>
/// Entropy and digest functions backed by the BouncyCastle library.
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
/// </remarks>
public static class BouncyCastleEntropyFunctions
{
    private static readonly SecureRandom SecureRandom = new();

    private static readonly ProviderLibrary ProviderLib = new(
        typeof(BouncyCastleEntropyFunctions).Assembly.GetName().Name
            ?? "Verifiable.BouncyCastle",
        typeof(BouncyCastleEntropyFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    //BouncyCastle is an independently versioned NuGet package — its assembly
    //version is the most meaningful CBOM identifier.
    private static readonly CryptoLibraryInfo CryptoLib = new(
        "Org.BouncyCastle.Cryptography",
        typeof(SecureRandom).Assembly.GetName().Version?.ToString() ?? "Unknown");

    private static readonly ProviderClass ProviderCls =
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

        Salt result = Salt.Generate(byteLength, stamped, SecureRandom.NextBytes,
            EntropyHealthObservation.Unknown, pool, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose ep)
            ? ep : Purpose.Data;
        CryptoEvent evt = EntropyConsumedEvent.Create(
            EntropySource.Csprng, byteLength, evtPurpose, EntropyHealthObservation.Unknown);

        return (result, evt);
    }


    /// <summary>
    /// Computes a <see cref="DigestValue"/> using the BouncyCastle digest implementation
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

        Org.BouncyCastle.Crypto.IDigest digest = algorithmName switch
        {
            var a when a == HashAlgorithmName.SHA256 => new Sha256Digest(),
            var a when a == HashAlgorithmName.SHA384 => new Sha384Digest(),
            var a when a == HashAlgorithmName.SHA512 => new Sha512Digest(),
            _ => throw new ArgumentException(
                $"Unsupported hash algorithm: {algorithmName.Name}.", nameof(tag))
        };

        HashFunctionDelegate hashFunction = (source, destination) =>
        {
            digest.Reset();
            byte[] inputArray = source.ToArray();
            digest.BlockUpdate(inputArray, 0, inputArray.Length);
            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            output.AsSpan().CopyTo(destination);
            return output.Length;
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