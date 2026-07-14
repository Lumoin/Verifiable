using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
///     (GenerateNonceDelegate)MicrosoftEntropyFunctions.GenerateNonce);
///
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateSaltDelegate),
///     (GenerateSaltDelegate)MicrosoftEntropyFunctions.GenerateSalt);
///
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(ComputeDigestDelegate),
///     (ComputeDigestDelegate)MicrosoftEntropyFunctions.ComputeDigestAsync);
/// </code>
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


    /// <summary>
    /// Computes a <see cref="DigestValue"/> using the .NET platform hash implementation
    /// identified by the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>.
    /// Supports SHA-256, SHA-384, SHA-512, and SHA-1 (the SHA-1 path exists for TPM
    /// session protocol compatibility).
    /// </summary>
    /// <remarks>
    /// Single-segment input uses the .NET BCL one-shot hash methods. Multi-segment
    /// input streams via <see cref="IncrementalHash"/>, iterating
    /// <see cref="ReadOnlySequence{T}"/> segments and feeding each to
    /// <c>AppendData</c> without pre-buffering. Returns a synchronously-completed
    /// <see cref="ValueTask{TResult}"/>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned DigestValue takes ownership of the IMemoryOwner and is disposed by the caller.")]
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "SHA-1 is dispatched only when the consumer composes a Tag inline with HashAlgorithmName.SHA1 — exclusively the TPM command-parameter hashing path. Convenience tags in CryptoTags omit SHA-1 so new protocol code cannot use it.")]
    public static ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeDigestAsync(
        ReadOnlySequence<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        if(!tag.TryGet<HashAlgorithmName>(out HashAlgorithmName algorithmName))
        {
            throw new ArgumentException(
                "The tag must carry a HashAlgorithmName to select the hash function.",
                nameof(tag));
        }

        ProviderOperation operation = new(nameof(ComputeDigestAsync));
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

        IMemoryOwner<byte> owner = pool.Rent(outputByteLength);
        int written;
        try
        {
            Span<byte> destination = owner.Memory.Span[..outputByteLength];

            if(input.IsSingleSegment)
            {
                ReadOnlySpan<byte> inputSpan = input.FirstSpan;
                written = algorithmName switch
                {
                    var a when a == HashAlgorithmName.SHA256 => SHA256.HashData(inputSpan, destination),
                    var a when a == HashAlgorithmName.SHA384 => SHA384.HashData(inputSpan, destination),
                    var a when a == HashAlgorithmName.SHA512 => SHA512.HashData(inputSpan, destination),
                    var a when a == HashAlgorithmName.SHA1 => SHA1.HashData(inputSpan, destination),
                    _ => throw new ArgumentException(
                        $"Unsupported digest hash algorithm: {algorithmName.Name}.", nameof(tag))
                };
            }
            else
            {
                using IncrementalHash hasher = IncrementalHash.CreateHash(algorithmName);
                foreach(ReadOnlyMemory<byte> segment in input)
                {
                    hasher.AppendData(segment.Span);
                }
                written = hasher.GetHashAndReset(destination);
            }
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        if(written != outputByteLength)
        {
            owner.Dispose();
            throw new InvalidOperationException(
                $"Digest output length mismatch: expected {outputByteLength}, got {written}.");
        }

        DigestValue result = new(owner, stamped, activity);

        Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose p)
            ? p : Purpose.Digest;
        CryptoEvent evt = DigestComputedEvent.Create(
            algorithmName.Name ?? "Unknown", (int)input.Length, outputByteLength, evtPurpose);

        return ValueTask.FromResult<(DigestValue, CryptoEvent?)>((result, evt));
    }
}