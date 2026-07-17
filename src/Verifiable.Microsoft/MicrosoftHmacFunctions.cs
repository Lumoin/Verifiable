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
/// HMAC compute and verify functions backed by .NET platform cryptography
/// (<see cref="HMACSHA256"/>, <see cref="HMACSHA384"/>, <see cref="HMACSHA512"/>,
/// <see cref="HMACSHA1"/>).
/// </summary>
/// <remarks>
/// <para>
/// Register at application startup:
/// </para>
/// <code>
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(ComputeHmacDelegate),
///     (ComputeHmacDelegate)MicrosoftHmacFunctions.ComputeHmacAsync);
///
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(VerifyHmacDelegate),
///     (VerifyHmacDelegate)MicrosoftHmacFunctions.VerifyHmacAsync);
/// </code>
/// <para>
/// SHA-1 support exists for TPM session protocol compatibility (TPM 2.0 spec allows
/// SHA-1 sessions; some platforms negotiate it). The convenience tag constants in
/// <see cref="CryptoTags"/> deliberately do not include an <c>HmacSha1Key</c> — new
/// protocol code should not use SHA-1 — but the backend dispatches it when the
/// consumer composes a Tag inline with <see cref="HashAlgorithmName.SHA1"/>.
/// </para>
/// </remarks>
public static class MicrosoftHmacFunctions
{
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(MicrosoftHmacFunctions).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftHmacFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "System.Security.Cryptography",
        typeof(HMACSHA256).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static ProviderClass ProviderCls { get; } =
        new(nameof(MicrosoftHmacFunctions));


    /// <summary>Convenience overload accepting <see cref="ReadOnlyMemory{T}"/>.</summary>
    public static ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default) =>
        ComputeHmacAsync(new ReadOnlySequence<byte>(message), keyBytes, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// Computes an HMAC using the .NET platform HMAC implementation identified by
    /// the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned HmacValue takes ownership of the IMemoryOwner and is disposed by the caller.")]
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "HMAC-SHA-1 is dispatched only when the consumer composes a Tag inline with HashAlgorithmName.SHA1 — exclusively the TPM session authorisation path per the TPM 2.0 spec. Convenience tags in CryptoTags omit SHA-1 so new protocol code cannot use it.")]
    public static ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacAsync(
        ReadOnlySequence<byte> message,
        ReadOnlyMemory<byte> keyBytes,
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
                "The tag must carry a HashAlgorithmName to select the HMAC variant.",
                nameof(tag));
        }

        ProviderOperation operation = new(nameof(ComputeHmacAsync));
        Tag stamped = CryptoProviderInstrumentation.StampTag(
            tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(
            CryptoTelemetry.ActivityNames.HmacCompute);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(
                activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Hmac.Algorithm, algorithmName.Name);
            activity.SetTag(CryptoTelemetry.Hmac.InputLength, message.Length);
            activity.SetTag(CryptoTelemetry.Hmac.OutputLength, outputByteLength);
        }

        IMemoryOwner<byte> owner = pool.Rent(outputByteLength);
        int written;
        try
        {
            Span<byte> destination = owner.Memory.Span[..outputByteLength];

            if(message.IsSingleSegment)
            {
                ReadOnlySpan<byte> messageSpan = message.FirstSpan;
                written = algorithmName switch
                {
                    var a when a == HashAlgorithmName.SHA256 =>
                        HMACSHA256.HashData(keyBytes.Span, messageSpan, destination),
                    var a when a == HashAlgorithmName.SHA384 =>
                        HMACSHA384.HashData(keyBytes.Span, messageSpan, destination),
                    var a when a == HashAlgorithmName.SHA512 =>
                        HMACSHA512.HashData(keyBytes.Span, messageSpan, destination),
                    var a when a == HashAlgorithmName.SHA1 =>
                        HMACSHA1.HashData(keyBytes.Span, messageSpan, destination),
                    _ => throw new ArgumentException(
                        $"Unsupported HMAC hash algorithm: {algorithmName.Name}.", nameof(tag))
                };
            }
            else
            {
                using IncrementalHash hasher = IncrementalHash.CreateHMAC(algorithmName, keyBytes.Span);
                foreach(ReadOnlyMemory<byte> segment in message)
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
                $"HMAC output length mismatch: expected {outputByteLength}, got {written}.");
        }

        HmacValue result = new(owner, stamped, activity);
        CryptoEvent evt = HmacComputedEvent.Create(
            algorithmName.Name ?? "Unknown", (int)message.Length, outputByteLength);

        return ValueTask.FromResult<(HmacValue, CryptoEvent?)>((result, evt));
    }


    /// <summary>Convenience overload accepting <see cref="ReadOnlyMemory{T}"/>.</summary>
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> expectedMac,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default) =>
        VerifyHmacAsync(new ReadOnlySequence<byte>(message), keyBytes, expectedMac, tag, pool, context, cancellationToken);


    /// <summary>
    /// Verifies an HMAC using constant-time comparison via
    /// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
    /// </summary>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "HMAC-SHA-1 dispatched only for TPM session protocol; see ComputeHmacAsync.")]
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacAsync(
        ReadOnlySequence<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> expectedMac,
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
                "The tag must carry a HashAlgorithmName to select the HMAC variant.",
                nameof(tag));
        }

        int outputByteLength = algorithmName switch
        {
            var a when a == HashAlgorithmName.SHA256 => HMACSHA256.HashSizeInBytes,
            var a when a == HashAlgorithmName.SHA384 => HMACSHA384.HashSizeInBytes,
            var a when a == HashAlgorithmName.SHA512 => HMACSHA512.HashSizeInBytes,
            var a when a == HashAlgorithmName.SHA1 => HMACSHA1.HashSizeInBytes,
            _ => throw new ArgumentException(
                $"Unsupported HMAC hash algorithm: {algorithmName.Name}.", nameof(tag))
        };

        ProviderOperation operation = new(nameof(VerifyHmacAsync));
        Tag stamped = CryptoProviderInstrumentation.StampTag(
            tag, ProviderLib, CryptoLib, ProviderCls, operation);

        Activity? activity = CryptoActivitySource.Source.StartActivity(
            CryptoTelemetry.ActivityNames.HmacVerify);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(
                activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Hmac.Algorithm, algorithmName.Name);
            activity.SetTag(CryptoTelemetry.Hmac.InputLength, message.Length);
        }

        bool isValid;
        using(IMemoryOwner<byte> tempOwner = pool.Rent(outputByteLength))
        {
            Span<byte> tempSpan = tempOwner.Memory.Span[..outputByteLength];

            int written;
            if(message.IsSingleSegment)
            {
                ReadOnlySpan<byte> messageSpan = message.FirstSpan;
                written = algorithmName switch
                {
                    var a when a == HashAlgorithmName.SHA256 =>
                        HMACSHA256.HashData(keyBytes.Span, messageSpan, tempSpan),
                    var a when a == HashAlgorithmName.SHA384 =>
                        HMACSHA384.HashData(keyBytes.Span, messageSpan, tempSpan),
                    var a when a == HashAlgorithmName.SHA512 =>
                        HMACSHA512.HashData(keyBytes.Span, messageSpan, tempSpan),
                    var a when a == HashAlgorithmName.SHA1 =>
                        HMACSHA1.HashData(keyBytes.Span, messageSpan, tempSpan),
                    _ => 0
                };
            }
            else
            {
                using IncrementalHash hasher = IncrementalHash.CreateHMAC(algorithmName, keyBytes.Span);
                foreach(ReadOnlyMemory<byte> segment in message)
                {
                    hasher.AppendData(segment.Span);
                }
                written = hasher.GetHashAndReset(tempSpan);
            }

            isValid = written == outputByteLength
                && expectedMac.Length == outputByteLength
                && CryptographicOperations.FixedTimeEquals(tempSpan, expectedMac.Span);

            tempSpan.Clear();
        }

        activity?.SetTag(CryptoTelemetry.Hmac.Valid, isValid);
        activity?.Stop();

        VerificationOutcome outcome = isValid
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
        CryptoEvent evt = HmacVerifiedEvent.Create(
            algorithmName.Name ?? "Unknown", outcome, (int)message.Length);

        _ = stamped;
        _ = context;

        return ValueTask.FromResult<(bool, CryptoEvent?)>((isValid, evt));
    }
}