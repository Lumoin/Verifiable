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
/// (<see cref="HMACSHA256"/>, <see cref="HMACSHA384"/>, <see cref="HMACSHA512"/>).
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
/// The compute and verify operations are synchronous at the BCL layer but the
/// delegate shape is async to accommodate hardware backends. Software returns a
/// synchronously-completed <see cref="ValueTask{TResult}"/> with effectively zero
/// state-machine cost.
/// </para>
/// </remarks>
public static class MicrosoftHmacFunctions
{
    private static readonly ProviderLibrary ProviderLib = new(
        typeof(MicrosoftHmacFunctions).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftHmacFunctions).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    private static readonly CryptoLibraryInfo CryptoLib = new(
        "System.Security.Cryptography",
        typeof(HMACSHA256).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static readonly ProviderClass ProviderCls =
        new(nameof(MicrosoftHmacFunctions));


    /// <summary>
    /// Computes an HMAC using the .NET platform HMAC implementation identified by
    /// the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>. Supports
    /// SHA-256, SHA-384, and SHA-512.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned HmacValue takes ownership of the IMemoryOwner and is disposed by the caller.")]
    public static ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacAsync(
        ReadOnlyMemory<byte> message,
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
            written = algorithmName switch
            {
                var a when a == HashAlgorithmName.SHA256 =>
                    HMACSHA256.HashData(keyBytes.Span, message.Span, owner.Memory.Span[..outputByteLength]),
                var a when a == HashAlgorithmName.SHA384 =>
                    HMACSHA384.HashData(keyBytes.Span, message.Span, owner.Memory.Span[..outputByteLength]),
                var a when a == HashAlgorithmName.SHA512 =>
                    HMACSHA512.HashData(keyBytes.Span, message.Span, owner.Memory.Span[..outputByteLength]),
                _ => throw new ArgumentException(
                    $"Unsupported HMAC hash algorithm: {algorithmName.Name}.", nameof(tag))
            };
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
            algorithmName.Name ?? "Unknown", message.Length, outputByteLength);

        return ValueTask.FromResult<(HmacValue, CryptoEvent?)>((result, evt));
    }


    /// <summary>
    /// Verifies an HMAC using the .NET platform HMAC implementation identified by
    /// the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>. Uses
    /// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    /// for constant-time comparison.
    /// </summary>
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacAsync(
        ReadOnlyMemory<byte> message,
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

            int written = algorithmName switch
            {
                var a when a == HashAlgorithmName.SHA256 =>
                    HMACSHA256.HashData(keyBytes.Span, message.Span, tempSpan),
                var a when a == HashAlgorithmName.SHA384 =>
                    HMACSHA384.HashData(keyBytes.Span, message.Span, tempSpan),
                var a when a == HashAlgorithmName.SHA512 =>
                    HMACSHA512.HashData(keyBytes.Span, message.Span, tempSpan),
                _ => 0
            };

            isValid = written == outputByteLength
                && expectedMac.Length == outputByteLength
                && CryptographicOperations.FixedTimeEquals(tempSpan, expectedMac.Span);

            //Clear the temporary tag before returning the buffer to the pool — the
            //HMAC value itself is not secret but constant-time discipline keeps the
            //comparison-side bytes from lingering longer than necessary.
            tempSpan.Clear();
        }

        activity?.SetTag(CryptoTelemetry.Hmac.Valid, isValid);
        activity?.Stop();

        VerificationOutcome outcome = isValid
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
        CryptoEvent evt = HmacVerifiedEvent.Create(
            algorithmName.Name ?? "Unknown", outcome, message.Length);

        _ = stamped;
        _ = context;

        return ValueTask.FromResult<(bool, CryptoEvent?)>((isValid, evt));
    }
}
