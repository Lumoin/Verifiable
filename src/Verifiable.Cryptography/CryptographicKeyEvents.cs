using System;
using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Extends <see cref="CryptographicKeyFactory"/> with an observable event stream
/// and typed dispatch methods for entropy and digest operations.
/// </summary>
/// <remarks>
/// <para>
/// Backend libraries register their implementations via
/// <see cref="CryptographicKeyFactory.RegisterFunction{TFunction}"/> at startup:
/// </para>
/// <code>
/// //Verifiable.Microsoft registers .NET CSPRNG-backed implementations.
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateNonceDelegate),
///     MicrosoftEntropyFunctions.GenerateNonce);
///
/// //Verifiable.BouncyCastle registers its own implementations.
/// CryptographicKeyFactory.RegisterFunction(
///     typeof(GenerateNonceDelegate),
///     BouncyCastleEntropyFunctions.GenerateNonce,
///     qualifier: "bouncy-castle");
/// </code>
/// <para>
/// When a delegate returns a non-null <see cref="CryptoEvent"/>, this class
/// emits it to <see cref="Events"/>. The application subscribes at startup.
/// Providers that do not support observability return <see langword="null"/>
/// for the event and <see cref="Events"/> remains silent for that operation.
/// </para>
/// </remarks>
public static class CryptographicKeyEvents
{
    private static readonly CryptoSubject subject = new();


    /// <summary>
    /// The stream of <see cref="CryptoEvent"/> instances emitted when registered
    /// delegates produce events. Subscribe at application startup to receive
    /// entropy, digest, and future cryptographic operation events.
    /// </summary>
    public static IObservable<CryptoEvent> Events => subject;


    /// <summary>
    /// Retrieves the registered <see cref="GenerateNonceDelegate"/>, invokes it,
    /// and emits any produced <see cref="CryptoEvent"/> to <see cref="Events"/>.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate.</param>
    /// <param name="tag">Metadata identifying the purpose and entropy source.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <param name="qualifier">Optional qualifier for selecting among multiple implementations.</param>
    /// <returns>The generated <see cref="Nonce"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="GenerateNonceDelegate"/> has been registered.
    /// </exception>
    public static Nonce GenerateNonce(
        int byteLength,
        Tag tag,
        MemoryPool<byte> pool,
        string? qualifier = null)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        GenerateNonceDelegate? generate =
            CryptographicKeyFactory.GetFunction<GenerateNonceDelegate>(
                typeof(GenerateNonceDelegate), qualifier);

        if(generate is null)
        {
            throw new InvalidOperationException(
                $"No {nameof(GenerateNonceDelegate)} has been registered. " +
                "Call CryptographicKeyFactory.RegisterFunction during application startup.");
        }

        (Nonce result, CryptoEvent? evt) = generate(byteLength, tag, pool);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return result;
    }


    /// <summary>
    /// Retrieves the registered <see cref="GenerateSaltDelegate"/>, invokes it,
    /// and emits any produced <see cref="CryptoEvent"/> to <see cref="Events"/>.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate.</param>
    /// <param name="tag">Metadata identifying the purpose and entropy source.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <param name="qualifier">Optional qualifier for selecting among multiple implementations.</param>
    /// <returns>The generated <see cref="Salt"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="GenerateSaltDelegate"/> has been registered.
    /// </exception>
    public static Salt GenerateSalt(
        int byteLength,
        Tag tag,
        MemoryPool<byte> pool,
        string? qualifier = null)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        GenerateSaltDelegate? generate =
            CryptographicKeyFactory.GetFunction<GenerateSaltDelegate>(
                typeof(GenerateSaltDelegate), qualifier);

        if(generate is null)
        {
            throw new InvalidOperationException(
                $"No {nameof(GenerateSaltDelegate)} has been registered. " +
                "Call CryptographicKeyFactory.RegisterFunction during application startup.");
        }

        (Salt result, CryptoEvent? evt) = generate(byteLength, tag, pool);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return result;
    }


    /// <summary>
    /// Invokes the supplied <see cref="ComputeDigestDelegate"/> and emits any produced
    /// <see cref="CryptoEvent"/> to <see cref="Events"/>. This is the explicit-delegate primary: a caller that
    /// holds its own digest implementation passes it here; the registry overload resolves the registered delegate
    /// and calls this one.
    /// </summary>
    public static async ValueTask<DigestValue> ComputeDigestAsync(
        ComputeDigestDelegate computeDigest,
        ReadOnlySequence<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        (DigestValue result, CryptoEvent? evt) = await computeDigest(
            input, outputByteLength, tag, pool, context, cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return result;
    }


    /// <summary>
    /// Retrieves the registered async <see cref="ComputeDigestDelegate"/> and forwards to the explicit-delegate
    /// overload, emitting any produced <see cref="CryptoEvent"/> to <see cref="Events"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="ComputeDigestDelegate"/> has been registered.
    /// </exception>
    public static ValueTask<DigestValue> ComputeDigestAsync(
        ReadOnlySequence<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        string? qualifier = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        ComputeDigestDelegate? compute =
            CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(
                typeof(ComputeDigestDelegate), qualifier);

        if(compute is null)
        {
            throw new InvalidOperationException(
                $"No {nameof(ComputeDigestDelegate)} has been registered. " +
                "Call CryptographicKeyFactory.RegisterFunction during application startup.");
        }

        return ComputeDigestAsync(compute, input, outputByteLength, tag, pool, context, cancellationToken);
    }


    /// <summary>
    /// Convenience overload accepting <see cref="ReadOnlyMemory{T}"/> for one-shot
    /// callers. Wraps in <c>new ReadOnlySequence&lt;byte&gt;(input)</c> and forwards.
    /// </summary>
    public static ValueTask<DigestValue> ComputeDigestAsync(
        ReadOnlyMemory<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        string? qualifier = null,
        CancellationToken cancellationToken = default) =>
        ComputeDigestAsync(new ReadOnlySequence<byte>(input), outputByteLength, tag, pool, context, qualifier, cancellationToken);


    /// <summary>
    /// Computes a digest <strong>synchronously</strong> through the registered <see cref="HashFunctionDelegate"/> —
    /// the sync counterpart of
    /// <see cref="ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, MemoryPool{byte}, FrozenDictionary{string, object}?, string?, CancellationToken)"/>
    /// for a caller whose hash is sync by nature: a hash of public or local data that can never have a
    /// hardware-async backend (a JWK thumbprint, a PKCE S256 challenge, a Concat KDF round, an SD-JWT disclosure
    /// digest). Unlike the removed sync bridge, this consumes a genuinely synchronous
    /// <see cref="HashFunctionDelegate"/>, so it never asserts or blocks on a <see cref="ValueTask"/>. The async
    /// <see cref="ComputeDigestDelegate"/> remains the seam for the trust/custody digests that may be TPM2_Hash- or
    /// KMS-backed (SAID, KERI/ACDC, did:webvh/peer/webplus self-hashing).
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="outputByteLength">The digest length in bytes (32 for SHA-256).</param>
    /// <param name="tag">The tag naming the hash algorithm, e.g. <see cref="CryptoTags.Sha256Digest"/>.</param>
    /// <param name="pool">The pool the digest buffer is rented from.</param>
    /// <param name="qualifier">Selects a non-default registered hash (for an algorithm-agile caller such as SD-JWT, which may request SHA-384/512); <see langword="null"/> uses the default SHA-256 registration.</param>
    /// <returns>The computed digest.</returns>
    /// <exception cref="InvalidOperationException">No matching <see cref="HashFunctionDelegate"/> has been registered.</exception>
    public static DigestValue ComputeDigest(
        ReadOnlySpan<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        string? qualifier = null)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        HashFunctionDelegate? hashFunction =
            CryptographicKeyFactory.GetFunction<HashFunctionDelegate>(typeof(HashFunctionDelegate), qualifier);
        if(hashFunction is null)
        {
            throw new InvalidOperationException(
                $"No {nameof(HashFunctionDelegate)} has been registered"
                + (qualifier is null ? ". " : $" under qualifier '{qualifier}'. ")
                + "Call CryptographicKeyFactory.RegisterFunction during application startup.");
        }

        return DigestValue.Compute(input, hashFunction, outputByteLength, tag, pool);
    }


    /// <summary>
    /// Retrieves the registered <see cref="ComputeHmacDelegate"/>, invokes it,
    /// and emits any produced <see cref="CryptoEvent"/> to <see cref="Events"/>.
    /// </summary>
    public static async ValueTask<HmacValue> ComputeHmacAsync(
        ReadOnlySequence<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        string? qualifier = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        ComputeHmacDelegate? compute =
            CryptographicKeyFactory.GetFunction<ComputeHmacDelegate>(
                typeof(ComputeHmacDelegate), qualifier);

        if(compute is null)
        {
            throw new InvalidOperationException(
                $"No {nameof(ComputeHmacDelegate)} has been registered. " +
                "Call CryptographicKeyFactory.RegisterFunction during application startup.");
        }

        (HmacValue result, CryptoEvent? evt) = await compute(
            message, keyBytes, outputByteLength, tag, pool, context, cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return result;
    }


    /// <summary>Convenience overload for one-shot callers.</summary>
    public static ValueTask<HmacValue> ComputeHmacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        string? qualifier = null,
        CancellationToken cancellationToken = default) =>
        ComputeHmacAsync(new ReadOnlySequence<byte>(message), keyBytes, outputByteLength, tag, pool, context, qualifier, cancellationToken);


    /// <summary>
    /// Retrieves the registered <see cref="VerifyHmacDelegate"/>, invokes it,
    /// and emits any produced <see cref="CryptoEvent"/> to <see cref="Events"/>.
    /// </summary>
    public static async ValueTask<bool> VerifyHmacAsync(
        ReadOnlySequence<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> expectedMac,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        string? qualifier = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        VerifyHmacDelegate? verify =
            CryptographicKeyFactory.GetFunction<VerifyHmacDelegate>(
                typeof(VerifyHmacDelegate), qualifier);

        if(verify is null)
        {
            throw new InvalidOperationException(
                $"No {nameof(VerifyHmacDelegate)} has been registered. " +
                "Call CryptographicKeyFactory.RegisterFunction during application startup.");
        }

        (bool isValid, CryptoEvent? evt) = await verify(
            message, keyBytes, expectedMac, tag, pool, context, cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return isValid;
    }


    /// <summary>Convenience overload for one-shot callers.</summary>
    public static ValueTask<bool> VerifyHmacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> keyBytes,
        ReadOnlyMemory<byte> expectedMac,
        Tag tag,
        MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        string? qualifier = null,
        CancellationToken cancellationToken = default) =>
        VerifyHmacAsync(new ReadOnlySequence<byte>(message), keyBytes, expectedMac, tag, pool, context, qualifier, cancellationToken);


    //Minimal IObservable/IObserver implementation — no System.Reactive dependency.
    //Thread-safe subscriber list using copy-on-write.
    internal sealed class CryptoSubject: IObservable<CryptoEvent>
    {
        private volatile IObserver<CryptoEvent>[] observers = [];
        private readonly object gate = new();


        public IDisposable Subscribe(IObserver<CryptoEvent> observer)
        {
            ArgumentNullException.ThrowIfNull(observer);

            lock(gate)
            {
                IObserver<CryptoEvent>[] current = observers;
                IObserver<CryptoEvent>[] updated =
                    new IObserver<CryptoEvent>[current.Length + 1];
                current.CopyTo(updated, 0);
                updated[current.Length] = observer;
                observers = updated;
            }

            return new Subscription(this, observer);
        }


        public void OnNext(CryptoEvent value)
        {
            IObserver<CryptoEvent>[] current = observers;
            foreach(IObserver<CryptoEvent> observer in current)
            {
                observer.OnNext(value);
            }
        }


        private void Remove(IObserver<CryptoEvent> observer)
        {
            lock(gate)
            {
                IObserver<CryptoEvent>[] current = observers;
                int index = Array.IndexOf(current, observer);
                if(index < 0)
                {
                    return;
                }

                IObserver<CryptoEvent>[] updated =
                    new IObserver<CryptoEvent>[current.Length - 1];
                Array.Copy(current, 0, updated, 0, index);
                Array.Copy(current, index + 1, updated, index,
                    current.Length - index - 1);
                observers = updated;
            }
        }


        private sealed class Subscription(
            CryptoSubject subject,
            IObserver<CryptoEvent> observer): IDisposable
        {
            private bool disposed;

            public void Dispose()
            {
                if(!disposed)
                {
                    subject.Remove(observer);
                    disposed = true;
                }
            }
        }
    }
}