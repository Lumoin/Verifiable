using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

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
    /// Retrieves the registered <see cref="ComputeDigestDelegate"/>, invokes it,
    /// and emits any produced <see cref="CryptoEvent"/> to <see cref="Events"/>.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="outputByteLength">The expected digest length in bytes.</param>
    /// <param name="tag">Metadata identifying the algorithm and purpose.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <param name="qualifier">Optional qualifier for selecting among multiple implementations.</param>
    /// <returns>The computed <see cref="DigestValue"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="ComputeDigestDelegate"/> has been registered.
    /// </exception>
    public static DigestValue ComputeDigest(
        ReadOnlySpan<byte> input,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        string? qualifier = null)
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

        (DigestValue result, CryptoEvent? evt) = compute(input, outputByteLength, tag, pool);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return result;
    }


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