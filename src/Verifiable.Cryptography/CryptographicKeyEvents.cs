using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using Verifiable.Cryptography.Context;

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
    private static CryptoSubject subject { get; } = new();


    /// <summary>
    /// The stream of <see cref="CryptoEvent"/> instances emitted when registered
    /// delegates produce events. Subscribe at application startup to receive
    /// entropy, digest, and future cryptographic operation events.
    /// </summary>
    /// <remarks>
    /// The underlying <see cref="CryptoSubject"/> may deliver concurrently from multiple threads — every
    /// signing/verification call site across the library publishes to this single process-wide stream, so
    /// a subscriber observing more than one operation at a time (directly, or indirectly by running
    /// alongside other concurrent operations in the same process) must synchronize its own state; the
    /// stream itself never serializes delivery to a single subscriber against itself.
    /// </remarks>
    public static IObservable<CryptoEvent> Events => subject;


    /// <summary>
    /// The number of currently subscribed observers on <see cref="Events"/>. Not part of the runtime
    /// public API surface — an application has no legitimate reason to introspect subscriber count — this
    /// exists solely so a test can prove a consumer's subscription lifetime is bounded: subscribe, run its
    /// workload, dispose, and leave the count exactly as it found it (see <c>Verifiable</c>'s
    /// <c>CryptoEventProvenance.CaptureAsync</c>, the wave-7 CLI/MCP consumer).
    /// </summary>
    internal static int SubscriberCountForTests => subject.ObserverCount;


    /// <summary>
    /// The default <see cref="CryptoEventSink"/>: forwards directly to <see cref="Events"/>, exactly as
    /// <see cref="Emit"/> does. Library layers that resolve and invoke a <see cref="SigningDelegate"/>/
    /// <see cref="VerificationDelegate"/> (or a sibling delegate family sharing the same tuple shape)
    /// directly — rather than through the <see cref="PrivateKey.SignAsync"/>/<see cref="PublicKey.VerifyAsync"/>
    /// choke points — invoke <c>(eventSink ?? DefaultSink)(cryptoEvent)</c> when their own trailing
    /// <c>CryptoEventSink? eventSink</c> parameter is <see langword="null"/>, so every call site publishes
    /// to the same stream by default regardless of which route reached it. See <see cref="CryptoEventSink"/>
    /// for the rationale.
    /// </summary>
    public static CryptoEventSink DefaultSink { get; } = subject.OnNext;


    /// <summary>
    /// Emits <paramref name="cryptoEvent"/> to <see cref="Events"/> when it is non-null. The internal hook
    /// used by the <see cref="PrivateKey.SignAsync"/>/<see cref="PublicKey.VerifyAsync"/> choke points, and
    /// by the handful of call sites this assembly grants <c>InternalsVisibleTo</c> access to, to publish
    /// the <see cref="SignatureProducedEvent"/>/<see cref="VerificationCompletedEvent"/> a
    /// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/> implementation constructs. Every
    /// other call site — one without <c>InternalsVisibleTo</c> access, which is the overwhelming majority
    /// of the library's COSE/JOSE, SD-JWT/SD-CWT, DIDComm, and APDU/eMRTD call sites — reaches the same
    /// stream through the public <see cref="DefaultSink"/> instead, via its own <see cref="CryptoEventSink"/>
    /// parameter. Not part of the public API in its own right; the public surface for emitting is
    /// <see cref="DefaultSink"/> (a value, not a spoofable ambient method) and <see cref="Events"/>
    /// (subscribing).
    /// </summary>
    /// <param name="cryptoEvent">The event to emit, or <see langword="null"/> to emit nothing.</param>
    internal static void Emit(CryptoEvent? cryptoEvent)
    {
        if(cryptoEvent is not null)
        {
            subject.OnNext(cryptoEvent);
        }
    }


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
    /// Resolves the registered <see cref="KeyCreationDelegate"/> for <paramref name="algorithm"/> and
    /// <paramref name="purpose"/>, invokes it, and emits any produced <see cref="KeyMaterialGeneratedEvent"/>
    /// to <see cref="Events"/>.
    /// </summary>
    /// <remarks>
    /// This is the choke point for freshly-minted key material — mirroring <see cref="GenerateNonce"/>'s
    /// shape for the same reason: the registered creation delegate is resolved, invoked once, and its event
    /// emitted directly here, unconditionally, because this method (unlike the widened JOSE/COSE/APDU call
    /// sites) IS the seam, not a caller reaching through it. <see cref="CryptographicKeyFactory.CreatePrivateKey"/>/
    /// <see cref="CryptographicKeyFactory.CreatePublicKey"/> deliberately do NOT also emit
    /// <see cref="KeyMaterialGeneratedEvent"/>: those two methods bind both freshly-minted and
    /// loaded/parsed/stored key material indistinguishably, so emitting there would mislabel every loaded
    /// key as newly generated. Call this method instead of a backend <c>Create*Keys</c> static directly when
    /// the resulting <see cref="KeyMaterialGeneratedEvent"/> provenance matters; the existing
    /// <c>Create*Keys</c> statics remain fully legal to call directly and simply forfeit the event, exactly
    /// as a direct <see cref="SigningDelegate"/> call forfeits <see cref="SignatureProducedEvent"/>.
    /// </remarks>
    /// <param name="algorithm">The algorithm of the key pair to create.</param>
    /// <param name="purpose">The purpose (signing, exchange) the key pair is created for.</param>
    /// <param name="pool">The memory pool to allocate key material from.</param>
    /// <param name="qualifier">Optional qualifier for selecting among multiple registered creators.</param>
    /// <returns>The created key pair.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="KeyCreationDelegate"/> has been registered for the given algorithm/purpose.
    /// </exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateKeyPair(
        CryptoAlgorithm algorithm,
        Purpose purpose,
        MemoryPool<byte> pool,
        string? qualifier = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        KeyCreationDelegate create = KeyCreationFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveCreation(
            algorithm, purpose, qualifier);

        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys, CryptoEvent? evt) = create(pool);

        if(evt is not null)
        {
            subject.OnNext(evt);
        }

        return keys;
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
    //Thread-safe subscriber list using copy-on-write: Subscribe/Remove never mutate an existing array in
    //place, they build a new one and reassign the volatile field, so a reader that already captured a
    //snapshot (as OnNext does below) never observes a torn or concurrently-mutated array — the snapshot is
    //immutable for the lifetime of that OnNext call, regardless of how many Subscribe/Dispose calls a
    //concurrent emitter or subscriber interleaves with it. This is what makes concurrent subscribe/dispose
    //during an in-flight emit safe: the emit either sees the observer or it does not, but it never sees a
    //partially-updated array.
    internal sealed class CryptoSubject: IObservable<CryptoEvent>
    {
        private volatile IObserver<CryptoEvent>[] observers = [];
        private readonly object gate = new();


        /// <summary>The number of currently subscribed observers. Test-only introspection hook.</summary>
        internal int ObserverCount => observers.Length;


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


        /// <summary>
        /// Delivers <paramref name="value"/> to every subscriber captured in the immutable snapshot taken
        /// at the start of this call (see the type-level remarks). Each subscriber is isolated from every
        /// other: a subscriber whose <see cref="IObserver{T}.OnNext"/> throws never propagates the exception
        /// into the crypto call site that produced <paramref name="value"/>, and never prevents delivery to
        /// subscribers later in the snapshot. The failure is recorded on <see cref="Activity.Current"/> as
        /// an event carrying the <see cref="CryptoEvent"/>'s runtime type and the exception's runtime type
        /// only — never the event payload itself, which a telemetry backend already receives once, from a
        /// non-throwing subscriber, and should not receive a second time embedded in a diagnostic.
        /// </summary>
        public void OnNext(CryptoEvent value)
        {
            IObserver<CryptoEvent>[] current = observers;
            foreach(IObserver<CryptoEvent> observer in current)
            {
                try
                {
                    observer.OnNext(value);
                }
                catch(Exception exception)
                {
                    Activity.Current?.AddEvent(new ActivityEvent(
                        CryptoTelemetry.ActivityNames.SubscriberException,
                        tags: new ActivityTagsCollection
                        {
                            [CryptoTelemetry.Subscriber.EventType] = value.GetType().Name,
                            [CryptoTelemetry.Subscriber.ExceptionType] = exception.GetType().Name
                        }));
                }
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