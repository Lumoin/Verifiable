using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Fills <paramref name="destination"/> with bytes from an entropy source.
/// </summary>
/// <param name="destination">
/// The span to fill. The implementation must fill the entire span.
/// </param>
/// <remarks>
/// <para>
/// The implementation decides the entropy source — CSPRNG, TPM, HSM, or
/// deterministic test vector. The caller has no visibility into how the
/// bytes are produced; that information is captured in the accompanying
/// <see cref="EntropyHealthObservation"/> returned alongside the generated value.
/// </para>
/// <para>
/// Production implementations must use a cryptographically strong source.
/// Deterministic implementations (for test reproducibility) must never be
/// registered in production.
/// </para>
/// <para>
/// Common implementations via direct method group:
/// </para>
/// <code>
/// FillEntropyDelegate csprng = RandomNumberGenerator.Fill;
/// FillEntropyDelegate tpm    = TpmEntropyProvider.Fill;
/// </code>
/// </remarks>
public delegate void FillEntropyDelegate(Span<byte> destination);


/// <summary>
/// Exposes an <see cref="IObservable{T}"/> stream of <see cref="CryptoEvent"/>
/// instances emitted by cryptographic operations in this library.
/// </summary>
/// <remarks>
/// <para>
/// The library emits events here. The application developer subscribes and
/// routes events to whatever sinks are needed — metrics, audit logs, Merkle
/// logs, did:cel, OpenTelemetry spans, CloudEvents over HTTP, dashboards.
/// The library owns the event shapes and the observable surface only.
/// </para>
/// <para>
/// Typical subscriber setup at application startup:
/// </para>
/// <code>
/// CryptoObservable.Events.Subscribe(evt =>
/// {
///     //Route to OpenTelemetry, CloudEvents, audit log, etc.
///     myAuditSink.Record(evt);
/// });
/// </code>
/// <para>
/// In tests, collect events into a list for assertion:
/// </para>
/// <code>
/// var observed = new List&lt;CryptoEvent&gt;();
/// using IDisposable sub = CryptoObservable.Events.Subscribe(observed.Add);
///
/// //Exercise code under test...
///
/// Assert.IsTrue(observed.OfType&lt;EntropyConsumedEvent&gt;().Any());
/// </code>
/// </remarks>
public static class CryptoObservable
{
    private static readonly CryptoSubject subject = new();

    /// <summary>
    /// The stream of <see cref="CryptoEvent"/> instances emitted by
    /// cryptographic operations. Subscribe here to observe all events.
    /// </summary>
    public static IObservable<CryptoEvent> Events => subject;


    /// <summary>
    /// Emits a <see cref="CryptoEvent"/> to all current subscribers.
    /// Called internally by cryptographic operations — not part of the
    /// public API for application code.
    /// </summary>
    internal static void Emit(CryptoEvent cryptoEvent)
    {
        ArgumentNullException.ThrowIfNull(cryptoEvent);
        subject.OnNext(cryptoEvent);
    }


    //A minimal IObservable/IObserver implementation that avoids a dependency
    //on System.Reactive. Thread-safe subscriber list using copy-on-write.
    private sealed class CryptoSubject: IObservable<CryptoEvent>
    {
        private volatile IObserver<CryptoEvent>[] observers = [];
        private readonly object gate = new();


        public IDisposable Subscribe(IObserver<CryptoEvent> observer)
        {
            ArgumentNullException.ThrowIfNull(observer);

            lock(gate)
            {
                IObserver<CryptoEvent>[] current = observers;
                IObserver<CryptoEvent>[] updated = new IObserver<CryptoEvent>[current.Length + 1];
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

                IObserver<CryptoEvent>[] updated = new IObserver<CryptoEvent>[current.Length - 1];
                Array.Copy(current, 0, updated, 0, index);
                Array.Copy(current, index + 1, updated, index, current.Length - index - 1);
                observers = updated;
            }
        }


        private sealed class Subscription(CryptoSubject subject, IObserver<CryptoEvent> observer)
            : IDisposable
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