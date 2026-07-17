using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Coverage for the wave-7 <see cref="CryptoEventSink"/> seam itself: <see cref="CryptographicKeyEvents.DefaultSink"/>
/// forwarding to <see cref="CryptographicKeyEvents.Events"/>, per-subscriber exception isolation, and
/// snapshot-safe subscriber enumeration under concurrent subscribe/unsubscribe. These are the properties
/// design item 2 of the wave-7 contract requires before any new emission site is widened — a throwing
/// subscriber must never propagate into a crypto call site, and a subscriber list mutated concurrently with
/// delivery must never throw "Collection was modified" out of <see cref="CryptographicKeyEvents.Events"/>.
/// </summary>
[TestClass]
internal sealed class CryptoEventSinkTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see cref="CryptographicKeyEvents.DefaultSink"/> forwards a directly-constructed event onto
    /// <see cref="CryptographicKeyEvents.Events"/> — the mechanism every widened call site's
    /// <c>eventSink ?? CryptographicKeyEvents.DefaultSink</c> forwarding relies on.
    /// </summary>
    [TestMethod]
    public void DefaultSinkForwardsToEventsStream()
    {
        var observer = new TestObserver<CryptoEvent>();
        CryptoEvent evt = SignatureProducedEvent.Create(CryptoAlgorithm.P256, dataLength: 32, signatureLength: 64, backend: "test-backend");

        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            CryptographicKeyEvents.DefaultSink(evt);
        }

        Assert.Contains(evt, observer.Received, "DefaultSink must publish the exact event instance to the Events stream.");
    }


    /// <summary>
    /// A subscriber whose <see cref="IObserver{T}.OnNext"/> throws must not prevent delivery to a
    /// subscriber registered after it in the snapshot, and the exception must never propagate to the
    /// caller of <see cref="CryptographicKeyEvents.DefaultSink"/> (the crypto call site).
    /// </summary>
    [TestMethod]
    public void ThrowingSubscriberDoesNotBlockLaterSubscriberOrPropagate()
    {
        var throwingObserver = new ThrowingObserver();
        var laterObserver = new TestObserver<CryptoEvent>();
        CryptoEvent evt = VerificationCompletedEvent.Create(CryptoAlgorithm.P256, VerificationOutcome.Valid, dataLength: 32, backend: "test-backend");

        using(CryptographicKeyEvents.Events.Subscribe(throwingObserver))
        using(CryptographicKeyEvents.Events.Subscribe(laterObserver))
        {
            //Must not throw: a throwing subscriber's exception is isolated, never escaping into the caller.
            CryptographicKeyEvents.DefaultSink(evt);
        }

        Assert.IsTrue(throwingObserver.WasInvoked, "The throwing subscriber must still have been invoked.");
        Assert.Contains(evt, laterObserver.Received, "A subscriber registered after a throwing one must still receive the event.");
    }


    /// <summary>
    /// A subscriber registered BEFORE a throwing one still receives the event — isolation does not
    /// depend on subscription order.
    /// </summary>
    [TestMethod]
    public void ThrowingSubscriberDoesNotBlockEarlierSubscriber()
    {
        var earlierObserver = new TestObserver<CryptoEvent>();
        var throwingObserver = new ThrowingObserver();
        CryptoEvent evt = SignatureProducedEvent.Create(CryptoAlgorithm.Ed25519, dataLength: 16, signatureLength: 64, backend: "test-backend");

        using(CryptographicKeyEvents.Events.Subscribe(earlierObserver))
        using(CryptographicKeyEvents.Events.Subscribe(throwingObserver))
        {
            CryptographicKeyEvents.DefaultSink(evt);
        }

        Assert.Contains(evt, earlierObserver.Received);
        Assert.IsTrue(throwingObserver.WasInvoked);
    }


    /// <summary>
    /// Concurrent subscribe, emit, and unsubscribe/dispose must never throw
    /// "Collection was modified; enumeration operation may not execute" — the latent race the wave-6
    /// verifier hit once under 32-way parallelism (<c>SignVerifyEventTests.MicrosoftSignAsyncEmitsSignatureProducedEvent</c>).
    /// The subscriber list must be an immutable snapshot at the start of each emit, so a concurrent
    /// Subscribe/Dispose never observes, nor is observed by, an in-flight enumeration.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentSubscribeUnsubscribeDuringEmitDoesNotThrow()
    {
        const int WorkerCount = 16;
        const int IterationsPerWorker = 200;
        CryptoEvent evt = SignatureProducedEvent.Create(CryptoAlgorithm.P256, dataLength: 8, signatureLength: 64, backend: "stress-test");

        var emitters = Enumerable.Range(0, WorkerCount).Select(_ => Task.Run(() =>
        {
            for(int i = 0; i < IterationsPerWorker; i++)
            {
                CryptographicKeyEvents.DefaultSink(evt);
            }
        }, TestContext.CancellationToken));

        var subscribers = Enumerable.Range(0, WorkerCount).Select(_ => Task.Run(() =>
        {
            for(int i = 0; i < IterationsPerWorker; i++)
            {
                using IDisposable subscription = CryptographicKeyEvents.Events.Subscribe(new TestObserver<CryptoEvent>());
            }
        }, TestContext.CancellationToken));

        //Task.WhenAll re-throws any worker exception (including a torn-collection InvalidOperationException),
        //failing this test if the race were still present.
        await Task.WhenAll(emitters.Concat(subscribers)).ConfigureAwait(false);
    }


    /// <summary>
    /// An <see cref="IObserver{T}"/> whose <see cref="OnNext"/> always throws, tracking whether it was
    /// invoked so a test can assert isolation without depending on the exception having escaped.
    /// </summary>
    private sealed class ThrowingObserver: IObserver<CryptoEvent>
    {
        /// <summary><see langword="true"/> once <see cref="OnNext"/> has been called at least once.</summary>
        public bool WasInvoked { get; private set; }


        /// <summary>Records that it was invoked, then always throws.</summary>
        public void OnNext(CryptoEvent value)
        {
            WasInvoked = true;
            throw new InvalidOperationException("Deliberate subscriber failure for isolation testing.");
        }


        /// <summary>No-op: the live subject never calls <see cref="IObserver{T}.OnError"/>.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>No-op: this test observer never unsubscribes via completion.</summary>
        public void OnCompleted()
        {
        }
    }
}
