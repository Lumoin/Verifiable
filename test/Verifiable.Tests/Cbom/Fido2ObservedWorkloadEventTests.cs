using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cbom;

/// <summary>
/// Ties the CLI's observed-CBOM FIDO2 workload (<see cref="VerifiableOperations.RunFido2ObservedWorkloadAsync"/>,
/// wave-4 ruling 3) to the <see cref="CryptographicKeyEvents"/> sign/verify wiring (wave-4 ruling 4): proves the
/// workload's <c>PrivateKey.SignAsync</c>/<c>PublicKey.VerifyAsync</c> calls actually flow through the live
/// <see cref="CryptoEvent"/> subject, not merely through the separate Activity-span mechanism
/// <see cref="Verifiable.Cryptography.Cbom.CbomObserver"/> reads (the two are distinct observability paths —
/// scout-cbom's finding this wave's contract binds on).
/// </summary>
/// <remarks>
/// This test runs the workload in-process (rather than spawning the CLI, as the <c>ToolTests</c> flow tests do)
/// specifically because subscribing to the process-wide <see cref="CryptographicKeyEvents.Events"/> subject
/// requires being in the same process the workload runs in.
/// </remarks>
[TestClass]
internal sealed class Fido2ObservedWorkloadEventTests
{
    /// <summary>
    /// Running the observed FIDO2 workload emits both a <see cref="SignatureProducedEvent"/> (from the
    /// workload's <c>PrivateKey.SignAsync</c> call) and a <see cref="VerificationCompletedEvent"/> with
    /// <see cref="VerificationOutcome.Valid"/> (from <c>Fido2AssertionVerifier</c>'s internal
    /// <c>PublicKey.VerifyAsync</c> call) — presence only, never exact counts, since the subject is
    /// process-wide and shared with every concurrently running test.
    /// </summary>
    [TestMethod]
    public async Task ObservedFido2WorkloadEmitsSignatureAndValidVerificationEvents()
    {
        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            await VerifiableOperations.RunFido2ObservedWorkloadAsync(CancellationToken.None).ConfigureAwait(false);

            Assert.Contains(
                (SignatureProducedEvent e) => e.Algorithm == CryptoAlgorithm.P256,
                observed.OfType<SignatureProducedEvent>(),
                "The observed FIDO2 workload must emit a SignatureProducedEvent for its P-256 assertion signature.");

            Assert.Contains(
                (VerificationCompletedEvent e) => e.Algorithm == CryptoAlgorithm.P256 && e.Outcome == VerificationOutcome.Valid,
                observed.OfType<VerificationCompletedEvent>(),
                "The observed FIDO2 workload must emit a VerificationCompletedEvent with a Valid outcome for its assertion verification.");
        }
    }


    /// <summary>
    /// A minimal <see cref="IObserver{T}"/> appending every observed event to a caller-owned
    /// <see cref="ConcurrentQueue{T}"/> — <see cref="CryptographicKeyEvents.Events"/> is process-wide and
    /// shared with every concurrently running test, and its dispatch makes no promise about which thread
    /// delivers, so a plain <see cref="List{T}"/> here would risk "Collection was modified" under
    /// concurrent delivery from unrelated parallel tests (reproduced: wave 7 added more concurrent traffic
    /// to the shared stream and this observer's prior <c>List&lt;CryptoEvent&gt;</c> started failing
    /// intermittently under the 32-way parallel run).
    /// </summary>
    private sealed class CollectingObserver(ConcurrentQueue<CryptoEvent> sink): IObserver<CryptoEvent>
    {
        /// <summary>No-op: this test observer never unsubscribes via completion.</summary>
        public void OnCompleted()
        {
        }


        /// <summary>No-op: the live subject never calls <see cref="IObserver{T}.OnError"/>.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>Appends the observed event to the sink queue.</summary>
        public void OnNext(CryptoEvent value) => sink.Enqueue(value);
    }
}
