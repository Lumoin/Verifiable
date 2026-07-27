using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Fido2.Ctap.Authenticator.Custody;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Wraps an inner <see cref="CtapSignatureCounterCustody"/> bundle (typically <see cref="TpmNvSignatureCounterCustody"/>
/// over a real in-house simulated TPM) with two test-only observation/injection hooks, both held as
/// INSTANCE state on this harness rather than closed-over locals — the same no-closure-capture discipline
/// <c>TpmSealedStateCustodyBinding</c>'s bound instance methods follow in production code:
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>
///   <see cref="RetiredCreationSequences"/> — a context log of every creation sequence
///   <see cref="Custody"/>'s <c>RetireCounterAsync</c> delegate was called with, in call order, recorded by
///   the delegate's OWN bound method rather than a captured test-local (wavenv capstone (3)'s "test-recorded
///   via the delegate's own context log, no closure capture" requirement).
///   </description></item>
///   <item><description>
///   <see cref="FailNextIncrement"/> — arms the NEXT <c>IncrementCounterAsync</c> call (only) to throw
///   instead of reaching the inner bundle, so a capstone can prove a failed increment fails the whole
///   assertion command on the wire (wavenv capstone (4)) without needing the real TPM itself to reject
///   anything.
///   </description></item>
/// </list>
/// </remarks>
internal sealed class RecordingSignatureCounterCustodyHarness
{
    /// <summary>The wrapped bundle every non-injected call delegates to.</summary>
    private readonly CtapSignatureCounterCustody inner;

    /// <summary>The backing store for <see cref="RetiredCreationSequences"/>.</summary>
    private readonly List<ulong> retiredCreationSequences = [];

    /// <summary>The number of remaining <c>IncrementCounterAsync</c> calls this harness will fail before delegating again.</summary>
    private int remainingIncrementFailures;


    /// <summary>
    /// Initializes a new harness wrapping <paramref name="inner"/>.
    /// </summary>
    /// <param name="inner">The bundle every non-injected call delegates to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="inner"/> is <see langword="null"/>.</exception>
    public RecordingSignatureCounterCustodyHarness(CtapSignatureCounterCustody inner)
    {
        ArgumentNullException.ThrowIfNull(inner);

        this.inner = inner;
    }


    /// <summary>
    /// The composed <see cref="CtapSignatureCounterCustody"/> bundle a simulator should be built with —
    /// three bound instance methods on this harness, never a closure.
    /// </summary>
    public CtapSignatureCounterCustody Custody { get; private set; } = null!;


    /// <summary>Every creation sequence <see cref="RetireCounterAsync"/> observed, in call order.</summary>
    public IReadOnlyList<ulong> RetiredCreationSequences => retiredCreationSequences;


    /// <summary>
    /// Builds and returns this harness's <see cref="Custody"/> bundle. Call once, immediately after
    /// construction.
    /// </summary>
    /// <returns>This harness, for call chaining at the construction site.</returns>
    public RecordingSignatureCounterCustodyHarness Build()
    {
        Custody = new CtapSignatureCounterCustody(EnsureCounterAsync, IncrementCounterAsync, RetireCounterAsync);

        return this;
    }


    /// <summary>Arms the next <see cref="IncrementCounterAsync"/> call to throw instead of advancing the inner bundle's counter.</summary>
    public void FailNextIncrement() => remainingIncrementFailures++;


    /// <summary>Delegates to the inner bundle's <c>EnsureCounterAsync</c>. Has the <see cref="EnsureCounterAsyncDelegate"/> shape.</summary>
    /// <param name="creationSequence">The minting credential's own creation-sequence identity.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The counter's initial count.</returns>
    private ValueTask<ulong> EnsureCounterAsync(ulong creationSequence, CancellationToken cancellationToken) =>
        inner.EnsureCounterAsync(creationSequence, cancellationToken);


    /// <summary>
    /// Delegates to the inner bundle's <c>IncrementCounterAsync</c>, UNLESS <see cref="FailNextIncrement"/>
    /// has armed a pending failure, in which case this call throws instead and the arm count decrements by
    /// one. Has the <see cref="IncrementCounterAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="creationSequence">The asserting credential's own creation-sequence identity.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The counter's fresh count.</returns>
    /// <exception cref="InvalidOperationException">A test-injected failure was armed for this call.</exception>
    private async ValueTask<ulong> IncrementCounterAsync(ulong creationSequence, CancellationToken cancellationToken)
    {
        if(remainingIncrementFailures > 0)
        {
            remainingIncrementFailures--;
            throw new InvalidOperationException($"Test-injected increment failure for creation sequence '{creationSequence}'.");
        }

        return await inner.IncrementCounterAsync(creationSequence, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Records <paramref name="creationSequence"/> onto <see cref="RetiredCreationSequences"/>, then
    /// delegates to the inner bundle's <c>RetireCounterAsync</c>. Has the
    /// <see cref="RetireCounterAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="creationSequence">The removed credential's own creation-sequence identity.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private async ValueTask RetireCounterAsync(ulong creationSequence, CancellationToken cancellationToken)
    {
        retiredCreationSequences.Add(creationSequence);

        await inner.RetireCounterAsync(creationSequence, cancellationToken).ConfigureAwait(false);
    }
}
