using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Foundation;

/// <summary>
/// Instruments <see cref="BaseMemoryPool"/> for the two failure shapes many-way concurrent rent/return traffic
/// could produce — a double rent (two callers handed the same backing storage) or a use-after-return (a caller
/// still reads storage another caller has since been handed) — either of which lets one caller's write bleed
/// into another caller's rental. A carrier corrupted this way that happens to back an RSA modulus reads as a
/// value the modulus comparison in
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 1, clause 43.2 (RSAEP/RSADP require <c>0 &lt;= m &lt; n</c>) can wrongly fail,
/// which the raw-scheme return path in Part 3, clause 14.3.1 then reports as <c>TPM_RC_VALUE</c> even though
/// the ciphertext and the key are both individually well formed.
/// </summary>
/// <remarks>
/// Every worker's fill pattern tiles its own rental id across the buffer 8 octets at a time; verifying a
/// rental therefore either finds its own id everywhere (no aliasing) or finds a foreign rental's id at the
/// point of overlap, which names the two colliding rentals directly. Only the aliasing invariant is asserted
/// on failure — never that a particular interleaving occurred, per the house race-test discipline: a race may
/// run in any order, but wrong code is the only thing allowed to fail the test.
/// </remarks>
[TestClass]
internal sealed class BaseMemoryPoolContentionTests
{
    /// <summary>How many workers contend on the pool at once.</summary>
    private const int WorkerCount = 32;

    /// <summary>How many rent/fill/verify/return cycles each worker runs.</summary>
    private const int CyclesPerWorker = 1200;

    /// <summary>
    /// The rental sizes workers cycle through, in octets. Every size is a multiple of 8 so the 8-octet
    /// rental-id fingerprint tiles across a rental with no partial tail; 256, 384 and 512 are the RSA
    /// ciphertext/modulus carrier widths for 2048-, 3072- and 4096-bit keys under
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1, clause 43.2's RSAEP/RSADP primitives — the exact carrier family whose
    /// corruption would explain a spurious <c>TPM_RC_VALUE</c> on an otherwise-below-modulus ciphertext.
    /// </summary>
    private static int[] RentalSizesInOctets { get; } = [8, 16, 32, 64, 128, 256, 384, 512];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Thirty-two workers contend on a freshly constructed, dedicated <see cref="BaseMemoryPool"/>
    /// (<see cref="MeteredHousePool.Pool"/>): no two concurrently outstanding rentals ever alias the same
    /// backing storage, and every rental reads back all-zero octets at the moment it is handed out.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentRentersNeverAliasOverADedicatedPool()
    {
        using var housePool = new MeteredHousePool();

        await RunContentionAsync(housePool.Pool).ConfigureAwait(false);
    }

    /// <summary>
    /// The same 32-worker contention run over <see cref="BaseMemoryPool.Shared"/> itself — the literal
    /// process-wide singleton every TPM simulator test in this binary rents from, and the one instance a
    /// buffer-lifetime fault would have to corrupt to produce a cross-test aliasing symptom.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentRentersNeverAliasOverTheSharedHousePool()
    {
        await RunContentionAsync(BaseMemoryPool.Shared).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs <see cref="WorkerCount"/> concurrent rent/fill/verify/return workers over <paramref name="pool"/>,
    /// synchronized to a common start so their rent/return traffic overlaps from the first cycle. The start gate
    /// is an asynchronously awaited <see cref="TaskCompletionSource"/> rather than a blocking barrier: each
    /// worker registers its arrival and yields the thread it holds back to the pool while it waits, so the
    /// rendezvous never requires <see cref="WorkerCount"/> OS threads to be simultaneously resident — a
    /// precondition the suite's own 32-way parallelization otherwise starves. Each worker's rental gets a
    /// globally unique id (derived from its worker index and cycle, never a shared counter), is checked zeroed on
    /// rent, is filled with a pattern tiling that id, is held across a yield while every other worker is doing
    /// the same, and is re-verified octet-for-octet before returning.
    /// </summary>
    /// <param name="pool">The pool under contention.</param>
    private async Task RunContentionAsync(BaseMemoryPool pool)
    {
        var startGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrivedCount = 0;

        async Task RunWorkerAsync(int workerIndex)
        {
            if(Interlocked.Increment(ref arrivedCount) == WorkerCount)
            {
                startGate.SetResult();
            }

            await startGate.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            for(int cycle = 0; cycle < CyclesPerWorker; cycle++)
            {
                long rentalId = ((long)workerIndex * CyclesPerWorker) + cycle;
                int size = RentalSizesInOctets[(int)(rentalId % RentalSizesInOctets.Length)];

                using IMemoryOwner<byte> owner = pool.Rent(size);

                //Held as Memory<byte> rather than Span<byte> because a Span cannot be preserved across the
                //Task.Yield() below; a fresh Span is sliced from it on each side of the yield instead.
                Memory<byte> rentedMemory = owner.Memory[..size];

                if(!IsAllZero(rentedMemory.Span))
                {
                    Assert.Fail($"Rental {rentalId} (worker {workerIndex}, cycle {cycle}, size {size}) was not zeroed on rent.");
                }

                FillWithRentalPattern(rentedMemory.Span, rentalId);
                await Task.Yield();

                if(TryFindAliasingMismatch(rentedMemory.Span, rentalId, out long observedRentalId, out int mismatchOffset))
                {
                    Assert.Fail(
                        $"Aliasing at byte offset {mismatchOffset} of rental {rentalId} (worker {workerIndex}, cycle {cycle}, size {size}): " +
                        $"expected rental {rentalId}'s own pattern but read rental {observedRentalId}'s pattern instead " +
                        "-- a double rent or a use-after-return.");
                }
            }
        }

        var workers = new Task[WorkerCount];
        for(int workerIndex = 0; workerIndex < WorkerCount; workerIndex++)
        {
            int capturedWorkerIndex = workerIndex;
            workers[workerIndex] = Task.Run(() => RunWorkerAsync(capturedWorkerIndex), TestContext.CancellationToken);
        }

        await Task.WhenAll(workers).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reports whether every octet of <paramref name="span"/> is zero.</summary>
    /// <param name="span">The span to check.</param>
    /// <returns><see langword="true"/> if every octet is zero.</returns>
    private static bool IsAllZero(ReadOnlySpan<byte> span)
    {
        foreach(byte value in span)
        {
            if(value != 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Fills <paramref name="span"/> by tiling <paramref name="rentalId"/>'s little-endian octets across it.</summary>
    /// <param name="span">The rented storage to fill.</param>
    /// <param name="rentalId">The rental's unique id.</param>
    private static void FillWithRentalPattern(Span<byte> span, long rentalId)
    {
        Span<byte> idOctets = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(idOctets, rentalId);

        for(int offset = 0; offset < span.Length; offset += idOctets.Length)
        {
            idOctets.CopyTo(span[offset..]);
        }
    }

    /// <summary>Checks every 8-octet tile of <paramref name="span"/> against <paramref name="expectedRentalId"/>'s own pattern, decoding the foreign id at the first mismatch.</summary>
    /// <param name="span">The rented storage to verify.</param>
    /// <param name="expectedRentalId">The id this rental filled the storage with.</param>
    /// <param name="observedRentalId">The foreign rental id decoded at the mismatch, or zero when none is found.</param>
    /// <param name="mismatchOffset">The byte offset of the first mismatching tile, or -1 when none is found.</param>
    /// <returns><see langword="true"/> if a mismatching tile was found.</returns>
    private static bool TryFindAliasingMismatch(ReadOnlySpan<byte> span, long expectedRentalId, out long observedRentalId, out int mismatchOffset)
    {
        for(int offset = 0; offset < span.Length; offset += sizeof(long))
        {
            long tileValue = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(offset, sizeof(long)));
            if(tileValue != expectedRentalId)
            {
                observedRentalId = tileValue;
                mismatchOffset = offset;

                return true;
            }
        }

        observedRentalId = 0;
        mismatchOffset = -1;

        return false;
    }
}
