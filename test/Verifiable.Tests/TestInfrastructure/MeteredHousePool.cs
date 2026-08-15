using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Threading;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A genuine <see cref="BaseMemoryPool"/> constructed over its own <see cref="Meter"/>, with a
/// <see cref="MeterListener"/> reading the pool's own rent and return counters — the accounting
/// instrument that replaced the pre-flip <c>MemoryPool&lt;byte&gt;</c> decorators, which the sealed house
/// pool type cannot admit. Because <see cref="Pool"/> IS the house pool rather than a wrapper imitating
/// one, every rental carries the house guarantees themselves — exact length, zero on return, canary
/// overrun detection — and the accounting observes the pool's own telemetry instead of interposing on it.
/// </summary>
/// <remarks>
/// Each instance creates a uniquely named <see cref="Meter"/> and enables measurement events only for
/// instruments published by that meter, so concurrently running tests each observe exactly their own
/// pool. Rent measurements carry the pool's <c>bufferSize</c> tag, which
/// <see cref="RentedCountOfSize"/> aggregates by; return measurements carry no size, so disposal
/// evidence is the balance: <see cref="OutstandingCount"/> reaching the expected residue proves every
/// other rented carrier came back.
/// </remarks>
internal sealed class MeteredHousePool: IDisposable
{
    /// <summary>The counter name the pool publishes each successful rent under.</summary>
    private const string RentCounterName = "Lumoin.BaseMemoryPool.RentOperationsTotal";

    /// <summary>The counter name the pool publishes each return under.</summary>
    private const string ReturnCounterName = "Lumoin.BaseMemoryPool.ReturnOperationsTotal";

    /// <summary>The tag name the rent counter carries the requested buffer size under.</summary>
    private const string BufferSizeTagName = "bufferSize";

    /// <summary>The meter the observed pool publishes its instruments on.</summary>
    private Meter Meter { get; }

    /// <summary>The listener reading the pool's counters.</summary>
    private MeterListener Listener { get; }

    /// <summary>The gate serializing access to <see cref="rentedBySize"/>.</summary>
    private Lock SizeGate { get; } = new();

    /// <summary>How many carriers have been rented, per requested size.</summary>
    private readonly Dictionary<int, long> rentedBySize = [];

    /// <summary>How many carriers have been rented in total.</summary>
    private long rentedCount;

    /// <summary>How many carriers have been returned in total.</summary>
    private long returnedCount;


    /// <summary>The observed house pool; pass this wherever a surface takes a <see cref="BaseMemoryPool"/>.</summary>
    public BaseMemoryPool Pool { get; }

    /// <summary>
    /// An optional hook invoked with the running rent total on each rent, synchronously on the renting
    /// thread from inside the pool's own counter publication — the injection point that replaced the
    /// pre-flip failing-pool decorator: a hook that throws makes that rent ordinal refuse, propagating out
    /// of <c>Rent</c> exactly where the decorator's refusal used to surface. The refused rent has already
    /// been counted when the hook runs, so an accounting assertion over an injected refusal expects
    /// <c>ReturnedCount == RentedCount - 1</c>.
    /// </summary>
    public Action<long>? OnRent { get; set; }

    /// <summary>How many carriers the pool has handed out.</summary>
    public long RentedCount => Volatile.Read(ref rentedCount);

    /// <summary>How many of the handed-out carriers have been disposed back to the pool.</summary>
    public long ReturnedCount => Volatile.Read(ref returnedCount);

    /// <summary>How many carriers are still outstanding.</summary>
    public long OutstandingCount => RentedCount - ReturnedCount;


    /// <summary>Creates the observed pool and starts listening to its counters.</summary>
    public MeteredHousePool()
    {
        Meter = new Meter($"verifiable-tests-housepool-{Guid.NewGuid():N}");
        Listener = new MeterListener();
        Listener.InstrumentPublished = (instrument, listener) =>
        {
            if(ReferenceEquals(instrument.Meter, Meter))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        Listener.SetMeasurementEventCallback<long>(OnMeasurement);
        Listener.Start();
        Pool = new BaseMemoryPool(Meter);
    }


    /// <summary>How many carriers of exactly the given requested size the pool has handed out.</summary>
    /// <param name="size">The requested rental size in octets.</param>
    /// <returns>The rent count for that size.</returns>
    public long RentedCountOfSize(int size)
    {
        lock(SizeGate)
        {
            return rentedBySize.TryGetValue(size, out long count) ? count : 0;
        }
    }


    /// <summary>Disposes the pool, the listener and the meter, in that order.</summary>
    public void Dispose()
    {
        Pool.Dispose();
        Listener.Dispose();
        Meter.Dispose();
    }


    /// <summary>Accumulates one rent or return measurement into the counts.</summary>
    /// <param name="instrument">The instrument the measurement came from.</param>
    /// <param name="value">The measured increment.</param>
    /// <param name="tags">The measurement's tags; a rent carries the requested size.</param>
    /// <param name="state">Unused listener state.</param>
    private void OnMeasurement(Instrument instrument, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
    {
        if(string.Equals(instrument.Name, RentCounterName, StringComparison.Ordinal))
        {
            long total = Interlocked.Add(ref rentedCount, value);
            foreach(KeyValuePair<string, object?> tag in tags)
            {
                if(string.Equals(tag.Key, BufferSizeTagName, StringComparison.Ordinal) && tag.Value is int size)
                {
                    lock(SizeGate)
                    {
                        rentedBySize[size] = rentedBySize.TryGetValue(size, out long count) ? count + value : value;
                    }

                    break;
                }
            }

            OnRent?.Invoke(total);
        }
        else if(string.Equals(instrument.Name, ReturnCounterName, StringComparison.Ordinal))
        {
            _ = Interlocked.Add(ref returnedCount, value);
        }
    }
}
