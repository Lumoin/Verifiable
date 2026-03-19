namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A minimal <see cref="IObserver{T}"/> that collects received values into a
/// thread-safe buffer. Use in tests to observe <see cref="IObservable{T}"/>
/// streams without depending on <c>System.Reactive</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="OnNext"/> may be called from any thread — library event streams
/// make no promise about which thread emits, and some streams (such as the
/// process-global crypto events) receive emissions from multiple threads
/// concurrently, including finaliser threads cleaning up sensitive memory and
/// parallel test threads using the same global subject.
/// </para>
/// <para>
/// <see cref="Received"/> returns a snapshot array, not a live reference. Each
/// read produces an independent array safe to enumerate regardless of concurrent
/// writes. Tests that want multiple snapshots call <see cref="Received"/>
/// multiple times.
/// </para>
/// </remarks>
internal sealed class TestObserver<T>: IObserver<T>
{
    private readonly Lock gate = new();

    private readonly List<T> received = [];

    private readonly Action<T>? onNext;


    /// <summary>
    /// Initializes a <see cref="TestObserver{T}"/> that collects values into
    /// the internal buffer and optionally calls <paramref name="onNext"/>.
    /// </summary>
    public TestObserver(Action<T>? onNext = null)
    {
        this.onNext = onNext;
    }


    /// <summary>
    /// A snapshot of all values received via <see cref="OnNext"/> up to this
    /// moment. Each read returns a fresh array that is safe to enumerate
    /// concurrently with further emissions.
    /// </summary>
    public IReadOnlyList<T> Received
    {
        get
        {
            lock(gate)
            {
                return received.ToArray();
            }
        }
    }


    /// <inheritdoc/>
    public void OnNext(T value)
    {
        lock(gate)
        {
            received.Add(value);
        }

        onNext?.Invoke(value);
    }


    /// <inheritdoc/>
    public void OnError(Exception error) { }


    /// <inheritdoc/>
    public void OnCompleted() { }
}
