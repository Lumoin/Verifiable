using System;
using System.Collections.Generic;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A minimal <see cref="IObserver{T}"/> that collects received values into a list.
/// Use in tests to observe <see cref="System.IObservable{T}"/> streams without
/// depending on <c>System.Reactive</c>.
/// </summary>
internal sealed class TestObserver<T>: IObserver<T>
{
    private readonly Action<T>? onNext;

    /// <summary>All values received via <see cref="OnNext"/>.</summary>
    public List<T> Received { get; } = [];

    /// <summary>
    /// Initializes a <see cref="TestObserver{T}"/> that collects values into
    /// <see cref="Received"/> and optionally calls <paramref name="onNext"/>.
    /// </summary>
    public TestObserver(Action<T>? onNext = null)
    {
        this.onNext = onNext;
    }

    /// <inheritdoc/>
    public void OnNext(T value)
    {
        Received.Add(value);
        onNext?.Invoke(value);
    }

    /// <inheritdoc/>
    public void OnError(Exception error) { }

    /// <inheritdoc/>
    public void OnCompleted() { }
}