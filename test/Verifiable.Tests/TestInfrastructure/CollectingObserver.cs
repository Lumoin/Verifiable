namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An event observer that retains the notifications it is handed, so a test can inspect what a server announced:
/// the supplied list receives each notification in delivery order, and an optional action observes each one as it
/// arrives. Error and completion notifications add nothing to the list.
/// </summary>
/// <typeparam name="T">The notification type.</typeparam>
/// <param name="collected">The list used by the test to inspect notifications.</param>
/// <param name="observe">An optional synchronous observation of each notification.</param>
internal sealed class CollectingObserver<T>(List<T> collected, Action<T>? observe = null): IObserver<T>
{
    /// <summary>
    /// Records the delivered notification so the test can inspect its payload, then hands it to the optional
    /// observation.
    /// </summary>
    /// <param name="value">The delivered notification.</param>
    public void OnNext(T value)
    {
        collected.Add(value);
        observe?.Invoke(value);
    }


    /// <summary>
    /// Accepts an error notification without adding an entry to the test list.
    /// </summary>
    /// <param name="error">The reported error.</param>
    public void OnError(Exception error)
    {
    }


    /// <summary>
    /// Accepts completion without adding an entry to the test list.
    /// </summary>
    public void OnCompleted()
    {
    }
}
