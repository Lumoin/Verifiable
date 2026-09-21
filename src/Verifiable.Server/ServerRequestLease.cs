namespace Verifiable.Server;

/// <summary>A validated request view and its exactly-once release of the serving owner's admission count.</summary>
public sealed class ServerRequestLease: IDisposable
{
    /// <summary>The pending release callback; this field is an Interlocked target for exactly-once lease release.</summary>
    private Action? release;


    /// <summary>The fixed view of integration seams, registry, configuration and executor for this request.</summary>
    /// <remarks>Disposing this view disposes the serving owner; disposing the lease only releases its request count.</remarks>
    public EndpointServer Server { get; }


    /// <summary>Associates captured wiring with the serving owner's release callback.</summary>
    /// <param name="server">The captured wiring view.</param>
    /// <param name="release">The owner's admission-count release.</param>
    internal ServerRequestLease(EndpointServer server, Action release)
    {
        Server = server;
        this.release = release;
    }


    /// <summary>Releases admission once so an alteration can proceed after the last active request.</summary>
    public void Dispose()
    {
        Interlocked.Exchange(ref release, null)?.Invoke();
    }
}
