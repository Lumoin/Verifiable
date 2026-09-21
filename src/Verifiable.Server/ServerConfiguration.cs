using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// An immutable snapshot of the dispatch host's protocol-neutral configuration:
/// the endpoint builders that contribute the endpoints each protocol flow supports.
/// </summary>
/// <remarks>
/// <para>
/// This snapshot is part of the complete wiring published by
/// <see cref="EndpointServer.RequestAlterationAsync"/>. The candidate replaces its configuration
/// together with integration seams and family registries. Admitted requests finish before the swap;
/// subsequent requests retain the published configuration through completion.
/// </para>
/// <para>
/// The builder set is itself immutable; this configuration is a value-shaped wrapper
/// around a reference to that set. Each protocol family carries its own family-scoped
/// configuration (token producers, claim issuers, action executors, cryptography) on
/// its family integration, registered through the host's integration registry — the
/// neutral configuration carries nothing any single family owns.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerConfiguration EndpointBuilders={EndpointBuilders.Count}")]
public sealed record ServerConfiguration
{
    /// <summary>
    /// An empty configuration carrying an empty builder set. Useful as a starting
    /// point for compositional construction:
    /// <c>ServerConfiguration.Empty.WithEndpointBuilders(...)</c>.
    /// </summary>
    public static ServerConfiguration Empty { get; } = new()
    {
        EndpointBuilders = EndpointBuilderSet.Empty
    };


    /// <summary>
    /// The endpoint-builder modules that contribute <see cref="ServerEndpoint"/>
    /// records when invoked against a registration. Membership is immutable; application state
    /// captured by builders remains shared and requires application synchronization.
    /// </summary>
    public required EndpointBuilderSet EndpointBuilders { get; init; }


    /// <summary>Explicitly permits an empty endpoint set during a maintenance deployment.</summary>
    public bool IsMaintenanceMode { get; init; }


    /// <summary>
    /// The maximum total hold for an arrival while queued alterations drain and publish.
    /// Defaults to five seconds; expiry emits an OAuth temporary refusal with Retry-After.
    /// An arrival is held only while the window closes within this bound; a drain that runs
    /// to its bound refuses arrivals whose admission hold expires.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive or exceeds one minute.</exception>
    public TimeSpan AdmissionWaitTimeout
    {
        get;
        init
        {
            ValidateTimeout(value, nameof(AdmissionWaitTimeout));
            field = value;
        }
    } = TimeSpan.FromSeconds(5);


    /// <summary>
    /// The maximum time a requested alteration waits for admitted requests to drain before
    /// abandoning every alteration queued in that window and reopening admission on the
    /// unchanged wiring. Defaults to five seconds.
    /// An arrival is held only while the window closes within AdmissionWaitTimeout; a drain
    /// that runs to its bound refuses arrivals whose admission hold expires.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive or exceeds one minute.</exception>
    public TimeSpan DrainTimeout
    {
        get;
        init
        {
            ValidateTimeout(value, nameof(DrainTimeout));
            field = value;
        }
    } = TimeSpan.FromSeconds(5);


    /// <summary>Checks both bounds before an alteration takes ownership of admission.</summary>
    internal void ValidatePolicy()
    {
        ValidateTimeout(AdmissionWaitTimeout, nameof(AdmissionWaitTimeout));
        ValidateTimeout(DrainTimeout, nameof(DrainTimeout));
    }


    /// <summary>Restricts timer inputs to the supported positive, at-most-one-minute interval.</summary>
    /// <param name="value">The proposed timeout.</param>
    /// <param name="member">The policy member named by the fault.</param>
    private static void ValidateTimeout(TimeSpan value, string member)
    {
        if(value <= TimeSpan.Zero || value > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(member, value, $"ServerConfiguration.{member} must be positive and at most one minute.");
        }
    }


    /// <summary>
    /// Returns a copy of this configuration with a different
    /// <see cref="EndpointBuilders"/> set. Convenience for non-destructive
    /// updates.
    /// </summary>
    /// <param name="builders">The replacement builder set.</param>
    /// <returns>A new <see cref="ServerConfiguration"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builders"/> is <see langword="null"/>.
    /// </exception>
    public ServerConfiguration WithEndpointBuilders(EndpointBuilderSet builders)
    {
        ArgumentNullException.ThrowIfNull(builders);

        return this with { EndpointBuilders = builders };
    }
}
