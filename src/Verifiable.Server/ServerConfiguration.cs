using System.Collections.Immutable;
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
/// neutral configuration carries nothing any single family owns. The optional capability
/// declaration is likewise an immutable set: it scopes validation and dispatch to the capabilities a
/// composition serves without naming any family's wiring.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerConfiguration EndpointBuilders={EndpointBuilders.Count} DeclaredCapabilities={DeclaredCapabilities?.Count}")]
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
    /// The capabilities this composition serves, or <see langword="null"/> when the composition
    /// declares nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without a declaration, validation requires every dependency a protocol family can need and
    /// dispatch filters endpoint candidates by the per-request capability set alone. With a
    /// declaration, validation requires only the dependencies of the declared capabilities, reports a
    /// missing one as a <see cref="CompositionDependencyFailure"/> inside a
    /// <see cref="CompositionDependencyException"/>, and dispatch builds the endpoint chain only from
    /// candidates whose capability the declaration names, so no request reaches a handler whose
    /// dependencies validation did not check.
    /// </para>
    /// <para>
    /// An empty declaration is refused unless <see cref="IsMaintenanceMode"/> is explicitly true, and
    /// then every request receives the ordinary unmatched-endpoint response. The declaration filters
    /// endpoint candidates only: the per-request capability set a registration resolves and the
    /// builders' own registration checks are unchanged by it.
    /// </para>
    /// <para>
    /// The stored set compares its members with <see cref="CapabilityIdentifier"/>'s own ordinal URN
    /// equality whatever comparer the supplied set carries, so validation, which enumerates the
    /// members, and dispatch, which asks the set whether it names a candidate's capability, agree on
    /// exactly the same capabilities. A member that is the default <see cref="CapabilityIdentifier"/>
    /// names no capability and is refused by validation with the named
    /// <see cref="InvalidOperationException"/>.
    /// </para>
    /// <para>
    /// Helpers an application calls outside dispatch are not scoped by the declaration. Bearer-token
    /// validation reads the codec decoder, the JWT deserializers and the verification key resolver, so
    /// a composition that calls it declares a capability requiring subject resolution, the grant-family
    /// loader, both key resolvers and every codec delegate: any capability other than discovery and the
    /// key set.
    /// </para>
    /// </remarks>
    public ImmutableHashSet<CapabilityIdentifier>? DeclaredCapabilities
    {
        get;
        init => field = value?.WithComparer(EqualityComparer<CapabilityIdentifier>.Default);
    }


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
