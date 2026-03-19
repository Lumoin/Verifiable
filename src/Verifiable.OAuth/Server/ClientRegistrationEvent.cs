using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Base record for all client registration lifecycle events emitted via
/// <see cref="AuthorizationServer.Events"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every event carries the <see cref="ClientId"/>, <see cref="TenantId"/>,
/// <see cref="OccurredAt"/>, and <see cref="Context"/> so subscribers can filter
/// and correlate without pattern-matching the derived type.
/// </para>
/// <para>
/// <see cref="Context"/> is the same parameter bag passed to all server delegates —
/// it carries request-scoped data (resolved tenant identifier, trace context, remote IP)
/// that the application chose to surface when the event was raised.
/// </para>
/// </remarks>
[DebuggerDisplay("{GetType().Name,nq} ClientId={ClientId} TenantId={TenantId}")]
public abstract record ClientRegistrationEvent
{
    /// <summary>The client identifier of the registration that changed.</summary>
    public required string ClientId { get; init; }

    /// <summary>The tenant identifier of the registration that changed.</summary>
    public required TenantId TenantId { get; init; }

    /// <summary>The UTC instant at which the event occurred.</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>
    /// Application-defined context from the request that triggered the event.
    /// Contains whatever the application placed in the context parameter bag.
    /// </summary>
    public required RequestContext Context { get; init; }
}


/// <summary>
/// Emitted when a new <see cref="ClientRegistration"/> is created.
/// Subscribers should make the registration's endpoints immediately reachable.
/// </summary>
[DebuggerDisplay("ClientRegistered ClientId={ClientId} TenantId={TenantId}")]
public sealed record ClientRegistered: ClientRegistrationEvent
{
    /// <summary>The newly created registration.</summary>
    public required ClientRegistration Registration { get; init; }
}


/// <summary>
/// Emitted when an existing <see cref="ClientRegistration"/> is replaced.
/// Subscribers should refresh any cached data derived from the registration.
/// </summary>
[DebuggerDisplay("ClientUpdated ClientId={ClientId} TenantId={TenantId}")]
public sealed record ClientUpdated: ClientRegistrationEvent
{
    /// <summary>The registration before the update.</summary>
    public required ClientRegistration Previous { get; init; }

    /// <summary>The registration after the update.</summary>
    public required ClientRegistration Current { get; init; }
}


/// <summary>
/// Emitted when a <see cref="ClientRegistration"/> is removed.
/// Subscribers should make the registration's endpoints immediately unreachable
/// and evict any cached state for this client.
/// </summary>
[DebuggerDisplay("ClientDeregistered ClientId={ClientId} TenantId={TenantId}")]
public sealed record ClientDeregistered: ClientRegistrationEvent
{
    /// <summary>
    /// Human-readable reason for deregistration, suitable for audit logging.
    /// Not forwarded to any external party.
    /// </summary>
    public required string Reason { get; init; }
}


/// <summary>
/// Emitted when a capability is added to an existing <see cref="ClientRegistration"/>.
/// Subscribers should activate the corresponding endpoint for this client's tenant.
/// </summary>
[DebuggerDisplay("CapabilityGranted ClientId={ClientId} Capability={Capability}")]
public sealed record CapabilityGranted: ClientRegistrationEvent
{
    /// <summary>The capability that was granted.</summary>
    public required ServerCapabilityName Capability { get; init; }
}


/// <summary>
/// Emitted when a capability is removed from an existing <see cref="ClientRegistration"/>.
/// Subscribers should deactivate the corresponding endpoint for this client's tenant.
/// </summary>
[DebuggerDisplay("CapabilityRevoked ClientId={ClientId} Capability={Capability}")]
public sealed record CapabilityRevoked: ClientRegistrationEvent
{
    /// <summary>The capability that was revoked.</summary>
    public required ServerCapabilityName Capability { get; init; }

    /// <summary>
    /// Human-readable reason for revocation, suitable for audit logging.
    /// Not forwarded to any external party.
    /// </summary>
    public required string Reason { get; init; }
}
