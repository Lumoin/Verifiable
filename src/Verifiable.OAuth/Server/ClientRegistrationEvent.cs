using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A registration notification containing an immutable projection and event identity.
/// Concurrent emissions have independent identities and may arrive out of revision order.
/// Subscribers use the tenant, client identifier and revision to reject stale cache updates.
/// </summary>
[DebuggerDisplay("{GetType().Name,nq} ClientId={ClientId} TenantHandle={TenantHandle}")]
public abstract record ClientRegistrationEvent
{
    /// <summary>The unique numeric identifier of this emission within its instance-scoped event stream.</summary>
    public required long EventId { get; init; }


    /// <summary>The immutable committed client data; safe to retain after the request ends.</summary>
    public required ClientRegistrationProjection Projection { get; init; }


    /// <summary>The client identifier selected from the projection.</summary>
    public string ClientId => Projection.ClientId;


    /// <summary>The tenant identifier selected from the projection.</summary>
    public TenantId TenantId => Projection.TenantId;


    /// <summary>The tenant handle selected from the projection; the value diagnostics built from this event show.</summary>
    public TenantHandle? TenantHandle => Projection.TenantHandle;


    /// <summary>The registration revision selected from the projection; capability signals identify their source revision.</summary>
    public long Revision => Projection.Revision;


    /// <summary>The UTC instant after commitment at which this notification was created.</summary>
    public required DateTimeOffset OccurredAt { get; init; }
}


/// <summary>
/// A notification of a committed registration. The required store receives the management
/// credential; optional observers receive only the projection under
/// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">section 4.1</see>.
/// The client-information response carries the credential under
/// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-3">RFC 7592 section 3</see>.
/// </summary>
public sealed record ClientRegistered: ClientRegistrationEvent;


/// <summary>A notification of a committed replacement, including its immutable prior projection.</summary>
public sealed record ClientUpdated: ClientRegistrationEvent
{
    /// <summary>The selected data and revision read before the conditional replacement.</summary>
    public required ClientRegistrationProjection Previous { get; init; }
}


/// <summary>
/// A notification after conditional removal from the authoritative store. Its tombstone revision
/// is the atomically removed record's final revision plus one. Consumers retain that revision
/// when removing cached data so delayed updates cannot repopulate the deleted entry.
/// </summary>
public sealed record ClientDeregistered: ClientRegistrationEvent
{
    /// <summary>The application-supplied reason, excluding credentials and request content.</summary>
    public required string Reason { get; init; }
}


/// <summary>
/// A capability grant signal requiring an application effect before reachability changes.
/// The application updates its synchronized registration and granted set, and its capability
/// resolver reads that set on each request. Emission itself changes no registration or wiring.
/// </summary>
public sealed record CapabilityGranted: ClientRegistrationEvent
{
    /// <summary>The capability the application is asked to activate.</summary>
    public required CapabilityIdentifier Capability { get; init; }
}


/// <summary>
/// A capability revoke signal requiring an application effect before reachability changes.
/// The application removes the capability from its synchronized granted set and ensures its
/// resolver reads that set on subsequent requests. Observer delivery is best effort.
/// </summary>
public sealed record CapabilityRevoked: ClientRegistrationEvent
{
    /// <summary>The capability the application is asked to deactivate.</summary>
    public required CapabilityIdentifier Capability { get; init; }


    /// <summary>The application-supplied reason, excluding credentials and request content.</summary>
    public required string Reason { get; init; }
}


/// <summary>
/// Inspection of one optional observer's exception after an event has been emitted.
/// The payload identifies the immutable event and exception; it does not include the observer.
/// InspectAsync receives a detached, empty context. The complete diagnostic inputs contain only
/// the selected projection and event identity, this stage and the exception: never the incoming
/// request, its headers or body, a live registration object or the management bearer.
/// Diagnostic exceptions at this stage are isolated so a committed operation remains successful.
/// </summary>
/// <param name="Event">The immutable notification whose observer failed.</param>
/// <param name="Exception">The observer's exception, intended for protected application diagnostics.</param>
public sealed record RegistrationObserverFailureStage(
    ClientRegistrationEvent Event, Exception Exception): InspectionStage;
