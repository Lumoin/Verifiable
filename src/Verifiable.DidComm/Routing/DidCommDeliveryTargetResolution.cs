using System.Collections.Generic;

namespace Verifiable.DidComm.Routing;

/// <summary>
/// The outcome of resolving a recipient's DIDComm delivery options, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#service-endpoint">DIDComm Messaging v2.1 §Service Endpoint</see>.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="DidCommServiceEndpointExtensions.ResolveDeliveryTargetsAsync"/>. <see cref="Targets"/>
/// carries ONLY dispatchable endpoints, so an empty list always means "nothing to send to" — a caller can index
/// <c>Targets[0]</c> for failover without a separate check. A declared Queue Transport
/// (<c>didcomm:transport/queue</c>) contributes no entry to <see cref="Targets"/>: the Return-Route and Queue
/// Transport extension defines it as "a special form of transport where messages are held at the sender for
/// pickup by the recipient"
/// (<see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">Return-Route and Queue Transport Extension</see>
/// §Queue Transport) — a hold-at-sender marker, not a destination — so it is reported separately via
/// <see cref="DeclaresQueueTransport"/> instead of being silently dropped or masquerading as a target.
/// </para>
/// <para>
/// This library only REPORTS the declaration: holding messages at the sender and matching a later pickup to
/// the connection is the application's job, the same LIBRARY vs APPLICATION boundary
/// <see cref="Verifiable.DidComm.ReturnRoute.DidCommReturnRouteExtensions"/> documents for the
/// <c>return_route</c> header.
/// </para>
/// </remarks>
public sealed class DidCommDeliveryTargetResolution
{
    internal DidCommDeliveryTargetResolution(IReadOnlyList<DidCommDeliveryTarget> targets, bool declaresQueueTransport)
    {
        Targets = targets;
        DeclaresQueueTransport = declaresQueueTransport;
    }


    /// <summary>
    /// The dispatchable delivery targets, in the DID document's preference order (for failover). Empty when
    /// none resolve, including when the only declared <c>didcomm/v2</c> endpoint is a Queue Transport.
    /// </summary>
    public IReadOnlyList<DidCommDeliveryTarget> Targets { get; }

    /// <summary>
    /// Whether any <c>didcomm/v2</c> service endpoint — the recipient's own, or a mediator's resolved via the
    /// DID-uri indirection — declared the Queue Transport URI (<c>didcomm:transport/queue</c>).
    /// </summary>
    public bool DeclaresQueueTransport { get; }
}
