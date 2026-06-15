using Verifiable.Core;

namespace Verifiable.Vcalm;

/// <summary>
/// Resolves the W3C VCALM 1.0 §3.7.4 protocols map for a §3.7.1 interaction id — the
/// protocol identifier → initiation URL pairs the coordinator advertises for that interaction. The
/// coordinator owns the mapping (which §3.6 exchange / §3.7.5 inviteRequest endpoint / OID4VP-OID4VCI
/// entry an interaction bootstraps into), so this is its policy seam. Required when the
/// <see cref="WellKnownVcalmCapabilities.VcalmCoordinator"/> capability is allowed — without it the
/// §3.7.4 endpoint cannot answer (fail-closed; the route does not materialize). A <see langword="null"/>
/// result is the §3.7.4 404 (unknown interaction).
/// </summary>
/// <remarks>
/// §3.7.4: the protocols response "enables protocol execution to be delegated to third-party service
/// providers through the HTTPS domain trust model" — the coordinator MAY point an interaction's vcapi /
/// inviteRequest URL at a partner origin. The library composes the JSON / HTML §3.7.4 response from the
/// map this seam returns; it does not own which protocols an interaction supports.
/// </remarks>
/// <param name="interactionId">The §3.7.1 <c>{localInteractionId}</c> the interaction URL addresses.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The §3.7.4 protocols map, or <see langword="null"/> when no interaction exists for the id.</returns>
public delegate ValueTask<VcalmInteractionProtocols?> ResolveVcalmInteractionProtocolsDelegate(
    string interactionId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a W3C VCALM 1.0 §3.7.5 inviteRequest body into the neutral <see cref="VcalmInviteRequest"/>.
/// The default <c>System.Text.Json</c> implementation lives in <c>Verifiable.Json</c> and is wired by
/// the application — the <c>Verifiable.Vcalm</c> serialization firewall keeps STJ out of the library.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object, omits the <c>url</c>, or carries a top-level
/// member the endpoint does not recognize is returned as the corresponding
/// <see cref="VcalmParseFailure"/> rather than thrown.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmInviteRequest?> ParseVcalmInviteRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Records a W3C VCALM 1.0 §3.7.5 inviteRequest the coordinator accepted, keyed by the
/// <c>{localInviteId}</c> path segment it was POSTed to, so the coordinator can later correlate the
/// individual's interaction. Optional — when unwired the §3.7.5 endpoint still validates and accepts the
/// invitation (returns 200) but the coordinator does not retain it. The application owns the invite
/// store behind this seam.
/// </summary>
/// <param name="inviteId">The §3.7.5 <c>{localInviteId}</c> the invitation was POSTed to.</param>
/// <param name="invite">The parsed inviteRequest body.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask StoreVcalmInviteRequestDelegate(
    string inviteId,
    VcalmInviteRequest invite,
    ExchangeContext context,
    CancellationToken cancellationToken);
