using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Loads a registration from the backing store by tenant identifier.
/// </summary>
/// <remarks>
/// <para>
/// Called at the start of every request after the dispatcher has resolved the tenant.
/// The implementation looks up the registration in whatever per-tenant store it
/// maintains and returns its host-generic <see cref="IRegistrationRecord"/> projection;
/// protocol families return their own richer record type.
/// </para>
/// <para>
/// Return <see langword="null"/> when the registration is not found — the dispatcher
/// responds 404 without leaking whether the identifier exists. The
/// <paramref name="context"/> carries request-scoped data the implementation can read
/// for finer-grained decisions (region routing, feature flags).
/// </para>
/// </remarks>
public delegate ValueTask<IRegistrationRecord?> LoadRegistrationDelegate(
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Persists a <see cref="FlowState"/> and its step count to durable storage under the
/// given correlation key, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// Called after every successful PDA transition. Must be idempotent. The
/// <paramref name="tenantId"/> scopes the storage write so flow state from one tenant
/// cannot be loaded under another; the state record itself does not carry tenant —
/// tenant isolation is enforced at this storage boundary, not at the state layer.
/// </para>
/// <para>
/// The <paramref name="correlationKey"/> is the protocol handle that will arrive at the
/// next endpoint. The application stores the state under this key so
/// <see cref="LoadServerFlowStateDelegate"/> can retrieve it directly without any
/// secondary index.
/// </para>
/// </remarks>
public delegate ValueTask SaveServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
    FlowState state,
    int stepCount,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Deletes a saved flow state, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// Required by <see cref="ServerIntegration.Validate"/>. Implementations are
/// idempotent: a delete against an unknown <paramref name="correlationKey"/> is a no-op,
/// not an error. The dispatcher relies on this for clean retry semantics.
/// </para>
/// <para>
/// OAuth code replay and refresh reuse call this with the claimed live descendant's internal
/// flow id after walking retained rotation records. Rotation itself retires its presented
/// record through SaveFlowStateAsync and keeps its index until ExpiresAt. This supports
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
/// "SHOULD revoke (when possible)" even when audited-token revocation is unavailable.
/// </para>
/// </remarks>
public delegate ValueTask DeleteServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a <see cref="FlowState"/> and step count from durable storage by correlation
/// key, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// The <paramref name="tenantId"/> scopes the storage read so a load under one tenant
/// never returns a record persisted under another. The
/// <paramref name="correlationKey"/> is whatever the protocol's natural handle is at this
/// endpoint. Returns <c>(null, 0)</c> when no state is found for the given pair.
/// </para>
/// </remarks>
public delegate ValueTask<(FlowState? State, int StepCount)> LoadServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Atomically claims one step of a flow before an irreversible effect — minting a token,
/// consuming a pushed-authorization <c>request_uri</c> — runs, so that of any number of
/// concurrent callers holding the same <paramref name="correlationKey"/> at the same
/// <paramref name="expectedStepCount"/>, exactly one receives <see langword="true"/> and every
/// other receives <see langword="false"/>.
/// </summary>
/// <remarks>
/// <para>
/// Required. Called after every request-shaped verification has passed and before the
/// endpoint performs the effect that must happen at most once —
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
/// draft-16 §4.1.3</see>: "The authorization server MUST return an access token only once
/// for a given authorization code." A caller whose claim returns <see langword="false"/>
/// treats the flow as already consumed and answers accordingly (an authorization-code grant
/// answers <c>invalid_grant</c>); it must not perform the effect or step the PDA.
/// </para>
/// <para>
/// The unconditional <see cref="SaveServerFlowStateDelegate"/> that follows a PDA step is not
/// itself a concurrency control — two concurrent readers of the same
/// <paramref name="expectedStepCount"/> would both pass verification and both save, the second
/// silently clobbering the first. This delegate is the compare-and-claim that makes
/// exactly-once hold under concurrency: an in-memory implementation is a single atomic
/// operation over a <c>(correlationKey, expectedStepCount)</c> pair (e.g.
/// <see cref="System.Collections.Concurrent.ConcurrentDictionary{TKey,TValue}.TryAdd"/>); a
/// distributed store implements it as a conditional write — a compare-and-swap or an
/// <c>UPDATE ... WHERE step_count = @expectedStepCount</c> — against the same version/step
/// column <see cref="LoadServerFlowStateDelegate"/> read and <see cref="SaveServerFlowStateDelegate"/>
/// writes, so the claim and the eventual save agree on what "this step" means without the
/// claim itself mutating the persisted state or step count.
/// </para>
/// <para>
/// Refresh rotation and family revocation share this seam. Revocation claims the loaded live
/// refresh step before deletion; a failed claim permits one reload to follow a retired successor.
/// Deletion must not permit a stale caller to claim the same consumed step again: implementations
/// retain the claim or atomically reject absent and obsolete flow versions.
/// </para>
/// </remarks>
/// <param name="tenantId">The tenant the flow belongs to.</param>
/// <param name="correlationKey">The internal flow identifier being claimed.</param>
/// <param name="expectedStepCount">
/// The step count the caller loaded the flow at — the same value
/// <see cref="LoadServerFlowStateDelegate"/> returned. The claim succeeds only for the first
/// caller presenting this exact value for this <paramref name="correlationKey"/>.
/// </param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<bool> ClaimServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
    int expectedStepCount,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves the dispatch host's issuer URI for downstream emitters that embed an
/// issuer-derived value. Hoisted to the host-generic seam set because the dispatch
/// loop resolves the issuer for every matched request before any handler runs.
/// </summary>
/// <remarks>
/// Return <see langword="null"/> when no issuer is resolved for the request; the host
/// leaves the per-request issuer unset and downstream emitters fall back to whatever the
/// skin placed on the context.
/// </remarks>
public delegate ValueTask<Uri?> ResolveServerIssuerDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves and stamps the per-request policy values for the loaded registration on the
/// <see cref="ExchangeContext"/> at dispatch entry, before any matcher runs.
/// </summary>
/// <remarks>
/// Hoisted to the host-generic seam set because the dispatch loop invokes it
/// unconditionally for every matched request. The host treats it as an opaque
/// pre-handler hook over the registration; a protocol family supplies the policy
/// vocabulary it stamps onto the context.
/// </remarks>
public delegate ValueTask ResolveServerPolicyDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
