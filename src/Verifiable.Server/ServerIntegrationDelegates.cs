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
/// Deletes a previously-saved flow state, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// Required for protocol paths that rotate or invalidate state. Implementations are
/// idempotent: a delete against an unknown <paramref name="correlationKey"/> is a no-op,
/// not an error. The dispatcher relies on this for clean retry semantics.
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
