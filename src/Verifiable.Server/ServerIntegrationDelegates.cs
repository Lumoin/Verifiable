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
/// OAuth code replay and refresh reuse call this with the flow id of the grant's claimed live
/// refresh record, found by one grant read rather than by walking retained rotation records.
/// Rotation itself retires its presented record through SaveFlowStateAsync and keeps its index
/// until ExpiresAt. This supports
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
/// A claim of a <c>(tenant, correlationKey, expectedStepCount)</c> is retained apart from the record
/// <see cref="SaveServerFlowStateDelegate"/> writes: a later save of the same key, at the same step
/// or any other, never makes a claimed step claimable again. A caller may save before it claims —
/// the <c>jti</c> replay guard records a first presentation and then claims it, so a concurrent
/// presentation that lost the claim can still save the same record afterwards — and exactly one
/// caller still receives <see langword="true"/> only when the save cannot erase the claim. A store
/// that keeps the claim as a mark on the saved record, cleared or re-armed by the next save, breaks
/// this contract.
/// </para>
/// <para>
/// Refresh rotation and grant revocation share this seam. Revocation claims a grant's loaded
/// live refresh step before deletion; a failed claim permits one re-read of the grant to retry
/// whatever it still reports live. Deletion must not permit a stale caller to claim the same
/// consumed step again: implementations retain the claim or atomically reject absent and
/// obsolete flow versions.
/// </para>
/// <para>
/// The claim precedes the costly effects of a step, not only its irreversible ones. The one-time
/// step of a grant, an authorization code or a refresh token, is claimed before the issuance walk,
/// so a replayed or concurrently presented grant is refused after the request's verification and
/// before any token is signed, the subject resolved or a producer run, and a party holding an
/// already-spent grant cannot make the server pay the walk's cost by presenting it again.
/// <see cref="ReleaseServerFlowStateDelegate"/> is the inverse of a won claim for a walk that ends
/// before the step's first store write.
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
/// Makes one claimed step of a flow claimable again: the inverse of a
/// <see cref="ClaimServerFlowStateDelegate"/> call that returned <see langword="true"/>, for a
/// step whose walk ended before the step's first store write.
/// </summary>
/// <remarks>
/// <para>
/// Called only by the caller that won the claim of this
/// <c>(tenant, correlationKey, expectedStepCount)</c>, at most once per won claim, and only when the
/// issuance walk that follows the claim of an authorization code or a refresh token returned a
/// failure, threw or was cancelled before the step's first store write made by the library. The
/// release keeps a fault of the application's own seams during that walk from spending the client's
/// grant, so the same grant presented again can complete. Since the library releases at most once per
/// won claim, a store need not track which caller holds a mark.
/// </para>
/// <para>
/// The window is bounded by the library's first store write of the step; the library does not see
/// what the application's seams persist. The seams the walk calls (the token producers, the claim
/// contributors, the resolvers and the identifier seam) run again when a released grant is presented
/// again, so they keep no effect that a repeated walk would duplicate, or the application reconciles
/// such effects itself.
/// </para>
/// <para>
/// A walk ended by the request's cancellation is released as well, so the
/// <paramref name="cancellationToken"/> the library passes cannot be cancelled. The application bounds
/// its release inside this delegate, for example by its store's own timeout: a release that does not
/// complete holds the request, and with it the drain of an alteration that waits for the request.
/// </para>
/// <para>
/// When the walk threw, the walk's exception stays the request's fault and the release's exception is
/// recorded on the request's activity when one is being recorded; an application that needs every
/// release failure observes it inside this delegate. When the walk returned a failure, the release's
/// exception propagates as the request's fault.
/// </para>
/// <para>
/// The library does not retry a release, so a release that throws or times out leaves the store's
/// outcome to the store. A store that fails without removing its mark leaves the step claimed, so the
/// grant is spent and the server fails closed. A store whose release may remove the mark and then throw
/// documents that for its host, since the grant can then be presented again.
/// </para>
/// <para>
/// The release is required wherever the claim is: a host wires it on the same store as
/// <see cref="ClaimServerFlowStateDelegate"/>, and a store whose claim always succeeds releases as
/// a no-op.
/// </para>
/// <para>
/// From the step's first store write on, no release follows, whatever fails afterwards, the write
/// itself included. This is the library's own fail-closed rule: the write may have taken effect, and a
/// persisted record of the step, such as a refresh token born of the grant, may already be live.
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1
/// draft-16 Section 4.1.3</see> requires the denial of a second valid token request made with the same
/// code as "a previously successful token request"; the library reads a step whose record may be live
/// as used, whether or not the request that wrote it succeeded.
/// </para>
/// <para>
/// An in-memory store removes the claim mark (for example
/// <see cref="System.Collections.Concurrent.ConcurrentDictionary{TKey,TValue}.TryRemove(TKey, out TValue)"/>);
/// a distributed store deletes the conditional-write mark or reverts the compare-and-swap its
/// claim made. The release is idempotent: releasing a pair that is not claimed does nothing. The
/// store does not step, save or delete the flow record itself.
/// </para>
/// </remarks>
/// <param name="tenantId">The tenant the flow belongs to.</param>
/// <param name="correlationKey">The internal flow identifier whose claim is released.</param>
/// <param name="expectedStepCount">
/// The step count the caller claimed: the same value it passed to
/// <see cref="ClaimServerFlowStateDelegate"/>.
/// </param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask ReleaseServerFlowStateDelegate(
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
