using System.Diagnostics;
using System.Text;

namespace Verifiable.Server;

/// <summary>
/// Groups the host-generic integration delegates the dispatch host asks the
/// application to resolve: which signal identifies a tenant, where flow state is
/// persisted, which capabilities are active, where endpoints are reachable, and the
/// per-request inspection, policy, and issuer hooks the dispatch loop runs for every
/// request.
/// </summary>
/// <remarks>
/// <para>
/// Every delegate on this base has the same shape: the host has a question, the
/// application supplies an answer. None of them perform protocol logic — that lives in
/// the protocol family's endpoints. A protocol family derives a richer integration from
/// this base, adding its own protocol seams; the dispatch host depends only on this
/// host-generic projection.
/// </para>
/// <para>
/// The seams are set at construction and altered while serving through the requested,
/// drained, candidate-validated alteration operation described in
/// <see href="../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration</see>.
/// A serving setter throws a named configuration fault. Candidate validation names missing
/// delegates before a complete wiring copy is published. Delegates share application resources;
/// the application owns their synchronization and retirement after requests drain.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerIntegration Validated={IsValidated}")]
public class ServerIntegration: WiringComponent
{
    /// <summary>Resolves the response for an absent tenant registration; protocol families can preserve their authentication refusal rules.</summary>
    /// <param name="tenantId">The resolved tenant whose record is absent.</param>
    /// <param name="context">The admitted request context.</param>
    /// <param name="cancellationToken">Cancellation of response resolution.</param>
    public virtual ValueTask<ServerHttpResponse> ResolveMissingRegistrationAsync(
        Verifiable.Core.TenantId tenantId, Verifiable.Core.ExchangeContext context, CancellationToken cancellationToken)
    {

        return ValueTask.FromResult(ServerHttpResponse.NotFound());
    }


    /// <summary>
    /// Extracts the <see cref="Verifiable.Core.TenantId"/> from the inbound request.
    /// Required. Returning <see langword="null"/> indicates the request carries no
    /// identifiable tenant; the dispatcher responds 400 without invoking any further
    /// delegate.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ExtractTenantIdDelegate? ExtractTenantIdAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Loads a registration by tenant identifier. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// Resolves once per request unless the skin supplies context.Registration. Each request needs its own
    /// context and an immutable registration snapshot; the application synchronizes changes to its backing store.
    /// </para>
    /// </remarks>
    public LoadRegistrationDelegate? LoadRegistrationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Persists a <see cref="FlowState"/> under the internal <c>flowId</c> scoped by
    /// tenant. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// The drain quiesces requests, not persisted flows. Publish load, claim, delete, save and
    /// correlation operations together. The host must migrate or forward retained flow state
    /// before replacing its backend, and retire resources only after their users finish.
    /// </para>
    /// </remarks>
    public SaveServerFlowStateDelegate? SaveFlowStateAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Deletes a saved flow state, scoped by tenant. Required so token revocation can
    /// invalidate a claimed live refresh record even when audited-token revocation is unavailable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// The drain quiesces requests, not persisted flows. Publish load, claim, delete, save and
    /// correlation operations together. The host must migrate or forward retained flow state
    /// before replacing its backend, and retire resources only after their users finish.
    /// </para>
    /// </remarks>
    public DeleteServerFlowStateDelegate? DeleteFlowStateAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Loads a <see cref="FlowState"/> and step count by the internal <c>flowId</c>.
    /// Required. The key has already been resolved from any external handle by
    /// <see cref="ResolveCorrelationKeyAsync"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// The drain quiesces requests, not persisted flows. Publish load, claim, delete, save and
    /// correlation operations together. The host must migrate or forward retained flow state
    /// before replacing its backend, and retire resources only after their users finish.
    /// </para>
    /// </remarks>
    public LoadServerFlowStateDelegate? LoadFlowStateAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Atomically claims one step of a flow before an irreversible effect runs. Required.
    /// See <see cref="ClaimServerFlowStateDelegate"/> for the exactly-once contract and the
    /// distributed-store implementation guidance.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// The drain quiesces requests, not persisted flows. Publish load, claim, delete, save and
    /// correlation operations together. The host must migrate or forward retained flow state
    /// before replacing its backend, and retire resources only after their users finish.
    /// </para>
    /// </remarks>
    public ClaimServerFlowStateDelegate? ClaimFlowStateAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves an external correlation handle to the stable internal <c>flowId</c> used
    /// as the primary persistence key. Optional for flows where the external handle is
    /// the <c>flowId</c>; when <see langword="null"/> the external handle is used directly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// The drain quiesces requests, not persisted flows. Publish load, claim, delete, save and
    /// correlation operations together. The host must migrate or forward retained flow state
    /// before replacing its backend, and retire resources only after their users finish.
    /// </para>
    /// </remarks>
    public ResolveCorrelationKeyDelegate? ResolveCorrelationKeyAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the absolute URL at which a capability is reachable for a given
    /// registration in the current request. Required when the server emits metadata or
    /// tokens whose claims include endpoint URLs.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveEndpointUriDelegate? ResolveEndpointUriAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the per-request capability set active for a registration. Consulted once
    /// per request by <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/>; the
    /// returned set filters which builder-produced candidates land in the chain. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// Returns an immutable set for this request. Capability notifications affect later resolutions only when
    /// the application commits their state changes to the source this delegate reads.
    /// </para>
    /// </remarks>
    public ResolveCapabilitiesDelegate? ResolveCapabilitiesAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Invoked at each pipeline inspection stage (see <see cref="InspectionStage"/>).
    /// Required.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public InspectDelegate? InspectAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Generates an identifier for a stated <see cref="IdentifierPurpose"/>. Threaded
    /// through every wire-identifier and correlation-identifier generation site; Required.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public GenerateIdentifierDelegate? GenerateIdentifierAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves the host's issuer URI for the request. Optional; when
    /// <see langword="null"/> the dispatch loop uses its built-in fallback (the value the
    /// skin placed on the context).
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public ResolveServerIssuerDelegate? ResolveIssuerAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Resolves and stamps per-request policy values on the context at dispatch entry,
    /// before any matcher runs. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </para>
    /// <para>
    /// Runs once after registration resolution. The application supplies a coherent policy snapshot and
    /// keeps the mutable context exclusive to that request; structural validation cannot judge external policy.
    /// </para>
    /// </remarks>
    public ResolveServerPolicyDelegate? ResolvePolicyAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Materializes the client-data-dependent fields of a matched request's registration
    /// after routing has matched an endpoint, before that endpoint runs. Optional; when
    /// <see langword="null"/> dispatch proceeds with the loaded registration unchanged.
    /// </summary>
    /// <remarks>
    /// Set during construction or on an alteration candidate. A serving setter throws
    /// <see cref="InvalidOperationException"/> naming this member; use
    /// <see cref="EndpointServer.RequestAlterationAsync"/> to publish related changes together.
    /// Dispatch retains this operation and its dependencies from admission through completion.
    /// Delegate targets own synchronization of mutable application state.
    /// </remarks>
    public MaterializeRegistrationDelegate? MaterializeRegistrationAsync
    {
        get;
        set
        {
            lock(MutationLock)
            {
                EnsureMutable();
                field = value;
            }
        }
    }


    /// <summary>
    /// Validates that the required host-generic delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public virtual void Validate()
    {
        IsValidated = false;
        var missing = new List<string>();

        CollectMissingHostSeams(missing);

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                $"{GetType().Name} is missing required delegates: ");
            _ = sb.AppendJoin(", ", missing);
            _ = sb.Append('.');

            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }


    /// <summary>
    /// Validates a secondary family's protocol wiring. Its shared host seams belong to the primary
    /// integration; derived families override this method to check their enabled dependencies.
    /// </summary>
    /// <param name="primaryIntegration">The composition's shared host operations.</param>
    public virtual void ValidateFamily(ServerIntegration primaryIntegration)
    {
        ArgumentNullException.ThrowIfNull(primaryIntegration);
    }


    /// <summary>
    /// Appends the names of any unset required host-generic seams to
    /// <paramref name="missing"/>. A derived integration calls this from its own
    /// <see cref="Validate"/> override before adding its protocol-seam checks, so a single
    /// error message reports every missing delegate across both layers.
    /// </summary>
    /// <param name="missing">The accumulating list of missing delegate names.</param>
    protected void CollectMissingHostSeams(List<string> missing)
    {
        ArgumentNullException.ThrowIfNull(missing);

        if(ExtractTenantIdAsync is null) { missing.Add(nameof(ExtractTenantIdAsync)); }
        if(LoadRegistrationAsync is null) { missing.Add(nameof(LoadRegistrationAsync)); }
        if(SaveFlowStateAsync is null) { missing.Add(nameof(SaveFlowStateAsync)); }
        if(LoadFlowStateAsync is null) { missing.Add(nameof(LoadFlowStateAsync)); }
        if(ClaimFlowStateAsync is null) { missing.Add(nameof(ClaimFlowStateAsync)); }
        if(DeleteFlowStateAsync is null) { missing.Add(nameof(DeleteFlowStateAsync)); }
        if(ResolvePolicyAsync is null) { missing.Add(nameof(ResolvePolicyAsync)); }
        if(ResolveCapabilitiesAsync is null) { missing.Add(nameof(ResolveCapabilitiesAsync)); }
        if(InspectAsync is null) { missing.Add(nameof(InspectAsync)); }
        if(GenerateIdentifierAsync is null) { missing.Add(nameof(GenerateIdentifierAsync)); }
        if(ResolveEndpointUriAsync is null) { missing.Add(nameof(ResolveEndpointUriAsync)); }
    }
}
