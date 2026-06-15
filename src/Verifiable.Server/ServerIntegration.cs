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
/// Wire all required delegates at construction time. <see cref="Validate"/> reports any
/// missing delegate by name in a single error message rather than failing piecemeal at
/// request time.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerIntegration Validated={IsValidated}")]
public class ServerIntegration
{
    /// <summary>
    /// Extracts the <see cref="Verifiable.Core.TenantId"/> from the inbound request.
    /// Required. Returning <see langword="null"/> indicates the request carries no
    /// identifiable tenant; the dispatcher responds 400 without invoking any further
    /// delegate.
    /// </summary>
    public ExtractTenantIdDelegate? ExtractTenantIdAsync { get; set; }

    /// <summary>
    /// Loads a registration by tenant identifier. Required.
    /// </summary>
    public LoadRegistrationDelegate? LoadRegistrationAsync { get; set; }

    /// <summary>
    /// Persists a <see cref="FlowState"/> under the internal <c>flowId</c> scoped by
    /// tenant. Required.
    /// </summary>
    public SaveServerFlowStateDelegate? SaveFlowStateAsync { get; set; }

    /// <summary>
    /// Deletes a previously-saved flow state, scoped by tenant. Optional; flows that
    /// never invalidate state can leave this null.
    /// </summary>
    public DeleteServerFlowStateDelegate? DeleteFlowStateAsync { get; set; }

    /// <summary>
    /// Loads a <see cref="FlowState"/> and step count by the internal <c>flowId</c>.
    /// Required. The key has already been resolved from any external handle by
    /// <see cref="ResolveCorrelationKeyAsync"/>.
    /// </summary>
    public LoadServerFlowStateDelegate? LoadFlowStateAsync { get; set; }

    /// <summary>
    /// Resolves an external correlation handle to the stable internal <c>flowId</c> used
    /// as the primary persistence key. Optional for flows where the external handle is
    /// the <c>flowId</c>; when <see langword="null"/> the external handle is used directly.
    /// </summary>
    public ResolveCorrelationKeyDelegate? ResolveCorrelationKeyAsync { get; set; }

    /// <summary>
    /// Resolves the absolute URL at which a capability is reachable for a given
    /// registration in the current request. Required when the server emits metadata or
    /// tokens whose claims include endpoint URLs.
    /// </summary>
    public ResolveEndpointUriDelegate? ResolveEndpointUriAsync { get; set; }

    /// <summary>
    /// Resolves the per-request capability set active for a registration. Consulted once
    /// per request by <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/>; the
    /// returned set filters which builder-produced candidates land in the chain. Required.
    /// </summary>
    public ResolveCapabilitiesDelegate? ResolveCapabilitiesAsync { get; set; }

    /// <summary>
    /// Invoked at each pipeline inspection stage (see <see cref="InspectionStage"/>).
    /// Required.
    /// </summary>
    public InspectDelegate? InspectAsync { get; set; }

    /// <summary>
    /// Generates an identifier for a stated <see cref="IdentifierPurpose"/>. Threaded
    /// through every wire-identifier and correlation-identifier generation site; Required.
    /// </summary>
    public GenerateIdentifierDelegate? GenerateIdentifierAsync { get; set; }

    /// <summary>
    /// Resolves the host's issuer URI for the request. Optional; when
    /// <see langword="null"/> the dispatch loop uses its built-in fallback (the value the
    /// skin placed on the context).
    /// </summary>
    public ResolveServerIssuerDelegate? ResolveIssuerAsync { get; set; }

    /// <summary>
    /// Resolves and stamps per-request policy values on the context at dispatch entry,
    /// before any matcher runs. Required.
    /// </summary>
    public ResolveServerPolicyDelegate? ResolvePolicyAsync { get; set; }


    /// <summary>
    /// Whether <see cref="Validate"/> has been called successfully on this group.
    /// </summary>
    public bool IsValidated { get; protected set; }


    /// <summary>
    /// Validates that the required host-generic delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public virtual void Validate()
    {
        var missing = new List<string>();

        CollectMissingHostSeams(missing);

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                $"{GetType().Name} is missing required delegates: ");
            sb.AppendJoin(", ", missing);
            sb.Append('.');

            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
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
        if(ResolvePolicyAsync is null) { missing.Add(nameof(ResolvePolicyAsync)); }
        if(ResolveCapabilitiesAsync is null) { missing.Add(nameof(ResolveCapabilitiesAsync)); }
        if(InspectAsync is null) { missing.Add(nameof(InspectAsync)); }
        if(GenerateIdentifierAsync is null) { missing.Add(nameof(GenerateIdentifierAsync)); }
    }
}
