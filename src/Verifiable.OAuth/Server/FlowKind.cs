using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Identifies a flow type and serves as the persistence discriminator for
/// <see cref="OAuthFlowState"/> records and the routing discriminator for
/// <see cref="ServerEndpoint"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="FlowKind"/> is the base of a two-tier class hierarchy:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="StatefulFlowKind"/> — flow kinds backed by a pushdown
///       automaton with persisted state. Carries the Create and Step contracts.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="StatelessFlowKind"/> — a single marker type for endpoints
///       that compute responses without any flow state. No PDA, no persistence,
///       no state machine.
///     </description>
///   </item>
/// </list>
/// <para>
/// Library-provided flow kinds are discoverable via the <c>extension</c> block
/// in <see cref="FlowKindExtensions"/>:
/// </para>
/// <code>
/// Kind = FlowKind.AuthCodeServer
/// Kind = FlowKind.Oid4VpVerifierServer
/// Kind = FlowKind.Stateless
/// </code>
/// <para>
/// Library users add their own flow kinds by deriving from
/// <see cref="StatefulFlowKind"/> and surfacing the singleton instance via their
/// own <c>extension</c> block. The custom flow appears alongside the
/// library-provided kinds in IntelliSense.
/// </para>
/// <para>
/// The <see cref="Name"/> string is the persistence discriminator written
/// alongside serialised <see cref="OAuthFlowState"/> records. Names must remain
/// stable across deployments. Do not rename them after going to production.
/// </para>
/// </remarks>
[DebuggerDisplay("FlowKind Name={Name}")]
public abstract class FlowKind
{
    /// <summary>
    /// The stable identifier for this flow kind. Used as the persistence
    /// discriminator and for logging and tracing. Must be unique across all
    /// flow kinds in a deployment.
    /// </summary>
    public abstract string Name { get; }
}
