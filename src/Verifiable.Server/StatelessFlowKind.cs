using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// A flow kind marker for endpoints that compute responses without any PDA or
/// flow state — JWKS, discovery, and similar metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Stateless endpoints set <see cref="ServerEndpoint.Kind"/> to the stateless
/// marker. The dispatcher recognises this type and skips the PDA Create / Step /
/// persistence path entirely. The endpoint's
/// <see cref="ServerEndpoint.BuildInputAsync"/> returns an early-exit
/// <see cref="ServerHttpResponse"/> directly and
/// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
/// </para>
/// <para>
/// Caching, precomputation, and distribution of JWKS or discovery documents are
/// entirely the application's concern — wired through the family's JWKS-assembly
/// seam. The delegate receives the per-request context so it can make per-call
/// decisions. Invalidation signals come from the host's registration-lifecycle
/// event stream — a client-updated subscriber evicts from cache.
/// </para>
/// <para>
/// <see cref="StatelessFlowKind"/> is a sealed singleton reached through
/// <see cref="Instance"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("StatelessFlowKind")]
public sealed class StatelessFlowKind: FlowKind
{
    /// <summary>The singleton instance.</summary>
    public static StatelessFlowKind Instance { get; } = new();


    private StatelessFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "stateless";
}
