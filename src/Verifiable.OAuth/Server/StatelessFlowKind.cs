using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A flow kind marker for endpoints that compute responses without any PDA or
/// flow state — JWKS, discovery, and similar metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Stateless endpoints set <see cref="ServerEndpoint.Kind"/> to
/// <c>FlowKind.Stateless</c>. The dispatcher recognises this type and skips
/// the PDA Create / Step / persistence path entirely. The endpoint's
/// <see cref="ServerEndpoint.BuildInputAsync"/> returns an early-exit
/// <see cref="ServerHttpResponse"/> directly and
/// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
/// </para>
/// <para>
/// Caching, precomputation, and distribution of JWKS or discovery documents are
/// entirely the application's concern — wired through
/// <see cref="AuthorizationServerOptions.BuildJwksDocumentAsync"/>. The delegate
/// receives the per-request context so it can make per-call decisions.
/// Invalidation signals come from <see cref="AuthorizationServer.Events"/> —
/// a <see cref="ClientUpdated"/> subscriber evicts from cache.
/// </para>
/// <para>
/// <see cref="StatelessFlowKind"/> is a sealed singleton accessed via
/// <c>FlowKind.Stateless</c>.
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
