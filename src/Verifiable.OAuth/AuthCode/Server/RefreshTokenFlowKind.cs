using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// A flow kind marker for refresh-token storage and lookup.
/// </summary>
/// <remarks>
/// <para>
/// Refresh tokens persist as <see cref="States.ServerRefreshTokenIssuedState"/>
/// records keyed by a fresh internal <c>flowId</c>. The application's
/// <see cref="Verifiable.OAuth.Server.ResolveCorrelationKeyDelegate"/> matches
/// on this flow kind to look up the refresh-token string in the secondary
/// index it maintains. Sealed singleton accessed via
/// <c>FlowKind.RefreshToken</c>.
/// </para>
/// <para>
/// Refresh tokens have their own flow kind (rather than reusing
/// <see cref="AuthCodeServerFlowKind"/>) because the storage volume profile
/// differs — refresh tokens are long-lived per RFC 6749 §6 (typically days
/// to months), while authorization codes are short-lived single-use handles.
/// Deployments may back the two with different storage tiers; the discriminator
/// lets <see cref="Verifiable.OAuth.Server.ResolveCorrelationKeyDelegate"/>
/// route to the right tier.
/// </para>
/// </remarks>
[DebuggerDisplay("RefreshTokenFlowKind")]
public sealed class RefreshTokenFlowKind: FlowKind
{
    /// <summary>The singleton instance.</summary>
    public static RefreshTokenFlowKind Instance { get; } = new();


    private RefreshTokenFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "auth-code-refresh-token";
}
