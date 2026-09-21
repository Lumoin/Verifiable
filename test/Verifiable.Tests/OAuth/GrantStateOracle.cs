using System.Collections.Concurrent;
using Verifiable.OAuth.AuthCode.Server.States;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// What a grant's records look like right now, as reported by
/// <see cref="GrantStateOracle.SnapshotGrant(HostedAuthorizationServer, string, string)"/>.
/// </summary>
/// <param name="RedeemableRefreshFlowIds">
/// The flow ids of every live <see cref="ServerRefreshTokenIssuedState"/> found under the grant.
/// </param>
/// <param name="RedeemableCodeFlowIds">
/// The flow ids of every not-yet-redeemed <see cref="ServerCodeIssuedState"/> found under the
/// grant — at most one, since a grant born from a code has exactly one code record and no other
/// grant shares its key.
/// </param>
/// <param name="LiveRecordsMissingFromGrantIndex">
/// The flow ids among <see cref="RedeemableRefreshFlowIds"/> that
/// <see cref="HostedAuthorizationServer.GrantIndex"/> does NOT list under the grant's own key —
/// a live record the production revocation walk (which reads through
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration.LoadGrantFlowStatesAsync"/>,
/// itself backed by <see cref="HostedAuthorizationServer.GrantIndex"/>) would never see. Always
/// empty on a store with no fault injected.
/// </param>
internal readonly record struct GrantStateSnapshot(
    IReadOnlyList<string> RedeemableRefreshFlowIds,
    IReadOnlyList<string> RedeemableCodeFlowIds,
    IReadOnlyList<string> LiveRecordsMissingFromGrantIndex)
{
    /// <summary>
    /// How many records under this grant a presentation could still redeem right now — the
    /// number a race test's state assertion compares against zero or one.
    /// </summary>
    public int RedeemableRecordCount => RedeemableRefreshFlowIds.Count + RedeemableCodeFlowIds.Count;
}


/// <summary>
/// A race test's own read of grant state, independent of the library's revocation walk. Answers
/// what a race actually left behind, in the test host's own terms, so a race test's assertion
/// does not share the blind spot of the very mechanism it is proving — see the remarks on
/// <see cref="SnapshotGrant(HostedAuthorizationServer, string, string)"/>.
/// </summary>
internal static class GrantStateOracle
{
    /// <summary>
    /// Scans <see cref="HostedAuthorizationServer.FlowStates"/> directly — never
    /// <see cref="HostedAuthorizationServer.GrantIndex"/> and never
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration.LoadGrantFlowStatesAsync"/>,
    /// since the production revocation walk reads through those and an oracle that did too would
    /// share its blind spot — for every record whose grant key
    /// (<c>GrantFlowId ?? FlowId</c> for a refresh or terminal record, or its own <c>FlowId</c> for
    /// a code record) equals <paramref name="grantFlowId"/> and whose <c>ClientId</c> equals
    /// <paramref name="clientId"/>, then reports which of them can still be redeemed: a live
    /// <see cref="ServerRefreshTokenIssuedState"/>, or a <see cref="ServerCodeIssuedState"/> not
    /// yet redeemed (a redeemed code transitions in place into a
    /// <see cref="ServerTokenIssuedState"/> under the same flow id, so its presence in
    /// <see cref="HostedAuthorizationServer.FlowStates"/> alone means it is still live). A
    /// terminal <see cref="ServerTokenIssuedState"/> is never itself redeemable and contributes
    /// nothing to the count, whichever grant it names.
    /// </summary>
    /// <param name="hosted">The host whose store is scanned.</param>
    /// <param name="grantFlowId">The grant key to match.</param>
    /// <param name="clientId">The client the matched records must belong to.</param>
    public static GrantStateSnapshot SnapshotGrant(HostedAuthorizationServer hosted, string grantFlowId, string clientId)
    {
        List<string> redeemableRefreshFlowIds = [];
        List<string> redeemableCodeFlowIds = [];
        List<string> liveRecordsMissingFromGrantIndex = [];

        foreach(KeyValuePair<string, (FlowState State, int StepCount)> entry in hosted.FlowStates)
        {
            string flowId = entry.Key;
            switch(entry.Value.State)
            {
                case ServerRefreshTokenIssuedState refresh
                    when string.Equals(refresh.ClientId, clientId, StringComparison.Ordinal)
                        && string.Equals(refresh.GrantFlowId ?? flowId, grantFlowId, StringComparison.Ordinal):
                {
                    redeemableRefreshFlowIds.Add(flowId);
                    bool isIndexed = hosted.GrantIndex.TryGetValue(grantFlowId, out ConcurrentDictionary<string, byte>? indexed)
                        && indexed.ContainsKey(flowId);
                    if(!isIndexed)
                    {
                        liveRecordsMissingFromGrantIndex.Add(flowId);
                    }

                    break;
                }

                case ServerCodeIssuedState code
                    when string.Equals(code.ClientId, clientId, StringComparison.Ordinal)
                        && string.Equals(flowId, grantFlowId, StringComparison.Ordinal):
                {
                    redeemableCodeFlowIds.Add(flowId);

                    break;
                }
            }
        }

        return new GrantStateSnapshot(redeemableRefreshFlowIds, redeemableCodeFlowIds, liveRecordsMissingFromGrantIndex);
    }


    /// <summary>
    /// Whether the refresh token <paramref name="refreshToken"/> resolves, through
    /// <see cref="HostedAuthorizationServer.RefreshTokenIndex"/>, to a record that is still a live
    /// <see cref="ServerRefreshTokenIssuedState"/> in <see cref="HostedAuthorizationServer.FlowStates"/>.
    /// <see langword="false"/> for a token the index does not resolve, or whose record has
    /// retired, been deleted, or never existed.
    /// </summary>
    /// <param name="hosted">The host whose store is scanned.</param>
    /// <param name="refreshToken">The wire refresh-token string to resolve.</param>
    public static bool IsRefreshTokenLive(HostedAuthorizationServer hosted, string refreshToken) =>
        hosted.RefreshTokenIndex.TryGetValue(refreshToken, out string? flowId)
        && hosted.FlowStates.TryGetValue(flowId, out (FlowState State, int StepCount) entry)
        && entry.State is ServerRefreshTokenIssuedState;
}
