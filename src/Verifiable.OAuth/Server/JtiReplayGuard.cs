using Verifiable.Core;
using Verifiable.OAuth.Server.States;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The outcome of a <c>jti</c> replay-store consultation governed by
/// <see cref="JtiReplayPolicy"/>.
/// </summary>
public enum JtiReplayOutcome
{
    /// <summary>
    /// The <c>jti</c> was not seen before, or the policy does not require a check —
    /// processing may continue. When a store was available, first use has been recorded.
    /// </summary>
    FirstUse,

    /// <summary>
    /// The <c>jti</c> was already recorded within its window — the caller must reject
    /// the presentation as a replay.
    /// </summary>
    Replayed,

    /// <summary>
    /// The policy is <see cref="JtiReplayPolicy.Required"/> but no replay store is wired —
    /// the caller must fail closed rather than proceed without replay defense.
    /// </summary>
    StoreUnavailable
}


/// <summary>
/// The single <c>jti</c> replay defense shared by every authorization-server path that
/// presents a <c>jti</c> — the JWT-Secured Authorization Request object (RFC 9101 §10.2,
/// RFC 9700 §4) and the DPoP proof at the token endpoint (RFC 9449 §11.1). Both consult the
/// one <c>(issuer, jti)</c>-keyed correlation store
/// (<see cref="AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/> /
/// <see cref="AuthorizationServerIntegration.SaveFlowStateAsync"/> under
/// <see cref="FlowKind.JtiReplay"/>), so there is no second parallel tracker to keep
/// coherent. The <c>(issuer, jti)</c> composite isolates issuers — a bare <c>jti</c> would
/// conflate independent issuers into false rejections.
/// </summary>
public static class JtiReplayGuard
{
    /// <summary>
    /// Consults the replay store for <paramref name="jti"/> under <paramref name="issuer"/>,
    /// governed by the request's <see cref="JtiReplayPolicy"/>. The read and the first-use
    /// record happen as ONE unit: when the policy calls for a check and a store is present,
    /// a miss is recorded immediately, so a deployment can never end up reading without
    /// recording (which would make the defense a silent no-op). Under
    /// <see cref="JtiReplayPolicy.Required"/> a missing store yields
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> so the caller fails closed.
    /// </summary>
    /// <param name="server">The authorization server (its integration store and clock).</param>
    /// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
    /// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under (the composite-key prefix).</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <param name="expiresAt">When the recorded entry should expire — the same window the temporal checks accept the token in.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<JtiReplayOutcome> ConsultAsync(
        AuthorizationServer server,
        ExchangeContext context,
        TenantId tenantId,
        string issuer,
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        JtiReplayPolicy policy = context.JtiReplayPolicy;
        if(policy == JtiReplayPolicy.Disabled)
        {
            return JtiReplayOutcome.FirstUse;
        }

        //The store is the (issuer, jti)-keyed correlation index. The read delegate, the
        //write delegate, and the id generator the write needs must ALL be present for the
        //defense to actually record — a read-only half-wiring would never trip, so the
        //three are treated as one indivisible capability.
        bool isStoreAvailable =
            server.Integration.ResolveCorrelationKeyAsync is not null
            && server.Integration.SaveFlowStateAsync is not null
            && server.Integration.GenerateIdentifierAsync is not null;
        if(!isStoreAvailable)
        {
            return policy == JtiReplayPolicy.Required
                ? JtiReplayOutcome.StoreUnavailable
                : JtiReplayOutcome.FirstUse;
        }

        string correlationKey = $"{issuer}:{jti}";
        string? existing = await server.Integration.ResolveCorrelationKeyAsync!(
            tenantId, FlowKind.JtiReplay, correlationKey, context, cancellationToken).ConfigureAwait(false);
        if(existing is not null)
        {
            return JtiReplayOutcome.Replayed;
        }

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string flowId = await server.Integration.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthCorrelationId, context, cancellationToken).ConfigureAwait(false);
        JtiSeenState state = new()
        {
            FlowId = flowId,
            ExpectedIssuer = issuer,
            EnteredAt = now,
            ExpiresAt = expiresAt,
            Kind = FlowKind.JtiReplay,
            Issuer = issuer,
            Jti = jti,
            SeenAt = now
        };
        await server.Integration.SaveFlowStateAsync!(
            tenantId, correlationKey, state, stepCount: 0, context, cancellationToken).ConfigureAwait(false);

        return JtiReplayOutcome.FirstUse;
    }
}
