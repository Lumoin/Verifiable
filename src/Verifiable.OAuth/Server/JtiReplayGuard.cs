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
    /// No replay store is wired under <see cref="JtiReplayPolicy.Required"/>, or the wired
    /// store cannot resolve what it recorded under either <see cref="JtiReplayPolicy.Required"/>
    /// or <see cref="JtiReplayPolicy.OptionalIfStorePresent"/> — the caller must fail closed
    /// rather than proceed on a defense that cannot prove it is working.
    /// </summary>
    StoreUnavailable,

    /// <summary>
    /// The <c>jti</c> exceeds <see cref="JtiReplayGuard.MaxJtiLength"/> and cannot be tracked —
    /// the caller must reject the presentation as malformed before any store is consulted.
    /// </summary>
    Unacceptable
}


/// <summary>
/// The single <c>jti</c> replay defense shared by every authorization-server path that
/// presents a <c>jti</c> — the JWT-Secured Authorization Request object (RFC 9101 §10.2,
/// RFC 9700 §4), the DPoP proof at the token endpoint (RFC 9449 §11.1), and the JWT Bearer
/// authorization-grant assertion redeemed at the token endpoint (RFC 7523 §3 rule 7), which an
/// Identity Assertion JWT Authorization Grant (ID-JAG) redemption always exercises since §3.1
/// makes its <c>jti</c> REQUIRED. They all consult the
/// one <c>(issuer, jti)</c>-keyed correlation store
/// (<see cref="AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/> /
/// <see cref="AuthorizationServerIntegration.SaveFlowStateAsync"/> under
/// <see cref="FlowKind.JtiReplay"/>), so there is no second parallel tracker to keep
/// coherent. The <c>(issuer, jti)</c> composite isolates issuers — a bare <c>jti</c> would
/// conflate independent issuers into false rejections. A store that records a first use is
/// proved, not assumed: immediately after saving, the guard resolves the very key it just
/// wrote and requires the resolved value to equal the saved flow id, so a store wired for
/// other correlation kinds but never for <see cref="FlowKind.JtiReplay"/> — which would
/// otherwise answer <see cref="JtiReplayOutcome.FirstUse"/> to every consultation and make
/// the defense a silent no-op — is caught on its first use.
/// </summary>
public static class JtiReplayGuard
{
    /// <summary>
    /// The longest <c>jti</c> the guard will track (RFC 9449 §11.1: "In order to guard
    /// against memory exhaustion attacks, a server that is tracking jti values should
    /// reject DPoP proof JWTs with unnecessarily large jti values or store only a hash
    /// thereof."). A <c>jti</c> longer than this is refused via
    /// <see cref="JtiReplayOutcome.Unacceptable"/> before any store access.
    /// </summary>
    public const int MaxJtiLength = 1024;

    /// <summary>
    /// Composes the one <c>(issuer, jti)</c> correlation key every replay-defense path and
    /// every host's flow-state store uses, so no site re-derives the shape. Mirrored by
    /// <see cref="Verifiable.OAuth.Server.States.JtiSeenState.CorrelationKey"/> for the state
    /// a host indexes under.
    /// </summary>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    public static string CorrelationKey(string issuer, string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        return $"{issuer}:{jti}";
    }


    /// <summary>
    /// Consults the replay store for <paramref name="jti"/> under <paramref name="issuer"/>,
    /// governed by the request's <see cref="JtiReplayPolicy"/>. The read and the first-use
    /// record happen as ONE unit: when the policy calls for a check and a store is present,
    /// a miss is recorded immediately, so a deployment can never end up reading without
    /// recording (which would make the defense a silent no-op). Under
    /// <see cref="JtiReplayPolicy.Required"/> a missing store yields
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> so the caller fails closed. Once a
    /// first use is recorded, the guard resolves the same key again and requires equality
    /// with the flow id it just saved; a store that cannot reproduce what it recorded is
    /// treated as unavailable under every policy (a defective store is neither "present"
    /// nor "absent").
    /// </summary>
    /// <param name="server">The authorization server (its integration store and clock).</param>
    /// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
    /// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under (the composite-key prefix).</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <param name="expiresAt">When the recorded entry should expire — the same window the temporal checks accept the token in.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<JtiReplayOutcome> ConsultAsync(
        EndpointServer server,
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

        var oauth = server.OAuth();

        JtiReplayPolicy policy = context.JtiReplayPolicy;
        if(policy == JtiReplayPolicy.Disabled)
        {
            return JtiReplayOutcome.FirstUse;
        }

        //RFC 9449 §11.1's memory-exhaustion rule: an oversized jti is refused before it ever
        //reaches a store, under every policy that consults the store at all.
        if(jti.Length > MaxJtiLength)
        {
            return JtiReplayOutcome.Unacceptable;
        }

        //The store is the (issuer, jti)-keyed correlation index. The read delegate, the
        //write delegate, and the id generator the write needs must ALL be present for the
        //defense to actually record — a read-only half-wiring would never trip, so the
        //three are treated as one indivisible capability.
        bool isStoreAvailable =
            oauth.ResolveCorrelationKeyAsync is not null
            && oauth.SaveFlowStateAsync is not null
            && oauth.GenerateIdentifierAsync is not null;
        if(!isStoreAvailable)
        {
            return policy == JtiReplayPolicy.Required
                ? JtiReplayOutcome.StoreUnavailable
                : JtiReplayOutcome.FirstUse;
        }

        string correlationKey = CorrelationKey(issuer, jti);
        string? existing = await oauth.ResolveCorrelationKeyAsync!(
            tenantId, FlowKind.JtiReplay, correlationKey, context, cancellationToken).ConfigureAwait(false);
        if(existing is not null)
        {
            return JtiReplayOutcome.Replayed;
        }

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string flowId = await oauth.GenerateIdentifierAsync!(
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
        //The jti marker addresses itself: the correlation key IS the flow id SaveFlowStateAsync
        //saves under (there is no separate flow to link back to), while the freshly generated
        //identifier only populates the required FlowState.FlowId — a jti record's own identity,
        //never a storage key.
        await oauth.SaveFlowStateAsync!(
            tenantId, correlationKey, state, stepCount: 0, context, cancellationToken).ConfigureAwait(false);

        //The self-check: a store that saved the entry must also be able to resolve it back
        //under the same (tenant, FlowKind.JtiReplay, key) it was saved under, and the
        //resolved value must equal the flow id just saved (correlationKey, above) — mere
        //presence is not enough, since a store could resolve a stale or foreign id. A store
        //that fails this is defective under BOTH policies: Required was never going to
        //tolerate it, and OptionalIfStorePresent tolerates a store's absence, not its
        //malfunction.
        string? proof = await oauth.ResolveCorrelationKeyAsync!(
            tenantId, FlowKind.JtiReplay, correlationKey, context, cancellationToken).ConfigureAwait(false);

        return string.Equals(proof, correlationKey, StringComparison.Ordinal)
            ? JtiReplayOutcome.FirstUse
            : JtiReplayOutcome.StoreUnavailable;
    }
}
