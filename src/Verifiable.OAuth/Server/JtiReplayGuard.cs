using System.Globalization;
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
    /// store has no atomic claim or cannot resolve what it recorded, under either
    /// <see cref="JtiReplayPolicy.Required"/> or <see cref="JtiReplayPolicy.OptionalIfStorePresent"/>
    /// — the caller must fail closed rather than proceed on a defense that cannot prove it is working.
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
/// one <c>(purpose, issuer, jti)</c>-keyed correlation store
/// (<c>AuthorizationServerIntegration.ResolveCorrelationKeyAsync</c> /
/// <c>AuthorizationServerIntegration.SaveFlowStateAsync</c> under
/// <see cref="JtiReplayFlowKind.Instance"/>), so there is no second parallel tracker to keep
/// coherent. The composite isolates the kinds of object (<see cref="JtiReplayPurpose"/>) and the
/// issuers — a bare <c>jti</c> would conflate a request object with a DPoP proof, or independent
/// issuers, into false rejections. A store that records a first use is
/// proved, not assumed: immediately after saving, the guard resolves the very key it just
/// wrote and requires the resolved value to equal the saved flow id, so a store wired for
/// other correlation kinds but never for <see cref="JtiReplayFlowKind.Instance"/> — which would
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
    /// Composes the one <c>(purpose, issuer, jti)</c> correlation key every replay-defense path and
    /// every host's flow-state store uses, so no site re-derives the shape. Mirrored by
    /// <see cref="Verifiable.OAuth.Server.States.JtiSeenState.CorrelationKey"/> for the state
    /// a host indexes under.
    /// </summary>
    /// <remarks>
    /// The key is <c>{purpose}:{issuer length}:{issuer}:{jti}</c>. The purpose token holds no colon
    /// and the issuer is read by its stated length, so two distinct triples never compose the same
    /// key even when the issuer and the <c>jti</c> both carry colons (the issuer
    /// <c>https://i/x</c> with the <c>jti</c> <c>b:c</c>, and the issuer <c>https://i/x:b</c> with the
    /// <c>jti</c> <c>c</c>, stay two records). The <c>jti</c> is the key's last component.
    /// </remarks>
    /// <param name="purpose">The kind of object the <c>jti</c> identifies.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <returns>The correlation key.</returns>
    public static string CorrelationKey(JtiReplayPurpose purpose, string issuer, string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        string purposeToken = purpose switch
        {
            JtiReplayPurpose.RequestObject => "request-object",
            JtiReplayPurpose.DpopProof => "dpop-proof",
            JtiReplayPurpose.AuthorizationGrantAssertion => "grant-assertion",
            JtiReplayPurpose.ClientAssertion => "client-assertion",
            JtiReplayPurpose.SelfIssuedResponseNonce => "siop-nonce",
            _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown replay purpose.")
        };

        return string.Create(
            CultureInfo.InvariantCulture, $"{purposeToken}:{issuer.Length}:{issuer}:{jti}");
    }


    /// <summary>
    /// Consults the replay store for a <c>private_key_jwt</c> client assertion's <c>jti</c> under
    /// <see cref="JtiReplayPurpose.ClientAssertion"/>: <see cref="ConsultAsync"/> in the shape of
    /// <see cref="CheckClientAssertionJtiReplayDelegate"/>, so a caller wires this method directly as
    /// that delegate.
    /// </summary>
    /// <param name="server">The authorization server (its integration store and clock).</param>
    /// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
    /// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
    /// <param name="issuer">The assertion's <c>iss</c>.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <param name="expiresAt">When the recorded entry should expire.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The replay outcome.</returns>
    public static ValueTask<JtiReplayOutcome> ConsultClientAssertionAsync(
        EndpointServer server,
        ExchangeContext context,
        TenantId tenantId,
        string issuer,
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken) =>
        ConsultAsync(server, context, tenantId, JtiReplayPurpose.ClientAssertion, issuer, jti, expiresAt, cancellationToken);


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
    /// nor "absent"). The first use is then decided by the store's atomic claim
    /// (<see cref="Verifiable.Server.ServerIntegration.ClaimFlowStateAsync"/>) on the record's first
    /// step, which exactly one caller wins, so concurrent presentations of the same
    /// <c>(purpose, issuer, jti)</c> that all found no record admit one presentation and answer every
    /// other one <see cref="JtiReplayOutcome.Replayed"/> (RFC 9449 §11.1).
    /// </summary>
    /// <remarks>
    /// Every presentation that found no record saves the record before it claims, so a presentation
    /// that loses the claim may save the same record, at the same step, after the winner has claimed
    /// it. The guard is correct only because the claim of a <c>(tenant, key, step)</c> is retained
    /// apart from the record a save writes: a later <see cref="Verifiable.Server.ServerIntegration.SaveFlowStateAsync"/>
    /// of the same key never makes a claimed step claimable again, which is the
    /// <see cref="Verifiable.Server.ClaimServerFlowStateDelegate"/> contract ("exactly one receives
    /// <see langword="true"/>"). A store that kept the claim as a mark on the saved record, cleared
    /// by the next save, would admit both presentations. A store wired with the correlation read and
    /// the save but no claim cannot decide first use; the guard answers
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> for it under every policy that consults the
    /// store, since such a store is defective rather than absent.
    /// </remarks>
    /// <param name="server">The authorization server (its integration store and clock).</param>
    /// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
    /// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
    /// <param name="purpose">The kind of object the <c>jti</c> identifies, the key's domain.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <param name="expiresAt">When the recorded entry should expire — the same window the temporal checks accept the token in.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The replay outcome.</returns>
    public static async ValueTask<JtiReplayOutcome> ConsultAsync(
        EndpointServer server,
        ExchangeContext context,
        TenantId tenantId,
        JtiReplayPurpose purpose,
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

        //The store is the (purpose, issuer, jti)-keyed correlation index. The read delegate, the
        //write delegate and the id generator the write needs must ALL be present for the defense
        //to actually record — a read-only half-wiring would never trip, so the three are treated
        //as one indivisible capability whose absence is the store's absence.
        bool isStorePresent =
            oauth.ResolveCorrelationKeyAsync is not null
            && oauth.SaveFlowStateAsync is not null
            && oauth.GenerateIdentifierAsync is not null;
        if(!isStorePresent)
        {
            return policy == JtiReplayPolicy.Required
                ? JtiReplayOutcome.StoreUnavailable
                : JtiReplayOutcome.FirstUse;
        }

        //A store that records but has no atomic claim cannot pick the one first use among
        //concurrent presentations; it is present and defective, never absent.
        if(oauth.ClaimFlowStateAsync is null)
        {
            return JtiReplayOutcome.StoreUnavailable;
        }

        string correlationKey = CorrelationKey(purpose, issuer, jti);
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
            Purpose = purpose,
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
        if(!string.Equals(proof, correlationKey, StringComparison.Ordinal))
        {
            return JtiReplayOutcome.StoreUnavailable;
        }

        //Concurrent presentations of one jti can all read "absent" above and all save the same
        //record, so neither the read nor the save decides the first use. The store's atomic claim
        //on the record's first step does: exactly one caller wins it, and every other presentation
        //of the same (issuer, jti) is a replay.
        bool isFirstUse = await oauth.ClaimFlowStateAsync!(
            tenantId, correlationKey, 0, context, cancellationToken).ConfigureAwait(false);

        return isFirstUse
            ? JtiReplayOutcome.FirstUse
            : JtiReplayOutcome.Replayed;
    }
}
