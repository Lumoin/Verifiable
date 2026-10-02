using System.Globalization;
using Verifiable.Core;
using Verifiable.Core.Text;
using Verifiable.OAuth.Dpop;
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
    /// The <c>jti</c> exceeds <see cref="JtiReplayGuard.MaxJtiLength"/>, or the <c>jti</c> or the issuer holds a
    /// character of the Unicode general category Cc (the C0 and C1 controls and U+007F) or an unpaired surrogate,
    /// so the guard cannot track it; the caller must reject the presentation as malformed, and no store has been
    /// consulted. The length bound answers
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449, Section 11.1</see>; the character
    /// rule is this library's policy, since the application's store may not hold such a character.
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
/// one <c>(purpose, issuer, jti)</c>-keyed correlation store, a DPoP proof's key also naming the target
/// URI it was presented at (RFC 9449 §11.1)
/// (<c>AuthorizationServerIntegration.ResolveCorrelationKeyAsync</c> /
/// <c>AuthorizationServerIntegration.SaveFlowStateAsync</c> under
/// <see cref="JtiReplayFlowKind.Instance"/>), so there is no second parallel tracker to keep
/// coherent. The composite isolates the kinds of object (<see cref="JtiReplayPurpose"/>), the
/// issuers and the targets of DPoP proofs — a bare <c>jti</c> would conflate a request object with a
/// DPoP proof, independent issuers, or proofs for the token endpoint and a protected resource, into
/// false rejections. A store that records a first use is
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
    public static int MaxJtiLength { get; } = 1024;


    /// <summary>
    /// The classes of character the guard refuses in a <c>jti</c> or an issuer before any store call: the Unicode
    /// general category Cc (the C0 and C1 controls and U+007F) and an unpaired surrogate, with no exempt code point.
    /// A format character (Cf) such as U+200B is not selected. Built once over the shared classifier
    /// <see cref="TextHygiene"/>; the rule is this library's policy, which <see cref="ConsultCoreAsync"/> applies.
    /// </summary>
    private static TextHygieneRule UnstorableCharacterRule { get; } = new(
        [TextHygieneClass.Control, TextHygieneClass.UnpairedSurrogate], []);

    /// <summary>
    /// Composes the <c>(purpose, issuer, jti)</c> correlation key of a purpose whose identifiers are not
    /// scoped to a target URI: every purpose except <see cref="JtiReplayPurpose.DpopProof"/>, whose key
    /// <see cref="CorrelationKey(JtiReplayPurpose, string, string?, string)"/> composes with its target.
    /// </summary>
    /// <param name="purpose">The kind of object the <c>jti</c> identifies.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <returns>The correlation key.</returns>
    /// <exception cref="ArgumentException"><paramref name="purpose"/> is <see cref="JtiReplayPurpose.DpopProof"/>, whose key names a target URI.</exception>
    public static string CorrelationKey(JtiReplayPurpose purpose, string issuer, string jti) =>
        CorrelationKey(purpose, issuer, target: null, jti);


    /// <summary>
    /// Composes the one correlation key every replay-defense path and every host's flow-state store
    /// uses, so no site re-derives the shape. Mirrored by
    /// <see cref="Verifiable.OAuth.Server.States.JtiSeenState.CorrelationKey"/> for the state
    /// a host indexes under.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A DPoP proof's <c>jti</c> is recorded in the context of the target URI the proof was presented
    /// at (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "In the
    /// context of the target URI, servers can store the jti value of each DPoP proof for the time window
    /// in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP
    /// proof. HTTP requests to the same URI for which the jti value has been seen before would be
    /// declined."), so <see cref="JtiReplayPurpose.DpopProof"/> requires <paramref name="target"/>, and
    /// the identifiers of every other purpose are scoped to no target, so they take none.
    /// </para>
    /// <para>
    /// The key is <c>{purpose}:{issuer length}:{issuer}:{jti}</c>, and for a DPoP proof
    /// <c>{purpose}:{issuer length}:{issuer}:{target length}:{target}:{jti}</c>. The purpose token holds
    /// no colon and decides which of the two shapes follows it; the issuer and the target are read by
    /// their stated lengths, so two distinct presentations never compose the same key even when the
    /// issuer, the target and the <c>jti</c> carry colons (the issuer <c>https://i/x</c> with the
    /// <c>jti</c> <c>b:c</c>, and the issuer <c>https://i/x:b</c> with the <c>jti</c> <c>c</c>, stay two
    /// records). The <c>jti</c> is the key's last component.
    /// </para>
    /// </remarks>
    /// <param name="purpose">The kind of object the <c>jti</c> identifies.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="target">
    /// The normalized target URI a DPoP proof was presented at, or <see langword="null"/> for every other
    /// purpose.
    /// </param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <returns>The correlation key.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="target"/> is absent for <see cref="JtiReplayPurpose.DpopProof"/>, or present for
    /// another purpose.
    /// </exception>
    public static string CorrelationKey(JtiReplayPurpose purpose, string issuer, string? target, string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jti);
        RequireTargetShape(purpose, target);

        string purposeToken = purpose switch
        {
            JtiReplayPurpose.RequestObject => "request-object",
            JtiReplayPurpose.DpopProof => "dpop-proof",
            JtiReplayPurpose.AuthorizationGrantAssertion => "grant-assertion",
            JtiReplayPurpose.ClientAssertion => "client-assertion",
            JtiReplayPurpose.SelfIssuedResponseNonce => "siop-nonce",
            _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown replay purpose.")
        };

        return target is null
            ? string.Create(CultureInfo.InvariantCulture, $"{purposeToken}:{issuer.Length}:{issuer}:{jti}")
            : string.Create(
                CultureInfo.InvariantCulture, $"{purposeToken}:{issuer.Length}:{issuer}:{target.Length}:{target}:{jti}");
    }


    /// <summary>
    /// Consults the replay store for a DPoP proof's <c>jti</c> under
    /// <see cref="JtiReplayPurpose.DpopProof"/>, in the context of the target URI the proof was presented
    /// at (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "HTTP
    /// requests to the same URI for which the jti value has been seen before would be declined."). Two
    /// proofs that carry the same <c>jti</c> at two target URIs are two first uses; a proof presented
    /// again at the same target URI is a replay. The target is normalized the way
    /// <see cref="DpopProofValidator"/> compares an <c>htu</c> with it (scheme, host, port and path, no
    /// query or fragment, RFC 3986 §6.2.2 and §6.2.3), so two spellings of one target are one record.
    /// </summary>
    /// <param name="server">The authorization server (its integration store and clock).</param>
    /// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
    /// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
    /// <param name="issuer">The issuer the proof was presented under.</param>
    /// <param name="target">The target URI of the request the proof was presented with.</param>
    /// <param name="jti">The proof's <c>jti</c>.</param>
    /// <param name="expiresAt">When the recorded entry should expire.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The replay outcome.</returns>
    public static ValueTask<JtiReplayOutcome> ConsultDpopProofAsync(
        EndpointServer server,
        ExchangeContext context,
        TenantId tenantId,
        string issuer,
        string target,
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(target);

        return ConsultCoreAsync(
            server, context, tenantId, JtiReplayPurpose.DpopProof, issuer,
            DpopProofValidator.NormalizeTargetUri(target), jti, expiresAt, cancellationToken);
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
    /// <param name="purpose">
    /// The kind of object the <c>jti</c> identifies, the key's domain; never
    /// <see cref="JtiReplayPurpose.DpopProof"/>, which <see cref="ConsultDpopProofAsync"/> records with its
    /// target URI.
    /// </param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <param name="expiresAt">When the recorded entry should expire — the same window the temporal checks accept the token in.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The replay outcome.</returns>
    /// <exception cref="ArgumentException"><paramref name="purpose"/> is <see cref="JtiReplayPurpose.DpopProof"/>.</exception>
    public static ValueTask<JtiReplayOutcome> ConsultAsync(
        EndpointServer server,
        ExchangeContext context,
        TenantId tenantId,
        JtiReplayPurpose purpose,
        string issuer,
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken) =>
        ConsultCoreAsync(server, context, tenantId, purpose, issuer, target: null, jti, expiresAt, cancellationToken);


    /// <summary>
    /// The one consultation <see cref="ConsultAsync"/> and <see cref="ConsultDpopProofAsync"/> share: the
    /// policy, the length bound, the character rule of <see cref="UnstorableCharacterRule"/>, the store's
    /// presence and claim, the record, its read-back and the claim that decides the first use, over the correlation
    /// key <see cref="CorrelationKey(JtiReplayPurpose, string, string?, string)"/> composes.
    /// </summary>
    /// <param name="server">The authorization server (its integration store and clock).</param>
    /// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
    /// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
    /// <param name="purpose">The kind of object the <c>jti</c> identifies.</param>
    /// <param name="issuer">The issuer the <c>jti</c> was presented under.</param>
    /// <param name="target">The normalized target URI of a DPoP proof, or <see langword="null"/> for every other purpose.</param>
    /// <param name="jti">The presented <c>jti</c> value.</param>
    /// <param name="expiresAt">When the recorded entry should expire.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The replay outcome.</returns>
    private static async ValueTask<JtiReplayOutcome> ConsultCoreAsync(
        EndpointServer server,
        ExchangeContext context,
        TenantId tenantId,
        JtiReplayPurpose purpose,
        string issuer,
        string? target,
        string jti,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jti);
        RequireTargetShape(purpose, target);

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

        //The composed correlation string and the saved record carry the jti and the issuer to the application's
        //store, and a store may not hold a control character or an unpaired surrogate (a durable store faults on
        //U+0000), so the guard answers a refusal where a fault would otherwise reach the caller as a server error.
        //The rule is this library's policy, beyond the length the text asks to bound, and runs before any store
        //call.
        bool isUnstorable = TextHygiene.Inspect(jti, UnstorableCharacterRule) is not null
            || TextHygiene.Inspect(issuer, UnstorableCharacterRule) is not null;
        if(isUnstorable)
        {
            return JtiReplayOutcome.Unacceptable;
        }

        //The store is the (purpose, issuer, jti)-keyed correlation index. The check reads the
        //correlation read, which an integration may leave unwired, and the id generator the record's
        //write draws its flow id from: a write without the read could record but never find, so
        //either one missing is the store's absence. The save is not read here, since it is a
        //required seam of every validated integration (ServerIntegration.Validate).
        bool isStorePresent =
            oauth.ResolveCorrelationKeyAsync is not null
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

        string correlationKey = CorrelationKey(purpose, issuer, target, jti);
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
            Target = target,
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
        //under the same key is a replay.
        bool isFirstUse = await oauth.ClaimFlowStateAsync!(
            tenantId, correlationKey, 0, context, cancellationToken).ConfigureAwait(false);

        return isFirstUse
            ? JtiReplayOutcome.FirstUse
            : JtiReplayOutcome.Replayed;
    }


    /// <summary>
    /// Requires a target URI exactly for <see cref="JtiReplayPurpose.DpopProof"/>: RFC 9449 §11.1 records a
    /// DPoP proof's <c>jti</c> "in the context of the target URI", and no other purpose's identifier is
    /// scoped to one. The purpose therefore decides the key's shape, which keeps the two shapes from
    /// composing the same key.
    /// </summary>
    /// <param name="purpose">The kind of object the <c>jti</c> identifies.</param>
    /// <param name="target">The target URI, or <see langword="null"/>.</param>
    /// <exception cref="ArgumentException">The target is absent for a DPoP proof or present for another purpose.</exception>
    private static void RequireTargetShape(JtiReplayPurpose purpose, string? target)
    {
        bool isTargetScoped = purpose == JtiReplayPurpose.DpopProof;
        if(isTargetScoped && string.IsNullOrEmpty(target))
        {
            throw new ArgumentException(
                "A DPoP proof's jti is recorded in the context of its target URI (RFC 9449 §11.1); supply the target.",
                nameof(target));
        }

        if(!isTargetScoped && target is not null)
        {
            throw new ArgumentException(
                "Only a DPoP proof's jti is recorded in the context of a target URI.", nameof(target));
        }
    }
}
