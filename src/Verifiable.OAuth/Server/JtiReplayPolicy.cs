using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The replay-defense policy applied to inbound JAR <c>jti</c> claims.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7519 §4.1.7 specifies <c>jti</c> as OPTIONAL but recommends it for
/// replay defense. When the library wires JTI replay defense (separate
/// round), it will use the existing general-purpose correlation-keyed
/// storage — <see cref="LoadServerFlowStateDelegate"/> and
/// <see cref="SaveServerFlowStateDelegate"/> on
/// <see cref="AuthorizationServerIntegration"/> — keyed by
/// <c>(issuer, jti)</c>. The presence of a non-null state record at the
/// <c>(issuer, jti)</c> key signals the JTI has been seen before; absence
/// signals first-use. This axis controls whether the JAR matchers consult
/// that storage:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="Required"/> — matchers always consult the store. If the store
/// is unavailable, validation fails closed.
/// </description></item>
/// <item><description>
/// <see cref="OptionalIfStorePresent"/> — matchers consult the store when
/// present; absence is a no-op rather than a rejection. Useful for
/// deployments that have not yet wired a JTI store but want strict policy
/// elsewhere.
/// </description></item>
/// <item><description>
/// <see cref="Disabled"/> — matchers do not consult the store. JTI replay
/// defense is off; the <c>jti</c> claim may still be carried for audit but
/// is not verified against prior submissions.
/// </description></item>
/// </list>
/// <para>
/// No new delegate slot is required for JTI replay. The cross-issuer
/// composite key <c>(issuer, jti)</c> defends against the case where the
/// same <c>jti</c> appears under different issuers — bare <c>jti</c> alone
/// would conflate independent issuers and create false-positive rejections.
/// </para>
/// </remarks>
[DebuggerDisplay("JtiReplayPolicy={ToString(),nq}")]
public enum JtiReplayPolicy
{
    /// <summary>
    /// <c>jti</c> required and checked against the
    /// <see cref="LoadServerFlowStateDelegate"/> /
    /// <see cref="SaveServerFlowStateDelegate"/> store keyed by
    /// <c>(issuer, jti)</c>; rejection on repeat. The future strict default.
    /// </summary>
    Required,

    /// <summary>
    /// <c>jti</c> checked when the
    /// <see cref="LoadServerFlowStateDelegate"/> /
    /// <see cref="SaveServerFlowStateDelegate"/> store is configured; not
    /// required when no store is wired. The library's interim default until
    /// JTI replay defense lands as a built-in matcher path.
    /// </summary>
    OptionalIfStorePresent,

    /// <summary>
    /// <c>jti</c> not checked. Used by deployments that rely on
    /// transport-level replay defense (e.g., DPoP) and accept the risk on
    /// JARs.
    /// </summary>
    Disabled
}
