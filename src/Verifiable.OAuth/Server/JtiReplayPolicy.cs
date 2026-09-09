using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The replay-defense policy <see cref="JtiReplayGuard.ConsultAsync"/> applies to every
/// <c>jti</c>-bearing path.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7519 §4.1.7 specifies <c>jti</c> as OPTIONAL but recommends it for replay defense.
/// <see cref="JtiReplayGuard"/> is the one implementation of that defense, consulted by the
/// JWT-Secured Authorization Request object (RFC 9101 §10.2), the JWT Bearer authorization-grant
/// assertion and so an Identity Assertion JWT Authorization Grant redemption (RFC 7523 §3 rule 7),
/// the DPoP proof at the token and credential endpoints (RFC 9449 §11.1), a
/// <c>private_key_jwt</c> client assertion (RFC 7523 §2.2), and the SIOPv2 self-issued response
/// nonce (SIOPv2 §11.2). Every path shares the same <see cref="AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/> /
/// <see cref="AuthorizationServerIntegration.SaveFlowStateAsync"/> store, keyed by
/// <see cref="JtiReplayGuard.CorrelationKey"/> under <see cref="FlowKind.JtiReplay"/>. A
/// non-null resolution at that key signals the <c>jti</c> has been seen before; a null
/// resolution signals first use, which the guard records before returning — and then proves,
/// by resolving the same key again and requiring it to equal the flow id it just saved. This
/// axis controls whether a path consults the store at all, and how a defective consultation is
/// treated:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="Required"/> — the guard always consults the store. When no store is wired, or
/// the wired store cannot resolve what it just recorded, validation fails closed.
/// </description></item>
/// <item><description>
/// <see cref="OptionalIfStorePresent"/> — the guard consults the store when one is wired;
/// its absence is a no-op rather than a rejection. A store that IS wired but cannot resolve
/// what it recorded is not "absent" — it is defective, and this policy fails closed for it
/// exactly as <see cref="Required"/> does.
/// </description></item>
/// <item><description>
/// <see cref="Disabled"/> — the guard never consults the store. JTI replay defense is off for
/// the path; the <c>jti</c> claim may still be carried for audit but is not checked against
/// prior submissions.
/// </description></item>
/// </list>
/// <para>
/// The cross-issuer composite key <c>(issuer, jti)</c> defends against the case where the
/// same <c>jti</c> appears under different issuers — a bare <c>jti</c> alone would conflate
/// independent issuers and create false-positive rejections.
/// </para>
/// </remarks>
[DebuggerDisplay("JtiReplayPolicy={ToString(),nq}")]
public enum JtiReplayPolicy
{
    /// <summary>
    /// <c>jti</c> required and checked against the <see cref="JtiReplayGuard"/> store keyed by
    /// <see cref="JtiReplayGuard.CorrelationKey"/>; rejection on repeat, and on a store that
    /// cannot prove it recorded the first use.
    /// </summary>
    Required,

    /// <summary>
    /// <c>jti</c> checked when the <see cref="JtiReplayGuard"/> store is wired and proves it
    /// can resolve what it records; not required when no store is wired.
    /// </summary>
    OptionalIfStorePresent,

    /// <summary>
    /// <c>jti</c> not checked. Used by deployments that rely on
    /// transport-level replay defense (e.g., DPoP) and accept the risk on
    /// JARs.
    /// </summary>
    Disabled
}
