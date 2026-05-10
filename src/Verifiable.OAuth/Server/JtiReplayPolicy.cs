using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The library's <c>jti</c> replay-defense policy for inbound JARs and similar
/// signed envelopes.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7519 §4.1.7 specifies <c>jti</c> as OPTIONAL but recommends it for replay
/// defense. The library does not yet ship a replay store; the policy axis lets
/// deployments declare intent so the future replay-store integration can light
/// up without an API change.
/// </para>
/// </remarks>
[DebuggerDisplay("JtiReplayPolicy={ToString(),nq}")]
public enum JtiReplayPolicy
{
    /// <summary>
    /// <c>jti</c> required and checked against a replay store; rejection on
    /// repeat. The future strict default.
    /// </summary>
    Required,

    /// <summary>
    /// <c>jti</c> checked when a replay store is configured; not required when
    /// no store is wired. The library's interim default until the replay-store
    /// surface is finalised.
    /// </summary>
    OptionalIfStorePresent,

    /// <summary>
    /// <c>jti</c> not checked. Used by deployments that rely on transport-level
    /// replay defense (e.g., DPoP) and accept the risk on JARs.
    /// </summary>
    Disabled
}
