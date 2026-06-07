using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The policy a deployment applies to the <c>aud</c> claim on RFC 9068 access
/// tokens.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9068 §2.2 mandates <c>aud</c> on access tokens. Some deployments emit
/// access tokens consumable by multiple resource servers and want
/// <see cref="Suppressed"/> behaviour during a migration window;
/// <see cref="Optional"/> covers the in-between case where <c>aud</c> is
/// emitted only when a resource-server identifier is available.
/// </para>
/// </remarks>
[DebuggerDisplay("AccessTokenAudPolicy={ToString(),nq}")]
public enum AccessTokenAudPolicy
{
    /// <summary>
    /// The <c>aud</c> claim is required. The producer fails if no resource
    /// server identifier is available. RFC 9068-conformant default.
    /// </summary>
    Required,

    /// <summary>
    /// The <c>aud</c> claim is emitted when a resource server identifier is
    /// available; otherwise the token has no <c>aud</c>.
    /// </summary>
    Optional,

    /// <summary>
    /// The <c>aud</c> claim is never emitted. Useful only during a migration
    /// where resource servers do not yet enforce the claim.
    /// </summary>
    Suppressed
}
