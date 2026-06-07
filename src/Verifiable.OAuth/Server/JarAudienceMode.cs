using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The reading of the JAR <c>aud</c> claim a deployment accepts. Anchors the
/// substantive disagreement in the ecosystem about what RFC 9101 §10.2 means.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9101 §10.2 says JAR <c>aud</c> SHOULD be the AS issuer. Real-world
/// deployments diverge: FAPI 2.0 reads it as the AS issuer URL strict; some
/// EUDI Wallet and Microsoft Entra deployments historically populate
/// <c>client_id</c>; some implementations accept either. The library expresses
/// the choice as a policy axis rather than baking one reading in.
/// </para>
/// </remarks>
[DebuggerDisplay("JarAudienceMode={ToString(),nq}")]
public enum JarAudienceMode
{
    /// <summary>
    /// <c>aud</c> must equal the AS issuer URL resolved through
    /// <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>. The
    /// FAPI 2.0 reading; the only reading that defends RFC 9700 §4.2 mix-up
    /// attacks across multiple AS deployments.
    /// </summary>
    IssuerOnly,

    /// <summary>
    /// <c>aud</c> must equal <c>client_id</c>. The historical EUDI / Microsoft
    /// reading; correct for KB-JWT in OID4VP but wrong for AuthCode JAR per
    /// RFC 9101 §10.2.
    /// </summary>
    ClientIdOnly,

    /// <summary>
    /// Either reading accepted. Used by deployments that need to interoperate
    /// with both modes during a migration window.
    /// </summary>
    EitherIssuerOrClientId
}
