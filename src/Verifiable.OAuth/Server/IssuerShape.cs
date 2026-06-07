using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The shape of the issuer URL a deployment advertises in metadata documents
/// and in the <c>iss</c> claim of issued tokens.
/// </summary>
/// <remarks>
/// <para>
/// The OAuth/OIDC ecosystem disagrees about whether the issuer URL is the
/// authority only (<c>https://issuer.example.com</c>) or the full canonical
/// URL including any path prefix (<c>https://issuer.example.com/tenants/foo</c>).
/// FAPI 2.0 effectively requires <see cref="FullUrl"/> for multi-tenant
/// deployments; older OIDC reference implementations defaulted to
/// <see cref="AuthorityOnly"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("IssuerShape={ToString(),nq}")]
public enum IssuerShape
{
    /// <summary>
    /// Issuer is the URL authority only (scheme + host + optional port). Used
    /// by single-tenant deployments and pre-FAPI-2 reference implementations.
    /// </summary>
    AuthorityOnly,

    /// <summary>
    /// Issuer is the full canonical URL including any path prefix. Required
    /// by multi-tenant FAPI 2.0 deployments where each tenant has its own
    /// issuer.
    /// </summary>
    FullUrl
}
