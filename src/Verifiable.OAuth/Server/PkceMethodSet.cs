using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The set of PKCE <c>code_challenge_method</c> values a deployment accepts on
/// authorization-style requests.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7636 §4.2 permits both <c>S256</c> and <c>plain</c>. FAPI 2.0 §5.2.2 and
/// HAIP §3 mandate <c>S256</c>. The library defaults to <see cref="S256Only"/>;
/// pre-FAPI-2 deployments still using <c>plain</c> opt into
/// <see cref="S256AndPlain"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("PkceMethodSet={ToString(),nq}")]
public enum PkceMethodSet
{
    /// <summary>Only <c>S256</c> accepted (FAPI 2.0 / HAIP).</summary>
    S256Only,

    /// <summary>Both <c>S256</c> and <c>plain</c> accepted (RFC 7636 baseline).</summary>
    S256AndPlain
}
