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
    /// <summary>Only <c>S256</c> accepted (FAPI 2.0 / HAIP / OAuth 2.1).</summary>
    S256Only,

    /// <summary>
    /// Both <c>S256</c> and <c>plain</c> accepted — the RFC 6749 + RFC 7636 baseline
    /// (<see cref="PolicyProfile.Rfc6749WithPkce"/>) alone. Every OAuth 2.1-lineage profile the
    /// library ships (<see cref="PolicyProfile.Fapi20"/>, <see cref="PolicyProfile.Haip10"/>) stays
    /// on <see cref="S256Only"/>:
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.2</see> states "The plain code challenge method, defined in [RFC7636], is
    /// explicitly forbidden in OAuth 2.1." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see> adds
    /// "clients SHOULD use PKCE code challenge methods that do not expose the PKCE verifier in the
    /// authorization request. ... Currently, S256 is the only such method." <c>plain</c> exists here
    /// only to interoperate with pre-OAuth-2.1 RFC 6749 + RFC 7636 deployments.
    /// </summary>
    S256AndPlain
}
