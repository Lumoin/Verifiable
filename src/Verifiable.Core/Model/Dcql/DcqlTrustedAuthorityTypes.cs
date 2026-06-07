using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// The registered <c>type</c> VALUES of a DCQL Trusted Authorities Query
/// (<see cref="TrustedAuthoritiesQuery.Type"/>) per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OID4VP 1.0 §6.1.1</see>.
/// Each value names the scheme by which <see cref="TrustedAuthoritiesQuery.Values"/>
/// identifies an acceptable authority.
/// </summary>
/// <remarks>
/// <para>
/// Companion to <see cref="DcqlParameterNames"/>: that class holds the member
/// <em>names</em> of the DCQL wire objects (including the <c>type</c> key itself);
/// this class holds the enumerated <em>values</em> that key may take. Declared
/// <see langword="static readonly"/> (not <see langword="const"/>) to match the
/// surrounding well-known classes and avoid cross-assembly const inlining; match with
/// the <c>Is*</c> ordinal helpers rather than <c>case</c> labels.
/// </para>
/// </remarks>
[DebuggerDisplay("DcqlTrustedAuthorityTypes")]
public static class DcqlTrustedAuthorityTypes
{
    /// <summary>
    /// <c>aki</c> — the authority is identified by the <c>KeyIdentifier</c> of the
    /// <c>AuthorityKeyIdentifier</c> X.509 extension (base64url-encoded DER value) per
    /// OID4VP 1.0 §6.1.1.1. Used with X.509-anchored credential formats (e.g. mdoc).
    /// </summary>
    public static readonly string Aki = "aki";

    /// <summary>
    /// <c>etsi_tl</c> — the authority is identified by the location of an ETSI Trusted
    /// List (ETSI TS 119 612) per OID4VP 1.0 §6.1.1.2; the list, or one it cascades to,
    /// must contain the credential's issuing authority.
    /// </summary>
    public static readonly string EtsiTrustedList = "etsi_tl";

    /// <summary>
    /// <c>openid_federation</c> — the authority is identified by an OpenID Federation
    /// Entity Identifier (OpenID Federation §1) per OID4VP 1.0 §6.1.1.3; a valid trust
    /// path including that identifier must be constructible from a matching credential.
    /// This is the value carried for SD-JWT VC issuers identified by their <c>iss</c>.
    /// </summary>
    public static readonly string OpenIdFederation = "openid_federation";


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>aki</c>.</summary>
    public static bool IsAki(string value) => string.Equals(value, Aki, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>etsi_tl</c>.</summary>
    public static bool IsEtsiTrustedList(string value) => string.Equals(value, EtsiTrustedList, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>openid_federation</c>.</summary>
    public static bool IsOpenIdFederation(string value) => string.Equals(value, OpenIdFederation, StringComparison.Ordinal);
}
