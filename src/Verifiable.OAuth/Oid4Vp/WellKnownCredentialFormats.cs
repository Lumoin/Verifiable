using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Credential format identifier constants used as keys in <c>vp_formats_supported</c>
/// and in DCQL <c>format</c> fields, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B">OID4VP 1.0 Appendix B</see>.
/// </summary>
/// <remarks>
/// <para>
/// These identifiers are defined by OID4VP 1.0 Appendix B or by specifications
/// that OID4VP Appendix B references. They name credential formats in
/// <c>vp_formats_supported</c> metadata and in DCQL credential queries.
/// </para>
/// <para>
/// The <c>dc+sd-jwt</c> format identifier is not listed here because it is
/// defined in RFC 9901 and already lives in
/// <see cref="Verifiable.JCose.WellKnownMediaTypes.Jwt.DcSdJwt"/>. Code in
/// this assembly uses that constant directly.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownCredentialFormats")]
public static class WellKnownCredentialFormats
{
    //W3C VC JWT formats — defined in OID4VP 1.0 Appendix B.1.

    /// <summary>
    /// W3C Verifiable Credential secured as a JWT (<c>jwt_vc_json</c>).
    /// Defined in OID4VP 1.0 Appendix B.1.
    /// </summary>
    public const string JwtVcJson = "jwt_vc_json";

    /// <summary>
    /// W3C Verifiable Presentation secured as a JWT (<c>jwt_vp_json</c>).
    /// Defined in OID4VP 1.0 Appendix B.1.
    /// </summary>
    public const string JwtVpJson = "jwt_vp_json";

    //ISO mdoc format — defined in ISO/IEC 18013-5, referenced by OID4VP 1.0 Appendix B.2.

    /// <summary>
    /// ISO/IEC 18013-5 mobile document format identifier (<c>mso_mdoc</c>).
    /// Defined in ISO/IEC 18013-5 and referenced by OID4VP 1.0 Appendix B.2.
    /// </summary>
    public const string MsoMdoc = "mso_mdoc";


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>jwt_vc_json</c>.</summary>
    public static bool IsJwtVcJson(string value) =>
        string.Equals(value, JwtVcJson, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>jwt_vp_json</c>.</summary>
    public static bool IsJwtVpJson(string value) =>
        string.Equals(value, JwtVpJson, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>mso_mdoc</c>.</summary>
    public static bool IsMsoMdoc(string value) =>
        string.Equals(value, MsoMdoc, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known credential format identifier,
    /// or the original value when not recognized. Comparison is case-sensitive
    /// per OID4VP 1.0 Appendix B.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsJwtVcJson(value) => JwtVcJson,
        _ when IsJwtVpJson(value) => JwtVpJson,
        _ when IsMsoMdoc(value) => MsoMdoc,
        _ => value
    };
}
