namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Well-known credential format identifiers defined in the OpenID for Verifiable
/// Presentations specification and related credential format registries.
/// </summary>
public static class DcqlCredentialFormats
{
    /// <summary>
    /// SD-JWT Verifiable Credentials (<c>dc+sd-jwt</c>).
    /// </summary>
    public const string SdJwt = "dc+sd-jwt";

    /// <summary>
    /// SD-CWT Verifiable Credentials (<c>dc+sd-cwt</c>).
    /// </summary>
    /// <remarks>
    /// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
    /// draft-ietf-spice-sd-cwt</see>.
    /// </remarks>
    public const string SdCwt = "dc+sd-cwt";

    /// <summary>
    /// ISO mdoc credentials (<c>mso_mdoc</c>).
    /// </summary>
    public const string MsoMdoc = "mso_mdoc";

    /// <summary>
    /// W3C JSON-LD Verifiable Credentials (<c>ldp_vc</c>).
    /// </summary>
    public const string LdpVc = "ldp_vc";

    /// <summary>
    /// W3C JWT Verifiable Credentials (<c>jwt_vc_json</c>).
    /// </summary>
    public const string JwtVcJson = "jwt_vc_json";
}