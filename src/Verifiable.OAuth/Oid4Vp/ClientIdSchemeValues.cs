namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Client identifier scheme values used in OID4VP signed authorization requests.
/// </summary>
/// <remarks>
/// All values are case-sensitive per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>.
/// HAIP 1.0 mandates <see cref="X509Hash"/> for redirect-based flows.
/// </remarks>
public static class ClientIdSchemeValues
{
    /// <summary>
    /// The client identifier is the SHA-256 thumbprint of the leaf X.509 certificate
    /// used to sign the JAR, prefixed with <c>x509_hash</c>.
    /// Mandated by HAIP 1.0.
    /// </summary>
    public const string X509Hash = "x509_hash";

    /// <summary>
    /// The client identifier is the redirect URI. Used in pre-HAIP deployments.
    /// </summary>
    public const string RedirectUri = "redirect_uri";

    /// <summary>
    /// The client identifier is a DID.
    /// </summary>
    public const string Did = "did";
}
