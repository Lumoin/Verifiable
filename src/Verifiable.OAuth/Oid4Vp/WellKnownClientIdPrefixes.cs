namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Client Identifier Prefix values defined by OID4VP 1.0 §5.9.3.
/// </summary>
/// <remarks>
/// <para>
/// A Client Identifier Prefix is the string before the first <c>:</c> in the
/// <c>client_id</c> Authorization Request parameter. It dictates how the Wallet
/// interprets the Client Identifier and which mechanism it uses to obtain and
/// validate the Verifier's public key for JAR signature verification.
/// </para>
/// <para>
/// HAIP 1.0 mandates that the Wallet MUST support both
/// <see cref="VerifierAttestation"/> and <see cref="X509SanDns"/>, and that the
/// Verifier MUST use one of these two prefixes.
/// </para>
/// </remarks>
public static class WellKnownClientIdPrefixes
{
    /// <summary>
    /// The <c>redirect_uri</c> prefix. The Client Identifier is the Verifier's redirect
    /// URI. Requests using this prefix cannot be signed — no trusted key is available.
    /// Not usable under HAIP 1.0.
    /// </summary>
    public const string RedirectUri = "redirect_uri";

    /// <summary>
    /// The <c>decentralized_identifier</c> prefix. The Client Identifier is a DID.
    /// The JAR must be signed with a key from the DID Document's
    /// <c>verificationMethod</c> property.
    /// </summary>
    public const string DecentralizedIdentifier = "decentralized_identifier";

    /// <summary>
    /// The <c>verifier_attestation</c> prefix. The JAR header carries a Verifier
    /// Attestation JWT in the <c>jwt</c> JOSE header parameter. The JAR must be
    /// signed with the key in the attestation's <c>cnf</c> claim.
    /// HAIP 1.0 mandatory.
    /// </summary>
    public const string VerifierAttestation = "verifier_attestation";

    /// <summary>
    /// The <c>x509_san_dns</c> prefix. The Client Identifier is a DNS name that
    /// must match a DNS SAN entry in the leaf X.509 certificate carried in the
    /// <c>x5c</c> JOSE header of the signed JAR.
    /// HAIP 1.0 mandatory.
    /// </summary>
    public const string X509SanDns = "x509_san_dns";

    /// <summary>
    /// The <c>x509_hash</c> prefix. The Client Identifier is the base64url-encoded
    /// SHA-256 hash of the leaf X.509 certificate carried in the <c>x5c</c> JOSE
    /// header of the signed JAR.
    /// </summary>
    public const string X509Hash = "x509_hash";

    /// <summary>
    /// The <c>openid_federation</c> prefix. The Client Identifier is an OpenID
    /// Federation Entity Identifier. The Verifier metadata is obtained from the
    /// Trust Chain.
    /// </summary>
    public const string OpenIdFederation = "openid_federation";

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="VerifierAttestation"/> prefix.
    /// </summary>
    public static bool IsVerifierAttestation(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(VerifierAttestation + ":", StringComparison.Ordinal);
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="X509SanDns"/> prefix.
    /// </summary>
    public static bool IsX509SanDns(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(X509SanDns + ":", StringComparison.Ordinal);
    }

    /// <summary>
    /// Extracts the original Client Identifier from a prefixed <c>client_id</c> value,
    /// i.e. the part after the first <c>:</c>.
    /// </summary>
    /// <param name="clientId">The full <c>client_id</c> value including prefix.</param>
    /// <returns>
    /// The identifier within the prefix namespace, or the original value unchanged
    /// if no <c>:</c> is present.
    /// </returns>
    public static string StripPrefix(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        int colon = clientId.IndexOf(':', StringComparison.Ordinal);

        return colon >= 0 ? clientId[(colon + 1)..] : clientId;
    }
}