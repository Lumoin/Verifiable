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
/// HAIP 1.0 §5.2 mandates that for signed requests the Verifier MUST use, and the
/// Wallet MUST accept, the <see cref="X509Hash"/> prefix. The library also supports
/// <see cref="X509SanDns"/> (used by deployed ecosystems), <see cref="VerifierAttestation"/>,
/// <see cref="OpenIdFederation"/>, and <see cref="DecentralizedIdentifier"/>.
/// </para>
/// </remarks>
public static class WellKnownClientIdPrefixes
{
    /// <summary>
    /// The <c>redirect_uri</c> prefix. The Client Identifier is the Verifier's redirect
    /// URI. Requests using this prefix cannot be signed — no trusted key is available.
    /// Not usable under HAIP 1.0.
    /// </summary>
    public static readonly ClientIdPrefix RedirectUri = new("redirect_uri");

    /// <summary>
    /// The <c>decentralized_identifier</c> prefix. The Client Identifier is a DID.
    /// The JAR must be signed with a key from the DID Document's
    /// <c>verificationMethod</c> property.
    /// </summary>
    public static readonly ClientIdPrefix DecentralizedIdentifier = new("decentralized_identifier");

    /// <summary>
    /// The <c>verifier_attestation</c> prefix. The JAR header carries a Verifier
    /// Attestation JWT in the <c>jwt</c> JOSE header parameter. The JAR must be
    /// signed with the key in the attestation's <c>cnf</c> claim.
    /// </summary>
    public static readonly ClientIdPrefix VerifierAttestation = new("verifier_attestation");

    /// <summary>
    /// The <c>x509_san_dns</c> prefix. The Client Identifier is a DNS name that
    /// must match a DNS SAN entry in the leaf X.509 certificate carried in the
    /// <c>x5c</c> JOSE header of the signed JAR.
    /// </summary>
    public static readonly ClientIdPrefix X509SanDns = new("x509_san_dns");

    /// <summary>
    /// The <c>x509_hash</c> prefix. The Client Identifier is the base64url-encoded
    /// SHA-256 hash of the leaf X.509 certificate carried in the <c>x5c</c> JOSE
    /// header of the signed JAR. HAIP 1.0 §5.2 mandates this prefix for signed
    /// requests; HAIP additionally forbids a self-signed signing certificate and
    /// forbids carrying the trust anchor in <c>x5c</c>.
    /// </summary>
    public static readonly ClientIdPrefix X509Hash = new("x509_hash");

    /// <summary>
    /// The <c>openid_federation</c> prefix. The Client Identifier is an OpenID
    /// Federation Entity Identifier. The Verifier metadata is obtained from the
    /// Trust Chain.
    /// </summary>
    public static readonly ClientIdPrefix OpenIdFederation = new("openid_federation");


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="VerifierAttestation"/> prefix.
    /// </summary>
    public static bool IsVerifierAttestation(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(VerifierAttestation.Value + ":", StringComparison.Ordinal);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="X509SanDns"/> prefix.
    /// </summary>
    public static bool IsX509SanDns(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(X509SanDns.Value + ":", StringComparison.Ordinal);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="RedirectUri"/> prefix per OID4VP 1.0 §5.9.3.
    /// </summary>
    public static bool IsRedirectUri(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(RedirectUri.Value + ":", StringComparison.Ordinal);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="DecentralizedIdentifier"/> prefix.
    /// </summary>
    public static bool IsDecentralizedIdentifier(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(DecentralizedIdentifier.Value + ":", StringComparison.Ordinal);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="X509Hash"/> prefix.
    /// </summary>
    public static bool IsX509Hash(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(X509Hash.Value + ":", StringComparison.Ordinal);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="clientId"/> uses the
    /// <see cref="OpenIdFederation"/> prefix.
    /// </summary>
    public static bool IsOpenIdFederation(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        return clientId.StartsWith(OpenIdFederation.Value + ":", StringComparison.Ordinal);
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


    /// <summary>
    /// Extracts the <see cref="ClientIdPrefix"/> from a prefixed
    /// <c>client_id</c> value. Returns <see langword="false"/> when no
    /// <c>:</c> is present or the prefix portion is empty.
    /// </summary>
    public static bool TryReadPrefix(string clientId, out ClientIdPrefix prefix)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        int colon = clientId.IndexOf(':', StringComparison.Ordinal);
        if(colon <= 0)
        {
            prefix = default;

            return false;
        }

        prefix = new ClientIdPrefix(clientId[..colon]);

        return true;
    }
}
