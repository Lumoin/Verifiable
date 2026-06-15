using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Well-known context bag key constants for SIOPv2 Relying-Party request preparation.
/// </summary>
/// <remarks>
/// <para>
/// The Relying-Party application places the transaction inputs on the request context bag before
/// calling <see cref="EndpointServer.DispatchAsync"/> at the request-preparation endpoint:
/// the <c>nonce</c> the Self-Issued ID Token must echo, the <c>client_id</c> the token's
/// <c>aud</c> must equal, and the signing algorithms the RP accepts. The preparation endpoint
/// reads these to mint the <see cref="States.SiopRequestPreparedState"/> the response endpoint
/// later loads.
/// </para>
/// <para>
/// This mirrors <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpContextKeys"/>, where the OID4VP PAR
/// endpoint reads its prepared query, transaction nonce, and decryption key id off the context
/// rather than off the wire — the request-preparation crossing is RP-internal, not a wallet HTTP
/// request.
/// </para>
/// </remarks>
[DebuggerDisplay("SiopVerifierContextKeys")]
public static class SiopVerifierContextKeys
{
    /// <summary>The UTF-8 source literal of <see cref="Nonce"/>.</summary>
    public static ReadOnlySpan<byte> NonceUtf8 => "siop.nonce"u8;

    /// <summary>
    /// The transaction nonce the Self-Issued ID Token MUST echo (§9 REQUIRED).
    /// Value type: <see cref="string"/>.
    /// </summary>
    public static readonly string Nonce = Utf8Constants.ToInternedString(NonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "siop.clientId"u8;

    /// <summary>
    /// The Relying Party's <c>client_id</c> — the expected <c>aud</c> of the Self-Issued ID Token.
    /// When absent, the preparation endpoint falls back to the resolved registration's
    /// <see cref="ClientRecord.ClientId"/>. Value type: <see cref="string"/>.
    /// </summary>
    public static readonly string ClientId = Utf8Constants.ToInternedString(ClientIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AllowedAlgorithms"/>.</summary>
    public static ReadOnlySpan<byte> AllowedAlgorithmsUtf8 => "siop.allowedAlgorithms"u8;

    /// <summary>
    /// The signing algorithms the Relying Party accepts for the Self-Issued ID Token (alg
    /// allow-list; <c>none</c> is always rejected). Value type:
    /// <c>IReadOnlyList&lt;string&gt;</c>.
    /// </summary>
    public static readonly string AllowedAlgorithms = Utf8Constants.ToInternedString(AllowedAlgorithmsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenType"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenTypeUtf8 => "siop.idTokenType"u8;

    /// <summary>
    /// The requested <c>id_token_type</c> (§7), when the Relying Party constrains it. Value type:
    /// <see cref="string"/>.
    /// </summary>
    public static readonly string IdTokenType = Utf8Constants.ToInternedString(IdTokenTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EncryptionKeyId"/>.</summary>
    public static ReadOnlySpan<byte> EncryptionKeyIdUtf8 => "siop.encryptionKeyId"u8;

    /// <summary>
    /// The decryption key id whose public half the Relying Party advertises as its encryption key.
    /// The Wallet encrypts the Self-Issued ID Token JWE to that public key; the response endpoint
    /// resolves the private half through the server's <c>DecryptionKeyResolver</c> to decrypt. The
    /// Relying Party sets this before dispatching the preparation request when it accepts encrypted
    /// responses. Value type: <see cref="string"/>.
    /// </summary>
    public static readonly string EncryptionKeyId = Utf8Constants.ToInternedString(EncryptionKeyIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AllowedEncAlgorithms"/>.</summary>
    public static ReadOnlySpan<byte> AllowedEncAlgorithmsUtf8 => "siop.allowedEncAlgorithms"u8;

    /// <summary>
    /// The content encryption algorithms the Relying Party advertises for an encrypted response (the
    /// SIOP parallel of <c>encrypted_response_enc_values_supported</c>). The encrypted response's JWE
    /// <c>enc</c> header MUST be one of these values. Value type: <c>IReadOnlyList&lt;string&gt;</c>.
    /// </summary>
    public static readonly string AllowedEncAlgorithms = Utf8Constants.ToInternedString(AllowedEncAlgorithmsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UseStaticDiscoveryAudience"/>.</summary>
    public static ReadOnlySpan<byte> UseStaticDiscoveryAudienceUtf8 => "siop.useStaticDiscoveryAudience"u8;

    /// <summary>
    /// Whether the §9.1 Request Object <c>aud</c> is the static-discovery value
    /// (<c>https://self-issued.me/v2</c>) rather than the dynamically discovered issuer. The Relying
    /// Party sets this before dispatching the preparation request. Value type: <see cref="bool"/>.
    /// </summary>
    public static readonly string UseStaticDiscoveryAudience = Utf8Constants.ToInternedString(UseStaticDiscoveryAudienceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestObjectAdditionalHeaderClaims"/>.</summary>
    public static ReadOnlySpan<byte> RequestObjectAdditionalHeaderClaimsUtf8 => "siop.requestObjectAdditionalHeaderClaims"u8;

    /// <summary>
    /// Additional JOSE header claims to merge into the signed §9 Request Object header when it is
    /// built. The SIOPv2 §9 Request Object is the same RFC 9101 <c>oauth-authz-req+jwt</c> artifact
    /// as the OID4VP JAR, so this injects the same client-id-prefix material the wallet resolves the
    /// RP signing key from — the <c>x5c</c> array for <c>x509_san_dns:</c>, the <c>trust_chain</c>
    /// array for <c>openid_federation:</c>, the verifier-attestation <c>jwt</c>, or the <c>kid</c>
    /// verification-method DID URL for <c>decentralized_identifier:</c>. Value type:
    /// <see cref="Verifiable.JCose.JwtHeader"/>. Set by the application before dispatching the
    /// preparation request. The SIOP parallel of
    /// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpContextKeys.JarAdditionalHeaderClaims"/>.
    /// </summary>
    /// <remarks>
    /// The standard <c>alg</c> and <c>typ</c> header entries are the library's to set; any entries
    /// with those keys are ignored by the <see cref="SignSiopRequestObject"/> handler. Per SIOPv2 §9
    /// the appropriate header set depends on the client_id prefix the deployment uses.
    /// </remarks>
    public static readonly string RequestObjectAdditionalHeaderClaims = Utf8Constants.ToInternedString(RequestObjectAdditionalHeaderClaimsUtf8);


    //Output key — set by the preparation endpoint, read by the application after dispatch.

    /// <summary>The UTF-8 source literal of <see cref="RequestHandle"/>.</summary>
    public static ReadOnlySpan<byte> RequestHandleUtf8 => "siop.requestHandle"u8;

    /// <summary>
    /// The opaque per-flow request handle the preparation endpoint mints. The application reads it
    /// after dispatch to echo as the <c>state</c> the Wallet returns on the response POST, so
    /// <see cref="AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/> can map it back to
    /// the internal flow identifier. Value type: <see cref="string"/>.
    /// </summary>
    public static readonly string RequestHandle = Utf8Constants.ToInternedString(RequestHandleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestObject"/>.</summary>
    public static ReadOnlySpan<byte> RequestObjectUtf8 => "siop.requestObject"u8;

    /// <summary>
    /// The signed §9 Request Object compact JWS the request-object endpoint produces. Set by the
    /// <see cref="OAuthActionExecutor"/> after signing and read by the application to write into the
    /// HTTP response body with media type <c>application/oauth-authz-req+jwt</c> at the
    /// <c>request_uri</c> endpoint — the SIOP parallel of the OID4VP
    /// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpContextKeys"/> compact-JAR slot. Value type:
    /// <see cref="string"/>.
    /// </summary>
    public static readonly string RequestObject = Utf8Constants.ToInternedString(RequestObjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GeneratedRequestUri"/>.</summary>
    public static ReadOnlySpan<byte> GeneratedRequestUriUtf8 => "siop.generatedRequestUri"u8;

    /// <summary>
    /// The absolute §9 <c>request_uri</c> the preparation endpoint composed for the by-reference
    /// flow. Set by the preparation endpoint after it resolves the URL through
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>; read by the application
    /// after dispatch to carry in a QR code or deep link. Value type: <see cref="System.Uri"/>.
    /// </summary>
    public static readonly string GeneratedRequestUri = Utf8Constants.ToInternedString(GeneratedRequestUriUtf8);
}
