using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The Wallet's declared capabilities serialized into the <c>wallet_metadata</c>
/// the Wallet POSTs to the Verifier's <c>request_uri</c> on the OID4VP 1.0 §5.10
/// <c>request_uri_method=post</c> path. This is the Wallet's Authorization Server
/// metadata (OID4VP 1.0 §10, layered on RFC 8414): a strict Verifier validates
/// the full document, so the discovery members below — not just the encryption
/// JWKS — must be present or the POST is rejected.
/// </summary>
/// <remarks>
/// <para>
/// The values are wallet-declared, so a deployment supplies them via
/// <see cref="Oid4VpWalletConfiguration.WalletCapabilities"/>. <see cref="HaipDefault"/>
/// is a HAIP 1.0 / P-256 baseline used when none is configured; a real wallet
/// SHOULD override at least <see cref="VpFormatsSupportedJson"/> with the exact
/// per-format algorithm hints its credentials and its target verifiers expect —
/// that nested shape is profile-specific and is the member most likely to need
/// tailoring.
/// </para>
/// <para>
/// <see cref="VpFormatsSupportedJson"/> is carried as raw JSON text (not a typed
/// object) because its shape is a nested, profile-defined structure; the Verifier
/// side reads it the same way (<c>WalletMetadataReader.ParseVpFormatsSupportedJson</c>).
/// </para>
/// <para>
/// <strong>Overriding.</strong> Start from <see cref="HaipDefault"/> and change only
/// what your deployment needs with a <c>with</c> expression, then set it on
/// <see cref="Oid4VpWalletConfiguration.WalletCapabilities"/>. The
/// <see cref="Issuer"/> (your real https issuer) and
/// <see cref="AuthorizationEndpoint"/> (the custom scheme you were invoked on, e.g.
/// <c>mdoc-openid4vp://</c> for an mdoc QR) almost always need overriding; narrow
/// <see cref="ClientIdPrefixesSupported"/> to the prefix(es) your target Verifier
/// expects:
/// <code>
/// config = config with
/// {
///     WalletCapabilities = Oid4VpWalletCapabilities.HaipDefault with
///     {
///         Issuer = "https://wallet.lumoin.com",
///         AuthorizationEndpoint = "mdoc-openid4vp://",
///         ClientIdPrefixesSupported = ["x509_san_dns"]
///     }
/// };
/// </code>
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpWalletCapabilities Issuer={Issuer}")]
public sealed record Oid4VpWalletCapabilities
{
    /// <summary>
    /// <c>issuer</c> — the Wallet Authorization Server's issuer identifier.
    /// REQUIRED of AS metadata per RFC 8414 §2, and MUST be an <c>https</c> URL
    /// with no query or fragment — it is the AS's identity, NOT the custom
    /// invocation scheme (that is <see cref="AuthorizationEndpoint"/>). A strict
    /// Verifier rejects a non-<c>https</c> issuer. Deployments MUST override the
    /// placeholder with their real issuer URL.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// <c>authorization_endpoint</c> — the URI the Wallet is invoked on. For a
    /// Wallet this is a custom invocation scheme and a strict Verifier (e.g. the
    /// iDAKTO sandbox) requires it to end with <c>://</c> (e.g.
    /// <c>mdoc-openid4vp://</c>). Per OID4VP 1.0 §10 / RFC 8414 §2.
    /// </summary>
    public required string AuthorizationEndpoint { get; init; }

    /// <summary><c>response_types_supported</c> — the OAuth response types the Wallet issues (OID4VP: <c>vp_token</c>).</summary>
    public required IReadOnlyList<string> ResponseTypesSupported { get; init; }

    /// <summary><c>response_modes_supported</c> — e.g. <c>direct_post.jwt</c>, <c>direct_post</c> (OID4VP 1.0 §8).</summary>
    public required IReadOnlyList<string> ResponseModesSupported { get; init; }

    /// <summary><c>client_id_prefixes_supported</c> — the client-identifier prefixes the Wallet accepts (OID4VP 1.0 §10).</summary>
    public required IReadOnlyList<string> ClientIdPrefixesSupported { get; init; }

    /// <summary><c>request_object_signing_alg_values_supported</c> — JWS algorithms the Wallet accepts on the JAR.</summary>
    public required IReadOnlyList<string> RequestObjectSigningAlgValuesSupported { get; init; }

    /// <summary><c>authorization_encryption_alg_values_supported</c> — JWE key-management algorithms (e.g. <c>ECDH-ES</c>).</summary>
    public required IReadOnlyList<string> AuthorizationEncryptionAlgValuesSupported { get; init; }

    /// <summary><c>authorization_encryption_enc_values_supported</c> — JWE content-encryption algorithms (e.g. <c>A128GCM</c>).</summary>
    public required IReadOnlyList<string> AuthorizationEncryptionEncValuesSupported { get; init; }

    /// <summary>
    /// <c>vp_formats_supported</c> as raw JSON text (object braces included) —
    /// REQUIRED per OID4VP 1.0 §10 / HAIP 1.0 §5.2. A nested object keyed by
    /// credential format identifier with per-format algorithm hints.
    /// </summary>
    public required string VpFormatsSupportedJson { get; init; }


    /// <summary>
    /// HAIP 1.0 / P-256 baseline capabilities used when a deployment configures
    /// none. Covers the response types/modes, client-id schemes, and algorithms
    /// this library implements. Deployments SHOULD override
    /// <see cref="VpFormatsSupportedJson"/> for their exact format profile.
    /// </summary>
    public static Oid4VpWalletCapabilities HaipDefault { get; } = new()
    {
        //issuer is the AS identity — an https URL (RFC 8414 §2); this is a
        //placeholder deployments MUST override with their real issuer.
        //authorization_endpoint is the Wallet's custom invocation scheme (ends with
        //"://"); deployments derive it from the scheme they were invoked on
        //(e.g. mdoc-openid4vp:// for an mdoc QR, openid4vp:// for SD-JWT).
        Issuer = "https://wallet.example.com",
        AuthorizationEndpoint = "openid4vp://",
        //OID4VP issues vp_token; the wire value of ResponseType.VpToken.
        ResponseTypesSupported = [Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken],
        ResponseModesSupported = [WellKnownResponseModes.DirectPostJwt, WellKnownResponseModes.DirectPost],
        ClientIdPrefixesSupported =
        [
            WellKnownClientIdPrefixes.RedirectUri.Value,
            WellKnownClientIdPrefixes.X509SanDns.Value,
            WellKnownClientIdPrefixes.VerifierAttestation.Value,
            WellKnownClientIdPrefixes.OpenIdFederation.Value,
            WellKnownClientIdPrefixes.DecentralizedIdentifier.Value
        ],
        RequestObjectSigningAlgValuesSupported = [WellKnownJwaValues.Es256],
        AuthorizationEncryptionAlgValuesSupported = [WellKnownJweAlgorithms.EcdhEs],
        AuthorizationEncryptionEncValuesSupported =
        [
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            WellKnownJweEncryptionAlgorithms.A256Gcm
        ],
        //Minimal valid baseline; deployments override with their exact per-format hints.
        VpFormatsSupportedJson =
            "{\"dc+sd-jwt\":{\"sd-jwt_alg_values\":[\"ES256\"],\"kb-jwt_alg_values\":[\"ES256\"]}," +
            "\"mso_mdoc\":{\"issuerauth_alg_values\":[-7],\"deviceauth_alg_values\":[-7]}," +
            "\"dc+sd-cwt\":{\"sd-cwt_alg_values\":[-7],\"kb-cwt_alg_values\":[-7]}}"
    };
}
