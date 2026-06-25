using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Library-shipped <see cref="IdentifierPurpose"/> instances for every
/// identifier-generation site the library has today. URN scheme:
/// <c>urn:verifiable:identifier-purpose:&lt;namespace&gt;:&lt;name&gt;</c>
/// where <c>&lt;namespace&gt;</c> groups related purposes.
/// </summary>
/// <remarks>
/// <para>
/// One static property per identifier-generation site. Property names carry the namespace prefix
/// (<c>OAuth*</c>, <c>Oid4Vp*</c>, …) so call-site references
/// disambiguate without requiring a fully-qualified URN.
/// </para>
/// <para>
/// Downstream tracks add their own well-known classes (e.g.
/// <c>WellKnownFederationIdentifierPurposes</c> for Federation 1.0's
/// entity-statement and trust-mark identifiers) rather than extending
/// this class. The closed set on this class is "what the library
/// shipped at this point in time"; track-specific additions live near
/// their consuming code.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownIdentifierPurposes")]
public static class WellKnownIdentifierPurposes
{
    //OAuth-side wire identifiers.

    /// <summary>
    /// Flow identifier — the per-request correlation key the dispatcher
    /// stamps onto a new flow when a flow-creating endpoint matches. v7
    /// GUIDs by default so the encoded creation timestamp gives database
    /// indexes and forensic archives time-locality for free.
    /// </summary>
    public static IdentifierPurpose OAuthFlowId =>
        WellKnownServerIdentifierPurposes.FlowId;

    /// <summary>
    /// JWT identifier (JTI) per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 §4.1.7</see> —
    /// stamped onto every issued access token and ID Token to uniquely
    /// identify the token for revocation and replay-defense purposes.
    /// </summary>
    public static IdentifierPurpose OAuthJti { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:jti");

    /// <summary>
    /// Authorization code per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see> —
    /// the one-time code the AS emits to the user-agent for exchange at
    /// the token endpoint.
    /// </summary>
    public static IdentifierPurpose OAuthAuthorizationCode { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:authorization_code");

    /// <summary>
    /// Request-URI token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126 (PAR)</see> —
    /// the opaque handle returned from the PAR endpoint, embedded into
    /// the subsequent Authorization request via the <c>request_uri</c>
    /// parameter.
    /// </summary>
    public static IdentifierPurpose OAuthRequestUriToken { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:request_uri_token");

    /// <summary>
    /// Refresh-flow identifier — the per-rotation correlation key for a
    /// refresh-token exchange. Distinct from <see cref="OAuthFlowId"/>
    /// because the refresh exchange chains a new logical flow off the
    /// original code-exchange flow per RFC 6749 §6.
    /// </summary>
    public static IdentifierPurpose OAuthRefreshFlowId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:refresh_flow_id");

    /// <summary>
    /// Refresh token value per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see> —
    /// the opaque bearer credential the client presents to obtain new access
    /// tokens, rotated on every use per RFC 9700 §2.2.2. A secret: the seam
    /// implementation must source it from tracked, cryptographically strong
    /// entropy.
    /// </summary>
    public static IdentifierPurpose OAuthRefreshToken { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:refresh_token");

    /// <summary>
    /// Dynamic-client-registration <c>client_id</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see> —
    /// the identifier the AS assigns to a newly-registered client.
    /// Replaces the standalone <c>GenerateClientIdDelegate</c>.
    /// </summary>
    public static IdentifierPurpose OAuthClientId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:client_id");

    /// <summary>
    /// Dynamic-client-registration <c>registration_access_token</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see> —
    /// the bearer token the registering client uses for subsequent
    /// configuration-endpoint operations. Replaces the standalone
    /// <c>GenerateRegistrationAccessTokenDelegate</c>.
    /// </summary>
    public static IdentifierPurpose OAuthRegistrationAccessToken { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:registration_access_token");

    /// <summary>
    /// Generic correlation identifier — used by handlers that need a
    /// transient unique string for cross-stage correlation but where the
    /// identifier doesn't have a more specific RFC-defined purpose
    /// (e.g. the UserInfo endpoint's claim-walk correlation key, the
    /// DPoP token-endpoint synthetic flowIds).
    /// </summary>
    public static IdentifierPurpose OAuthCorrelationId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oauth:correlation_id");


    //OID4VP-side wire identifiers.

    /// <summary>
    /// OID4VP Verifier-side PAR handle — the opaque request-URI token
    /// the Verifier returns from its PAR endpoint, embedded into the
    /// subsequent Authorization request to the wallet.
    /// </summary>
    public static IdentifierPurpose Oid4VpParHandle { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oid4vp:par_handle");

    /// <summary>
    /// OID4VP Wallet-side flow identifier — the wallet's per-presentation
    /// correlation key, distinct from the AS-side flowId because the
    /// wallet is the client in this exchange.
    /// </summary>
    public static IdentifierPurpose Oid4VpWalletFlowId { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oid4vp:wallet_flow_id");

    /// <summary>
    /// OID4VP Wallet-side fresh nonce sent on the <c>request_uri_method=post</c>
    /// body per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
    /// The Verifier echoes the value back in the JAR's <c>wallet_nonce</c> claim;
    /// the Wallet verifies the echo before trusting the JAR — the replay defence
    /// the POST round-trip is for.
    /// </summary>
    public static IdentifierPurpose Oid4VpWalletNonce { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:oid4vp:wallet_nonce");


    //SIOPv2-side wire identifiers.

    /// <summary>
    /// SIOPv2 Relying-Party request handle — the opaque per-flow token the RP returns from its
    /// request-preparation endpoint, carried in the <c>request_uri</c> and echoed by the Wallet as
    /// the <c>state</c> on the Self-Issued ID Token response. The internal flow identifier never
    /// leaves the server process; this handle is what crosses the wire.
    /// </summary>
    public static IdentifierPurpose SiopRequestHandle { get; } =
        IdentifierPurpose.Create("urn:verifiable:identifier-purpose:siop:request_handle");
}
