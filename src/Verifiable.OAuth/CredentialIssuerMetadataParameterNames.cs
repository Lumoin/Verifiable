using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the OpenID for Verifiable Credential
/// Issuance (OID4VCI) credential-issuer metadata document. These are
/// JSON keys appearing in the credential issuer's metadata document.
/// </summary>
/// <remarks>
/// These are the NAMES of credential-issuer metadata parameters (e.g.,
/// <c>"credential_endpoint"</c>, <c>"deferred_credential_endpoint"</c>),
/// not their VALUES. Values are deployment-specific URLs.
/// </remarks>
public static class CredentialIssuerMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="CredentialIssuer"/>.</summary>
    public static ReadOnlySpan<byte> CredentialIssuerUtf8 => "credential_issuer"u8;

    /// <summary>
    /// <c>credential_issuer</c> — REQUIRED (§12.2.4). The Credential Issuer's identifier;
    /// MUST equal the identifier the well-known URI string was inserted into.
    /// </summary>
    public static readonly string CredentialIssuer = Utf8Constants.ToInternedString(CredentialIssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationServers"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationServersUtf8 => "authorization_servers"u8;

    /// <summary>
    /// <c>authorization_servers</c> — OPTIONAL (§12.2.4). Identifiers of the OAuth 2.0
    /// Authorization Server(s) the Credential Issuer relies on for authorization.
    /// </summary>
    public static readonly string AuthorizationServers = Utf8Constants.ToInternedString(AuthorizationServersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> CredentialEndpointUtf8 => "credential_endpoint"u8;

    /// <summary>
    /// URL of the credential issuer's credential endpoint.
    /// </summary>
    public static readonly string CredentialEndpoint = Utf8Constants.ToInternedString(CredentialEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NonceEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> NonceEndpointUtf8 => "nonce_endpoint"u8;

    /// <summary>
    /// <c>nonce_endpoint</c> — OPTIONAL (§12.2.4). URL of the Credential Issuer's Nonce
    /// Endpoint (§7). If omitted, the Issuer does not require the use of <c>c_nonce</c>.
    /// </summary>
    public static readonly string NonceEndpoint = Utf8Constants.ToInternedString(NonceEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialConfigurationsSupported"/>.</summary>
    public static ReadOnlySpan<byte> CredentialConfigurationsSupportedUtf8 => "credential_configurations_supported"u8;

    /// <summary>
    /// <c>credential_configurations_supported</c> — REQUIRED (§12.2.4). Object mapping each
    /// supported Credential Configuration identifier to its metadata (format, scope, proof
    /// types, display).
    /// </summary>
    public static readonly string CredentialConfigurationsSupported = Utf8Constants.ToInternedString(CredentialConfigurationsSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Scope"/>.</summary>
    public static ReadOnlySpan<byte> ScopeUtf8 => "scope"u8;

    /// <summary>
    /// <c>scope</c> — OPTIONAL (§12.2.4), a member INSIDE a
    /// <see cref="CredentialConfigurationsSupported"/> configuration object: the OAuth scope a
    /// Wallet uses to request authorization for that configuration. Per §8.2 the requested
    /// configuration's <c>scope</c> MUST be among the scopes the Access Token was granted.
    /// </summary>
    public static readonly string Scope = Utf8Constants.ToInternedString(ScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BatchSize"/>.</summary>
    public static ReadOnlySpan<byte> BatchSizeUtf8 => "batch_size"u8;

    /// <summary>
    /// <c>batch_size</c> — REQUIRED (§12.2.4) inside <see cref="BatchCredentialIssuance"/>: the
    /// maximum number of proofs (and therefore Credentials) a single Credential Request may
    /// carry. Its absence means the Issuer does not support batch issuance.
    /// </summary>
    public static readonly string BatchSize = Utf8Constants.ToInternedString(BatchSizeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BatchCredentialIssuance"/>.</summary>
    public static ReadOnlySpan<byte> BatchCredentialIssuanceUtf8 => "batch_credential_issuance"u8;

    /// <summary>
    /// <c>batch_credential_issuance</c> — OPTIONAL (§12.2.4). Object signalling support for
    /// issuing multiple Credentials per request (the <c>batch_size</c> upper bound).
    /// </summary>
    public static readonly string BatchCredentialIssuance = Utf8Constants.ToInternedString(BatchCredentialIssuanceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Display"/>.</summary>
    public static ReadOnlySpan<byte> DisplayUtf8 => "display"u8;

    /// <summary>
    /// <c>display</c> — OPTIONAL (§12.2.4). Array of per-language display objects for the
    /// Credential Issuer.
    /// </summary>
    public static readonly string Display = Utf8Constants.ToInternedString(DisplayUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialMetadata"/>.</summary>
    public static ReadOnlySpan<byte> CredentialMetadataUtf8 => "credential_metadata"u8;

    /// <summary>
    /// <c>credential_metadata</c> — OPTIONAL (§12.2.4), a member INSIDE a
    /// <see cref="CredentialConfigurationsSupported"/> configuration object: "Object containing
    /// information relevant to the usage and display of issued Credentials." Its <see cref="Display"/>
    /// array carries the per-configuration human-readable values the §12.2.2 <c>Accept-Language</c>
    /// negotiation filters.
    /// </summary>
    public static readonly string CredentialMetadata = Utf8Constants.ToInternedString(CredentialMetadataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Name"/>.</summary>
    public static ReadOnlySpan<byte> NameUtf8 => "name"u8;

    /// <summary>
    /// <c>name</c> — a member INSIDE a <see cref="Display"/> entry. For the Credential Issuer's
    /// <c>display</c> the spec marks it OPTIONAL; for a credential configuration's
    /// <c>credential_metadata.display</c> entry §12.2.4 marks it REQUIRED:
    /// "<c>name</c> : REQUIRED. String value of a display name for the Credential."
    /// </summary>
    public static readonly string Name = Utf8Constants.ToInternedString(NameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Locale"/>.</summary>
    public static ReadOnlySpan<byte> LocaleUtf8 => "locale"u8;

    /// <summary>
    /// <c>locale</c> — OPTIONAL (§12.2.4), a member INSIDE a <see cref="Display"/> entry: the
    /// RFC 3066 / BCP 47 language tag the entry's human-readable values are written in. The
    /// §12.2.2 <c>Accept-Language</c> negotiation filters the <c>display</c> array by this tag.
    /// "There MUST be only one object for each language identifier."
    /// </summary>
    public static readonly string Locale = Utf8Constants.ToInternedString(LocaleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Format"/>.</summary>
    public static ReadOnlySpan<byte> FormatUtf8 => "format"u8;

    /// <summary>
    /// <c>format</c> — REQUIRED (§12.2.4), a member INSIDE a
    /// <see cref="CredentialConfigurationsSupported"/> configuration object:
    /// "<c>format</c> : REQUIRED. A JSON string identifying the format of this Credential".
    /// </summary>
    public static readonly string Format = Utf8Constants.ToInternedString(FormatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProofSigningAlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ProofSigningAlgValuesSupportedUtf8 => "proof_signing_alg_values_supported"u8;

    /// <summary>
    /// <c>proof_signing_alg_values_supported</c> — REQUIRED (§12.2.4) inside each
    /// <c>proof_types_supported</c> entry:
    /// "<c>proof_signing_alg_values_supported</c> : REQUIRED. A non-empty array of algorithm
    /// identifiers that the Issuer supports for this proof type."
    /// </summary>
    public static readonly string ProofSigningAlgValuesSupported = Utf8Constants.ToInternedString(ProofSigningAlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwks"/>.</summary>
    public static ReadOnlySpan<byte> JwksUtf8 => "jwks"u8;

    /// <summary>
    /// <c>jwks</c> — REQUIRED (§12.2.4) inside a <see cref="CredentialRequestEncryption"/> object:
    /// "<c>jwks</c> : REQUIRED. A JSON Web Key Set ... that contains one or more public keys, to
    /// be used by the Wallet as an input to a key agreement for encryption of the Credential
    /// Request."
    /// </summary>
    public static readonly string Jwks = Utf8Constants.ToInternedString(JwksUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AlgValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> AlgValuesSupportedUtf8 => "alg_values_supported"u8;

    /// <summary>
    /// <c>alg_values_supported</c> — REQUIRED (§12.2.4) inside a
    /// <see cref="CredentialResponseEncryption"/> object:
    /// "<c>alg_values_supported</c> : REQUIRED. A non-empty array containing a list of the JWE
    /// encryption algorithms (<c>alg</c> values) supported by the Credential Endpoint to encode
    /// the Credential Response in a JWT."
    /// </summary>
    public static readonly string AlgValuesSupported = Utf8Constants.ToInternedString(AlgValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EncValuesSupported"/>.</summary>
    public static ReadOnlySpan<byte> EncValuesSupportedUtf8 => "enc_values_supported"u8;

    /// <summary>
    /// <c>enc_values_supported</c> — REQUIRED (§12.2.4) inside both the
    /// <see cref="CredentialRequestEncryption"/> and <see cref="CredentialResponseEncryption"/>
    /// objects:
    /// "<c>enc_values_supported</c> : REQUIRED. A non-empty array containing a list of the JWE
    /// encryption algorithms (<c>enc</c> values) supported by the Credential Endpoint".
    /// </summary>
    public static readonly string EncValuesSupported = Utf8Constants.ToInternedString(EncValuesSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EncryptionRequired"/>.</summary>
    public static ReadOnlySpan<byte> EncryptionRequiredUtf8 => "encryption_required"u8;

    /// <summary>
    /// <c>encryption_required</c> — REQUIRED (§12.2.4) inside both the
    /// <see cref="CredentialRequestEncryption"/> and <see cref="CredentialResponseEncryption"/>
    /// objects: "<c>encryption_required</c> : REQUIRED. Boolean value specifying whether the
    /// Credential Issuer requires the additional encryption on top of TLS".
    /// </summary>
    public static readonly string EncryptionRequired = Utf8Constants.ToInternedString(EncryptionRequiredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SignedMetadata"/>.</summary>
    public static ReadOnlySpan<byte> SignedMetadataUtf8 => "signed_metadata"u8;

    /// <summary>
    /// <c>signed_metadata</c> — OPTIONAL (§12.2.3). A JWT asserting the metadata values as
    /// claims, typed <c>openidvci-issuer-metadata+jwt</c> with <c>sub</c> = the Credential
    /// Issuer Identifier. It is never a claim inside that JWT.
    /// </summary>
    public static readonly string SignedMetadata = Utf8Constants.ToInternedString(SignedMetadataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BatchCredentialEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> BatchCredentialEndpointUtf8 => "batch_credential_endpoint"u8;

    /// <summary>
    /// URL of the credential issuer's batch credential endpoint.
    /// </summary>
    public static readonly string BatchCredentialEndpoint = Utf8Constants.ToInternedString(BatchCredentialEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeferredCredentialEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> DeferredCredentialEndpointUtf8 => "deferred_credential_endpoint"u8;

    /// <summary>
    /// URL of the credential issuer's deferred credential endpoint.
    /// </summary>
    public static readonly string DeferredCredentialEndpoint = Utf8Constants.ToInternedString(DeferredCredentialEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NotificationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> NotificationEndpointUtf8 => "notification_endpoint"u8;

    /// <summary>
    /// URL of the credential issuer's notification endpoint.
    /// </summary>
    public static readonly string NotificationEndpoint = Utf8Constants.ToInternedString(NotificationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialRequestEncryption"/>.</summary>
    public static ReadOnlySpan<byte> CredentialRequestEncryptionUtf8 => "credential_request_encryption"u8;

    /// <summary>
    /// <c>credential_request_encryption</c> — OPTIONAL (§12.2.4). Object describing the
    /// Issuer's support for encrypting the Credential Request on top of TLS
    /// (<c>jwks</c>, <c>enc_values_supported</c>, <c>zip_values_supported</c>,
    /// <c>encryption_required</c>).
    /// </summary>
    public static readonly string CredentialRequestEncryption = Utf8Constants.ToInternedString(CredentialRequestEncryptionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialResponseEncryption"/>.</summary>
    public static ReadOnlySpan<byte> CredentialResponseEncryptionUtf8 => "credential_response_encryption"u8;

    /// <summary>
    /// <c>credential_response_encryption</c> — OPTIONAL (§12.2.4). Object describing the
    /// Issuer's support for encrypting the Credential Response on top of TLS
    /// (<c>alg_values_supported</c>, <c>enc_values_supported</c>,
    /// <c>zip_values_supported</c>, <c>encryption_required</c>).
    /// </summary>
    public static readonly string CredentialResponseEncryption = Utf8Constants.ToInternedString(CredentialResponseEncryptionUtf8);
}
