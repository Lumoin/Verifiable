using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Well-known JSON member NAMES for the OID4VCI 1.0 §8 Credential Request and Credential
/// Response, plus the §8.3.1.2 Credential Error Response codes. These are the wire keys and
/// error strings the Credential Endpoint reads and emits; their VALUES are deployment data.
/// </summary>
/// <remarks>
/// Grouped here so the request parser (in <c>Verifiable.Json</c>) and the endpoint (in
/// <c>Verifiable.OAuth</c>) name the same wire shape from one source. See
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §8</see>.
/// </remarks>
public static class Oid4VciCredentialParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="CredentialConfigurationId"/>.</summary>
    public static ReadOnlySpan<byte> CredentialConfigurationIdUtf8 => "credential_configuration_id"u8;

    /// <summary>
    /// §8.2 <c>credential_configuration_id</c> — identifies one of the keys in the
    /// <c>credential_configurations_supported</c> Credential Issuer metadata. Mutually
    /// exclusive with <see cref="CredentialIdentifier"/>.
    /// </summary>
    public static readonly string CredentialConfigurationId = Utf8Constants.ToInternedString(CredentialConfigurationIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialIdentifier"/>.</summary>
    public static ReadOnlySpan<byte> CredentialIdentifierUtf8 => "credential_identifier"u8;

    /// <summary>
    /// §8.2 <c>credential_identifier</c> — identifies a Credential Dataset returned in an
    /// <c>authorization_details</c> of type <c>openid_credential</c>. Mutually exclusive with
    /// <see cref="CredentialConfigurationId"/>.
    /// </summary>
    public static readonly string CredentialIdentifier = Utf8Constants.ToInternedString(CredentialIdentifierUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Proofs"/>.</summary>
    public static ReadOnlySpan<byte> ProofsUtf8 => "proofs"u8;

    /// <summary>
    /// §8.2 <c>proofs</c> — object whose single member is named for the proof type
    /// (<see cref="JwtProofType"/> et al.) and whose value is a non-empty array of proofs of
    /// possession of the holder key material the issued Credential binds to.
    /// </summary>
    public static readonly string Proofs = Utf8Constants.ToInternedString(ProofsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwtProofType"/>.</summary>
    public static ReadOnlySpan<byte> JwtProofTypeUtf8 => "jwt"u8;

    /// <summary>
    /// The <c>jwt</c> proof type (OID4VCI 1.0 Appendix F) — each entry is a compact JWS with
    /// <c>typ: openid4vci-proof+jwt</c> carrying the holder key, the Credential Issuer
    /// audience, and the <c>c_nonce</c>.
    /// </summary>
    public static readonly string JwtProofType = Utf8Constants.ToInternedString(JwtProofTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DiVpProofType"/>.</summary>
    public static ReadOnlySpan<byte> DiVpProofTypeUtf8 => "di_vp"u8;

    /// <summary>
    /// The <c>di_vp</c> proof type (OID4VCI 1.0 Appendix F.2) — each entry is a W3C Verifiable
    /// Presentation JSON object secured with a Data Integrity Proof, carrying the holder key, the
    /// Credential Issuer (as the proof <c>domain</c>), and the <c>c_nonce</c> (as the proof
    /// <c>challenge</c>). Unlike <see cref="JwtProofType"/>, its array entries are objects, not
    /// strings.
    /// </summary>
    public static readonly string DiVpProofType = Utf8Constants.ToInternedString(DiVpProofTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Credentials"/>.</summary>
    public static ReadOnlySpan<byte> CredentialsUtf8 => "credentials"u8;

    /// <summary>
    /// §8.3 <c>credentials</c> — array of one or more issued Credential objects, each carrying
    /// a <see cref="Credential"/> member.
    /// </summary>
    public static readonly string Credentials = Utf8Constants.ToInternedString(CredentialsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Credential"/>.</summary>
    public static ReadOnlySpan<byte> CredentialUtf8 => "credential"u8;

    /// <summary>
    /// §8.3 <c>credential</c> — one issued Credential. A string for string-encoded formats
    /// (<c>dc+sd-jwt</c>) and base64url-encoded binary formats (mdoc).
    /// </summary>
    public static readonly string Credential = Utf8Constants.ToInternedString(CredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NotificationId"/>.</summary>
    public static ReadOnlySpan<byte> NotificationIdUtf8 => "notification_id"u8;

    /// <summary>
    /// §8.3 <c>notification_id</c> — identifies the issued Credentials in a later §11.1
    /// Notification Request.
    /// </summary>
    public static readonly string NotificationId = Utf8Constants.ToInternedString(NotificationIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialIdentifiers"/>.</summary>
    public static ReadOnlySpan<byte> CredentialIdentifiersUtf8 => "credential_identifiers"u8;

    /// <summary>
    /// §6.2 <c>credential_identifiers</c> — REQUIRED in each <c>openid_credential</c>
    /// authorization details object of the Token Response: a non-empty array of strings, each
    /// identifying a Credential Dataset issuable with the returned access token. The Wallet
    /// presents one as the §8.2 <c>credential_identifier</c> in a subsequent Credential Request.
    /// </summary>
    public static readonly string CredentialIdentifiers = Utf8Constants.ToInternedString(CredentialIdentifiersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TransactionId"/>.</summary>
    public static ReadOnlySpan<byte> TransactionIdUtf8 => "transaction_id"u8;

    /// <summary>
    /// §8.3 / §9.1 <c>transaction_id</c> — identifies a Deferred Issuance transaction. The
    /// Credential Response carries it (HTTP 202) when issuance cannot complete immediately;
    /// the Wallet later presents it at the §9 Deferred Credential Endpoint.
    /// </summary>
    public static readonly string TransactionId = Utf8Constants.ToInternedString(TransactionIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Interval"/>.</summary>
    public static ReadOnlySpan<byte> IntervalUtf8 => "interval"u8;

    /// <summary>
    /// §8.3 <c>interval</c> — the minimum number of seconds the Wallet SHOULD wait before
    /// polling the Deferred Credential Endpoint again. REQUIRED whenever
    /// <c>transaction_id</c> is present.
    /// </summary>
    public static readonly string Interval = Utf8Constants.ToInternedString(IntervalUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Event"/>.</summary>
    public static ReadOnlySpan<byte> EventUtf8 => "event"u8;

    /// <summary>
    /// §11.1 <c>event</c> — the type of the notification event; values per
    /// <see cref="Oid4VciNotificationEvents"/>.
    /// </summary>
    public static readonly string Event = Utf8Constants.ToInternedString(EventUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EventDescription"/>.</summary>
    public static ReadOnlySpan<byte> EventDescriptionUtf8 => "event_description"u8;

    /// <summary>
    /// §11.1 <c>event_description</c> — optional human-readable ASCII text describing the
    /// event.
    /// </summary>
    public static readonly string EventDescription = Utf8Constants.ToInternedString(EventDescriptionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialResponseEncryption"/>.</summary>
    public static ReadOnlySpan<byte> CredentialResponseEncryptionUtf8 => "credential_response_encryption"u8;

    /// <summary>
    /// §8.2 / §9.1 <c>credential_response_encryption</c> — the request object asking for an
    /// encrypted (Deferred) Credential Response, carrying <c>jwk</c>, <c>enc</c>, and the
    /// optional <c>zip</c>.
    /// </summary>
    public static readonly string CredentialResponseEncryption = Utf8Constants.ToInternedString(CredentialResponseEncryptionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jwk"/>.</summary>
    public static ReadOnlySpan<byte> JwkUtf8 => "jwk"u8;

    /// <summary>§8.2 <c>jwk</c> — the single public key the response is encrypted to.</summary>
    public static readonly string Jwk = Utf8Constants.ToInternedString(JwkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Enc"/>.</summary>
    public static ReadOnlySpan<byte> EncUtf8 => "enc"u8;

    /// <summary>§8.2 <c>enc</c> — the JWE content encryption algorithm for the response.</summary>
    public static readonly string Enc = Utf8Constants.ToInternedString(EncUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Zip"/>.</summary>
    public static ReadOnlySpan<byte> ZipUtf8 => "zip"u8;

    /// <summary>§8.2 <c>zip</c> — the optional JWE compression algorithm applied before encryption.</summary>
    public static readonly string Zip = Utf8Constants.ToInternedString(ZipUtf8);
}


/// <summary>
/// The OID4VCI 1.0 §8.3.1.2 Credential Error Response codes. The Credential Endpoint emits one
/// of these (HTTP 400) when the application's issuance seam refuses the request, taking
/// precedence over the generic <c>invalid_request</c> per §8.3.1.2.
/// </summary>
public static class Oid4VciCredentialErrors
{
    /// <summary>The UTF-8 source literal of <see cref="InvalidCredentialRequest"/>.</summary>
    public static ReadOnlySpan<byte> InvalidCredentialRequestUtf8 => "invalid_credential_request"u8;

    /// <summary>
    /// <c>invalid_credential_request</c> — the request is missing a required parameter,
    /// includes an unsupported parameter or value, repeats a parameter, or is otherwise
    /// malformed.
    /// </summary>
    public static readonly string InvalidCredentialRequest = Utf8Constants.ToInternedString(InvalidCredentialRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UnknownCredentialConfiguration"/>.</summary>
    public static ReadOnlySpan<byte> UnknownCredentialConfigurationUtf8 => "unknown_credential_configuration"u8;

    /// <summary><c>unknown_credential_configuration</c> — the requested Credential Configuration is unknown.</summary>
    public static readonly string UnknownCredentialConfiguration = Utf8Constants.ToInternedString(UnknownCredentialConfigurationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UnknownCredentialIdentifier"/>.</summary>
    public static ReadOnlySpan<byte> UnknownCredentialIdentifierUtf8 => "unknown_credential_identifier"u8;

    /// <summary><c>unknown_credential_identifier</c> — the requested Credential identifier is unknown.</summary>
    public static readonly string UnknownCredentialIdentifier = Utf8Constants.ToInternedString(UnknownCredentialIdentifierUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidProof"/>.</summary>
    public static ReadOnlySpan<byte> InvalidProofUtf8 => "invalid_proof"u8;

    /// <summary>
    /// <c>invalid_proof</c> — the <c>proofs</c> parameter is missing, one of the key proofs is
    /// invalid, or at least one key proof carries no <c>c_nonce</c> (§7.2).
    /// </summary>
    public static readonly string InvalidProof = Utf8Constants.ToInternedString(InvalidProofUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidNonce"/>.</summary>
    public static ReadOnlySpan<byte> InvalidNonceUtf8 => "invalid_nonce"u8;

    /// <summary>
    /// <c>invalid_nonce</c> — at least one key proof carries an invalid <c>c_nonce</c>; the
    /// Wallet should retrieve a fresh one from the Nonce Endpoint (§7).
    /// </summary>
    public static readonly string InvalidNonce = Utf8Constants.ToInternedString(InvalidNonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidEncryptionParameters"/>.</summary>
    public static ReadOnlySpan<byte> InvalidEncryptionParametersUtf8 => "invalid_encryption_parameters"u8;

    /// <summary>
    /// <c>invalid_encryption_parameters</c> — the Credential Request's encryption parameters
    /// are invalid or missing when the Issuer requires an encrypted response.
    /// </summary>
    public static readonly string InvalidEncryptionParameters = Utf8Constants.ToInternedString(InvalidEncryptionParametersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialRequestDenied"/>.</summary>
    public static ReadOnlySpan<byte> CredentialRequestDeniedUtf8 => "credential_request_denied"u8;

    /// <summary>
    /// <c>credential_request_denied</c> — the Credential Request was not accepted; the Wallet
    /// SHOULD treat this as unrecoverable.
    /// </summary>
    public static readonly string CredentialRequestDenied = Utf8Constants.ToInternedString(CredentialRequestDeniedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidTransactionId"/>.</summary>
    public static ReadOnlySpan<byte> InvalidTransactionIdUtf8 => "invalid_transaction_id"u8;

    /// <summary>
    /// §9.3 <c>invalid_transaction_id</c> — the Deferred Credential Request's
    /// <c>transaction_id</c> was not issued by this Credential Issuer or was already used to
    /// obtain a Credential.
    /// </summary>
    public static readonly string InvalidTransactionId = Utf8Constants.ToInternedString(InvalidTransactionIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidNotificationId"/>.</summary>
    public static ReadOnlySpan<byte> InvalidNotificationIdUtf8 => "invalid_notification_id"u8;

    /// <summary>
    /// §11.3 <c>invalid_notification_id</c> — the Notification Request's
    /// <c>notification_id</c> was invalid.
    /// </summary>
    public static readonly string InvalidNotificationId = Utf8Constants.ToInternedString(InvalidNotificationIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InvalidNotificationRequest"/>.</summary>
    public static ReadOnlySpan<byte> InvalidNotificationRequestUtf8 => "invalid_notification_request"u8;

    /// <summary>
    /// §11.3 <c>invalid_notification_request</c> — the Notification Request is missing a
    /// required parameter, includes an unsupported parameter or value, repeats a parameter,
    /// or is otherwise malformed.
    /// </summary>
    public static readonly string InvalidNotificationRequest = Utf8Constants.ToInternedString(InvalidNotificationRequestUtf8);
}
