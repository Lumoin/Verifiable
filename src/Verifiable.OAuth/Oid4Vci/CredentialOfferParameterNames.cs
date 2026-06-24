using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Well-known JSON member NAMES for the OID4VCI 1.0 §4.1.1 Credential Offer object and the
/// transport query parameters that carry it (§4.1.2/§4.1.3). The grant-block keys reuse the
/// grant-type identifiers in <see cref="WellKnownGrantTypes"/>; <c>credential_issuer</c>
/// reuses <see cref="CredentialIssuerMetadataParameterNames.CredentialIssuer"/>; the
/// <c>pre-authorized_code</c> / <c>tx_code</c> names reuse
/// <see cref="OAuthRequestParameterNames"/>.
/// </summary>
public static class CredentialOfferParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="CredentialOffer"/>.</summary>
    public static ReadOnlySpan<byte> CredentialOfferUtf8 => "credential_offer"u8;

    /// <summary>
    /// The <c>credential_offer</c> transport query parameter (§4.1.2) — carries the offer object
    /// by value (URL-encoded JSON). Mutually exclusive with <see cref="CredentialOfferUri"/>.
    /// </summary>
    public static readonly string CredentialOffer = Utf8Constants.ToInternedString(CredentialOfferUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialOfferUri"/>.</summary>
    public static ReadOnlySpan<byte> CredentialOfferUriUtf8 => "credential_offer_uri"u8;

    /// <summary>
    /// The <c>credential_offer_uri</c> transport query parameter (§4.1.3) — carries a URL the
    /// Wallet GETs to retrieve the offer object. Mutually exclusive with
    /// <see cref="CredentialOffer"/>.
    /// </summary>
    public static readonly string CredentialOfferUri = Utf8Constants.ToInternedString(CredentialOfferUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>
    /// The <c>id</c> request field that identifies which stored Credential Offer the §4.1.3
    /// Credential Offer Endpoint serves — the value embedded in the <c>credential_offer_uri</c>.
    /// </summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialConfigurationIds"/>.</summary>
    public static ReadOnlySpan<byte> CredentialConfigurationIdsUtf8 => "credential_configuration_ids"u8;

    /// <summary>
    /// <c>credential_configuration_ids</c> — REQUIRED (§4.1.1). A non-empty array of identifiers
    /// into the <c>credential_configurations_supported</c> Credential Issuer metadata.
    /// </summary>
    public static readonly string CredentialConfigurationIds = Utf8Constants.ToInternedString(CredentialConfigurationIdsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Grants"/>.</summary>
    public static ReadOnlySpan<byte> GrantsUtf8 => "grants"u8;

    /// <summary>
    /// <c>grants</c> — OPTIONAL (§4.1.1). Object mapping each offered Grant Type identifier to
    /// its parameters.
    /// </summary>
    public static readonly string Grants = Utf8Constants.ToInternedString(GrantsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IssuerState"/>.</summary>
    public static ReadOnlySpan<byte> IssuerStateUtf8 => "issuer_state"u8;

    /// <summary>
    /// <c>issuer_state</c> — OPTIONAL (§4.1.1, <c>authorization_code</c> grant). Opaque value the
    /// Wallet echoes in the subsequent Authorization Request.
    /// </summary>
    public static readonly string IssuerState = Utf8Constants.ToInternedString(IssuerStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationServer"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationServerUtf8 => "authorization_server"u8;

    /// <summary>
    /// <c>authorization_server</c> — OPTIONAL (§4.1.1). Identifies which Authorization Server to
    /// use when the Credential Issuer metadata lists multiple.
    /// </summary>
    public static readonly string AuthorizationServer = Utf8Constants.ToInternedString(AuthorizationServerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InputMode"/>.</summary>
    public static ReadOnlySpan<byte> InputModeUtf8 => "input_mode"u8;

    /// <summary>
    /// <c>input_mode</c> — OPTIONAL (§4.1.1, <c>tx_code</c>). The Transaction Code input
    /// character set; see <see cref="TxCodeInputModes"/>. Defaults to <c>numeric</c>.
    /// </summary>
    public static readonly string InputMode = Utf8Constants.ToInternedString(InputModeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Length"/>.</summary>
    public static ReadOnlySpan<byte> LengthUtf8 => "length"u8;

    /// <summary><c>length</c> — OPTIONAL (§4.1.1, <c>tx_code</c>). The Transaction Code length.</summary>
    public static readonly string Length = Utf8Constants.ToInternedString(LengthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Description"/>.</summary>
    public static ReadOnlySpan<byte> DescriptionUtf8 => "description"u8;

    /// <summary>
    /// <c>description</c> — OPTIONAL (§4.1.1, <c>tx_code</c>). Guidance on how the Holder obtains
    /// the Transaction Code; MUST NOT exceed 300 characters.
    /// </summary>
    public static readonly string Description = Utf8Constants.ToInternedString(DescriptionUtf8);
}


/// <summary>
/// The defined <c>tx_code.input_mode</c> values (OID4VCI 1.0 §4.1.1).
/// </summary>
public static class TxCodeInputModes
{
    /// <summary>The UTF-8 source literal of <see cref="Numeric"/>.</summary>
    public static ReadOnlySpan<byte> NumericUtf8 => "numeric"u8;

    /// <summary><c>numeric</c> — only digits (the default).</summary>
    public static readonly string Numeric = Utf8Constants.ToInternedString(NumericUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Text"/>.</summary>
    public static ReadOnlySpan<byte> TextUtf8 => "text"u8;

    /// <summary><c>text</c> — any characters.</summary>
    public static readonly string Text = Utf8Constants.ToInternedString(TextUtf8);
}
