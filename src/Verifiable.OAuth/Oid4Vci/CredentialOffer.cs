using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The neutral information model of an OID4VCI 1.0 §4.1.1 Credential Offer — the object a
/// Credential Issuer composes and hands to the Wallet (by value as a QR/deep link, or by
/// reference as a URL) to initiate issuance. Serialize it with
/// <see cref="CredentialOfferSerializer"/>.
/// </summary>
/// <remarks>
/// The library owns only the wire format; the Issuer application composes the offer out-of-band
/// when it provisions the Pre-Authorized Code (or sets up the Authorization Code Flow context).
/// The <see cref="PreAuthorizedCodeGrant"/> here carries the <c>pre-authorized_code</c> the
/// Wallet later presents to the §6 token endpoint that the
/// <see cref="Server.ValidatePreAuthorizedCodeDelegate"/> validates.
/// </remarks>
[DebuggerDisplay("CredentialOffer Issuer={CredentialIssuer} Configurations={CredentialConfigurationIds.Count}")]
public sealed record CredentialOffer
{
    /// <summary>
    /// §4.1.1 <c>credential_issuer</c> (REQUIRED): the Credential Issuer Identifier the Wallet
    /// resolves §12.2 metadata from. Emitted verbatim (its exact case-sensitive form).
    /// </summary>
    public required Uri CredentialIssuer { get; init; }

    /// <summary>
    /// §4.1.1 <c>credential_configuration_ids</c> (REQUIRED, non-empty): identifiers into the
    /// issuer's <c>credential_configurations_supported</c> metadata.
    /// </summary>
    public required IReadOnlyList<string> CredentialConfigurationIds { get; init; }

    /// <summary>
    /// The §4.1.1 <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c> grant block, or
    /// <see langword="null"/> when this offer does not advertise the Pre-Authorized Code Flow.
    /// </summary>
    public PreAuthorizedCodeOfferGrant? PreAuthorizedCodeGrant { get; init; }

    /// <summary>
    /// The §4.1.1 <c>authorization_code</c> grant block, or <see langword="null"/> when this
    /// offer does not advertise the Authorization Code Flow.
    /// </summary>
    public AuthorizationCodeOfferGrant? AuthorizationCodeGrant { get; init; }
}


/// <summary>
/// The OID4VCI 1.0 §4.1.1 <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c> grant
/// block of a <see cref="CredentialOffer"/>.
/// </summary>
[DebuggerDisplay("PreAuthorizedCodeOfferGrant TxCodeRequired={TxCode is not null}")]
public sealed record PreAuthorizedCodeOfferGrant
{
    /// <summary>
    /// <c>pre-authorized_code</c> (REQUIRED): the short-lived, single-use code the Wallet
    /// presents to the §6 token endpoint.
    /// </summary>
    public required string PreAuthorizedCode { get; init; }

    /// <summary>
    /// The <c>tx_code</c> requirement. A non-<see langword="null"/> value — <em>even an empty
    /// one</em> (<see cref="TxCodeRequirement.Empty"/>) — signals that a Transaction Code is
    /// required with the Token Request; <see langword="null"/> means none is expected.
    /// </summary>
    public TxCodeRequirement? TxCode { get; init; }

    /// <summary>
    /// The optional <c>authorization_server</c> hint when the issuer metadata lists multiple
    /// Authorization Servers.
    /// </summary>
    public string? AuthorizationServer { get; init; }
}


/// <summary>
/// The OID4VCI 1.0 §4.1.1 <c>tx_code</c> requirement object. Its mere presence on a
/// <see cref="PreAuthorizedCodeOfferGrant"/> signals a Transaction Code is required; the members
/// are display hints, all optional. An all-unset value serializes to <c>{}</c>.
/// </summary>
[DebuggerDisplay("TxCodeRequirement InputMode={InputMode} Length={Length}")]
public sealed record TxCodeRequirement
{
    /// <summary>An empty requirement — a Transaction Code is required with no rendering hints.</summary>
    public static TxCodeRequirement Empty { get; } = new();

    /// <summary>
    /// <c>input_mode</c> — the input character set (<see cref="TxCodeInputModes.Numeric"/> or
    /// <see cref="TxCodeInputModes.Text"/>); <see langword="null"/> defaults to numeric.
    /// </summary>
    public string? InputMode { get; init; }

    /// <summary><c>length</c> — the Transaction Code length, or <see langword="null"/>.</summary>
    public int? Length { get; init; }

    /// <summary>
    /// <c>description</c> — guidance on obtaining the Transaction Code (§4.1.1: MUST NOT exceed
    /// 300 characters), or <see langword="null"/>.
    /// </summary>
    public string? Description { get; init; }
}


/// <summary>
/// The OID4VCI 1.0 §4.1.1 <c>authorization_code</c> grant block of a <see cref="CredentialOffer"/>.
/// </summary>
[DebuggerDisplay("AuthorizationCodeOfferGrant IssuerState={IssuerState}")]
public sealed record AuthorizationCodeOfferGrant
{
    /// <summary>
    /// <c>issuer_state</c> (OPTIONAL): opaque value the Wallet MUST echo as the
    /// <c>issuer_state</c> Authorization Request parameter when it uses this grant.
    /// </summary>
    public string? IssuerState { get; init; }

    /// <summary>
    /// The optional <c>authorization_server</c> hint when the issuer metadata lists multiple
    /// Authorization Servers.
    /// </summary>
    public string? AuthorizationServer { get; init; }
}
