using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The OID4VCI view of one RFC 9396 authorization details object of type <c>openid_credential</c>,
/// projected from the generic <see cref="AuthorizationDetail"/> by the built-in
/// <see cref="OpenIdCredentialAuthorizationDetailHandler"/>. The object carries the type
/// <c>openid_credential</c> and a <c>credential_configuration_id</c> per
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §5.1.1</see>.
/// </summary>
/// <remarks>
/// The generic parser extracts the wire shape only; the
/// <see cref="Server.AuthorizationDetailTypeRegistry"/> validates the §5.1.1 requirements (the
/// object's <see cref="Type"/> must have a registered handler and an <c>openid_credential</c>
/// entry must carry a <see cref="CredentialConfigurationId"/>) before the handler projects it
/// into this model for the <see cref="Server.ResolveCredentialAuthorizationDelegate"/> decision
/// seam. Unknown fields inside an <c>openid_credential</c> object are permitted (§5.1.1: the type
/// is never invalid due to unknown fields) and are not carried in this model.
/// </remarks>
[DebuggerDisplay("CredentialAuthorizationDetail Type={Type} ConfigurationId={CredentialConfigurationId}")]
public sealed record CredentialAuthorizationDetail
{
    /// <summary>
    /// The RFC 9396 §2 <c>type</c> (REQUIRED) — <see cref="AuthorizationDetailsTypeValues.OpenIdCredential"/>
    /// for the objects this library processes.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The §5.1.1 <c>credential_configuration_id</c> (REQUIRED for <c>openid_credential</c>):
    /// an identifier into the issuer's <c>credential_configurations_supported</c> metadata.
    /// <see langword="null"/> when absent on the wire — the library rejects that shape before
    /// the decision seam runs.
    /// </summary>
    public string? CredentialConfigurationId { get; init; }

    /// <summary>
    /// The RFC 9396 §2.2 <c>locations</c> common field, or <see langword="null"/> when absent.
    /// OID4VCI 1.0 §5.1.1 requires it to name the Credential Issuer Identifier when the issuer
    /// metadata carries <c>authorization_servers</c> — a deployment fact the decision seam
    /// owns, so the library carries the value without enforcing it.
    /// </summary>
    public IReadOnlyList<string>? Locations { get; init; }
}
