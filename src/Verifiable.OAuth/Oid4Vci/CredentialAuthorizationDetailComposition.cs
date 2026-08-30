using System.Text;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Composes the OID4VCI 1.0 section 5.1.1 <c>authorization_details</c> request value: a JSON array
/// with one RFC 9396 object of type <c>openid_credential</c> naming the Credential Configuration to
/// authorize, with <c>locations</c> carrying the Credential Issuer Identifier when the issuer
/// metadata names separate authorization servers. The composed string is the VALUE of the
/// <see cref="OAuthRequestParameterNames.AuthorizationDetails"/> parameter on an authorization
/// request (RFC 9126 pushed or front-channel), matching the shape the server-side
/// <see cref="OpenIdCredentialAuthorizationDetailHandler"/> validates at receipt.
/// </summary>
public static class CredentialAuthorizationDetailComposition
{
    /// <summary>
    /// Composes the section 5.1.1 <c>authorization_details</c> JSON array for one Credential
    /// Configuration. Values are carried verbatim in the same way the sibling request-body
    /// composition does: both are metadata identifiers, not free text.
    /// </summary>
    /// <param name="credentialConfigurationId">The Credential Configuration to request; an identifier into the issuer's <c>credential_configurations_supported</c>.</param>
    /// <param name="credentialIssuerLocation">The Credential Issuer Identifier for <c>locations</c> - REQUIRED by section 5.1.1 when the issuer metadata carries <c>authorization_servers</c>; <see langword="null"/> omits the field.</param>
    /// <returns>The JSON array string to send as the <c>authorization_details</c> parameter value.</returns>
    public static string Compose(string credentialConfigurationId, Uri? credentialIssuerLocation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialConfigurationId);

        StringBuilder builder = new();
        builder.Append("[{\"");
        builder.Append(AuthorizationDetailsParameterNames.Type).Append("\":\"");
        builder.Append(AuthorizationDetailsTypeValues.OpenIdCredential).Append("\",\"");
        builder.Append(Oid4VciCredentialParameterNames.CredentialConfigurationId).Append("\":\"");
        builder.Append(credentialConfigurationId).Append('"');

        if(credentialIssuerLocation is not null)
        {
            builder.Append(",\"").Append(AuthorizationDetailsParameterNames.Locations).Append("\":[\"");
            builder.Append(credentialIssuerLocation.OriginalString).Append("\"]");
        }

        builder.Append("}]");

        return builder.ToString();
    }
}
