using System.Text;
using Verifiable.Core.Text;

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
    /// Configuration, written through <see cref="JsonAppender"/> as the sibling Credential Request
    /// body is: <c>type</c>, <c>credential_configuration_id</c> and each <c>locations</c> entry are
    /// JSON strings escaped as RFC 8259 Section 7 requires ("All Unicode characters may be placed
    /// within the quotation marks, except for the characters that MUST be escaped: quotation mark,
    /// reverse solidus, and the control characters"), so an identifier taken from a Credential Offer
    /// stays the one string value it is and never closes or extends the object.
    /// </summary>
    /// <param name="credentialConfigurationId">The Credential Configuration to request; an identifier into the issuer's <c>credential_configurations_supported</c>.</param>
    /// <param name="credentialIssuerLocation">The Credential Issuer Identifier for <c>locations</c> - REQUIRED by section 5.1.1 when the issuer metadata carries <c>authorization_servers</c>; <see langword="null"/> omits the field.</param>
    /// <returns>The JSON array string to send as the <c>authorization_details</c> parameter value.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="credentialConfigurationId"/> is empty, white space, or holds an
    /// unpaired surrogate. RFC 8259 Section 8.2 names such a string, "a single unpaired UTF-16
    /// surrogate", as one that cannot encode Unicode characters, so the identifier the server reads
    /// would not be the one composed; the identifier is the caller's own argument and is refused here.
    /// </exception>
    public static string Compose(string credentialConfigurationId, Uri? credentialIssuerLocation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialConfigurationId);
        if(TextHygiene.Inspect(credentialConfigurationId, UnpairedSurrogateRule) is not null)
        {
            throw new ArgumentException(
                "The credential_configuration_id holds an unpaired surrogate, which encodes no Unicode character.",
                nameof(credentialConfigurationId));
        }

        StringBuilder builder = JsonAppender.Rent();
        try
        {
            _ = builder.Append("[{");
            bool isFirstMember = true;
            JsonAppender.AppendStringField(
                builder, AuthorizationDetailsParameterNames.Type, AuthorizationDetailsTypeValues.OpenIdCredential, ref isFirstMember);
            JsonAppender.AppendStringField(
                builder, Oid4VciCredentialParameterNames.CredentialConfigurationId, credentialConfigurationId, ref isFirstMember);

            if(credentialIssuerLocation is not null)
            {
                JsonAppender.AppendUriArrayField(
                    builder, AuthorizationDetailsParameterNames.Locations, [credentialIssuerLocation], ref isFirstMember);
            }

            _ = builder.Append("}]");

            return builder.ToString();
        }
        finally
        {
            JsonAppender.Return(builder);
        }
    }


    /// <summary>
    /// The rule <see cref="Compose"/> holds the caller's configuration identifier to: no unpaired
    /// surrogate, the one class of code unit sequence a JSON string carries that encodes no Unicode
    /// character (RFC 8259 Section 8.2). Built once over the shared classifier <see cref="TextHygiene"/>.
    /// </summary>
    private static TextHygieneRule UnpairedSurrogateRule { get; } = new([TextHygieneClass.UnpairedSurrogate], []);
}
