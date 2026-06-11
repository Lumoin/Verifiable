using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The built-in RFC 9396 authorization details handler for the <c>openid_credential</c> type —
/// the OID4VCI 1.0 §5.1.1 profile. It owns the shape requirements for an <c>openid_credential</c>
/// object (a required <c>credential_configuration_id</c>, the §5.1.1 / §6.1.1 <c>locations</c>
/// rule, and the lenient-unknown-fields rule) and projects a generic
/// <see cref="AuthorizationDetail"/> into the <see cref="CredentialAuthorizationDetail"/> the
/// decision seam consumes.
/// </summary>
/// <remarks>
/// Registered into every <see cref="AuthorizationDetailTypeRegistry"/> by default
/// (<see cref="AuthorizationDetailTypeRegistry"/> creation in
/// <see cref="AuthorizationServerIntegration"/>), so the generic registry dispatch reproduces the
/// OID4VCI behavior with no profile change.
/// </remarks>
public static class OpenIdCredentialAuthorizationDetailHandler
{
    /// <summary>
    /// The <see cref="AuthorizationDetailHandler"/> for the <c>openid_credential</c> type.
    /// </summary>
    public static AuthorizationDetailHandler Handler { get; } = new()
    {
        Type = AuthorizationDetailsTypeValues.OpenIdCredential,
        ValidateShape = ValidateShape
    };


    /// <summary>
    /// The OID4VCI 1.0 §5.1.1 shape requirements for an <c>openid_credential</c> object: it MUST
    /// carry a <c>credential_configuration_id</c>, and — when the Credential Issuer metadata
    /// declares <c>authorization_servers</c> — its <c>locations</c> common data field MUST be set
    /// to the Credential Issuer Identifier value. Unknown fields are permitted (§5.1.1: the type
    /// is never invalid due to unknown fields).
    /// </summary>
    /// <param name="detail">The parsed <c>openid_credential</c> object.</param>
    /// <param name="validation">The per-request deployment facts.</param>
    /// <returns><see langword="null"/> when the object is acceptable; the error description otherwise.</returns>
    public static string? ValidateShape(
        AuthorizationDetail detail,
        AuthorizationDetailValidationContext validation)
    {
        ArgumentNullException.ThrowIfNull(detail);

        string? configurationId = ReadCredentialConfigurationId(detail);
        if(string.IsNullOrWhiteSpace(configurationId))
        {
            return "credential_configuration_id is required in an openid_credential authorization details object.";
        }

        //OID4VCI 1.0 §5.1.1 / §6.1.1: "If the Credential Issuer metadata contains an
        //authorization_servers parameter, the authorization detail's locations common data
        //field MUST be set to the Credential Issuer Identifier value." Enforced only when the
        //deployment declares authorization_servers; the common single-issuer deployment (AS ==
        //issuer) carries no such parameter and the locations field stays optional.
        if(validation.RequiredLocation is not null
            && (detail.Locations is null
                || !detail.Locations.Contains(validation.RequiredLocation, StringComparer.Ordinal)))
        {
            return "The Credential Issuer metadata declares authorization_servers, so each "
                + "openid_credential authorization details object MUST set its locations element "
                + $"to the Credential Issuer Identifier '{validation.RequiredLocation}'.";
        }

        return null;
    }


    /// <summary>
    /// Projects a generic <see cref="AuthorizationDetail"/> of type <c>openid_credential</c> into
    /// the <see cref="CredentialAuthorizationDetail"/> the decision seam consumes, reading the
    /// §5.1.1 <c>credential_configuration_id</c> from the object's type-specific members.
    /// </summary>
    /// <param name="detail">The parsed <c>openid_credential</c> object.</param>
    /// <returns>The projected credential authorization detail.</returns>
    public static CredentialAuthorizationDetail Project(AuthorizationDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);

        return new CredentialAuthorizationDetail
        {
            Type = detail.Type,
            CredentialConfigurationId = ReadCredentialConfigurationId(detail),
            Locations = detail.Locations
        };
    }


    /// <summary>
    /// Reads the §5.1.1 <c>credential_configuration_id</c> from the object's type-specific
    /// members, or <see langword="null"/> when it is absent or not a JSON string.
    /// </summary>
    private static string? ReadCredentialConfigurationId(AuthorizationDetail detail)
    {
        if(!detail.ExtensionData.TryGetValue(
            Oid4VciCredentialParameterNames.CredentialConfigurationId, out string? rawValue))
        {
            return null;
        }

        return JsonScalarText.AsString(rawValue);
    }
}
