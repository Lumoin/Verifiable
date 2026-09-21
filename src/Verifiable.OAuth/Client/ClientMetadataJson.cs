using System.Text;

namespace Verifiable.OAuth.Client;

/// <summary>The shared wire writer for all supported dynamic client metadata fields.</summary>
internal static class ClientMetadataJson
{
    /// <summary>Serializes complete metadata and its optional issued management identifier.</summary>
    internal static string Serialize(ClientMetadata metadata)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');
            bool isFirst = true;
            if(metadata.ClientId is not null)
            {
                JsonAppender.AppendStringField(sb, ClientMetadataParameterNames.ClientId, metadata.ClientId, ref isFirst);
            }

            Append(sb, metadata, ref isFirst);
            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>Appends the supported RFC 7591 §2 metadata fields to a registration response.</summary>
    internal static void Append(
        StringBuilder sb, ClientMetadata metadata, ref bool isFirst)
    {
        if(metadata.ClientName is not null)
        {
            JsonAppender.AppendStringField(sb, ClientMetadataParameterNames.ClientName, metadata.ClientName, ref isFirst);
        }

        if(metadata.ClientUri is not null)
        {
            JsonAppender.AppendUriField(sb, ClientMetadataParameterNames.ClientUri, metadata.ClientUri, ref isFirst);
        }

        if(metadata.RedirectUris.Count > 0)
        {
            JsonAppender.AppendUriArrayField(sb, ClientMetadataParameterNames.RedirectUris,
                metadata.RedirectUris, ref isFirst);
        }

        if(metadata.Scope is not null)
        {
            JsonAppender.AppendStringField(sb, ClientMetadataParameterNames.Scope, metadata.Scope, ref isFirst);
        }

        if(metadata.AuthorizationDetailsTypes is not null)
        {
            //RFC 9396 §10/§14.5: echo the registered authorization_details_types so the client
            //sees the allowlist the AS will enforce on its authorization details requests.
            JsonAppender.AppendStringArrayField(sb,
                AuthorizationDetailsParameterNames.AuthorizationDetailsTypes,
                metadata.AuthorizationDetailsTypes, ref isFirst);
        }

        if(metadata.TokenEndpointAuthMethod is not null)
        {
            JsonAppender.AppendStringField(sb, ClientMetadataParameterNames.TokenEndpointAuthMethod,
                ClientAuthenticationMethodNames.GetName(metadata.TokenEndpointAuthMethod.Value),
                ref isFirst);
        }

        if(metadata.JwksUri is not null)
        {
            JsonAppender.AppendUriField(sb, ClientMetadataParameterNames.JwksUri, metadata.JwksUri, ref isFirst);
        }

        AppendExtendedMetadataFields(sb, metadata, ref isFirst);
    }


    /// <summary>Appends every additional supported registration metadata member using its wire type.</summary>
    private static void AppendExtendedMetadataFields(StringBuilder sb, ClientMetadata metadata, ref bool isFirst)
    {
        if(metadata.LogoUri is not null)
        {
            JsonAppender.AppendUriField(sb, "logo_uri", metadata.LogoUri, ref isFirst);
        }

        if(metadata.TokenEndpointAuthSigningAlg is not null)
        {
            JsonAppender.AppendStringField(sb, "token_endpoint_auth_signing_alg", metadata.TokenEndpointAuthSigningAlg, ref isFirst);
        }

        if(metadata.Jwks is not null)
        {
            JsonAppender.AppendRawField(sb, "jwks", metadata.Jwks, ref isFirst);
        }

        if(metadata.SoftwareStatement is not null)
        {
            JsonAppender.AppendStringField(sb, "software_statement", metadata.SoftwareStatement, ref isFirst);
        }

        if(metadata.ApplicationType is not null)
        {
            JsonAppender.AppendStringField(sb, "application_type", metadata.ApplicationType, ref isFirst);
        }

        if(metadata.IdTokenSignedResponseAlg is not null)
        {
            JsonAppender.AppendStringField(sb, "id_token_signed_response_alg", metadata.IdTokenSignedResponseAlg, ref isFirst);
        }

        if(metadata.RequestObjectSigningAlg is not null)
        {
            JsonAppender.AppendStringField(sb, "request_object_signing_alg", metadata.RequestObjectSigningAlg, ref isFirst);
        }

        if(metadata.RequestObjectEncryptionAlg is not null)
        {
            JsonAppender.AppendStringField(sb, "request_object_encryption_alg", metadata.RequestObjectEncryptionAlg, ref isFirst);
        }

        if(metadata.BackchannelLogoutUri is not null)
        {
            JsonAppender.AppendUriField(sb, "backchannel_logout_uri", metadata.BackchannelLogoutUri, ref isFirst);
        }

        if(metadata.FrontchannelLogoutUri is not null)
        {
            JsonAppender.AppendUriField(sb, "frontchannel_logout_uri", metadata.FrontchannelLogoutUri, ref isFirst);
        }

        if(metadata.GrantTypes.Count > 0)
        {
            JsonAppender.AppendStringArrayField(sb, "grant_types", metadata.GrantTypes.Select(GrantTypeNames.GetName), ref isFirst);
        }

        if(metadata.ResponseTypes.Count > 0)
        {
            JsonAppender.AppendStringArrayField(sb, "response_types", metadata.ResponseTypes.Select(ResponseTypeNames.GetName), ref isFirst);
        }

        if(metadata.PostLogoutRedirectUris.Count > 0)
        {
            JsonAppender.AppendUriArrayField(sb, "post_logout_redirect_uris", metadata.PostLogoutRedirectUris, ref isFirst);
        }

        if(metadata.AuthorizationGrantProfilesSupported is not null)
        {
            JsonAppender.AppendStringArrayField(sb, "authorization_grant_profiles_supported", metadata.AuthorizationGrantProfilesSupported, ref isFirst);
        }

        if(metadata.BackchannelLogoutUri is not null || metadata.BackchannelLogoutSessionRequired)
        {
            JsonAppender.AppendBoolField(sb, "backchannel_logout_session_required", metadata.BackchannelLogoutSessionRequired, ref isFirst);
        }

        if(metadata.FrontchannelLogoutUri is not null || metadata.FrontchannelLogoutSessionRequired)
        {
            JsonAppender.AppendBoolField(sb, "frontchannel_logout_session_required", metadata.FrontchannelLogoutSessionRequired, ref isFirst);
        }
    }


}
