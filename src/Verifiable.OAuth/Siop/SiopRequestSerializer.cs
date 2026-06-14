using System.Text;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Server;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Serializes a <see cref="SiopRequest"/> to its wire forms: the form-urlencoded query
/// string of
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-9">SIOPv2 §9</see>
/// and the full request URL targeted at a Self-Issued OP's <c>authorization_endpoint</c>,
/// plus the §7.5 RP metadata JSON object.
/// </summary>
/// <remarks>
/// Built on <see cref="JsonAppender"/> for the metadata object to honour the
/// <c>Verifiable.OAuth</c> serialization firewall. The RP chooses the delivery: an HTTP
/// 302 to the OP's <c>authorization_endpoint</c> in the same-device flow, or a QR code
/// carrying the request URL in the cross-device flow (§9.2, with
/// <c>response_mode=direct_post</c>).
/// </remarks>
public static class SiopRequestSerializer
{
    /// <summary>
    /// The custom URL scheme of the §15.1.2 static Self-Issued OP configuration,
    /// including the <c>://</c> so it composes directly with the query string. The
    /// RECOMMENDED alternative is a claimed URL (Universal Link / App Link) obtained
    /// via discovery (§6.2).
    /// </summary>
    public const string DefaultScheme = "siopv2://";


    /// <summary>
    /// Serializes the request to its §9 query string (without a leading <c>?</c>):
    /// <c>response_type=id_token&amp;client_id=…&amp;redirect_uri=…&amp;scope=…&amp;nonce=…</c>
    /// followed by the optional parameters that are set.
    /// </summary>
    /// <param name="request">The request to serialize.</param>
    /// <returns>The form-urlencoded query string.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when both <see cref="SiopRequest.ClientMetadata"/> and
    /// <see cref="SiopRequest.ClientMetadataUri"/> are set — §9 declares them mutually
    /// exclusive.
    /// </exception>
    public static string ToQueryString(SiopRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if(request.ClientMetadata is not null && request.ClientMetadataUri is not null)
        {
            throw new ArgumentException(
                "client_metadata and client_metadata_uri are mutually exclusive per SIOPv2 §9.",
                nameof(request));
        }

        StringBuilder sb = new();
        AppendParameter(sb, OAuthRequestParameterNames.ResponseType,
            SiopAuthorizationRequestParameterValues.ResponseTypeIdToken);
        AppendParameter(sb, OAuthRequestParameterNames.ClientId, request.ClientId);
        AppendParameter(sb, OAuthRequestParameterNames.RedirectUri, request.RedirectUri.OriginalString);
        AppendParameter(sb, OAuthRequestParameterNames.Scope, request.Scope);
        AppendParameter(sb, JCose.WellKnownJwtClaimNames.Nonce, request.Nonce);

        if(request.IdTokenType is not null)
        {
            AppendParameter(sb, SiopAuthorizationRequestParameterNames.IdTokenType, request.IdTokenType);
        }

        if(request.State is not null)
        {
            AppendParameter(sb, OAuthRequestParameterNames.State, request.State);
        }

        if(request.ResponseMode is not null)
        {
            AppendParameter(sb, OAuthRequestParameterNames.ResponseMode, request.ResponseMode);
        }

        if(request.ClientMetadata is SiopRelyingPartyMetadata metadata)
        {
            AppendParameter(sb, Oid4VpAuthorizationRequestParameterNames.ClientMetadata,
                ToJson(metadata));
        }

        if(request.ClientMetadataUri is Uri metadataUri)
        {
            AppendParameter(sb, SiopAuthorizationRequestParameterNames.ClientMetadataUri,
                metadataUri.OriginalString);
        }

        return sb.ToString();
    }


    /// <summary>
    /// Composes the full Authorization Request URL against the Self-Issued OP's
    /// <c>authorization_endpoint</c> — a claimed URL from discovery, or a custom
    /// scheme such as <see cref="DefaultScheme"/>.
    /// </summary>
    /// <param name="authorizationEndpoint">
    /// The <c>authorization_endpoint</c> to target, with or without an existing query
    /// component.
    /// </param>
    /// <param name="request">The request to carry.</param>
    /// <returns>The request link a redirect, link, or QR code can carry.</returns>
    public static string ToAuthorizationRequestLink(string authorizationEndpoint, SiopRequest request)
    {
        ArgumentException.ThrowIfNullOrEmpty(authorizationEndpoint);
        ArgumentNullException.ThrowIfNull(request);

        char separator = authorizationEndpoint.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        return authorizationEndpoint + separator + ToQueryString(request);
    }


    /// <summary>
    /// Serializes the §7.5 RP metadata to its JSON object — the <c>client_metadata</c>
    /// parameter value, and the document an RP serves at its <c>client_metadata_uri</c>.
    /// </summary>
    /// <param name="metadata">The RP metadata to serialize.</param>
    /// <returns>The JSON-encoded RP metadata object.</returns>
    public static string ToJson(SiopRelyingPartyMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringArrayField(
                sb, SiopClientMetadataParameterNames.SubjectSyntaxTypesSupported,
                metadata.SubjectSyntaxTypesSupported, ref first);

            if(metadata.IdTokenSignedResponseAlg is not null)
            {
                JsonAppender.AppendStringField(
                    sb, SiopClientMetadataParameterNames.IdTokenSignedResponseAlg,
                    metadata.IdTokenSignedResponseAlg, ref first);
            }

            if(metadata.AdditionalParameters is not null)
            {
                foreach(KeyValuePair<string, object> parameter in metadata.AdditionalParameters)
                {
                    if(!first)
                    {
                        sb.Append(',');
                    }

                    sb.Append('"');
                    JsonAppender.AppendEscapedString(sb, parameter.Key);
                    sb.Append("\":");
                    JsonAppender.AppendValue(sb, parameter.Value);
                    first = false;
                }
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    private static void AppendParameter(StringBuilder sb, string name, string value)
    {
        if(sb.Length > 0)
        {
            sb.Append('&');
        }

        sb.Append(name).Append('=').Append(Uri.EscapeDataString(value));
    }
}
