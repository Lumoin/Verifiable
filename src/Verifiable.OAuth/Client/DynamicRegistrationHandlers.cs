using System.Text;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Pure static handler functions for RFC 7591 client registration and
/// RFC 7592 management. Each handler takes the per-call inputs, the
/// long-lived <see cref="OAuthClientInfrastructure"/>, and a cancellation
/// token; no instance state is held.
/// </summary>
public static class DynamicRegistrationHandlers
{
    /// <summary>
    /// Handles RFC 7591 §3 client registration. POSTs the metadata as JSON,
    /// parses the response, and constructs a runtime
    /// <see cref="ClientRegistration"/>.
    /// </summary>
    public static async ValueTask<DynamicRegistrationResult> HandleRegisterAsync(
        RegisterClientOptions options,
        OAuthClientInfrastructure infrastructure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(infrastructure);

        if(infrastructure.SendJsonPostAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.SendJsonPostAsync is not configured. "
                + "Dynamic registration requires a JSON-aware transport delegate "
                + "since RFC 7591 §3 mandates a JSON request body.");
        }

        string body = SerializeClientMetadata(options.Metadata);

        HttpResponseData response = await infrastructure.SendJsonPostAsync(
            options.RegistrationEndpoint, body, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"Registration request failed with status {response.StatusCode}: {response.Body}");
        }

        RegistrationResponse parsed = await infrastructure.ParseRegistrationResponseAsync(
            response.Body, cancellationToken).ConfigureAwait(false);

        ClientRegistration registration = BuildRegistration(options, parsed);

        return new DynamicRegistrationResult
        {
            Response = parsed,
            Registration = registration
        };
    }


    /// <summary>
    /// Handles RFC 7592 §2.1 client read. GETs the management URI with the
    /// registration's bearer token, parses the echoed metadata.
    /// </summary>
    public static async ValueTask<ClientMetadata> HandleReadAsync(
        ClientRegistration registration,
        OAuthClientInfrastructure infrastructure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(infrastructure);

        if(registration.ManagementUri is null || registration.AccessToken is null)
        {
            throw new InvalidOperationException(
                "Read requires a registration with ManagementUri and AccessToken set.");
        }
        if(infrastructure.SendJsonGetAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.SendJsonGetAsync is not configured.");
        }
        if(infrastructure.ParseClientMetadataAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.ParseClientMetadataAsync is not configured.");
        }

        OutgoingHeaders headers = OutgoingHeaders.Empty
            .WithAuthorization("Bearer", registration.AccessToken.Value.Value);

        HttpResponseData response = await infrastructure.SendJsonGetAsync(
            registration.ManagementUri, headers, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"RFC 7592 read failed with status {response.StatusCode}: {response.Body}");
        }

        return await infrastructure.ParseClientMetadataAsync(
            response.Body, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Handles RFC 7592 §2.2 client update. PUTs the new metadata with the
    /// registration's bearer token, parses the echoed updated metadata.
    /// </summary>
    public static async ValueTask<ClientMetadata> HandleUpdateAsync(
        ClientRegistration registration,
        ClientMetadata newMetadata,
        OAuthClientInfrastructure infrastructure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(newMetadata);
        ArgumentNullException.ThrowIfNull(infrastructure);

        if(registration.ManagementUri is null || registration.AccessToken is null)
        {
            throw new InvalidOperationException(
                "Update requires a registration with ManagementUri and AccessToken set.");
        }
        if(infrastructure.SendJsonPutAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.SendJsonPutAsync is not configured.");
        }
        if(infrastructure.ParseClientMetadataAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.ParseClientMetadataAsync is not configured.");
        }

        string body = SerializeClientMetadata(newMetadata);

        OutgoingHeaders headers = OutgoingHeaders.Empty
            .WithAuthorization("Bearer", registration.AccessToken.Value.Value);

        HttpResponseData response = await infrastructure.SendJsonPutAsync(
            registration.ManagementUri, body, headers, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"RFC 7592 update failed with status {response.StatusCode}: {response.Body}");
        }

        return await infrastructure.ParseClientMetadataAsync(
            response.Body, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Handles RFC 7592 §2.3 client deregistration. DELETEs the management URI
    /// with the registration's bearer token.
    /// </summary>
    public static async ValueTask HandleDeregisterAsync(
        ClientRegistration registration,
        OAuthClientInfrastructure infrastructure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(infrastructure);

        if(registration.ManagementUri is null || registration.AccessToken is null)
        {
            throw new InvalidOperationException(
                "Deregister requires a registration with ManagementUri and AccessToken set.");
        }
        if(infrastructure.SendJsonDeleteAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.SendJsonDeleteAsync is not configured.");
        }

        OutgoingHeaders headers = OutgoingHeaders.Empty
            .WithAuthorization("Bearer", registration.AccessToken.Value.Value);

        HttpResponseData response = await infrastructure.SendJsonDeleteAsync(
            registration.ManagementUri, headers, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"RFC 7592 deregister failed with status {response.StatusCode}: {response.Body}");
        }
    }


    private static ClientRegistration BuildRegistration(
        RegisterClientOptions options,
        RegistrationResponse response) =>
        new()
        {
            ClientId = response.ClientId,
            AuthorizationServerIssuer = options.AuthorizationServerIssuer,
            RedirectUris = options.Metadata.RedirectUris,
            Scope = options.Metadata.Scope,
            GrantTypes = options.Metadata.GrantTypes,
            ResponseTypes = options.Metadata.ResponseTypes,
            AuthenticationMethod = options.AuthenticationMethod,
            Profile = options.Profile,
            SigningKeyMaterial = options.SigningKeyMaterial,
            AuthenticationKeyMaterial = options.AuthenticationKeyMaterial,
            JwksUri = options.Metadata.JwksUri,
            RegisteredAt = response.IssuedAt,
            RegistrationExpiresAt = response.ExpiresAt,
            AccessToken = response.AccessToken,
            ManagementUri = response.ManagementUri
        };


    private static string SerializeClientMetadata(ClientMetadata metadata)
    {
        //Hand-written JSON. The client side does NOT pull System.Text.Json
        //into Verifiable.OAuth; serialization of the request body lives
        //in the same library as the metadata type. Field order follows
        //RFC 7591 §2 table order.
        StringBuilder sb = new();
        sb.Append('{');
        bool first = true;
        if(metadata.RedirectUris.Count > 0)
        {
            AppendUriListField(sb, "redirect_uris", metadata.RedirectUris, ref first);
        }
        if(metadata.TokenEndpointAuthMethod is not null)
        {
            AppendStringField(sb, "token_endpoint_auth_method",
                ClientAuthenticationMethodNames.GetName(metadata.TokenEndpointAuthMethod.Value),
                ref first);
        }
        if(metadata.ClientName is not null)
        {
            AppendStringField(sb, "client_name", metadata.ClientName, ref first);
        }
        if(metadata.ClientUri is not null)
        {
            AppendStringField(sb, "client_uri", metadata.ClientUri.OriginalString, ref first);
        }
        if(metadata.Scope is not null)
        {
            AppendStringField(sb, "scope", metadata.Scope, ref first);
        }
        if(metadata.JwksUri is not null)
        {
            AppendStringField(sb, "jwks_uri", metadata.JwksUri.OriginalString, ref first);
        }
        sb.Append('}');
        return sb.ToString();
    }


    private static void AppendStringField(StringBuilder sb, string key, string value, ref bool first)
    {
        if(!first) { sb.Append(','); }
        sb.Append('"').Append(key).Append("\":\"");
        AppendEscapedJsonString(sb, value);
        sb.Append('"');
        first = false;
    }


    private static void AppendUriListField(
        StringBuilder sb, string key, IReadOnlyList<Uri> values, ref bool first)
    {
        if(!first) { sb.Append(','); }
        sb.Append('"').Append(key).Append("\":[");
        for(int i = 0; i < values.Count; ++i)
        {
            if(i > 0) { sb.Append(','); }
            sb.Append('"');
            AppendEscapedJsonString(sb, values[i].OriginalString);
            sb.Append('"');
        }
        sb.Append(']');
        first = false;
    }


    private static void AppendEscapedJsonString(StringBuilder sb, string value)
    {
        //Same minimal JSON escaping as RegistrationEndpoints.AppendEscapedJsonString
        //on the server side. Kept duplicated rather than shared because the
        //server and client sides should not depend on each other's
        //serialization helpers; a future cleanup round can extract both into a
        //shared utility if it earns its keep.
        for(int i = 0; i < value.Length; ++i)
        {
            char c = value[i];
            switch(c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if(c < 0x20)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4",
                            System.Globalization.CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
    }
}
