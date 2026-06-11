using System.Text;
using Verifiable.Core;

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
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(context);

        if(infrastructure.SendJsonPostAsync is null)
        {
            throw new InvalidOperationException(
                "OAuthClientInfrastructure.SendJsonPostAsync is not configured. "
                + "Dynamic registration requires a JSON-aware transport delegate "
                + "since RFC 7591 §3 mandates a JSON request body.");
        }

        string body = SerializeClientMetadata(options.Metadata);

        HttpResponseData response = await infrastructure.SendJsonPostAsync(
            options.RegistrationEndpoint, body, OutgoingHeaders.Empty, context, cancellationToken).ConfigureAwait(false);

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
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(context);

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
            .WithAuthorization(WellKnownAuthenticationSchemes.Bearer, registration.AccessToken.Value.Value);

        HttpResponseData response = await infrastructure.SendJsonGetAsync(
            registration.ManagementUri, headers, context, cancellationToken).ConfigureAwait(false);

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
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(newMetadata);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(context);

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
            .WithAuthorization(WellKnownAuthenticationSchemes.Bearer, registration.AccessToken.Value.Value);

        HttpResponseData response = await infrastructure.SendJsonPutAsync(
            registration.ManagementUri, body, headers, context, cancellationToken).ConfigureAwait(false);

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
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(context);

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
            .WithAuthorization(WellKnownAuthenticationSchemes.Bearer, registration.AccessToken.Value.Value);

        HttpResponseData response = await infrastructure.SendJsonDeleteAsync(
            registration.ManagementUri, headers, context, cancellationToken).ConfigureAwait(false);

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
        //Field order follows RFC 7591 §2 table order. Optional fields are
        //emitted only when populated so the wire body stays minimal.
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            if(metadata.RedirectUris.Count > 0)
            {
                JsonAppender.AppendUriArrayField(
                    sb, "redirect_uris", metadata.RedirectUris, ref first);
            }
            if(metadata.TokenEndpointAuthMethod is not null)
            {
                JsonAppender.AppendStringField(
                    sb, "token_endpoint_auth_method",
                    ClientAuthenticationMethodNames.GetName(metadata.TokenEndpointAuthMethod.Value),
                    ref first);
            }
            if(metadata.ClientName is not null)
            {
                JsonAppender.AppendStringField(sb, "client_name", metadata.ClientName, ref first);
            }
            if(metadata.ClientUri is not null)
            {
                JsonAppender.AppendUriField(sb, "client_uri", metadata.ClientUri, ref first);
            }
            if(metadata.Scope is not null)
            {
                JsonAppender.AppendStringField(sb, "scope", metadata.Scope, ref first);
            }
            if(metadata.AuthorizationDetailsTypes is not null)
            {
                //RFC 9396 §10/§14.5: the client declares the authorization details types it will
                //use so the AS can entitle it to exactly those types.
                JsonAppender.AppendStringArrayField(
                    sb, AuthorizationDetailsParameterNames.AuthorizationDetailsTypes,
                    metadata.AuthorizationDetailsTypes, ref first);
            }
            if(metadata.JwksUri is not null)
            {
                JsonAppender.AppendUriField(sb, "jwks_uri", metadata.JwksUri, ref first);
            }
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
