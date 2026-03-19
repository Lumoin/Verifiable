using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Endpoint builder module for JWKS and Discovery metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="AuthorizationServerOptions.EndpointBuilders"/>:
/// </para>
/// <code>
/// options.EndpointBuilders =
/// [
///     MetadataEndpoints.Builder,
///     AuthCodeEndpoints.Builder,
///     Oid4VpEndpoints.Builder
/// ];
/// </code>
/// <para>
/// Produces endpoints only for registrations that have
/// <see cref="ServerCapabilityName.JwksEndpoint"/> or
/// <see cref="ServerCapabilityName.DiscoveryEndpoint"/> capabilities.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataEndpoints")]
public static class MetadataEndpoints
{
    private const string Get = "GET";


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServerOptions.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, options) =>
    {
        List<ServerEndpoint> endpoints = [];

        if(registration.IsCapabilityAllowed(ServerCapabilityName.JwksEndpoint))
        {
            endpoints.Add(BuildJwks());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.DiscoveryEndpoint))
        {
            endpoints.Add(BuildDiscovery());
        }

        return endpoints;
    };


    private static ServerEndpoint BuildJwks() =>
        new()
        {
            HttpMethod = Get,
            PathTemplate = ServerEndpointPaths.Jwks,
            Capability = ServerCapabilityName.JwksEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            //The JWKS endpoint is stateless — it does not step the PDA. BuildInputAsync
            //builds the complete response and returns it as an early exit. BuildResponse
            //is never reached.
            BuildInputAsync = static async (fields, context, currentState, options, ct) =>
            {
                if(options.BuildJwksDocumentAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "BuildJwksDocumentAsync is not configured."));
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                JwksDocument jwks = await options.BuildJwksDocumentAsync(
                    registration, context, ct).ConfigureAwait(false);

                string body = BuildJwksJson(jwks);

                return (null, ServerHttpResponse.Ok(body, "application/json"));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static ServerEndpoint BuildDiscovery() =>
        new()
        {
            HttpMethod = Get,
            PathTemplate = ServerEndpointPaths.Discovery,
            Capability = ServerCapabilityName.DiscoveryEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            BuildInputAsync = static async (fields, context, currentState, options, ct) =>
            {
                ClientRegistration? registration = context.Registration;
                if(registration is null)
                {
                    return (null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Client registration not found in context."));
                }

                Uri issuer;
                try
                {
                    issuer = options.ResolveIssuerAsync is not null
                        ? await options.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Issuer URI not found in context."));
                }

                string segment = registration.TenantId.Value;
                var sb = new System.Text.StringBuilder();
                sb.Append('{');

                string issuerValue = issuer.GetLeftPart(UriPartial.Authority);
                sb.Append("\"issuer\":\"");
                sb.Append(issuerValue);
                sb.Append('"');

                string jwksUri = ServerEndpointPaths
                    .ComputeUri(issuer, segment, ServerEndpointPaths.Jwks)
                    .ToString();
                sb.Append(",\"");
                sb.Append(AuthorizationServerMetadataKeys.JwksUri);
                sb.Append("\":\"");
                sb.Append(jwksUri);
                sb.Append('"');

                if(registration.IsCapabilityAllowed(ServerCapabilityName.PushedAuthorization))
                {
                    string parUri = ServerEndpointPaths
                        .ComputeUri(issuer, segment, ServerEndpointPaths.Par)
                        .ToString();
                    sb.Append(",\"");
                    sb.Append(AuthorizationServerMetadataKeys.PushedAuthorizationRequestEndpoint);
                    sb.Append("\":\"");
                    sb.Append(parUri);
                    sb.Append('"');
                }

                if(registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode))
                {
                    string authUri = ServerEndpointPaths
                        .ComputeUri(issuer, segment, ServerEndpointPaths.Authorize)
                        .ToString();
                    sb.Append(",\"");
                    sb.Append(AuthorizationServerMetadataKeys.AuthorizationEndpoint);
                    sb.Append("\":\"");
                    sb.Append(authUri);
                    sb.Append('"');
                }

                bool hasToken =
                    registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode) ||
                    registration.IsCapabilityAllowed(ServerCapabilityName.ClientCredentials) ||
                    registration.IsCapabilityAllowed(ServerCapabilityName.TokenExchange);

                if(hasToken)
                {
                    string tokenUri = ServerEndpointPaths
                        .ComputeUri(issuer, segment, ServerEndpointPaths.Token)
                        .ToString();
                    sb.Append(",\"");
                    sb.Append(AuthorizationServerMetadataKeys.TokenEndpoint);
                    sb.Append("\":\"");
                    sb.Append(tokenUri);
                    sb.Append('"');
                }

                if(registration.IsCapabilityAllowed(ServerCapabilityName.TokenRevocation))
                {
                    string revokeUri = ServerEndpointPaths
                        .ComputeUri(issuer, segment, ServerEndpointPaths.Revoke)
                        .ToString();
                    sb.Append(",\"");
                    sb.Append(AuthorizationServerMetadataKeys.RevocationEndpoint);
                    sb.Append("\":\"");
                    sb.Append(revokeUri);
                    sb.Append('"');
                }

                sb.Append('}');

                return (null, ServerHttpResponse.Ok(sb.ToString(), "application/json"));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static string BuildJwksJson(JwksDocument jwks)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("{\"keys\":[");

        bool first = true;
        foreach(JsonWebKey key in jwks.Keys)
        {
            if(!first)
            {
                sb.Append(',');
            }

            first = false;
            sb.Append('{');

            bool firstProp = true;
            foreach(KeyValuePair<string, object> entry in key)
            {
                AppendJsonValue(sb, entry.Key, entry.Value, ref firstProp);
            }

            sb.Append('}');
        }

        sb.Append("]}");
        return sb.ToString();
    }


    private static void AppendJsonValue(
        System.Text.StringBuilder sb,
        string name,
        object value,
        ref bool firstProp)
    {
        if(!firstProp)
        {
            sb.Append(',');
        }

        firstProp = false;
        sb.Append('"');
        sb.Append(name);
        sb.Append("\":");

        if(value is string s)
        {
            sb.Append('"');
            sb.Append(s);
            sb.Append('"');
            return;
        }

        if(value is bool b)
        {
            sb.Append(b ? "true" : "false");
            return;
        }

        if(value is IReadOnlyList<string> list)
        {
            sb.Append('[');
            bool firstItem = true;
            foreach(string item in list)
            {
                if(!firstItem)
                {
                    sb.Append(',');
                }
                firstItem = false;
                sb.Append('"');
                sb.Append(item);
                sb.Append('"');
            }
            sb.Append(']');
            return;
        }

        if(value is IFormattable formattable)
        {
            sb.Append(formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture));
            return;
        }

        sb.Append('"');
        sb.Append(value.ToString());
        sb.Append('"');
    }
}
