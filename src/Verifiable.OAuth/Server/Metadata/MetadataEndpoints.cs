using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Server.Pipeline;
namespace Verifiable.OAuth.Server.Metadata;

/// <summary>
/// Endpoint builder module for JWKS and Discovery metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="AuthorizationServer.EndpointBuilders"/>:
/// </para>
/// <code>
/// server.EndpointBuilders.AddRange([
///     MetadataEndpoints.Builder,
///     AuthCodeEndpoints.Builder,
///     Oid4VpEndpoints.Builder
/// ]);
/// </code>
/// <para>
/// Produces endpoints only for registrations that have
/// <see cref="ServerCapabilityName.JwksEndpoint"/> or
/// <see cref="ServerCapabilityName.DiscoveryEndpoint"/> capabilities.
/// </para>
/// <para>
/// The discovery endpoint composes URLs by asking the application via
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>. The
/// library never composes paths from templates — each URL the discovery document
/// advertises is the URL the application actually serves.
/// </para>
/// <para>
/// <strong>JSON wire format and the serialization firewall.</strong> The
/// discovery and JWKS response bodies are written as JSON by hand using
/// <see cref="StringBuilder"/> rather than through a serializer. This is
/// deliberate. <c>Verifiable.OAuth</c> takes no dependency on
/// <c>Verifiable.Json</c>, on <c>System.Text.Json</c>, or on any other JSON
/// library, and the project's banned-symbol analyzer enforces this. The
/// library does not impose a JSON implementation on the application.
/// </para>
/// <para>
/// The wire shapes here are RFC-defined and stable: the discovery document
/// per
/// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>
/// (and the OIDC Discovery profile that extends it) and the JWKS document
/// per
/// <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>. The
/// fields are well-known property names with primitive values (strings,
/// booleans, integers) plus arrays of strings; nested or schema-variable
/// structure is not used. For shapes like that, manual
/// <see cref="StringBuilder"/> construction is the simplest path that
/// respects the firewall and stays AOT-safe without source-generator
/// context maintenance.
/// </para>
/// <para>
/// Application-contributed discovery fields arrive through
/// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>
/// as already-typed values; the helper
/// <see cref="AppendContributedField"/> emits each according to its
/// runtime CLR type (string, bool, list of strings, otherwise
/// <see cref="IFormattable"/> with invariant culture). The application is
/// free to compute those values with any serializer; it just hands the
/// library typed primitives.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataEndpoints")]
public static class MetadataEndpoints
{


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(registration.IsCapabilityAllowed(ServerCapabilityName.JwksEndpoint))
        {
            candidates.Add(BuildJwks());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.DiscoveryEndpoint))
        {
            candidates.Add(BuildDiscovery());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the JWKS endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The endpoint is stateless: <see cref="ServerEndpoint.BuildInputAsync"/>
    /// resolves the <see cref="JwksDocument"/> via the application's
    /// <see cref="AuthorizationServerCryptography.BuildJwksDocumentAsync"/>
    /// delegate, then serializes it to JSON via <see cref="BuildJwksJson"/>
    /// and short-circuits the dispatcher with an early
    /// <see cref="ServerHttpResponse.Ok(string, string)"/> result.
    /// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
    /// </para>
    /// <para>
    /// The serialization is hand-written; see the serialization-firewall
    /// paragraph in the remarks on <see cref="MetadataEndpoints"/> for the
    /// rationale.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildJwks() =>
        new()
        {
            Name = WellKnownEndpointNames.MetadataJwks,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = ServerCapabilityName.JwksEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.JwksUri,

            //Acceptance test: GET to the JWKS URL for this registration. The
            //chain build guarantees registration is loaded and capability is
            //allowed before any matcher runs; path comparison goes against the
            //endpoint's per-request ResolvedUri.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            //The JWKS endpoint is stateless — it does not step the PDA. BuildInputAsync
            //builds the complete response and returns it as an early exit. BuildResponse
            //is never reached.
            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                if(server.Cryptography.BuildJwksDocumentAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "BuildJwksDocumentAsync is not configured."));
                }

                ClientRecord? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                JwksDocument jwks = await server.Cryptography.BuildJwksDocumentAsync(
                    registration, context, ct).ConfigureAwait(false);

                string body = BuildJwksJson(jwks);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the OAuth/OIDC discovery endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>
    /// and the OpenID Connect Discovery 1.0 profile that extends it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The endpoint is stateless:
    /// <see cref="ServerEndpoint.BuildInputAsync"/> resolves the issuer via
    /// <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>
    /// (falling back to <see cref="DefaultIssuerResolver"/>), then asks the
    /// application's
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// for the absolute URL of each capability-gated endpoint, optionally
    /// merges fields from
    /// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>,
    /// and short-circuits the dispatcher with an early
    /// <see cref="ServerHttpResponse.Ok(string, string)"/> result.
    /// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
    /// </para>
    /// <para>
    /// The library never composes paths; each advertised URL comes from the
    /// per-request <see cref="EndpointChain"/> the dispatcher placed on the
    /// context. Endpoints are projected through
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// at chain-build time; discovery emission then reads
    /// <see cref="ServerEndpoint.ResolvedUri"/> directly, guaranteeing the
    /// advertised URL is the same URL the matcher will match against.
    /// </para>
    /// <para>
    /// The JSON body is assembled by hand using <see cref="StringBuilder"/>
    /// via the helpers <see cref="AppendField"/> and
    /// <see cref="AppendContributedField"/>. See the serialization-firewall
    /// paragraph in the remarks on <see cref="MetadataEndpoints"/> for the
    /// rationale.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildDiscovery() =>
        new()
        {
            Name = WellKnownEndpointNames.MetadataDiscovery,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = ServerCapabilityName.DiscoveryEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey is null — the discovery endpoint isn't itself
            //advertised in the discovery document; clients hit a well-known URL.

            //Acceptance test: GET to the discovery URL for this registration.
            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                ClientRecord? registration = context.Registration;
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
                    issuer = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
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

                var sb = new StringBuilder();
                sb.Append('{');

                string issuerValue = issuer.GetLeftPart(UriPartial.Authority);
                sb.Append("\"issuer\":\"");
                sb.Append(issuerValue);
                sb.Append('"');

                //Phase 9h chunk 9 — endpoint emission walks the per-request
                //EndpointChain. The dispatcher places it on the context after
                //ResolveCapabilitiesAsync attenuation and per-candidate URL
                //resolution, so this loop emits exactly the endpoints active
                //for this request: capability-vetoed endpoints are absent,
                //and the advertised URL is the same Uri the matcher will
                //match against (no drift possible because both read
                //ServerEndpoint.ResolvedUri).
                //
                //Endpoints share a DiscoveryMetadataKey when they share a URL
                //(JAR variants of PAR/Authorize advertise under their non-JAR
                //sibling's key; refresh-token shares the token endpoint URL).
                //Per chunk 6 the JAR variants and refresh-token carry
                //DiscoveryMetadataKey=null specifically to avoid double-
                //emission, so the skip-null guard below is the only
                //deduplication this loop needs.
                EndpointChain? chain = context.EndpointChain;
                if(chain is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "EndpointChain not on context for discovery emission. "
                        + "DispatchAsync sets this; this code path is only "
                        + "reachable through dispatch."));
                }

                bool authorizationCodeOnChain = false;
                foreach(ServerEndpoint chainEndpoint in chain)
                {
                    if(chainEndpoint.Capability == ServerCapabilityName.AuthorizationCode)
                    {
                        authorizationCodeOnChain = true;
                    }

                    if(chainEndpoint.DiscoveryMetadataKey is null) { continue; }
                    AppendField(
                        sb,
                        chainEndpoint.DiscoveryMetadataKey,
                        chainEndpoint.ResolvedUri.ToString());
                }

                //OIDC Discovery 1.0 §3 REQUIRED fields. The library's subject
                //identifier story is "public" by default (the application
                //installs a custom ResolveSubjectIdentifierAsync to add the
                //pairwise option); chunks 12-16 will iterate on the
                //tenant-specific subject-type set in a follow-up.
                AppendStringArrayField(
                    sb,
                    OpenIdProviderMetadataParameterNames.SubjectTypesSupported,
                    SubjectTypePublic);

                //response_types_supported — derived from the per-request chain
                //to match the existing endpoint-URL emission's attenuation
                //semantics. Authorization Code is the only OAuth 2.1-conformant
                //response type the library ships; hybrid / implicit flows are
                //out of scope.
                if(authorizationCodeOnChain)
                {
                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.ResponseTypesSupported,
                        ResponseTypeCode);
                }

                //id_token_signing_alg_values_supported — derived from the
                //registration's IdTokenIssuance signing keys. Each KeyId is
                //resolved through the verification-key resolver and its tag
                //mapped to a JWA identifier; the deduped set forms the
                //advertised list.
                IReadOnlyList<string> idTokenAlgs = await ResolveIdTokenSigningAlgValuesAsync(
                    server, registration, context, ct).ConfigureAwait(false);
                if(idTokenAlgs.Count > 0)
                {
                    AppendStringArrayField(
                        sb,
                        OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported,
                        idTokenAlgs);
                }

                //Application-supplied additional fields merged after the base set.
                if(server.Integration.ContributeDiscoveryFieldsAsync is not null)
                {
                    DiscoveryDocumentContribution contributed =
                        await server.Integration.ContributeDiscoveryFieldsAsync(
                            registration, context, ct).ConfigureAwait(false);

                    foreach(DiscoveryField field in contributed.Fields)
                    {
                        AppendContributedField(sb, field);
                    }
                }

                sb.Append('}');

                return (null, ServerHttpResponse.Ok(sb.ToString(), WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    //Helpers go below the public surface.

    /// <summary>
    /// Appends a single string-valued JSON field to the discovery-document
    /// builder, formatted as <c>,"key":"value"</c>. Always emits the leading
    /// comma; callers must have written the opening brace and at least the
    /// <c>issuer</c> field before calling.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the discovery
    /// document; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the field is written to.</param>
    /// <param name="key">The JSON property name.</param>
    /// <param name="value">The JSON property value, written as a JSON string.</param>
    private static void AppendField(StringBuilder sb, string key, string value)
    {
        sb.Append(",\"");
        sb.Append(key);
        sb.Append("\":\"");
        sb.Append(value);
        sb.Append('"');
    }


    /// <summary>
    /// Appends a string-array field to the discovery-document builder,
    /// formatted as <c>,"key":["v1","v2",…]</c>. Always emits the leading
    /// comma; callers must have written the opening brace and at least the
    /// <c>issuer</c> field before calling. No-ops on an empty list to avoid
    /// emitting <c>"key":[]</c> for fields that should be omitted entirely
    /// when no values are available.
    /// </summary>
    private static void AppendStringArrayField(
        StringBuilder sb, string key, IReadOnlyList<string> values)
    {
        if(values.Count == 0) { return; }

        sb.Append(",\"");
        sb.Append(key);
        sb.Append("\":[");
        for(int i = 0; i < values.Count; i++)
        {
            if(i > 0) { sb.Append(','); }
            sb.Append('"');
            sb.Append(values[i]);
            sb.Append('"');
        }
        sb.Append(']');
    }


    //Static well-known value sets emitted by the discovery endpoint.
    private static readonly IReadOnlyList<string> SubjectTypePublic = ["public"];
    private static readonly IReadOnlyList<string> ResponseTypeCode = ["code"];


    /// <summary>
    /// Derives <c>id_token_signing_alg_values_supported</c> from the
    /// registration's <see cref="KeyUsageContext.IdTokenIssuance"/> signing
    /// keys. Each <see cref="KeyId"/> in the rotation-aware
    /// <see cref="SigningKeySet"/> is resolved through the verification-key
    /// resolver and its <see cref="PublicKeyMemory.Tag"/> mapped to a JWA
    /// identifier via <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>.
    /// The set is deduplicated by ordinal equality and stable across the
    /// rotation-slot order.
    /// </summary>
    /// <remarks>
    /// Returns an empty list when the registration has no IdTokenIssuance
    /// signing keys configured (the OIDC ID Token producer would not run for
    /// such a registration anyway). The discovery emitter omits the field
    /// entirely in that case rather than emitting an empty array.
    /// </remarks>
    private static async ValueTask<IReadOnlyList<string>> ResolveIdTokenSigningAlgValuesAsync(
        AuthorizationServer server,
        ClientRecord registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        if(!registration.SigningKeys.TryGetValue(
                Verifiable.Cryptography.Context.KeyUsageContext.IdTokenIssuance,
                out SigningKeySet? signingKeySet))
        {
            return [];
        }

        ServerVerificationKeyResolverDelegate? resolver =
            server.Cryptography.VerificationKeyResolver;
        if(resolver is null)
        {
            return [];
        }

        HashSet<string> algorithms = new(StringComparer.Ordinal);
        foreach(KeyId keyId in signingKeySet.Current)
        {
            Verifiable.Cryptography.PublicKeyMemory? key =
                await resolver(keyId, registration.TenantId, context, cancellationToken)
                    .ConfigureAwait(false);
            if(key is null) { continue; }

            string jwa = Verifiable.JCose.CryptoFormatConversions.DefaultTagToJwaConverter(key.Tag);
            algorithms.Add(jwa);
        }

        return algorithms.Count == 0 ? [] : algorithms.ToArray();
    }


    /// <summary>
    /// Appends a single application-contributed discovery-document field to
    /// the builder, dispatching on the <see cref="DiscoveryField"/> record
    /// subtype: <see cref="DiscoveryStringField"/> emits as a JSON string,
    /// <see cref="DiscoveryBooleanField"/> as a JSON boolean,
    /// <see cref="DiscoveryNumberField"/> as a JSON integer formatted with
    /// invariant culture, and <see cref="DiscoveryStringArrayField"/> as a
    /// JSON array of strings. Always emits the leading comma; callers must
    /// have written the opening brace and at least the <c>issuer</c> field
    /// before calling.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the discovery
    /// document; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale. The application
    /// hands the library typed field instances via
    /// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>;
    /// the closed <see cref="DiscoveryField"/> hierarchy means the library
    /// knows the JSON shape of every value at compile time without any
    /// runtime CLR-type inspection.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the field is written to.</param>
    /// <param name="field">The contributed field, dispatched on its record subtype.</param>
    private static void AppendContributedField(StringBuilder sb, DiscoveryField field)
    {
        sb.Append(",\"");
        sb.Append(field.Name);
        sb.Append("\":");

        switch(field)
        {
            case DiscoveryStringField stringField:
                sb.Append('"');
                sb.Append(stringField.Value);
                sb.Append('"');
                return;

            case DiscoveryBooleanField booleanField:
                sb.Append(booleanField.Value ? "true" : "false");
                return;

            case DiscoveryNumberField numberField:
                sb.Append(numberField.Value.ToString(CultureInfo.InvariantCulture));
                return;

            case DiscoveryStringArrayField arrayField:
                sb.Append('[');
                bool firstItem = true;
                foreach(string item in arrayField.Values)
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

            default:
                //Library invariant: the DiscoveryField hierarchy is closed
                //and exhaustively handled above. A new subtype added without
                //updating this dispatch is a library bug.
                throw new InvalidOperationException(
                    $"Unhandled discovery field record subtype '{field.GetType().FullName}'.");
        }
    }


    /// <summary>
    /// Serializes a <see cref="JwksDocument"/> to its
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>
    /// JSON wire form: <c>{"keys":[{...},{...}]}</c>. Each
    /// <see cref="JsonWebKey"/>'s entries are emitted in iteration order via
    /// <see cref="AppendJsonValue"/>; no field-name precedence or omission
    /// rules are applied here, the document is taken as-is.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the JWKS
    /// endpoint; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="jwks">The JWKS document to serialize.</param>
    /// <returns>The JSON wire form as a UTF-16 string suitable for an HTTP response body.</returns>
    private static string BuildJwksJson(JwksDocument jwks)
    {
        var sb = new StringBuilder();
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


    /// <summary>
    /// Appends a single JWK property to the builder, dispatching on the
    /// runtime CLR type of <paramref name="value"/>: <see cref="string"/>
    /// emits as a JSON string, <see cref="bool"/> as a JSON boolean,
    /// <see cref="IReadOnlyList{T}"/> of <see cref="string"/> as a JSON
    /// array of strings, <see cref="IFormattable"/> as the
    /// invariant-culture string form, and any other value via
    /// <see cref="object.ToString"/> wrapped as a JSON string. The leading
    /// comma is emitted on every call after the first within the same
    /// JWK-object scope, tracked via the
    /// <paramref name="firstProp"/> ref parameter.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the JWKS
    /// endpoint; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the property is written to.</param>
    /// <param name="name">The JSON property name.</param>
    /// <param name="value">The property value, dispatched on its runtime CLR type.</param>
    /// <param name="firstProp">Tracks whether this is the first property in the enclosing JWK object; set to <see langword="false"/> after the first call. Pass <see langword="true"/> initially per JWK.</param>
    private static void AppendJsonValue(
        StringBuilder sb,
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
            sb.Append(formattable.ToString(null, CultureInfo.InvariantCulture));
            return;
        }

        sb.Append('"');
        sb.Append(value.ToString());
        sb.Append('"');
    }
}
