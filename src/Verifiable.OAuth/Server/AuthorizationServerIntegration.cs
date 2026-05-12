using System.Diagnostics;
using System.Text;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Groups the integration delegates by which the Authorization Server asks the
/// application to resolve request data and read or write persistent state.
/// </summary>
/// <remarks>
/// <para>
/// Every delegate on this group has the same shape: <em>the library has a question,
/// the application supplies an answer</em>. None of the delegates perform protocol
/// logic — that lives entirely inside <see cref="AuthorizationServer"/>. They only
/// answer questions that depend on the application's deployment choices: which
/// signal identifies a tenant, where flow state is persisted, what URLs endpoints
/// are exposed at, and so on.
/// </para>
/// <para>
/// Wire all required delegates at construction time. <see cref="Validate"/> reports
/// any missing delegate by name in a single error message rather than failing
/// piecemeal at request time.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerIntegration Validated={IsValidated}")]
public sealed class AuthorizationServerIntegration
{
    /// <summary>
    /// Extracts the <see cref="TenantId"/> from the inbound request. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Invoked at the start of every request, before any other delegate. The
    /// implementation reads whichever signal identifies the tenant in this
    /// deployment — path segment, sub-domain, Host header, mTLS subject/SAN, a
    /// claim on an upstream JWT, or a combination — from the
    /// <see cref="RequestContext"/> the skin populated.
    /// </para>
    /// <para>
    /// Returning <see langword="null"/> indicates the request carries no
    /// identifiable tenant; the dispatcher responds with <c>400 invalid_request</c>
    /// without invoking any further delegates.
    /// </para>
    /// </remarks>
    public ExtractTenantIdDelegate? ExtractTenantIdAsync { get; set; }

    /// <summary>
    /// Loads a <see cref="ClientRecord"/> by tenant identifier. Required.
    /// </summary>
    public LoadClientRegistrationDelegate? LoadClientRegistrationAsync { get; set; }

    /// <summary>
    /// Persists an <see cref="OAuthFlowState"/> under the internal <c>flowId</c>
    /// scoped by tenant. Required.
    /// </summary>
    /// <remarks>
    /// The key is always the stable internal flow identifier — never an external
    /// handle. The application may pattern-match on the state to build secondary
    /// indexes, for example <c>code → flowId</c> or <c>request_uri_token → flowId</c>.
    /// </remarks>
    public SaveServerFlowStateDelegate? SaveFlowStateAsync { get; set; }

    /// <summary>
    /// Loads an <see cref="OAuthFlowState"/> and step count by the internal
    /// <c>flowId</c>. Required. The key has already been resolved from any
    /// external handle by <see cref="ResolveCorrelationKeyAsync"/>.
    /// </summary>
    public LoadServerFlowStateDelegate? LoadFlowStateAsync { get; set; }

    /// <summary>
    /// Resolves an external correlation handle (request_uri token, authorization
    /// code, device_code, etc.) to the stable internal <c>flowId</c> used as the
    /// primary persistence key.
    /// </summary>
    /// <remarks>
    /// Required for flows where the external handle differs from the
    /// <c>flowId</c> (Auth Code with PAR, Device Authorization). Optional for
    /// flows where the external handle <em>is</em> the <c>flowId</c>. When
    /// <see langword="null"/>, the external handle is used directly.
    /// </remarks>
    public ResolveCorrelationKeyDelegate? ResolveCorrelationKeyAsync { get; set; }

    /// <summary>
    /// Resolves the absolute URL at which a capability is reachable for a given
    /// registration in the current request. Required when the server emits
    /// metadata documents or tokens whose claims include endpoint URLs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used by the discovery endpoint to populate <c>jwks_uri</c>,
    /// <c>token_endpoint</c>, <c>authorization_endpoint</c> and similar fields,
    /// by the PAR endpoint to compose the <c>request_uri</c> value, by token
    /// producers to populate the <c>iss</c> claim, and by any other library call
    /// site that has to embed an absolute URL.
    /// </para>
    /// <para>
    /// The library never composes URLs from path templates. Only the application
    /// knows the routing scheme — segmented, sub-domained, header-routed, flat —
    /// and only the application can produce URLs that match the paths it serves.
    /// </para>
    /// </remarks>
    public ResolveEndpointUriDelegate? ResolveEndpointUriAsync { get; set; }

    /// <summary>
    /// Resolves the authorization server's issuer URI (the <c>iss</c> claim and
    /// the base URL advertised in discovery). Optional. When
    /// <see langword="null"/>, the library uses <see cref="DefaultIssuerResolver"/>
    /// which reads <see cref="ClientRecord.IssuerUri"/> first and falls
    /// back to <see cref="RequestContextExtensions.Issuer"/> on the request
    /// context.
    /// </summary>
    public ResolveIssuerDelegate? ResolveIssuerAsync { get; set; }

    /// <summary>
    /// Context-sensitive capability check. When <see langword="null"/>, falls
    /// back to <see cref="ClientRecord.IsCapabilityAllowed"/>. Optional.
    /// </summary>
    public IsCapabilityAllowedDelegate? IsCapabilityAllowedAsync { get; set; }

    /// <summary>
    /// Fetches and validates Client ID Metadata Documents for CIMD clients.
    /// Optional.
    /// </summary>
    public ResolveClientMetadataDelegate? ResolveClientMetadataAsync { get; set; }

    /// <summary>
    /// Generates the <c>client_id</c> for a newly-registered client.
    /// <see langword="null"/> means the library default
    /// (<see cref="Registration.RegistrationEndpoints.DefaultGenerateClientIdAsync"/>) is used.
    /// Optional.
    /// </summary>
    public GenerateClientIdDelegate? GenerateClientIdAsync { get; set; }

    /// <summary>
    /// Generates the <c>registration_access_token</c> for a newly-registered
    /// client. <see langword="null"/> means the library default
    /// (<see cref="Registration.RegistrationEndpoints.DefaultGenerateRegistrationAccessTokenAsync"/>)
    /// is used. Optional.
    /// </summary>
    public GenerateRegistrationAccessTokenDelegate? GenerateRegistrationAccessTokenAsync { get; set; }

    /// <summary>
    /// Parses an incoming RFC 7591 client metadata document body into a typed
    /// <see cref="Client.ClientMetadata"/>. Required when
    /// <see cref="ServerCapabilityName.DynamicClientRegistration"/> is
    /// advertised — the default JSON implementation lives in
    /// <c>Verifiable.OAuth.Json</c> and is wired by the application.
    /// </summary>
    public ParseClientMetadataServerDelegate? ParseClientMetadataAsync { get; set; }

    /// <summary>
    /// Validates a bearer token presented at an RFC 7592 management endpoint.
    /// Required when
    /// <see cref="ServerCapabilityName.DynamicClientRegistration"/> is
    /// advertised — the application implements the constant-time comparison
    /// against its persisted form.
    /// </summary>
    public ValidateRegistrationAccessTokenDelegate? ValidateRegistrationAccessTokenAsync { get; set; }

    /// <summary>
    /// Contributes additional fields to the discovery document
    /// (<c>/.well-known/openid-configuration</c> and equivalents). Optional.
    /// </summary>
    /// <remarks>
    /// The library's discovery endpoint emits its base OAuth 2.0 and OIDC fields
    /// first, then merges the contributed fields over the top. Applications use
    /// this delegate to advertise OIDC, FAPI, OID4VP, OID4VCI, OpenID Federation
    /// or deployment-specific capability fields without replacing the discovery
    /// endpoint.
    /// </remarks>
    public ContributeDiscoveryFieldsDelegate? ContributeDiscoveryFieldsAsync { get; set; }

    /// <summary>
    /// Classifies a raw token string into a typed
    /// <see cref="Verifiable.JCose.JoseTokenShape"/> by structural inspection.
    /// Optional.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required only when token-aware matchers are registered (introspection,
    /// revocation, userinfo, OID4VCI proof endpoints). Endpoints whose
    /// matchers do not consume tokens (PAR, JAR, direct_post, JWKS, discovery)
    /// run without this delegate set.
    /// </para>
    /// <para>
    /// Applications typically wire
    /// <see cref="Verifiable.JCose.JoseTokenClassifier.ClassifyAsync"/> as
    /// the implementation, supplying their Base64Url decoder, JOSE header
    /// deserializer, and memory pool. Deployments that issue non-JOSE token
    /// shapes (paseto, biscuit, macaroon) supply their own classifier or
    /// wrap the JCose default with a pre-classification step that
    /// recognizes their shapes first.
    /// </para>
    /// </remarks>
    public ClassifyTokenDelegate? ClassifyTokenAsync { get; set; }

    /// <summary>
    /// Resolves the per-request policy values for the loaded registration and
    /// populates them on the <see cref="RequestContext"/> at dispatch entry.
    /// Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The dispatcher invokes this delegate once per request after the
    /// registration is loaded but before any matcher executes. Matchers,
    /// validators, and token producers downstream consult policy via the
    /// typed extensions in <see cref="PolicyRequestContextExtensions"/>.
    /// </para>
    /// <para>
    /// Wire to <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/> for the
    /// library's named-profile dispatch (<c>strict</c>, <c>haip</c>,
    /// <c>rfc6749</c>), or supply a custom delegate for bespoke policy.
    /// </para>
    /// </remarks>
    public ResolvePolicyDelegate? ResolvePolicyAsync { get; set; }

    /// <summary>
    /// Resolves the <c>aud</c> claim audience(s) for an RFC 9068 access token
    /// at issuance time. Optional — when <see langword="null"/>, the library's
    /// default <see cref="Rfc9068AccessTokenProducer.DefaultResolveAccessTokenAudienceAsync"/>
    /// runs (reads from <see cref="ClientRecord.ScopeToAudience"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Closes audit Finding 2. The producer consults the active
    /// <see cref="AccessTokenAudPolicy"/> from the resolved policy and uses
    /// the audience(s) this delegate returns to populate the <c>aud</c> claim
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>.
    /// </para>
    /// </remarks>
    public ResolveAccessTokenAudienceDelegate? ResolveAccessTokenAudienceAsync { get; set; }


    /// <summary>
    /// Whether <see cref="Validate"/> has been called successfully on this group.
    /// </summary>
    public bool IsValidated { get; private set; }


    /// <summary>
    /// Validates that the required delegates on this group are set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing.
    /// </exception>
    public void Validate()
    {
        var missing = new List<string>();

        if(ExtractTenantIdAsync is null) { missing.Add(nameof(ExtractTenantIdAsync)); }
        if(LoadClientRegistrationAsync is null) { missing.Add(nameof(LoadClientRegistrationAsync)); }
        if(SaveFlowStateAsync is null) { missing.Add(nameof(SaveFlowStateAsync)); }
        if(LoadFlowStateAsync is null) { missing.Add(nameof(LoadFlowStateAsync)); }
        if(ResolvePolicyAsync is null) { missing.Add(nameof(ResolvePolicyAsync)); }

        if(missing.Count > 0)
        {
            var sb = new StringBuilder(
                "AuthorizationServerIntegration is missing required delegates: ");
            sb.AppendJoin(", ", missing);
            sb.Append('.');
            throw new InvalidOperationException(sb.ToString());
        }

        IsValidated = true;
    }
}
