using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the AuthZEN Authorization API 1.0
/// Policy Decision Point metadata document
/// (<c>/.well-known/authzen-configuration</c>), per
/// <see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN
/// Authorization API 1.0 §9.1 (Policy Decision Point Metadata)</see>.
/// </summary>
/// <remarks>
/// These are the NAMES of PDP metadata parameters (e.g.,
/// <c>"access_evaluation_endpoint"</c>, <c>"search_subject_endpoint"</c>),
/// not their VALUES. Values are deployment-specific URLs the application
/// supplies through
/// <see cref="Server.AuthorizationServerIntegration.ResolveEndpointUriAsync"/>.
/// </remarks>
public static class AuthZenMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="PolicyDecisionPoint"/>.</summary>
    public static ReadOnlySpan<byte> PolicyDecisionPointUtf8 => "policy_decision_point"u8;

    /// <summary>
    /// The Policy Decision Point identifier — a URL using the <c>https</c>
    /// scheme (§9.1, REQUIRED).
    /// </summary>
    public static readonly string PolicyDecisionPoint = Utf8Constants.ToInternedString(PolicyDecisionPointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessEvaluationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> AccessEvaluationEndpointUtf8 => "access_evaluation_endpoint"u8;

    /// <summary>
    /// URL of the PDP's Access Evaluation API endpoint (§9.1, REQUIRED).
    /// </summary>
    public static readonly string AccessEvaluationEndpoint = Utf8Constants.ToInternedString(AccessEvaluationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessEvaluationsEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> AccessEvaluationsEndpointUtf8 => "access_evaluations_endpoint"u8;

    /// <summary>
    /// URL of the PDP's batch Access Evaluations API endpoint (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string AccessEvaluationsEndpoint = Utf8Constants.ToInternedString(AccessEvaluationsEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SearchSubjectEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> SearchSubjectEndpointUtf8 => "search_subject_endpoint"u8;

    /// <summary>
    /// URL of the PDP's Search API endpoint for subject entities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SearchSubjectEndpoint = Utf8Constants.ToInternedString(SearchSubjectEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SearchResourceEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> SearchResourceEndpointUtf8 => "search_resource_endpoint"u8;

    /// <summary>
    /// URL of the PDP's Search API endpoint for resource entities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SearchResourceEndpoint = Utf8Constants.ToInternedString(SearchResourceEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SearchActionEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> SearchActionEndpointUtf8 => "search_action_endpoint"u8;

    /// <summary>
    /// URL of the PDP's Search API endpoint for action entities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SearchActionEndpoint = Utf8Constants.ToInternedString(SearchActionEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Capabilities"/>.</summary>
    public static ReadOnlySpan<byte> CapabilitiesUtf8 => "capabilities"u8;

    /// <summary>
    /// A JSON array of registered IANA URNs referencing PDP-specific
    /// capabilities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string Capabilities = Utf8Constants.ToInternedString(CapabilitiesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SignedMetadata"/>.</summary>
    public static ReadOnlySpan<byte> SignedMetadataUtf8 => "signed_metadata"u8;

    /// <summary>
    /// A JWT carrying the metadata parameters as claims, signed by the PDP
    /// (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SignedMetadata = Utf8Constants.ToInternedString(SignedMetadataUtf8);
}
