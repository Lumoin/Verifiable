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
    /// <summary>
    /// The Policy Decision Point identifier — a URL using the <c>https</c>
    /// scheme (§9.1, REQUIRED).
    /// </summary>
    public static readonly string PolicyDecisionPoint = "policy_decision_point";

    /// <summary>
    /// URL of the PDP's Access Evaluation API endpoint (§9.1, REQUIRED).
    /// </summary>
    public static readonly string AccessEvaluationEndpoint = "access_evaluation_endpoint";

    /// <summary>
    /// URL of the PDP's batch Access Evaluations API endpoint (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string AccessEvaluationsEndpoint = "access_evaluations_endpoint";

    /// <summary>
    /// URL of the PDP's Search API endpoint for subject entities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SearchSubjectEndpoint = "search_subject_endpoint";

    /// <summary>
    /// URL of the PDP's Search API endpoint for resource entities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SearchResourceEndpoint = "search_resource_endpoint";

    /// <summary>
    /// URL of the PDP's Search API endpoint for action entities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SearchActionEndpoint = "search_action_endpoint";

    /// <summary>
    /// A JSON array of registered IANA URNs referencing PDP-specific
    /// capabilities (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string Capabilities = "capabilities";

    /// <summary>
    /// A JWT carrying the metadata parameters as claims, signed by the PDP
    /// (§9.1, OPTIONAL).
    /// </summary>
    public static readonly string SignedMetadata = "signed_metadata";
}
