namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the AuthZEN Authorization API 1.0
/// metadata document. These are JSON keys appearing in a Policy
/// Decision Point's (PDP) metadata document.
/// </summary>
/// <remarks>
/// These are the NAMES of PDP metadata parameters (e.g.,
/// <c>"evaluation_endpoint"</c>, <c>"subject_search_endpoint"</c>), not
/// their VALUES. Values are deployment-specific URLs.
/// </remarks>
public static class AuthZenMetadataParameterNames
{
    /// <summary>
    /// URL of the PDP's access evaluation endpoint.
    /// </summary>
    public static readonly string EvaluationEndpoint = "evaluation_endpoint";

    /// <summary>
    /// URL of the PDP's batch access evaluations endpoint.
    /// </summary>
    public static readonly string EvaluationsEndpoint = "evaluations_endpoint";

    /// <summary>
    /// URL of the PDP's subject search endpoint.
    /// </summary>
    public static readonly string SubjectSearchEndpoint = "subject_search_endpoint";

    /// <summary>
    /// URL of the PDP's resource search endpoint.
    /// </summary>
    public static readonly string ResourceSearchEndpoint = "resource_search_endpoint";

    /// <summary>
    /// URL of the PDP's action search endpoint.
    /// </summary>
    public static readonly string ActionSearchEndpoint = "action_search_endpoint";
}
