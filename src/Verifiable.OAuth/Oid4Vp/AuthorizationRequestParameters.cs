namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Authorization request parameter name constants for OID4VP.
/// </summary>
/// <remarks>
/// Used when constructing or parsing the JAR JWT claims or the PAR request body.
/// </remarks>
public static class AuthorizationRequestParameters
{
    /// <summary>The <c>response_type</c> parameter. Always <c>vp_token</c> in OID4VP.</summary>
    public const string ResponseType = "response_type";

    /// <summary>The fixed value for <see cref="ResponseType"/> in OID4VP.</summary>
    public const string ResponseTypeVpToken = "vp_token";

    /// <summary>The <c>client_id</c> parameter identifying the verifier.</summary>
    public const string ClientId = "client_id";

    /// <summary>The <c>client_id_scheme</c> parameter identifying the client identifier scheme.</summary>
    public const string ClientIdScheme = "client_id_scheme";

    /// <summary>The <c>response_mode</c> parameter.</summary>
    public const string ResponseMode = "response_mode";

    /// <summary>The <c>response_uri</c> parameter — the endpoint to POST the response to.</summary>
    public const string ResponseUri = "response_uri";

    /// <summary>The <c>nonce</c> parameter for replay protection and KB-JWT binding.</summary>
    public const string Nonce = "nonce";

    /// <summary>The <c>state</c> parameter for CSRF protection.</summary>
    public const string State = "state";

    /// <summary>The <c>dcql_query</c> parameter carrying the DCQL query object.</summary>
    public const string DcqlQuery = "dcql_query";

    /// <summary>The <c>client_metadata</c> parameter carrying inline verifier metadata.</summary>
    public const string ClientMetadata = "client_metadata";

    /// <summary>The <c>iss</c> parameter carrying the verifier's identifier.</summary>
    public const string Iss = "iss";

    /// <summary>The <c>aud</c> parameter identifying the intended authorization server.</summary>
    public const string Aud = "aud";
}
