namespace Verifiable.OAuth.Logout;

/// <summary>
/// The outcome an application's revoke-subject seam reports for a Global Token
/// Revocation command, mapped by the endpoint to the
/// <see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>
/// status codes. Malformed bodies (400) and failed client authentication (401)
/// are handled by the endpoint before the seam runs; this enum covers the
/// outcomes only the application can determine.
/// </summary>
public enum GlobalTokenRevocationOutcome
{
    /// <summary>Revocation was initiated for the subject — HTTP 204.</summary>
    Initiated,

    /// <summary>The subject is not known to this server — HTTP 404.</summary>
    SubjectNotFound,

    /// <summary>The client is authenticated but not authorized to revoke this subject — HTTP 403.</summary>
    Forbidden,

    /// <summary>The request was well-formed and understood but cannot be acted on — HTTP 422.</summary>
    Unprocessable
}
