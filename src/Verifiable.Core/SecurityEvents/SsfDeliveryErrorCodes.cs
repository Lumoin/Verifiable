namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The SET delivery error codes (<c>err</c> values) defined by the Security Event
/// Token delivery specs — push (<see href="https://www.rfc-editor.org/rfc/rfc8935#section-2.4">RFC 8935 §2.4</see>)
/// and poll (<see href="https://www.rfc-editor.org/rfc/rfc8936">RFC 8936</see>) — plus the
/// SSF-defined <see cref="InvalidState"/> for a failed verification (SSF 1.0 §8.1.4.1).
/// Used in a push error response body and in the per-SET entries of a poll
/// request's <c>setErrs</c>.
/// </summary>
public static class SsfDeliveryErrorCodes
{
    /// <summary><c>invalid_request</c> — the request body / SET cannot be parsed or is otherwise invalid.</summary>
    public static readonly string InvalidRequest = "invalid_request";

    /// <summary><c>invalid_key</c> — a key used to sign or encrypt the SET is invalid or revoked.</summary>
    public static readonly string InvalidKey = "invalid_key";

    /// <summary><c>invalid_issuer</c> — the SET Issuer is invalid for the Receiver.</summary>
    public static readonly string InvalidIssuer = "invalid_issuer";

    /// <summary><c>invalid_audience</c> — the SET Audience does not correspond to the Receiver.</summary>
    public static readonly string InvalidAudience = "invalid_audience";

    /// <summary><c>authentication_failed</c> — the Recipient could not authenticate the SET.</summary>
    public static readonly string AuthenticationFailed = "authentication_failed";

    /// <summary><c>access_denied</c> — delivery is not authorized.</summary>
    public static readonly string AccessDenied = "access_denied";

    /// <summary><c>invalid_state</c> — a Verification Event's <c>state</c> did not match (SSF §8.1.4.1).</summary>
    public static readonly string InvalidState = "invalid_state";


    /// <summary>Whether <paramref name="code"/> is <see cref="InvalidRequest"/>.</summary>
    public static bool IsInvalidRequest(string code) => Equals(code, InvalidRequest);

    /// <summary>Whether <paramref name="code"/> is <see cref="InvalidKey"/>.</summary>
    public static bool IsInvalidKey(string code) => Equals(code, InvalidKey);

    /// <summary>Whether <paramref name="code"/> is <see cref="InvalidIssuer"/>.</summary>
    public static bool IsInvalidIssuer(string code) => Equals(code, InvalidIssuer);

    /// <summary>Whether <paramref name="code"/> is <see cref="InvalidAudience"/>.</summary>
    public static bool IsInvalidAudience(string code) => Equals(code, InvalidAudience);

    /// <summary>Whether <paramref name="code"/> is <see cref="AuthenticationFailed"/>.</summary>
    public static bool IsAuthenticationFailed(string code) => Equals(code, AuthenticationFailed);

    /// <summary>Whether <paramref name="code"/> is <see cref="AccessDenied"/>.</summary>
    public static bool IsAccessDenied(string code) => Equals(code, AccessDenied);

    /// <summary>Whether <paramref name="code"/> is <see cref="InvalidState"/>.</summary>
    public static bool IsInvalidState(string code) => Equals(code, InvalidState);


    /// <summary>Compares two error codes for equality (case-sensitive).</summary>
    public static bool Equals(string codeA, string codeB) =>
        object.ReferenceEquals(codeA, codeB) || System.StringComparer.Ordinal.Equals(codeA, codeB);
}


/// <summary>
/// A SET error descriptor: an <c>err</c> code and an optional human-readable
/// <c>description</c> (RFC 8935 §2.4 / RFC 8936 §2.6). Carried in a push error
/// response body and as each value of a poll request's <c>setErrs</c>.
/// </summary>
public sealed record SsfSetError
{
    /// <summary>The <c>err</c> code (REQUIRED) — see <see cref="SsfDeliveryErrorCodes"/>.</summary>
    public required string Err { get; init; }

    /// <summary>The OPTIONAL <c>description</c> elaborating the error.</summary>
    public string? Description { get; init; }
}


/// <summary>The member NAMES of a SET error object (<c>err</c>, <c>description</c>).</summary>
public static class SsfSetErrorParameterNames
{
    /// <summary><c>err</c> — the error code.</summary>
    public static readonly string Err = "err";

    /// <summary><c>description</c> — the optional error description.</summary>
    public static readonly string Description = "description";
}
