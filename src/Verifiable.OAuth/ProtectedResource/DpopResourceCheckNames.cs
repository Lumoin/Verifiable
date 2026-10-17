namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The closed list of names a <see cref="DpopResourceDecision"/> names its refusing check by, the values of
/// <see cref="Diagnostics.OAuthTagNames.DpopResourceCheck"/>: one name per check of
/// <see cref="DpopResourceAccess.DecideCoreAsync"/>, each a fixed low-cardinality text the library chooses, never a value
/// of the presentation. Every refusal of
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> ("The resource server MUST
/// NOT grant access to the resource unless all checks are successful.") names the check that refused.
/// </summary>
internal static class DpopResourceCheckNames
{
    /// <summary>
    /// A presentation under another scheme where DPoP-bound access tokens are required, answered with the <c>DPoP</c>
    /// challenge alone (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>dpop_bound_access_tokens_required</c>).
    /// </summary>
    public static string DpopRequired { get; } = "dpop_required";

    /// <summary>
    /// A token bound to no key presented under the <c>DPoP</c> scheme, which carries a DPoP-bound access token
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>).
    /// </summary>
    public static string UnboundUnderDpop { get; } = "unbound_under_dpop";

    /// <summary>
    /// A token sender-constrained by a confirmation method other than <c>jkt</c>, which the resource cannot enforce, so a
    /// check of the binding cannot succeed (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449
    /// Section 7.1</see>: "The resource server MUST NOT grant access to the resource unless all checks are successful.").
    /// </summary>
    public static string UnsupportedConfirmation { get; } = "unsupported_confirmation";

    /// <summary>
    /// A DPoP-bound token presented as a bearer token (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC
    /// 9449 Section 7.2</see>: "such a protected resource MUST reject a DPoP-bound access token received as a bearer token
    /// per [RFC6750].").
    /// </summary>
    public static string BoundUnderBearer { get; } = "bound_under_bearer";

    /// <summary>
    /// A check of a DPoP-bound token the resource has not wired, refused as a server error rather than served as a bearer
    /// token, since a check that does not run does not succeed
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful.").
    /// </summary>
    public static string ChecksNotWired { get; } = "checks_not_wired";

    /// <summary>
    /// More than one <c>DPoP</c> field line (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449
    /// Section 4.3</see>, check 1: "There is not more than one DPoP HTTP request header field.").
    /// </summary>
    public static string DpopFieldCount { get; } = "dpop_field_count";

    /// <summary>
    /// No <c>DPoP</c> field, answered with the resource's nonce challenge
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: the resource "MUST
    /// check that a DPoP proof was also received in the DPoP header field").
    /// </summary>
    public static string ProofAbsent { get; } = "proof_absent";

    /// <summary>
    /// No usable list of accepted algorithms to hold a proof's <c>alg</c> to, a server error
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5).
    /// </summary>
    public static string AlgorithmList { get; } = "algorithm_list";

    /// <summary>A proof that failed its validation (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>).</summary>
    public static string ProofValidation { get; } = "proof_validation";

    /// <summary>
    /// A validation answering success without the proof key's thumbprint or the proof's claims, a fault of the server's
    /// own validator refused as a server error, since the key binding and the later checks cannot be made on it; the name
    /// of both such checks (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>:
    /// "The resource server MUST NOT grant access to the resource unless all checks are successful.").
    /// </summary>
    public static string ValidatedProofIncomplete { get; } = "validated_proof_incomplete";

    /// <summary>
    /// The proof's key is not the one the token is bound to
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 12;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see>).
    /// </summary>
    public static string KeyBinding { get; } = "key_binding";

    /// <summary>
    /// The proof's <c>iat</c> outside the resource's freshness window
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "servers MUST only
    /// accept DPoP proofs for a limited time after their creation").
    /// </summary>
    public static string FreshnessWindow { get; } = "freshness_window";

    /// <summary>
    /// A proof carrying no nonce, answered with the nonce challenge
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">RFC 9449 Section 11.3</see>: "A server MUST NOT
    /// accept any DPoP proofs without the nonce claim when a DPoP nonce has been provided to the client.").
    /// </summary>
    public static string NonceAbsent { get; } = "nonce_absent";

    /// <summary>
    /// A nonce the resource did not provide for the target URI
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "nonces will be only
    /// accepted by the server that issued them").
    /// </summary>
    public static string NonceValidation { get; } = "nonce_validation";

    /// <summary>
    /// A proof's <c>jti</c> presented before at the target URI, or one no record can hold; the name of both such checks
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to
    /// the same URI for which the jti value has been seen before would be declined.").
    /// </summary>
    public static string Jti { get; } = "jti";

    /// <summary>
    /// The <c>jti</c> record could not record the proof, so the proof cannot be held to one use and is refused as a server
    /// error (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>).
    /// </summary>
    public static string JtiStoreUnavailable { get; } = "jti_store_unavailable";

    /// <summary>
    /// The <c>jti</c> record answered an outcome the checks do not name, refused as a server error since only a first use
    /// grants access (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>).
    /// </summary>
    public static string JtiOutcomeUnrecognized { get; } = "jti_outcome_unrecognized";
}
