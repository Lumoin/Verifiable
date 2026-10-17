using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Tag (attribute) names for OAuth wire facts the library already holds typed at the point of
/// use, added to <see cref="System.Diagnostics.Activity.Current"/> — the host-loop dispatch span
/// — from that point, with no new parsing.
/// </summary>
/// <remarks>
/// <para>
/// Distinct from <see cref="OAuthEventNames"/>, which names anomaly and defect span events;
/// these are routine per-request facts every applicable grant carries. Never a token, a code, a
/// subject identifier, or a secret: see <c>documents/AuthorizationServerDesign.md</c> §4.3 for
/// the tenant key's own, stricter rule.
/// </para>
/// <para>
/// No value the library composes for an attribute or event of its server operations, the dispatch span and its events
/// and the resource decision's span and event, carries an access, refresh or ID token or any segment of one, an
/// <c>Authorization</c> field value, a <c>DPoP</c> proof or any value of its claims (its <c>jti</c>, <c>nonce</c>,
/// <c>ath</c>, <c>iat</c> or <c>jwk</c>), a <c>DPoP-Nonce</c> value, a JWK SHA-256 Thumbprint of a proof key or a
/// token's <c>cnf.jkt</c>, a client secret or client assertion, an authorization code, <c>code_verifier</c>,
/// <c>state</c>, OpenID Connect <c>nonce</c>, PAR <c>request_uri</c>, pre-authorized code, <c>tx_code</c> or
/// <c>c_nonce</c>, the tenant key, a subject identifier or end-user claim, a request or response body or header value,
/// or <c>url.full</c>, <c>url.path</c> or <c>url.query</c>
/// (<see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#privacy-considerations">W3C Trace Context Level
/// 1, Section 6</see>: "Tracing vendors MUST NOT use traceparent and tracestate fields for any personally identifiable
/// or otherwise sensitive information."; <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry
/// semantic conventions for HTTP spans</see>: "Including all request headers can be a security risk - explicit
/// configuration helps avoid leaking sensitive information."). The resource decision's values are the decision kind's
/// name, a name of the closed list <see cref="DpopResourceCheck"/> documents, the answer's error code
/// (<c>server.response.error_code</c>) and <c>error.type</c>: <c>500</c> on a server error answer, or the exception
/// type's fully-qualified name when a slot of the decision raises an exception, nothing of whose text is recorded.
/// Beside the decision, an exception an application delegate raises that the library handles, and a description the
/// application hands the library, are recorded as the application gave them, at these sites: the exception of the
/// application's outgoing-response inspection stage at the dispatch, the exception of the pushed authorization
/// request's transport delegate, the exception of the flow-state release seam, the exception of the shared signals
/// authorization seam, and the denial description the shared signals host answers.
/// </para>
/// </remarks>
public static class OAuthTagNames
{
    /// <summary>The UTF-8 source literal of <see cref="GrantType"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypeUtf8 => "oauth.token.grant_type"u8;

    /// <summary>The wire <c>grant_type</c> value the token endpoint issued tokens for.</summary>
    public static string GrantType { get; } = Utf8Constants.ToInternedString(GrantTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "oauth.token.client_id"u8;

    /// <summary>The requesting client's <c>client_id</c>.</summary>
    public static string ClientId { get; } = Utf8Constants.ToInternedString(ClientIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GrantedScope"/>.</summary>
    public static ReadOnlySpan<byte> GrantedScopeUtf8 => "oauth.token.granted_scope"u8;

    /// <summary>The granted scope string carried by the tokens issued for the request.</summary>
    public static string GrantedScope { get; } = Utf8Constants.ToInternedString(GrantedScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PkceMethod"/>.</summary>
    public static ReadOnlySpan<byte> PkceMethodUtf8 => "oauth.token.pkce_method"u8;

    /// <summary>
    /// The RFC 7636 §4.3 <c>code_challenge_method</c> the redeemed authorization code carried.
    /// </summary>
    public static string PkceMethod { get; } = Utf8Constants.ToInternedString(PkceMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessTokenJti"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenJtiUtf8 => "oauth.token.access_token_jti"u8;

    /// <summary>The <c>jti</c> claim of the issued access token.</summary>
    public static string AccessTokenJti { get; } = Utf8Constants.ToInternedString(AccessTokenJtiUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DpopResourceDecision"/>.</summary>
    public static ReadOnlySpan<byte> DpopResourceDecisionUtf8 => "oauth.dpop.resource.decision"u8;

    /// <summary>
    /// The kind of a protected resource's decision on one presentation of an access token by the checks of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: the name of its
    /// <see cref="ProtectedResource.DpopResourceDecisionKind"/>, <c>Permit</c>, <c>Deny</c> or <c>IndeterminateDeny</c>.
    /// Carried by the <see cref="OAuthActivityNames.DecideResourceAccess"/> span and by the
    /// <see cref="OAuthEventNames.DpopResourceDecided"/> event.
    /// </summary>
    public static string DpopResourceDecision { get; } = Utf8Constants.ToInternedString(DpopResourceDecisionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DpopResourceCheck"/>.</summary>
    public static ReadOnlySpan<byte> DpopResourceCheckUtf8 => "oauth.dpop.resource.check"u8;

    /// <summary>
    /// The name of the check that refused a presentation, carried beside <see cref="DpopResourceDecision"/> on a
    /// <c>Deny</c> or an <c>IndeterminateDeny</c> and absent on a <c>Permit</c>. Its values are a closed list, each the
    /// check of <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> ("The resource
    /// server MUST NOT grant access to the resource unless all checks are successful.") that refused:
    /// <list type="bullet">
    ///   <item><description><c>dpop_required</c>: a presentation under another scheme where DPoP-bound access tokens are required (RFC 9728 Section 2).</description></item>
    ///   <item><description><c>unbound_under_dpop</c>: a token bound to no key presented under the <c>DPoP</c> scheme (RFC 9449 Section 7.1).</description></item>
    ///   <item><description><c>unsupported_confirmation</c>: a token sender-constrained by a confirmation method other than <c>jkt</c>.</description></item>
    ///   <item><description><c>bound_under_bearer</c>: a DPoP-bound token presented as a bearer token (RFC 9449 Section 7.2).</description></item>
    ///   <item><description><c>checks_not_wired</c>: a check the resource has not wired, a server error.</description></item>
    ///   <item><description><c>dpop_field_count</c>: more than one <c>DPoP</c> field line (RFC 9449 Section 4.3, check 1).</description></item>
    ///   <item><description><c>proof_absent</c>: no <c>DPoP</c> field, answered with the nonce challenge (RFC 9449 Section 7.1).</description></item>
    ///   <item><description><c>algorithm_list</c>: no usable list of accepted algorithms, a server error (RFC 9449 Section 4.3, check 5).</description></item>
    ///   <item><description><c>proof_validation</c>: the proof failed its validation (RFC 9449 Section 4.3).</description></item>
    ///   <item><description><c>validated_proof_incomplete</c>: a validation answering success without the key's thumbprint or the proof's claims, a server error.</description></item>
    ///   <item><description><c>key_binding</c>: the proof's key is not the one the token is bound to (RFC 9449 Section 4.3, check 12; Section 6.1).</description></item>
    ///   <item><description><c>freshness_window</c>: the proof's <c>iat</c> outside the resource's window (RFC 9449 Section 11.1).</description></item>
    ///   <item><description><c>nonce_absent</c>: a proof carrying no nonce, answered with the nonce challenge (RFC 9449 Section 11.3).</description></item>
    ///   <item><description><c>nonce_validation</c>: a nonce the resource did not provide for the target URI (RFC 9449 Section 9).</description></item>
    ///   <item><description><c>jti</c>: a proof's <c>jti</c> presented before at the target URI, or one no record can hold (RFC 9449 Section 11.1).</description></item>
    ///   <item><description><c>jti_store_unavailable</c>: the <c>jti</c> record could not record the proof, a server error (RFC 9449 Section 11.1).</description></item>
    ///   <item><description><c>jti_outcome_unrecognized</c>: the <c>jti</c> record answered an outcome the checks do not name, a server error (RFC 9449 Section 7.1).</description></item>
    /// </list>
    /// </summary>
    public static string DpopResourceCheck { get; } = Utf8Constants.ToInternedString(DpopResourceCheckUtf8);
}
