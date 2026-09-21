using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Span event names emitted during OAuth-specific operations. These events are added
/// to whichever span is active on <see cref="System.Diagnostics.Activity.Current"/> at the
/// time the OAuth operation runs (typically the host-loop dispatch span).
/// </summary>
/// <remarks>
/// <para>
/// Events are points in time within a span. Each event here corresponds to a discrete
/// observable occurrence in an OAuth endpoint handler that is worth surfacing in traces
/// for monitoring and alerting purposes.
/// </para>
/// </remarks>
public static class OAuthEventNames
{
    /// <summary>The UTF-8 source literal of <see cref="ExtraneousAuthorizeParameters"/>.</summary>
    public static ReadOnlySpan<byte> ExtraneousAuthorizeParametersUtf8 =>
        "oauth.authorize.extraneous_parameters_ignored"u8;

    /// <summary>
    /// A <c>request_uri</c>-referenced authorization request (PAR per RFC 9126, or JAR by
    /// reference per RFC 9101) carried front-channel parameters beyond <c>request_uri</c> and
    /// <c>client_id</c>. Per RFC 9101 §6.3 the authorization server uses only the pushed
    /// parameters and ignores these extras; their presence may indicate a non-conformant client
    /// or a front-channel tampering attempt, so it is surfaced for deployments to alert on.
    /// </summary>
    public static string ExtraneousAuthorizeParameters { get; } =
        Utf8Constants.ToInternedString(ExtraneousAuthorizeParametersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DuplicateGrantedCredentialConfigurationCollapsed"/>.</summary>
    public static ReadOnlySpan<byte> DuplicateGrantedCredentialConfigurationCollapsedUtf8 =>
        "oauth.token.duplicate_credential_configuration_collapsed"u8;

    /// <summary>
    /// The token endpoint collapsed a second granted authorization for an already-granted
    /// <c>credential_configuration_id</c> into a single OID4VCI 1.0 §6.2 entry. This is the §5.1.2
    /// scope-vs-<c>authorization_details</c> collision: a <c>scope</c> value mapped to the same
    /// Credential type as an <c>openid_credential</c> authorization details object, and the
    /// authorization details object took precedence so the type is granted once. Observational; it
    /// does not change the single-grant outcome.
    /// </summary>
    public static string DuplicateGrantedCredentialConfigurationCollapsed { get; } =
        Utf8Constants.ToInternedString(DuplicateGrantedCredentialConfigurationCollapsedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LongLivedBearerCredentialTokenRefused"/>.</summary>
    public static ReadOnlySpan<byte> LongLivedBearerCredentialTokenRefusedUtf8 =>
        "oauth.token.long_lived_bearer_credential_token_refused"u8;

    /// <summary>
    /// The token endpoint refused to issue an Access Token giving access to Credentials because it
    /// would outlive the OID4VCI 1.0 §13.10 long-lived threshold
    /// (<see cref="Server.TimingPolicy.CredentialAccessTokenSenderConstraintThreshold"/>) without
    /// being sender-constrained. §13.10: "Long-lived Access Tokens giving access to Credentials
    /// MUST not be issued unless sender-constrained." The library fails the request closed rather
    /// than mint a long-lived bearer Credential token; the event surfaces the detection for
    /// deployments to alert on.
    /// </summary>
    public static string LongLivedBearerCredentialTokenRefused { get; } =
        Utf8Constants.ToInternedString(LongLivedBearerCredentialTokenRefusedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Oid4VpClientIdMixUpRejected"/>.</summary>
    public static ReadOnlySpan<byte> Oid4VpClientIdMixUpRejectedUtf8 =>
        "oid4vp.wallet.client_id_mixup_rejected"u8;

    /// <summary>
    /// An OID4VP wallet refused an Authorization Request whose <c>client_id</c> did not match the
    /// Verifier identity the wallet pinned from the QR code or deep link
    /// (<see cref="Oid4Vp.Wallet.PresentJarOptions.ExpectedVerifierClientId"/>). Resolving the JAR
    /// signing key by the <c>client_id</c> scheme proves the request is signed by some key bound to
    /// the asserted identity, but it does not prove that identity is the one the wallet intended to
    /// answer; a forwarded or substituted request can still carry a validly-signed-but-different
    /// <c>client_id</c>. The wallet fails the presentation closed before producing any presentation
    /// or POSTing a response — the OID4VP mix-up defence — and the event surfaces the detection for
    /// deployments to alert on.
    /// </summary>
    public static string Oid4VpClientIdMixUpRejected { get; } =
        Utf8Constants.ToInternedString(Oid4VpClientIdMixUpRejectedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdentityScopesDroppedForNonEndUserGrant"/>.</summary>
    public static ReadOnlySpan<byte> IdentityScopesDroppedForNonEndUserGrantUtf8 =>
        "oauth.token.identity_scopes_dropped_for_non_end_user_grant"u8;

    /// <summary>
    /// The token endpoint narrowed the granted scope for a non-end-user grant
    /// (<c>client_credentials</c> or <c>pre_authorized_code</c>) by dropping <c>openid</c> and
    /// the OIDC Core §5.4 identity scopes (<c>profile</c> / <c>email</c> / <c>address</c> /
    /// <c>phone</c>) per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC
    /// 6749 §3.3</see> narrowing. These grants have no authenticated End-User — the subject is
    /// the client itself, or a Wallet with no established session — so a granted <c>openid</c>
    /// scope would let an ID Token or UserInfo response misrepresent a machine as an
    /// authenticated user. The dropped scope values ride under
    /// <see cref="DroppedScopesTagName"/>.
    /// </summary>
    public static string IdentityScopesDroppedForNonEndUserGrant { get; } =
        Utf8Constants.ToInternedString(IdentityScopesDroppedForNonEndUserGrantUtf8);

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key carrying the
    /// space-separated scope values dropped by an
    /// <see cref="IdentityScopesDroppedForNonEndUserGrant"/> event.
    /// </summary>
    public static string DroppedScopesTagName { get; } = "oauth.token.dropped_scopes";

    /// <summary>The UTF-8 source literal of <see cref="SsfRequestDenied"/>.</summary>
    public static ReadOnlySpan<byte> SsfRequestDeniedUtf8 =>
        "ssf.stream_management.request_denied"u8;

    /// <summary>
    /// A Stream Management API request (<see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>)
    /// was denied at the <c>AuthorizeSsfRequestAsync</c> seam, for any
    /// <c>SsfRequestDenialReason</c> — authentication, scope, tenant authority or
    /// stream-to-Receiver binding alike. The wire response carries a fixed,
    /// reason-specific description that never names the tenant, client or stream reached
    /// for; the application's own denial description (which might name any of those) rides
    /// this event's <see cref="SsfRequestDenialDescriptionTagName"/> tag instead, for
    /// deployments that want the detail in their own traces. Recorded only when the
    /// application supplied a description.
    /// </summary>
    public static string SsfRequestDenied { get; } =
        Utf8Constants.ToInternedString(SsfRequestDeniedUtf8);

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key carrying the
    /// application's own denial description for a <see cref="SsfRequestDenied"/> event.
    /// </summary>
    public static string SsfRequestDenialDescriptionTagName { get; } =
        "ssf.stream_management.request_denial_description";

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationServerMetadataResolutionFailed"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationServerMetadataResolutionFailedUtf8 =>
        "oauth.client.authorization_server_metadata_resolution_failed"u8;

    /// <summary>
    /// A client flow's <c>ResolveAuthorizationServerMetadataAsync</c> call ended with a
    /// non-<c>Resolved</c> outcome. The flow's own wire response never names the outcome or the
    /// resolver's internal defect text, since the metadata document a defect quotes from is served
    /// from a URL the authorization server itself controls; both ride this event's
    /// <see cref="AuthorizationServerMetadataResolutionOutcomeTagName"/> and
    /// <see cref="AuthorizationServerMetadataResolutionDefectTagName"/> tags instead, for
    /// deployments that want the detail in their own traces.
    /// </summary>
    public static string AuthorizationServerMetadataResolutionFailed { get; } =
        Utf8Constants.ToInternedString(AuthorizationServerMetadataResolutionFailedUtf8);

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key carrying the resolution
    /// outcome's name for an <see cref="AuthorizationServerMetadataResolutionFailed"/> event.
    /// </summary>
    public static string AuthorizationServerMetadataResolutionOutcomeTagName { get; } =
        "oauth.client.authorization_server_metadata_resolution_outcome";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key carrying the resolver's
    /// internal defect text for an <see cref="AuthorizationServerMetadataResolutionFailed"/> event.
    /// Recorded only when the resolution supplied one.
    /// </summary>
    public static string AuthorizationServerMetadataResolutionDefectTagName { get; } =
        "oauth.client.authorization_server_metadata_resolution_defect";

    /// <summary>The UTF-8 source literal of <see cref="OutboundFetchPolicyDenied"/>.</summary>
    public static ReadOnlySpan<byte> OutboundFetchPolicyDeniedUtf8 =>
        "oauth.client.outbound_fetch_policy_denied"u8;

    /// <summary>
    /// A client flow refused to dial a metadata-discovered endpoint (a token, PAR, or other
    /// client-side POST target) because <c>OutboundFetchPolicy.Evaluate</c> denied it. The
    /// endpoint came from a document the authorization server itself controls, so the wire
    /// response never names it; the reason and the denied endpoint ride this event's
    /// <see cref="OutboundFetchPolicyDenialReasonTagName"/> and
    /// <see cref="OutboundFetchPolicyDenialEndpointTagName"/> tags instead, for deployments that
    /// want the detail in their own traces.
    /// </summary>
    public static string OutboundFetchPolicyDenied { get; } =
        Utf8Constants.ToInternedString(OutboundFetchPolicyDeniedUtf8);

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key carrying the policy's deny
    /// reason for an <see cref="OutboundFetchPolicyDenied"/> event.
    /// </summary>
    public static string OutboundFetchPolicyDenialReasonTagName { get; } =
        "oauth.client.outbound_fetch_policy_denial_reason";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key carrying the denied
    /// endpoint's URL for an <see cref="OutboundFetchPolicyDenied"/> event.
    /// </summary>
    public static string OutboundFetchPolicyDenialEndpointTagName { get; } =
        "oauth.client.outbound_fetch_policy_denial_endpoint";

    /// <summary>The UTF-8 source literal of <see cref="SeamGrantedScopeExceedsRequest"/>.</summary>
    public static ReadOnlySpan<byte> SeamGrantedScopeExceedsRequestUtf8 =>
        "oauth.authorize.seam_granted_scope_exceeds_request"u8;

    /// <summary>
    /// The application's <see cref="Server.EvaluateAuthorizationRequestDelegate"/> called
    /// <see cref="Server.AuthorizationRequestDecision.Permit(string?)"/> with a scope value
    /// outside the client's requested scope, or with an empty or whitespace scope. Per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see> the
    /// seam may only narrow the requested scope, never widen it, and never to nothing; the
    /// library refuses the request with <c>server_error</c> rather than issue a silently
    /// widened or empty grant, and surfaces the defect here for deployments to alert on.
    /// </summary>
    public static string SeamGrantedScopeExceedsRequest { get; } =
        Utf8Constants.ToInternedString(SeamGrantedScopeExceedsRequestUtf8);
}
