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
    public static readonly string ExtraneousAuthorizeParameters =
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
    public static readonly string DuplicateGrantedCredentialConfigurationCollapsed =
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
    public static readonly string LongLivedBearerCredentialTokenRefused =
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
    public static readonly string Oid4VpClientIdMixUpRejected =
        Utf8Constants.ToInternedString(Oid4VpClientIdMixUpRejectedUtf8);
}
