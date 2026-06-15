using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// The Authorization Server received and validated a Pushed Authorization Request.
/// A <c>request_uri</c> has been assigned and returned to the client. The server
/// is waiting for the authorization endpoint to be called.
/// </summary>
/// <remarks>
/// <para>
/// This is the first persistence point for the server-side flow. Everything needed
/// to validate the subsequent authorize and token requests is stored here:
/// the PKCE code challenge for downgrade defense, the redirect URI for exact-match
/// validation, and the scope for grant validation.
/// </para>
/// <para>
/// The <see cref="RequestUri"/> is used as a secondary lookup key when the
/// authorization endpoint receives <c>request_uri</c> as a query parameter. The
/// application maps <c>request_uri → flowId</c> to locate this state.
/// </para>
/// <para>
/// Transitions to <see cref="ServerCodeIssuedState"/> when <see cref="ServerAuthorizeCompleted"/>
/// arrives with a matching <see cref="RequestUri"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ParRequestReceived FlowId={FlowId} RequestUri={RequestUri}")]
public sealed record ParRequestReceivedState: FlowState
{
    /// <summary>
    /// The <c>request_uri</c> assigned to this PAR entry and returned to the client.
    /// The application maps this to <see cref="FlowState.FlowId"/> so the
    /// authorization endpoint can load this state by <c>request_uri</c>.
    /// </summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The PKCE S256 code challenge from the PAR request body.
    /// Stored so the token endpoint can verify <c>SHA256(code_verifier) == CodeChallenge</c>
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>.
    /// </summary>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// The redirect URI from the PAR request. Exact-match validation is enforced
    /// at the authorization endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The scope from the PAR request, carried forward for grant validation.</summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The client identifier from the PAR request. Carried forward so the
    /// authorize and token endpoints can confirm the same client is continuing.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The <c>nonce</c> from the PAR request. Carried forward and bound into the
    /// ID Token at the token endpoint per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The lifetime in seconds of the <c>request_uri</c> from the moment the PAR
    /// request was received, returned to the client as the <c>expires_in</c>
    /// field of the PAR response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Carried as a first-class field rather than being recomputed at response
    /// time from <c>(ExpiresAt - EnteredAt).TotalSeconds</c>. The wire value is
    /// what was promised to the client; persisting it explicitly removes any
    /// ambiguity about rounding, time-source drift between assembly and
    /// response, or future changes to the lifetime source making the
    /// recomputation diverge from the value the client first saw.
    /// </para>
    /// <para>
    /// The library's <c>BuildPar</c> handler populates this from
    /// <see cref="Verifiable.OAuth.Server.TimingPolicy.AuthCodeParLifetime"/>;
    /// applications that compute the lifetime differently set it on
    /// <see cref="Verifiable.OAuth.AuthCode.Server.ServerParValidated"/> at the
    /// flow input stage.
    /// </para>
    /// </remarks>
    public required int ExpiresIn { get; init; }

    /// <summary>
    /// The <c>acr_values</c> from the PAR request (space-separated, preference-ordered),
    /// or <see langword="null"/> when none was requested. Carried forward so the authorization
    /// endpoint can evaluate whether the established authentication satisfies the requested
    /// Authentication Context Class Reference per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see>.
    /// </summary>
    public string? AcrValues { get; init; }

    /// <summary>
    /// The <c>max_age</c> from the PAR request (maximum authentication age in seconds), or
    /// <see langword="null"/> when none was requested. Carried forward so the authorization
    /// endpoint can enforce authentication recency per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    public int? MaxAge { get; init; }

    /// <summary>
    /// The opaque <c>state</c> value from the pushed authorization request, carried forward so
    /// the authorization endpoint echoes it on both the success and error redirects per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// <see langword="null"/> when the request carried no <c>state</c>.
    /// </summary>
    public string? State { get; init; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> value from the pushed authorization request,
    /// verbatim and shape-validated at PAR receipt, or <see langword="null"/> when the request
    /// carried none. The pushed value is authoritative (RFC 9101 §6.3 via RFC 9126 §4 — a
    /// front-channel duplicate is ignored) and is carried to the token endpoint, where the
    /// granted <c>credential_identifiers</c> are resolved per OID4VCI 1.0 §6.2.
    /// </summary>
    public string? AuthorizationDetails { get; init; }

    /// <summary>
    /// The <c>response_mode</c> the pushed authorization request asked for — authoritative
    /// over any front-channel duplicate per RFC 9101 §6.3 via RFC 9126 §4 — carried forward
    /// so the authorize response site knows whether to wrap the response in a JARM JWT
    /// (<see cref="Jarm.JarmResponseModes"/>). <see langword="null"/> when the request
    /// carried no <c>response_mode</c>.
    /// </summary>
    public string? ResponseMode { get; init; }

    /// <summary>
    /// The OID4VCI 1.0 §5.1.3 <c>issuer_state</c> the pushed authorization request carried,
    /// verbatim, or <see langword="null"/> when none was present. Carried to the authorization
    /// endpoint, where it is surfaced as UNTRUSTED input to the application's
    /// authorization-decision seam — §5.1.3 requires the issuer to treat it as possibly
    /// attacker-injected, so the library validates nothing about it and only the application can
    /// correlate it to the Credential Offer it created. The pushed value is authoritative over any
    /// front-channel duplicate (RFC 9101 §6.3 via RFC 9126 §4).
    /// </summary>
    public string? IssuerState { get; init; }

    /// <summary>
    /// The RFC 8707 <c>resource</c> indicator(s) the pushed authorization request carried
    /// (space-delimited when multiple), or <see langword="null"/> when none was present. Carried
    /// to the authorization endpoint and surfaced to the authorization-decision seam; OID4VCI 1.0
    /// §5.1.2 RECOMMENDS its use to let the Authorization Server differentiate Credential Issuers.
    /// </summary>
    public string? Resource { get; init; }
}
