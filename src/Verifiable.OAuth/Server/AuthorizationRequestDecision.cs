using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The reason an application denied an authorization request at the
/// <see cref="EvaluateAuthorizationRequestDelegate"/> seam. The library maps each
/// reason to the corresponding OAuth 2.0 Authorization Error Response code.
/// </summary>
public enum AuthorizationDenialReason
{
    /// <summary>
    /// The established authentication does not meet the request's authentication
    /// requirements — the requested Authentication Context Class Reference
    /// (<c>acr_values</c>) was not satisfied. Mapped to
    /// <see cref="OAuthErrors.UnmetAuthenticationRequirements"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see> /
    /// <see href="https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html">OIDCUAR</see>.
    /// </summary>
    UnmetAuthenticationRequirements,

    /// <summary>
    /// The resource owner or deployment policy denied the request — for example the
    /// End-User declined consent. Mapped to <see cref="OAuthErrors.AccessDenied"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>.
    /// </summary>
    AccessDenied
}


/// <summary>
/// The immutable snapshot of authorization-request facts handed to an application's
/// <see cref="EvaluateAuthorizationRequestDelegate"/>: what the client requested and what
/// authentication the application established. The library supplies the requested values
/// (which the application cannot otherwise see in the Pushed Authorization Request flow,
/// since they are held server-side) alongside the established authentication facts so the
/// application can reach an authorization decision without re-deriving them.
/// </summary>
[DebuggerDisplay("AuthorizationRequestEvaluation Subject={Subject} RequestedAcr={RequestedAcrValues}")]
public sealed record AuthorizationRequestEvaluation
{
    /// <summary>
    /// The requested <c>acr_values</c> (space-separated, preference-ordered), or
    /// <see langword="null"/> when the request asked for no specific authentication
    /// context class reference.
    /// </summary>
    public string? RequestedAcrValues { get; init; }

    /// <summary>
    /// The requested <c>max_age</c> in seconds, or <see langword="null"/> when absent.
    /// Informational at this seam — the library enforces the temporal <c>max_age</c>
    /// recency requirement itself before invoking the evaluator.
    /// </summary>
    public int? RequestedMaxAge { get; init; }

    /// <summary>The scope requested by the client (as carried in the authorization request).</summary>
    public required string RequestedScope { get; init; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> requested by the client, verbatim as carried
    /// in the authorization request (for PAR flows, the pushed value — a front-channel
    /// duplicate is never consulted), or <see langword="null"/> when none was requested. The
    /// value has passed the library's shape validation (supported type,
    /// <c>credential_configuration_id</c> present); the application parses it with its own JSON
    /// stack when its consent decision depends on the requested details. The granted
    /// <c>credential_identifiers</c> are resolved later, at the token endpoint, through
    /// <see cref="ResolveCredentialAuthorizationDelegate"/>.
    /// </summary>
    public string? RequestedAuthorizationDetails { get; init; }

    /// <summary>
    /// The OID4VCI 1.0 §5.1.3 <c>issuer_state</c> the Wallet echoed from a Credential Offer, or
    /// <see langword="null"/> when the request carried none. The library treats this strictly as
    /// UNTRUSTED input and validates nothing about it: §5.1.3 requires the Credential Issuer to
    /// take into account that <c>issuer_state</c> is not guaranteed to originate from this
    /// Credential Issuer — it could have been injected by an attacker. The application correlates
    /// it to the Credential Offer it created (the only party that can), and refuses the request at
    /// this seam when it cannot.
    /// </summary>
    public string? RequestedIssuerState { get; init; }

    /// <summary>
    /// The RFC 8707 <c>resource</c> indicator(s) the request carried, or <see langword="null"/>
    /// when none was present. OID4VCI 1.0 §5.1.2 RECOMMENDS the Wallet send the Credential
    /// Issuer's identifier here when the issuer metadata carries <c>authorization_servers</c>, so
    /// the Authorization Server can differentiate Credential Issuers. The library reads and
    /// surfaces the value(s) verbatim; whether and how to honor them — to scope or audience-bind
    /// the issued access token — is the application's decision.
    /// </summary>
    public IReadOnlyList<string>? RequestedResource { get; init; }

    /// <summary>The authenticated subject identifier.</summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The Authentication Context Class Reference the application established for this
    /// authentication (the value it placed on the request context via <c>SetAcr</c>), or
    /// <see langword="null"/> when none was established.
    /// </summary>
    public string? EstablishedAcr { get; init; }

    /// <summary>
    /// The instant the End-User authenticated, or <see langword="null"/> when the
    /// application stamped no authentication time.
    /// </summary>
    public DateTimeOffset? EstablishedAuthTime { get; init; }

    /// <summary>
    /// The host component of the request's <c>client_id</c> when it is URL-shaped, or
    /// <see langword="null"/> otherwise. Populated for every URL-shaped <c>client_id</c>
    /// regardless of whether its Client ID Metadata Document was fetched — draft-ietf-oauth-client-id-metadata-document-02
    /// §8.5: "The authorization server SHOULD display the hostname of the client_id on the
    /// authorization interface, in addition to displaying the fetched client information if any."
    /// </summary>
    public string? ClientIdHost { get; init; }

    /// <summary>
    /// Whether this authorization request's registration carries document-derived client
    /// metadata (<see cref="ClientName"/>, <see cref="ClientUri"/>, <see cref="LogoUri"/>) —
    /// draft-ietf-oauth-client-id-metadata-document-02 §8.5: "Authorization servers SHOULD fetch
    /// the client_id metadata document ... in order to provide users with additional
    /// information about the request." <see langword="false"/> for a pre-registered client or a
    /// CIMD client whose document fetch did not run or did not overlay any display field, in
    /// which case §8.5 ¶2 calls for the application to "take additional measures to ensure the
    /// user is provided with as much information as possible about the request" using
    /// <see cref="ClientIdHost"/> alone.
    /// </summary>
    public bool HasFetchedClientMetadata { get; init; }

    /// <summary>
    /// The client's human-readable name from the materialized registration
    /// (<see cref="ClientRecord.ClientName"/>), or <see langword="null"/> when none is known.
    /// </summary>
    public string? ClientName { get; init; }

    /// <summary>
    /// The client's web page from the materialized registration
    /// (<see cref="ClientRecord.ClientUri"/>), or <see langword="null"/> when none is known.
    /// </summary>
    public Uri? ClientUri { get; init; }

    /// <summary>
    /// The client's logo image URL from the materialized registration
    /// (<see cref="ClientRecord.LogoUri"/>), or <see langword="null"/> when none is known.
    /// </summary>
    public Uri? LogoUri { get; init; }
}


/// <summary>
/// An application's verdict on an authorization request, returned from the
/// <see cref="EvaluateAuthorizationRequestDelegate"/> seam. A denial carries the
/// <see cref="DenialReason"/> the library maps to an OAuth 2.0 Authorization Error
/// Response code, plus an optional human-readable <see cref="DenialDescription"/>.
/// </summary>
[DebuggerDisplay("AuthorizationRequestDecision IsPermitted={IsPermitted} DenialReason={DenialReason}")]
public sealed record AuthorizationRequestDecision
{
    /// <summary>
    /// Whether the request is permitted to proceed to code issuance.
    /// <see langword="false"/> fails the authorization request with the error mapped
    /// from <see cref="DenialReason"/>.
    /// </summary>
    public required bool IsPermitted { get; init; }

    /// <summary>
    /// The reason a non-permitted request was denied. Ignored when
    /// <see cref="IsPermitted"/> is <see langword="true"/>; a denial with no reason set
    /// is treated as <see cref="AuthorizationDenialReason.AccessDenied"/>.
    /// </summary>
    public AuthorizationDenialReason? DenialReason { get; init; }

    /// <summary>
    /// An optional human-readable description carried into the error response's
    /// <c>error_description</c>. <see langword="null"/> falls back to a reason-specific
    /// default.
    /// </summary>
    public string? DenialDescription { get; init; }


    /// <summary>A bare permit verdict.</summary>
    public static AuthorizationRequestDecision Permit { get; } = new() { IsPermitted = true };


    /// <summary>
    /// A deny verdict with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The reason the request was denied.</param>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A non-permitted <see cref="AuthorizationRequestDecision"/>.</returns>
    public static AuthorizationRequestDecision Deny(
        AuthorizationDenialReason reason, string? description = null)
    {
        return new AuthorizationRequestDecision
        {
            IsPermitted = false,
            DenialReason = reason,
            DenialDescription = description
        };
    }
}
