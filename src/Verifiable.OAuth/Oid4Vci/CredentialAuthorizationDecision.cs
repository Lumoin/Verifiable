using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The reason an application refused an <c>openid_credential</c> authorization details request
/// at the <see cref="Server.ResolveCredentialAuthorizationDelegate"/> seam. The library maps
/// each reason to the RFC 9396 §5 <c>invalid_authorization_details</c> error, since only the
/// application — which owns the supported Credential Configurations and the Credential Dataset
/// store — can distinguish these cases.
/// </summary>
public enum CredentialAuthorizationDenialReason
{
    /// <summary>
    /// A requested <c>credential_configuration_id</c> is not among the Credential
    /// Configurations this issuer supports.
    /// </summary>
    UnknownCredentialConfiguration,

    /// <summary>
    /// The deployment refused the requested authorization — for example the subject is not
    /// entitled to the requested Credential, or the <c>locations</c> value does not name this
    /// Credential Issuer.
    /// </summary>
    AuthorizationDenied
}


/// <summary>
/// One granted <c>openid_credential</c> authorization in a token response: the Credential
/// Configuration the grant covers and the Credential Dataset identifiers issuable with the
/// returned access token (OID4VCI 1.0 §6.2 <c>credential_identifiers</c>).
/// </summary>
[DebuggerDisplay("GrantedCredentialAuthorization ConfigurationId={CredentialConfigurationId} Identifiers={CredentialIdentifiers.Count}")]
public sealed record GrantedCredentialAuthorization
{
    /// <summary>The granted <c>credential_configuration_id</c>, echoed in the token response.</summary>
    public required string CredentialConfigurationId { get; init; }

    /// <summary>
    /// The §6.2 <c>credential_identifiers</c> (REQUIRED, non-empty): the Credential Dataset
    /// identifiers the Wallet presents as <c>credential_identifier</c> in subsequent
    /// Credential Requests.
    /// </summary>
    public required IReadOnlyList<string> CredentialIdentifiers { get; init; }
}


/// <summary>
/// An application's verdict on an <c>openid_credential</c> authorization details request,
/// returned from the <see cref="Server.ResolveCredentialAuthorizationDelegate"/> seam. A grant
/// carries one <see cref="GrantedCredentialAuthorization"/> per granted configuration — each
/// with the <c>credential_identifiers</c> only the application's Credential Dataset store can
/// mint; a denial carries the <see cref="DenialReason"/> the library maps to
/// <c>invalid_authorization_details</c>.
/// </summary>
/// <remarks>
/// The library owns only the wire: parsing and shape-validating the request parameter, the
/// OID4VCI 1.0 §6.1.1 narrowing rule (a token-request subset of the authorized configurations),
/// and emitting the §6.2 token-response <c>authorization_details</c>. Mirrors
/// <see cref="PreAuthorizedCodeDecision"/>.
/// </remarks>
[DebuggerDisplay("CredentialAuthorizationDecision IsGranted={IsGranted} Granted={Granted.Count} DenialReason={DenialReason}")]
public sealed record CredentialAuthorizationDecision
{
    /// <summary>
    /// Whether the requested authorization details were granted. <see langword="false"/> fails
    /// the token request with the error mapped from <see cref="DenialReason"/>.
    /// </summary>
    public required bool IsGranted { get; init; }

    /// <summary>
    /// The granted configurations with their Credential Dataset identifiers. Required non-empty
    /// on a grant; empty on a denial.
    /// </summary>
    public IReadOnlyList<GrantedCredentialAuthorization> Granted { get; init; } = [];

    /// <summary>
    /// The reason a non-granted request was refused. Ignored when <see cref="IsGranted"/> is
    /// <see langword="true"/>; a denial with no reason set is treated as
    /// <see cref="CredentialAuthorizationDenialReason.AuthorizationDenied"/>.
    /// </summary>
    public CredentialAuthorizationDenialReason? DenialReason { get; init; }

    /// <summary>
    /// An optional human-readable description carried into the error response's
    /// <c>error_description</c>. <see langword="null"/> falls back to a reason-specific default.
    /// </summary>
    public string? DenialDescription { get; init; }


    /// <summary>
    /// A grant verdict carrying the given <paramref name="granted"/> configurations.
    /// </summary>
    /// <param name="granted">The granted configurations, each with its Credential Dataset identifiers.</param>
    /// <returns>A granted <see cref="CredentialAuthorizationDecision"/>.</returns>
    public static CredentialAuthorizationDecision Grant(IReadOnlyList<GrantedCredentialAuthorization> granted)
    {
        ArgumentNullException.ThrowIfNull(granted);

        return new CredentialAuthorizationDecision
        {
            IsGranted = true,
            Granted = granted
        };
    }


    /// <summary>
    /// A deny verdict with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The reason the request was refused.</param>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A non-granted <see cref="CredentialAuthorizationDecision"/>.</returns>
    public static CredentialAuthorizationDecision Deny(
        CredentialAuthorizationDenialReason reason, string? description = null)
    {
        return new CredentialAuthorizationDecision
        {
            IsGranted = false,
            DenialReason = reason,
            DenialDescription = description
        };
    }
}
