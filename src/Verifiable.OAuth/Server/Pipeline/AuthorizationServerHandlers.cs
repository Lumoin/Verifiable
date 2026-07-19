using System.Diagnostics;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Well-known context bag key constants for the OAuth-specific values the OAuth/OpenID
/// endpoints place on the request context. The host-generic keys (capability, issuer,
/// registration, flow id, matched payload, the active host) live in the dispatch host's
/// own internal key holder.
/// </summary>
/// <remarks>
/// <para>
/// The context bag is typed as <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/>
/// of <see cref="string"/> to <see cref="object"/> to avoid coupling the library to
/// ASP.NET or any other HTTP framework. The endpoints read them via the typed accessors on
/// <see cref="ExchangeContextServerExtensions"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServerHandlers")]
internal static class AuthorizationServerHandlers
{
    /// <summary>
    /// Context key for accumulated validation results produced during request processing.
    /// Value type: <see cref="System.Collections.Generic.List{T}"/> of
    /// <see cref="Verifiable.Core.Assessment.ClaimIssueResult"/>.
    /// </summary>
    public const string ValidationResultsKey = "server.validationResults";

    /// <summary>
    /// Context-bag key for the <see cref="IssuedTokenSet"/> assembled by the token endpoint's
    /// <c>BuildInputAsync</c> for consumption by <c>BuildResponse</c>. Transient — never persisted.
    /// </summary>
    public const string IssuedTokensKey = "server.issuedTokens";

    /// <summary>
    /// Context-bag key for the granted RFC 9396 <c>authorization_details</c> response value
    /// (the serialised JSON array carrying the OID4VCI 1.0 §6.2 <c>credential_identifiers</c>).
    /// Transient — never persisted.
    /// </summary>
    public const string GrantedAuthorizationDetailsKey = "server.grantedAuthorizationDetails";

    /// <summary>
    /// Context-bag key for the granted RFC 9396 <c>authorization_details</c> in structured form.
    /// The RFC 9068 access-token producer reads it to embed the RFC 9396 §9.1
    /// <c>authorization_details</c> top-level claim. Transient — never persisted.
    /// </summary>
    public const string GrantedAuthorizationDetailsClaimKey = "server.grantedAuthorizationDetailsClaim";

    /// <summary>
    /// Context-bag key for the signed JARM JWT Response Document assembled by the authorize
    /// endpoint's <c>BuildInputAsync</c> for consumption by <c>BuildResponse</c> (JARM §2.3).
    /// Transient — never persisted.
    /// </summary>
    public const string JarmResponseJwtKey = "server.jarmResponseJwt";

    /// <summary>
    /// Key for the <see cref="ConfirmationMethod"/> binding the issuance pipeline established
    /// for the current request (typically the DPoP <c>jkt</c> thumbprint per RFC 9449 §6.1).
    /// </summary>
    public const string ConfirmationKey = "server.confirmation";

    /// <summary>
    /// Context-bag key for the issuer URI resolved for the current Authorize request's
    /// <c>iss</c> redirect parameter (RFC 9207 §2), computed once during
    /// <c>BuildInputAsync</c>'s authentication-requirements evaluation so both the success
    /// and error redirect paths read the identical value the discovery endpoint would
    /// resolve. Transient — never persisted.
    /// </summary>
    public const string ResolvedIssuerKey = "server.resolvedIssuer";
}
