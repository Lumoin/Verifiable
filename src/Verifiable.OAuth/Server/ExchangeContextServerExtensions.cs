using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Core.Assessment;

using Verifiable.OAuth.Server.Audit;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Typed accessor extensions for the OAuth-specific entries in a <see cref="ExchangeContext"/>
/// used by the OAuth/OpenID endpoint delegates. The host-generic accessors (capability,
/// issuer, flow id, matched payload, the active host) live on
/// <see cref="Verifiable.Server.ExchangeContextServerExtensions"/>.
/// </summary>
/// <remarks>
/// <para>
/// These extension methods eliminate the need for callers to know string key names
/// or cast <see cref="object"/> values. The underlying keys are defined in
/// <see cref="Pipeline.AuthorizationServerHandlers"/>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ExchangeContextServerExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the <see cref="ClientRecord"/> resolved by the dispatcher at the start of
        /// each request — the OAuth-family registration shape, downcast from the host-generic
        /// <see cref="Verifiable.Server.IRegistrationRecord"/> the host stamped on the context.
        /// </summary>
        /// <returns>
        /// The resolved registration, or <see langword="null"/> when the dispatcher has
        /// not yet resolved it or the resolved record is not a <see cref="ClientRecord"/>.
        /// </returns>
        public ClientRecord? ClientRegistration =>
            context.Registration as ClientRecord;


        /// <summary>
        /// Gets the validation results accumulated during request processing.
        /// </summary>
        public IReadOnlyList<ClaimIssueResult>? ValidationResults =>
            context.TryGetValue(Pipeline.AuthorizationServerHandlers.ValidationResultsKey, out object? v)
                && v is List<ClaimIssueResult> list ? list : null;

        /// <summary>
        /// Appends a validation result to the request context. Called by action handlers and
        /// endpoint delegates after running a <see cref="ClaimIssuer{TInput}"/>.
        /// </summary>
        /// <param name="result">The validation result to append.</param>
        public void AddValidationResult(ClaimIssueResult result)
        {
            ArgumentNullException.ThrowIfNull(result);

            if(!context.TryGetValue(Pipeline.AuthorizationServerHandlers.ValidationResultsKey, out object? v)
                || v is not List<ClaimIssueResult> list)
            {
                list = [];
                context[Pipeline.AuthorizationServerHandlers.ValidationResultsKey] = list;
            }

            list.Add(result);
        }


        /// <summary>
        /// Gets the <see cref="IssuedTokenSet"/> assembled by the token endpoint during
        /// <c>BuildInputAsync</c> for consumption by <c>BuildResponse</c>.
        /// </summary>
        public IssuedTokenSet? IssuedTokens =>
            context.TryGetValue(Pipeline.AuthorizationServerHandlers.IssuedTokensKey, out object? v)
                && v is IssuedTokenSet set ? set : null;

        /// <summary>Sets the <see cref="IssuedTokenSet"/> assembled during token endpoint processing.</summary>
        /// <param name="tokens">The issued token set.</param>
        public void SetIssuedTokens(IssuedTokenSet tokens)
        {
            ArgumentNullException.ThrowIfNull(tokens);
            context[Pipeline.AuthorizationServerHandlers.IssuedTokensKey] = tokens;
        }


        /// <summary>
        /// Gets the granted RFC 9396 <c>authorization_details</c> response value — the
        /// serialised JSON array carrying the OID4VCI 1.0 §6.2 <c>credential_identifiers</c>.
        /// </summary>
        public string? GrantedAuthorizationDetails =>
            context.TryGetValue(Pipeline.AuthorizationServerHandlers.GrantedAuthorizationDetailsKey, out object? v)
                && v is string json ? json : null;

        /// <summary>Sets the granted RFC 9396 <c>authorization_details</c> response value.</summary>
        /// <param name="grantedAuthorizationDetailsJson">The serialised authorization_details array.</param>
        public void SetGrantedAuthorizationDetails(string grantedAuthorizationDetailsJson)
        {
            ArgumentNullException.ThrowIfNull(grantedAuthorizationDetailsJson);
            context[Pipeline.AuthorizationServerHandlers.GrantedAuthorizationDetailsKey] = grantedAuthorizationDetailsJson;
        }


        /// <summary>
        /// Gets the granted RFC 9396 <c>authorization_details</c> in structured form — a list of
        /// authorization details objects (each a string-keyed map). The RFC 9068 access-token
        /// producer reads it to populate the RFC 9396 §9.1 <c>authorization_details</c> claim.
        /// </summary>
        public IReadOnlyList<object>? GrantedAuthorizationDetailsClaim =>
            context.TryGetValue(Pipeline.AuthorizationServerHandlers.GrantedAuthorizationDetailsClaimKey, out object? v)
                && v is IReadOnlyList<object> details ? details : null;

        /// <summary>Sets the granted RFC 9396 <c>authorization_details</c> in structured form.</summary>
        /// <param name="grantedAuthorizationDetails">The structured authorization details objects.</param>
        public void SetGrantedAuthorizationDetailsClaim(IReadOnlyList<object> grantedAuthorizationDetails)
        {
            ArgumentNullException.ThrowIfNull(grantedAuthorizationDetails);
            context[Pipeline.AuthorizationServerHandlers.GrantedAuthorizationDetailsClaimKey] = grantedAuthorizationDetails;
        }


        /// <summary>
        /// Gets the signed JARM JWT Response Document assembled by the authorize endpoint
        /// during <c>BuildInputAsync</c> for consumption by <c>BuildResponse</c>.
        /// </summary>
        public string? JarmResponseJwt =>
            context.TryGetValue(Pipeline.AuthorizationServerHandlers.JarmResponseJwtKey, out object? v)
                && v is string jwt ? jwt : null;

        /// <summary>Sets the signed JARM JWT Response Document assembled during authorize endpoint processing.</summary>
        /// <param name="responseJwt">The compact response JWT.</param>
        public void SetJarmResponseJwt(string responseJwt)
        {
            ArgumentNullException.ThrowIfNull(responseJwt);
            context[Pipeline.AuthorizationServerHandlers.JarmResponseJwtKey] = responseJwt;
        }


        /// <summary>
        /// Gets the <see cref="ConfirmationMethod"/> binding the issuance pipeline established
        /// for the current request (typically the DPoP <c>jkt</c> thumbprint per RFC 9449 §6.1).
        /// </summary>
        public ConfirmationMethod? Confirmation =>
            context.TryGetValue(Pipeline.AuthorizationServerHandlers.ConfirmationKey, out object? v)
                && v is ConfirmationMethod confirmation ? confirmation : null;

        /// <summary>Sets the <see cref="ConfirmationMethod"/> binding on the request context.</summary>
        /// <param name="confirmation">The confirmation method.</param>
        public void SetConfirmation(ConfirmationMethod confirmation)
        {
            ArgumentNullException.ThrowIfNull(confirmation);
            context[Pipeline.AuthorizationServerHandlers.ConfirmationKey] = confirmation;
        }
    }
}
