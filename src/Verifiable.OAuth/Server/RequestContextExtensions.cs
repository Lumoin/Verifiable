using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Typed accessor extensions for well-known entries in a <see cref="RequestContext"/>
/// used by the Authorization Server dispatcher and endpoint delegates.
/// </summary>
/// <remarks>
/// <para>
/// These extension methods eliminate the need for callers to know string key names
/// or cast <see cref="object"/> values. The underlying keys are defined in
/// <see cref="AuthorizationServerHandlers"/> and remain stable across versions.
/// </para>
/// <para>
/// Library users add their own typed accessors following the same pattern using
/// C# 14 extension syntax. The methods appear alongside the library-provided ones
/// in IntelliSense.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class RequestContextExtensions
{
    extension(RequestContext context)
    {
        /// <summary>
        /// Gets the resolved <see cref="Verifiable.OAuth.TenantId"/> for the
        /// request. Set either by the application skin before dispatching, or
        /// by the dispatcher after invoking
        /// <see cref="AuthorizationServerOptions.ExtractTenantIdAsync"/>.
        /// </summary>
        /// <returns>
        /// The resolved tenant identifier, or <see langword="null"/> when no
        /// tenant has been resolved for this request.
        /// </returns>
        public TenantId? TenantId =>
            context.TryGetValue(AuthorizationServerHandlers.TenantIdKey, out object? v)
                && v is TenantId tenantId ? tenantId : default(TenantId?);

        /// <summary>
        /// Sets the resolved tenant identifier on the request context.
        /// </summary>
        /// <param name="tenantId">The tenant identifier.</param>
        public void SetTenantId(TenantId tenantId)
        {
            context[AuthorizationServerHandlers.TenantIdKey] = tenantId;
        }


        /// <summary>
        /// Gets the server issuer URI placed by the ASP.NET skin.
        /// </summary>
        /// <returns>
        /// The issuer <see cref="Uri"/>, or <see langword="null"/> when not set.
        /// </returns>
        public Uri? Issuer =>
            context.TryGetValue(AuthorizationServerHandlers.IssuerKey, out object? v)
                && v is Uri u ? u : null;

        /// <summary>
        /// Sets the server issuer URI. Called by the ASP.NET skin before dispatching.
        /// </summary>
        /// <param name="issuer">The issuer URI.</param>
        public void SetIssuer(Uri issuer)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            context[AuthorizationServerHandlers.IssuerKey] = issuer;
        }


        /// <summary>
        /// Gets the authenticated subject identifier placed by the application's
        /// authentication middleware.
        /// </summary>
        /// <returns>
        /// The subject identifier string, or <see langword="null"/> when the user
        /// is not authenticated or the value was not set.
        /// </returns>
        public string? SubjectId =>
            context.TryGetValue(AuthorizationServerHandlers.SubjectIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the authenticated subject identifier. Called by the application's
        /// authentication middleware before dispatching to the authorize endpoint.
        /// </summary>
        /// <param name="subjectId">The authenticated subject identifier.</param>
        public void SetSubjectId(string subjectId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
            context[AuthorizationServerHandlers.SubjectIdKey] = subjectId;
        }


        /// <summary>
        /// Gets the authentication time placed by the application's authentication
        /// middleware.
        /// </summary>
        /// <returns>
        /// The authentication time, or <see langword="null"/> when not set.
        /// </returns>
        public DateTimeOffset? AuthTime =>
            context.TryGetValue(AuthorizationServerHandlers.AuthTimeKey, out object? v)
                && v is DateTimeOffset dt ? dt : null;

        /// <summary>
        /// Sets the authentication time. Called by the application's authentication
        /// middleware before dispatching to the authorize endpoint.
        /// </summary>
        /// <param name="authTime">The UTC instant at which the subject authenticated.</param>
        public void SetAuthTime(DateTimeOffset authTime)
        {
            context[AuthorizationServerHandlers.AuthTimeKey] = authTime;
        }


        /// <summary>
        /// Gets the <see cref="ClientRegistration"/> resolved by the dispatcher at the
        /// start of each request. Available to all <see cref="BuildInputDelegate"/>
        /// implementations without capturing the registration from outside.
        /// </summary>
        /// <returns>
        /// The resolved registration, or <see langword="null"/> when the dispatcher has
        /// not yet resolved it.
        /// </returns>
        public ClientRegistration? Registration =>
            context.TryGetValue(AuthorizationServerHandlers.RegistrationKey, out object? v)
                && v is ClientRegistration r ? r : null;

        /// <summary>
        /// Sets the resolved <see cref="ClientRegistration"/>. Called by the dispatcher
        /// after resolving the registration by tenant identifier.
        /// </summary>
        /// <param name="registration">The resolved client registration.</param>
        public void SetRegistration(ClientRegistration registration)
        {
            ArgumentNullException.ThrowIfNull(registration);
            context[AuthorizationServerHandlers.RegistrationKey] = registration;
        }


        /// <summary>
        /// Gets the flow identifier written by a <see cref="BuildInputDelegate"/>
        /// on continuing-flow endpoints.
        /// </summary>
        /// <returns>
        /// The flow identifier string, or <see langword="null"/> when not set.
        /// </returns>
        public string? FlowId =>
            context.TryGetValue(AuthorizationServerHandlers.FlowIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the flow identifier. Called by <see cref="BuildInputDelegate"/>
        /// implementations on continuing-flow endpoints.
        /// </summary>
        /// <param name="flowId">The flow identifier.</param>
        public void SetFlowId(string flowId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(flowId);
            context[AuthorizationServerHandlers.FlowIdKey] = flowId;
        }


        /// <summary>
        /// Gets the correlation key generated by <see cref="BuildInputDelegate"/>
        /// on new-flow endpoints. The dispatcher reads this after the delegate runs
        /// to determine the storage key for
        /// <see cref="SaveServerFlowStateDelegate"/>.
        /// </summary>
        /// <returns>
        /// The correlation key string, or <see langword="null"/> when not set.
        /// </returns>
        public string? CorrelationKey =>
            context.TryGetValue(AuthorizationServerHandlers.CorrelationKeyOutputKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the correlation key generated for a new flow. Called by
        /// <see cref="BuildInputDelegate"/> implementations on new-flow endpoints.
        /// </summary>
        /// <param name="correlationKey">The generated correlation key.</param>
        public void SetCorrelationKey(string correlationKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(correlationKey);
            context[AuthorizationServerHandlers.CorrelationKeyOutputKey] = correlationKey;
        }


        /// <summary>
        /// Gets the UTC instant stamped by the dispatcher at the start of effectful
        /// work. All effectful operations within a single request use this consistent
        /// timestamp rather than reading the system clock directly.
        /// </summary>
        /// <returns>
        /// The request timestamp, or <see langword="null"/> when the dispatcher has
        /// not yet stamped it.
        /// </returns>
        public DateTimeOffset? VerifiedAt =>
            context.TryGetValue(AuthorizationServerHandlers.VerifiedAtKey, out object? v)
                && v is DateTimeOffset dt ? dt : null;

        /// <summary>
        /// Sets the request timestamp. Called by the dispatcher once per request
        /// before effectful work begins.
        /// </summary>
        /// <param name="verifiedAt">The UTC instant for this request.</param>
        public void SetVerifiedAt(DateTimeOffset verifiedAt)
        {
            context[AuthorizationServerHandlers.VerifiedAtKey] = verifiedAt;
        }


        /// <summary>
        /// Gets the validation results accumulated during request processing.
        /// Each entry corresponds to one validation point (callback, VP token, etc.)
        /// that ran during this request.
        /// </summary>
        /// <returns>
        /// The list of validation results, or <see langword="null"/> when no
        /// validation has been performed during this request.
        /// </returns>
        public IReadOnlyList<ClaimIssueResult>? ValidationResults =>
            context.TryGetValue(AuthorizationServerHandlers.ValidationResultsKey, out object? v)
                && v is List<ClaimIssueResult> list ? list : null;

        /// <summary>
        /// Appends a validation result to the request context. Called by action
        /// handlers and endpoint delegates after running a
        /// <see cref="ClaimIssuer{TInput}"/>. The application reads
        /// <see cref="ValidationResults"/> after <c>HandleAsync</c> returns for
        /// logging, OTel emission, audit archival, or structured error responses.
        /// </summary>
        /// <param name="result">The validation result to append.</param>
        public void AddValidationResult(ClaimIssueResult result)
        {
            ArgumentNullException.ThrowIfNull(result);

            if(!context.TryGetValue(AuthorizationServerHandlers.ValidationResultsKey, out object? v)
                || v is not List<ClaimIssueResult> list)
            {
                list = [];
                context[AuthorizationServerHandlers.ValidationResultsKey] = list;
            }

            list.Add(result);
        }


        /// <summary>
        /// Gets the <see cref="IssuedTokenSet"/> assembled by the token endpoint
        /// during <c>BuildInputAsync</c> for consumption by <c>BuildResponse</c>.
        /// </summary>
        /// <returns>
        /// The set of issued tokens, or <see langword="null"/> when no tokens
        /// were placed on the context (typical for non-token endpoints).
        /// </returns>
        public IssuedTokenSet? IssuedTokens =>
            context.TryGetValue(AuthorizationServerHandlers.IssuedTokensKey, out object? v)
                && v is IssuedTokenSet set ? set : null;

        /// <summary>
        /// Sets the <see cref="IssuedTokenSet"/> assembled during token endpoint
        /// processing. The transient token strings live here for the remainder of
        /// the request and are consumed by <c>BuildResponse</c> when composing
        /// the HTTP response body. The strings are never persisted.
        /// </summary>
        /// <param name="tokens">The issued token set.</param>
        public void SetIssuedTokens(IssuedTokenSet tokens)
        {
            ArgumentNullException.ThrowIfNull(tokens);
            context[AuthorizationServerHandlers.IssuedTokensKey] = tokens;
        }
    }
}
