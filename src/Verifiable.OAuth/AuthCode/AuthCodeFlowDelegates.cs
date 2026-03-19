using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Par;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Persists a flow state to durable storage.
/// </summary>
/// <remarks>
/// <para>
/// Called at each DB persistence point in the flow:
/// </para>
/// <list type="bullet">
///   <item><description>After PAR completes — state is <see cref="States.ParCompleted"/>, keyed by <c>FlowId</c> and <c>Par.RequestUri</c>.</description></item>
///   <item><description>After the authorization code arrives — state is <see cref="States.AuthorizationCodeReceived"/>.</description></item>
///   <item><description>After tokens are received — state is <see cref="States.TokenReceived"/>.</description></item>
/// </list>
/// <para>
/// The implementation must be idempotent: saving the same state twice must not
/// produce duplicate records. The <see cref="OAuthFlowState.FlowId"/> is the
/// primary key; <see cref="States.ParCompleted.Par"/>'s <c>RequestUri</c> is
/// the secondary lookup key used when the callback arrives.
/// </para>
/// </remarks>
/// <param name="state">The flow state to persist.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask SaveFlowStateDelegate(
    OAuthFlowState state,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a flow state from durable storage by flow identifier.
/// </summary>
/// <remarks>
/// Called when an inbound HTTP request needs to resume a flow that was previously
/// persisted. Returns <see langword="null"/> when no state is found for the given
/// identifier, which the caller should treat as an invalid or expired request.
/// </remarks>
/// <param name="flowId">The flow identifier to load, matching <see cref="OAuthFlowState.FlowId"/>.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The persisted flow state, or <see langword="null"/> if not found.</returns>
public delegate ValueTask<OAuthFlowState?> LoadFlowStateDelegate(
    string flowId,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a flow state from durable storage by the PAR <c>request_uri</c>.
/// </summary>
/// <remarks>
/// Called when the authorization callback arrives. The <c>state</c> parameter in the
/// callback maps to the <c>FlowId</c>, but some deployments may need to look up by
/// <c>request_uri</c> instead. Both delegates are provided so the implementation can
/// choose the appropriate key for its storage schema.
/// </remarks>
/// <param name="requestUri">The PAR <c>request_uri</c> identifying the flow.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The persisted flow state, or <see langword="null"/> if not found.</returns>
public delegate ValueTask<OAuthFlowState?> LoadFlowStateByRequestUriDelegate(
    string requestUri,
    CancellationToken cancellationToken);




/// <summary>
/// Posts a form-encoded request to an OAuth endpoint and returns the full
/// HTTP response including transport-level metadata.
/// </summary>
/// <remarks>
/// <para>
/// The implementation supplies the HTTP client and any authentication headers
/// (DPoP, client assertion, mTLS, etc.). The library does not create or own
/// HTTP connections.
/// </para>
/// <para>
/// The returned <see cref="HttpResponseData"/> carries the response body,
/// HTTP status code, and any transport metadata the implementation chooses
/// to surface — OTel <c>traceparent</c> from response headers, RFC 9457
/// <c>instance</c> URIs, server request identifiers. This metadata travels
/// through the parser into <see cref="DecisionSupport"/> on any error result,
/// enabling correlation with server-side logs.
/// </para>
/// <para>
/// In the in-process development configuration the implementation calls
/// directly into server handler functions rather than making a network
/// request, and may populate <see cref="HttpResponseData.TransportMetadata"/>
/// with server-side context such as a flow identifier.
/// </para>
/// </remarks>
/// <param name="endpoint">The URI to POST to.</param>
/// <param name="formFields">The form fields as <c>application/x-www-form-urlencoded</c>.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The HTTP response carrying body, status code, and optional transport metadata.
/// </returns>
public delegate ValueTask<HttpResponseData> SendFormPostDelegate(
    Uri endpoint,
    System.Collections.Generic.IReadOnlyDictionary<string, string> formFields,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a PAR endpoint response into a <see cref="ParResponse"/> or a
/// structured <see cref="OAuthParseError"/> describing the failure.
/// </summary>
/// <remarks>
/// <para>
/// The default implementation is <see cref="OAuthResponseParsers.ParseParResponse"/>,
/// which handles RFC 9126 §2.2 success responses, RFC 6749 §5.2 error responses,
/// and RFC 9457 problem+json responses with no dependency on
/// <c>System.Text.Json</c>.
/// </para>
/// <para>
/// Supply a custom implementation when the authorization server uses a
/// non-standard response format or when additional fields need to be extracted.
/// </para>
/// </remarks>
/// <param name="response">The full HTTP response from the PAR endpoint.</param>
/// <returns>
/// A <see cref="Result{TValue,TError}"/> that is either a <see cref="ParResponse"/>
/// on success or an <see cref="OAuthParseError"/> describing the failure with
/// actionable diagnostic information.
/// </returns>
public delegate Result<ParResponse, OAuthParseError> ParseParResponseDelegate(
    HttpResponseData response);


/// <summary>
/// Parses a token endpoint response into a <see cref="TokenResponse"/> or a
/// structured <see cref="OAuthParseError"/> describing the failure.
/// </summary>
/// <remarks>
/// <para>
/// The default implementation is <see cref="OAuthResponseParsers.ParseTokenResponse"/>,
/// which handles RFC 6749 §5.1 success responses, RFC 6749 §5.2 error responses,
/// and RFC 9457 problem+json responses.
/// </para>
/// </remarks>
/// <param name="response">The full HTTP response from the token endpoint.</param>
/// <param name="receivedAt">
/// The UTC instant at which the response was received. Used to compute
/// token expiry from the <c>expires_in</c> value.
/// </param>
/// <returns>
/// A <see cref="Result{TValue,TError}"/> that is either a <see cref="TokenResponse"/>
/// on success or an <see cref="OAuthParseError"/> describing the failure.
/// </returns>
public delegate Result<TokenResponse, OAuthParseError> ParseTokenResponseDelegate(
    HttpResponseData response,
    DateTimeOffset receivedAt);


/// <summary>
/// Validates the inbound callback fields against the loaded flow state.
/// Returns a list of <see cref="Verifiable.Core.Assessment.Claim"/> instances so that
/// callers can inspect per-check outcomes and integrate with monitoring or telemetry.
/// </summary>
/// <remarks>
/// <para>
/// The profile-specific set of rules is supplied here so that the same orchestrator
/// can serve different security profiles without modification:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       HAIP 1.0 / FAPI 2.0: include <c>iss</c> presence and exact match checks
///       (<see cref="OAuthCallbackClaimIds.CallbackIssPresent"/> and
///       <see cref="OAuthCallbackClaimIds.IssuerMatchesExpected"/>) as required by
///       <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>
///       and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
///     </description>
///   </item>
///   <item>
///     <description>
///       Plain RFC 6749: omit the <c>iss</c> checks and rely on <c>state</c> alone
///       for CSRF defense per
///       <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
///     </description>
///   </item>
/// </list>
/// <para>
/// All claims whose <c>Outcome</c> is not <c>Success</c> are treated as failures by
/// <see cref="AuthCodeFlow"/>. The full claim list is available in
/// <see cref="AuthCodeFlowEndpointResult.ValidationClaims"/> for audit and telemetry.
/// </para>
/// </remarks>
/// <param name="callbackFields">The inbound callback query parameters.</param>
/// <param name="flowState">The flow state loaded for the <c>state</c> parameter value.</param>
/// <param name="timeProvider">The time provider used for expiry checks.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>All claims produced by the validation rules.</returns>
public delegate System.Collections.Generic.List<Verifiable.Core.Assessment.Claim> ValidateCallbackDelegate(
    System.Collections.Generic.IReadOnlyDictionary<string, string> callbackFields,
    OAuthFlowState flowState,
    System.TimeProvider timeProvider,
    CancellationToken cancellationToken);