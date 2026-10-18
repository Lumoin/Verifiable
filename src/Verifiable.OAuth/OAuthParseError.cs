using System.Globalization;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth;

/// <summary>
/// Discriminated union base for errors produced when parsing OAuth protocol
/// endpoint responses.
/// </summary>
/// <remarks>
/// <para>
/// Several distinct failure modes exist for a client flow driving a PAR or token
/// endpoint call. Callers must distinguish between them to respond appropriately:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="OAuthProtocolError"/> — the server returned a well-formed
///       OAuth error response. The request reached the server and was understood.
///       Retry may be possible after fixing the request.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthMalformedResponse"/> — the response body could not be
///       parsed as a valid OAuth response. The server may have returned an HTML
///       error page, a proxy may have intercepted the request, or the wrong
///       endpoint was called.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthRepeatedMemberName"/> — the response body is one well-formed JSON
///       object, but one of its objects names a member more than once (RFC 8259 §4), so it
///       names no parameter one way.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthUndecodableMemberValue"/> — the response body is one well-formed JSON
///       object, but a member of one of its objects, read as a parameter or not, has a name or a
///       string value naming no Unicode text (RFC 8259 §8.2), so the body holds text no reader
///       agrees on.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthInvalidFieldValue"/> — a required field was present but
///       its value failed validation per the relevant specification.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthAuthorizationServerMetadataUnresolved"/> — the flow could not resolve the
///       authorization server metadata document the call needed before a request could even be
///       built.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthOutboundFetchPolicyDenied"/> — the metadata resolved and named an
///       endpoint, but that endpoint was refused by the caller's
///       <see cref="Verifiable.Core.Outbound.OutboundFetchPolicy"/> before any request was sent.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthClientAssertionRefused"/> — the client authentication assertion the request was to
///       present was refused as its credential was formed from the registration, before anything was resolved,
///       composed or sent.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="OAuthClientAuthenticationRefused"/> — the client authentication the exchange was to
///       present was refused as the exchange was composed: a secret method whose registration carries no
///       secret, or an assertion method handed no assertion inputs, before anything was resolved or sent.
///     </description>
///   </item>
/// </list>
/// <para>
/// Each case carries a <see cref="DecisionSupport"/> record with the library's
/// assessment of the likely cause, actionable guidance, and any correlation
/// identifiers available from the transport layer.
/// </para>
/// </remarks>
public abstract record OAuthParseError(DecisionSupport Support)
{
    /// <summary>
    /// Returns a new <see cref="OAuthParseError"/> of the same derived type
    /// with <see cref="DecisionSupport"/> enriched by the supplied transport
    /// metadata from <see cref="HttpResponseData"/>.
    /// </summary>
    public OAuthParseError WithTransportMetadata(HttpResponseData response)
    {
        DecisionSupport enriched = Support;

        string? traceParent = response.GetMetadata(HttpResponseDataKeys.TraceParent);
        if(traceParent is not null)
        {
            enriched = enriched.WithCorrelationId(traceParent);
        }

        string? requestId = response.GetMetadata(HttpResponseDataKeys.RequestId);
        if(requestId is not null)
        {
            enriched = enriched.WithContext(HttpResponseDataKeys.RequestId, requestId);
        }

        enriched = enriched.WithContext(
            HttpResponseDataKeys.StatusCode,
            response.StatusCode.ToString(CultureInfo.InvariantCulture));

        return this with { Support = enriched };
    }
}


/// <summary>
/// The server returned a well-formed OAuth error response per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
/// or
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 §2.3</see>.
/// </summary>
/// <remarks>
/// This is a protocol-level error, not a parse failure. The request reached the
/// server and was understood; the server rejected it for a protocol reason.
/// Common error codes and their meanings:
/// <list type="bullet">
///   <item><description>
///     <c>invalid_request</c> — a required parameter is missing, malformed, or repeated.
///     In HAIP 1.0 contexts this frequently means <c>code_challenge</c> is absent
///     or <c>redirect_uri</c> does not exactly match the registered value.
///   </description></item>
///   <item><description>
///     <c>invalid_client</c> — client authentication failed. Check client credentials
///     and registration status.
///   </description></item>
///   <item><description>
///     <c>access_denied</c> — the resource owner or authorization server denied the request.
///   </description></item>
///   <item><description>
///     <c>unauthorized_client</c> — the client is not authorised to use this grant type
///     or request type.
///   </description></item>
/// </list>
/// </remarks>
public sealed record OAuthProtocolError(
    string ErrorCode,
    DecisionSupport Support,
    string? ErrorDescription = null,
    Uri? ErrorUri = null) : OAuthParseError(Support);


/// <summary>
/// The response body could not be recognised as a valid OAuth protocol
/// response or RFC 9457 problem+json document.
/// </summary>
/// <remarks>
/// Common causes: the wrong endpoint was called, a reverse proxy or firewall
/// returned an HTML error page, the connection was truncated, or the server
/// has a bug. The raw <see cref="Body"/> is preserved for logging and diagnostic
/// purposes.
/// </remarks>
public sealed record OAuthMalformedResponse(
    string Body,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>
/// The response body is one well-formed JSON object, but one of its objects names a member more than once, where
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see> says the names within an object SHOULD be
/// unique: readers of a repeated name differ in which value they take, so the value one reader checks and the value another
/// uses could differ, and the response names no parameter one way.
/// </summary>
/// <remarks>
/// Carries the repeated name and where it is repeated, the facts the JSON reader answered
/// (<see cref="Verifiable.JCose.JsonRepeatedMemberName"/>), so the application reads the reason without parsing a sentence;
/// <see cref="DecisionSupport.Summary"/> is composed from them. No value the response carries, under the repeated name or any
/// other, is carried.
/// </remarks>
/// <param name="MemberName">The repeated name, decoded once (RFC 8259 §7).</param>
/// <param name="ObjectDepth">
/// The nesting depth of the object that repeats it: one for the response's own object, whose members are its parameters.
/// </param>
/// <param name="Support">Guidance for the calling application.</param>
public sealed record OAuthRepeatedMemberName(
    string MemberName,
    int ObjectDepth,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>
/// The response body is one well-formed JSON object, but a member of one of its objects, its own or one nested within it, has
/// a name or a string value whose escapes name an unpaired surrogate, which the grammar admits and which encodes no Unicode
/// character (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 §8.2</see>), so the body holds text no
/// reader agrees on and is refused whether or not the member is a parameter the client reads.
/// </summary>
/// <remarks>
/// Names the first such member in document order and carries the facts the JSON reader answered
/// (<see cref="Verifiable.JCose.JsonUndecodableMember"/>): its name as it can be written, the depth of the object carrying it,
/// and whether its name or its value names no text, so the application reads the reason without parsing a sentence;
/// <see cref="DecisionSupport.Summary"/> is composed from them. No value the response carries, the member's or any other, is
/// carried.
/// </remarks>
/// <param name="MemberName">
/// When <paramref name="Part"/> is <see cref="Verifiable.JCose.JsonUndecodableMemberPart.Value"/>, the member's name decoded
/// once (RFC 8259 §7); when it is <see cref="Verifiable.JCose.JsonUndecodableMemberPart.Name"/>, the name as the response
/// spells it, its escapes as written, which is text that can be written, as the decoded name is not.
/// </param>
/// <param name="ObjectDepth">
/// The nesting depth of the object carrying the member: one for the response's own object, whose members are its parameters.
/// </param>
/// <param name="Part">Whether the member's name or its value names no Unicode text.</param>
/// <param name="Support">Guidance for the calling application.</param>
public sealed record OAuthUndecodableMemberValue(
    string MemberName,
    int ObjectDepth,
    JsonUndecodableMemberPart Part,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>
/// A required field was present in the response but its value failed validation
/// according to the specification.
/// </summary>
/// <remarks>
/// Examples: <c>expires_in</c> was zero or negative (RFC 9126 §2.2 requires a
/// positive integer), <c>request_uri</c> was a relative URI rather than an
/// absolute one, or <c>access_token</c> was an empty string.
/// </remarks>
public sealed record OAuthInvalidFieldValue(
    string FieldName,
    string ReceivedValue,
    string Reason,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>
/// The client flow could not resolve the authorization server metadata document a PAR, token, or
/// grant-exchange call needed before a request could even be built.
/// </summary>
/// <remarks>
/// Carries the resolver's complete typed evidence, allowing the application to inspect the failure
/// without parsing a diagnostic sentence or repeating the library's metadata decision.
/// </remarks>
/// <param name="Resolution">The metadata resolution failure and its evidence.</param>
/// <param name="Support">Guidance for the calling application.</param>
public sealed record OAuthAuthorizationServerMetadataUnresolved(
    AuthorizationServerMetadataResolution Resolution,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>
/// The endpoint this exchange was about to dial was refused by the caller's
/// <see cref="Verifiable.Core.Outbound.OutboundFetchPolicy"/> before any network contact.
/// </summary>
/// <remarks>
/// Distinct from <see cref="OAuthAuthorizationServerMetadataUnresolved"/>: the metadata document
/// resolved and named a token endpoint, so a document was obtained and parsed successfully — the
/// endpoint it named simply failed the outbound-fetch policy's SSRF checks (scheme, loopback, or
/// private-network denial per
/// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>-style resource
/// hardening), a policy decision rather than an unresolved document.
/// </remarks>
public sealed record OAuthOutboundFetchPolicyDenied(
    Uri Endpoint,
    string DenyReason,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>
/// The client authentication assertion (RFC 7523 Section 2.2) the exchange was to present was refused as its credential
/// was formed from the registration's method and key material
/// (<see cref="ClientAssertionCredential.Of"/>), before any metadata was resolved, any assertion
/// composed or any request sent.
/// </summary>
/// <remarks>
/// Carries the library's typed refusal as it is, the rule broken and the values it was judged on, so the application
/// reads the reason without parsing a sentence; <see cref="DecisionSupport.Summary"/> is rendered from it.
/// </remarks>
/// <param name="Refusal">The refusal of the credential.</param>
/// <param name="Support">Guidance for the calling application.</param>
public sealed record OAuthClientAssertionRefused(
    ClientAssertionCredentialRefusal Refusal,
    DecisionSupport Support) : OAuthParseError(Support);


/// <summary>The rule a client authentication its exchange was to present refuses, before anything is sent.</summary>
public enum ClientAuthenticationRefusalReason
{
    /// <summary>
    /// The registration names <c>client_secret_basic</c> or <c>client_secret_post</c> and carries no client secret in its
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/> (RFC 6749 §2.3.1).
    /// </summary>
    ClientSecretNotCarried,

    /// <summary>
    /// The registration names <c>private_key_jwt</c> or <c>client_secret_jwt</c> and the exchange was handed no client
    /// assertion inputs to compose its assertion with (RFC 7523 §2.2).
    /// </summary>
    AssertionInputsNotGiven
}


/// <summary>
/// The client authentication the exchange was to present was refused as the exchange was composed, before any metadata was
/// resolved or any request sent: a secret method whose registration carries no secret, or an assertion method handed no
/// assertion inputs.
/// </summary>
/// <param name="Method">The method the registration names.</param>
/// <param name="Reason">The rule broken.</param>
/// <param name="Support">Guidance for the calling application.</param>
public sealed record OAuthClientAuthenticationRefused(
    ClientAuthenticationMethod Method,
    ClientAuthenticationRefusalReason Reason,
    DecisionSupport Support) : OAuthParseError(Support);
