using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.TokenExchange;

/// <summary>
/// The application's refusal of a Token Exchange request
/// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>) through
/// <see cref="ValidateTokenExchangeRequestDelegate"/>: the parameter it refuses and its reason. The library
/// derives the error code from the parameter and writes the error response.
/// </summary>
/// <remarks>
/// <para>
/// The code follows <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>,
/// one code per parameter:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="OAuthRequestParameterNames.Resource"/> and <see cref="OAuthRequestParameterNames.Audience"/>
///     give <c>invalid_target</c>: "If the authorization server is unwilling or unable to issue a token for any
///     target service indicated by the "resource" or "audience" parameters, the "invalid_target" error code
///     SHOULD be used in the error response."
///     <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see> names the same code for
///     a token request: "The following error code is provided for an authorization server to indicate problems with
///     the requested resource(s) in response to an authorization request or access token request."
///   </description></item>
///   <item><description>
///     Every other parameter gives <c>invalid_request</c>: "If the request itself is not valid or if either the
///     "subject_token" or "actor_token" are invalid for any reason, or are unacceptable based on policy, the
///     authorization server MUST construct an error response, as specified in Section 5.2 of [RFC6749]. The
///     value of the "error" parameter MUST be the "invalid_request" error code."
///   </description></item>
/// </list>
/// <para>
/// The answer is HTTP 400. <see cref="Description"/> is written as the <c>error_description</c> through the
/// error body's writer, which reduces it to the character set
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> allows, so the
/// record checks neither member when it is built.
/// </para>
/// <para>
/// The record's text shows <see cref="Parameter"/> alone, as its debugger display does (<see cref="ToString"/>).
/// </para>
/// </remarks>
[DebuggerDisplay("TokenExchangeRequestRefusal Parameter={Parameter}")]
public sealed record TokenExchangeRequestRefusal
{
    /// <summary>
    /// The name of the refused request parameter as <see cref="OAuthRequestParameterNames"/> spells it, for
    /// example <see cref="OAuthRequestParameterNames.RequestedTokenType"/>. Compared ordinally when the code is
    /// derived.
    /// </summary>
    public required string Parameter { get; init; }

    /// <summary>
    /// The application's reason, written as the <c>error_description</c> of the error response after the
    /// error body's writer has reduced it to the character set of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>.
    /// </summary>
    public required string Description { get; init; }


    /// <summary>
    /// Renders the refusal's text: <see cref="Parameter"/> alone. <see cref="Description"/> is the application's text
    /// and stays out of the record's text, a rule of this library.
    /// </summary>
    /// <returns>The refused parameter's name in the record's text.</returns>
    public override string ToString() => $"TokenExchangeRequestRefusal {{ Parameter = {Parameter} }}";
}
