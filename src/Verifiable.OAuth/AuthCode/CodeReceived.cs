using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth;
using Verifiable.OAuth.Par;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Carries the authorization code from the redirect callback. Transitions from
/// <see cref="ParCompleted"/> to <see cref="AuthorizationCodeReceived"/>.
/// </summary>
/// <param name="Code">The authorization code from the redirect.</param>
/// <param name="State">
/// The <c>state</c> value echoed by the authorization server. Must be validated against
/// the value sent in the original request to prevent CSRF per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
/// </param>
/// <param name="IssuerId">
/// The <c>iss</c> parameter from the redirect. Must be validated against
/// <see cref="OAuthFlowState.ExpectedIssuer"/> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
/// </param>
/// <param name="ReceivedAt">The UTC instant the redirect was received.</param>
[DebuggerDisplay("CodeReceived")]
public sealed record CodeReceived(
    string Code,
    string State,
    string IssuerId,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
