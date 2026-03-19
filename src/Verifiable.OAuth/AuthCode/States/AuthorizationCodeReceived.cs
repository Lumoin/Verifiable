using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth;
using Verifiable.OAuth.Par;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode.States;

/// <summary>
/// The authorization server redirected back with an authorization code.
/// This is the second DB persistence point.
/// </summary>
/// <remarks>
/// Transitions to <see cref="TokenReceived"/> after a successful token exchange.
/// </remarks>
[DebuggerDisplay("AuthorizationCodeReceived FlowId={FlowId}")]
public sealed record AuthorizationCodeReceived: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>
    /// The authorization code from the redirect. Single-use; must not be logged.
    /// </summary>
    public required string Code { get; init; }

    /// <summary>
    /// The <c>state</c> value echoed back in the redirect. Must be validated against the
    /// value sent in the authorization request to prevent CSRF per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public required string State { get; init; }

    /// <summary>
    /// The <c>iss</c> parameter echoed back in the redirect. Must be validated against
    /// <see cref="OAuthFlowState.ExpectedIssuer"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>
    /// when present. Absent in plain RFC 6749 flows that do not require issuer identification.
    /// </summary>
    public required string? IssuerId { get; init; }

    /// <summary>Carried forward for the token exchange request.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>Carried forward for the token exchange request.</summary>
    public required Uri RedirectUri { get; init; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Pkce.Dispose();
            disposed = true;
        }
    }
}