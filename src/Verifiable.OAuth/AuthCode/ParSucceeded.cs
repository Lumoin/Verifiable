using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Carries a successful PAR HTTP response. Transitions from
/// <see cref="ParRequestReady"/> to <see cref="ParCompleted"/>.
/// </summary>
/// <param name="Par">The PAR response body parsed from the authorization server.</param>
/// <param name="ReceivedAt">The UTC instant the response was received.</param>
[DebuggerDisplay("ParSucceeded RequestUri={Par.RequestUri}")]
public sealed record ParSucceeded(
    ParResponse Par,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
