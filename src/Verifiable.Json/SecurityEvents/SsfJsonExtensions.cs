using System;
using Verifiable.OAuth.Server;

namespace Verifiable.Json;

/// <summary>
/// Wires the default <c>System.Text.Json</c> Shared Signals parsers
/// (<see cref="SsfStreamJsonParsing"/>) onto an
/// <see cref="AuthorizationServerIntegration"/>. Called once at startup by a
/// deployment acting as an SSF Transmitter; the stream STORE seams are not set
/// here — the application always supplies those.
/// </summary>
public static class SsfJsonExtensions
{
    /// <summary>
    /// Sets the SSF stream-management request parsers that are unset, leaving
    /// any application-supplied parser in place.
    /// </summary>
    public static AuthorizationServerIntegration UseDefaultSsfJsonParsing(
        this AuthorizationServerIntegration integration)
    {
        ArgumentNullException.ThrowIfNull(integration);

        integration.ParseSsfStreamCreateRequestAsync ??= static (body, context, ct) =>
            ValueTask.FromResult(SsfStreamJsonParsing.ParseStreamCreateRequest(body));
        integration.ParseSsfStreamUpdateRequestAsync ??= static (body, context, ct) =>
            ValueTask.FromResult(SsfStreamJsonParsing.ParseStreamUpdateRequest(body));
        integration.ParseSsfStreamStatusAsync ??= static (body, context, ct) =>
            ValueTask.FromResult(SsfStreamJsonParsing.ParseStreamStatus(body));
        integration.ParseSsfAddSubjectRequestAsync ??= static (body, context, ct) =>
            ValueTask.FromResult(SsfStreamJsonParsing.ParseAddSubjectRequest(body));
        integration.ParseSsfRemoveSubjectRequestAsync ??= static (body, context, ct) =>
            ValueTask.FromResult(SsfStreamJsonParsing.ParseRemoveSubjectRequest(body));
        integration.ParseSsfVerificationRequestAsync ??= static (body, context, ct) =>
            ValueTask.FromResult(SsfStreamJsonParsing.ParseVerificationRequest(body));

        return integration;
    }
}
