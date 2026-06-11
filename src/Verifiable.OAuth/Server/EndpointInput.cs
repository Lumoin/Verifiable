namespace Verifiable.OAuth.Server;

/// <summary>
/// Names the two arms of a <c>BuildInputAsync</c> result — the
/// <c>(<see cref="OAuthFlowInput"/>?, <see cref="ServerHttpResponse"/>?)</c> tuple every
/// endpoint candidate returns. Either the call produced a flow input that advances the state
/// machine, or it produced an HTTP response that is returned directly without advancing. These
/// helpers let call sites read as <c>Advance(input)</c> / <c>Respond(response)</c> instead of
/// casting <see langword="null"/> in both tuple positions, which the compiler otherwise requires
/// because a bare <c>(null, expr)</c> cannot infer the nullable tuple's element types.
/// </summary>
public static class EndpointInput
{
    /// <summary>Advance the flow with <paramref name="input"/>; no direct response is returned.</summary>
    public static (OAuthFlowInput? Input, ServerHttpResponse? Response) Advance(OAuthFlowInput input) =>
        (input, null);

    /// <summary>Return <paramref name="response"/> directly without advancing the flow.</summary>
    public static (OAuthFlowInput? Input, ServerHttpResponse? Response) Respond(ServerHttpResponse response) =>
        (null, response);
}
