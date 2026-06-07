using System.Diagnostics;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Discriminated base for the well-defined points in dispatch at which
/// <see cref="InspectDelegate"/> is invoked. Each concrete subtype carries
/// the stage-specific payload the inspector reads — the incoming request,
/// the match decision, a state transition, or the outgoing response.
/// </summary>
/// <remarks>
/// Phase 9h ships four stages: <see cref="IncomingRequestStage"/>,
/// <see cref="MatchedStage"/>, <see cref="StateTransitionStage"/>, and
/// <see cref="OutgoingResponseStage"/>. Additional stages may be added in
/// later phases as new pipeline phases gain inspectability needs.
/// </remarks>
[DebuggerDisplay("InspectionStage")]
public abstract record InspectionStage;


/// <summary>
/// Fired at dispatch entry, before tenant resolution or registration load.
/// Carries the raw <see cref="IncomingRequest"/> the skin handed to the
/// server. Always fires, including on requests that go on to fail
/// validation or match no endpoint.
/// </summary>
[DebuggerDisplay("IncomingRequestStage")]
public sealed record IncomingRequestStage(IncomingRequest Request): InspectionStage;


/// <summary>
/// Fired immediately after the chain walk completes, with the matched
/// endpoint and its match payload (both <see langword="null"/> when no
/// endpoint accepted the request). Always fires, including on the
/// unmatched-request case so inspectors observe 404 responses.
/// </summary>
[DebuggerDisplay("MatchedStage Endpoint={Endpoint?.Name}")]
public sealed record MatchedStage(
    ServerEndpoint? Endpoint,
    MatchPayload? Payload): InspectionStage;


/// <summary>
/// Fired after each successful PDA state transition driven by
/// <see cref="Pipeline.FlowRunner.StepWithEffectsAsync"/>. Carries the
/// before-state, the input that drove the transition, and the after-state.
/// Does <em>not</em> fire when the inner step throws — the dispatcher's
/// inspection emission is post-success only.
/// </summary>
/// <remarks>
/// The natural emission point for replay-determinism event capture; see
/// <c>documents/AuthorizationServerDesign.md §2.4</c>.
/// </remarks>
[DebuggerDisplay("StateTransitionStage")]
public sealed record StateTransitionStage(
    OAuthFlowState Before,
    OAuthFlowInput Input,
    OAuthFlowState After): InspectionStage;


/// <summary>
/// Fired immediately before <see cref="AuthorizationServer.DispatchAsync"/>
/// returns. Carries the response the dispatcher is about to hand back to
/// the skin. Always fires, regardless of the status code.
/// </summary>
[DebuggerDisplay("OutgoingResponseStage StatusCode={Response.StatusCode}")]
public sealed record OutgoingResponseStage(ServerHttpResponse Response): InspectionStage;
