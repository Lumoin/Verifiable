using System.Diagnostics;
using Verifiable.Server.Routing;

namespace Verifiable.Server;

/// <summary>
/// Discriminated base for the well-defined points in dispatch at which
/// <see cref="InspectDelegate"/> is invoked. Each concrete subtype carries
/// the stage-specific payload the inspector reads — the incoming request,
/// the match decision, a state transition, or the outgoing response.
/// </summary>
/// <remarks>
/// Four stages ship: <see cref="IncomingRequestStage"/>,
/// <see cref="MatchedStage"/>, <see cref="StateTransitionStage"/>, and
/// <see cref="OutgoingResponseStage"/>. Additional stages may be added as
/// new pipeline phases gain inspectability needs.
/// </remarks>
public abstract record InspectionStage;


/// <summary>
/// Fired at dispatch entry, before tenant resolution or registration load.
/// Carries the raw <see cref="IncomingRequest"/> the skin handed to the
/// server. Always fires, including on requests that go on to fail
/// validation or match no endpoint.
/// </summary>
public sealed record IncomingRequestStage(IncomingRequest Request): InspectionStage;


/// <summary>
/// Fired immediately after the chain walk completes, with the matched
/// endpoint and its match payload (both <see langword="null"/> when no
/// endpoint accepted the request). Always fires, including on the
/// unmatched-request case so inspectors observe 404 responses.
/// </summary>
/// <remarks>
/// After a registration the application's
/// <see cref="ServerIntegration.MaterializeRegistrationAsync"/> answers in
/// place of the loaded one is judged and the chain is built again for it,
/// the stage fires again with the decision that is executed: the endpoint
/// matched in that chain, or none. When an endpoint runs, or the no-match
/// answer is sent, the request's last announced decision is the one
/// executed. A materialization that answers a failure, and a materialized
/// record of another type than the loaded one, which is answered
/// <c>500</c>, are answered without the announced endpoint running; the
/// context the <see cref="OutgoingResponseStage"/> is inspected with then
/// carries the capability of the endpoint the request matched.
/// </remarks>
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
public sealed record StateTransitionStage(
    FlowState Before,
    FlowInput Input,
    FlowState After): InspectionStage;


/// <summary>
/// Fired immediately before the dispatch host returns. Carries the response
/// the dispatcher is about to hand back to the skin. Always fires, regardless
/// of the status code.
/// </summary>
[DebuggerDisplay("OutgoingResponseStage StatusCode={Response.StatusCode}")]
public sealed record OutgoingResponseStage(ServerHttpResponse Response): InspectionStage;
