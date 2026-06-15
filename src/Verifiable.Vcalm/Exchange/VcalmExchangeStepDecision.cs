using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The engine's decision for the next move in a W3C VCALM 1.0 §3.6.5 vcapi step — what the exchange
/// engine does with the client's incoming message. The deployment supplies this through the
/// <see cref="ResolveVcalmExchangeStepDelegate"/> seam; for a single-step present-or-offer exchange it
/// names one of the four §3.6 outcomes. A later §3.6.1 workflow surface can drive the same decisions
/// off an admin-authored step graph.
/// </summary>
/// <remarks>
/// §3.6: the engine answers a vcapi message with one of — a <c>verifiablePresentationRequest</c> (more
/// needed, <see cref="VcalmExchangeStepKind.RequestPresentation"/>), an empty object (complete,
/// <see cref="VcalmExchangeStepKind.Complete"/>), or a <c>redirectUrl</c> (complete elsewhere,
/// <see cref="VcalmExchangeStepKind.Redirect"/>). When the incoming message is a holder
/// <c>verifiablePresentation</c> the engine first verifies it; the deployment expresses that the
/// engine should consume-and-complete with <see cref="VcalmExchangeStepKind.AcceptPresentation"/>.
/// </remarks>
[DebuggerDisplay("VcalmExchangeStepDecision Kind={Kind} Step={StepName}")]
public sealed record VcalmExchangeStepDecision
{
    /// <summary>The §3.6 outcome the engine takes for this step.</summary>
    public required VcalmExchangeStepKind Kind { get; init; }

    /// <summary>
    /// The §3.6.6 <c>step</c> name this decision belongs to. Used to bind the issued request and to
    /// key the verified presentation in <c>variables.results</c>. Defaulted to a single-step name when
    /// the deployment names none.
    /// </summary>
    public string StepName { get; init; } = "step";

    /// <summary>
    /// For <see cref="VcalmExchangeStepKind.RequestPresentation"/>: the verbatim §3.4 verifiable
    /// presentation request JSON the engine sends, MINUS its <c>challenge</c> / <c>domain</c> — the
    /// engine mints and binds a fresh anti-replay challenge and supplies the domain itself, so the
    /// supplied JSON carries only the <c>query</c> array (and any other VPR members the deployment
    /// wants). <see langword="null"/> for the other kinds.
    /// </summary>
    public string? PresentationRequestQueryJson { get; init; }

    /// <summary>
    /// For <see cref="VcalmExchangeStepKind.RequestPresentation"/>: the <c>domain</c> the engine binds
    /// the issued request to (the verifier target the holder checks against). Defaulted to the
    /// exchange's vcapi URL host by the engine when the deployment names none.
    /// </summary>
    public string? Domain { get; init; }

    /// <summary>
    /// For <see cref="VcalmExchangeStepKind.Redirect"/>: the <c>redirectUrl</c> the engine recommends
    /// the client continue at. <see langword="null"/> for the other kinds.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely; promoting to System.Uri would lose the deployment's exact percent-encoding shape on the wire.")]
    public string? RedirectUrl { get; init; }


    /// <summary>The engine requests a presentation from the holder (§3.6: more needed).</summary>
    public static VcalmExchangeStepDecision RequestPresentation(
        string stepName, string presentationRequestQueryJson, string? domain = null) =>
        new()
        {
            Kind = VcalmExchangeStepKind.RequestPresentation,
            StepName = stepName,
            PresentationRequestQueryJson = presentationRequestQueryJson,
            Domain = domain
        };


    /// <summary>The engine accepts the holder's presentation (after verification) and completes (§3.6).</summary>
    public static VcalmExchangeStepDecision AcceptPresentation(string stepName) =>
        new()
        {
            Kind = VcalmExchangeStepKind.AcceptPresentation,
            StepName = stepName
        };


    /// <summary>The engine completes the exchange with nothing more to request nor offer (§3.6: empty reply).</summary>
    public static VcalmExchangeStepDecision Complete() =>
        new() { Kind = VcalmExchangeStepKind.Complete };


    /// <summary>The engine completes the exchange recommending the client continue at a redirect URL (§3.6).</summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely; it rides through to the response body unparsed.")]
    public static VcalmExchangeStepDecision Redirect(string redirectUrl) =>
        new()
        {
            Kind = VcalmExchangeStepKind.Redirect,
            RedirectUrl = redirectUrl
        };
}


/// <summary>The §3.6 outcomes a <see cref="VcalmExchangeStepDecision"/> can name.</summary>
public enum VcalmExchangeStepKind
{
    /// <summary>§3.6: the engine sends a <c>verifiablePresentationRequest</c> — more information is needed.</summary>
    RequestPresentation,

    /// <summary>§3.6: the engine verifies the holder's presented <c>verifiablePresentation</c> and completes.</summary>
    AcceptPresentation,

    /// <summary>§3.6: the engine replies with an empty object — the exchange is complete.</summary>
    Complete,

    /// <summary>§3.6: the engine replies with a <c>redirectUrl</c> — complete, continue elsewhere.</summary>
    Redirect
}
