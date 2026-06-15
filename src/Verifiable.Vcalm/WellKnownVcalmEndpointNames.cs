using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Stable endpoint role identifiers for the W3C VCALM 1.0 issuer and verifier services, used as the
/// <see cref="Server.ServerEndpoint.Name"/> value and as the lookup key the application's
/// endpoint-URI resolver switches on to produce the per-deployment URLs.
/// </summary>
/// <remarks>
/// The role identifier is one-to-one with the URL the application has to provide. These are
/// UTF-8-first per the library convention: each <c>XUtf8</c> span sits beside an interned string
/// <c>X</c> whose value is the span's UTF-8 decoding, swept by the well-known-constant guard.
/// </remarks>
[DebuggerDisplay("WellKnownVcalmEndpointNames")]
public static class WellKnownVcalmEndpointNames
{
    //VCALM 1.0 §3.3 verifier family
    /// <summary>The UTF-8 source literal of <see cref="VcalmCredentialsVerify"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCredentialsVerifyUtf8 => "Vcalm.CredentialsVerify"u8;

    /// <summary>The VCALM 1.0 §3.3.1 <c>POST /credentials/verify</c> verifier endpoint.</summary>
    public static readonly string VcalmCredentialsVerify = Utf8Constants.ToInternedString(VcalmCredentialsVerifyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmPresentationsVerify"/>.</summary>
    public static ReadOnlySpan<byte> VcalmPresentationsVerifyUtf8 => "Vcalm.PresentationsVerify"u8;

    /// <summary>The VCALM 1.0 §3.3.2 <c>POST /presentations/verify</c> verifier endpoint.</summary>
    public static readonly string VcalmPresentationsVerify = Utf8Constants.ToInternedString(VcalmPresentationsVerifyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmCreateChallenge"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCreateChallengeUtf8 => "Vcalm.CreateChallenge"u8;

    /// <summary>The VCALM 1.0 §3.3.3 <c>POST /challenges</c> challenge-minting endpoint.</summary>
    public static readonly string VcalmCreateChallenge = Utf8Constants.ToInternedString(VcalmCreateChallengeUtf8);

    //VCALM 1.0 §3.2 issuer family
    /// <summary>The UTF-8 source literal of <see cref="VcalmCredentialsIssue"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCredentialsIssueUtf8 => "Vcalm.CredentialsIssue"u8;

    /// <summary>The VCALM 1.0 §3.2.1 <c>POST /credentials/issue</c> issuer endpoint.</summary>
    public static readonly string VcalmCredentialsIssue = Utf8Constants.ToInternedString(VcalmCredentialsIssueUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetCredential"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetCredentialUtf8 => "Vcalm.GetCredential"u8;

    /// <summary>The VCALM 1.0 §3.2.2 <c>GET /credentials/{id}</c> retrieval endpoint.</summary>
    public static readonly string VcalmGetCredential = Utf8Constants.ToInternedString(VcalmGetCredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmDeleteCredential"/>.</summary>
    public static ReadOnlySpan<byte> VcalmDeleteCredentialUtf8 => "Vcalm.DeleteCredential"u8;

    /// <summary>The VCALM 1.0 §3.2.3 <c>DELETE /credentials/{id}</c> deletion endpoint.</summary>
    public static readonly string VcalmDeleteCredential = Utf8Constants.ToInternedString(VcalmDeleteCredentialUtf8);

    //VCALM 1.0 Appendix C status family
    /// <summary>The UTF-8 source literal of <see cref="VcalmCredentialsStatus"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCredentialsStatusUtf8 => "Vcalm.CredentialsStatus"u8;

    /// <summary>
    /// The VCALM 1.0 §C.3 <c>POST /credentials/status</c> update-status endpoint — the §1.3 binding
    /// status-service MUST.
    /// </summary>
    public static readonly string VcalmCredentialsStatus = Utf8Constants.ToInternedString(VcalmCredentialsStatusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmCreateStatusList"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCreateStatusListUtf8 => "Vcalm.CreateStatusList"u8;

    /// <summary>The VCALM 1.0 §C.1 <c>POST /status-lists</c> create-status-list endpoint (a MAY).</summary>
    public static readonly string VcalmCreateStatusList = Utf8Constants.ToInternedString(VcalmCreateStatusListUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetStatusList"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetStatusListUtf8 => "Vcalm.GetStatusList"u8;

    /// <summary>The VCALM 1.0 §C.2 <c>GET /status-lists/{id}</c> get-status-list endpoint (a MAY).</summary>
    public static readonly string VcalmGetStatusList = Utf8Constants.ToInternedString(VcalmGetStatusListUtf8);

    //VCALM 1.0 §3.5 holder presentation family
    /// <summary>The UTF-8 source literal of <see cref="VcalmCredentialsDerive"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCredentialsDeriveUtf8 => "Vcalm.CredentialsDerive"u8;

    /// <summary>The VCALM 1.0 §3.5.1 <c>POST /credentials/derive</c> selective-disclosure derive endpoint.</summary>
    public static readonly string VcalmCredentialsDerive = Utf8Constants.ToInternedString(VcalmCredentialsDeriveUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmCreatePresentation"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCreatePresentationUtf8 => "Vcalm.CreatePresentation"u8;

    /// <summary>The VCALM 1.0 §3.5.2 <c>POST /presentations</c> create-presentation endpoint.</summary>
    public static readonly string VcalmCreatePresentation = Utf8Constants.ToInternedString(VcalmCreatePresentationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetPresentations"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetPresentationsUtf8 => "Vcalm.GetPresentations"u8;

    /// <summary>The VCALM 1.0 §3.5.3 <c>GET /presentations</c> list-presentations endpoint.</summary>
    public static readonly string VcalmGetPresentations = Utf8Constants.ToInternedString(VcalmGetPresentationsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetPresentation"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetPresentationUtf8 => "Vcalm.GetPresentation"u8;

    /// <summary>The VCALM 1.0 §3.5.4 <c>GET /presentations/{id}</c> retrieval endpoint.</summary>
    public static readonly string VcalmGetPresentation = Utf8Constants.ToInternedString(VcalmGetPresentationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmDeletePresentation"/>.</summary>
    public static ReadOnlySpan<byte> VcalmDeletePresentationUtf8 => "Vcalm.DeletePresentation"u8;

    /// <summary>The VCALM 1.0 §3.5.5 <c>DELETE /presentations/{id}</c> deletion endpoint.</summary>
    public static readonly string VcalmDeletePresentation = Utf8Constants.ToInternedString(VcalmDeletePresentationUtf8);

    //VCALM 1.0 §3.6 workflows-and-exchanges family
    /// <summary>The UTF-8 source literal of <see cref="VcalmCreateExchange"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCreateExchangeUtf8 => "Vcalm.CreateExchange"u8;

    /// <summary>The VCALM 1.0 §3.6.3 <c>POST /workflows/{localWorkflowId}/exchanges</c> create-exchange endpoint.</summary>
    public static readonly string VcalmCreateExchange = Utf8Constants.ToInternedString(VcalmCreateExchangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetExchangeProtocols"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetExchangeProtocolsUtf8 => "Vcalm.GetExchangeProtocols"u8;

    /// <summary>
    /// The VCALM 1.0 §3.6.4 <c>GET /workflows/{localWorkflowId}/exchanges/{localExchangeId}/protocols</c>
    /// get-exchange-protocols endpoint — a §1.3 conforming-holder REQUIRED interface.
    /// </summary>
    public static readonly string VcalmGetExchangeProtocols = Utf8Constants.ToInternedString(VcalmGetExchangeProtocolsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmParticipateInExchange"/>.</summary>
    public static ReadOnlySpan<byte> VcalmParticipateInExchangeUtf8 => "Vcalm.ParticipateInExchange"u8;

    /// <summary>
    /// The VCALM 1.0 §3.6.5 <c>POST /workflows/{localWorkflowId}/exchanges/{localExchangeId}</c>
    /// participate-in-an-exchange vcapi endpoint — a §1.3 conforming-holder REQUIRED interface.
    /// </summary>
    public static readonly string VcalmParticipateInExchange = Utf8Constants.ToInternedString(VcalmParticipateInExchangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetExchangeState"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetExchangeStateUtf8 => "Vcalm.GetExchangeState"u8;

    /// <summary>
    /// The VCALM 1.0 §3.6.6 <c>GET /workflows/{localWorkflowId}/exchanges/{localExchangeId}</c>
    /// get-exchange-state endpoint. Querying the state requires additional authorization beyond the
    /// exchange URL the §3.6.5 participation runs on (§3.6: "Querying the exchange in this way
    /// requires additional authorization that the coordinator is expected to have and that the
    /// exchange client is not."); the authorization mechanism is the deployment's, as with every
    /// VCALM endpoint.
    /// </summary>
    public static readonly string VcalmGetExchangeState = Utf8Constants.ToInternedString(VcalmGetExchangeStateUtf8);

    //VCALM 1.0 §3.6.1 / §3.6.2 administration family + §3.6.7 callbacks
    /// <summary>The UTF-8 source literal of <see cref="VcalmCreateWorkflow"/>.</summary>
    public static ReadOnlySpan<byte> VcalmCreateWorkflowUtf8 => "Vcalm.CreateWorkflow"u8;

    /// <summary>
    /// The VCALM 1.0 §3.6.1 <c>POST /workflows</c> create-workflow endpoint — a §3.1 administration
    /// interface ("Administrators").
    /// </summary>
    public static readonly string VcalmCreateWorkflow = Utf8Constants.ToInternedString(VcalmCreateWorkflowUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmGetWorkflow"/>.</summary>
    public static ReadOnlySpan<byte> VcalmGetWorkflowUtf8 => "Vcalm.GetWorkflow"u8;

    /// <summary>
    /// The VCALM 1.0 §3.6.2 <c>GET /workflows/{localWorkflowId}</c> get-workflow-configuration
    /// endpoint — a §3.1 administration interface ("Administrators").
    /// </summary>
    public static readonly string VcalmGetWorkflow = Utf8Constants.ToInternedString(VcalmGetWorkflowUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmExchangeStepCallback"/>.</summary>
    public static ReadOnlySpan<byte> VcalmExchangeStepCallbackUtf8 => "Vcalm.ExchangeStepCallback"u8;

    /// <summary>
    /// The VCALM 1.0 §3.6.7 <c>POST /callbacks/{localCallbackId}</c> exchange-step-callback endpoint —
    /// the capability-URL the workflow service POSTs the <c>{event{data{exchangeId}}}</c> body to when
    /// a step fires its callback. §3.6.7: "A callback … can be any capability URL (i.e., a URL that is
    /// infeasible to guess)."
    /// </summary>
    public static readonly string VcalmExchangeStepCallback = Utf8Constants.ToInternedString(VcalmExchangeStepCallbackUtf8);

    //VCALM 1.0 §3.7 initiating-interactions family (coordinator-hosted)
    /// <summary>The UTF-8 source literal of <see cref="VcalmInteractionProtocols"/>.</summary>
    public static ReadOnlySpan<byte> VcalmInteractionProtocolsUtf8 => "Vcalm.InteractionProtocols"u8;

    /// <summary>
    /// The VCALM 1.0 §3.7.4 <c>GET /interactions/{localInteractionId}</c> interaction-protocols-response
    /// endpoint — the content-negotiated bootstrapping read. With <c>Accept: application/json</c> it
    /// returns the §3.7.4 <c>{protocols:{…}}</c> map (protocol id → initiation URL); with an
    /// unrecognized <c>Accept</c> it returns a <c>text/html</c> body directing a human to suitable
    /// software (the §3.7.4 MUST). It is the §3.7.1 interaction URL resource itself.
    /// </summary>
    public static readonly string VcalmInteractionProtocols = Utf8Constants.ToInternedString(VcalmInteractionProtocolsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VcalmInviteRequest"/>.</summary>
    public static ReadOnlySpan<byte> VcalmInviteRequestUtf8 => "Vcalm.InviteRequest"u8;

    /// <summary>
    /// The VCALM 1.0 §3.7.5 <c>POST /{localInviteId}/invite-request/response</c> inviteRequest endpoint
    /// — the holder-initiated interaction protocol: the local system POSTs <c>{url, purpose, referenceId?}</c>
    /// to signal where to send the individual for a use-case-specific interaction.
    /// </summary>
    public static readonly string VcalmInviteRequest = Utf8Constants.ToInternedString(VcalmInviteRequestUtf8);
}
