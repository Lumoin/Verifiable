namespace Verifiable.Vcalm;

/// <summary>
/// The route-template parameter names the VCALM 1.0 §3.2 issuer endpoints read from
/// <see cref="Server.RouteValues"/> when a skin did template routing
/// (<c>/credentials/{credentialId}</c>). Skins that hand the raw path through let the §3.2.2 / §3.2.3
/// matcher parse the trailing segment itself; either way the id reaches the handler.
/// </summary>
public static class WellKnownVcalmRouteParameters
{
    /// <summary>
    /// The §3.2.2 / §3.2.3 <c>{credentialId}</c> path-template parameter — the id of the credential
    /// to retrieve or delete (<c>credential.id</c> or the associated <c>credentialId</c>).
    /// </summary>
    public const string CredentialId = "credentialId";

    /// <summary>
    /// The §C.2 <c>{id}</c> path-template parameter — the id of the status-list credential to
    /// retrieve via <c>GET /status-lists/{id}</c>.
    /// </summary>
    public const string StatusListId = "statusListId";

    /// <summary>
    /// The §3.5.4 / §3.5.5 <c>{id}</c> path-template parameter — the id of the presentation to
    /// retrieve via <c>GET /presentations/{id}</c> or delete via <c>DELETE /presentations/{id}</c>.
    /// </summary>
    public const string PresentationId = "presentationId";

    /// <summary>
    /// The §3.6 <c>{localExchangeId}</c> path-template parameter — the local id of the exchange the
    /// §3.6.4 protocols, §3.6.5 participate, and §3.6.6 state endpoints address. A skin that did
    /// template routing populates it; a skin that hands the raw path through lets the matcher parse
    /// the trailing path segment itself.
    /// </summary>
    public const string ExchangeId = "localExchangeId";

    /// <summary>
    /// The §3.6.2 <c>{localWorkflowId}</c> path-template parameter — the local id of the workflow the
    /// §3.6.2 get-workflow-configuration endpoint addresses. A skin that did template routing populates
    /// it; a skin that hands the raw path through lets the matcher parse the trailing path segment.
    /// </summary>
    public const string WorkflowId = "localWorkflowId";

    /// <summary>
    /// The §3.6.7 <c>{localCallbackId}</c> path-template parameter — the capability-URL segment the
    /// §3.6.7 exchange-step-callback endpoint addresses. A skin that did template routing populates it;
    /// a skin that hands the raw path through lets the matcher parse the trailing path segment.
    /// </summary>
    public const string CallbackId = "localCallbackId";

    /// <summary>
    /// The §3.7.1 / §3.7.4 <c>{localInteractionId}</c> path-template parameter — the interaction-specific
    /// id the §3.7.4 interaction-protocols-response endpoint addresses (the opaque segment of the §3.7.1
    /// interaction URL). A skin that did template routing populates it; a skin that hands the raw path
    /// through lets the matcher parse the trailing path segment itself.
    /// </summary>
    public const string InteractionId = "localInteractionId";

    /// <summary>
    /// The §3.7.5 <c>{localInviteId}</c> path-template parameter — the id segment the §3.7.5
    /// <c>POST /{localInviteId}/invite-request/response</c> inviteRequest endpoint addresses. A skin that
    /// did template routing populates it; a skin that hands the raw path through lets the matcher parse
    /// the trailing path segment itself.
    /// </summary>
    public const string InviteId = "localInviteId";
}
