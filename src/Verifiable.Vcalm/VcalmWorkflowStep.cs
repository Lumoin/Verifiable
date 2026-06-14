using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a single W3C VCALM 1.0 §3.6.1 workflow step — the directives
/// the exchange engine reads to decide what the step does (request a presentation, mint and offer a
/// credential, redirect, complete) and where the exchange goes next (<c>nextStep</c>).
/// </summary>
/// <remarks>
/// <para>
/// §3.6.1 step data members the engine consumes here: <c>createChallenge</c> (the engine mints and
/// binds a fresh anti-replay challenge for the step's presentation request), <c>verifiablePresentationRequest</c>
/// (the §3.4 VPR query the engine sends, carried verbatim minus its challenge / domain which the engine
/// binds), <c>verifiablePresentation</c> (a server-offered presentation, verbatim),
/// <c>redirectUrl</c> (complete elsewhere), <c>callback</c> (the §3.6.7 callback fired on the step
/// event), <c>issueRequests</c> (mint credentials and offer them), <c>nextStep</c> (the LINEAR
/// successor; MUST NOT be present on the final step, §3.6.1).
/// </para>
/// <para>
/// Modeled-but-deferred: <c>presentationSchema</c> (a §3.6.1 JSON-Schema validation of the presented
/// presentation — no JSON Schema package, so the field is carried verbatim but not enforced) and
/// <c>openId</c> (the OID4VP / OID4VCI bridge — the field is carried verbatim but the vcapi participation
/// path does not consume it).
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmWorkflowStep CreateChallenge={CreateChallenge} NextStep={NextStep}")]
public sealed record VcalmWorkflowStep
{
    /// <summary>
    /// The §3.6.1 <c>createChallenge</c> directive — when set, the engine mints and binds a fresh
    /// anti-replay challenge for the step's verifiable presentation request (the step requests a
    /// presentation from the holder). <see langword="false"/> for a step that issues / redirects /
    /// completes without requesting a presentation.
    /// </summary>
    public bool CreateChallenge { get; init; }

    /// <summary>
    /// The §3.6.1 <c>verifiablePresentationRequest</c> — the verbatim, WHOLE §3.4 VPR object (its
    /// REQUIRED <c>query</c> array and any other VPR members it carries, such as a step-authored
    /// <c>domain</c>) as the admin authored it. Round-tripped byte-faithful through the §3.6.2
    /// get-workflow-configuration response. <see langword="null"/> when the step requests no
    /// presentation. The engine does NOT send this object verbatim on the wire — it composes the §3.6.5
    /// wire VPR from <see cref="PresentationQueryJson"/> under the challenge / domain it binds itself
    /// (§3.4.1 anti-replay), so a step-authored <c>challenge</c> / <c>domain</c> here is round-tripped
    /// but never propagated to the holder.
    /// </summary>
    public string? VerifiablePresentationRequestJson { get; init; }

    /// <summary>
    /// The §3.4.1 <c>query</c> array extracted from <see cref="VerifiablePresentationRequestJson"/> — the
    /// verbatim array of typed query maps the engine wraps into the §3.6.5 wire verifiable presentation
    /// request under its OWN bound <c>challenge</c> / <c>domain</c>. Present exactly when
    /// <see cref="VerifiablePresentationRequestJson"/> is (the parser requires the VPR carry a query
    /// array); <see langword="null"/> when the step requests no presentation.
    /// </summary>
    public string? PresentationQueryJson { get; init; }

    /// <summary>
    /// The §3.6.1 <c>verifiablePresentation</c> — a verbatim server-offered presentation the step
    /// returns to the client (e.g. a pre-composed presentation carrying out-of-band credentials).
    /// <see langword="null"/> when the step offers no server-side presentation.
    /// </summary>
    public string? VerifiablePresentationJson { get; init; }

    /// <summary>
    /// The §3.6.1 <c>redirectUrl</c> — when set, the step completes the exchange recommending the
    /// client continue at this URL. <see langword="null"/> for a step that does not redirect.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6.1 redirectUrl is a verbatim wire string the engine passes through opaquely; promoting to System.Uri would lose the admin's exact percent-encoding shape on the wire.")]
    public string? RedirectUrl { get; init; }

    /// <summary>
    /// The §3.6.1 <c>callback.url</c> — the §3.6.7 capability URL the engine POSTs the
    /// <c>{event{data{exchangeId}}}</c> callback body to after the step executes. <see langword="null"/>
    /// when the step fires no callback.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6.1 / §3.6.7 callback url is a verbatim capability URL the engine passes through opaquely; promoting to System.Uri would lose the admin's exact shape and the callback is delivered through the app's outbound seam.")]
    public string? CallbackUrl { get; init; }

    /// <summary>
    /// The §3.6.1 <c>issueRequests</c> array — each entry naming a credential template (by id or index)
    /// the step mints a credential from and offers back over vcapi as a <c>verifiablePresentation</c>.
    /// Empty when the step issues no credential.
    /// </summary>
    public ImmutableArray<VcalmIssueRequest> IssueRequests { get; init; } =
        ImmutableArray<VcalmIssueRequest>.Empty;

    /// <summary>
    /// The §3.6.1 <c>nextStep</c> — the name of the LINEAR successor step. <see langword="null"/> on
    /// the final step (§3.6.1: "This field MUST NOT be present on the final step configuration"); a
    /// step with no <c>nextStep</c> completes the exchange when it finishes.
    /// </summary>
    public string? NextStep { get; init; }

    /// <summary>
    /// The §3.6.1 <c>presentationSchema</c>, verbatim JSON, or <see langword="null"/>. Modeled but
    /// DEFERRED: the JSON-Schema validation of a presented presentation needs a JSON Schema package the
    /// repo does not carry, so the field is round-tripped through §3.6.2 but not enforced.
    /// </summary>
    public string? PresentationSchemaJson { get; init; }

    /// <summary>
    /// The §3.6.1 <c>openId</c>, verbatim JSON, or <see langword="null"/>. Modeled but DEFERRED: the
    /// OID4VP / OID4VCI bridge (createAuthorizationRequest / authorizationRequest / clientProfiles) is
    /// the §3.7 interactions surface (V-5d); the field is carried verbatim, the vcapi path ignores it.
    /// </summary>
    public string? OpenIdJson { get; init; }


    /// <summary>
    /// Whether this step requests a presentation from the holder — it has a
    /// <see cref="PresentationQueryJson"/> the engine wraps into a §3.4 verifiable presentation request
    /// (§3.6.1: the step's <c>verifiablePresentationRequest.query</c> is what the engine asks the holder
    /// for). Keyed off the query the engine actually sends, so detection matches what the engine drives.
    /// </summary>
    public bool RequestsPresentation => PresentationQueryJson is not null;

    /// <summary>Whether this step mints one or more credentials (§3.6.1 <c>issueRequests</c>).</summary>
    public bool IssuesCredential => !IssueRequests.IsDefaultOrEmpty;
}


/// <summary>
/// The neutral view of a single W3C VCALM 1.0 §3.6.1 <c>issueRequests</c> entry — the credential
/// template the step mints from (named by id XOR index) and the OPTIONAL per-request variables fed to
/// the template evaluation in addition to the exchange variables.
/// </summary>
/// <remarks>
/// §3.6.1: "Each issue request object identifies a credential template to use, either by its identifier
/// (credentialTemplateId) or by its index (credentialTemplateIndex) in the workflow's
/// credentialTemplates array." Exactly one of the two MUST be present (the §3.6.1 schema's
/// <c>required: [credentialTemplateId] OR required: [credentialTemplateIndex]</c>).
/// </remarks>
[DebuggerDisplay("VcalmIssueRequest TemplateId={CredentialTemplateId} TemplateIndex={CredentialTemplateIndex}")]
public sealed record VcalmIssueRequest
{
    /// <summary>
    /// The §3.6.1 <c>credentialTemplateId</c> — the id of the credential template to evaluate, or
    /// <see langword="null"/> when the request names the template by <see cref="CredentialTemplateIndex"/>.
    /// </summary>
    public string? CredentialTemplateId { get; init; }

    /// <summary>
    /// The §3.6.1 <c>credentialTemplateIndex</c> — the array index of the credential template to
    /// evaluate, or <see langword="null"/> when the request names the template by
    /// <see cref="CredentialTemplateId"/>.
    /// </summary>
    public int? CredentialTemplateIndex { get; init; }

    /// <summary>
    /// The §3.6.1 OPTIONAL <c>variables</c> — verbatim JSON of the per-request variables provided to
    /// the credential-template evaluation (merged over the exchange variables), or <see langword="null"/>.
    /// </summary>
    public string? VariablesJson { get; init; }
}
