using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.JsonPointer.Jsonata;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Drives a W3C VCALM 1.0 §3.6 exchange across the admin-authored §3.6.1 step graph — the V-5c
/// workflow surface that turns the LINEAR <c>nextStep</c> chain into a MULTI-STEP exchange. Given the
/// workflow configuration, the current step, the accumulated <c>variables.results</c>, and (when a
/// holder just presented one) the verified presentation, it walks forward through the non-interactive
/// steps (mint-and-offer a credential, fire a §3.6.7 callback, redirect, complete) until it reaches a
/// step that requests a presentation from the holder (which suspends the walk on a fresh anti-replay
/// challenge) or the chain terminates (which completes the exchange).
/// </summary>
/// <remarks>
/// <para>
/// The walk is the engine's analogue of the explicit <see cref="ResolveVcalmExchangeStepDelegate"/>
/// step logic: where the deployment seam returns one decision per message, the workflow engine reads
/// the step graph and derives the same kind of decision — plus it carries out the step's
/// <c>issueRequests</c> (mint a credential through the issuance seam and offer it back over vcapi) and
/// fires the step's <c>callback</c> (through the outbound-callback seam). The library reads the graph;
/// the cryptographic and transport effects flow through the configured seams.
/// </para>
/// <para>
/// <strong>Fail-closed per step.</strong> Each step that requests a presentation binds its OWN fresh
/// challenge / domain — the walk never carries a prior step's challenge forward. The verification of a
/// presented presentation always runs against the current active step's bound challenge (in the
/// participate endpoint), so a presentation replayed from an earlier step cannot satisfy a later one.
/// </para>
/// <para>
/// <strong>Bounded.</strong> The walk caps the number of steps it visits in a single message at
/// <see cref="MaxStepsPerMessage"/>; a malformed <c>nextStep</c> cycle (which §3.6.1 validation already
/// rejects at create time, but which a directly-supplied config could still carry) terminates the walk
/// as invalid rather than looping forever.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmWorkflowStepEngine")]
public static class VcalmWorkflowStepEngine
{
    /// <summary>
    /// The maximum number of step-graph nodes the engine visits while resolving a single §3.6.5 vcapi
    /// message. A LINEAR <c>nextStep</c> chain visits each step at most once, so a well-formed workflow
    /// never approaches this bound; it exists to stop a malformed cycle (a config that bypassed §3.6.1
    /// validation) from looping forever — the walk that exceeds it fails the exchange as invalid.
    /// </summary>
    public const int MaxStepsPerMessage = 64;


    /// <summary>
    /// Walks the step graph from <paramref name="startStep"/> forward, carrying out each non-interactive
    /// step's effects (issuance, callback) until the walk suspends on a presentation-requesting step or
    /// the chain completes. Returns the resulting <see cref="VcalmWorkflowAdvanceOutcome"/> describing
    /// the engine's next move and the accumulated results.
    /// </summary>
    /// <param name="server">The host, for the time provider, the identifier seam, and the integration.</param>
    /// <param name="workflow">The workflow configuration whose step graph is walked.</param>
    /// <param name="startStep">The step the walk begins on.</param>
    /// <param name="accumulatedResults">The §3.6.6 <c>variables.results</c> accumulated so far.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<VcalmWorkflowAdvanceOutcome> WalkAsync(
        EndpointServer server,
        VcalmWorkflowConfiguration workflow,
        string startStep,
        ImmutableDictionary<string, string> accumulatedResults,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(workflow);
        ArgumentException.ThrowIfNullOrEmpty(startStep);
        ArgumentNullException.ThrowIfNull(accumulatedResults);
        ArgumentNullException.ThrowIfNull(context);

        VcalmIntegration vcalm = server.Vcalm();
        ImmutableDictionary<string, string> results = accumulatedResults;
        string currentStepName = startStep;
        int visited = 0;

        while(true)
        {
            if(++visited > MaxStepsPerMessage)
            {
                //A malformed nextStep cycle — bounded rather than looped forever. §3.6.1 validation
                //rejects a cycle at create time; this is the runtime backstop.
                return VcalmWorkflowAdvanceOutcome.Invalid(
                    currentStepName,
                    results,
                    "The workflow's step graph exceeded the maximum step count for a single message; a "
                    + "malformed nextStep cycle is suspected.");
            }

            if(!workflow.Steps.TryGetValue(currentStepName, out VcalmWorkflowStep? step))
            {
                return VcalmWorkflowAdvanceOutcome.Invalid(
                    currentStepName, results,
                    $"The workflow references an undefined step '{currentStepName}'.");
            }

            //A step that requests a presentation SUSPENDS the walk: the engine asks the holder and
            //waits. It carries the step's §3.4.1 query array forward; the participate endpoint wraps it
            //into the wire VPR under a FRESH bound challenge / domain (a fresh binding per step). The
            //step VPR's own challenge / domain (if the admin authored any) are not propagated — the
            //engine owns the anti-replay binding (§3.4.1).
            if(step.RequestsPresentation)
            {
                return VcalmWorkflowAdvanceOutcome.RequestPresentation(
                    currentStepName, step.PresentationQueryJson!, results, step.CallbackUrl);
            }

            //A step that mints credentials: evaluate each issueRequest's template against the exchange
            //variables + results, sign it through the issuance seam, and offer the issued credential
            //back over vcapi as a verifiablePresentation. The offered presentation is recorded under the
            //step and the walk continues (the issuance step is non-interactive).
            if(step.IssuesCredential)
            {
                VcalmIssuanceStepResult issuance = await IssueForStepAsync(
                    server, vcalm, workflow, step, results, context, cancellationToken).ConfigureAwait(false);
                if(!issuance.IsSuccess)
                {
                    return VcalmWorkflowAdvanceOutcome.Invalid(currentStepName, results, issuance.FailureDetail!);
                }

                results = results.SetItem(currentStepName, issuance.OfferedPresentationJson!);
                await FireCallbackIfAnyAsync(vcalm, step, context, cancellationToken).ConfigureAwait(false);

                if(step.NextStep is null)
                {
                    //The final step issued a credential — complete the exchange, offering the issued
                    //presentation as the completing reply (§3.6.5 server-emitted verifiablePresentation).
                    return VcalmWorkflowAdvanceOutcome.CompleteWithPresentation(
                        currentStepName, issuance.OfferedPresentationJson!, results);
                }

                currentStepName = step.NextStep;
                continue;
            }

            //A step that redirects completes the exchange recommending the client continue elsewhere.
            if(step.RedirectUrl is { } redirectUrl)
            {
                await FireCallbackIfAnyAsync(vcalm, step, context, cancellationToken).ConfigureAwait(false);

                return VcalmWorkflowAdvanceOutcome.Redirect(currentStepName, redirectUrl, results);
            }

            //A non-interactive step with no issuance / redirect / presentation request: fire its
            //callback and advance. If it has no nextStep it completes the exchange.
            await FireCallbackIfAnyAsync(vcalm, step, context, cancellationToken).ConfigureAwait(false);

            if(step.NextStep is null)
            {
                return VcalmWorkflowAdvanceOutcome.Complete(currentStepName, results);
            }

            currentStepName = step.NextStep;
        }
    }


    //§3.6 issuance-in-exchange: evaluate the step's issueRequests through the template seam, sign the
    //produced credential through the issuance seam, and compose a verifiablePresentation carrying the
    //issued credential(s) for the §3.6.5 server-emitted reply.
    private static async ValueTask<VcalmIssuanceStepResult> IssueForStepAsync(
        EndpointServer server,
        VcalmIntegration vcalm,
        VcalmWorkflowConfiguration workflow,
        VcalmWorkflowStep step,
        ImmutableDictionary<string, string> results,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        VcalmCredentialIssuance? issuance = await vcalm
            .ResolveEffectiveExchangeIssuanceAsync(context, cancellationToken).ConfigureAwait(false);
        if(issuance is null)
        {
            //Fail-closed: a step that mints credentials needs the issuance seam. Without it the engine
            //cannot honour the workflow's issuance step, so it refuses rather than completing silently.
            return VcalmIssuanceStepResult.Failure(
                "The workflow step issues a credential but no exchange issuance configuration is wired.");
        }

        VcalmProofDescriptor descriptor = issuance.SigningDescriptors[0];
        DateTime proofCreated = server.TimeProvider.GetUtcNow().UtcDateTime;

        List<string> issuedCredentialJsons = [];
        foreach(VcalmIssueRequest issueRequest in step.IssueRequests)
        {
            VcalmCredentialTemplate? template = SelectTemplate(workflow, issueRequest);
            if(template is null)
            {
                return VcalmIssuanceStepResult.Failure(
                    "The workflow step's issueRequest names a credentialTemplate the workflow does not define.");
            }

            //Evaluate the template against the exchange variables (the §3.6.6 results plus the issue
            //request's own variables) through the bounded template-evaluation seam.
            JsonataValue variables = ComposeTemplateVariables(vcalm, results, issueRequest);
            JsonataValue rendered = vcalm.VcalmTemplateEvaluators.Evaluate(template, variables);

            //§3.6.2: the template renders to an object with a "credential" field (and optionally an
            //"options" field — the POST /credentials/issue body shape). The credential is the part the
            //engine signs.
            JsonataValue credentialValue = rendered.Kind == JsonataValueKind.Object
                ? rendered.GetMemberOrNull(VcalmParameterNames.Credential)
                : JsonataValue.Null;
            JsonataValue toSign = credentialValue.IsNull ? rendered : credentialValue;

            string credentialJson = JsonataJsonWriter.Write(toSign);
            VerifiableCredential credential;
            try
            {
                credential = descriptor.DeserializeCredential(credentialJson);
            }
            catch(InvalidOperationException)
            {
                return VcalmIssuanceStepResult.Failure(
                    "The credential the workflow template rendered could not be read as a verifiable credential.");
            }

            VcalmIssuanceResult signed = await VcalmCredentialIssuanceService.IssueAsync(
                credential,
                hasExistingProof: false,
                issuance,
                proofCreated,
                context,
                cancellationToken).ConfigureAwait(false);
            if(!signed.IsSuccess)
            {
                return VcalmIssuanceStepResult.Failure(
                    "The credential the workflow template rendered could not be secured.");
            }

            issuedCredentialJsons.Add(descriptor.SerializeCredential(signed.SecuredCredential!));
        }

        //§3.6.5 / §3.6.8: the issued credential(s) ride back to the client inside a verifiablePresentation
        //(the server-emitted presentation the exchange offers in the same step).
        string presentationJson = ComposePresentationOfCredentials(issuedCredentialJsons);

        return VcalmIssuanceStepResult.Success(presentationJson);
    }


    //§3.6.1 issueRequest template selection: by credentialTemplateId (matched against the template's id)
    //or by credentialTemplateIndex (the array position in the workflow's credentialTemplates).
    private static VcalmCredentialTemplate? SelectTemplate(
        VcalmWorkflowConfiguration workflow, VcalmIssueRequest issueRequest)
    {
        if(issueRequest.CredentialTemplateId is { } id)
        {
            foreach(VcalmCredentialTemplate candidate in workflow.CredentialTemplates)
            {
                if(string.Equals(candidate.Id, id, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }

            return null;
        }

        if(issueRequest.CredentialTemplateIndex is { } index
            && index >= 0
            && index < workflow.CredentialTemplates.Length)
        {
            return workflow.CredentialTemplates[index];
        }

        return null;
    }


    //Composes the JSONata input for a template evaluation: an object carrying the exchange's
    //variables.results (so a template can reference results.<step>.verifiablePresentation.holder) and
    //the issue request's own variables flattened on top. The verbatim JSON fragments cross the
    //serialization firewall to the JsonataValue model through the integration's ParseVcalmTemplateInput
    //seam; when that seam is unwired the engine evaluates against an empty context (a constant credential
    //body still renders). The minimal in-repo engine navigates these by field reference; the full
    //Lumoin.Veritas engine a deployment registers consumes the same model.
    private static JsonataValue ComposeTemplateVariables(
        VcalmIntegration vcalm, ImmutableDictionary<string, string> results, VcalmIssueRequest issueRequest)
    {
        ParseVcalmTemplateInputDelegate? parse = vcalm.ParseVcalmTemplateInputAsync;
        var members = new Dictionary<string, JsonataValue>(StringComparer.Ordinal);

        if(parse is not null && !results.IsEmpty)
        {
            var resultMembers = new Dictionary<string, JsonataValue>(StringComparer.Ordinal);
            foreach(KeyValuePair<string, string> entry in results)
            {
                resultMembers[entry.Key] = parse(entry.Value);
            }

            members[VcalmParameterNames.Results] = JsonataValue.FromObject(resultMembers);
        }

        if(parse is not null && issueRequest.VariablesJson is { } variablesJson)
        {
            JsonataValue parsed = parse(variablesJson);
            if(parsed.Kind == JsonataValueKind.Object)
            {
                foreach(KeyValuePair<string, JsonataValue> member in parsed.AsObject())
                {
                    members[member.Key] = member.Value;
                }
            }
            else if(!parsed.IsNull)
            {
                //§3.6.1: variables MAY be a bare top-level variable NAME (a string) — the per-request
                //variables object is then expected to already live under the exchange variables. The
                //minimal engine has no exchange-variable store of its own, so the name is exposed as a
                //"variables" member the template can reference; the full engine resolves it natively.
                members[VcalmParameterNames.Variables] = parsed;
            }
        }

        return JsonataValue.FromObject(members);
    }


    //§3.6.8: wrap the issued credential(s) in a minimal VC-DM 2.0 verifiable presentation the §3.6.5
    //reply offers. The presentation is server-emitted (the issuer offering the credential), so it
    //carries no holder proof — the credential's own Data Integrity proof is what the client verifies.
    private static string ComposePresentationOfCredentials(List<string> credentialJsons)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append("{\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Context);
            sb.Append("\":[\"");
            JsonAppender.AppendEscapedString(sb, Context.Credentials20);
            sb.Append("\"],\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Type);
            sb.Append("\":[\"VerifiablePresentation\"],\"");
            JsonAppender.AppendEscapedString(sb, VcalmParameterNames.VerifiableCredential);
            sb.Append("\":[");

            for(int i = 0; i < credentialJsons.Count; ++i)
            {
                if(i > 0)
                {
                    sb.Append(',');
                }

                sb.Append(credentialJsons[i]);
            }

            sb.Append("]}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    //§3.6.1 / §3.6.7: fire the step's callback when it names one and the outbound-callback seam is
    //wired. The engine mints a fresh ≥128-bit capability id is the CALLER's concern (the step already
    //carries the admin-supplied capability URL); the engine composes the body and invokes the seam. The
    //actual HTTP POST is the application's (the library has no System.Net.*).
    private static async ValueTask FireCallbackIfAnyAsync(
        VcalmIntegration vcalm,
        VcalmWorkflowStep step,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(step.CallbackUrl is not { } callbackUrl || vcalm.DeliverVcalmCallbackAsync is not { } deliver)
        {
            return;
        }

        string exchangeId = context.VcalmExchangeId ?? string.Empty;
        string body = VcalmCallbackComposer.ComposeCallbackBody(exchangeId);

        await deliver(callbackUrl, body, context, cancellationToken).ConfigureAwait(false);
    }
}


/// <summary>
/// The outcome of a <see cref="VcalmWorkflowStepEngine.WalkAsync"/> step-graph walk — what the engine
/// does next after walking the §3.6.1 step graph: request a presentation, complete (optionally with a
/// server-offered presentation or a redirect), or fail the exchange.
/// </summary>
[DebuggerDisplay("VcalmWorkflowAdvanceOutcome Kind={Kind} Step={StepName}")]
public sealed record VcalmWorkflowAdvanceOutcome
{
    /// <summary>The kind of outcome the walk reached.</summary>
    public required VcalmWorkflowAdvanceKind Kind { get; init; }

    /// <summary>The §3.6.6 step the walk suspended / completed / failed on.</summary>
    public required string StepName { get; init; }

    /// <summary>The §3.6.6 <c>variables.results</c> accumulated through the walk.</summary>
    public required ImmutableDictionary<string, string> StepResults { get; init; }

    /// <summary>
    /// For <see cref="VcalmWorkflowAdvanceKind.RequestPresentation"/>: the verbatim §3.4 VPR query JSON
    /// (minus challenge / domain) the engine sends. <see langword="null"/> otherwise.
    /// </summary>
    public string? PresentationRequestQueryJson { get; init; }

    /// <summary>
    /// For <see cref="VcalmWorkflowAdvanceKind.CompleteWithPresentation"/>: the verbatim server-offered
    /// <c>verifiablePresentation</c> JSON. <see langword="null"/> otherwise.
    /// </summary>
    public string? OfferedPresentationJson { get; init; }

    /// <summary>
    /// For <see cref="VcalmWorkflowAdvanceKind.Redirect"/>: the redirect URL. <see langword="null"/>
    /// otherwise.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely; promoting to System.Uri would lose the admin's exact percent-encoding shape on the wire.")]
    public string? RedirectUrl { get; init; }

    /// <summary>
    /// For <see cref="VcalmWorkflowAdvanceKind.Invalid"/>: the failure detail. <see langword="null"/>
    /// otherwise.
    /// </summary>
    public string? FailureDetail { get; init; }

    /// <summary>The callback URL the suspending step named, if any (the participate endpoint fires it after the reply).</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6.1 / §3.6.7 callback url is a verbatim capability URL the engine passes through opaquely to the outbound-callback seam.")]
    public string? CallbackUrl { get; init; }


    /// <summary>The walk suspended on a step requesting a presentation from the holder.</summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "§3.6.1 callback url is a verbatim capability URL carried through opaquely to the outbound-callback seam.")]
    public static VcalmWorkflowAdvanceOutcome RequestPresentation(
        string stepName, string queryJson, ImmutableDictionary<string, string> results, string? callbackUrl) =>
        new()
        {
            Kind = VcalmWorkflowAdvanceKind.RequestPresentation,
            StepName = stepName,
            PresentationRequestQueryJson = queryJson,
            StepResults = results,
            CallbackUrl = callbackUrl
        };


    /// <summary>The walk completed the exchange offering a server-emitted presentation (an issued credential).</summary>
    public static VcalmWorkflowAdvanceOutcome CompleteWithPresentation(
        string stepName, string presentationJson, ImmutableDictionary<string, string> results) =>
        new()
        {
            Kind = VcalmWorkflowAdvanceKind.CompleteWithPresentation,
            StepName = stepName,
            OfferedPresentationJson = presentationJson,
            StepResults = results
        };


    /// <summary>The walk completed the exchange recommending the client continue at a redirect URL.</summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string carried through opaquely to the vcapi reply.")]
    public static VcalmWorkflowAdvanceOutcome Redirect(
        string stepName, string redirectUrl, ImmutableDictionary<string, string> results) =>
        new()
        {
            Kind = VcalmWorkflowAdvanceKind.Redirect,
            StepName = stepName,
            RedirectUrl = redirectUrl,
            StepResults = results
        };


    /// <summary>The walk completed the exchange with nothing more to request nor offer (empty reply).</summary>
    public static VcalmWorkflowAdvanceOutcome Complete(
        string stepName, ImmutableDictionary<string, string> results) =>
        new()
        {
            Kind = VcalmWorkflowAdvanceKind.Complete,
            StepName = stepName,
            StepResults = results
        };


    /// <summary>The walk failed the exchange (a malformed cycle, an undefined step, an issuance failure).</summary>
    public static VcalmWorkflowAdvanceOutcome Invalid(
        string stepName, ImmutableDictionary<string, string> results, string detail) =>
        new()
        {
            Kind = VcalmWorkflowAdvanceKind.Invalid,
            StepName = stepName,
            FailureDetail = detail,
            StepResults = results
        };
}


/// <summary>The kinds of outcome a §3.6.1 step-graph walk reaches.</summary>
public enum VcalmWorkflowAdvanceKind
{
    /// <summary>The walk suspended on a step requesting a presentation from the holder.</summary>
    RequestPresentation,

    /// <summary>The walk completed offering a server-emitted presentation (an issued credential).</summary>
    CompleteWithPresentation,

    /// <summary>The walk completed recommending the client continue at a redirect URL.</summary>
    Redirect,

    /// <summary>The walk completed with nothing more to request nor offer.</summary>
    Complete,

    /// <summary>The walk failed the exchange (a malformed cycle, undefined step, issuance failure).</summary>
    Invalid
}


//The result of a single step's issuance: the server-offered presentation JSON on success, or a failure
//detail when the template / signing could not produce a credential.
internal sealed record VcalmIssuanceStepResult
{
    public required bool IsSuccess { get; init; }

    public string? OfferedPresentationJson { get; init; }

    public string? FailureDetail { get; init; }


    public static VcalmIssuanceStepResult Success(string presentationJson) =>
        new() { IsSuccess = true, OfferedPresentationJson = presentationJson };


    public static VcalmIssuanceStepResult Failure(string detail) =>
        new() { IsSuccess = false, FailureDetail = detail };
}
