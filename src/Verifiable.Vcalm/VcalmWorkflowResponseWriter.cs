using System.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Hand-built JSON writer for the W3C VCALM 1.0 §3.6.2 get-workflow-configuration response body —
/// the workflow configuration echoed back through <see cref="JsonAppender"/> per the
/// <c>Verifiable.Vcalm</c> serialization firewall (no <c>System.Text.Json</c>). Each step's verbatim
/// sub-objects (the §3.4 <c>verifiablePresentationRequest</c>, the offered <c>verifiablePresentation</c>,
/// the <c>presentationSchema</c> / <c>openId</c>) and the <c>authorization</c> object ride through with
/// <see cref="JsonAppender.AppendRawField"/> so they are returned byte-faithful.
/// </summary>
public static class VcalmWorkflowResponseWriter
{
    /// <summary>
    /// Writes the §3.6.2 workflow-configuration response: the workflow's <c>id</c> (the id the §3.6.1
    /// create endpoint stored it under), the REQUIRED <c>initialStep</c>, the <c>steps</c> object, the
    /// optional <c>credentialTemplates</c>, <c>controller</c>, and <c>authorization</c>.
    /// </summary>
    /// <param name="workflowId">The id the workflow is stored under (echoed as the response <c>id</c>).</param>
    /// <param name="configuration">The stored workflow configuration.</param>
    public static string BuildWorkflowResponse(string workflowId, VcalmWorkflowConfiguration configuration)
    {
        ArgumentException.ThrowIfNullOrEmpty(workflowId);
        ArgumentNullException.ThrowIfNull(configuration);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');
            bool first = true;

            JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, workflowId, ref first);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.InitialStep, configuration.InitialStep, ref first);

            if(configuration.Controller is { } controller)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Controller, controller, ref first);
            }

            if(configuration.AuthorizationJson is { } authorizationJson)
            {
                JsonAppender.AppendRawField(sb, VcalmParameterNames.Authorization, authorizationJson, ref first);
            }

            AppendSteps(sb, configuration, ref first);
            AppendCredentialTemplates(sb, configuration, ref first);

            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    //§3.6.2 steps: { STEP_NAME : { <step directives> } }.
    private static void AppendSteps(StringBuilder sb, VcalmWorkflowConfiguration configuration, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Steps);
        _ = sb.Append("\":{");

        bool stepsFirst = true;
        foreach(KeyValuePair<string, VcalmWorkflowStep> entry in configuration.Steps)
        {
            if(!stepsFirst)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('"');
            JsonAppender.AppendEscapedString(sb, entry.Key);
            _ = sb.Append("\":");
            AppendStep(sb, entry.Value);
            stepsFirst = false;
        }

        _ = sb.Append('}');
        first = false;
    }


    //§3.6.2 one step: the directives the engine drives, in a stable order.
    private static void AppendStep(StringBuilder sb, VcalmWorkflowStep step)
    {
        _ = sb.Append('{');
        bool first = true;

        if(step.CreateChallenge)
        {
            JsonAppender.AppendBoolField(sb, VcalmParameterNames.CreateChallenge, value: true, ref first);
        }

        if(step.VerifiablePresentationRequestJson is { } vprJson)
        {
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiablePresentationRequest, vprJson, ref first);
        }

        if(step.VerifiablePresentationJson is { } vpJson)
        {
            JsonAppender.AppendRawField(sb, VcalmParameterNames.VerifiablePresentation, vpJson, ref first);
        }

        if(step.RedirectUrl is { } redirectUrl)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.RedirectUrl, redirectUrl, ref first);
        }

        if(step.CallbackUrl is { } callbackUrl)
        {
            AppendCallback(sb, callbackUrl, ref first);
        }

        if(step.IssuesCredential)
        {
            AppendIssueRequests(sb, step, ref first);
        }

        if(step.PresentationSchemaJson is { } schemaJson)
        {
            JsonAppender.AppendRawField(sb, VcalmParameterNames.PresentationSchema, schemaJson, ref first);
        }

        if(step.OpenIdJson is { } openIdJson)
        {
            JsonAppender.AppendRawField(sb, VcalmParameterNames.OpenId, openIdJson, ref first);
        }

        if(step.NextStep is { } nextStep)
        {
            JsonAppender.AppendStringField(sb, VcalmParameterNames.NextStep, nextStep, ref first);
        }

        _ = sb.Append('}');
    }


    private static void AppendCallback(StringBuilder sb, string callbackUrl, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.Callback);
        _ = sb.Append("\":{");

        bool callbackFirst = true;
        JsonAppender.AppendStringField(sb, VcalmParameterNames.Url, callbackUrl, ref callbackFirst);

        _ = sb.Append('}');
        first = false;
    }


    private static void AppendIssueRequests(StringBuilder sb, VcalmWorkflowStep step, ref bool first)
    {
        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.IssueRequests);
        _ = sb.Append("\":[");

        bool requestsFirst = true;
        foreach(VcalmIssueRequest issueRequest in step.IssueRequests)
        {
            if(!requestsFirst)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            bool entryFirst = true;

            if(issueRequest.CredentialTemplateId is { } templateId)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.CredentialTemplateId, templateId, ref entryFirst);
            }

            if(issueRequest.CredentialTemplateIndex is { } templateIndex)
            {
                JsonAppender.AppendInt64Field(sb, VcalmParameterNames.CredentialTemplateIndex, templateIndex, ref entryFirst);
            }

            if(issueRequest.VariablesJson is { } variablesJson)
            {
                JsonAppender.AppendRawField(sb, VcalmParameterNames.Variables, variablesJson, ref entryFirst);
            }

            _ = sb.Append('}');
            requestsFirst = false;
        }

        _ = sb.Append(']');
        first = false;
    }


    //§3.6.2 credentialTemplates: [ { id?, type, template } ].
    private static void AppendCredentialTemplates(StringBuilder sb, VcalmWorkflowConfiguration configuration, ref bool first)
    {
        if(configuration.CredentialTemplates.IsDefaultOrEmpty)
        {
            return;
        }

        if(!first)
        {
            _ = sb.Append(',');
        }

        _ = sb.Append('"');
        JsonAppender.AppendEscapedString(sb, VcalmParameterNames.CredentialTemplates);
        _ = sb.Append("\":[");

        bool templatesFirst = true;
        foreach(VcalmCredentialTemplate template in configuration.CredentialTemplates)
        {
            if(!templatesFirst)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            bool entryFirst = true;

            if(template.Id is { } id)
            {
                JsonAppender.AppendStringField(sb, VcalmParameterNames.Id, id, ref entryFirst);
            }

            JsonAppender.AppendStringField(sb, VcalmParameterNames.Type, template.TemplateType, ref entryFirst);
            JsonAppender.AppendStringField(sb, VcalmParameterNames.Template, template.Template, ref entryFirst);

            _ = sb.Append('}');
            templatesFirst = false;
        }

        _ = sb.Append(']');
        first = false;
    }
}
