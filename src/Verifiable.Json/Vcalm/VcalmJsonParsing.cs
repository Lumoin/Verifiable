using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.StatusList;
using Verifiable.JsonPointer.Jsonata;
using Verifiable.Vcalm;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parsers for the W3C VCALM 1.0 §3.3.1 / §3.3.2 verify request
/// bodies — the JSON side the <c>Verifiable.Vcalm</c> serialization firewall keeps out of the
/// library. Wire them onto a <see cref="VcalmIntegration"/> with
/// <see cref="VcalmJsonExtensions.UseDefaultVcalmJsonParsing"/>.
/// </summary>
/// <remarks>
/// The parsers are STRICT per §2.4: a body that is not a JSON object, omits the REQUIRED credential
/// / presentation member, carries an unrecognized TOP-LEVEL member, or carries a credential /
/// presentation that is not a recognized secured shape yields
/// <see cref="VcalmParseFailure.Malformed"/>; a body whose <c>options</c> object carries a member
/// the verifier does not understand yields <see cref="VcalmParseFailure.UnknownOption"/>
/// ("Implementations MUST throw an error if an endpoint receives data, options, or option values
/// that it does not understand or know how to process"). The parsers never throw to the caller;
/// every rejection is a typed failure the endpoint maps to its HTTP outcome.
/// </remarks>
public static class VcalmJsonParsing
{
    /// <summary>
    /// Builds a <see cref="ParseVcalmVerifyCredentialDelegate"/> bound to <paramref name="options"/>
    /// (the serializer options carrying the Verifiable credential converters).
    /// </summary>
    public static ParseVcalmVerifyCredentialDelegate CreateCredentialParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmVerifyCredentialRequest?>(ParseCredential(requestBody, options));
    }


    /// <summary>
    /// Builds a <see cref="ParseVcalmVerifyPresentationDelegate"/> bound to <paramref name="options"/>.
    /// </summary>
    public static ParseVcalmVerifyPresentationDelegate CreatePresentationParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmVerifyPresentationRequest?>(ParsePresentation(requestBody, options));
    }


    /// <summary>
    /// Builds a <see cref="ParseVcalmIssueCredentialDelegate"/> bound to <paramref name="options"/>
    /// (the serializer options carrying the Verifiable credential converters).
    /// </summary>
    public static ParseVcalmIssueCredentialDelegate CreateIssueParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmIssueCredentialRequest?>(ParseIssue(requestBody, options));
    }


    /// <summary>
    /// Builds a <see cref="ParseVcalmDeriveCredentialDelegate"/> bound to <paramref name="options"/>
    /// (the serializer options carrying the Verifiable credential converters) for the §3.5.1
    /// <c>POST /credentials/derive</c> body.
    /// </summary>
    public static ParseVcalmDeriveCredentialDelegate CreateDeriveParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmDeriveCredentialRequest?>(ParseDerive(requestBody, options));
    }


    /// <summary>
    /// Builds a <see cref="ParseVcalmCreatePresentationDelegate"/> bound to <paramref name="options"/>
    /// for the §3.5.2 <c>POST /presentations</c> body.
    /// </summary>
    public static ParseVcalmCreatePresentationDelegate CreateCreatePresentationParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmCreatePresentationRequest?>(ParseCreatePresentation(requestBody, options));
    }


    /// <summary>
    /// Builds a <see cref="ParseVcalmUpdateStatusDelegate"/> for the §C.3
    /// <c>POST /credentials/status</c> body. STJ-free of <paramref name="options"/> dependencies —
    /// the §C.3 body is a small fixed-shape object the parser reads with <see cref="JsonDocument"/>.
    /// </summary>
    public static ParseVcalmUpdateStatusDelegate CreateUpdateStatusParser() =>
        (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmUpdateStatusRequest?>(ParseUpdateStatus(requestBody));


    /// <summary>
    /// Builds a <see cref="ParseVcalmCreateStatusListDelegate"/> for the §C.1
    /// <c>POST /status-lists</c> body.
    /// </summary>
    public static ParseVcalmCreateStatusListDelegate CreateStatusListParser() =>
        (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmCreateStatusListRequest?>(ParseCreateStatusList(requestBody));


    /// <summary>
    /// Builds a <see cref="ParseVcalmCreateExchangeDelegate"/> for the §3.6.3
    /// <c>POST /workflows/{localWorkflowId}/exchanges</c> body. The body's fixed-shape outer members
    /// are read with <see cref="JsonDocument"/>; <c>variables</c> / <c>openId</c> are carried verbatim.
    /// </summary>
    public static ParseVcalmCreateExchangeDelegate CreateExchangeParser() =>
        (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmCreateExchangeRequest?>(ParseCreateExchange(requestBody));


    /// <summary>
    /// Builds a <see cref="ParseVcalmExchangeMessageDelegate"/> bound to <paramref name="options"/>
    /// (the serializer options carrying the Verifiable credential and DCQL converters) for the §3.6.5
    /// vcapi protocol message body.
    /// </summary>
    public static ParseVcalmExchangeMessageDelegate CreateExchangeMessageParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmExchangeMessage?>(ParseExchangeMessage(requestBody, options));
    }


    /// <summary>
    /// Builds a <see cref="ParseVcalmCreateWorkflowDelegate"/> for the §3.6.1 <c>POST /workflows</c>
    /// body. The body is read with <see cref="JsonDocument"/>; verbatim sub-objects (each step's
    /// <c>verifiablePresentationRequest</c> / <c>verifiablePresentation</c> / <c>presentationSchema</c>
    /// / <c>openId</c>, the <c>authorization</c> object) are carried as raw JSON.
    /// </summary>
    public static ParseVcalmCreateWorkflowDelegate CreateWorkflowParser() =>
        (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmWorkflowConfiguration?>(ParseCreateWorkflow(requestBody));


    /// <summary>
    /// Builds a <see cref="ParseVcalmCallbackDelegate"/> for the §3.6.7
    /// <c>POST /callbacks/{localCallbackId}</c> body. The body is the small fixed-shape
    /// <c>{event{data{exchangeId}}}</c> object read with <see cref="JsonDocument"/>.
    /// </summary>
    public static ParseVcalmCallbackDelegate CreateCallbackParser() =>
        (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmCallbackRequest?>(ParseCallback(requestBody));


    /// <summary>
    /// Builds a <see cref="ParseVcalmTemplateInputDelegate"/> — the §3.6 JSON → <see cref="JsonataValue"/>
    /// adapter the exchange engine uses to feed an exchange's <c>variables.results</c> and an issue
    /// request's <c>variables</c> to the credential-template evaluation. A fragment that is not parseable
    /// JSON adapts to <see cref="JsonataValue.Null"/> (the template then navigates it to nothing).
    /// </summary>
    public static ParseVcalmTemplateInputDelegate CreateTemplateInputParser() =>
        json => ParseTemplateInput(json);


    /// <summary>
    /// Builds a <see cref="ParseVcalmInviteRequestDelegate"/> for the §3.7.5 inviteRequest body. The
    /// body is the small fixed-shape <c>{url, purpose, referenceId?}</c> object read with
    /// <see cref="JsonDocument"/>.
    /// </summary>
    public static ParseVcalmInviteRequestDelegate CreateInviteRequestParser() =>
        (requestBody, context, cancellationToken) =>
            ValueTask.FromResult<VcalmInviteRequest?>(ParseInviteRequest(requestBody));


    //§3.7.5 inviteRequest: {url, purpose?, referenceId?}. STRICT per §2.4: a non-object body, a missing
    //REQUIRED url, or an unrecognized top-level member is Malformed / UnknownOption. The §3.7.5 examples
    //always carry url + purpose; referenceId is the recommended unique id (a urn:uuid value).
    private static VcalmInviteRequest ParseInviteRequest(string requestBody)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmInviteRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmInviteRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.7.5 body has exactly url, purpose,
            //and the optional referenceId.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.Url, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Purpose, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.ReferenceId, StringComparison.Ordinal))
                {
                    return VcalmInviteRequest.UnknownOption();
                }
            }

            //§3.7.5: the url is the member directing where to send the individual; it is REQUIRED for
            //the invitation to mean anything (format is the implementer's choice, but it must be present).
            if(!root.TryGetProperty(VcalmParameterNames.Url, out JsonElement urlElement)
                || urlElement.ValueKind != JsonValueKind.String
                || string.IsNullOrEmpty(urlElement.GetString()))
            {
                return VcalmInviteRequest.Malformed();
            }

            string? purpose = root.TryGetProperty(VcalmParameterNames.Purpose, out JsonElement purposeElement)
                && purposeElement.ValueKind == JsonValueKind.String
                ? purposeElement.GetString()
                : null;

            string? referenceId = root.TryGetProperty(VcalmParameterNames.ReferenceId, out JsonElement referenceIdElement)
                && referenceIdElement.ValueKind == JsonValueKind.String
                ? referenceIdElement.GetString()
                : null;

            return new VcalmInviteRequest
            {
                Url = urlElement.GetString(),
                Purpose = purpose,
                ReferenceId = referenceId
            };
        }
    }


    //§3.6 JSON → JsonataValue adapter: the local value model the minimal JSONata evaluator reads. Object
    //member order is preserved so a constructed credential body renders deterministically.
    private static JsonataValue ParseTemplateInput(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch(JsonException)
        {
            return JsonataValue.Null;
        }

        using(doc)
        {
            return ConvertElement(doc.RootElement);
        }
    }


    private static JsonataValue ConvertElement(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => ConvertObject(element),
        JsonValueKind.Array => ConvertArray(element),
        JsonValueKind.String => JsonataValue.FromString(element.GetString()!),
        JsonValueKind.Number => ConvertNumber(element),
        JsonValueKind.True => JsonataValue.True,
        JsonValueKind.False => JsonataValue.False,
        _ => JsonataValue.Null
    };


    private static JsonataValue ConvertObject(JsonElement element)
    {
        var members = new Dictionary<string, JsonataValue>(StringComparer.Ordinal);
        foreach(JsonProperty property in element.EnumerateObject())
        {
            members[property.Name] = ConvertElement(property.Value);
        }

        return JsonataValue.FromObject(members);
    }


    private static JsonataValue ConvertArray(JsonElement element)
    {
        var elements = new List<JsonataValue>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            elements.Add(ConvertElement(item));
        }

        return JsonataValue.FromArray(elements);
    }


    private static JsonataValue ConvertNumber(JsonElement element) =>
        element.TryGetInt64(out long integer)
            ? JsonataValue.FromInteger(integer)
            : JsonataValue.FromNumber(element.GetDouble());


    //§3.6.1 create-workflow: {id?, initialStep (REQUIRED), steps (REQUIRED), credentialTemplates?,
    //controller?, authorization?}. STRICT per §2.4: a non-object body, a missing REQUIRED initialStep
    ///steps, or an unrecognized top-level member is the strict-parse rejection (Malformed / UnknownOption).
    //The §3.6.1 step-graph structural MUSTs are enforced separately by VcalmWorkflowValidation.
    private static VcalmWorkflowConfiguration ParseCreateWorkflow(string requestBody)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmWorkflowConfiguration.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmWorkflowConfiguration.Malformed();
            }

            //§2.4: reject an unrecognized top-level member.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.Id, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.InitialStep, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Steps, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.CredentialTemplates, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Controller, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Authorization, StringComparison.Ordinal))
                {
                    return VcalmWorkflowConfiguration.UnknownOption();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.InitialStep, out JsonElement initialStepElement)
                || initialStepElement.ValueKind != JsonValueKind.String)
            {
                return VcalmWorkflowConfiguration.Malformed();
            }

            if(!root.TryGetProperty(VcalmParameterNames.Steps, out JsonElement stepsElement)
                || stepsElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmWorkflowConfiguration.Malformed();
            }

            ImmutableDictionary<string, VcalmWorkflowStep>.Builder steps =
                ImmutableDictionary.CreateBuilder<string, VcalmWorkflowStep>(StringComparer.Ordinal);
            foreach(JsonProperty stepProperty in stepsElement.EnumerateObject())
            {
                if(stepProperty.Value.ValueKind != JsonValueKind.Object)
                {
                    return VcalmWorkflowConfiguration.Malformed();
                }

                (VcalmWorkflowStep? step, VcalmParseFailure stepFailure) = ParseWorkflowStep(stepProperty.Value);
                if(step is null)
                {
                    return stepFailure == VcalmParseFailure.UnknownOption
                        ? VcalmWorkflowConfiguration.UnknownOption()
                        : VcalmWorkflowConfiguration.Malformed();
                }

                steps[stepProperty.Name] = step;
            }

            (ImmutableArray<VcalmCredentialTemplate> templates, VcalmParseFailure templatesFailure) =
                ParseCredentialTemplates(root);
            if(templatesFailure != VcalmParseFailure.None)
            {
                return templatesFailure == VcalmParseFailure.UnknownOption
                    ? VcalmWorkflowConfiguration.UnknownOption()
                    : VcalmWorkflowConfiguration.Malformed();
            }

            string? id = root.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement)
                && idElement.ValueKind == JsonValueKind.String
                ? idElement.GetString()
                : null;

            string? controller = root.TryGetProperty(VcalmParameterNames.Controller, out JsonElement controllerElement)
                && controllerElement.ValueKind == JsonValueKind.String
                ? controllerElement.GetString()
                : null;

            string? authorizationJson = root.TryGetProperty(VcalmParameterNames.Authorization, out JsonElement authorizationElement)
                && authorizationElement.ValueKind == JsonValueKind.Object
                ? authorizationElement.GetRawText()
                : null;

            return new VcalmWorkflowConfiguration
            {
                Id = id,
                InitialStep = initialStepElement.GetString()!,
                Steps = steps.ToImmutable(),
                CredentialTemplates = templates,
                Controller = controller,
                AuthorizationJson = authorizationJson
            };
        }
    }


    //§3.6.1 step data: {createChallenge?, verifiablePresentationRequest?, verifiablePresentation?,
    //redirectUrl?, callback{url}?, issueRequests[]?, presentationSchema?, nextStep?, openId?}. An
    //unrecognized member is the §2.4 strict-parse rejection. The stepTemplate alternative (a jsonata
    //step template) is modeled-but-deferred: a step carrying it is not the literal step-data shape this
    //engine drives, so it is rejected as Malformed rather than silently accepted.
    private static (VcalmWorkflowStep? Step, VcalmParseFailure Failure) ParseWorkflowStep(JsonElement element)
    {
        bool createChallenge = false;
        string? vprJson = null;
        string? presentationQueryJson = null;
        string? vpJson = null;
        string? redirectUrl = null;
        string? callbackUrl = null;
        ImmutableArray<VcalmIssueRequest> issueRequests = ImmutableArray<VcalmIssueRequest>.Empty;
        string? nextStep = null;
        string? presentationSchemaJson = null;
        string? openIdJson = null;

        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(string.Equals(property.Name, VcalmParameterNames.CreateChallenge, StringComparison.Ordinal))
            {
                createChallenge = property.Value.ValueKind == JsonValueKind.True;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.VerifiablePresentationRequest, StringComparison.Ordinal))
            {
                //§3.6.1 / §3.4.1: the step's verifiablePresentationRequest is a §3.4 VPR object whose
                //query is the REQUIRED array of typed query maps. The whole object is kept verbatim for
                //the §3.6.2 round-trip; the query array is extracted for the engine, which composes the
                //wire VPR by wrapping the query under its OWN bound challenge / domain. A non-object VPR,
                //or one without a query array, is rejected here rather than silently dropping the step's
                //presentation gate (a non-object VPR would otherwise leave the step requesting nothing).
                if(property.Value.ValueKind != JsonValueKind.Object
                    || !property.Value.TryGetProperty(VcalmParameterNames.Query, out JsonElement queryElement)
                    || queryElement.ValueKind != JsonValueKind.Array)
                {
                    return (null, VcalmParseFailure.Malformed);
                }

                vprJson = property.Value.GetRawText();
                presentationQueryJson = queryElement.GetRawText();
            }
            else if(string.Equals(property.Name, VcalmParameterNames.VerifiablePresentation, StringComparison.Ordinal))
            {
                vpJson = property.Value.ValueKind == JsonValueKind.Object ? property.Value.GetRawText() : null;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.RedirectUrl, StringComparison.Ordinal))
            {
                redirectUrl = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Callback, StringComparison.Ordinal))
            {
                if(property.Value.ValueKind != JsonValueKind.Object
                    || !property.Value.TryGetProperty(VcalmParameterNames.Url, out JsonElement urlElement)
                    || urlElement.ValueKind != JsonValueKind.String)
                {
                    return (null, VcalmParseFailure.Malformed);
                }

                callbackUrl = urlElement.GetString();
            }
            else if(string.Equals(property.Name, VcalmParameterNames.IssueRequests, StringComparison.Ordinal))
            {
                (ImmutableArray<VcalmIssueRequest> parsed, VcalmParseFailure failure) = ParseIssueRequests(property.Value);
                if(failure != VcalmParseFailure.None)
                {
                    return (null, failure);
                }

                issueRequests = parsed;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.NextStep, StringComparison.Ordinal))
            {
                nextStep = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.PresentationSchema, StringComparison.Ordinal))
            {
                presentationSchemaJson = property.Value.ValueKind == JsonValueKind.Object ? property.Value.GetRawText() : null;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.OpenId, StringComparison.Ordinal))
            {
                openIdJson = property.Value.ValueKind == JsonValueKind.Object ? property.Value.GetRawText() : null;
            }
            else
            {
                //§2.4 unknown-member MUST (covers the modeled-but-deferred stepTemplate /
                //verifyPresentationResponseSchema members this engine does not drive).
                return (null, VcalmParseFailure.UnknownOption);
            }
        }

        return (new VcalmWorkflowStep
        {
            CreateChallenge = createChallenge,
            VerifiablePresentationRequestJson = vprJson,
            PresentationQueryJson = presentationQueryJson,
            VerifiablePresentationJson = vpJson,
            RedirectUrl = redirectUrl,
            CallbackUrl = callbackUrl,
            IssueRequests = issueRequests,
            NextStep = nextStep,
            PresentationSchemaJson = presentationSchemaJson,
            OpenIdJson = openIdJson
        }, VcalmParseFailure.None);
    }


    //§3.6.1 issueRequests[]: each entry MUST carry credentialTemplateId XOR credentialTemplateIndex,
    //plus an OPTIONAL variables value (a top-level variable name or a per-request object, carried
    //verbatim). A non-array value, a non-object entry, or an entry naming neither / both is Malformed.
    private static (ImmutableArray<VcalmIssueRequest> Requests, VcalmParseFailure Failure) ParseIssueRequests(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.Array)
        {
            return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
        }

        ImmutableArray<VcalmIssueRequest>.Builder builder = ImmutableArray.CreateBuilder<VcalmIssueRequest>();
        foreach(JsonElement entry in element.EnumerateArray())
        {
            if(entry.ValueKind != JsonValueKind.Object)
            {
                return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
            }

            string? templateId = null;
            int? templateIndex = null;
            string? variablesJson = null;

            foreach(JsonProperty property in entry.EnumerateObject())
            {
                if(string.Equals(property.Name, VcalmParameterNames.CredentialTemplateId, StringComparison.Ordinal))
                {
                    templateId = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
                }
                else if(string.Equals(property.Name, VcalmParameterNames.CredentialTemplateIndex, StringComparison.Ordinal))
                {
                    if(property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt32(out int index))
                    {
                        templateIndex = index;
                    }
                }
                else if(string.Equals(property.Name, VcalmParameterNames.Variables, StringComparison.Ordinal))
                {
                    //§3.6.1 variables MAY be a top-level variable NAME (a string) or a per-request
                    //object; both are carried verbatim for the engine's template evaluation.
                    variablesJson = property.Value.GetRawText();
                }
                else
                {
                    return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
                }
            }

            //§3.6.1: exactly one of credentialTemplateId / credentialTemplateIndex MUST be present.
            bool hasId = !string.IsNullOrEmpty(templateId);
            bool hasIndex = templateIndex is not null;
            if(hasId == hasIndex)
            {
                return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
            }

            builder.Add(new VcalmIssueRequest
            {
                CredentialTemplateId = templateId,
                CredentialTemplateIndex = templateIndex,
                VariablesJson = variablesJson
            });
        }

        return (builder.ToImmutable(), VcalmParseFailure.None);
    }


    //§3.6.1 credentialTemplates[]: each entry {id?, type, template}. A non-array value or an entry
    //missing the REQUIRED type / template is Malformed.
    private static (ImmutableArray<VcalmCredentialTemplate> Templates, VcalmParseFailure Failure) ParseCredentialTemplates(JsonElement root)
    {
        if(!root.TryGetProperty(VcalmParameterNames.CredentialTemplates, out JsonElement templatesElement))
        {
            return (ImmutableArray<VcalmCredentialTemplate>.Empty, VcalmParseFailure.None);
        }

        if(templatesElement.ValueKind != JsonValueKind.Array)
        {
            return (ImmutableArray<VcalmCredentialTemplate>.Empty, VcalmParseFailure.Malformed);
        }

        ImmutableArray<VcalmCredentialTemplate>.Builder builder = ImmutableArray.CreateBuilder<VcalmCredentialTemplate>();
        foreach(JsonElement entry in templatesElement.EnumerateArray())
        {
            if(entry.ValueKind != JsonValueKind.Object
                || !entry.TryGetProperty(VcalmParameterNames.Type, out JsonElement typeElement)
                || typeElement.ValueKind != JsonValueKind.String
                || !entry.TryGetProperty(VcalmParameterNames.Template, out JsonElement templateElement)
                || templateElement.ValueKind != JsonValueKind.String)
            {
                return (ImmutableArray<VcalmCredentialTemplate>.Empty, VcalmParseFailure.Malformed);
            }

            string? templateId = entry.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement)
                && idElement.ValueKind == JsonValueKind.String
                ? idElement.GetString()
                : null;

            builder.Add(new VcalmCredentialTemplate
            {
                Id = templateId,
                TemplateType = typeElement.GetString()!,
                Template = templateElement.GetString()!
            });
        }

        return (builder.ToImmutable(), VcalmParseFailure.None);
    }


    //§3.6.7 callback: {event{data{exchangeId}}}. A body that is not this nested shape (or omits the
    //exchangeId) is the §3.6.7 400 ("Callback data was not received.").
    private static VcalmCallbackRequest ParseCallback(string requestBody)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmCallbackRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty(VcalmParameterNames.Event, out JsonElement eventElement)
                || eventElement.ValueKind != JsonValueKind.Object
                || !eventElement.TryGetProperty(VcalmParameterNames.Data, out JsonElement dataElement)
                || dataElement.ValueKind != JsonValueKind.Object
                || !dataElement.TryGetProperty(VcalmParameterNames.ExchangeId, out JsonElement exchangeIdElement)
                || exchangeIdElement.ValueKind != JsonValueKind.String)
            {
                return VcalmCallbackRequest.Malformed();
            }

            return new VcalmCallbackRequest
            {
                ExchangeId = exchangeIdElement.GetString()
            };
        }
    }


    private static VcalmIssueCredentialRequest ParseIssue(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmIssueCredentialRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmIssueCredentialRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.2.1 body has exactly credential
            //and options.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.Credential, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                {
                    return VcalmIssueCredentialRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.Credential, out JsonElement credentialElement)
                || credentialElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmIssueCredentialRequest.Malformed();
            }

            //VC-DM 2.0 §4.1: @context MUST be an ordered set — a JSON array; the VC-API issuer interface
            //likewise requires type to be an array. A core member present with the WRONG JSON shape is a
            //malformed credential: the issuer MUST NOT coerce a bare scalar (e.g. a single @context URL or
            //a single type term) into a one-element array and then secure it. Presence — a MISSING member —
            //is caught later as the structural 400; this gate is the wrong-shape case the typed model can no
            //longer see once the converter has normalized the scalar into a collection.
            if(credentialElement.TryGetProperty(VcalmParameterNames.Context, out JsonElement contextShape)
                && contextShape.ValueKind != JsonValueKind.Array)
            {
                return VcalmIssueCredentialRequest.Malformed();
            }

            if(credentialElement.TryGetProperty(VcalmParameterNames.Type, out JsonElement typeShape)
                && typeShape.ValueKind != JsonValueKind.Array)
            {
                return VcalmIssueCredentialRequest.Malformed();
            }

            VcalmParseFailure optionsFailure = TryParseIssueOptions(root, out VcalmIssueOptions parsedOptions);
            if(optionsFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmIssueCredentialRequest.UnknownOption();
            }

            //§3.2.1: the credential is the unsecured VC-DM 2.0 credential intended for issuance. A
            //caller MAY supply existing proofs (the existing-proof case the issuer instance handles
            //per its configuration); record whether the wire carried a proof member.
            bool hasExistingProof = credentialElement.TryGetProperty(VcalmParameterNames.Proof, out _);

            string credentialJson = credentialElement.GetRawText();
            VerifiableCredential? credential = TryDeserialize<VerifiableCredential>(credentialJson, options);
            if(credential is null)
            {
                return VcalmIssueCredentialRequest.Malformed();
            }

            //The §3.2.1 auto-populate source: credential.id when present (the credential model parses
            //it into Id). The converter upcasts a credential carrying a proof to the secured subtype;
            //the issuer instance handles those existing proofs (Proof Sets / Chains / Error) at the
            //endpoint, so the credential is passed through as parsed — including its proof chain.
            return new VcalmIssueCredentialRequest
            {
                Credential = credential,
                CredentialId = credential.Id,
                HasExistingProof = hasExistingProof,
                Options = parsedOptions
            };
        }
    }


    //§3.5.1 body: {verifiableCredential, options{selectivePointers[]}}. STRICT per §2.4: a non-object
    //body, a missing REQUIRED verifiableCredential, or an unrecognized top-level member is Malformed;
    //an unrecognized options member is UnknownOption. The credential MUST carry an embedded proof to be
    //derivable — a credential with no proof deserializes to the open base type and is Malformed (not a
    //base-proofed selective-disclosure credential).
    private static VcalmDeriveCredentialRequest ParseDerive(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmDeriveCredentialRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmDeriveCredentialRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.5.1 body has exactly
            //verifiableCredential and options.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.VerifiableCredential, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                {
                    return VcalmDeriveCredentialRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.VerifiableCredential, out JsonElement credentialElement)
                || credentialElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmDeriveCredentialRequest.Malformed();
            }

            VcalmParseFailure optionsFailure = TryParseSelectivePointers(root, out ImmutableArray<string> selectivePointers);
            if(optionsFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmDeriveCredentialRequest.UnknownOption();
            }

            string credentialJson = credentialElement.GetRawText();
            VerifiableCredential? credential = TryDeserialize<VerifiableCredential>(credentialJson, options);

            //The converter upcasts a credential carrying a proof to the secured subtype. A derivable
            //credential MUST be a DataIntegritySecuredCredential carrying a base proof; one without a
            //proof is not a derivable selective-disclosure credential.
            if(credential is not DataIntegritySecuredCredential secured)
            {
                return VcalmDeriveCredentialRequest.Malformed();
            }

            return new VcalmDeriveCredentialRequest
            {
                Credential = secured,
                SelectivePointers = selectivePointers
            };
        }
    }


    //§3.5.2 body: {presentation, options{type?, cryptosuite?, verificationMethod?, proofPurpose?,
    //created?, challenge?, domain?}}. STRICT per §2.4: a non-object body, a missing REQUIRED
    //presentation, or an unrecognized top-level member is Malformed; an unrecognized options member is
    //UnknownOption.
    private static VcalmCreatePresentationRequest ParseCreatePresentation(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmCreatePresentationRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmCreatePresentationRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.5.2 body has exactly presentation
            //and options.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.Presentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                {
                    return VcalmCreatePresentationRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.Presentation, out JsonElement presentationElement)
                || presentationElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmCreatePresentationRequest.Malformed();
            }

            VcalmParseFailure optionsFailure = TryParseCreatePresentationOptions(
                root, out VcalmCreatePresentationOptions parsedOptions);
            if(optionsFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmCreatePresentationRequest.UnknownOption();
            }

            string presentationJson = presentationElement.GetRawText();
            VerifiablePresentation? presentation = TryDeserialize<VerifiablePresentation>(presentationJson, options);
            if(presentation is null)
            {
                return VcalmCreatePresentationRequest.Malformed();
            }

            return new VcalmCreatePresentationRequest
            {
                Presentation = presentation,
                PresentationId = presentation.Id,
                Options = parsedOptions
            };
        }
    }


    //§3.5.1 options: only selectivePointers (an array of string JSON pointers). §2.4: a non-object
    //options value, a non-array selectivePointers, a non-string item, or any other options member is
    //UnknownOption. An absent options object yields an empty pointer set.
    private static VcalmParseFailure TryParseSelectivePointers(JsonElement root, out ImmutableArray<string> selectivePointers)
    {
        selectivePointers = ImmutableArray<string>.Empty;
        if(!root.TryGetProperty(VcalmParameterNames.Options, out JsonElement optionsElement))
        {
            return VcalmParseFailure.None;
        }

        if(optionsElement.ValueKind != JsonValueKind.Object)
        {
            return VcalmParseFailure.UnknownOption;
        }

        ImmutableArray<string> pointers = ImmutableArray<string>.Empty;
        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            if(string.Equals(property.Name, VcalmParameterNames.SelectivePointers, StringComparison.Ordinal))
            {
                if(property.Value.ValueKind != JsonValueKind.Array)
                {
                    //§3.5.1: "Each item in the selectivePointers array MUST be a string." A non-array
                    //value is an unprocessable option.
                    return VcalmParseFailure.UnknownOption;
                }

                ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
                foreach(JsonElement item in property.Value.EnumerateArray())
                {
                    if(item.ValueKind != JsonValueKind.String)
                    {
                        return VcalmParseFailure.UnknownOption;
                    }

                    builder.Add(item.GetString()!);
                }

                pointers = builder.ToImmutable();
            }
            else
            {
                //§2.4 unknown-option MUST.
                return VcalmParseFailure.UnknownOption;
            }
        }

        selectivePointers = pointers;

        return VcalmParseFailure.None;
    }


    //§3.5.2 options: the members shaping the produced proof. §2.4: a non-object options value or an
    //unrecognized member is UnknownOption. type / cryptosuite / proofPurpose are accepted on the wire
    //(the instance's signing configuration fixes the actual proof type / cryptosuite / purpose) so a
    //caller may name the defaults; challenge / domain / verificationMethod / created are read into the
    //parsed options.
    private static VcalmParseFailure TryParseCreatePresentationOptions(
        JsonElement root, out VcalmCreatePresentationOptions options)
    {
        options = new VcalmCreatePresentationOptions();
        if(!root.TryGetProperty(VcalmParameterNames.Options, out JsonElement optionsElement))
        {
            return VcalmParseFailure.None;
        }

        if(optionsElement.ValueKind != JsonValueKind.Object)
        {
            return VcalmParseFailure.UnknownOption;
        }

        string? challenge = null;
        string? domain = null;
        string? verificationMethod = null;
        string? created = null;

        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            if(string.Equals(property.Name, VcalmParameterNames.Challenge, StringComparison.Ordinal))
            {
                challenge = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Domain, StringComparison.Ordinal))
            {
                domain = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.VerificationMethod, StringComparison.Ordinal))
            {
                verificationMethod = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Created, StringComparison.Ordinal))
            {
                created = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Type, StringComparison.Ordinal)
                || string.Equals(property.Name, VcalmParameterNames.Cryptosuite, StringComparison.Ordinal)
                || string.Equals(property.Name, VcalmParameterNames.ProofPurpose, StringComparison.Ordinal))
            {
                //§3.5.2 type / cryptosuite / proofPurpose are accepted but the instance's signing
                //configuration fixes the actual proof shape; the wire values are not threaded through.
            }
            else
            {
                //§2.4 unknown-option MUST.
                return VcalmParseFailure.UnknownOption;
            }
        }

        options = new VcalmCreatePresentationOptions
        {
            Challenge = challenge,
            Domain = domain,
            VerificationMethod = verificationMethod,
            Created = created
        };

        return VcalmParseFailure.None;
    }


    //§C.3 body: {credentialId, credentialStatus{id,type,statusPurpose,statusListIndex,
    //statusListCredential}, status (boolean), indexAllocator?}. STRICT per §2.4: a non-object body, a
    //missing REQUIRED credentialStatus / status, or an unrecognized top-level member is Malformed; an
    //unrecognized credentialStatus member is UnknownOption.
    private static VcalmUpdateStatusRequest ParseUpdateStatus(string requestBody)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmUpdateStatusRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmUpdateStatusRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §C.3 body has exactly credentialId,
            //credentialStatus, status, and the optional indexAllocator.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.CredentialId, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.CredentialStatus, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Status, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.IndexAllocator, StringComparison.Ordinal))
                {
                    return VcalmUpdateStatusRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.CredentialId, out JsonElement credentialIdElement)
                || credentialIdElement.ValueKind != JsonValueKind.String)
            {
                return VcalmUpdateStatusRequest.Malformed();
            }

            if(!root.TryGetProperty(VcalmParameterNames.CredentialStatus, out JsonElement statusEntryElement)
                || statusEntryElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmUpdateStatusRequest.Malformed();
            }

            if(!root.TryGetProperty(VcalmParameterNames.Status, out JsonElement statusElement)
                || statusElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return VcalmUpdateStatusRequest.Malformed();
            }

            VcalmParseFailure entryFailure = TryParseStatusEntry(
                statusEntryElement, out BitstringStatusListEntry? entry);
            if(entryFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmUpdateStatusRequest.UnknownOption();
            }

            if(entry is null)
            {
                return VcalmUpdateStatusRequest.Malformed();
            }

            string? indexAllocator = root.TryGetProperty(VcalmParameterNames.IndexAllocator, out JsonElement allocatorElement)
                && allocatorElement.ValueKind == JsonValueKind.String
                ? allocatorElement.GetString()
                : null;

            return new VcalmUpdateStatusRequest
            {
                CredentialId = credentialIdElement.GetString(),
                Entry = entry,
                Status = statusElement.ValueKind == JsonValueKind.True,
                IndexAllocator = indexAllocator
            };
        }
    }


    //§C.3 credentialStatus: {id, type, statusPurpose, statusListIndex, statusListCredential}. The
    //typed entry reuses the Core BitstringStatusListEntry. A member the parser does not recognize is
    //the §2.4 unknown-option case; a missing REQUIRED statusPurpose / statusListIndex /
    //statusListCredential leaves the entry null (Malformed).
    private static VcalmParseFailure TryParseStatusEntry(JsonElement element, out BitstringStatusListEntry? entry)
    {
        entry = null;

        string? id = null;
        string? type = null;
        string? statusPurpose = null;
        string? statusListIndexText = null;
        string? statusListCredential = null;

        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(string.Equals(property.Name, VcalmParameterNames.Id, StringComparison.Ordinal))
            {
                id = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Type, StringComparison.Ordinal))
            {
                type = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.StatusPurpose, StringComparison.Ordinal))
            {
                statusPurpose = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.StatusListIndex, StringComparison.Ordinal))
            {
                statusListIndexText = ReadString(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.StatusListCredential, StringComparison.Ordinal))
            {
                statusListCredential = ReadString(property.Value);
            }
            else
            {
                //§2.4 unknown-option MUST.
                return VcalmParseFailure.UnknownOption;
            }
        }

        if(string.IsNullOrEmpty(statusPurpose)
            || string.IsNullOrEmpty(statusListCredential)
            || !int.TryParse(statusListIndexText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int statusListIndex))
        {
            return VcalmParseFailure.Malformed;
        }

        entry = new BitstringStatusListEntry
        {
            Id = id,
            StatusPurpose = statusPurpose,
            StatusListIndex = statusListIndex,
            StatusListCredential = statusListCredential
        };

        //The §C.3 type member is BitstringStatusListEntry; the typed entry carries no type slot (the
        //Core entry IS a BitstringStatusListEntry), so the parsed type is validated, not stored.
        if(!string.IsNullOrEmpty(type)
            && !string.Equals(type, BitstringStatusListConstants.EntryType, StringComparison.Ordinal))
        {
            entry = null;

            return VcalmParseFailure.Malformed;
        }

        return VcalmParseFailure.None;
    }


    //§C.1 body: {statusPurpose, id?, options?}. STRICT per §2.4: a non-object body, a missing
    //REQUIRED statusPurpose, or an unrecognized top-level member is Malformed; an unrecognized
    //options member is UnknownOption.
    private static VcalmCreateStatusListRequest ParseCreateStatusList(string requestBody)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmCreateStatusListRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmCreateStatusListRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §C.1 body has exactly statusPurpose,
            //the optional id, and the optional options.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.StatusPurpose, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Id, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                {
                    return VcalmCreateStatusListRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.StatusPurpose, out JsonElement purposeElement)
                || purposeElement.ValueKind != JsonValueKind.String)
            {
                return VcalmCreateStatusListRequest.Malformed();
            }

            //§C.1 options is an open object on the wire; an options value that is not an object is the
            //§2.4 unknown-option case, but the §C.1 endpoint defines no options members of its own, so
            //any present member is unknown.
            if(root.TryGetProperty(VcalmParameterNames.Options, out JsonElement optionsElement))
            {
                if(optionsElement.ValueKind != JsonValueKind.Object)
                {
                    return VcalmCreateStatusListRequest.UnknownOption();
                }

                foreach(JsonProperty _ in optionsElement.EnumerateObject())
                {
                    return VcalmCreateStatusListRequest.UnknownOption();
                }
            }

            string? id = root.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement)
                && idElement.ValueKind == JsonValueKind.String
                ? idElement.GetString()
                : null;

            return new VcalmCreateStatusListRequest
            {
                StatusPurpose = purposeElement.GetString(),
                Id = id
            };
        }
    }


    private static string? ReadString(JsonElement element) =>
        element.ValueKind == JsonValueKind.String ? element.GetString() : null;


    private static VcalmVerifyCredentialRequest ParseCredential(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmVerifyCredentialRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmVerifyCredentialRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.3.1 body has exactly
            //verifiableCredential and options.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.VerifiableCredential, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                {
                    return VcalmVerifyCredentialRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.VerifiableCredential, out JsonElement credentialElement)
                || credentialElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmVerifyCredentialRequest.Malformed();
            }

            VcalmParseFailure optionsFailure = TryParseOptions(root, out VcalmVerifyOptions parsedOptions);
            if(optionsFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmVerifyCredentialRequest.UnknownOption();
            }

            string credentialJson = credentialElement.GetRawText();

            //An EnvelopedVerifiableCredential is discriminated by its EnvelopedVerifiableCredential
            //type and a data: URL id; otherwise it is an embedded (possibly proofed) credential.
            if(IsEnvelopedCredential(credentialElement))
            {
                EnvelopedVerifiableCredential? enveloped = TryDeserialize<EnvelopedVerifiableCredential>(
                    credentialJson, options);
                if(enveloped is null)
                {
                    return VcalmVerifyCredentialRequest.Malformed();
                }

                return new VcalmVerifyCredentialRequest
                {
                    EnvelopedCredential = enveloped,
                    CredentialJson = credentialJson,
                    Options = parsedOptions
                };
            }

            VerifiableCredential? credential = TryDeserialize<VerifiableCredential>(credentialJson, options);

            //The converter upcasts a credential carrying a proof member to the secured subtype; a
            //credential with no embedded proof deserializes to the open base type, which the verifier
            //treats as a cryptographic error (no proof to verify) rather than a parse failure.
            return new VcalmVerifyCredentialRequest
            {
                DataIntegrityCredential = credential as DataIntegritySecuredCredential
                    ?? AsUnproofedSecured(credential),
                CredentialJson = credentialJson,
                Options = parsedOptions
            };
        }
    }


    private static VcalmVerifyPresentationRequest ParsePresentation(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmVerifyPresentationRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmVerifyPresentationRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.3.2 body carries one of
            //verifiablePresentation / presentation, plus options.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.VerifiablePresentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Presentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                {
                    return VcalmVerifyPresentationRequest.Malformed();
                }
            }

            VcalmParseFailure optionsFailure = TryParseOptions(root, out VcalmVerifyOptions parsedOptions);
            if(optionsFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmVerifyPresentationRequest.UnknownOption();
            }

            //The §3.3.2 unproofed alternative uses the presentation member; the proofed / enveloped
            //alternatives use verifiablePresentation.
            bool hasUnproofed = root.TryGetProperty(VcalmParameterNames.Presentation, out JsonElement unproofedElement)
                && unproofedElement.ValueKind == JsonValueKind.Object;
            bool hasVp = root.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out JsonElement vpElement)
                && vpElement.ValueKind == JsonValueKind.Object;

            if(hasUnproofed && !hasVp)
            {
                string unproofedJson = unproofedElement.GetRawText();
                VerifiablePresentation? presentation = TryDeserialize<VerifiablePresentation>(unproofedJson, options);
                if(presentation is null)
                {
                    return VcalmVerifyPresentationRequest.Malformed();
                }

                return new VcalmVerifyPresentationRequest
                {
                    UnproofedPresentation = presentation,
                    PresentationJson = unproofedJson,
                    Options = parsedOptions
                };
            }

            if(!hasVp)
            {
                return VcalmVerifyPresentationRequest.Malformed();
            }

            string presentationJson = vpElement.GetRawText();

            if(IsEnvelopedPresentation(vpElement))
            {
                EnvelopedVerifiablePresentation? enveloped =
                    TryDeserialize<EnvelopedVerifiablePresentation>(presentationJson, options);
                if(enveloped is null)
                {
                    return VcalmVerifyPresentationRequest.Malformed();
                }

                return new VcalmVerifyPresentationRequest
                {
                    EnvelopedPresentation = enveloped,
                    PresentationJson = presentationJson,
                    Options = parsedOptions
                };
            }

            VerifiablePresentation? parsed = TryDeserialize<VerifiablePresentation>(presentationJson, options);
            if(parsed is null)
            {
                return VcalmVerifyPresentationRequest.Malformed();
            }

            //The converter upcasts a presentation carrying a proof member to the secured subtype. §3.3.2
            //reserves the verifiablePresentation member for the SECURED form — a Data Integrity proof
            //(here) or an EnvelopedVerifiablePresentation (handled above). A verifiablePresentation that
            //carries NEITHER is not a secured presentation: it is a §3.8.1 cryptographic ERROR
            //(verified:false), NOT the unproofed alternative — that form has its own 'presentation'
            //member. (Mirrors a proof-less verifiableCredential, which is likewise an ERROR.)
            if(parsed is DataIntegritySecuredPresentation secured)
            {
                return new VcalmVerifyPresentationRequest
                {
                    DataIntegrityPresentation = secured,
                    PresentationJson = presentationJson,
                    Options = parsedOptions
                };
            }

            return new VcalmVerifyPresentationRequest
            {
                UnsecuredVerifiablePresentation = parsed,
                PresentationJson = presentationJson,
                Options = parsedOptions
            };
        }
    }


    //§2.4: every options member is optional, but a member the verifier does not understand MUST be
    //rejected. Returns UnknownOption when the options object carries an unrecognized member.
    private static VcalmParseFailure TryParseOptions(JsonElement root, out VcalmVerifyOptions options)
    {
        options = new VcalmVerifyOptions();
        if(!root.TryGetProperty(VcalmParameterNames.Options, out JsonElement optionsElement))
        {
            return VcalmParseFailure.None;
        }

        if(optionsElement.ValueKind != JsonValueKind.Object)
        {
            return VcalmParseFailure.UnknownOption;
        }

        bool returnResults = false;
        bool returnProblemDetails = false;
        bool returnCredential = false;
        bool returnPresentation = false;
        string? challenge = null;
        string? domain = null;

        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            if(string.Equals(property.Name, VcalmParameterNames.ReturnResults, StringComparison.Ordinal))
            {
                returnResults = ReadBool(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.ReturnProblemDetails, StringComparison.Ordinal))
            {
                returnProblemDetails = ReadBool(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.ReturnCredential, StringComparison.Ordinal))
            {
                returnCredential = ReadBool(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.ReturnPresentation, StringComparison.Ordinal))
            {
                returnPresentation = ReadBool(property.Value);
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Challenge, StringComparison.Ordinal))
            {
                challenge = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.Domain, StringComparison.Ordinal))
            {
                domain = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
            }
            else
            {
                //§2.4 unknown-option MUST.
                return VcalmParseFailure.UnknownOption;
            }
        }

        options = new VcalmVerifyOptions
        {
            ReturnResults = returnResults,
            ReturnProblemDetails = returnProblemDetails,
            ReturnCredential = returnCredential,
            ReturnPresentation = returnPresentation,
            Challenge = challenge,
            Domain = domain
        };

        return VcalmParseFailure.None;
    }


    //§2.4: every §3.2.1 option is optional, but a member the issuer does not understand MUST be
    //rejected. Returns UnknownOption when the options object carries an unrecognized member.
    private static VcalmParseFailure TryParseIssueOptions(JsonElement root, out VcalmIssueOptions options)
    {
        options = new VcalmIssueOptions();
        if(!root.TryGetProperty(VcalmParameterNames.Options, out JsonElement optionsElement))
        {
            return VcalmParseFailure.None;
        }

        if(optionsElement.ValueKind != JsonValueKind.Object)
        {
            return VcalmParseFailure.UnknownOption;
        }

        string? credentialId = null;
        bool hasCredentialId = false;
        ImmutableArray<string> mandatoryPointers = ImmutableArray<string>.Empty;
        bool hasMandatoryPointers = false;

        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            if(string.Equals(property.Name, VcalmParameterNames.CredentialId, StringComparison.Ordinal))
            {
                hasCredentialId = true;
                credentialId = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null;
            }
            else if(string.Equals(property.Name, VcalmParameterNames.MandatoryPointers, StringComparison.Ordinal))
            {
                if(property.Value.ValueKind != JsonValueKind.Array)
                {
                    //§3.2.1: "Each item in the mandatoryPointers array MUST be a string." A
                    //non-array value is malformed, reported as an unknown/unprocessable option.
                    return VcalmParseFailure.UnknownOption;
                }

                hasMandatoryPointers = true;
                ImmutableArray<string>.Builder pointers = ImmutableArray.CreateBuilder<string>();
                foreach(JsonElement item in property.Value.EnumerateArray())
                {
                    if(item.ValueKind != JsonValueKind.String)
                    {
                        return VcalmParseFailure.UnknownOption;
                    }

                    pointers.Add(item.GetString()!);
                }

                mandatoryPointers = pointers.ToImmutable();
            }
            else
            {
                //§2.4 unknown-option MUST.
                return VcalmParseFailure.UnknownOption;
            }
        }

        options = new VcalmIssueOptions
        {
            CredentialId = credentialId,
            HasCredentialId = hasCredentialId,
            MandatoryPointers = mandatoryPointers,
            HasMandatoryPointers = hasMandatoryPointers
        };

        return VcalmParseFailure.None;
    }


    //§3.6.3 create-exchange: {expires?, variables?, openId?}. All-optional; the empty object is valid.
    //An unrecognized top-level member is the §2.4 strict-parse rejection.
    private static VcalmCreateExchangeRequest ParseCreateExchange(string requestBody)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmCreateExchangeRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmCreateExchangeRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. §3.6.3 carries exactly expires, variables,
            //and openId.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.Expires, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Variables, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.OpenId, StringComparison.Ordinal))
                {
                    return VcalmCreateExchangeRequest.UnknownOption();
                }
            }

            string? expires = root.TryGetProperty(VcalmParameterNames.Expires, out JsonElement expiresElement)
                && expiresElement.ValueKind == JsonValueKind.String
                ? expiresElement.GetString()
                : null;

            string? variablesJson = root.TryGetProperty(VcalmParameterNames.Variables, out JsonElement variablesElement)
                && variablesElement.ValueKind == JsonValueKind.Object
                ? variablesElement.GetRawText()
                : null;

            string? openIdJson = root.TryGetProperty(VcalmParameterNames.OpenId, out JsonElement openIdElement)
                && openIdElement.ValueKind == JsonValueKind.Object
                ? openIdElement.GetRawText()
                : null;

            return new VcalmCreateExchangeRequest
            {
                Expires = expires,
                VariablesJson = variablesJson,
                OpenIdJson = openIdJson
            };
        }
    }


    //§3.6.5 vcapi message: {verifiablePresentation?, verifiablePresentationRequest?, redirectUrl?,
    //referenceId?}. The empty object is the valid initiating message. §3.6: an unrecognized top-level
    //member triggers an error in implementations that do not recognize it (§2.4 strict-parse).
    private static VcalmExchangeMessage ParseExchangeMessage(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VcalmExchangeMessage.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VcalmExchangeMessage.Malformed();
            }

            //§3.6 / §2.4: reject an unrecognized top-level member.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.VerifiablePresentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.VerifiablePresentationRequest, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.RedirectUrl, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.ReferenceId, StringComparison.Ordinal))
                {
                    return VcalmExchangeMessage.Malformed();
                }
            }

            DataIntegritySecuredPresentation? presentation = null;
            string? presentationJson = null;
            if(root.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out JsonElement vpElement)
                && vpElement.ValueKind == JsonValueKind.Object)
            {
                presentationJson = vpElement.GetRawText();
                VerifiablePresentation? parsed = TryDeserialize<VerifiablePresentation>(presentationJson, options);

                //§3.6.5: a presented verifiablePresentation must be a proofed presentation for the
                //engine to verify it against the bound challenge / domain. The converter upcasts a
                //presentation carrying a proof to the secured subtype; one without a proof cannot be
                //verified and is a malformed vcapi message.
                if(parsed is not DataIntegritySecuredPresentation secured)
                {
                    return VcalmExchangeMessage.Malformed();
                }

                presentation = secured;
            }

            VerifiablePresentationRequest? vpr = null;
            if(root.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out JsonElement vprElement)
                && vprElement.ValueKind == JsonValueKind.Object)
            {
                vpr = VcalmPresentationRequestJsonParsing.Parse(vprElement.GetRawText(), options);
                if(vpr.Failure != VcalmParseFailure.None)
                {
                    return vpr.Failure == VcalmParseFailure.UnknownOption
                        ? VcalmExchangeMessage.UnknownOption()
                        : VcalmExchangeMessage.Malformed();
                }
            }

            string? redirectUrl = root.TryGetProperty(VcalmParameterNames.RedirectUrl, out JsonElement redirectElement)
                && redirectElement.ValueKind == JsonValueKind.String
                ? redirectElement.GetString()
                : null;

            string? referenceId = root.TryGetProperty(VcalmParameterNames.ReferenceId, out JsonElement referenceElement)
                && referenceElement.ValueKind == JsonValueKind.String
                ? referenceElement.GetString()
                : null;

            return new VcalmExchangeMessage
            {
                VerifiablePresentation = presentation,
                VerifiablePresentationJson = presentationJson,
                VerifiablePresentationRequest = vpr,
                RedirectUrl = redirectUrl,
                ReferenceId = referenceId
            };
        }
    }


    private static bool ReadBool(JsonElement element) =>
        element.ValueKind == JsonValueKind.True;


    private static bool IsEnvelopedCredential(JsonElement element) =>
        HasType(element, CredentialConstants.EnvelopedVerifiableCredentialType) && HasDataUrlId(element);


    private static bool IsEnvelopedPresentation(JsonElement element) =>
        HasType(element, CredentialConstants.EnvelopedVerifiablePresentationType) && HasDataUrlId(element);


    private static bool HasType(JsonElement element, string expectedType)
    {
        if(!element.TryGetProperty("type", out JsonElement typeElement))
        {
            return false;
        }

        if(typeElement.ValueKind == JsonValueKind.String)
        {
            return string.Equals(typeElement.GetString(), expectedType, StringComparison.Ordinal);
        }

        if(typeElement.ValueKind == JsonValueKind.Array)
        {
            foreach(JsonElement item in typeElement.EnumerateArray())
            {
                if(item.ValueKind == JsonValueKind.String
                    && string.Equals(item.GetString(), expectedType, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }


    private static bool HasDataUrlId(JsonElement element) =>
        element.TryGetProperty("id", out JsonElement idElement)
        && idElement.ValueKind == JsonValueKind.String
        && (idElement.GetString()?.StartsWith("data:", StringComparison.Ordinal) ?? false);


    //An embedded credential with no proof deserializes to the open VerifiableCredential. The
    //verifier needs a DataIntegritySecuredCredential to report "no proof"; clone the parsed members
    //into the secured shape with a null proof chain so the verifier surfaces the proof-absent error.
    private static DataIntegritySecuredCredential? AsUnproofedSecured(VerifiableCredential? credential)
    {
        if(credential is null)
        {
            return null;
        }

        return new DataIntegritySecuredCredential
        {
            Context = credential.Context,
            Id = credential.Id,
            Type = credential.Type,
            Name = credential.Name,
            Description = credential.Description,
            Issuer = credential.Issuer,
            CredentialSubject = credential.CredentialSubject,
            ValidFrom = credential.ValidFrom,
            ValidUntil = credential.ValidUntil,
            CredentialStatus = credential.CredentialStatus,
            CredentialSchema = credential.CredentialSchema,
            RelatedResource = credential.RelatedResource,
            RefreshService = credential.RefreshService,
            TermsOfUse = credential.TermsOfUse,
            Evidence = credential.Evidence,
            AdditionalData = credential.AdditionalData,
            Proof = null
        };
    }


    private static T? TryDeserialize<T>(string json, JsonSerializerOptions options)
    {
        try
        {
            return JsonSerializerExtensions.Deserialize<T>(json, options);
        }
        catch(Exception ex) when(IsParseFailure(ex))
        {
            return default;
        }
    }


    //The deserialization-failure exception family for an untrusted request body, matching the
    //Verifiable.Json convention (cf. the SSF / AuthZen / ProtectedResource parsers). A hand-written
    //W3C VC / VP / proof converter binds members with JsonElement.GetString() / Utf8JsonReader.GetString()
    //and friends, which raise InvalidOperationException / FormatException — not only JsonException — on a
    //wrong-typed value. §2.4 makes every such body MALFORMED and §3.8 requires sanitizing the error
    //rather than leaking it as a 500, so the seam treats the whole family as "not parseable" and the
    //endpoint maps it to a 400; relying on System.Text.Json to re-wrap converter throws as JsonException
    //is an implementation detail this makes explicit.
    private static bool IsParseFailure(Exception ex) =>
        ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or NotSupportedException;
}
