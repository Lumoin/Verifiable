using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.StatusLists;
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
    /// <c>POST /credentials/status</c> body. STJ-free of <see cref="JsonSerializerOptions"/> dependencies —
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
    /// Builds a <see cref="ParseVcalmPresentationSchemaDelegate"/> for a step's §3.6.1
    /// <c>presentationSchema</c> envelope: <c>{type, jsonSchema?}</c> with a REQUIRED string
    /// <c>type</c>, where the JSON Schema mechanism carries the inline <c>jsonSchema</c> object
    /// whose raw text rides through for the validator. A non-object envelope or a missing
    /// <c>type</c> parses to <see langword="null"/> (the participate endpoint refuses fail-closed).
    /// </summary>
    public static ParseVcalmPresentationSchemaDelegate CreatePresentationSchemaParser() =>
        presentationSchemaJson => ParsePresentationSchema(presentationSchemaJson);


    //§3.6.1 presentationSchema: {type, jsonSchema?}. The alternate-mechanism arm admits additional
    //members beyond this specification's scope, so unknown members are not rejected here; the
    //mechanism the type selects interprets its own payload.
    private static VcalmPresentationSchema? ParsePresentationSchema(string presentationSchemaJson)
    {
        ArgumentNullException.ThrowIfNull(presentationSchemaJson);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(presentationSchemaJson);
        }
        catch(JsonException)
        {
            return null;
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("type", out JsonElement typeElement)
                || typeElement.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            string? schemaJson = null;
            if(root.TryGetProperty("jsonSchema", out JsonElement schemaElement)
                && schemaElement.ValueKind == JsonValueKind.Object)
            {
                schemaJson = schemaElement.GetRawText();
            }

            return new VcalmPresentationSchema
            {
                Type = typeElement.GetString()!,
                SchemaJson = schemaJson
            };
        }
    }


    /// <summary>
    /// Builds the <see cref="FindVcalmJsonMemberDelegate"/> the §3.6 workflow engine reads decoded member names through:
    /// a <see cref="Utf8JsonReader"/> pass over the whole object that reads each top-level member name as the string its
    /// escapes decode to and skips every value it passes over without materializing it.
    /// </summary>
    /// <returns>The member lookup.</returns>
    public static FindVcalmJsonMemberDelegate CreateMemberFinder() => FindTopLevelMember;


    /// <summary>
    /// Answers whether <paramref name="jsonObject"/> carries a top-level member whose decoded name is
    /// <paramref name="memberName"/>, the lookup <see cref="CreateMemberFinder"/> returns. The object is read to its end
    /// before it is answered for. Every top-level member name is read with <see cref="Utf8JsonReader.GetString"/>, which
    /// throws <see cref="InvalidOperationException"/> for a name whose escapes spell no Unicode string, such as an
    /// unpaired surrogate, or whose bytes are not UTF-8, so such a name makes the object
    /// <see cref="VcalmJsonMemberLookup.Unreadable"/> whichever name it would have been read as elsewhere; so does input that
    /// is not one well-formed JSON object and a second top-level member of the looked-up name. A found value is located
    /// from its first byte to the byte after its last, so an object or array value spans its closing bracket.
    /// </summary>
    /// <param name="jsonObject">The UTF-8 JSON text of one object.</param>
    /// <param name="memberName">The member name looked for.</param>
    /// <param name="valueRange">The byte range of the member's value when it is found; the default range otherwise.</param>
    /// <returns>Whether the object carries the member, lacks it, or cannot be read as one object whose members it could name.</returns>
    private static VcalmJsonMemberLookup FindTopLevelMember(ReadOnlySpan<byte> jsonObject, string memberName, out Range valueRange)
    {
        valueRange = default;
        Utf8JsonReader reader = new(jsonObject);
        try
        {
            if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return VcalmJsonMemberLookup.Unreadable;
            }

            bool isFound = false;
            Range foundRange = default;

            //The reader is over the whole input, so it throws where the input ends inside the object rather than
            //reporting the end: every read here lands on a token of the object or throws.
            while(reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                bool isMatch = string.Equals(reader.GetString(), memberName, StringComparison.Ordinal);
                _ = reader.Read();
                int valueStart = checked((int)reader.TokenStartIndex);
                reader.Skip();
                if(isMatch)
                {
                    if(isFound)
                    {
                        return VcalmJsonMemberLookup.Unreadable;
                    }

                    isFound = true;
                    foundRange = new Range(valueStart, checked((int)reader.BytesConsumed));
                }
            }

            //The loop ends on the object's closing brace. Reading past it finds the end of the input, and makes the
            //reader throw when anything but whitespace follows the object.
            _ = reader.Read();
            valueRange = foundRange;

            return isFound ? VcalmJsonMemberLookup.Found : VcalmJsonMemberLookup.Absent;
        }
        catch(Exception exception) when(exception is JsonException or InvalidOperationException)
        {
            return VcalmJsonMemberLookup.Unreadable;
        }
    }


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
            //and the optional referenceId. A member name repeated (RFC 8259 §4 leaves the resolution of
            //duplicate names to the application) is refused the same way rather than resolved to
            //whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.Url, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Purpose, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.ReferenceId, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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


    /// <summary>
    /// §3.6.1 create-workflow: <c>{id?, initialStep (REQUIRED), steps (REQUIRED), credentialTemplates?,
    /// controller?, authorization?}</c>. STRICT per §2.4: a non-object body, a missing REQUIRED
    /// <c>initialStep</c> / <c>steps</c>, an unrecognized top-level member, or a recognized member
    /// present with a value of the wrong kind (<c>id</c> / <c>controller</c> both <c>[string]</c>) is
    /// the strict-parse rejection (<see cref="VcalmParseFailure.Malformed"/> /
    /// <see cref="VcalmParseFailure.UnknownOption"/>); <c>authorization</c>'s own <c>{oauth2?:
    /// {issuerConfigUrl}}</c> shape is enforced the same way by <see cref="ParseWorkflowAuthorization"/>.
    /// The §3.6.1 step-graph structural MUSTs are enforced separately by
    /// <see cref="Verifiable.Vcalm.VcalmWorkflowValidation"/>.
    /// </summary>
    /// <param name="requestBody">The create-workflow request body JSON text.</param>
    /// <returns>The parsed workflow configuration, or a strict-parse rejection.</returns>
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

            //§2.4: reject an unrecognized top-level member, and a member name repeated (RFC 8259 §4
            //leaves the resolution of duplicate names to the application) rather than resolved to
            //whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.Id, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.InitialStep, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Steps, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.CredentialTemplates, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Controller, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Authorization, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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

            //§3.6.1 id / controller are both [string]; a present member of any other kind is refused
            //rather than silently treated as absent.
            string? id = null;
            if(root.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement) && !TryReadString(idElement, out id))
            {
                return VcalmWorkflowConfiguration.Malformed();
            }

            string? controller = null;
            if(root.TryGetProperty(VcalmParameterNames.Controller, out JsonElement controllerElement) && !TryReadString(controllerElement, out controller))
            {
                return VcalmWorkflowConfiguration.Malformed();
            }

            VcalmWorkflowAuthorization? authorization = null;
            if(root.TryGetProperty(VcalmParameterNames.Authorization, out JsonElement authorizationElement))
            {
                (authorization, VcalmParseFailure authorizationFailure) = ParseWorkflowAuthorization(authorizationElement);
                if(authorizationFailure != VcalmParseFailure.None)
                {
                    return authorizationFailure == VcalmParseFailure.UnknownOption
                        ? VcalmWorkflowConfiguration.UnknownOption()
                        : VcalmWorkflowConfiguration.Malformed();
                }
            }

            return new VcalmWorkflowConfiguration
            {
                Id = id,
                InitialStep = initialStepElement.GetString()!,
                Steps = steps.ToImmutable(),
                CredentialTemplates = templates,
                Controller = controller,
                Authorization = authorization
            };
        }
    }


    /// <summary>
    /// §3.6.1 <c>authorization</c>: <c>{oauth2?: {issuerConfigUrl}}</c>. STRICT per §2.4: a non-object
    /// <c>authorization</c> or <c>oauth2</c> value, or an <c>issuerConfigUrl</c> that is not an absolute
    /// <c>https</c> URL with no userinfo, query or fragment component
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>: the issuer
    /// identifier "MUST be a URL that uses the 'https' scheme and has no query or fragment
    /// components"; <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 §3.2.1</see>
    /// deprecates userinfo in a URL), is <see cref="VcalmParseFailure.Malformed"/> — it fits neither
    /// form the specification names. A member of <c>authorization</c> other than <c>oauth2</c>, a member
    /// of <c>oauth2</c> other than <c>issuerConfigUrl</c>, or either object's member name repeated, is
    /// <see cref="VcalmParseFailure.UnknownOption"/> per
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM 1.0 §2.4</see> ("Implementations MUST
    /// throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process").
    /// </summary>
    /// <param name="authorizationElement">The <c>authorization</c> member's value.</param>
    /// <returns>The parsed authorization and <see cref="VcalmParseFailure.None"/> on success, or a
    /// strict-parse rejection with a <see langword="null"/> authorization.</returns>
    private static (VcalmWorkflowAuthorization? Authorization, VcalmParseFailure Failure) ParseWorkflowAuthorization(
        JsonElement authorizationElement)
    {
        if(authorizationElement.ValueKind != JsonValueKind.Object)
        {
            return (null, VcalmParseFailure.Malformed);
        }

        VcalmOAuth2Authorization? oauth2 = null;
        HashSet<string> seenAuthorizationMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty authorizationProperty in authorizationElement.EnumerateObject())
        {
            if(!string.Equals(authorizationProperty.Name, VcalmParameterNames.OAuth2, StringComparison.Ordinal)
                || !seenAuthorizationMemberNames.Add(authorizationProperty.Name))
            {
                return (null, VcalmParseFailure.UnknownOption);
            }

            if(authorizationProperty.Value.ValueKind != JsonValueKind.Object)
            {
                return (null, VcalmParseFailure.Malformed);
            }

            Uri? issuerConfigUrl = null;
            HashSet<string> seenOAuth2MemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty oauth2Property in authorizationProperty.Value.EnumerateObject())
            {
                if(!string.Equals(oauth2Property.Name, VcalmParameterNames.IssuerConfigUrl, StringComparison.Ordinal)
                    || !seenOAuth2MemberNames.Add(oauth2Property.Name))
                {
                    return (null, VcalmParseFailure.UnknownOption);
                }

                if(!TryReadString(oauth2Property.Value, out string? issuerConfigUrlText)
                    || !Uri.TryCreate(issuerConfigUrlText, UriKind.Absolute, out issuerConfigUrl)
                    || !string.Equals(issuerConfigUrl.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
                    || !string.IsNullOrEmpty(issuerConfigUrl.UserInfo)
                    || !string.IsNullOrEmpty(issuerConfigUrl.Query)
                    || !string.IsNullOrEmpty(issuerConfigUrl.Fragment))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
            }

            if(issuerConfigUrl is null)
            {
                return (null, VcalmParseFailure.Malformed);
            }

            oauth2 = new VcalmOAuth2Authorization { IssuerConfigUrl = issuerConfigUrl };
        }

        return (new VcalmWorkflowAuthorization { OAuth2 = oauth2 }, VcalmParseFailure.None);
    }


    /// <summary>
    /// §3.6.1 step data: <c>{createChallenge?, verifiablePresentationRequest?, verifiablePresentation?,
    /// redirectUrl?, callback{url}?, issueRequests[]?, presentationSchema?, nextStep?, openId?}</c>. An
    /// unrecognized member, or a recognized member present with a value of the wrong kind, is the §2.4
    /// strict-parse rejection. §3.6.1 <c>presentationSchema</c> is "Either A JSON Schema describing the
    /// validation to be performed on the presentation. It MUST be an object of the following form: type
    /// [string] The value MUST be JsonSchema. jsonSchema [object] an object", "or An alternate
    /// presentation schema format … It MUST be an object of the following form: type [string]". An
    /// envelope naming <c>JsonSchema</c> with no object <c>jsonSchema</c> fits neither alternative's
    /// form, so it is data this parser does not know how to process
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>: "Implementations MUST throw an
    /// error if an endpoint receives data … that it does not understand or know how to process"). The
    /// <c>stepTemplate</c> alternative (a jsonata step template) is modeled-but-deferred: a step
    /// carrying it is not the literal step-data shape this engine drives, so it is rejected as
    /// <see cref="VcalmParseFailure.Malformed"/> rather than silently accepted.
    /// </summary>
    /// <param name="element">One step's JSON object.</param>
    /// <returns>The parsed step, or a strict-parse rejection.</returns>
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

        //A step member name repeated (RFC 8259 §4 leaves the resolution of duplicate names to the
        //application) is refused rather than resolved to whichever occurrence a per-name read would
        //find, the same strictness this loop already applies to a wrong-kind or unrecognized member.
        HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(!seenMemberNames.Add(property.Name))
            {
                return (null, VcalmParseFailure.Malformed);
            }

            if(string.Equals(property.Name, VcalmParameterNames.CreateChallenge, StringComparison.Ordinal))
            {
                if(!TryReadBool(property.Value, out createChallenge))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
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
                if(!TryReadObjectJson(property.Value, out vpJson))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
            }
            else if(string.Equals(property.Name, VcalmParameterNames.RedirectUrl, StringComparison.Ordinal))
            {
                if(!TryReadString(property.Value, out redirectUrl))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
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
                if(!TryReadString(property.Value, out nextStep))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
            }
            else if(string.Equals(property.Name, VcalmParameterNames.PresentationSchema, StringComparison.Ordinal))
            {
                if(!TryReadObjectJson(property.Value, out presentationSchemaJson))
                {
                    return (null, VcalmParseFailure.Malformed);
                }

                //§3.6.1's two presentationSchema alternatives are discriminated by the literal type
                //value: "JsonSchema" selects the form whose own words name the object jsonSchema; any
                //other type string selects the alternate-mechanism form, whose own words name only its
                //type. An envelope naming JsonSchema with no object jsonSchema fits neither alternative's
                //form, so §2.4 (A919-920) refuses it as data this parser does not know how to process.
                //Mechanism REGISTRATION is not checked here — registries change under traffic — only
                //this fixed shape.
                VcalmPresentationSchema? parsedPresentationSchema = ParsePresentationSchema(presentationSchemaJson);
                if(parsedPresentationSchema is null
                    || (string.Equals(parsedPresentationSchema.Type, VcalmSchemaValidatorRegistry.JsonSchemaType, StringComparison.Ordinal)
                        && parsedPresentationSchema.SchemaJson is null))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
            }
            else if(string.Equals(property.Name, VcalmParameterNames.OpenId, StringComparison.Ordinal))
            {
                if(!TryReadObjectJson(property.Value, out openIdJson))
                {
                    return (null, VcalmParseFailure.Malformed);
                }
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

            //An entry member name repeated (RFC 8259 §4) is refused the same way this loop already
            //refuses an unrecognized member, rather than resolved to whichever occurrence a per-name
            //read would find.
            HashSet<string> seenEntryMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in entry.EnumerateObject())
            {
                if(!seenEntryMemberNames.Add(property.Name))
                {
                    return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
                }

                if(string.Equals(property.Name, VcalmParameterNames.CredentialTemplateId, StringComparison.Ordinal))
                {
                    //§3.6.1 credentialTemplateId [string]: a present member of any other kind is data
                    //this engine does not know how to process, not a silently-dropped id.
                    if(!TryReadString(property.Value, out templateId))
                    {
                        return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
                    }
                }
                else if(string.Equals(property.Name, VcalmParameterNames.CredentialTemplateIndex, StringComparison.Ordinal))
                {
                    //§3.6.1 credentialTemplateIndex [integer]: a present member that is not an integer
                    //number is refused rather than silently leaving the index unset.
                    if(property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt32(out int index))
                    {
                        return (ImmutableArray<VcalmIssueRequest>.Empty, VcalmParseFailure.Malformed);
                    }

                    templateIndex = index;
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

            //§3.6.1 credentialTemplates[].id [string]: a present member of any other kind is refused
            //rather than silently stored with no id.
            string? templateId = null;
            if(entry.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement) && !TryReadString(idElement, out templateId))
            {
                return (ImmutableArray<VcalmCredentialTemplate>.Empty, VcalmParseFailure.Malformed);
            }

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
            //and options. A member name repeated (RFC 8259 §4) is refused the same way rather than
            //resolved to whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.Credential, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
                {
                    return VcalmIssueCredentialRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.Credential, out JsonElement credentialElement)
                || credentialElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmIssueCredentialRequest.Malformed();
            }

            //VC-DM 2.0 §4.3: @context MUST be an ordered set — a JSON array; the VC-API issuer interface
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
            //verifiableCredential and options. A member name repeated (RFC 8259 §4) is refused the same
            //way rather than resolved to whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.VerifiableCredential, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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


    /// <summary>
    /// Reads the <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> body
    /// <c>{presentation, options{type?, cryptosuite?, verificationMethod?, proofPurpose?, created?, challenge?,
    /// domain?}}</c>. STRICT per <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>: a non-object body, a
    /// missing REQUIRED <c>presentation</c>, or an unrecognized or repeated top-level member is
    /// <see cref="VcalmParseFailure.Malformed"/>; an options member or value the holder cannot process is
    /// <see cref="VcalmParseFailure.UnknownOption"/>. A <c>proof</c> member on the presentation, of any JSON kind, is
    /// recorded on <see cref="VcalmCreatePresentationRequest.HasProofMember"/> for the endpoint to refuse.
    /// </summary>
    /// <param name="requestBody">The UTF-8-decoded request body.</param>
    /// <param name="options">The serializer options the presentation is read with.</param>
    /// <returns>The parsed request, or a request carrying its parse failure.</returns>
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
            //and options. A member name repeated (RFC 8259 §4) is refused the same way rather than
            //resolved to whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.Presentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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

            //§3.5.2: "The document MAY include an embedded proof." This holder processes none, so the
            //presence of a proof member is recorded from the raw JSON: the presentation reader drops a
            //JSON null member, which the typed presentation then cannot show.
            bool hasProofMember = presentationElement.TryGetProperty(VcalmParameterNames.Proof, out _);

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
                Options = parsedOptions,
                HasProofMember = hasProofMember
            };
        }
    }


    /// <summary>
    /// Reads the <see href="https://www.w3.org/TR/vcalm-1.0/#derive-credential">§3.5.1</see> <c>options</c> object,
    /// whose only member is <c>selectivePointers</c>: "An array of JSON pointers specifying the selectively disclosed
    /// information. Each item in the selectivePointers array MUST be a string."
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>: a non-object options value, a non-array
    /// <c>selectivePointers</c>, an item that is not a readable string (<see cref="TryReadString"/>), a repeated member
    /// or any other options member is <see cref="VcalmParseFailure.UnknownOption"/>. An absent options object yields an
    /// empty pointer set. The JSON pointer grammar of each item is checked by the library, not here, so a replaced parse
    /// seam cannot skip it.
    /// </summary>
    /// <param name="root">The derive request's top-level JSON object.</param>
    /// <param name="selectivePointers">The pointer strings; valid only when the result is <see cref="VcalmParseFailure.None"/>.</param>
    /// <returns><see cref="VcalmParseFailure.None"/> when the options object is absent or well formed; otherwise <see cref="VcalmParseFailure.UnknownOption"/>.</returns>
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
        HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            //A member name repeated (RFC 8259 §4) is refused the same way this loop already refuses an
            //unrecognized member, rather than resolved to whichever occurrence a later lookup would find.
            if(!seenMemberNames.Add(property.Name))
            {
                return VcalmParseFailure.UnknownOption;
            }

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
                    //An item of another kind, or a string whose escapes spell no Unicode string, is an option
                    //value this holder cannot process.
                    if(!TryReadString(item, out string? pointer))
                    {
                        return VcalmParseFailure.UnknownOption;
                    }

                    builder.Add(pointer);
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


    /// <summary>
    /// Reads the <see href="https://www.w3.org/TR/vcalm-1.0/#create-presentation">§3.5.2</see> <c>options</c> object,
    /// the members shaping the produced proof: <c>type</c>, <c>cryptosuite</c>, <c>verificationMethod</c>,
    /// <c>proofPurpose</c>, <c>created</c>, <c>challenge</c> and <c>domain</c>, each named "[string]" by §3.5.2.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>: "Implementations MUST throw an error if an
    /// endpoint receives data, options, or option values that it does not understand or know how to process." So a
    /// non-object options value, an unrecognized or repeated member, or a member whose value is not a readable string
    /// (<see cref="TryReadString"/>, an explicit JSON <c>null</c> included) is <see cref="VcalmParseFailure.UnknownOption"/>.
    /// Every value is carried into the parsed options as read; whether the instance can produce it is the endpoint's
    /// check against its own signing configuration.
    /// </summary>
    /// <param name="root">The create-presentation request's top-level JSON object.</param>
    /// <param name="options">The parsed options; valid only when the result is <see cref="VcalmParseFailure.None"/>.</param>
    /// <returns><see cref="VcalmParseFailure.None"/> when the options object is absent or every present member is recognized and a readable string; otherwise <see cref="VcalmParseFailure.UnknownOption"/>.</returns>
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
        string? type = null;
        string? cryptosuite = null;
        string? proofPurpose = null;

        HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            //A member name repeated (RFC 8259 §4) is refused the same way this loop already refuses an
            //unrecognized member, rather than resolved to whichever occurrence a later lookup would find.
            if(!seenMemberNames.Add(property.Name))
            {
                return VcalmParseFailure.UnknownOption;
            }

            //§3.5.2 names every option "[string]": a value of another kind, or a string whose escapes
            //spell no Unicode string, is an option value this holder cannot process, never read as absent.
            //An unrecognized member is the §2.4 unknown-option MUST.
            string name = property.Name;
            bool isReadable = name switch
            {
                _ when string.Equals(name, VcalmParameterNames.Challenge, StringComparison.Ordinal) => TryReadString(property.Value, out challenge),
                _ when string.Equals(name, VcalmParameterNames.Domain, StringComparison.Ordinal) => TryReadString(property.Value, out domain),
                _ when string.Equals(name, VcalmParameterNames.VerificationMethod, StringComparison.Ordinal) => TryReadString(property.Value, out verificationMethod),
                _ when string.Equals(name, VcalmParameterNames.Created, StringComparison.Ordinal) => TryReadString(property.Value, out created),
                _ when string.Equals(name, VcalmParameterNames.Type, StringComparison.Ordinal) => TryReadString(property.Value, out type),
                _ when string.Equals(name, VcalmParameterNames.Cryptosuite, StringComparison.Ordinal) => TryReadString(property.Value, out cryptosuite),
                _ when string.Equals(name, VcalmParameterNames.ProofPurpose, StringComparison.Ordinal) => TryReadString(property.Value, out proofPurpose),
                _ => false
            };

            if(!isReadable)
            {
                return VcalmParseFailure.UnknownOption;
            }
        }

        options = new VcalmCreatePresentationOptions
        {
            Challenge = challenge,
            Domain = domain,
            VerificationMethod = verificationMethod,
            Created = created,
            Type = type,
            Cryptosuite = cryptosuite,
            ProofPurpose = proofPurpose
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
            //credentialStatus, status, and the optional indexAllocator. A member name repeated
            //(RFC 8259 §4) is refused the same way rather than resolved to whichever occurrence a later
            //lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.CredentialId, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.CredentialStatus, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Status, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.IndexAllocator, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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

        HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty property in element.EnumerateObject())
        {
            //A member name repeated (RFC 8259 §4) is refused the same way this loop already refuses an
            //unrecognized member, rather than resolved to whichever occurrence a later lookup would find.
            if(!seenMemberNames.Add(property.Name))
            {
                return VcalmParseFailure.UnknownOption;
            }

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
            //the optional id, and the optional options. A member name repeated (RFC 8259 §4) is refused
            //the same way rather than resolved to whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.StatusPurpose, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Id, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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


    //A permissive string read for a member this endpoint does not strictly type-check: a wrong-kind or
    //unreadable (RFC 8259 §8.2 unpaired-surrogate) value reads as absent rather than throwing.
    private static string? ReadString(JsonElement element)
    {
        if(element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        try
        {
            return element.GetString();
        }
        catch(InvalidOperationException)
        {
            return null;
        }
    }


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
            //verifiableCredential and options. A member name repeated (RFC 8259 §4) is refused the same
            //way rather than resolved to whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.VerifiableCredential, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
                {
                    return VcalmVerifyCredentialRequest.Malformed();
                }
            }

            if(!root.TryGetProperty(VcalmParameterNames.VerifiableCredential, out JsonElement credentialElement)
                || credentialElement.ValueKind != JsonValueKind.Object)
            {
                return VcalmVerifyCredentialRequest.Malformed();
            }

            VcalmParseFailure optionsFailure = TryParseOptions(root, VcalmVerifyOptionsSubject.Credential, out VcalmVerifyOptions parsedOptions);
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
            //verifiablePresentation / presentation, plus options. A member name repeated (RFC 8259 §4)
            //is refused the same way rather than resolved to whichever occurrence a later lookup would
            //find — including a second copy of the SAME member name, which the presence checks below
            //cannot see on their own.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.VerifiablePresentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Presentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Options, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
                {
                    return VcalmVerifyPresentationRequest.Malformed();
                }
            }

            VcalmParseFailure optionsFailure = TryParseOptions(root, VcalmVerifyOptionsSubject.Presentation, out VcalmVerifyOptions parsedOptions);
            if(optionsFailure == VcalmParseFailure.UnknownOption)
            {
                return VcalmVerifyPresentationRequest.UnknownOption();
            }

            //The §3.3.2 unproofed alternative uses the presentation member; the proofed / enveloped
            //alternatives use verifiablePresentation. §3.3.2 exposes exactly one of the two per request:
            //a body naming both, or naming either with a value that is not the object each alternative's
            //own form requires, is data this endpoint does not know how to process (§2.4, A919-920)
            //rather than a member silently dropped in favour of the other.
            bool isUnproofedPresent = root.TryGetProperty(VcalmParameterNames.Presentation, out JsonElement unproofedElement);
            bool isVpPresent = root.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out JsonElement vpElement);

            if(isUnproofedPresent && isVpPresent)
            {
                return VcalmVerifyPresentationRequest.Malformed();
            }

            if(isUnproofedPresent)
            {
                if(unproofedElement.ValueKind != JsonValueKind.Object)
                {
                    return VcalmVerifyPresentationRequest.Malformed();
                }

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

            if(!isVpPresent || vpElement.ValueKind != JsonValueKind.Object)
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


    /// <summary>
    /// Which VCALM 1.0 verify endpoint's <c>options</c> object <see cref="TryParseOptions"/> is reading, so the
    /// reader accepts only the members that endpoint's own request schema names and refuses a member belonging to
    /// the OTHER endpoint's schema the same way it refuses one no schema names at all.
    /// </summary>
    private enum VcalmVerifyOptionsSubject
    {
        /// <summary>
        /// §3.3.1 <c>/credentials/verify</c>: its own <c>returnResults</c>, <c>returnProblemDetails</c> and
        /// <c>returnCredential</c>. Not <c>challenge</c>, <c>domain</c> or <c>returnPresentation</c>.
        /// </summary>
        Credential,

        /// <summary>
        /// §3.3.2 <c>/presentations/verify</c>: its own <c>challenge</c>, <c>domain</c> and
        /// <c>returnPresentation</c>, plus §3.3.1's <c>returnResults</c> / <c>returnProblemDetails</c>, which this
        /// implementation also accepts here as the extension VCALM A1597 admits ("Implementations MAY extend this
        /// object with additional properties to control verification behavior"). Not <c>returnCredential</c>.
        /// </summary>
        Presentation
    }


    /// <summary>
    /// §2.4: every options member is optional, but a member the calling endpoint does not recognize, or whose
    /// value is not the kind that member's own schema names, MUST be rejected:
    /// "Implementations MUST throw an error if an endpoint receives data, options, or option values that it does
    /// not understand or know how to process." <paramref name="subject"/> selects which of the §3.3.1 / §3.3.2
    /// options schemas <paramref name="root"/>'s <c>options</c> member is read against, since <c>returnCredential</c>
    /// is §3.3.1-only and <c>challenge</c> / <c>domain</c> / <c>returnPresentation</c> are §3.3.2-only, while
    /// <c>returnResults</c> / <c>returnProblemDetails</c> are §3.3.1's own options that this implementation also
    /// accepts on §3.3.2 as the extension VCALM A1597 admits ("Implementations MAY extend this object with
    /// additional properties to control verification behavior";
    /// <see cref="Verifiable.Vcalm.VcalmResponseWriter"/> reads both from either response-writing path).
    /// </summary>
    /// <param name="root">The verify request's top-level JSON object.</param>
    /// <param name="subject">Which endpoint's own options schema <paramref name="root"/>'s <c>options</c> member is read against.</param>
    /// <param name="options">The parsed options; valid only when the result is <see cref="VcalmParseFailure.None"/>.</param>
    /// <returns><see cref="VcalmParseFailure.None"/> when every present member is recognized and of its schema's kind; otherwise <see cref="VcalmParseFailure.UnknownOption"/>.</returns>
    private static VcalmParseFailure TryParseOptions(JsonElement root, VcalmVerifyOptionsSubject subject, out VcalmVerifyOptions options)
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

        HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            //A member name repeated (RFC 8259 §4) is refused the same way this loop already refuses an
            //unrecognized member, rather than resolved to whichever occurrence a per-name read would find.
            if(!seenMemberNames.Add(property.Name))
            {
                return VcalmParseFailure.UnknownOption;
            }

            if(string.Equals(property.Name, VcalmParameterNames.ReturnResults, StringComparison.Ordinal))
            {
                if(!TryReadBool(property.Value, out returnResults))
                {
                    return VcalmParseFailure.UnknownOption;
                }
            }
            else if(string.Equals(property.Name, VcalmParameterNames.ReturnProblemDetails, StringComparison.Ordinal))
            {
                if(!TryReadBool(property.Value, out returnProblemDetails))
                {
                    return VcalmParseFailure.UnknownOption;
                }
            }
            else if(subject == VcalmVerifyOptionsSubject.Credential
                && string.Equals(property.Name, VcalmParameterNames.ReturnCredential, StringComparison.Ordinal))
            {
                if(!TryReadBool(property.Value, out returnCredential))
                {
                    return VcalmParseFailure.UnknownOption;
                }
            }
            else if(subject == VcalmVerifyOptionsSubject.Presentation
                && string.Equals(property.Name, VcalmParameterNames.ReturnPresentation, StringComparison.Ordinal))
            {
                if(!TryReadBool(property.Value, out returnPresentation))
                {
                    return VcalmParseFailure.UnknownOption;
                }
            }
            else if(subject == VcalmVerifyOptionsSubject.Presentation
                && string.Equals(property.Name, VcalmParameterNames.Challenge, StringComparison.Ordinal))
            {
                if(!TryReadString(property.Value, out challenge))
                {
                    return VcalmParseFailure.UnknownOption;
                }
            }
            else if(subject == VcalmVerifyOptionsSubject.Presentation
                && string.Equals(property.Name, VcalmParameterNames.Domain, StringComparison.Ordinal))
            {
                if(!TryReadString(property.Value, out domain))
                {
                    return VcalmParseFailure.UnknownOption;
                }
            }
            else
            {
                //§2.4 unknown-option MUST: the member belongs to the OTHER endpoint's own options schema, or no
                //schema recognizes it at all.
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


    /// <summary>
    /// Reads <paramref name="element"/> as a required §2.4 boolean option value: <see langword="true"/> for a JSON
    /// <c>true</c>, <see langword="false"/> for <c>false</c>. A value of any other kind is an option value the
    /// endpoint does not know how to process, so the caller reports its own strict-parse rejection rather than
    /// defaulting the flag.
    /// </summary>
    /// <param name="element">The member's JSON value.</param>
    /// <param name="value">The decoded boolean when <paramref name="element"/> is a JSON boolean; otherwise <see langword="false"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="element"/> is a JSON boolean; otherwise <see langword="false"/>.</returns>
    private static bool TryReadBool(JsonElement element, out bool value)
    {
        value = element.ValueKind == JsonValueKind.True;

        return element.ValueKind is JsonValueKind.True or JsonValueKind.False;
    }


    /// <summary>
    /// Reads <paramref name="element"/> as a required <c>[string]</c>-typed option or member value. A value of any
    /// other kind, including an explicit JSON <c>null</c>, is a value the endpoint does not know how to process, so
    /// the caller reports its own strict-parse rejection rather than silently treating it as absent. A string whose
    /// escapes spell no Unicode string, such as an unpaired surrogate
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 §8.2</see>: "The behavior of
    /// software that receives JSON texts containing such values is unpredictable"), is refused the same way rather
    /// than left to throw past the caller's own rejection.
    /// </summary>
    /// <param name="element">The member's JSON value.</param>
    /// <param name="value">The decoded string when <paramref name="element"/> is a readable JSON string; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="element"/> is a readable JSON string; otherwise <see langword="false"/>.</returns>
    private static bool TryReadString(JsonElement element, [NotNullWhen(true)] out string? value)
    {
        if(element.ValueKind != JsonValueKind.String)
        {
            value = null;

            return false;
        }

        string? read;
        try
        {
            read = element.GetString();
        }
        catch(InvalidOperationException)
        {
            read = null;
        }

        value = read;

        return read is not null;
    }


    /// <summary>
    /// Reads <paramref name="element"/>'s verbatim JSON text as a required <c>[object]</c>-typed member value. A
    /// value of any other kind is a value the endpoint does not know how to process, so the caller reports its own
    /// strict-parse rejection rather than silently treating it as absent.
    /// </summary>
    /// <param name="element">The member's JSON value.</param>
    /// <param name="json">The member's verbatim JSON text when <paramref name="element"/> is a JSON object; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="element"/> is a JSON object; otherwise <see langword="false"/>.</returns>
    private static bool TryReadObjectJson(JsonElement element, [NotNullWhen(true)] out string? json)
    {
        if(element.ValueKind != JsonValueKind.Object)
        {
            json = null;

            return false;
        }

        json = element.GetRawText();

        return true;
    }


    /// <summary>
    /// §2.4: every §3.2.1 option is optional, but a member the issuer does not understand, or whose value is not
    /// the kind §3.2.1 names for it, MUST be rejected. Returns <see cref="VcalmParseFailure.UnknownOption"/> when
    /// the options object carries an unrecognized member or a recognized member of the wrong kind.
    /// </summary>
    /// <param name="root">The issue request's top-level JSON object.</param>
    /// <param name="options">The parsed options; valid only when the result is <see cref="VcalmParseFailure.None"/>.</param>
    /// <returns><see cref="VcalmParseFailure.None"/> when every present member is recognized and of its own kind; otherwise <see cref="VcalmParseFailure.UnknownOption"/>.</returns>
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

        HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
        foreach(JsonProperty property in optionsElement.EnumerateObject())
        {
            //A member name repeated (RFC 8259 §4) is refused the same way this loop already refuses an
            //unrecognized member, rather than resolved to whichever occurrence a per-name read would find.
            if(!seenMemberNames.Add(property.Name))
            {
                return VcalmParseFailure.UnknownOption;
            }

            if(string.Equals(property.Name, VcalmParameterNames.CredentialId, StringComparison.Ordinal))
            {
                //§3.2.1 "credentialId [string]": a URI identifying the issued credential. A value of any
                //other kind, including an explicit JSON null, is an option value this issuer does not
                //know how to process; an empty string is well-formed JSON but names no URI, so it is
                //refused the same way rather than silently treated as though credentialId were absent.
                if(!TryReadString(property.Value, out credentialId) || credentialId.Length == 0)
                {
                    return VcalmParseFailure.UnknownOption;
                }

                hasCredentialId = true;
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
                    //An item of another kind, or a string whose escapes spell no Unicode string, is an option
                    //value this issuer cannot process.
                    if(!TryReadString(item, out string? pointer))
                    {
                        return VcalmParseFailure.UnknownOption;
                    }

                    pointers.Add(pointer);
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
            //and openId. A member name repeated (RFC 8259 §4) is refused the same way rather than
            //resolved to whichever occurrence a later lookup would find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.Expires, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Variables, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.OpenId, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
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


    /// <summary>
    /// Parses the message a client posts to the participate interface
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#participate-in-an-exchange">VCALM §3.6.6</see>), "a
    /// simple JSON object that includes zero or more of the following properties and values"
    /// <c>{verifiablePresentation?, verifiablePresentationRequest?, redirectUrl?, referenceId?}</c>, the empty
    /// object being the initiating message; "Custom properties and values might also be included, but are
    /// expected to trigger errors in implementations that do not recognize them"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#workflows-and-exchanges">VCALM §3.6</see>), and
    /// "Implementations MUST throw an error if an endpoint receives data, options, or option values that it
    /// does not understand or know how to process"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>). An unrecognized or repeated
    /// member, a <c>verifiablePresentation</c> or <c>verifiablePresentationRequest</c> that is not an object,
    /// and a <c>redirectUrl</c> or <c>referenceId</c> that is not a string ("redirectUrl [string]",
    /// "referenceId [string]") each make the message <see cref="VcalmParseFailure.Malformed"/>, never a message
    /// read as if the member were absent.
    /// </summary>
    /// <param name="requestBody">The request body JSON text.</param>
    /// <param name="options">The serializer options the presentation and the presentation request are read with.</param>
    /// <returns>The parsed message, or one carrying its <see cref="VcalmParseFailure"/>.</returns>
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

            //§3.6 / §2.4: reject an unrecognized top-level member. A member name repeated (RFC 8259 §4)
            //is refused the same way rather than resolved to whichever occurrence a later lookup would
            //find.
            HashSet<string> seenMemberNames = new(StringComparer.Ordinal);
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if((!string.Equals(property.Name, VcalmParameterNames.VerifiablePresentation, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.VerifiablePresentationRequest, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.RedirectUrl, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.ReferenceId, StringComparison.Ordinal))
                    || !seenMemberNames.Add(property.Name))
                {
                    return VcalmExchangeMessage.Malformed();
                }
            }

            //§2.4: a present member of a shape this parser cannot process refuses the message rather than
            //reading as absent, which would turn it into the empty initiating message.
            if(!TryReadOptionalMember(root, VcalmParameterNames.VerifiablePresentation, JsonValueKind.Object, out JsonElement? vpElement)
                || !TryReadOptionalMember(root, VcalmParameterNames.VerifiablePresentationRequest, JsonValueKind.Object, out JsonElement? vprElement)
                || !TryReadOptionalMember(root, VcalmParameterNames.RedirectUrl, JsonValueKind.String, out JsonElement? redirectElement)
                || !TryReadOptionalMember(root, VcalmParameterNames.ReferenceId, JsonValueKind.String, out JsonElement? referenceElement))
            {
                return VcalmExchangeMessage.Malformed();
            }

            DataIntegritySecuredPresentation? presentation = null;
            string? presentationJson = null;
            if(vpElement is JsonElement presentationElement)
            {
                presentationJson = presentationElement.GetRawText();
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
            if(vprElement is JsonElement presentationRequestElement)
            {
                vpr = VcalmPresentationRequestJsonParsing.Parse(presentationRequestElement.GetRawText(), options);
                if(vpr.Failure != VcalmParseFailure.None)
                {
                    return vpr.Failure switch
                    {
                        VcalmParseFailure.UnknownOption => VcalmExchangeMessage.UnknownOption(),
                        _ => VcalmExchangeMessage.Malformed()
                    };
                }
            }

            return new VcalmExchangeMessage
            {
                VerifiablePresentation = presentation,
                VerifiablePresentationJson = presentationJson,
                VerifiablePresentationRequest = vpr,
                RedirectUrl = redirectElement?.GetString(),
                ReferenceId = referenceElement?.GetString()
            };
        }
    }


    /// <summary>
    /// Reads an OPTIONAL top-level member of the participate message whose value the message format fixes
    /// to one JSON kind: <c>verifiablePresentation</c> and <c>verifiablePresentationRequest</c> objects,
    /// <c>redirectUrl</c> and <c>referenceId</c> strings. A present value of another kind is not understood,
    /// and "Implementations MUST throw an error if an endpoint receives data, options, or option values that
    /// it does not understand or know how to process"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>), so it is reported rather than
    /// read as absent.
    /// </summary>
    /// <param name="element">The message object carrying the member.</param>
    /// <param name="memberName">The member name.</param>
    /// <param name="expectedKind">The one JSON kind the member's value takes.</param>
    /// <param name="member">The member's value, or <see langword="null"/> when the member is absent.</param>
    /// <returns><see langword="false"/> when the member is present with a value of another kind.</returns>
    private static bool TryReadOptionalMember(JsonElement element, string memberName, JsonValueKind expectedKind, out JsonElement? member)
    {
        member = null;
        if(!element.TryGetProperty(memberName, out JsonElement memberElement))
        {
            return true;
        }

        if(memberElement.ValueKind != expectedKind)
        {
            return false;
        }

        member = memberElement;

        return true;
    }


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
