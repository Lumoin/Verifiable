using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.Vcalm;

namespace Verifiable.Json;

/// <summary>
/// The default <c>System.Text.Json</c> parser for the W3C VCALM 1.0 §3.4 verifiable presentation
/// request (VPR) — the JSON side the <c>Verifiable.Vcalm</c> serialization firewall keeps out of the
/// library. A VPR is the payload a verifier sends a holder inside a §3.6 exchange / §3.7 interaction;
/// the parser materializes the neutral <see cref="VerifiablePresentationRequest"/> the holder reasons
/// over.
/// </summary>
/// <remarks>
/// The parser is STRICT per §3.4.1 / §2.4: a body that is not a JSON object, omits the REQUIRED
/// <c>query</c> array, carries an empty <c>query</c> array, carries an unrecognized top-level member,
/// or carries a query entry without a string <c>type</c> ("each map MUST define a type property with
/// an associated string value") yields <see cref="VcalmParseFailure.Malformed"/>. The parser never
/// throws to the caller; every rejection is a typed failure. A query entry whose <c>type</c> is a
/// well-formed-but-unrecognized string is NOT a failure — the §3.4.1 <c>query</c> array is an open
/// extension point, so such an entry parses into an <see cref="UnknownQuery"/>.
/// </remarks>
public static class VcalmPresentationRequestJsonParsing
{
    /// <summary>
    /// Builds a parser bound to <paramref name="options"/> (the serializer options carrying the
    /// Verifiable DCQL converters), for the §3.4 VPR body. The bound delegate maps a request-body
    /// string to a <see cref="VerifiablePresentationRequest"/>.
    /// </summary>
    /// <param name="options">The serializer options carrying the DCQL query converters.</param>
    /// <returns>A parser over the §3.4 VPR body.</returns>
    public static Func<string, VerifiablePresentationRequest> CreateParser(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return requestBody => Parse(requestBody, options);
    }


    /// <summary>
    /// Parses a §3.4 verifiable presentation request body into the neutral model.
    /// </summary>
    /// <param name="requestBody">The raw §3.4 VPR JSON body.</param>
    /// <param name="options">The serializer options carrying the DCQL query converters.</param>
    /// <returns>The parsed request, or a typed parse failure.</returns>
    public static VerifiablePresentationRequest Parse(string requestBody, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(requestBody);
        ArgumentNullException.ThrowIfNull(options);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestBody);
        }
        catch(JsonException)
        {
            return VerifiablePresentationRequest.Malformed();
        }

        using(doc)
        {
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return VerifiablePresentationRequest.Malformed();
            }

            //§2.4: reject an unrecognized top-level member. The §3.4.1 body has exactly query,
            //the optional domain, and the optional challenge.
            foreach(JsonProperty property in root.EnumerateObject())
            {
                if(!string.Equals(property.Name, VcalmParameterNames.Query, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Domain, StringComparison.Ordinal)
                    && !string.Equals(property.Name, VcalmParameterNames.Challenge, StringComparison.Ordinal))
                {
                    return VerifiablePresentationRequest.Malformed();
                }
            }

            //§3.4.1: query is REQUIRED and MUST be one or more query maps.
            if(!root.TryGetProperty(VcalmParameterNames.Query, out JsonElement queryElement)
                || queryElement.ValueKind != JsonValueKind.Array)
            {
                return VerifiablePresentationRequest.Malformed();
            }

            ImmutableArray<VcalmPresentationQuery>.Builder queries =
                ImmutableArray.CreateBuilder<VcalmPresentationQuery>();
            foreach(JsonElement entry in queryElement.EnumerateArray())
            {
                VcalmPresentationQuery? query = ParseQueryEntry(entry, options, out VcalmParseFailure failure);
                if(query is null)
                {
                    return failure == VcalmParseFailure.UnknownOption
                        ? VerifiablePresentationRequest.UnknownOption()
                        : VerifiablePresentationRequest.Malformed();
                }

                queries.Add(query);
            }

            //§3.4.1: "one or more" — an empty query array does not satisfy the REQUIRED member.
            if(queries.Count == 0)
            {
                return VerifiablePresentationRequest.Malformed();
            }

            string? domain = root.TryGetProperty(VcalmParameterNames.Domain, out JsonElement domainElement)
                && domainElement.ValueKind == JsonValueKind.String
                ? domainElement.GetString()
                : null;

            string? challenge = root.TryGetProperty(VcalmParameterNames.Challenge, out JsonElement challengeElement)
                && challengeElement.ValueKind == JsonValueKind.String
                ? challengeElement.GetString()
                : null;

            return new VerifiablePresentationRequest
            {
                Query = queries.ToImmutable(),
                Domain = domain,
                Challenge = challenge
            };
        }
    }


    //§3.4.1: each query entry MUST be a map with a string type. The type value selects the §3.4.2 /
    //§3.4.3 / §3.4 (DCQL) / §3.4.4 shape; a well-formed but unrecognized type is an open-extension
    //UnknownQuery, not a failure.
    private static VcalmPresentationQuery? ParseQueryEntry(
        JsonElement entry, JsonSerializerOptions options, out VcalmParseFailure failure)
    {
        failure = VcalmParseFailure.None;

        if(entry.ValueKind != JsonValueKind.Object)
        {
            failure = VcalmParseFailure.Malformed;

            return null;
        }

        if(!entry.TryGetProperty(VcalmParameterNames.Type, out JsonElement typeElement)
            || typeElement.ValueKind != JsonValueKind.String)
        {
            //§3.4.1: "each map MUST define a type property with an associated string value."
            failure = VcalmParseFailure.Malformed;

            return null;
        }

        string type = typeElement.GetString()!;
        string? group = entry.TryGetProperty(VcalmParameterNames.Group, out JsonElement groupElement)
            && groupElement.ValueKind == JsonValueKind.String
            ? groupElement.GetString()
            : null;

        if(string.Equals(type, VcalmQueryTypes.QueryByExample, StringComparison.Ordinal))
        {
            return ParseQueryByExample(entry, type, group, out failure);
        }

        if(string.Equals(type, VcalmQueryTypes.DidAuthentication, StringComparison.Ordinal))
        {
            return ParseDidAuthentication(entry, type, group, out failure);
        }

        if(string.Equals(type, VcalmQueryTypes.DigitalCredentialQueryLanguage, StringComparison.Ordinal))
        {
            return ParseDcql(entry, type, group, options, out failure);
        }

        if(string.Equals(type, VcalmQueryTypes.AuthorizationCapabilityQuery, StringComparison.Ordinal))
        {
            return ParseAuthorizationCapability(entry, type, group);
        }

        //§3.4.1 open extension point: a recognized-shape map with an unknown type round-trips.
        return new UnknownQuery
        {
            Type = type,
            Group = group,
            RawJson = entry.GetRawText()
        };
    }


    //§3.4.2: {type, group?, credentialQuery{reason?, example?, acceptedIssuers?,
    //acceptedCryptosuites?, acceptedEnvelopes?}}.
    private static QueryByExampleQuery? ParseQueryByExample(
        JsonElement entry, string type, string? group, out VcalmParseFailure failure)
    {
        failure = VcalmParseFailure.None;

        if(!entry.TryGetProperty(VcalmParameterNames.CredentialQuery, out JsonElement credentialQueryElement)
            || credentialQueryElement.ValueKind != JsonValueKind.Object)
        {
            failure = VcalmParseFailure.Malformed;

            return null;
        }

        string? reason = credentialQueryElement.TryGetProperty(VcalmParameterNames.Reason, out JsonElement reasonElement)
            && reasonElement.ValueKind == JsonValueKind.String
            ? reasonElement.GetString()
            : null;

        QueryByExampleCredential? example = null;
        if(credentialQueryElement.TryGetProperty(VcalmParameterNames.Example, out JsonElement exampleElement)
            && exampleElement.ValueKind == JsonValueKind.Object)
        {
            example = ParseExample(exampleElement);
        }

        ImmutableArray<QueryByExampleAcceptedIssuer> acceptedIssuers = ParseAcceptedIssuers(credentialQueryElement);
        ImmutableArray<string> acceptedCryptosuites = ParseSuiteOrEnvelope(
            credentialQueryElement, VcalmParameterNames.AcceptedCryptosuites, VcalmParameterNames.Cryptosuite);
        ImmutableArray<string> acceptedEnvelopes = ParseSuiteOrEnvelope(
            credentialQueryElement, VcalmParameterNames.AcceptedEnvelopes, VcalmParameterNames.MediaType);

        return new QueryByExampleQuery
        {
            Type = type,
            Group = group,
            CredentialQuery = new QueryByExampleCredentialQuery
            {
                Reason = reason,
                Example = example,
                AcceptedIssuers = acceptedIssuers,
                AcceptedCryptosuites = acceptedCryptosuites,
                AcceptedEnvelopes = acceptedEnvelopes
            }
        };
    }


    //§3.4.2 example: {@context?, type?, credentialSubject?}. Every present field is a §3.4.2
    //"required field"; a subject field value of "" requests the field with no value expectation.
    private static QueryByExampleCredential ParseExample(JsonElement exampleElement)
    {
        ImmutableArray<string> context = ReadStringList(exampleElement, VcalmParameterNames.Context);
        ImmutableArray<string> types = ReadStringList(exampleElement, VcalmParameterNames.Type);

        ImmutableDictionary<string, string>.Builder subjectFields =
            ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        if(exampleElement.TryGetProperty(VcalmParameterNames.CredentialSubject, out JsonElement subjectElement)
            && subjectElement.ValueKind == JsonValueKind.Object)
        {
            foreach(JsonProperty field in subjectElement.EnumerateObject())
            {
                //§3.4.2: a string value (including "") is the requested value; the empty string is
                //"any value". Non-string values are normalized to their raw text so a numeric or
                //object example value still constrains the field.
                string value = field.Value.ValueKind == JsonValueKind.String
                    ? field.Value.GetString()!
                    : field.Value.GetRawText();
                subjectFields[field.Name] = value;
            }
        }

        return new QueryByExampleCredential
        {
            Context = context,
            Types = types,
            SubjectFields = subjectFields.ToImmutable()
        };
    }


    //§3.4.2 acceptedIssuers: each item is a URL string, an object with id, or an object with
    //recognizedIn{id, type}.
    private static ImmutableArray<QueryByExampleAcceptedIssuer> ParseAcceptedIssuers(JsonElement credentialQueryElement)
    {
        if(!credentialQueryElement.TryGetProperty(VcalmParameterNames.AcceptedIssuers, out JsonElement issuersElement)
            || issuersElement.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<QueryByExampleAcceptedIssuer>.Empty;
        }

        ImmutableArray<QueryByExampleAcceptedIssuer>.Builder builder =
            ImmutableArray.CreateBuilder<QueryByExampleAcceptedIssuer>();
        foreach(JsonElement item in issuersElement.EnumerateArray())
        {
            if(item.ValueKind == JsonValueKind.String)
            {
                builder.Add(new QueryByExampleAcceptedIssuer { Id = item.GetString() });
            }
            else if(item.ValueKind == JsonValueKind.Object)
            {
                if(item.TryGetProperty(VcalmParameterNames.RecognizedIn, out JsonElement recognizedInElement)
                    && recognizedInElement.ValueKind == JsonValueKind.Object
                    && recognizedInElement.TryGetProperty(VcalmParameterNames.Id, out JsonElement recognizedIdElement)
                    && recognizedIdElement.ValueKind == JsonValueKind.String)
                {
                    builder.Add(new QueryByExampleAcceptedIssuer { RecognizedInId = recognizedIdElement.GetString() });
                }
                else if(item.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement)
                    && idElement.ValueKind == JsonValueKind.String)
                {
                    builder.Add(new QueryByExampleAcceptedIssuer { Id = idElement.GetString() });
                }
            }
        }

        return builder.ToImmutable();
    }


    //§3.4.2 acceptedCryptosuites / acceptedEnvelopes: each element SHOULD be an object with a
    //cryptosuite / mediaType property; a bare string is also accepted (backwards compatibility).
    private static ImmutableArray<string> ParseSuiteOrEnvelope(
        JsonElement credentialQueryElement, string arrayName, string objectMemberName)
    {
        if(!credentialQueryElement.TryGetProperty(arrayName, out JsonElement arrayElement)
            || arrayElement.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<string>.Empty;
        }

        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        foreach(JsonElement item in arrayElement.EnumerateArray())
        {
            if(item.ValueKind == JsonValueKind.String)
            {
                builder.Add(item.GetString()!);
            }
            else if(item.ValueKind == JsonValueKind.Object
                && item.TryGetProperty(objectMemberName, out JsonElement memberElement)
                && memberElement.ValueKind == JsonValueKind.String)
            {
                builder.Add(memberElement.GetString()!);
            }
        }

        return builder.ToImmutable();
    }


    //§3.4.3: {type, group?, acceptedMethods?[{method}], acceptedCryptosuites?[{cryptosuite}]}.
    private static DidAuthenticationQuery ParseDidAuthentication(
        JsonElement entry, string type, string? group, out VcalmParseFailure failure)
    {
        failure = VcalmParseFailure.None;

        ImmutableArray<string> acceptedMethods = ReadObjectMemberList(
            entry, VcalmParameterNames.AcceptedMethods, VcalmParameterNames.Method);
        ImmutableArray<string> acceptedCryptosuites = ReadObjectMemberList(
            entry, VcalmParameterNames.AcceptedCryptosuites, VcalmParameterNames.Cryptosuite);

        return new DidAuthenticationQuery
        {
            Type = type,
            Group = group,
            AcceptedMethods = acceptedMethods,
            AcceptedCryptosuites = acceptedCryptosuites
        };
    }


    //§3.4 DigitalCredentialQueryLanguage: the entry carries the existing DcqlQuery model. Deserialize
    //the whole entry into DcqlQuery via the supplied converters — DCQL is mapped, not reimplemented.
    private static DigitalCredentialQueryLanguageQuery? ParseDcql(
        JsonElement entry, string type, string? group, JsonSerializerOptions options, out VcalmParseFailure failure)
    {
        failure = VcalmParseFailure.None;

        DcqlQuery? query;
        try
        {
            query = JsonSerializerExtensions.Deserialize<DcqlQuery>(entry.GetRawText(), options);
        }
        catch(JsonException)
        {
            failure = VcalmParseFailure.Malformed;

            return null;
        }

        if(query is null)
        {
            failure = VcalmParseFailure.Malformed;

            return null;
        }

        return new DigitalCredentialQueryLanguageQuery
        {
            Type = type,
            Group = group,
            Query = query
        };
    }


    //§3.4.4 (editor-unstable): {type, group?, capabilityQuery[{referenceId, allowedAction,
    //controller, invocationTarget}]}. Modeled defensively — parsed, never gated on.
    private static AuthorizationCapabilityRequestQuery ParseAuthorizationCapability(JsonElement entry, string type, string? group)
    {
        ImmutableArray<CapabilityQueryItem>.Builder items = ImmutableArray.CreateBuilder<CapabilityQueryItem>();
        if(entry.TryGetProperty(VcalmParameterNames.CapabilityQuery, out JsonElement capabilityElement)
            && capabilityElement.ValueKind == JsonValueKind.Array)
        {
            foreach(JsonElement item in capabilityElement.EnumerateArray())
            {
                if(item.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string? referenceId = item.TryGetProperty(VcalmParameterNames.ReferenceId, out JsonElement refElement)
                    && refElement.ValueKind == JsonValueKind.String
                    ? refElement.GetString()
                    : null;

                ImmutableArray<string> allowedAction = ReadStringOrStringList(item, VcalmParameterNames.AllowedAction);

                string? controller = item.TryGetProperty(VcalmParameterNames.Controller, out JsonElement controllerElement)
                    && controllerElement.ValueKind == JsonValueKind.String
                    ? controllerElement.GetString()
                    : null;

                string? invocationTargetJson =
                    item.TryGetProperty(VcalmParameterNames.InvocationTarget, out JsonElement targetElement)
                    ? targetElement.GetRawText()
                    : null;

                items.Add(new CapabilityQueryItem
                {
                    ReferenceId = referenceId,
                    AllowedAction = allowedAction,
                    Controller = controller,
                    InvocationTargetJson = invocationTargetJson
                });
            }
        }

        return new AuthorizationCapabilityRequestQuery
        {
            Type = type,
            Group = group,
            CapabilityQuery = items.ToImmutable()
        };
    }


    //A member that is a string or an array of strings (e.g. example.type, allowedAction).
    private static ImmutableArray<string> ReadStringOrStringList(JsonElement element, string memberName)
    {
        if(!element.TryGetProperty(memberName, out JsonElement memberElement))
        {
            return ImmutableArray<string>.Empty;
        }

        if(memberElement.ValueKind == JsonValueKind.String)
        {
            return [memberElement.GetString()!];
        }

        if(memberElement.ValueKind == JsonValueKind.Array)
        {
            ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
            foreach(JsonElement item in memberElement.EnumerateArray())
            {
                if(item.ValueKind == JsonValueKind.String)
                {
                    builder.Add(item.GetString()!);
                }
            }

            return builder.ToImmutable();
        }

        return ImmutableArray<string>.Empty;
    }


    //A member that is a string or an array of strings, read with the same string-or-list rule as
    //example.type / @context.
    private static ImmutableArray<string> ReadStringList(JsonElement element, string memberName) =>
        ReadStringOrStringList(element, memberName);


    //An array of objects each carrying a named string member (e.g. acceptedMethods[{method}],
    //acceptedCryptosuites[{cryptosuite}]); a bare string element is also accepted.
    private static ImmutableArray<string> ReadObjectMemberList(
        JsonElement element, string arrayName, string objectMemberName)
    {
        if(!element.TryGetProperty(arrayName, out JsonElement arrayElement)
            || arrayElement.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<string>.Empty;
        }

        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        foreach(JsonElement item in arrayElement.EnumerateArray())
        {
            if(item.ValueKind == JsonValueKind.String)
            {
                builder.Add(item.GetString()!);
            }
            else if(item.ValueKind == JsonValueKind.Object
                && item.TryGetProperty(objectMemberName, out JsonElement memberElement)
                && memberElement.ValueKind == JsonValueKind.String)
            {
                builder.Add(memberElement.GetString()!);
            }
        }

        return builder.ToImmutable();
    }
}
