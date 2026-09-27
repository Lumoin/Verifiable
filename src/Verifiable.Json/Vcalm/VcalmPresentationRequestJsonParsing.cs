using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
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
/// <para>
/// The acceptance constraints are strict the same way, since "Implementations MUST throw an error if
/// an endpoint receives data, options, or option values that it does not understand or know how to
/// process" (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>): a constraint the
/// parser dropped would widen what the request accepts. A present <c>acceptedMethods</c>,
/// <c>acceptedCryptosuites</c>, <c>acceptedEnvelopes</c> or <c>acceptedIssuers</c> member that is
/// not an array; a DID Authentication element that is not an object; a missing, empty or non-string
/// <c>method</c>, <c>cryptosuite</c> or <c>mediaType</c>; and an accepted-issuer item of none of the
/// three §3.4.2 shapes each make the whole request <see cref="VcalmParseFailure.Malformed"/>. Bare
/// strings stand for a cryptosuite name or media type only in a Query By Example, where §3.4.2 admits
/// them "for backwards compatibility". Extra members inside an element object stay allowed ("MAY
/// contain other properties"). An absent member places no constraint.
/// </para>
/// <para>
/// A member name repeated inside any object of the request, a <c>domain</c>, <c>challenge</c>,
/// <c>group</c> or <c>reason</c> that is present but not a string, an <c>example</c> that is present but
/// not an object (or whose <c>@context</c>, <c>type</c> or <c>credentialSubject</c> is of another shape),
/// a <c>method</c> that is not a DID method name and an issuer URL that is not a valid URL string are
/// refused the same way: each would otherwise be dropped or resolved to one occurrence, and the request
/// would accept more than its author wrote.
/// </para>
/// </remarks>
public static class VcalmPresentationRequestJsonParsing
{
    /// <summary>
    /// The document options every request is parsed with. A member name repeated inside one object is
    /// refused (<see cref="JsonDocumentOptions.AllowDuplicateProperties"/> off), so a lookup never
    /// resolves a repeated name to one of its occurrences and an earlier, malformed or narrowing
    /// occurrence of an acceptance constraint is never discarded unseen; the parse throws
    /// <see cref="JsonException"/> and the request is <see cref="VcalmParseFailure.Malformed"/> under
    /// "Implementations MUST throw an error if an endpoint receives data, options, or option values that
    /// it does not understand or know how to process"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>).
    /// </summary>
    private static JsonDocumentOptions StrictDocumentOptions { get; } = new() { AllowDuplicateProperties = false };


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
            doc = JsonDocument.Parse(requestBody, StrictDocumentOptions);
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

            //§3.4.1: domain and challenge are each "An OPTIONAL string"; a present value of another kind
            //is not understood (§2.4) and refuses the request.
            if(!TryReadOptionalString(root, VcalmParameterNames.Domain, out string? domain)
                || !TryReadOptionalString(root, VcalmParameterNames.Challenge, out string? challenge))
            {
                return VerifiablePresentationRequest.Malformed();
            }

            return new VerifiablePresentationRequest
            {
                Query = queries.ToImmutable(),
                Domain = domain,
                Challenge = challenge
            };
        }
    }


    /// <summary>
    /// Reads one query entry. "The value MUST be one or more maps where each map MUST define a type
    /// property with an associated string value"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>).
    /// The type value selects the Query By Example, DID Authentication, DCQL or authorization capability
    /// shape; a well-formed but unrecognized type is an open-extension <see cref="UnknownQuery"/>, not a
    /// failure. A present <c>group</c> that is not a string refuses the entry: "Multiple queries with the
    /// same group value are processed as "AND" operations, while queries with different or missing group
    /// values are processed as "OR" operations"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>), so a group read
    /// as missing would turn an AND into an OR.
    /// </summary>
    /// <param name="entry">The query entry element.</param>
    /// <param name="options">The serializer options carrying the DCQL query converters.</param>
    /// <param name="failure">Why the entry was refused; <see cref="VcalmParseFailure.None"/> when it parsed.</param>
    /// <returns>The parsed entry, or <see langword="null"/> when refused.</returns>
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
        if(!TryReadOptionalString(entry, VcalmParameterNames.Group, out string? group))
        {
            failure = VcalmParseFailure.Malformed;

            return null;
        }

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


    /// <summary>
    /// Reads a Query By Example entry, <c>{type, group?, credentialQuery{reason?, example?,
    /// acceptedIssuers?, acceptedCryptosuites?, acceptedEnvelopes?}}</c>: "The credentialQuery property
    /// in a QueryByExample query is a single object"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>). A
    /// <c>reason</c> is "An OPTIONAL string" and an <c>example</c> "An OPTIONAL object"; a present value
    /// of another kind, like a malformed acceptance constraint, refuses the entry with its failure, so the
    /// whole request is refused.
    /// </summary>
    /// <param name="entry">The query entry element.</param>
    /// <param name="type">The entry's <c>type</c>.</param>
    /// <param name="group">The entry's <c>group</c>, or <see langword="null"/>.</param>
    /// <param name="failure">Why the entry was refused; <see cref="VcalmParseFailure.None"/> when it parsed.</param>
    /// <returns>The parsed entry, or <see langword="null"/> when refused.</returns>
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

        if(!TryReadOptionalString(credentialQueryElement, VcalmParameterNames.Reason, out string? reason))
        {
            failure = VcalmParseFailure.Malformed;

            return null;
        }

        //An example read as absent would place no claim or type constraint and admit every held
        //credential, so a present example of another shape refuses the entry.
        QueryByExampleCredential? example = null;
        if(credentialQueryElement.TryGetProperty(VcalmParameterNames.Example, out JsonElement exampleElement))
        {
            example = ParseExample(exampleElement);
            if(example is null)
            {
                failure = VcalmParseFailure.Malformed;

                return null;
            }
        }

        Result<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure> acceptedIssuers =
            ParseAcceptedIssuers(credentialQueryElement);
        if(!acceptedIssuers.IsSuccess)
        {
            failure = acceptedIssuers.Error;

            return null;
        }

        Result<ImmutableArray<string>, VcalmParseFailure> acceptedCryptosuites = ParseSuiteOrEnvelope(
            credentialQueryElement, VcalmParameterNames.AcceptedCryptosuites, VcalmParameterNames.Cryptosuite);
        if(!acceptedCryptosuites.IsSuccess)
        {
            failure = acceptedCryptosuites.Error;

            return null;
        }

        Result<ImmutableArray<string>, VcalmParseFailure> acceptedEnvelopes = ParseSuiteOrEnvelope(
            credentialQueryElement, VcalmParameterNames.AcceptedEnvelopes, VcalmParameterNames.MediaType);
        if(!acceptedEnvelopes.IsSuccess)
        {
            failure = acceptedEnvelopes.Error;

            return null;
        }

        return new QueryByExampleQuery
        {
            Type = type,
            Group = group,
            CredentialQuery = new QueryByExampleCredentialQuery
            {
                Reason = reason,
                Example = example,
                AcceptedIssuers = acceptedIssuers.Value,
                AcceptedCryptosuites = acceptedCryptosuites.Value,
                AcceptedEnvelopes = acceptedEnvelopes.Value
            }
        };
    }


    /// <summary>
    /// Reads a Query By Example <c>example</c>: "An OPTIONAL object that provides an example of the
    /// credential being requested, including its @context, type, and optionally credentialSubject fields
    /// to indicate which claims are needed"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>). Every present
    /// field is a required field; a subject field value of "" requests the field with no value
    /// expectation.
    /// </summary>
    /// <remarks>
    /// An example that is not an object, an <c>@context</c> or <c>type</c> that is neither a string nor
    /// an array of strings, and a <c>credentialSubject</c> that is not an object are each refused: read as
    /// absent, any of them would drop a constraint the verifier wrote.
    /// </remarks>
    /// <param name="exampleElement">The <c>example</c> value.</param>
    /// <returns>The parsed example, or <see langword="null"/> when the value is of another shape.</returns>
    private static QueryByExampleCredential? ParseExample(JsonElement exampleElement)
    {
        if(exampleElement.ValueKind != JsonValueKind.Object
            || !TryReadStrictStringOrStringList(exampleElement, VcalmParameterNames.Context, out ImmutableArray<string> context)
            || !TryReadStrictStringOrStringList(exampleElement, VcalmParameterNames.Type, out ImmutableArray<string> types))
        {
            return null;
        }

        ImmutableDictionary<string, string>.Builder subjectFields =
            ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        if(exampleElement.TryGetProperty(VcalmParameterNames.CredentialSubject, out JsonElement subjectElement))
        {
            if(subjectElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

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


    /// <summary>
    /// §3.4.2 <c>acceptedIssuers</c>: "An OPTIONAL array of items, or lists that contain items", each
    /// item "either 1) a [URL] ..., or 2) an object that contains an id property whose value is a
    /// [URL] ..., or 3) an object that contains a recognizedIn property that is associated with an
    /// object with a type property that is set to RecognizedEntityCredential and an id property with a
    /// [URL] value" (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>).
    /// </summary>
    /// <remarks>
    /// An absent member places no constraint. A present member that is not an array, an item of none
    /// of the three shapes (<see cref="ParseAcceptedIssuerItem"/>), an empty list, or a list inside a
    /// list is <see cref="VcalmParseFailure.Malformed"/>: dropping it would widen the accepted issuers.
    /// A list's items join the accepted issuers beside the top-level items, since any item that names
    /// the issuer accepts it; an empty list is refused because it names no issuer, and flattening it
    /// would leave a constraint that accepts every issuer.
    /// </remarks>
    /// <param name="credentialQueryElement">The <c>credentialQuery</c> object.</param>
    /// <returns>The accepted-issuer items, or <see cref="VcalmParseFailure.Malformed"/>.</returns>
    private static Result<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure> ParseAcceptedIssuers(
        JsonElement credentialQueryElement)
    {
        if(!credentialQueryElement.TryGetProperty(VcalmParameterNames.AcceptedIssuers, out JsonElement issuersElement))
        {
            return Result.Success<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure>(
                ImmutableArray<QueryByExampleAcceptedIssuer>.Empty);
        }

        if(issuersElement.ValueKind != JsonValueKind.Array)
        {
            return Result.Failure<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure>(VcalmParseFailure.Malformed);
        }

        ImmutableArray<QueryByExampleAcceptedIssuer>.Builder builder =
            ImmutableArray.CreateBuilder<QueryByExampleAcceptedIssuer>();
        foreach(JsonElement item in issuersElement.EnumerateArray())
        {
            if(item.ValueKind != JsonValueKind.Array)
            {
                if(ParseAcceptedIssuerItem(item) is not { } single)
                {
                    return Result.Failure<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure>(VcalmParseFailure.Malformed);
                }

                builder.Add(single);

                continue;
            }

            //A list that contains items: at least one, each an item, none a further list.
            if(item.GetArrayLength() == 0)
            {
                return Result.Failure<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure>(VcalmParseFailure.Malformed);
            }

            foreach(JsonElement listed in item.EnumerateArray())
            {
                if(ParseAcceptedIssuerItem(listed) is not { } listedIssuer)
                {
                    return Result.Failure<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure>(VcalmParseFailure.Malformed);
                }

                builder.Add(listedIssuer);
            }
        }

        return Result.Success<ImmutableArray<QueryByExampleAcceptedIssuer>, VcalmParseFailure>(builder.ToImmutable());
    }


    /// <summary>
    /// Reads one §3.4.2 accepted-issuer item: a URL string, an object with a URL <c>id</c>, or an
    /// object with a well-formed <c>recognizedIn</c> (<see cref="ParseRecognizedIn"/>). An object
    /// carrying <c>recognizedIn</c> is read as that shape, never as a direct <c>id</c>. A list is not an
    /// item.
    /// </summary>
    /// <param name="item">The item element.</param>
    /// <returns>The item, or <see langword="null"/> when it is of none of the three shapes.</returns>
    private static QueryByExampleAcceptedIssuer? ParseAcceptedIssuerItem(JsonElement item) => item.ValueKind switch
    {
        JsonValueKind.String when IsUrl(item.GetString()) => new QueryByExampleAcceptedIssuer { Id = item.GetString() },
        JsonValueKind.Object when item.TryGetProperty(VcalmParameterNames.RecognizedIn, out JsonElement recognizedIn) =>
            ParseRecognizedIn(recognizedIn),
        JsonValueKind.Object when item.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement)
            && idElement.ValueKind == JsonValueKind.String
            && IsUrl(idElement.GetString()) => new QueryByExampleAcceptedIssuer { Id = idElement.GetString() },
        _ => null
    };


    /// <summary>
    /// Reads a §3.4.2 <c>recognizedIn</c> value: "an object with a type property that is set to
    /// RecognizedEntityCredential and an id property with a [URL] value that points to such a
    /// credential". The issuers the list names are left to the caller
    /// (<see cref="QueryByExampleAcceptedIssuer.RecognizedIssuerIds"/> stays empty).
    /// </summary>
    /// <param name="recognizedIn">The <c>recognizedIn</c> value.</param>
    /// <returns>The item, or <see langword="null"/> when the value is not of that shape.</returns>
    private static QueryByExampleAcceptedIssuer? ParseRecognizedIn(JsonElement recognizedIn)
    {
        bool isRecognizedEntityList = recognizedIn.ValueKind == JsonValueKind.Object
            && recognizedIn.TryGetProperty(VcalmParameterNames.Type, out JsonElement typeElement)
            && typeElement.ValueKind == JsonValueKind.String
            && string.Equals(typeElement.GetString(), VcalmParameterNames.RecognizedEntityCredential, StringComparison.Ordinal);
        if(!isRecognizedEntityList
            || !recognizedIn.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement)
            || idElement.ValueKind != JsonValueKind.String
            || !IsUrl(idElement.GetString()))
        {
            return null;
        }

        return new QueryByExampleAcceptedIssuer { RecognizedInId = idElement.GetString() };
    }


    /// <summary>
    /// Whether <paramref name="value"/> is a [URL] in the §3.4.2 sense, the draft's [URL] reference being
    /// the <see href="https://url.spec.whatwg.org/">URL Standard</see>: a valid absolute URL string as
    /// <see cref="UrlStandardValidation.IsValidAbsoluteUrl"/> decides it (a DID such as
    /// <c>did:web:red-issuer.example</c> qualifies; <c>https://test.42/</c>, whose host ends in a number
    /// without being an IPv4 address, does not). The original text is kept for the exact issuer
    /// comparison; nothing here dereferences it.
    /// </summary>
    /// <param name="value">The candidate text.</param>
    /// <returns><see langword="true"/> when the text is a valid absolute URL string.</returns>
    private static bool IsUrl(string? value) => UrlStandardValidation.IsValidAbsoluteUrl(value);


    /// <summary>
    /// §3.4.2 <c>acceptedCryptosuites</c> / <c>acceptedEnvelopes</c>: "Each element SHOULD be an object
    /// with a cryptosuite property" (a <c>mediaType</c> property for envelopes), and "for backwards
    /// compatibility, string values MAY also be used"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>).
    /// </summary>
    /// <remarks>
    /// An absent member places no constraint. A present member that is not an array, or an element that
    /// is neither a non-empty string nor an object whose <paramref name="objectMemberName"/> is a
    /// non-empty string, is <see cref="VcalmParseFailure.Malformed"/>.
    /// </remarks>
    /// <param name="credentialQueryElement">The <c>credentialQuery</c> object.</param>
    /// <param name="arrayName">The array member name.</param>
    /// <param name="objectMemberName">The name each element object carries its value under.</param>
    /// <returns>The names, or <see cref="VcalmParseFailure.Malformed"/>.</returns>
    private static Result<ImmutableArray<string>, VcalmParseFailure> ParseSuiteOrEnvelope(
        JsonElement credentialQueryElement, string arrayName, string objectMemberName) =>
        ReadNamedElementList(credentialQueryElement, arrayName, objectMemberName, isBareStringAccepted: true, IsNonEmpty);


    /// <summary>
    /// §3.4.3.1: <c>{type, group?, acceptedMethods?[{method}], acceptedCryptosuites?[{cryptosuite}]}</c>.
    /// "Each object in the array MUST contain a property called method with a value that is a DID
    /// Method name", and each <c>acceptedCryptosuites</c> object "MUST contain a property called
    /// cryptosuite"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>); a malformed array refuses the entry. A <c>method</c> is checked against the DID
    /// method-name grammar (<see cref="IsDidMethodName"/>).
    /// </summary>
    /// <param name="entry">The query entry element.</param>
    /// <param name="type">The entry's <c>type</c>.</param>
    /// <param name="group">The entry's <c>group</c>, or <see langword="null"/>.</param>
    /// <param name="failure">Why the entry was refused; <see cref="VcalmParseFailure.None"/> when it parsed.</param>
    /// <returns>The parsed entry, or <see langword="null"/> when refused.</returns>
    private static DidAuthenticationQuery? ParseDidAuthentication(
        JsonElement entry, string type, string? group, out VcalmParseFailure failure)
    {
        failure = VcalmParseFailure.None;

        Result<ImmutableArray<string>, VcalmParseFailure> acceptedMethods = ReadObjectMemberList(
            entry, VcalmParameterNames.AcceptedMethods, VcalmParameterNames.Method, IsDidMethodName);
        if(!acceptedMethods.IsSuccess)
        {
            failure = acceptedMethods.Error;

            return null;
        }

        Result<ImmutableArray<string>, VcalmParseFailure> acceptedCryptosuites = ReadObjectMemberList(
            entry, VcalmParameterNames.AcceptedCryptosuites, VcalmParameterNames.Cryptosuite, IsNonEmpty);
        if(!acceptedCryptosuites.IsSuccess)
        {
            failure = acceptedCryptosuites.Error;

            return null;
        }

        return new DidAuthenticationQuery
        {
            Type = type,
            Group = group,
            AcceptedMethods = acceptedMethods.Value,
            AcceptedCryptosuites = acceptedCryptosuites.Value
        };
    }


    /// <summary>
    /// Reads a DigitalCredentialQueryLanguage entry, one of the query types of
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#requesting-a-presentation">VCALM §3.4</see>: the entry
    /// carries the existing <see cref="DcqlQuery"/> model, so the whole entry is deserialized into it
    /// through the supplied converters; DCQL is mapped, not reimplemented.
    /// </summary>
    /// <param name="entry">The query entry element.</param>
    /// <param name="type">The entry's <c>type</c>.</param>
    /// <param name="group">The entry's <c>group</c>, or <see langword="null"/>.</param>
    /// <param name="options">The serializer options carrying the DCQL query converters.</param>
    /// <param name="failure">Why the entry was refused; <see cref="VcalmParseFailure.None"/> when it parsed.</param>
    /// <returns>The parsed entry, or <see langword="null"/> when refused.</returns>
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


    /// <summary>
    /// §3.4.4 (editor-unstable): <c>{type, group?, capabilityQuery[{referenceId, allowedAction,
    /// controller, invocationTarget}]}</c>. Modeled defensively — parsed, never gated on.
    /// </summary>
    /// <param name="entry">The query entry element.</param>
    /// <param name="type">The entry's <c>type</c>.</param>
    /// <param name="group">The entry's <c>group</c>, or <see langword="null"/>.</param>
    /// <returns>The parsed entry.</returns>
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


    /// <summary>Reads a member that is a string or an array of strings (e.g. <c>allowedAction</c>).</summary>
    /// <param name="element">The object carrying the member.</param>
    /// <param name="memberName">The member name.</param>
    /// <returns>The strings; empty when the member is absent or of another shape.</returns>
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


    /// <summary>
    /// Reads an OPTIONAL member that is a string or an array of strings, the shape of an
    /// <c>example</c>'s <c>@context</c> and <c>type</c>, refusing any other shape instead of dropping it.
    /// </summary>
    /// <param name="element">The object carrying the member.</param>
    /// <param name="memberName">The member name.</param>
    /// <param name="values">The strings; empty when the member is absent.</param>
    /// <returns><see langword="false"/> when the member is present but neither a string nor an array of strings.</returns>
    private static bool TryReadStrictStringOrStringList(JsonElement element, string memberName, out ImmutableArray<string> values)
    {
        values = ImmutableArray<string>.Empty;
        if(!element.TryGetProperty(memberName, out JsonElement memberElement))
        {
            return true;
        }

        if(memberElement.ValueKind == JsonValueKind.String)
        {
            values = [memberElement.GetString()!];

            return true;
        }

        if(memberElement.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        foreach(JsonElement item in memberElement.EnumerateArray())
        {
            if(item.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            builder.Add(item.GetString()!);
        }

        values = builder.ToImmutable();

        return true;
    }


    /// <summary>
    /// Reads an OPTIONAL string member such as the request's <c>domain</c> and <c>challenge</c>, an
    /// entry's <c>group</c> or a Query By Example <c>reason</c>. A present value of another kind is not
    /// understood, and "Implementations MUST throw an error if an endpoint receives data, options, or
    /// option values that it does not understand or know how to process"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>).
    /// </summary>
    /// <param name="element">The object carrying the member.</param>
    /// <param name="memberName">The member name.</param>
    /// <param name="value">The string, or <see langword="null"/> when the member is absent.</param>
    /// <returns><see langword="false"/> when the member is present but not a string.</returns>
    private static bool TryReadOptionalString(JsonElement element, string memberName, out string? value)
    {
        value = null;
        if(!element.TryGetProperty(memberName, out JsonElement memberElement))
        {
            return true;
        }

        if(memberElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = memberElement.GetString();

        return true;
    }


    /// <summary>
    /// Reads a §3.4.3.1 "array of objects" in which "Each object in the array MUST contain a property
    /// called" <paramref name="objectMemberName"/> (<c>acceptedMethods[{method}]</c>,
    /// <c>acceptedCryptosuites[{cryptosuite}]</c>). No bare string stands for an element here: the
    /// clause admits objects only.
    /// </summary>
    /// <param name="element">The query entry element.</param>
    /// <param name="arrayName">The array member name.</param>
    /// <param name="objectMemberName">The name each element object carries its value under.</param>
    /// <param name="isValueWellFormed">Decides whether a string value is of the shape the clause names.</param>
    /// <returns>The values, or <see cref="VcalmParseFailure.Malformed"/>.</returns>
    private static Result<ImmutableArray<string>, VcalmParseFailure> ReadObjectMemberList(
        JsonElement element, string arrayName, string objectMemberName, Func<string, bool> isValueWellFormed) =>
        ReadNamedElementList(element, arrayName, objectMemberName, isBareStringAccepted: false, isValueWellFormed);


    /// <summary>
    /// Reads an OPTIONAL array whose elements each name one value: an object carrying the value as the
    /// string member <paramref name="objectMemberName"/> (other members allowed, since each object "MAY
    /// contain other properties"), or, when <paramref name="isBareStringAccepted"/>, a bare string; each
    /// value must satisfy <paramref name="isValueWellFormed"/>.
    /// </summary>
    /// <remarks>
    /// An absent member places no constraint (empty). A present member that is not an array, or any
    /// element of another shape, is <see cref="VcalmParseFailure.Malformed"/> for the whole array: an
    /// element dropped silently would widen what the request accepts, against "Implementations MUST
    /// throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>).
    /// </remarks>
    /// <param name="element">The object carrying the array.</param>
    /// <param name="arrayName">The array member name.</param>
    /// <param name="objectMemberName">The name each element object carries its value under.</param>
    /// <param name="isBareStringAccepted">Whether a bare string element stands for the value.</param>
    /// <param name="isValueWellFormed">Decides whether a string value is of the shape the clause names.</param>
    /// <returns>The values, or <see cref="VcalmParseFailure.Malformed"/>.</returns>
    private static Result<ImmutableArray<string>, VcalmParseFailure> ReadNamedElementList(
        JsonElement element, string arrayName, string objectMemberName, bool isBareStringAccepted, Func<string, bool> isValueWellFormed)
    {
        if(!element.TryGetProperty(arrayName, out JsonElement arrayElement))
        {
            return Result.Success<ImmutableArray<string>, VcalmParseFailure>(ImmutableArray<string>.Empty);
        }

        if(arrayElement.ValueKind != JsonValueKind.Array)
        {
            return Result.Failure<ImmutableArray<string>, VcalmParseFailure>(VcalmParseFailure.Malformed);
        }

        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        foreach(JsonElement item in arrayElement.EnumerateArray())
        {
            string? value = item.ValueKind switch
            {
                JsonValueKind.String when isBareStringAccepted => item.GetString(),
                JsonValueKind.Object when item.TryGetProperty(objectMemberName, out JsonElement memberElement)
                    && memberElement.ValueKind == JsonValueKind.String => memberElement.GetString(),
                _ => null
            };

            if(value is null || !isValueWellFormed(value))
            {
                return Result.Failure<ImmutableArray<string>, VcalmParseFailure>(VcalmParseFailure.Malformed);
            }

            builder.Add(value);
        }

        return Result.Success<ImmutableArray<string>, VcalmParseFailure>(builder.ToImmutable());
    }


    /// <summary>Whether <paramref name="value"/> names something at all: a cryptosuite name or media type is never the empty string.</summary>
    /// <param name="value">The candidate value.</param>
    /// <returns><see langword="true"/> when the value is not empty.</returns>
    private static bool IsNonEmpty(string value) => value.Length > 0;


    /// <summary>
    /// Whether <paramref name="value"/> is a DID method name, the value an <c>acceptedMethods</c> object's
    /// <c>method</c> "MUST" carry
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>), under the DID syntax rules "method-name = 1*method-char" and "method-char =
    /// %x61-7A / DIGIT" (<see href="https://www.w3.org/TR/did-core/#did-syntax">DID Core 1.0 §3.1</see>):
    /// one or more lowercase ASCII letters or digits. A full DID, an uppercase name or a name with any
    /// other character is refused.
    /// </summary>
    /// <param name="value">The candidate method name.</param>
    /// <returns><see langword="true"/> when the value is a DID method name.</returns>
    private static bool IsDidMethodName(string value) =>
        value.Length > 0 && !value.AsSpan().ContainsAnyExcept(DidMethodCharacters);


    /// <summary>The DID Core <c>method-char</c> set: <c>%x61-7A</c> (<c>a</c> to <c>z</c>) and <c>DIGIT</c>.</summary>
    private static System.Buffers.SearchValues<char> DidMethodCharacters { get; } =
        System.Buffers.SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789");
}
