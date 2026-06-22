using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Foundation;

namespace Verifiable.Json;

/// <summary>
/// The concrete JSON implementation of the did:webvh DID Log seams: parsing a <c>did.jsonl</c> line into a
/// <see cref="WebVhRawEntry"/> and producing, on demand, the RFC 8785 JCS-canonical byte forms the did:webvh
/// verification steps hash and sign over.
/// </summary>
/// <remarks>
/// <para>
/// <c>Verifiable.Core</c> is firewalled from a JSON serializer, so JSON parsing and RFC 8785 canonicalization
/// live here in the <c>Verifiable.Json</c> leaf, while the verification decisions — hashing, comparing, and
/// signature verification — stay in <c>Verifiable.Core</c>. Each canonicalizer wraps its JCS serializer output
/// in a <see cref="TaggedMemory{T}"/> tagged as JSON — the same tagged-buffer idiom the JOSE layer uses for
/// its serialized JWT parts — so the bytes carry their content kind without a copy into a pool. The four
/// canonical forms mirror normative did:webvh v1.0 steps: the entry-hash input, the Data Integrity document,
/// the SCID verification input, and the proof options.
/// </para>
/// </remarks>
public static class WebVhLogEntryJson
{
    private const string VersionIdProperty = "versionId";
    private const string VersionTimeProperty = "versionTime";
    private const string ParametersProperty = "parameters";
    private const string ProofProperty = "proof";
    private const string ProofValueProperty = "proofValue";
    private const string WitnessProperty = "witness";
    private const string ThresholdProperty = "threshold";
    private const string WitnessesProperty = "witnesses";
    private const string WatchersProperty = "watchers";
    private const string MethodProperty = "method";
    private const string ScidProperty = "scid";
    private const string UpdateKeysProperty = "updateKeys";
    private const string NextKeyHashesProperty = "nextKeyHashes";
    private const string PortableProperty = "portable";
    private const string DeactivatedProperty = "deactivated";
    private const string TtlProperty = "ttl";
    private const string IdProperty = "id";
    private const string StateProperty = "state";
    private const string AlsoKnownAsProperty = "alsoKnownAs";
    private const string ScidPlaceholder = "{SCID}";


    /// <summary>
    /// The <see cref="WebVhLineParser"/> that parses one <c>did.jsonl</c> line into a
    /// <see cref="WebVhRawEntry"/>.
    /// </summary>
    public static WebVhLineParser Parser { get; } = ParseEntry;


    /// <summary>
    /// The <see cref="WebVhWitnessFileParser"/> that parses the <c>did-witness.json</c> file into its
    /// witness proof records.
    /// </summary>
    public static WebVhWitnessFileParser WitnessFileParser { get; } = ParseWitnessFile;


    /// <summary>
    /// The <see cref="WebVhDocumentIdentityReader"/> that reads an entry's <c>state</c> DIDDoc <c>id</c> and
    /// <c>alsoKnownAs</c> for the portability check.
    /// </summary>
    public static WebVhDocumentIdentityReader DocumentIdentityReader { get; } = ReadDocumentIdentity;


    /// <summary>
    /// The on-demand did:webvh canonicalizers that produce the pooled JCS-canonical byte forms.
    /// </summary>
    public static WebVhCanonicalizer Canonicalizer { get; } = new()
    {
        EntryHashInput = ComputeEntryHashInput,
        DocumentInput = ComputeDocumentInput,
        ScidInput = ComputeScidInput,
        ProofOptionsInput = ComputeProofOptionsInput,
        WitnessDocumentInput = ComputeWitnessDocumentInput,
        WitnessProofOptionsInput = ComputeWitnessProofOptionsInput
    };


    private static WebVhRawEntry ParseEntry(ReadOnlyMemory<byte> rawEntryLine)
    {
        JsonObject entry = ParseObject(rawEntryLine.Span);

        string versionId = RequireString(entry, VersionIdProperty);
        string? versionTime = OptionalString(entry, VersionTimeProperty);

        JsonObject parameters = entry[ParametersProperty] as JsonObject
            ?? throw new JsonException("A did:webvh log entry MUST contain a parameters object.");

        return new WebVhRawEntry
        {
            VersionId = versionId,
            VersionTime = versionTime,
            DeclaredParameters = ReadDeclaredParameters(parameters),
            Proofs = ReadProofs(entry)
        };
    }


    //JCS(entry with proof removed and versionId set to the predecessor).
    private static TaggedMemory<byte> ComputeEntryHashInput(ReadOnlyMemory<byte> rawEntryLine, string predecessorVersionId)
    {
        ArgumentNullException.ThrowIfNull(predecessorVersionId);

        JsonObject entry = ParseObject(rawEntryLine.Span);
        entry.Remove(ProofProperty);
        entry[VersionIdProperty] = predecessorVersionId;

        return Canonicalize(entry.ToJsonString());
    }


    //JCS(entry with proof removed) — the unsecured Data Integrity document.
    private static TaggedMemory<byte> ComputeDocumentInput(ReadOnlyMemory<byte> rawEntryLine)
    {
        JsonObject entry = ParseObject(rawEntryLine.Span);
        entry.Remove(ProofProperty);

        return Canonicalize(entry.ToJsonString());
    }


    //JCS(entry with proof removed and versionId set to "{SCID}"), then a text replacement of the scid value
    //with the literal "{SCID}" on the canonical string.
    private static TaggedMemory<byte> ComputeScidInput(ReadOnlyMemory<byte> rawEntryLine, string scid)
    {
        ArgumentNullException.ThrowIfNull(scid);

        JsonObject entry = ParseObject(rawEntryLine.Span);
        entry.Remove(ProofProperty);
        entry[VersionIdProperty] = ScidPlaceholder;

        string canonical = Jcs.Canonicalize(entry.ToJsonString());
        string withPlaceholder = canonical.Replace(scid, ScidPlaceholder, StringComparison.Ordinal);

        return new TaggedMemory<byte>(Encoding.UTF8.GetBytes(withPlaceholder), BufferTags.Json);
    }


    //JCS(the proof at proofIndex with proofValue removed).
    private static TaggedMemory<byte> ComputeProofOptionsInput(ReadOnlyMemory<byte> rawEntryLine, int proofIndex)
    {
        JsonObject entry = ParseObject(rawEntryLine.Span);
        if(entry[ProofProperty] is not JsonArray proofArray
            || proofIndex < 0
            || proofIndex >= proofArray.Count
            || proofArray[proofIndex] is not JsonObject proof)
        {
            throw new JsonException($"The did:webvh log entry has no proof at index {proofIndex}.");
        }

        proof.Remove(ProofValueProperty);

        return Canonicalize(proof.ToJsonString());
    }


    //Reads the entry's state DIDDoc id + alsoKnownAs only (not the full document) for the portability check.
    private static WebVhDocumentIdentity ReadDocumentIdentity(ReadOnlySpan<byte> rawEntryLine)
    {
        JsonObject entry = ParseObject(rawEntryLine);
        if(entry[StateProperty] is not JsonObject state)
        {
            return new WebVhDocumentIdentity(null, ImmutableArray<string>.Empty);
        }

        return new WebVhDocumentIdentity(
            OptionalString(state, IdProperty),
            OptionalStringArray(state, AlsoKnownAsProperty) ?? ImmutableArray<string>.Empty);
    }


    private static ImmutableArray<WebVhWitnessProofEntry> ParseWitnessFile(ReadOnlySpan<byte> content)
    {
        if(JsonNode.Parse(content) is not JsonArray records)
        {
            throw new JsonException("A did:webvh did-witness.json file MUST be a JSON array.");
        }

        var builder = ImmutableArray.CreateBuilder<WebVhWitnessProofEntry>(records.Count);
        foreach(JsonNode? node in records)
        {
            if(node is not JsonObject record)
            {
                throw new JsonException("A did:webvh witness proof record MUST be a JSON object.");
            }

            builder.Add(new WebVhWitnessProofEntry
            {
                VersionId = RequireString(record, VersionIdProperty),
                Proofs = ReadProofs(record)
            });
        }

        return builder.ToImmutable();
    }


    //JCS({"versionId": versionId}) — the single-property object a witness proof is signed over.
    private static TaggedMemory<byte> ComputeWitnessDocumentInput(string versionId)
    {
        ArgumentNullException.ThrowIfNull(versionId);

        var document = new JsonObject { [VersionIdProperty] = versionId };

        return Canonicalize(document.ToJsonString());
    }


    //JCS(the proof at records[entryIndex].proof[proofIndex] with proofValue removed), re-parsed from the
    //retained did-witness.json bytes so the canonical options match the exact published proof object.
    private static TaggedMemory<byte> ComputeWitnessProofOptionsInput(WebVhWitnessFile witnessFile, int entryIndex, int proofIndex)
    {
        ArgumentNullException.ThrowIfNull(witnessFile);

        if(JsonNode.Parse(witnessFile.Content.Span) is not JsonArray records
            || entryIndex < 0
            || entryIndex >= records.Count
            || records[entryIndex] is not JsonObject record
            || record[ProofProperty] is not JsonArray proofArray
            || proofIndex < 0
            || proofIndex >= proofArray.Count
            || proofArray[proofIndex] is not JsonObject proof)
        {
            throw new JsonException($"The did:webvh did-witness.json has no proof at record {entryIndex}, proof {proofIndex}.");
        }

        proof.Remove(ProofValueProperty);

        return Canonicalize(proof.ToJsonString());
    }


    //Wraps the JCS serializer output as JSON-tagged memory, mirroring the JOSE layer's tagged JWT parts.
    private static TaggedMemory<byte> Canonicalize(string json)
    {
        return new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
    }


    private static ImmutableArray<WebVhProof> ReadProofs(JsonObject entry)
    {
        if(entry[ProofProperty] is not JsonArray proofArray)
        {
            return ImmutableArray<WebVhProof>.Empty;
        }

        var builder = ImmutableArray.CreateBuilder<WebVhProof>(proofArray.Count);
        foreach(JsonNode? proofNode in proofArray)
        {
            if(proofNode is not JsonObject proof)
            {
                throw new JsonException("A did:webvh proof entry MUST be a JSON object.");
            }

            builder.Add(new WebVhProof
            {
                Type = OptionalString(proof, "type"),
                Cryptosuite = OptionalString(proof, "cryptosuite"),
                Created = OptionalString(proof, "created"),
                Expires = OptionalString(proof, "expires"),
                VerificationMethod = OptionalString(proof, "verificationMethod"),
                ProofPurpose = OptionalString(proof, "proofPurpose"),
                ProofValue = OptionalString(proof, ProofValueProperty)
            });
        }

        return builder.ToImmutable();
    }


    //The parameter property names defined by did:webvh v1.0. The parameters object MUST only include properties
    //defined in the version of the specification being used, so any other property name invalidates the entry
    //(did:webvh v1.0, Parameters: L1035).
    private static readonly string[] DefinedParameterProperties =
    [
        MethodProperty, ScidProperty, UpdateKeysProperty, NextKeyHashesProperty,
        PortableProperty, DeactivatedProperty, TtlProperty, WitnessProperty, WatchersProperty
    ];


    private static WebVhDeclaredParameters ReadDeclaredParameters(JsonObject parameters)
    {
        RejectUnknownParameters(parameters);

        return new WebVhDeclaredParameters
        {
            Method = OptionalString(parameters, MethodProperty),
            Scid = OptionalString(parameters, ScidProperty),
            UpdateKeys = RequiredArrayWhenPresent(parameters, UpdateKeysProperty),
            NextKeyHashes = RequiredArrayWhenPresent(parameters, NextKeyHashesProperty),
            Portable = RequiredBoolWhenPresent(parameters, PortableProperty),
            Deactivated = RequiredBoolWhenPresent(parameters, DeactivatedProperty),
            Ttl = ReadTtl(parameters),
            Witness = ReadWitnessDeclaration(parameters),
            Watchers = ReadWatchers(parameters)
        };
    }


    //Reads a string-array parameter (updateKeys, nextKeyHashes). Absent -> null (retain the accumulated value).
    //The deprecated JSON null the specification says resolvers SHOULD accept -> the parameter's documented
    //default empty array [] (the same value used to deactivate the parameter), uniformly with every other
    //null-accepting parameter (did:webvh v1.0, Parameters: L1048 "convert the value to their equivalent default
    //value"). A JSON array -> the strings. Any other JSON kind does not conform to the data model and MUST be
    //rejected rather than coerced (did:webvh v1.0, Parameters: a non-conforming value invalidates the entry).
    private static ImmutableArray<string>? RequiredArrayWhenPresent(JsonObject parameters, string property)
    {
        if(!parameters.TryGetPropertyValue(property, out JsonNode? node))
        {
            return null;
        }

        if(node is null)
        {
            return ImmutableArray<string>.Empty;
        }

        if(node is not JsonArray)
        {
            throw new JsonException($"A did:webvh '{property}' parameter MUST be a JSON array.");
        }

        return OptionalStringArray(parameters, property);
    }


    //Reads a boolean parameter (portable, deactivated). Absent -> null (retain/default). The deprecated JSON null
    //the specification says resolvers SHOULD accept -> null (the parameter default). A JSON boolean -> the value.
    //Any other JSON kind does not conform to the data model and MUST be rejected rather than coerced to the
    //default (did:webvh v1.0, Parameters: a non-conforming value invalidates the entry).
    private static bool? RequiredBoolWhenPresent(JsonObject parameters, string property)
    {
        if(!parameters.TryGetPropertyValue(property, out JsonNode? node))
        {
            return null;
        }

        if(node is null)
        {
            return null;
        }

        if(node is not JsonValue value || !value.TryGetValue(out bool flag))
        {
            throw new JsonException($"A did:webvh '{property}' parameter MUST be a JSON boolean.");
        }

        return flag;
    }


    //The parameters object MUST only include properties defined by this did:webvh version; an undefined property
    //invalidates the entry rather than being ignored (did:webvh v1.0, Parameters: L1035).
    private static void RejectUnknownParameters(JsonObject parameters)
    {
        foreach(KeyValuePair<string, JsonNode?> property in parameters)
        {
            if(Array.IndexOf(DefinedParameterProperties, property.Key) < 0)
            {
                throw new JsonException($"A did:webvh parameters object MUST only include defined properties; '{property.Key}' is not defined.");
            }
        }
    }


    //Reads the ttl parameter. Absent -> null (retain the accumulated value). The deprecated JSON null the
    //specification says resolvers SHOULD accept -> the parameter's documented default (3600 seconds),
    //uniformly with every other null-accepting parameter (did:webvh v1.0, Parameters: L1048 "convert the value
    //to their equivalent default value"). A positive integer within range -> that value. A type-mismatched
    //value (a non-integer, or one outside Int32 range which is NOT silently truncated to the default) or a
    //non-positive value does not conform to the ttl data model (an unsigned, meaningful cache hint) and MUST be
    //rejected rather than coerced (did:webvh v1.0, Parameters: a non-conforming value invalidates the entry).
    private static int? ReadTtl(JsonObject parameters)
    {
        if(!parameters.TryGetPropertyValue(TtlProperty, out JsonNode? node))
        {
            return null;
        }

        if(node is null)
        {
            return WebVhParameters.DefaultTtlSeconds;
        }

        if(node is not JsonValue value || !value.TryGetValue(out int ttl))
        {
            throw new JsonException("A did:webvh ttl parameter MUST be an integer within range.");
        }

        if(ttl <= 0)
        {
            throw new JsonException($"A did:webvh ttl parameter MUST be a positive integer; got {ttl}.");
        }

        return ttl;
    }


    //Reads the tri-state watchers parameter. Absent -> null (retain the accumulated list). The deprecated JSON
    //null the specification says resolvers SHOULD accept -> the default empty list. An array -> the watcher
    //URLs (opaque strings). Any other JSON kind does not conform to the watchers data model and MUST be
    //rejected (did:webvh v1.0, Parameters).
    private static ImmutableArray<string>? ReadWatchers(JsonObject parameters)
    {
        if(!parameters.TryGetPropertyValue(WatchersProperty, out JsonNode? node))
        {
            return null;
        }

        if(node is null)
        {
            return ImmutableArray<string>.Empty;
        }

        if(node is not JsonArray)
        {
            throw new JsonException("A did:webvh watchers parameter MUST be a JSON array.");
        }

        return OptionalStringArray(parameters, WatchersProperty);
    }


    //Reads the tri-state witness parameter. Absent -> null (retain the accumulated rule). The empty object {}
    //(or the deprecated JSON null the specification says resolvers SHOULD accept as the parameter default) ->
    //a declaration with no rule (disable). A non-empty object -> the declared rule. Any other JSON kind (array,
    //string, number, boolean) does not conform to the witness data model and MUST be rejected rather than
    //coerced to a default (did:webvh v1.0, Parameters: a non-conforming parameter value invalidates the entry).
    //Semantic limits (threshold range, non-empty unique did:key witnesses) are validated on fold in
    //Verifiable.Core; the structural shape parsed here keeps a malformed rule reaching the fold as a rule that
    //fails validation rather than being silently coerced to "no witnesses".
    private static WebVhWitnessDeclaration? ReadWitnessDeclaration(JsonObject parameters)
    {
        if(!parameters.TryGetPropertyValue(WitnessProperty, out JsonNode? node))
        {
            return null;
        }

        if(node is null)
        {
            return new WebVhWitnessDeclaration(null);
        }

        if(node is not JsonObject witness)
        {
            throw new JsonException("A did:webvh witness parameter MUST be a JSON object.");
        }

        return witness.Count == 0
            ? new WebVhWitnessDeclaration(null)
            : new WebVhWitnessDeclaration(ReadWitnessRule(witness));
    }


    private static WebVhWitnessRule ReadWitnessRule(JsonObject witness)
    {
        int threshold = OptionalInt(witness, ThresholdProperty) ?? 0;

        var ids = ImmutableArray.CreateBuilder<string>();
        if(witness[WitnessesProperty] is JsonArray witnessArray)
        {
            foreach(JsonNode? element in witnessArray)
            {
                if(element is not JsonObject witnessEntry || OptionalString(witnessEntry, IdProperty) is not { } id)
                {
                    throw new JsonException("A did:webvh witness entry MUST be an object with a string 'id'.");
                }

                ids.Add(id);
            }
        }

        return new WebVhWitnessRule(threshold, ids.ToImmutable());
    }


    private static JsonObject ParseObject(ReadOnlySpan<byte> utf8Json)
    {
        return JsonNode.Parse(utf8Json) as JsonObject
            ?? throw new JsonException("A did:webvh log entry MUST be a JSON object.");
    }


    private static string RequireString(JsonObject obj, string property)
    {
        return OptionalString(obj, property)
            ?? throw new JsonException($"A did:webvh log entry MUST contain a string '{property}' property.");
    }


    private static string? OptionalString(JsonObject obj, string property)
    {
        return obj.TryGetPropertyValue(property, out JsonNode? node) && node is JsonValue value && value.TryGetValue(out string? text)
            ? text
            : null;
    }


    private static int? OptionalInt(JsonObject obj, string property)
    {
        return obj.TryGetPropertyValue(property, out JsonNode? node) && node is JsonValue value && value.TryGetValue(out int number)
            ? number
            : null;
    }


    private static ImmutableArray<string>? OptionalStringArray(JsonObject obj, string property)
    {
        if(!obj.TryGetPropertyValue(property, out JsonNode? node) || node is not JsonArray array)
        {
            return null;
        }

        var builder = ImmutableArray.CreateBuilder<string>(array.Count);
        foreach(JsonNode? element in array)
        {
            builder.Add(element is JsonValue value && value.TryGetValue(out string? text)
                ? text
                : throw new JsonException($"The did:webvh '{property}' array MUST contain only strings."));
        }

        return builder.ToImmutable();
    }
}
