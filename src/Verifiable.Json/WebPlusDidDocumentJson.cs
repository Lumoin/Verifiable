using System;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.Model.Did;
using Verifiable.Foundation;

namespace Verifiable.Json;

/// <summary>
/// The concrete JSON implementation of the strict did:webplus verifier parse: reading a JCS-serialized DID
/// document into a <see cref="WebPlusDidDocument"/> and producing its RFC 8785 JCS canonicalization for the
/// byte-equality step of validation.
/// </summary>
/// <remarks>
/// <c>Verifiable.Core</c> is firewalled from a JSON serializer, so JSON parsing and RFC 8785 canonicalization
/// live here in the <c>Verifiable.Json</c> leaf, while the validation decisions stay in <c>Verifiable.Core</c>.
/// This is the <em>strict</em> path the verifier uses: it surfaces the fields in the wire types the spec fixes
/// and rejects shape-level violations of the data model (a non-object document, a <c>verificationMethod</c>
/// field that is present but not an array, a <c>prevDIDDocumentSelfHash</c> that is present but neither
/// <c>null</c> nor a string) by throwing, satisfying step 2 of the validation algorithm. The lenient
/// method-polymorphic deserialization used for general ingest is the <c>DidDocumentConverter</c>.
/// </remarks>
public static class WebPlusDidDocumentJson
{
    private static string IdProperty { get; } = WellKnownWebPlusValues.IdField;
    private static string SelfHashProperty { get; } = WellKnownWebPlusValues.SelfHashField;
    private static string PrevDidDocumentSelfHashProperty { get; } = WellKnownWebPlusValues.PrevDidDocumentSelfHashField;
    private static string UpdateRulesProperty { get; } = WellKnownWebPlusValues.UpdateRulesField;
    private static string ValidFromProperty { get; } = WellKnownWebPlusValues.ValidFromField;
    private static string VersionIdProperty { get; } = WellKnownWebPlusValues.VersionIdField;
    private static string VerificationMethodProperty { get; } = WellKnownWebPlusValues.VerificationMethodField;
    private static string ProofsProperty { get; } = WellKnownWebPlusValues.ProofsField;

    //A self-hashed did:webplus document MUST have one unambiguous byte form, so duplicate property names are
    //rejected (AllowDuplicateProperties = false). RFC 8785 Section 3.1 leaves JCS over duplicate keys undefined,
    //and this verifier hashes the raw received bytes (self-hash slots preserved) while reading field values
    //last-wins through JsonNode; a duplicated member could make those two views disagree, so it is a malformed
    //document rather than a silent last-wins pick.
    private static JsonDocumentOptions StrictParseOptions { get; } = new() { AllowDuplicateProperties = false };


    /// <summary>
    /// The <see cref="WebPlusDidDocumentParser"/> that parses a JCS-serialized DID document into a
    /// <see cref="WebPlusDidDocument"/>.
    /// </summary>
    public static WebPlusDidDocumentParser Parser { get; } = ParseDocument;


    /// <summary>
    /// The <see cref="WebPlusProofExtractor"/> that extracts a document's <c>proofs</c> and the JCS of the
    /// document with <c>proofs</c> removed (the base for the proof-payload reconstruction).
    /// </summary>
    public static WebPlusProofExtractor ProofExtractor { get; } = ExtractProofs;


    /// <summary>
    /// The <see cref="WebPlusJcsCanonicalizer"/> that produces the RFC 8785 JCS canonicalization of a DID
    /// document for the byte-equality validation step.
    /// </summary>
    public static WebPlusJcsCanonicalizer Canonicalizer { get; } = Canonicalize;


    private static WebPlusDidDocument ParseDocument(ReadOnlySpan<byte> jcsDocument)
    {
        JsonObject document = JsonNode.Parse(jcsDocument, nodeOptions: null, StrictParseOptions) as JsonObject
            ?? throw new JsonException("A did:webplus DID document MUST be a JSON object.");

        string? id = OptionalString(document, IdProperty);

        return new WebPlusDidDocument
        {
            Id = id is not null ? new GenericDidMethod(id) : null,
            VerificationMethod = ReadVerificationMethods(document),
            SelfHash = OptionalString(document, SelfHashProperty),
            PrevDidDocumentSelfHash = ReadNullableString(document, PrevDidDocumentSelfHashProperty),
            UpdateRules = ReadUpdateRules(document),
            ValidFrom = OptionalString(document, ValidFromProperty),
            VersionId = ReadUnsignedInteger(document, VersionIdProperty)
        };
    }


    /// <summary>
    /// The proofs (each a detached-payload compact JWS) and JCS(document with the proofs member removed). The
    /// base bytes are the proof-payload S before its self-hash slots are reduced to the placeholder, which the
    /// Core slice finishes with the length-preserving slot substitution (did:webplus Self-Hashed Signed Data).
    /// </summary>
    private static WebPlusProofExtraction ExtractProofs(ReadOnlyMemory<byte> document)
    {
        JsonObject obj = JsonNode.Parse(document.Span, nodeOptions: null, StrictParseOptions) as JsonObject
            ?? throw new JsonException("A did:webplus DID document MUST be a JSON object.");

        ImmutableArray<string> proofs = ReadProofs(obj);

        obj.Remove(ProofsProperty);

        return new WebPlusProofExtraction(
            new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(obj.ToJsonString()), BufferTags.Json),
            proofs);
    }


    /// <summary>
    /// The proofs member, if present, MUST be an array of strings (each a detached-payload compact JWS); an
    /// absent member yields an empty array (a root document carries no proofs).
    /// </summary>
    private static ImmutableArray<string> ReadProofs(JsonObject document)
    {
        if(!document.TryGetPropertyValue(ProofsProperty, out JsonNode? node) || node is null)
        {
            return ImmutableArray<string>.Empty;
        }

        if(node is not JsonArray array)
        {
            throw new JsonException("A did:webplus 'proofs' field MUST be an array.");
        }

        var builder = ImmutableArray.CreateBuilder<string>(array.Count);
        for(int i = 0; i < array.Count; i++)
        {
            if(array[i] is not JsonValue value || value.GetValueKind() != JsonValueKind.String || !value.TryGetValue(out string? proof))
            {
                throw new JsonException("A did:webplus proof MUST be a string (a detached-payload compact JWS).");
            }

            builder.Add(proof);
        }

        return builder.MoveToImmutable();
    }


    /// <summary>
    /// JCS(received). The received bytes are UTF-8 JSON; re-canonicalizing and comparing to the received bytes
    /// decides whether the document was served in its JCS form (Validation of DID Documents, step 1).
    /// </summary>
    private static TaggedMemory<byte> Canonicalize(ReadOnlyMemory<byte> document)
    {
        string json = Encoding.UTF8.GetString(document.Span);

        return new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
    }


    /// <summary>
    /// The verificationMethod field, if present, MUST be an array of objects; each object's id (if any) is read
    /// into a verification method whose id the validation reasons about. An absent field yields null; a
    /// present-but-non-array field is a shape-level data-model violation.
    /// </summary>
    private static VerificationMethod[]? ReadVerificationMethods(JsonObject document)
    {
        if(!document.TryGetPropertyValue(VerificationMethodProperty, out JsonNode? node) || node is null)
        {
            return null;
        }

        if(node is not JsonArray array)
        {
            throw new JsonException("A did:webplus 'verificationMethod' field MUST be an array.");
        }

        var verificationMethods = new VerificationMethod[array.Count];
        for(int i = 0; i < array.Count; i++)
        {
            if(array[i] is not JsonObject verificationMethod)
            {
                throw new JsonException("A did:webplus verification method MUST be a JSON object.");
            }

            verificationMethods[i] = new VerificationMethod { Id = OptionalString(verificationMethod, IdProperty) };
        }

        return verificationMethods;
    }


    /// <summary>
    /// The updateRules value retained verbatim for the presence check; absent or JSON null yields null.
    /// </summary>
    private static JsonNode? ReadUpdateRules(JsonObject document)
    {
        return document.TryGetPropertyValue(UpdateRulesProperty, out JsonNode? node) && node is not null
            ? node
            : null;
    }


    private static string? OptionalString(JsonObject obj, string property)
    {
        return obj.TryGetPropertyValue(property, out JsonNode? node) && node is JsonValue value && value.GetValueKind() == JsonValueKind.String && value.TryGetValue(out string? text)
            ? text
            : null;
    }


    /// <summary>
    /// A field that is absent or JSON null yields null; a string yields its value; any other JSON kind is a
    /// shape-level data-model violation (used for prevDIDDocumentSelfHash, which MUST be null or a string).
    /// </summary>
    private static string? ReadNullableString(JsonObject obj, string property)
    {
        if(!obj.TryGetPropertyValue(property, out JsonNode? node) || node is null)
        {
            return null;
        }

        if(node is JsonValue value && value.GetValueKind() == JsonValueKind.String && value.TryGetValue(out string? text))
        {
            return text;
        }

        throw new JsonException($"A did:webplus '{property}' field MUST be null or a string.");
    }


    /// <summary>
    /// versionId MUST be an unsigned integer: a JSON number that is a non-negative integer. A string, a negative
    /// or non-integral number, or an absent field yields null, which the data-model validation rejects.
    /// </summary>
    private static ulong? ReadUnsignedInteger(JsonObject obj, string property)
    {
        return obj.TryGetPropertyValue(property, out JsonNode? node) && node is JsonValue value && value.GetValueKind() == JsonValueKind.Number && value.TryGetValue(out ulong number)
            ? number
            : null;
    }
}