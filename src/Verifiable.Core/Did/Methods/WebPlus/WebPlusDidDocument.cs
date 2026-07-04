using System;
using System.Collections.Immutable;
using Verifiable.Core.Model.Did;
using Verifiable.Foundation;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// A did:webplus DID document: a W3C <see cref="DidDocument"/> with the additional members the did:webplus
/// method fixes (did:webplus Draft v0.4, DID Document Data Model). The method-specific control fields are
/// surfaced as typed properties; the W3C core members (<c>id</c>, <c>verificationMethod</c>, the verification
/// relationships, <c>service</c>) are inherited from the base, and any further members ride
/// <see cref="DidDocument.AdditionalData"/>.
/// </summary>
/// <remarks>
/// A document is a <em>root</em> document exactly when <see cref="PrevDidDocumentSelfHash"/> is
/// <see langword="null"/> (the field is absent or JSON <c>null</c>); otherwise it is a non-root document
/// (did:webplus Draft v0.4, Validation of DID Documents: classification by the <c>prevDIDDocumentSelfHash</c>
/// field). Method-polymorphic deserialization materializes a received <c>did:webplus</c> document as this type;
/// the verifier validates it through <see cref="WebPlusDataModelValidation"/> over the received wire bytes.
/// </remarks>
public sealed class WebPlusDidDocument: DidDocument
{
    /// <summary>The <c>selfHash</c> field (an MBHash self-hash), or <see langword="null"/> when absent or not a string.</summary>
    public string? SelfHash { get; set; }

    /// <summary>
    /// The <c>prevDIDDocumentSelfHash</c> field (the predecessor's <c>selfHash</c>), or <see langword="null"/>
    /// when the field is absent or JSON <c>null</c> — which marks a root document.
    /// </summary>
    public string? PrevDidDocumentSelfHash { get; set; }

    /// <summary>
    /// The <c>updateRules</c> value, retained verbatim. Its structural validity as an UpdateRules expression is
    /// verified by the update-rules slice; the data model only requires its presence (a non-<see langword="null"/>
    /// value).
    /// </summary>
    public object? UpdateRules { get; set; }

    /// <summary>The raw <c>validFrom</c> timestamp string, or <see langword="null"/> when absent or not a string.</summary>
    public string? ValidFrom { get; set; }

    /// <summary>
    /// The <c>versionId</c> field when it is a JSON number that is a non-negative integer; otherwise
    /// <see langword="null"/> (absent, a string, negative, or non-integral), which the data model rejects.
    /// </summary>
    public ulong? VersionId { get; set; }
}


/// <summary>
/// Parses a JCS-serialized did:webplus DID document into a <see cref="WebPlusDidDocument"/> for the strict
/// verification path.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf, which owns JSON parsing so <see cref="Verifiable.Core"/>
/// takes no serializer dependency. This is the strict verifier parse: it surfaces the fields in their wire
/// types and rejects shape-level violations of the data model (for example a <c>verificationMethod</c> field
/// that is present but not an array) by throwing. It is distinct from the lenient method-polymorphic converter
/// used for general deserialization.
/// </remarks>
/// <param name="jcsDocument">The UTF-8 JCS bytes of the DID document.</param>
/// <returns>The parsed document.</returns>
public delegate WebPlusDidDocument WebPlusDidDocumentParser(ReadOnlySpan<byte> jcsDocument);


/// <summary>
/// Produces the RFC 8785 JCS canonicalization of a did:webplus DID document, used to verify that a received
/// document equals its JCS-serialized form (did:webplus Draft v0.4, Validation of DID Documents, step 1).
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf. The result wraps the JCS serializer output in a
/// <see cref="TaggedMemory{T}"/> tagged as JSON — the tagged-buffer idiom the JOSE layer uses for its
/// serialized parts — so the bytes carry their content kind without a copy into a pool.
/// </remarks>
/// <param name="document">The received DID document bytes to canonicalize.</param>
/// <returns>The JCS-canonical bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebPlusJcsCanonicalizer(ReadOnlyMemory<byte> document);


/// <summary>
/// The <c>proofs</c> of a did:webplus DID document together with the canonical bytes a proof signs over: the
/// JCS of the document with its <c>proofs</c> member removed, before the self-hash slots are reduced to the
/// placeholder (did:webplus Draft v0.4, Self-Hashed Signed Data).
/// </summary>
/// <param name="SigningInputBase">JCS of the document with <c>proofs</c> removed; the proof-payload reconstruction sets its self-hash slots to the placeholder.</param>
/// <param name="Proofs">Each <c>proofs</c> entry verbatim — a detached-payload compact JWS.</param>
public readonly record struct WebPlusProofExtraction(TaggedMemory<byte> SigningInputBase, ImmutableArray<string> Proofs);


/// <summary>
/// Extracts a did:webplus document's <c>proofs</c> and the canonical bytes those proofs sign over.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf, which owns JSON parsing and RFC 8785 canonicalization so
/// <see cref="Verifiable.Core"/> takes no serializer dependency. The proof payload itself — JCS of the document
/// with <c>proofs</c> removed AND every self-hash slot set to the placeholder — is finished in
/// <see cref="Verifiable.Core"/> by the length-preserving slot substitution shared with self-hash verification.
/// </remarks>
/// <param name="document">The received DID document bytes.</param>
/// <returns>The extracted proofs and signing-input base.</returns>
public delegate WebPlusProofExtraction WebPlusProofExtractor(ReadOnlyMemory<byte> document);


/// <summary>
/// Serializes a <see cref="WebPlusDidDocument"/> to its RFC 8785 JCS canonical bytes — the wire form of a
/// microledger line. This is the mint-side counterpart of <see cref="WebPlusDidDocumentParser"/>, used by the
/// did:webplus controller/builder side to produce a document for self-hashing and publication.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf (which owns the method-polymorphic <c>DidDocumentConverter</c>
/// that emits the typed control fields, plus RFC 8785 canonicalization), so <see cref="Verifiable.Core"/> takes
/// no serializer dependency. The result wraps the JCS bytes in a <see cref="TaggedMemory{T}"/> tagged as JSON,
/// the same tagged-buffer idiom the canonicalizer uses.
/// </remarks>
/// <param name="document">The DID document to serialize.</param>
/// <returns>The document's JCS canonical bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebPlusDidDocumentSerializer(WebPlusDidDocument document);


/// <summary>
/// Deserializes a resolved did:webplus microledger line (a JCS-serialized DID document) into a full
/// <see cref="DidDocument"/> for return to the caller — the resolved document the resolver hands back once the
/// microledger has been replayed and verified.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf via the lenient method-polymorphic
/// <c>DidDocumentConverter</c>, which materializes a <c>did:webplus</c> <c>id</c> as a typed
/// <see cref="WebPlusDidDocument"/> carrying every W3C core member (verification methods, services, the
/// verification relationships). This is distinct from the strict <see cref="WebPlusDidDocumentParser"/>, which
/// surfaces only the control fields the verifier reasons about. A malformed line yields <see langword="null"/>,
/// which the resolver maps to an invalid-DID failure rather than an exception.
/// </remarks>
/// <param name="jcsDocument">The UTF-8 JCS bytes of the resolved DID document.</param>
/// <returns>The deserialized DID document, or <see langword="null"/> when the bytes are malformed.</returns>
public delegate DidDocument? WebPlusDocumentDeserializer(ReadOnlySpan<byte> jcsDocument);
