using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for resolving JSON-LD context documents by URI.
/// </summary>
/// <remarks>
/// <para>
/// This delegate abstracts the retrieval of JSON-LD context documents, allowing implementations
/// to use various strategies such as embedded contexts, HTTP fetching, caching, or combinations thereof.
/// </para>
/// <para>
/// The delegate is used by RDFC canonicalization to resolve <c>@context</c> references during
/// JSON-LD expansion. JCS canonicalization does not require context resolution.
/// </para>
/// <para>
/// <strong>Example implementation with embedded contexts:</strong>
/// </para>
/// <code>
/// ContextResolverDelegate resolver = (uri, cancellationToken) =>
/// {
///     var contextJson = uri.ToString() switch
///     {
///         "https://www.w3.org/ns/credentials/v2" => CredentialsV2ContextJson,
///         "https://www.w3.org/ns/credentials/examples/v2" => ExamplesV2ContextJson,
///         _ => null
///     };
///     return ValueTask.FromResult(contextJson);
/// };
/// </code>
/// </remarks>
/// <param name="contextUri">The URI of the JSON-LD context to resolve.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// A task that resolves to the context JSON string, or <c>null</c> if the context cannot be resolved.
/// </returns>
public delegate ValueTask<string?> ContextResolverDelegate(Uri contextUri, CancellationToken cancellationToken = default);


/// <summary>
/// The result of canonicalizing a JSON or JSON-LD document.
/// </summary>
/// <remarks>
/// <para>
/// For RDFC-1.0 canonicalization, the result includes both the canonical N-Quads string
/// and the label map produced by the canonicalization algorithm. The label map maps
/// canonical blank node identifiers (e.g., <c>"c14n0"</c>) to the original blank node
/// identifiers from the input document.
/// </para>
/// <para>
/// For JCS canonicalization, only <see cref="CanonicalForm"/> is populated; there is no
/// blank node relabeling and <see cref="LabelMap"/> is <see langword="null"/>.
/// </para>
/// <para>
/// The label map is essential for selective disclosure cryptosuites such as ecdsa-sd-2023,
/// where the reduced credential is canonicalized independently and produces different
/// canonical identifiers than the full credential. The label maps from both canonicalizations
/// can be joined through their shared original blank node identifiers to compute the correct
/// mapping between reduced canonical IDs and the full credential's HMAC-derived labels.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/rdf-canon/#canon-algorithm">
/// RDF Dataset Canonicalization §4.5 Canonicalization Algorithm</see>.
/// </para>
/// </remarks>
public sealed class CanonicalizationResult
{
    /// <summary>
    /// The canonical string representation. For RDFC-1.0 this is N-Quads;
    /// for JCS this is canonical JSON.
    /// </summary>
    public required string CanonicalForm { get; init; }

    /// <summary>
    /// The RDFC label map mapping canonical blank node identifiers (e.g., <c>"_:c14n0"</c>)
    /// to original blank node identifiers (e.g., <c>"_:b0"</c>) from the input document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <see langword="null"/> for JCS canonicalization which does not perform
    /// blank node relabeling. For RDFC-1.0, this is the issued identifiers map from
    /// the canonicalization algorithm output.
    /// </para>
    /// <para>
    /// Per the RDFC specification (W3C Recommendation §4.3), identifiers include the
    /// <c>"_:"</c> blank node prefix (e.g., <c>"_:c14n0"</c>, not <c>"c14n0"</c>).
    /// </para>
    /// <para>
    /// Note that <see cref="BlankNodeRelabeling"/> uses bare identifiers without the
    /// <c>"_:"</c> prefix for its HMAC label maps. Consumers joining RDFC and HMAC label
    /// maps must account for this difference.
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<string, string>? LabelMap { get; init; }
}


/// <summary>
/// Delegate for canonicalizing JSON documents to a deterministic string representation.
/// </summary>
/// <remarks>
/// <para>
/// Canonicalization transforms a JSON document into a deterministic, normalized form suitable
/// for cryptographic hashing. Different canonicalization algorithms produce different outputs:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>JCS (JSON Canonicalization Scheme, RFC 8785)</strong>: Produces canonical JSON.
/// Does not require context resolution. All JSON properties are included.
/// The returned <see cref="CanonicalizationResult.LabelMap"/> is <see langword="null"/>.
/// </description></item>
/// <item><description>
/// <strong>RDFC-1.0 (RDF Dataset Canonicalization)</strong>: Produces canonical N-Quads
/// and a label map from canonical blank node identifiers to original identifiers.
/// Requires context resolution for JSON-LD expansion. Only properties defined in
/// <c>@context</c> are included.
/// </description></item>
/// </list>
/// <para>
/// <strong>Example JCS implementation:</strong>
/// </para>
/// <code>
/// CanonicalizationDelegate jcsCanonicalizer = (json, contextResolver, cancellationToken) =>
/// {
///     //JCS ignores the context resolver and produces no label map.
///     var result = new CanonicalizationResult
///     {
///         CanonicalForm = Jcs.Canonicalize(json)
///     };
///     return ValueTask.FromResult(result);
/// };
/// </code>
/// <para>
/// <strong>Example RDFC implementation (using dotNetRdf):</strong>
/// </para>
/// <code>
/// CanonicalizationDelegate rdfcCanonicalizer = async (json, contextResolver, cancellationToken) =>
/// {
///     var store = new TripleStore();
///     var options = new JsonLdProcessorOptions
///     {
///         DocumentLoader = async (uri, _) =>
///         {
///             var doc = await contextResolver(uri, cancellationToken);
///             return new RemoteDocument { DocumentUrl = uri, Document = doc };
///         }
///     };
///     var parser = new JsonLdParser(options);
///     parser.Load(store, new StringReader(json));
///     var canonResult = new RdfCanonicalizer().Canonicalize(store);
///     return new CanonicalizationResult
///     {
///         CanonicalForm = canonResult.SerializedNQuads,
///         LabelMap = canonResult.IssuedIdentifierMap
///     };
/// };
/// </code>
/// </remarks>
/// <param name="json">The JSON document to canonicalize.</param>
/// <param name="contextResolver">
/// Optional delegate for resolving JSON-LD contexts. Required for RDFC canonicalization,
/// ignored by JCS canonicalization.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>A task that resolves to the canonicalization result.</returns>
public delegate ValueTask<CanonicalizationResult> CanonicalizationDelegate(
    string json,
    ContextResolverDelegate? contextResolver,
    CancellationToken cancellationToken = default);


/// <summary>
/// Delegate for encoding a signature to a proof value string.
/// </summary>
/// <remarks>
/// <para>
/// Data Integrity proofs encode signatures using multibase encoding, typically Base58Btc.
/// This delegate takes all required parameters explicitly, allowing stateless implementations.
/// </para>
/// <para>
/// <strong>Example usage with MultibaseSerializer:</strong>
/// </para>
/// <code>
/// //Using the library-provided implementation.
/// var proofValue = ProofValueCodecs.EncodeBase58Btc(signatureBytes, base58Encoder, pool);
/// </code>
/// </remarks>
/// <param name="signatureBytes">The raw signature bytes to encode.</param>
/// <param name="encoder">The encoding delegate (e.g., Base58 encoder).</param>
/// <param name="pool">Memory pool for temporary allocations.</param>
/// <returns>The encoded proof value string (e.g., multibase-encoded with 'z' prefix).</returns>
public delegate string ProofValueEncoderDelegate(
    ReadOnlySpan<byte> signatureBytes,
    EncodeDelegate encoder,
    MemoryPool<byte> pool);


/// <summary>
/// Delegate for decoding a proof value string to signature bytes.
/// </summary>
/// <remarks>
/// <para>
/// This is the inverse of <see cref="ProofValueEncoderDelegate"/>, used during verification
/// to extract the raw signature bytes from the proof value.
/// </para>
/// <para>
/// <strong>Example usage with MultibaseSerializer:</strong>
/// </para>
/// <code>
/// //Using the library-provided implementation.
/// using var signatureBytes = ProofValueCodecs.DecodeBase58Btc(proofValue, base58Decoder, pool);
/// </code>
/// </remarks>
/// <param name="proofValue">The encoded proof value string.</param>
/// <param name="decoder">The decoding delegate (e.g., Base58 decoder).</param>
/// <param name="pool">Memory pool for allocating the decoded bytes.</param>
/// <returns>The decoded signature bytes. The caller must dispose the returned memory.</returns>
public delegate IMemoryOwner<byte> ProofValueDecoderDelegate(
    string proofValue,
    DecodeDelegate decoder,
    MemoryPool<byte> pool);