using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for resolving a JSON-LD context document by its IRI.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="CanonicalizationDelegate"/> that performs RDFC-1.0 canonicalization calls this
/// delegate once per <c>@context</c> IRI it encounters while expanding a JSON-LD document, to
/// obtain that context's JSON text. JCS canonicalization does not perform JSON-LD expansion and
/// never calls it.
/// </para>
/// <para>
/// <strong>The library never fetches or caches a context document itself.</strong> This delegate
/// is the entire seam: every implementation — reading an embedded string, a file, an Orleans
/// grain, a database row, a remote HTTP fetch, or a combination of these — is supplied by the
/// caller. Storage and retrieval are the caller's choice; the library recommends none of these
/// mechanisms over another.
/// </para>
/// <para>
/// A <see langword="null"/> result is never inspected by the library. It is forwarded, together
/// with this delegate, to whichever <see cref="CanonicalizationDelegate"/> the caller wired; that
/// canonicalizer decides how to treat an unresolved context, for example by failing JSON-LD
/// expansion on the first <c>@context</c> it cannot resolve.
/// </para>
/// <para>
/// <strong>What an implementation owns:</strong> a JSON-LD context document defines what the
/// signed document's terms mean, so resolving the wrong document, or a tampered one, changes what
/// a proof appears to attest to without changing its bytes. VC Data Model 2.0 requires that
/// "<see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">application developers MUST
/// understand every JSON-LD context used by their application, at least to the extent that it
/// affects the meaning of the terms used by their application</see>", and VC Data Integrity 1.0's
/// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">context validation
/// algorithm</see> treats a dereferenced context that "does not match a known good value or
/// cryptographic hash" as invalid. An implementation of this delegate owns matching each resolved
/// document against the caller's expected identity for <paramref name="contextUri"/> and, wherever
/// the storage or transport can be tampered with, that document's integrity. VC Data Integrity 1.0
/// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">names local copies of
/// approved context files, or a list of well-known context URLs paired with approved cryptographic
/// hashes, as two mechanisms that satisfy this</see> — without preferring either.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#base-context">Appendix B.1 Base
/// Context</see> requires implementations to treat the base context, at
/// <c>https://www.w3.org/ns/credentials/v2</c>, as already retrieved, and publishes its SHA-256
/// digest; an implementation of this delegate answers that IRI with the published document, whose
/// digest a caller can check.
/// </para>
/// <para>
/// An implementation receives <paramref name="cancellationToken"/> and must honor it. A resolver
/// that reaches outside the process — a remote fetch, a slow store — is exactly where VC Data
/// Integrity 1.0 <see href="https://www.w3.org/TR/vc-data-integrity/#network-requests">asks
/// implementers to cache aggressively and use defensive measures against denial-of-service during
/// any process that might fetch a resource from the network</see>. A remote implementation is
/// outbound network access driven by <paramref name="contextUri"/>, a value that traces back to
/// the input document rather than to the caller's own configuration; see <paramref name="context"/>
/// for how such a fetch carries the per-call SSRF policy.
/// </para>
/// </remarks>
/// <param name="contextUri">The IRI of the JSON-LD context to resolve.</param>
/// <param name="context">
/// The per-operation <see cref="ExchangeContext"/>. An implementation that fetches the
/// context over the network routes the dereference through the guarded outbound fetch,
/// which reads the SSRF <c>OutboundFetchPolicy</c> off this context — so the policy
/// arrives as an explicit per-call argument rather than a captured closure.
/// </param>
/// <param name="cancellationToken">The token an implementation observes to cancel an in-flight resolution.</param>
/// <returns>
/// A task that resolves to the context document's JSON text, or <see langword="null"/> if the
/// implementation could not resolve <paramref name="contextUri"/>.
/// </returns>
public delegate ValueTask<string?> ContextResolverDelegate(Uri contextUri, ExchangeContext context, CancellationToken cancellationToken = default);


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
    /// The RDFC label map mapping canonical blank node identifiers (e.g., <c>"c14n0"</c>)
    /// to original blank node identifiers (e.g., <c>"b0"</c>) from the input document,
    /// as bare identifiers without the <c>"_:"</c> prefix.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <see langword="null"/> for JCS canonicalization which does not perform
    /// blank node relabeling. For RDFC-1.0, this is the issued identifiers map from
    /// the canonicalization algorithm output, inverted to canonical-to-original
    /// orientation.
    /// </para>
    /// <para>
    /// The bare form matches the identifiers <see cref="BlankNodeRelabeling"/> uses for its
    /// HMAC label maps, so RDFC and HMAC label maps join without prefix adjustment.
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<string, string>? LabelMap { get; init; }
}


/// <summary>
/// Delegate for canonicalizing a JSON or JSON-LD document to a deterministic string representation.
/// </summary>
/// <remarks>
/// <para>
/// Canonicalization transforms a document into a deterministic, normalized form suitable
/// for cryptographic hashing. The library declares this seam and calls it from every Data
/// Integrity signing and verification path; it does not implement or ship a canonicalization
/// engine, so the caller wires any conformant implementation of the algorithm its
/// <c>cryptosuite</c> requires:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>JCS (JSON Canonicalization Scheme, RFC 8785)</strong>: Produces canonical JSON.
/// Does not require context resolution and never calls <paramref name="contextResolver"/>.
/// All JSON properties are included. The returned <see cref="CanonicalizationResult.LabelMap"/>
/// is <see langword="null"/>.
/// </description></item>
/// <item><description>
/// <strong>RDFC-1.0 (RDF Dataset Canonicalization)</strong>: Produces canonical N-Quads
/// and a label map from canonical blank node identifiers to original identifiers. Only
/// properties mapped by <c>@context</c> are included; an implementation resolves every
/// context it needs through <paramref name="contextResolver"/> and never on its own — the
/// same "no package" rule this delegate follows applies one level down.
/// </description></item>
/// </list>
/// <para>
/// <strong>Wiring an RDFC-1.0 implementation:</strong> parse the JSON text; expand it as
/// JSON-LD 1.1, resolving every remote <c>@context</c> through <paramref name="contextResolver"/>
/// so the per-call <paramref name="context"/> rides each resolution; convert the expanded
/// document to an RDF dataset; canonicalize that dataset per RDFC-1.0; return the resulting
/// canonical N-Quads and the algorithm's issued-identifiers map as
/// <see cref="CanonicalizationResult.CanonicalForm"/> and <see cref="CanonicalizationResult.LabelMap"/>.
/// </para>
/// <para>
/// <strong>The RDFC-1.0 hash.</strong> RDFC-1.0's own algorithm hashes intermediate data (for
/// example, to label blank nodes) using a
/// <see href="https://www.w3.org/TR/rdf-canon/#dfn-hash-algorithm">hash algorithm that defaults to
/// SHA-256, with implementations required to support a way to select SHA-256 and SHA-384</see>.
/// An implementation computes this hash through the registered
/// <see cref="Verifiable.Cryptography.HashFunctionDelegate"/> seam, for example via
/// <see cref="Verifiable.Cryptography.CryptographicKeyEvents.ComputeDigest(ReadOnlySpan{byte}, int, Tag, BaseMemoryPool, string?)"/>,
/// so that a replaced cryptography backend applies here too. This is a separate hash from the one
/// a cryptosuite later computes over <see cref="CanonicalizationResult.CanonicalForm"/> through
/// <see cref="Verifiable.Cryptography.ComputeDigestDelegate"/> to build the proof: RDF Dataset
/// Canonicalization notes "there is no expectation that the default hash algorithm will also be
/// used by any application creating a hash digest of the canonical N-Quads result".
/// </para>
/// <para>
/// <strong>Determinism.</strong> RDFC-1.0 is, by definition, a
/// <see href="https://www.w3.org/TR/rdf-canon/#dfn-canonicalization-function">canonicalization
/// function: it maps RDF datasets into isomorphic datasets, and two datasets produce the same
/// canonical result if and only if they are isomorphic</see>. An implementation preserves that:
/// the same input dataset always canonicalizes to the same <see cref="CanonicalizationResult"/>.
/// </para>
/// <para>
/// An implementation receives <paramref name="cancellationToken"/> and must honor it, both for the
/// canonicalization work itself and for any resolution it awaits through
/// <paramref name="contextResolver"/>.
/// </para>
/// <para>
/// <strong>What consuming cryptosuites refuse:</strong> a document that canonicalizes to zero
/// statements would let a base proof cover nothing while still verifying, so bbs-2023's
/// <see cref="CredentialBbs2023Extensions.extension(Verifiable.Core.Model.Credentials.VerifiableCredential).CreateBaseProofVerboseAsync(ReadOnlyMemory{byte}, string, DateTime, IReadOnlyList{Verifiable.Core.Model.SelectiveDisclosure.CredentialPath}, HmacKeyGeneratorDelegate, PartitionStatementsDelegate, CanonicalizationDelegate, ContextResolverDelegate?, CredentialSerializeDelegate, CredentialDeserializeDelegate, ProofOptionsSerializeDelegate, SerializeBbsBaseProofDelegate, BbsSignDelegate, EncodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/>
/// and ecdsa-sd-2023's
/// <see cref="CredentialEcdsaSd2023Extensions.extension(Verifiable.Core.Model.Credentials.VerifiableCredential).CreateBaseProofVerboseAsync(PrivateKeyMemory, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, string, DateTime, IReadOnlyList{Verifiable.Core.Model.SelectiveDisclosure.CredentialPath}, HmacKeyGeneratorDelegate, PartitionStatementsDelegate, CanonicalizationDelegate, ContextResolverDelegate?, CredentialSerializeDelegate, CredentialDeserializeDelegate, ProofOptionsSerializeDelegate, SerializeBaseProofDelegate, EncodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/>
/// both refuse to mint a base proof over such a result with an <see cref="InvalidOperationException"/>.
/// </para>
/// </remarks>
/// <param name="json">The JSON or JSON-LD document to canonicalize.</param>
/// <param name="contextResolver">
/// Delegate for resolving JSON-LD contexts. Required for RDFC-1.0 canonicalization, which calls
/// it once per <c>@context</c> IRI it encounters and never fetches or caches a context itself;
/// ignored by JCS canonicalization.
/// </param>
/// <param name="context">
/// The per-operation <see cref="ExchangeContext"/>, forwarded to
/// <paramref name="contextResolver"/> so a network-fetching resolver applies the SSRF
/// <c>OutboundFetchPolicy</c> it carries.
/// </param>
/// <param name="cancellationToken">The token an implementation observes to cancel canonicalization and any context resolution it awaits.</param>
/// <returns>A task that resolves to the canonicalization result.</returns>
public delegate ValueTask<CanonicalizationResult> CanonicalizationDelegate(
    string json,
    ContextResolverDelegate? contextResolver,
    ExchangeContext context,
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
    BaseMemoryPool pool);


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
    BaseMemoryPool pool);
