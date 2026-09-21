using Lumoin.Veritas.Canonicalization;
using Lumoin.Veritas.Json.Stj;
using Lumoin.Veritas.JsonLd;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Provides canonicalization utilities for Data Integrity proofs in Verifiable Credentials.
/// </summary>
/// <remarks>
/// <para>
/// <strong>W3C Data Integrity Specification Requirements</strong>
/// </para>
/// <para>
/// Per <see href="https://www.w3.org/TR/vc-data-integrity/">W3C Verifiable Credential Data Integrity 1.0</see>,
/// a context document defines what a signed document's terms mean, so resolving the wrong one, or
/// a tampered one, changes what a proof appears to attest to. The specification describes several
/// equivalent ways to guard against this:
/// </para>
/// <list type="number">
/// <item>
/// <description>
/// Use only local copies of approved context files, so neither the files nor their hashes can
/// change in transit. This is the approach taken by <see cref="CreateTestContextResolver"/>.
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">§2.4.1 Validating Contexts</see>.
/// </description>
/// </item>
/// <item>
/// <description>
/// Keep a list of well-known context URLs paired with their approved cryptographic hashes, and
/// verify a fetched document against that list before using it.
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context Validation</see>.
/// </description>
/// </item>
/// <item>
/// <description>
/// Cache aggressively and defend against denial-of-service wherever a context must still be
/// fetched from the network.
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#network-requests">§5.14 Network Requests</see>.
/// </description>
/// </item>
/// </list>
/// <para>
/// The test utilities in this class use embedded, pre-validated context documents to:
/// </para>
/// <list type="bullet">
/// <item><description>Ensure deterministic test behavior (no network dependencies)</description></item>
/// <item><description>Prevent test flakiness from network issues</description></item>
/// <item><description>Guarantee context integrity (embedded documents are immutable)</description></item>
/// <item><description>Enable offline testing</description></item>
/// </list>
/// <para>
/// See <see cref="ContextResolverDelegate"/> for what a production implementation of this seam owns.
/// </para>
/// </remarks>
internal static class CanonicalizationTestUtilities
{
    /// <summary>
    /// W3C Verifiable Credentials Data Model v2.0 context URL.
    /// </summary>
    public const string CredentialsV2ContextUrl = "https://www.w3.org/ns/credentials/v2";

    /// <summary>
    /// W3C Verifiable Credentials Examples v2 context URL.
    /// </summary>
    public const string CredentialsExamplesV2ContextUrl = "https://www.w3.org/ns/credentials/examples/v2";

    /// <summary>
    /// W3C CCG Citizenship Vocabulary v4rc1 context URL.
    /// </summary>
    /// <remarks>
    /// Used by W3C ecdsa-sd-2023 test vectors for Employment Authorization Document credentials.
    /// </remarks>
    public const string CitizenshipV4Rc1ContextUrl = "https://w3id.org/citizenship/v4rc1";



    /// <summary>
    /// W3C Verifiable Credentials Examples v2 context document.
    /// </summary>
    /// <remarks>
    /// Source: <see href="https://www.w3.org/ns/credentials/examples/v2"/>.
    /// This is an embedded copy for test determinism and offline operation.
    /// </remarks>
    public static string CredentialsExamplesV2ContextJson { get; } =
        /*lang=json,strict*/
        """
        {
          "@context": {
            "@vocab": "https://www.w3.org/ns/credentials/examples#"
          }
        }
        """;

    /// <summary>
    /// Expected SHA-256 hash of the W3C Credentials v2 base context document.
    /// </summary>
    /// <remarks>
    /// This is the literal digest published by
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#base-context">Appendix B.1 Base Context</see>
    /// for the document at <see href="https://www.w3.org/ns/credentials/v2"/>, not a value computed
    /// from the embedded text it is meant to check.
    /// </remarks>
    public static string CredentialsV2ContextSha256 { get; } = "59955CED6697D61E03F2B2556FEBE5308AB16842846F5B586D7F1F7ADEC92734";

    /// <summary>
    /// Expected SHA-256 hash of the W3C Credentials Examples v2 context document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Source: <see href="https://www.w3.org/ns/credentials/examples/v2"/>, retrieved 2026-09-17.
    /// The live document matched <see cref="CredentialsExamplesV2ContextJson"/> byte for byte at
    /// that date, so this is the literal SHA-256 hex digest of that content rather than a value
    /// computed from the embedded text it is meant to check.
    /// </para>
    /// </remarks>
    public static string CredentialsExamplesV2ContextSha256 { get; } = "58D3EB0C82FF326381C11710FB6728245849089A8B000896A3BC07C882AC0E89";


    /// <summary>
    /// Creates an RDFC-1.0 canonicalization delegate backed by the Lumoin.Veritas RDF stack.
    /// </summary>
    /// <returns>A canonicalization delegate for RDF Dataset Canonicalization.</returns>
    /// <remarks>
    /// <para>
    /// This delegate implements the RDF Dataset Canonicalization Algorithm (RDFC-1.0)
    /// as specified in <see href="https://www.w3.org/TR/rdf-canon/">RDF Dataset Canonicalization</see>.
    /// </para>
    /// <para>
    /// The canonicalization process:
    /// </para>
    /// <list type="number">
    /// <item><description>Parses the JSON-LD document and expands it (JSON-LD 1.1), resolving every
    /// remote <c>@context</c> asynchronously through the caller's resolver so the per-call
    /// <see cref="ExchangeContext"/> rides each fetch.</description></item>
    /// <item><description>Serializes the expanded document to RDF quads.</description></item>
    /// <item><description>Applies the RDFC-1.0 canonicalization algorithm with SHA-256 and
    /// serializes to sorted canonical N-Quads.</description></item>
    /// </list>
    /// <para>
    /// <strong>Context Resolution Security:</strong> The context resolver MUST ensure integrity
    /// of fetched contexts as per <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation"/>.
    /// </para>
    /// </remarks>
    public static CanonicalizationDelegate CreateRdfcCanonicalizer()
    {
        return async (json, contextResolver, context, cancellationToken) =>
        {
            //The bridge carries the per-call ExchangeContext into every remote @context fetch;
            //a null resolver resolves nothing, and expansion fails on the first remote context.
            async ValueTask<Utf8String?> resolveContext(Uri uri, CancellationToken resolveCancellation)
            {
                string? resolved = contextResolver == null
                    ? null
                    : await contextResolver(uri, context, resolveCancellation).ConfigureAwait(false);

                return resolved == null ? null : Utf8StringInterner.Shared.Intern(resolved);
            }

            var document = StjJsonAdapter.Parse(Utf8StringInterner.Shared.Intern(json));
            var expanded = await JsonLdExpansionTree.ExpandAsync(
                document,
                baseUrl: null,
resolveContext,
                StjJsonAdapter.Parse,
                cancellationToken).ConfigureAwait(false);

            using var pool = new Utf8StringPool();

            //The serializer issues blank labels per serialization in encounter order and exposes the
            //document-to-issued map; the derive flows' full-vs-reduced label-map join rides those
            //per-document labels.
            JsonLdRdfSerializationResult serialized = JsonLdRdfSerializer.Serialize(expanded, pool);

            //RDFC-1.0 requires SHA-256; hashViaSeam resolves the registered HashFunctionDelegate rather than
            //calling a framework hash function directly. A false return is the canonicalizer's work-budget
            //refusal for a poison graph.
            static int hashViaSeam(ReadOnlySpan<byte> data, Span<byte> destination)
            {
                using DigestValue digest = CryptographicKeyEvents.ComputeDigest(data, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared);
                digest.AsReadOnlySpan().CopyTo(destination);

                return digest.Length;
            }

            if(!RdfCanonicalizer.TryCanonicalizeWithMap(serialized.Quads, hashViaSeam, out RdfCanonicalizationResult? canonicalized))
            {
                throw new InvalidOperationException(
                    "RDF canonicalization exceeded its work budget: the dataset's blank-node structure is a poison graph.");
            }

            //IssuedIdentifiers maps original blank-node label → canonical c14nN label. LabelMap
            //carries the inverse orientation, canonical → original, as bare identifiers matching
            //BlankNodeRelabeling's HMAC label maps.
            Dictionary<string, string>? labelMap = null;
            if(canonicalized.IssuedIdentifiers is { Count: > 0 } issuedMap)
            {
                labelMap = new Dictionary<string, string>(issuedMap.Count, StringComparer.Ordinal);
                foreach(var (originalId, canonicalId) in issuedMap)
                {
                    labelMap[StripBlankNodePrefix(canonicalId)] = StripBlankNodePrefix(originalId);
                }
            }

            return new CanonicalizationResult
            {
                CanonicalForm = canonicalized.Canonical,
                LabelMap = labelMap
            };
        };
    }

    /// <summary>
    /// Creates a test context resolver that uses embedded context documents.
    /// </summary>
    /// <returns>A context resolver suitable for testing.</returns>
    /// <remarks>
    /// <para>
    /// This resolver returns embedded copies of W3C contexts for:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Deterministic test behavior.</description></item>
    /// <item><description>Offline operation.</description></item>
    /// <item><description>No network dependencies.</description></item>
    /// </list>
    /// <para>
    /// <strong>Production Use:</strong> a production implementation of
    /// <see cref="ContextResolverDelegate"/> is the caller's; it may read from a file store, an
    /// Orleans grain, a database, a remote fetch, or a combination of these, and owns matching
    /// each resolved document against its expected identity and integrity.
    /// </para>
    /// <para>
    /// <strong>Note:</strong> This resolver always returns synchronously from embedded resources,
    /// so no cache pre-warming is required for tests.
    /// </para>
    /// </remarks>
    public static ContextResolverDelegate CreateTestContextResolver()
    {
        return (uri, context, cancellationToken) =>
        {
            var contextJson = uri.ToString() switch
            {
                CredentialsV2ContextUrl => EmbeddedContextDocuments.CredentialsV2ContextJson,
                CredentialsExamplesV2ContextUrl => CredentialsExamplesV2ContextJson,
                CitizenshipV4Rc1ContextUrl => EmbeddedContextDocuments.CitizenshipV4Rc1ContextJson,
                _ => null
            };

            return ValueTask.FromResult(contextJson);
        };
    }

    /// <summary>
    /// Computes the SHA-256 hash of a context document.
    /// </summary>
    /// <param name="contextJson">The JSON-LD context document.</param>
    /// <returns>Lowercase hexadecimal SHA-256 hash.</returns>
    /// <remarks>
    /// <para>
    /// This hash can be used to verify context integrity as per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation"/>.
    /// </para>
    /// <para>
    /// <strong>Usage in Production:</strong> Compare this hash against known good values
    /// before using a context document in credential processing.
    /// </para>
    /// <para>
    /// <strong>Verification:</strong> To verify a remote context matches the expected hash:
    /// </para>
    /// <code>
    /// curl -s https://www.w3.org/ns/credentials/v2 | openssl dgst -sha256
    /// </code>
    /// </remarks>
    public static string ComputeContextHash(string contextJson)
    {
        var bytes = Encoding.UTF8.GetBytes(contextJson);
        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(bytes, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared);

        return Convert.ToHexString(digest.AsReadOnlySpan()).ToUpperInvariant();
    }

    /// <summary>
    /// Strips the <c>"_:"</c> prefix from a blank node identifier if present.
    /// </summary>
    /// <param name="identifier">The blank node identifier, possibly with <c>"_:"</c> prefix.</param>
    /// <returns>The bare identifier (e.g., <c>"c14n0"</c> or <c>"b0"</c>).</returns>
    private static string StripBlankNodePrefix(string identifier) =>
        identifier.StartsWith("_:", StringComparison.Ordinal)
            ? identifier[2..]
            : identifier;


    /// <summary>Serializes <paramref name="credential"/> with <see cref="TestSetup.DefaultSerializationOptions"/>, for the BBS/ecdsa-sd spec-vector round trip.</summary>
    /// <param name="credential">The credential to serialize.</param>
    /// <returns>The serialized JSON text.</returns>
    public static string SerializeCredential(VerifiableCredential credential) =>
        JsonSerializerExtensions.Serialize(credential, TestSetup.DefaultSerializationOptions);


    /// <summary>Deserializes <paramref name="json"/> as a <see cref="VerifiableCredential"/> with <see cref="TestSetup.DefaultSerializationOptions"/>.</summary>
    /// <param name="json">The credential JSON text.</param>
    /// <returns>The deserialized credential.</returns>
    public static VerifiableCredential DeserializeCredential(string json) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(json, TestSetup.DefaultSerializationOptions)!;


    /// <summary>Serializes <paramref name="proofOptions"/> with <see cref="TestSetup.DefaultSerializationOptions"/> via <see cref="ProofOptionsSerializer.Serialize"/>.</summary>
    /// <param name="proofOptions">The proof options document to serialize.</param>
    /// <returns>The serialized JSON text.</returns>
    public static string SerializeProofOptions(ProofOptionsDocument proofOptions) =>
        ProofOptionsSerializer.Serialize(proofOptions, TestSetup.DefaultSerializationOptions);
}
