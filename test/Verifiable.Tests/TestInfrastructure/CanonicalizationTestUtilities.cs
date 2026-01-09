using Microsoft.Extensions.Caching.Memory;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;
using VDS.RDF.Parsing;
using Verifiable.Core.Model.DataIntegrity;

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
/// JSON-LD context documents used in credential processing MUST be integrity-protected. The specification
/// requires that:
/// </para>
/// <list type="number">
/// <item>
/// <description>
/// Context documents SHOULD be retrieved from well-known, trusted sources.
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#securing-json-ld-contexts"/>.
/// </description>
/// </item>
/// <item>
/// <description>
/// Context documents MUST be cacheable to prevent network-based attacks.
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#context-caching"/>.
/// </description>
/// </item>
/// <item>
/// <description>
/// Context integrity SHOULD be verified using cryptographic hashes (e.g., SHA-256).
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation"/>.
/// </description>
/// </item>
/// <item>
/// <description>
/// Local copies of context documents SHOULD be used when available to avoid network fetches.
/// This is the approach taken in these test utilities.
/// </description>
/// </item>
/// </list>
/// <para>
/// <strong>Context Integrity Verification</strong>
/// </para>
/// <para>
/// In production systems, context documents fetched from remote URLs should be verified against
/// known SHA-256 hashes. For example, the W3C Credentials v2 context should match:
/// </para>
/// <code>
/// SHA-256: [expected hash of https://www.w3.org/ns/credentials/v2]
/// </code>
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
/// See <see cref="CreateProductionContextResolver"/> for an example of how to implement
/// context integrity verification in production code.
/// </para>
/// </remarks>
public static class CanonicalizationTestUtilities
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
    /// W3C Verifiable Credentials Data Model v2.0 context document.
    /// </summary>
    /// <remarks>
    /// Source: <see href="https://www.w3.org/ns/credentials/v2"/>.
    /// This is an embedded copy for test determinism and offline operation.
    /// In production, fetch from the canonical URL and verify against <see cref="CredentialsV2ContextSha256"/>.
    /// </remarks>
    public static string CredentialsV2ContextJson { get; } =
        /*lang=json,strict*/
        """
        {
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "description": "https://schema.org/description",
            "digestMultibase": {
              "@id": "https://w3id.org/security#digestMultibase",
              "@type": "https://w3id.org/security#multibase"
            },
            "digestSRI": {
              "@id": "https://www.w3.org/2018/credentials#digestSRI",
              "@type": "https://www.w3.org/2018/credentials#sriString"
            },
            "mediaType": {
              "@id": "https://schema.org/encodingFormat"
            },
            "name": "https://schema.org/name",
            "VerifiableCredential": {
              "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "confidenceMethod": {
                  "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
                  "@type": "@id"
                },
                "credentialSchema": {
                  "@id": "https://www.w3.org/2018/credentials#credentialSchema",
                  "@type": "@id"
                },
                "credentialStatus": {
                  "@id": "https://www.w3.org/2018/credentials#credentialStatus",
                  "@type": "@id"
                },
                "credentialSubject": {
                  "@id": "https://www.w3.org/2018/credentials#credentialSubject",
                  "@type": "@id"
                },
                "description": "https://schema.org/description",
                "evidence": {
                  "@id": "https://www.w3.org/2018/credentials#evidence",
                  "@type": "@id"
                },
                "issuer": {
                  "@id": "https://www.w3.org/2018/credentials#issuer",
                  "@type": "@id"
                },
                "name": "https://schema.org/name",
                "proof": {
                  "@id": "https://w3id.org/security#proof",
                  "@type": "@id",
                  "@container": "@graph"
                },
                "refreshService": {
                  "@id": "https://www.w3.org/2018/credentials#refreshService",
                  "@type": "@id"
                },
                "relatedResource": {
                  "@id": "https://www.w3.org/2018/credentials#relatedResource",
                  "@type": "@id"
                },
                "renderMethod": {
                  "@id": "https://www.w3.org/2018/credentials#renderMethod",
                  "@type": "@id"
                },
                "termsOfUse": {
                  "@id": "https://www.w3.org/2018/credentials#termsOfUse",
                  "@type": "@id"
                },
                "validFrom": {
                  "@id": "https://www.w3.org/2018/credentials#validFrom",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "validUntil": {
                  "@id": "https://www.w3.org/2018/credentials#validUntil",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                }
              }
            },
            "DataIntegrityProof": {
              "@id": "https://w3id.org/security#DataIntegrityProof",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "challenge": "https://w3id.org/security#challenge",
                "created": {
                  "@id": "http://purl.org/dc/terms/created",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "domain": "https://w3id.org/security#domain",
                "expires": {
                  "@id": "https://w3id.org/security#expiration",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "nonce": "https://w3id.org/security#nonce",
                "previousProof": {
                  "@id": "https://w3id.org/security#previousProof",
                  "@type": "@id"
                },
                "proofPurpose": {
                  "@id": "https://w3id.org/security#proofPurpose",
                  "@type": "@vocab",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "assertionMethod": {
                      "@id": "https://w3id.org/security#assertionMethod",
                      "@type": "@id",
                      "@container": "@set"
                    }
                  }
                },
                "cryptosuite": {
                  "@id": "https://w3id.org/security#cryptosuite",
                  "@type": "https://w3id.org/security#cryptosuiteString"
                },
                "proofValue": {
                  "@id": "https://w3id.org/security#proofValue",
                  "@type": "https://w3id.org/security#multibase"
                },
                "verificationMethod": {
                  "@id": "https://w3id.org/security#verificationMethod",
                  "@type": "@id"
                }
              }
            }
          }
        }
        """;

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
    /// Expected SHA-256 hash of the W3C Credentials v2 context document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// To verify this hash against the live W3C document:
    /// </para>
    /// <code>
    /// curl -s https://www.w3.org/ns/credentials/v2 | openssl dgst -sha256
    /// </code>
    /// <para>
    /// Last verified: January 2026 (Update this date when re-verifying).
    /// </para>
    /// <para>
    /// This hash should be updated if the W3C publishes a new version of the context.
    /// Always verify context integrity as per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation"/>.
    /// </para>
    /// </remarks>
    public static string CredentialsV2ContextSha256 { get; } = ComputeContextHash(CredentialsV2ContextJson);

    /// <summary>
    /// Expected SHA-256 hash of the W3C Credentials Examples v2 context document.
    /// </summary>
    /// <remarks>
    /// Last verified: January 2026 (Update this date when re-verifying).
    /// </remarks>
    public static string CredentialsExamplesV2ContextSha256 { get; } = ComputeContextHash(CredentialsExamplesV2ContextJson);

    /// <summary>
    /// W3C CCG Citizenship Vocabulary v4rc1 JSON-LD context document.
    /// </summary>
    /// <remarks>
    /// Source: <see href="https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v4rc1.jsonld"/>.
    /// This is an embedded copy for test determinism and offline operation.
    /// Used by W3C ecdsa-sd-2023 test vectors.
    /// </remarks>
    public static string CitizenshipV4Rc1ContextJson { get; } =
        /*lang=json,strict*/
        """
        {
          "@context": {
            "@protected": true,
            "birthCountry": "https://w3id.org/citizenship#birthCountry",
            "birthDate": {
              "@id": "https://schema.org/birthDate",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "CertificateOfCitizenship": "https://w3id.org/citizenship#CertificateOfCitizenship",
            "CertificateOfCitizenshipCredential": "https://w3id.org/citizenship#CertificateOfCitizenshipCredential",
            "CertificateOfNaturalization": "https://w3id.org/citizenship#CertificateOfNaturalization",
            "CertificateOfNaturalizationCredential": "https://w3id.org/citizenship#CertificateOfNaturalizationCredential",
            "commuterClassification": "https://w3id.org/citizenship#commuterClassification",
            "EmployablePerson": {
              "@id": "https://w3id.org/citizenship#EmployablePerson",
              "@context": {
                "@protected": true,
                "employmentAuthorizationDocument": {
                  "@id": "https://w3id.org/citizenship#employmentAuthorizationDocument",
                  "@type": "@id"
                },
                "residentSince": {
                  "@id": "https://w3id.org/citizenship#residentSince",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                }
              }
            },
            "EmploymentAuthorizationDocument": "https://w3id.org/citizenship#EmploymentAuthorizationDocument",
            "EmploymentAuthorizationDocumentCredential": "https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential",
            "familyName": "https://schema.org/familyName",
            "gender": "https://schema.org/gender",
            "givenName": "https://schema.org/givenName",
            "additionalName": "https://schema.org/additionalName",
            "identifier": "https://schema.org/identifier",
            "image": {
              "@id": "https://schema.org/image",
              "@type": "@id"
            },
            "lprCategory": "https://w3id.org/citizenship#lprCategory",
            "lprNumber": "https://w3id.org/citizenship#lprNumber",
            "NaturalizedPerson": {
              "@id": "https://w3id.org/citizenship#NaturalizedPerson",
              "@context": {
                "@protected": true,
                "certificateOfNaturalization": {
                  "@id": "https://w3id.org/citizenship#certificateOfNaturalization",
                  "@type": "@id"
                },
                "commuterClassification": "https://w3id.org/citizenship#commuterClassification",
                "residence": "https://schema.org/address",
                "residentSince": {
                  "@id": "https://w3id.org/citizenship#residentSince",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                }
              }
            },
            "PermanentResident": {
              "@id": "https://w3id.org/citizenship#PermanentResident",
              "@context": {
                "@protected": true,
                "permanentResidentCard": {
                  "@id": "https://w3id.org/citizenship#permanentResidentCard",
                  "@type": "@id"
                }
              }
            },
            "PermanentResidentCard": "https://w3id.org/citizenship#PermanentResidentCard",
            "PermanentResidentCardCredential": "https://w3id.org/citizenship#PermanentResidentCardCredential",
            "Person": "https://schema.org/Person"
          }
        }
        """;

    /// <summary>
    /// Pre-warms the context cache by fetching and verifying all known contexts asynchronously.
    /// </summary>
    /// <param name="contextResolver">The context resolver to pre-warm (typically wraps a cache).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Critical for Production Use:</strong> This method MUST be called before any
    /// synchronous JSON-LD parsing operations to avoid deadlocks from sync-over-async patterns.
    /// </para>
    /// <para>
    /// <strong>Usage Pattern:</strong>
    /// </para>
    /// <code>
    /// //1. Create resolver with cache.
    /// var httpClient = new HttpClient();
    /// var cache = new MemoryCache(new MemoryCacheOptions());
    /// var contextResolver = CanonicalizationUtilities.CreateProductionContextResolver(httpClient, cache);
    /// 
    /// //2. Pre-warm cache asynchronously (once at startup).
    /// await CanonicalizationUtilities.PreWarmContextCacheAsync(contextResolver);
    /// 
    /// //3. Now safe to use in synchronous document loader.
    /// var canonicalizer = CanonicalizationUtilities.CreateRdfcCanonicalizer();
    /// var result = await canonicalizer(json, contextResolver, cancellationToken);
    /// </code>
    /// <para>
    /// This pattern:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Performs all I/O and async operations upfront.</description></item>
    /// <item><description>Ensures the synchronous document loader only reads from cache.</description></item>
    /// <item><description>Prevents deadlocks from captured synchronization contexts.</description></item>
    /// <item><description>Enables fast, deterministic canonicalization.</description></item>
    /// </list>
    /// </remarks>
    public static async Task PreWarmContextCacheAsync(ContextResolverDelegate contextResolver, CancellationToken cancellationToken = default)
    {
        var knownContexts = new[]
        {
            new Uri(CredentialsV2ContextUrl),
            new Uri(CredentialsExamplesV2ContextUrl)
        };

        foreach(var contextUri in knownContexts)
        {
            //This will fetch, verify (if production resolver), and cache the context.
            var result = await contextResolver(contextUri, cancellationToken);
            if(result == null)
            {
                throw new InvalidOperationException(
                    $"Failed to pre-warm context cache for URI: {contextUri}. Ensure the context resolver can resolve all known context URIs.");
            }
        }
    }

    /// <summary>
    /// Verifies that embedded context documents match actual W3C published contexts.
    /// </summary>
    /// <param name="httpClient">HTTP client for fetching W3C contexts.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes successfully if all hashes match.</returns>
    /// <exception cref="SecurityException">Thrown if any context hash mismatch is detected.</exception>
    /// <remarks>
    /// <para>
    /// This method should be called in CI/CD pipelines or during development to ensure
    /// embedded context documents haven't diverged from W3C published versions.
    /// </para>
    /// <para>
    /// <strong>Example Usage in Tests:</strong>
    /// </para>
    /// <code>
    /// [Fact]
    /// public async Task EmbeddedContexts_MatchW3CPublishedVersions()
    /// {
    ///     using var httpClient = new HttpClient();
    ///     await CanonicalizationUtilities.VerifyEmbeddedContextsAsync(httpClient);
    /// }
    /// </code>
    /// </remarks>
    public static async Task VerifyEmbeddedContextsAsync(HttpClient httpClient, CancellationToken cancellationToken = default)
    {
        //Verify Credentials v2 context.
        var credV2Response = await httpClient.GetStringAsync(CredentialsV2ContextUrl, cancellationToken);
        var credV2Hash = ComputeContextHash(credV2Response);
        var embeddedCredV2Hash = CredentialsV2ContextSha256;

        if(credV2Hash != embeddedCredV2Hash)
        {
            throw new SecurityException(
                $"Embedded Credentials v2 context hash mismatch. Expected (from W3C): {credV2Hash}, Embedded: {embeddedCredV2Hash}. The W3C may have updated the context. Update the embedded context and hash.");
        }

        //Verify Credentials Examples v2 context.
        var examplesV2Response = await httpClient.GetStringAsync(CredentialsExamplesV2ContextUrl, cancellationToken);
        var examplesV2Hash = ComputeContextHash(examplesV2Response);
        var embeddedExamplesV2Hash = CredentialsExamplesV2ContextSha256;

        if(examplesV2Hash != embeddedExamplesV2Hash)
        {
            throw new SecurityException(
                $"Embedded Credentials Examples v2 context hash mismatch. Expected (from W3C): {examplesV2Hash}, Embedded: {embeddedExamplesV2Hash}. The W3C may have updated the context. Update the embedded context and hash.");
        }
    }

    /// <summary>
    /// Creates an RDFC-1.0 canonicalization delegate using dotNetRdf.
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
    /// <item><description>Parses JSON-LD to RDF using the provided context resolver.</description></item>
    /// <item><description>Loads RDF triples into a triple store.</description></item>
    /// <item><description>Applies RDFC-1.0 canonicalization algorithm.</description></item>
    /// <item><description>Serializes to N-Quads format.</description></item>
    /// </list>
    /// <para>
    /// <strong>Context Resolution Security:</strong> The context resolver MUST ensure integrity
    /// of fetched contexts as per <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation"/>.
    /// </para>
    /// <para>
    /// <strong>Important:</strong> Call <see cref="PreWarmContextCacheAsync"/> before using this
    /// canonicalizer to ensure all contexts are cached and avoid synchronous blocking.
    /// </para>
    /// </remarks>
    public static CanonicalizationDelegate CreateRdfcCanonicalizer()
    {
        return (json, contextResolver, cancellationToken) =>
        {
            var store = new TripleStore();
            var parserOptions = new JsonLdProcessorOptions
            {
                ProcessingMode = JsonLdProcessingMode.JsonLd11,
                DocumentLoader = CreateDotNetRdfContextLoader(contextResolver)
            };
            var parser = new JsonLdParser(parserOptions);

            using var reader = new StringReader(json);
            parser.Load(store, reader);

            var canonicalizer = new RdfCanonicalizer();
            var canonicalizedResult = canonicalizer.Canonicalize(store);

            return ValueTask.FromResult(canonicalizedResult.SerializedNQuads);
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
    /// <strong>Production Use:</strong> In production, use <see cref="CreateProductionContextResolver"/>
    /// which fetches contexts remotely and verifies their integrity using SHA-256 hashes.
    /// </para>
    /// <para>
    /// <strong>Note:</strong> This resolver always returns synchronously from embedded resources,
    /// so no cache pre-warming is required for tests.
    /// </para>
    /// </remarks>
    public static ContextResolverDelegate CreateTestContextResolver()
    {
        return (uri, cancellationToken) =>
        {
            var contextJson = uri.ToString() switch
            {
                CredentialsV2ContextUrl => CredentialsV2ContextJson,
                CredentialsExamplesV2ContextUrl => CredentialsExamplesV2ContextJson,
                CitizenshipV4Rc1ContextUrl => CitizenshipV4Rc1ContextJson,
                _ => null
            };

            return ValueTask.FromResult(contextJson);
        };
    }

    /// <summary>
    /// Creates a production context resolver that fetches contexts remotely and verifies integrity.
    /// </summary>
    /// <param name="httpClient">HTTP client for fetching remote contexts.</param>
    /// <param name="contextCache">Optional cache for storing verified contexts. Strongly recommended for production.</param>
    /// <returns>A context resolver suitable for production use.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Production Context Resolution Pattern</strong>
    /// </para>
    /// <para>
    /// Per <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">W3C Data Integrity §4.1.3</see>,
    /// production systems MUST verify context integrity. This resolver implements the recommended pattern:
    /// </para>
    /// <list type="number">
    /// <item><description>Check if context is cached locally with verified integrity.</description></item>
    /// <item><description>If not cached, fetch from remote URL using HTTPS.</description></item>
    /// <item><description>Compute SHA-256 hash of fetched content.</description></item>
    /// <item><description>Verify hash matches known good value for that context URL.</description></item>
    /// <item><description>If verification fails, reject the context and raise an error.</description></item>
    /// <item><description>If verification succeeds, cache the context for future use.</description></item>
    /// </list>
    /// <para>
    /// <strong>Example Production Usage:</strong>
    /// </para>
    /// <code>
    /// var httpClient = new HttpClient();
    /// var contextCache = new MemoryCache(new MemoryCacheOptions());
    /// var contextResolver = CanonicalizationUtilities.CreateProductionContextResolver(httpClient, contextCache);
    /// 
    /// //Pre-warm cache to avoid sync-over-async in document loader.
    /// await CanonicalizationUtilities.PreWarmContextCacheAsync(contextResolver);
    /// 
    /// //Use in credential verification.
    /// var canonicalizer = CanonicalizationUtilities.CreateRdfcCanonicalizer();
    /// var result = await credential.VerifyAsync(
    ///     issuerDidDocument,
    ///     canonicalizer,
    ///     contextResolver,
    ///     ...);
    /// </code>
    /// <para>
    /// <strong>Security Considerations:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>Always use HTTPS for fetching remote contexts to prevent MITM attacks.</description></item>
    /// <item><description>Maintain a whitelist of known context URLs and their expected SHA-256 hashes.</description></item>
    /// <item><description>Implement cache expiration policies to refresh contexts periodically.</description></item>
    /// <item><description>Consider using Subresource Integrity (SRI) hashes if contexts support it.</description></item>
    /// <item><description>Call <see cref="PreWarmContextCacheAsync"/> during application startup to populate cache.</description></item>
    /// </list>
    /// </remarks>
    public static ContextResolverDelegate CreateProductionContextResolver(
        HttpClient httpClient,
        IMemoryCache? contextCache = null)
    {
        //Known good SHA-256 hashes for W3C contexts.
        var knownContextHashes = new Dictionary<string, string>
        {
            [CredentialsV2ContextUrl] = CredentialsV2ContextSha256,
            [CredentialsExamplesV2ContextUrl] = CredentialsExamplesV2ContextSha256
        };

        return async (uri, cancellationToken) =>
        {
            var uriString = uri.ToString();

            //Check cache first.
            if(contextCache?.TryGetValue(uriString, out string? cachedContext) == true)
            {
                return cachedContext;
            }

            //Fetch from remote.
            var response = await httpClient.GetAsync(uri, cancellationToken);
            response.EnsureSuccessStatusCode();

            var contextJson = await response.Content.ReadAsStringAsync(cancellationToken);

            //Verify integrity.
            var actualHash = ComputeContextHash(contextJson);

            if(!knownContextHashes.TryGetValue(uriString, out var expectedHash))
            {
                throw new SecurityException(
                    $"Context URI '{uri}' is not in the whitelist of known contexts. For security, only pre-verified contexts are allowed.");
            }

            if(actualHash != expectedHash)
            {
                throw new SecurityException(
                    $"Context integrity check failed for '{uri}'. Expected SHA-256: {expectedHash}, but got: {actualHash}. This may indicate tampering or an updated context version.");
            }

            //Cache verified context.
            if(contextCache != null)
            {
                var cacheOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromHours(24));
                contextCache.Set(uriString, contextJson, cacheOptions);
            }

            return contextJson;
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
        var hashBytes = SHA256.HashData(bytes);

        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Creates a dotNetRdf document loader that reads from pre-warmed context cache.
    /// </summary>
    /// <param name="contextResolver">The context resolver with pre-warmed cache.</param>
    /// <returns>A document loader function for dotNetRdf's JSON-LD parser.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Important:</strong> This method expects that <see cref="PreWarmContextCacheAsync"/>
    /// has been called to populate the cache. The loader uses <see cref="Task.Run"/> to avoid
    /// capturing synchronization contexts, but contexts should already be cached to avoid I/O.
    /// </para>
    /// <para>
    /// <strong>Design Rationale:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>dotNetRdf's DocumentLoader interface is synchronous: <c>Func&lt;Uri, JsonLdLoaderOptions?, RemoteDocument&gt;</c>.</description></item>
    /// <item><description>Our <see cref="ContextResolverDelegate"/> is async to support network I/O and integrity checks.</description></item>
    /// <item><description>Using <c>.GetAwaiter().GetResult()</c> directly can cause deadlocks in sync contexts.</description></item>
    /// <item><description><see cref="Task.Run"/> isolates the async work from the calling synchronization context.</description></item>
    /// <item><description>Pre-warming the cache ensures this only reads from cache (fast, synchronous).</description></item>
    /// </list>
    /// <para>
    /// If a context is not in cache, an exception is thrown rather than blocking on network I/O.
    /// </para>
    /// </remarks>
    private static Func<Uri, JsonLdLoaderOptions?, RemoteDocument> CreateDotNetRdfContextLoader(ContextResolverDelegate? contextResolver)
    {
        return (uri, options) =>
        {
            string? contextJson = null;

            if(contextResolver != null)
            {
                //Use Task.Run to avoid captured synchronization context issues.
                //Context should already be cached from PreWarmContextCacheAsync.
                try
                {
                    contextJson = Task.Run(async () =>
                        await contextResolver(uri, CancellationToken.None)).GetAwaiter().GetResult();
                }
                catch(Exception ex)
                {
                    throw new JsonLdProcessorException(
                        JsonLdErrorCode.LoadingDocumentFailed,
                        $"Failed to resolve context URI: {uri}. " +
                        "Ensure PreWarmContextCacheAsync was called before canonicalization. " +
                        $"Inner exception: {ex.Message}",
                        ex);
                }
            }

            if(contextJson == null)
            {
                throw new JsonLdProcessorException(
                    JsonLdErrorCode.LoadingDocumentFailed,
                    $"Failed to resolve context URI: {uri}. Context not found in cache. Ensure PreWarmContextCacheAsync was called with a resolver that can handle this URI, or use CreateTestContextResolver() for tests.");
            }

            return new RemoteDocument
            {
                DocumentUrl = uri,
                Document = contextJson
            };
        };
    }
}