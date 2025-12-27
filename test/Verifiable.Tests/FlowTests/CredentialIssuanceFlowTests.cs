using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;
using VDS.RDF.Parsing;
using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Proofs;
using Verifiable.Tests.Resolver;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Flows;

/// <summary>
/// End-to-end flow tests for Verifiable Credential issuance and verification.
/// These tests demonstrate the complete trust triangle: Issuer, Holder, Verifier.
/// </summary>
/// <remarks>
/// <para>
/// The credential issuance and verification flow involves three parties:
/// </para>
/// <list type="number">
/// <item><description>Issuer: Creates and signs credentials using their DID's assertionMethod key.</description></item>
/// <item><description>Holder: Receives credentials about themselves (identified by their DID as subject).</description></item>
/// <item><description>Verifier: Validates credential authenticity by resolving issuer's DID and verifying signature.</description></item>
/// </list>
/// <para>
/// Two cryptosuites are tested:
/// </para>
/// <list type="bullet">
/// <item><description>eddsa-rdfc-2022: Uses JSON-LD canonicalization (RDFC-1.0). Only claims defined in @context are signed.</description></item>
/// <item><description>eddsa-jcs-2022: Uses JSON Canonicalization Scheme. ALL JSON properties are signed regardless of context.</description></item>
/// </list>
/// </remarks>
[TestClass]
public sealed class CredentialIssuanceFlowTests
{
    //Test DID identifiers.
    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string HolderDidExample = "did:example:holder";

    //Credential constants.
    private const string AlumniCredentialType = "AlumniCredential";

    //Claim keys and values.
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";
    private const string ClaimValueFakeUniversity = "Fake University";

    //JSON-LD context URLs.
    private const string CredentialsV2ContextUrl = "https://www.w3.org/ns/credentials/v2";
    private const string CredentialsExamplesV2ContextUrl = "https://www.w3.org/ns/credentials/examples/v2";

    //Cryptosuite constants.
    private const string EddsaRdfc2022Cryptosuite = "eddsa-rdfc-2022";
    private const string EddsaJcs2022Cryptosuite = "eddsa-jcs-2022";
    private const string DataIntegrityProofType = "DataIntegrityProof";

    /// <summary>
    /// W3C Verifiable Credentials Data Model 2.0 context.
    /// Source: https://www.w3.org/ns/credentials/v2
    /// </summary>
    private const string CredentialsV2ContextJson =
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
            "EnvelopedVerifiableCredential": "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",
            "VerifiablePresentation": {
              "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "holder": {
                  "@id": "https://www.w3.org/2018/credentials#holder",
                  "@type": "@id"
                },
                "proof": {
                  "@id": "https://w3id.org/security#proof",
                  "@type": "@id",
                  "@container": "@graph"
                },
                "termsOfUse": {
                  "@id": "https://www.w3.org/2018/credentials#termsOfUse",
                  "@type": "@id"
                },
                "verifiableCredential": {
                  "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
                  "@type": "@id",
                  "@container": "@graph",
                  "@context": null
                }
              }
            },
            "EnvelopedVerifiablePresentation": "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",
            "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential",
            "JsonSchema": {
              "@id": "https://www.w3.org/2018/credentials#JsonSchema",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "jsonSchema": {
                  "@id": "https://www.w3.org/2018/credentials#jsonSchema",
                  "@type": "@json"
                }
              }
            },
            "BitstringStatusListCredential": "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",
            "BitstringStatusList": {
              "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "encodedList": {
                  "@id": "https://www.w3.org/ns/credentials/status#encodedList",
                  "@type": "https://w3id.org/security#multibase"
                },
                "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
                "ttl": "https://www.w3.org/ns/credentials/status#ttl"
              }
            },
            "BitstringStatusListEntry": {
              "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "statusListCredential": {
                  "@id": "https://www.w3.org/ns/credentials/status#statusListCredential",
                  "@type": "@id"
                },
                "statusListIndex": "https://www.w3.org/ns/credentials/status#statusListIndex",
                "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
                "statusMessage": {
                  "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "message": "https://www.w3.org/ns/credentials/status#message",
                    "status": "https://www.w3.org/ns/credentials/status#status"
                  }
                },
                "statusReference": {
                  "@id": "https://www.w3.org/ns/credentials/status#statusReference",
                  "@type": "@id"
                },
                "statusSize": {
                  "@id": "https://www.w3.org/ns/credentials/status#statusSize",
                  "@type": "https://www.w3.org/2001/XMLSchema#integer"
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
                "cryptosuite": {
                  "@id": "https://w3id.org/security#cryptosuite",
                  "@type": "https://w3id.org/security#cryptosuiteString"
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
                    },
                    "authentication": {
                      "@id": "https://w3id.org/security#authenticationMethod",
                      "@type": "@id",
                      "@container": "@set"
                    },
                    "capabilityDelegation": {
                      "@id": "https://w3id.org/security#capabilityDelegationMethod",
                      "@type": "@id",
                      "@container": "@set"
                    },
                    "capabilityInvocation": {
                      "@id": "https://w3id.org/security#capabilityInvocationMethod",
                      "@type": "@id",
                      "@container": "@set"
                    },
                    "keyAgreement": {
                      "@id": "https://w3id.org/security#keyAgreementMethod",
                      "@type": "@id",
                      "@container": "@set"
                    }
                  }
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
            },
            "...": {
              "@id": "https://www.iana.org/assignments/jwt#..."
            },
            "_sd": {
              "@id": "https://www.iana.org/assignments/jwt#_sd",
              "@type": "@json"
            },
            "_sd_alg": {
              "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
            },
            "aud": {
              "@id": "https://www.iana.org/assignments/jwt#aud",
              "@type": "@id"
            },
            "cnf": {
              "@id": "https://www.iana.org/assignments/jwt#cnf",
              "@context": {
                "@protected": true,
                "kid": {
                  "@id": "https://www.iana.org/assignments/jwt#kid",
                  "@type": "@id"
                },
                "jwk": {
                  "@id": "https://www.iana.org/assignments/jwt#jwk",
                  "@type": "@json"
                }
              }
            },
            "exp": {
              "@id": "https://www.iana.org/assignments/jwt#exp",
              "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
            },
            "iat": {
              "@id": "https://www.iana.org/assignments/jwt#iat",
              "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
            },
            "iss": {
              "@id": "https://www.iana.org/assignments/jose#iss",
              "@type": "@id"
            },
            "jku": {
              "@id": "https://www.iana.org/assignments/jose#jku",
              "@type": "@id"
            },
            "kid": {
              "@id": "https://www.iana.org/assignments/jose#kid",
              "@type": "@id"
            },
            "nbf": {
              "@id": "https://www.iana.org/assignments/jwt#nbf",
              "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
            },
            "sub": {
              "@id": "https://www.iana.org/assignments/jose#sub",
              "@type": "@id"
            },
            "x5u": {
              "@id": "https://www.iana.org/assignments/jose#x5u",
              "@type": "@id"
            }
          }
        }
        """;

    /// <summary>
    /// W3C Verifiable Credentials Examples v2 context.
    /// Uses @vocab to map all undefined terms to the examples namespace.
    /// Source: https://www.w3.org/ns/credentials/examples/v2
    /// </summary>
    private const string CredentialsExamplesV2ContextJson =
        /*lang=json,strict*/
        """
        {
          "@context": {
            "@vocab": "https://www.w3.org/ns/credentials/examples#"
          }
        }
        """;

    /// <summary>
    /// JSON serialization options with all required converters for Verifiable Credentials.
    /// </summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>
    /// Shared credential builder instance.
    /// </summary>
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();

    /// <summary>
    /// Shared key DID builder instance.
    /// </summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();

    /// <summary>
    /// Shared web DID builder instance.
    /// </summary>
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();


    /// <summary>
    /// Creates a document loader that resolves JSON-LD contexts from embedded static strings.
    /// This enables offline testing without HTTP requests to W3C servers.
    /// </summary>
    private static Func<Uri, JsonLdLoaderOptions?, RemoteDocument> CreateContextResolver()
    {
        return (uri, options) =>
        {
            var uriString = uri.ToString();

            string? contextJson = uriString switch
            {
                CredentialsV2ContextUrl => CredentialsV2ContextJson,
                CredentialsExamplesV2ContextUrl => CredentialsExamplesV2ContextJson,
                _ => null
            };

            if(contextJson == null)
            {
                throw new JsonLdProcessorException(
                    JsonLdErrorCode.LoadingDocumentFailed,
                    $"Unknown context URI: {uri}");
            }

            return new RemoteDocument
            {
                DocumentUrl = uri,
                Document = contextJson
            };
        };
    }


    /// <summary>
    /// Verifies that JSON-LD canonicalization includes claims only when context defines them.
    /// Without the examples context, alumniOf is dropped during expansion.
    /// With the examples context, alumniOf is included in the canonical form.
    /// </summary>
    [TestMethod]
    public void CanonicalFormIncludesClaimsOnlyWhenContextDefinesThem()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var credential = CredentialBuilder.Build(issuer, subject, additionalTypes: [AlumniCredentialType]);
        var credentialJson = JsonSerializer.Serialize(credential, JsonOptions);

        //Canonicalize without examples context. The alumniOf claim should be dropped.
        var canonicalFormWithoutContext = CanonicalizeRdfc(credentialJson);
        var alumniOfInCanonicalWithoutContext = canonicalFormWithoutContext.Contains(ClaimValueUniversityName, StringComparison.Ordinal);

        //Add examples context and canonicalize again. The alumniOf claim should now be included.
        var credentialWithContext = AddContextToCredential(credentialJson, CredentialsExamplesV2ContextUrl);
        var canonicalFormWithContext = CanonicalizeRdfc(credentialWithContext);
        var alumniOfInCanonicalWithContext = canonicalFormWithContext.Contains(ClaimValueUniversityName, StringComparison.Ordinal);

        Assert.IsFalse(alumniOfInCanonicalWithoutContext, "Claim should NOT be in canonical form without examples context.");
        Assert.IsTrue(alumniOfInCanonicalWithContext, "Claim should be in canonical form with examples context.");
    }


    /// <summary>
    /// Tests the complete credential issuance and verification flow using RDFC canonicalization.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueAndVerifyCredentialWithRdfcSucceeds(DidWebTestData testData)
    {
        var issuerDidDocument = WebDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = KeyDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo);

        var holderDid = holderDidDocument.Id!.ToString();

        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = DateTime.UtcNow;
        var validUntil = validFrom.AddYears(10);

        var unsignedCredential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [AlumniCredentialType],
            validFrom: validFrom,
            validUntil: validUntil);

        //Add examples context so alumniOf is protected by signature.
        var credentialJson = JsonSerializer.Serialize(unsignedCredential, JsonOptions);
        var credentialWithContext = AddContextToCredential(credentialJson, CredentialsExamplesV2ContextUrl);

        var signedCredential = await SignCredentialRdfcAsync(
            credentialWithContext,
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId);

        var verificationResult = await VerifyCredentialRdfcAsync(signedCredential, issuerDidDocument);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
        Assert.AreEqual(holderDid, signedCredential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, signedCredential.Issuer!.Id);
    }


    /// <summary>
    /// Tests the complete credential issuance and verification flow using JCS canonicalization.
    /// JCS signs ALL JSON properties regardless of context.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueAndVerifyCredentialWithJcsSucceeds(DidWebTestData testData)
    {
        var issuerDidDocument = WebDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = KeyDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo);

        var holderDid = holderDidDocument.Id!.ToString();

        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = DateTime.UtcNow;
        var validUntil = validFrom.AddYears(10);

        var unsignedCredential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [AlumniCredentialType],
            validFrom: validFrom,
            validUntil: validUntil);

        //No need for examples context with JCS since all properties are signed.
        var signedCredential = await SignCredentialJcsAsync(
            unsignedCredential,
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId);

        var verificationResult = await VerifyCredentialJcsAsync(signedCredential, issuerDidDocument);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
        Assert.AreEqual(holderDid, signedCredential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, signedCredential.Issuer!.Id);
    }


    /// <summary>
    /// Tests that tampered credentials fail verification with RDFC.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedCredentialFailsVerificationWithRdfc(DidWebTestData testData)
    {
        var issuerDidDocument = WebDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var unsignedCredential = CredentialBuilder.Build(issuer, subject, additionalTypes: [AlumniCredentialType]);

        var credentialJson = JsonSerializer.Serialize(unsignedCredential, JsonOptions);
        var credentialWithContext = AddContextToCredential(credentialJson, CredentialsExamplesV2ContextUrl);

        var signedCredential = await SignCredentialRdfcAsync(credentialWithContext, testData.KeyPair.PrivateKey, issuerVerificationMethodId);

        //Tamper by modifying the JSON string directly.
        var signedCredentialJson = JsonSerializer.Serialize(signedCredential, JsonOptions);
        var tamperedJson = signedCredentialJson.Replace(ClaimValueUniversityName, ClaimValueFakeUniversity, StringComparison.Ordinal);
        var tamperedCredential = JsonSerializer.Deserialize<VerifiableCredential>(tamperedJson, JsonOptions)!;

        var verificationResult = await VerifyCredentialRdfcAsync(tamperedCredential, issuerDidDocument);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), verificationResult);
    }


    /// <summary>
    /// Tests that tampered credentials fail verification with JCS.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedCredentialFailsVerificationWithJcs(DidWebTestData testData)
    {
        var issuerDidDocument = WebDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var unsignedCredential = CredentialBuilder.Build(issuer, subject, additionalTypes: [AlumniCredentialType]);

        var signedCredential = await SignCredentialJcsAsync(unsignedCredential, testData.KeyPair.PrivateKey, issuerVerificationMethodId);

        //Tamper by modifying the JSON string directly.
        var signedCredentialJson = JsonSerializer.Serialize(signedCredential, JsonOptions);
        var tamperedJson = signedCredentialJson.Replace(ClaimValueUniversityName, ClaimValueFakeUniversity, StringComparison.Ordinal);
        var tamperedCredential = JsonSerializer.Deserialize<VerifiableCredential>(tamperedJson, JsonOptions)!;

        var verificationResult = await VerifyCredentialJcsAsync(tamperedCredential, issuerDidDocument);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), verificationResult);
    }


    /// <summary>
    /// Tests that expired credentials are detected during verification.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task ExpiredCredentialIsDetected(DidWebTestData testData)
    {
        var issuerDidDocument = WebDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = DateTime.UtcNow.AddDays(-30);
        var validUntil = DateTime.UtcNow.AddDays(-1);

        var unsignedCredential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [AlumniCredentialType],
            validFrom: validFrom,
            validUntil: validUntil);

        var signedCredential = await SignCredentialJcsAsync(unsignedCredential, testData.KeyPair.PrivateKey, issuerVerificationMethodId);

        var verificationResult = await VerifyCredentialJcsAsync(signedCredential, issuerDidDocument);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.CredentialExpired), verificationResult);
    }


    /// <summary>
    /// Tests that credentials not yet valid are detected during verification.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task NotYetValidCredentialIsDetected(DidWebTestData testData)
    {
        var issuerDidDocument = WebDidBuilder.Build(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = DateTime.UtcNow.AddDays(30);
        var validUntil = DateTime.UtcNow.AddDays(365);

        var unsignedCredential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [AlumniCredentialType],
            validFrom: validFrom,
            validUntil: validUntil);

        var signedCredential = await SignCredentialJcsAsync(unsignedCredential, testData.KeyPair.PrivateKey, issuerVerificationMethodId);

        var verificationResult = await VerifyCredentialJcsAsync(signedCredential, issuerDidDocument);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.CredentialNotYetValid), verificationResult);
    }


    /// <summary>
    /// Tests DID resolution as part of the verification flow.
    /// </summary>
    [TestMethod]
    public void DidWebResolutionProducesCorrectUrl()
    {
        var simpleDidWeb = "did:web:university.example";
        var resolvedUrl = WebDidResolver.Resolve(simpleDidWeb);
        Assert.AreEqual("https://university.example/.well-known/did.json", resolvedUrl);

        var didWebWithPath = "did:web:university.example:departments:cs";
        var resolvedUrlWithPath = WebDidResolver.Resolve(didWebWithPath);
        Assert.AreEqual("https://university.example/departments/cs/did.json", resolvedUrlWithPath);

        var didWebWithPort = "did:web:localhost%3A8080:issuers:test";
        var resolvedUrlWithPort = WebDidResolver.Resolve(didWebWithPort);
        Assert.AreEqual("https://localhost:8080/issuers/test/did.json", resolvedUrlWithPort);
    }


    /// <summary>
    /// Adds an additional context to a credential JSON string.
    /// </summary>
    private static string AddContextToCredential(string credentialJson, string contextToAdd)
    {
        var jsonNode = JsonNode.Parse(credentialJson)!;
        var contextNode = jsonNode["@context"];

        if(contextNode is JsonArray contextArray)
        {
            contextArray.Add(contextToAdd);
        }
        else if(contextNode is JsonValue contextValue)
        {
            jsonNode["@context"] = new JsonArray(JsonValue.Create(contextValue.GetValue<string>()), JsonValue.Create(contextToAdd));
        }

        return jsonNode.ToJsonString(JsonOptions);
    }


    /// <summary>
    /// Signs a credential using the eddsa-rdfc-2022 cryptosuite (JSON-LD canonicalization).
    /// </summary>
    private static async Task<VerifiableCredential> SignCredentialRdfcAsync(
        string credentialJson,
        PrivateKeyMemory privateKey,
        string verificationMethodId)
    {
        var proofCreated = DateTime.UtcNow;

        //Parse credential to get context for proof options.
        var credentialNode = JsonNode.Parse(credentialJson)!;
        var context = credentialNode["@context"];

        var proofOptionsJson = JsonSerializer.Serialize(new
        {
            type = DataIntegrityProofType,
            cryptosuite = EddsaRdfc2022Cryptosuite,
            created = proofCreated.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            verificationMethod = verificationMethodId,
            proofPurpose = AssertionMethod.Purpose,
            context
        }, JsonOptions);

        var canonicalCredential = CanonicalizeRdfc(credentialJson);
        var canonicalProofOptions = CanonicalizeRdfc(proofOptionsJson);

        var credentialHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCredential));
        var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));
        var hashData = proofOptionsHash.Concat(credentialHash).ToArray();

        using var signature = await privateKey.SignAsync(hashData, BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
        var proofValue = $"{MultibaseAlgorithms.Base58Btc}{TestSetup.Base58Encoder(signature.AsReadOnlySpan())}";

        var signedCredential = JsonSerializer.Deserialize<VerifiableCredential>(credentialJson, JsonOptions)!;
        signedCredential.Proof =
        [
            new DataIntegrityProof
            {
                Type = DataIntegrityProofType,
                Cryptosuite = CryptosuiteInfo.FromName(EddsaRdfc2022Cryptosuite),
                Created = proofCreated,
                VerificationMethod = new AssertionMethod(verificationMethodId),
                ProofPurpose = AssertionMethod.Purpose,
                ProofValue = proofValue
            }
        ];

        return signedCredential;
    }


    /// <summary>
    /// Signs a credential using the eddsa-jcs-2022 cryptosuite (JSON Canonicalization Scheme).
    /// JCS signs ALL JSON properties regardless of @context.
    /// </summary>
    private static async Task<VerifiableCredential> SignCredentialJcsAsync(
        VerifiableCredential credential,
        PrivateKeyMemory privateKey,
        string verificationMethodId)
    {
        var credentialJson = JsonSerializer.Serialize(credential, JsonOptions);
        var proofCreated = DateTime.UtcNow;

        var proofOptions = new
        {
            type = DataIntegrityProofType,
            cryptosuite = EddsaJcs2022Cryptosuite,
            created = proofCreated.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            verificationMethod = verificationMethodId,
            proofPurpose = AssertionMethod.Purpose
        };
        var proofOptionsJson = JsonSerializer.Serialize(proofOptions, JsonOptions);

        var canonicalCredential = CanonicalizeJcs(credentialJson);
        var canonicalProofOptions = CanonicalizeJcs(proofOptionsJson);

        var credentialHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCredential));
        var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));
        var hashData = proofOptionsHash.Concat(credentialHash).ToArray();

        using var signature = await privateKey.SignAsync(hashData, BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
        var proofValue = $"{MultibaseAlgorithms.Base58Btc}{TestSetup.Base58Encoder(signature.AsReadOnlySpan())}";

        var signedCredential = JsonSerializer.Deserialize<VerifiableCredential>(credentialJson, JsonOptions)!;
        signedCredential.Proof =
        [
            new DataIntegrityProof
            {
                Type = DataIntegrityProofType,
                Cryptosuite = CryptosuiteInfo.FromName(EddsaJcs2022Cryptosuite),
                Created = proofCreated,
                VerificationMethod = new AssertionMethod(verificationMethodId),
                ProofPurpose = AssertionMethod.Purpose,
                ProofValue = proofValue
            }
        ];

        return signedCredential;
    }


    /// <summary>
    /// Verifies a credential's signature and validity period using RDFC canonicalization.
    /// </summary>
    private static async Task<CredentialVerificationResult> VerifyCredentialRdfcAsync(
        VerifiableCredential credential,
        DidDocument issuerDidDocument)
    {
        var validityResult = CheckCredentialValidity(credential);
        if(!validityResult.IsValid)
        {
            return validityResult;
        }

        var proof = credential.Proof?.FirstOrDefault();
        if(proof == null)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.NoProof);
        }

        var verificationMethodId = proof.VerificationMethod?.Id;
        if(string.IsNullOrEmpty(verificationMethodId))
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod);
        }

        var verificationMethod = issuerDidDocument.ResolveVerificationMethodReference(verificationMethodId);
        if(verificationMethod == null)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.VerificationMethodNotFound);
        }

        var credentialWithoutProof = JsonSerializer.Deserialize<VerifiableCredential>(
            JsonSerializer.Serialize(credential, JsonOptions), JsonOptions)!;
        credentialWithoutProof.Proof = null;

        var credentialJson = JsonSerializer.Serialize(credentialWithoutProof, JsonOptions);

        var proofOptionsJson = JsonSerializer.Serialize(new
        {
            type = proof.Type,
            cryptosuite = proof.Cryptosuite?.CryptosuiteName,
            created = proof.Created?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            verificationMethod = verificationMethodId,
            proofPurpose = proof.ProofPurpose,
            context = credential.Context
        }, JsonOptions);

        var canonicalCredential = CanonicalizeRdfc(credentialJson);
        var canonicalProofOptions = CanonicalizeRdfc(proofOptionsJson);

        var credentialHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCredential));
        var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));
        var hashData = proofOptionsHash.Concat(credentialHash).ToArray();

        return await VerifySignatureAsync(proof.ProofValue!, hashData, verificationMethod);
    }


    /// <summary>
    /// Verifies a credential's signature and validity period using JCS canonicalization.
    /// </summary>
    private static async Task<CredentialVerificationResult> VerifyCredentialJcsAsync(
        VerifiableCredential credential,
        DidDocument issuerDidDocument)
    {
        var validityResult = CheckCredentialValidity(credential);
        if(!validityResult.IsValid)
        {
            return validityResult;
        }

        var proof = credential.Proof?.FirstOrDefault();
        if(proof == null)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.NoProof);
        }

        var verificationMethodId = proof.VerificationMethod?.Id;
        if(string.IsNullOrEmpty(verificationMethodId))
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod);
        }

        var verificationMethod = issuerDidDocument.ResolveVerificationMethodReference(verificationMethodId);
        if(verificationMethod == null)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.VerificationMethodNotFound);
        }

        var credentialWithoutProof = JsonSerializer.Deserialize<VerifiableCredential>(
            JsonSerializer.Serialize(credential, JsonOptions), JsonOptions)!;
        credentialWithoutProof.Proof = null;

        var credentialJson = JsonSerializer.Serialize(credentialWithoutProof, JsonOptions);

        var proofOptions = new
        {
            type = proof.Type,
            cryptosuite = proof.Cryptosuite?.CryptosuiteName,
            created = proof.Created?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            verificationMethod = verificationMethodId,
            proofPurpose = proof.ProofPurpose
        };
        var proofOptionsJson = JsonSerializer.Serialize(proofOptions, JsonOptions);

        var canonicalCredential = CanonicalizeJcs(credentialJson);
        var canonicalProofOptions = CanonicalizeJcs(proofOptionsJson);

        var credentialHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCredential));
        var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));
        var hashData = proofOptionsHash.Concat(credentialHash).ToArray();

        return await VerifySignatureAsync(proof.ProofValue!, hashData, verificationMethod);
    }


    /// <summary>
    /// Checks credential validity period.
    /// </summary>
    private static CredentialVerificationResult CheckCredentialValidity(VerifiableCredential credential)
    {
        var now = DateTime.UtcNow;

        if(credential.ValidUntil.HasValue && now > credential.ValidUntil.Value)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.CredentialExpired);
        }

        if(credential.ValidFrom.HasValue && now < credential.ValidFrom.Value)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.CredentialNotYetValid);
        }

        return CredentialVerificationResult.Success();
    }


    /// <summary>
    /// Verifies a signature against verification method.
    /// </summary>
    private static async Task<CredentialVerificationResult> VerifySignatureAsync(
        string proofValue,
        byte[] hashData,
        VerificationMethod verificationMethod)
    {
        var signatureBytes = MultibaseSerializer.Decode(
            proofValue,
            0,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        var signatureToVerify = new Signature(signatureBytes, Tag.Ed25519Signature);

        var isValid = await verificationMethod.VerifySignatureAsync(
            hashData,
            signatureToVerify,
            SensitiveMemoryPool<byte>.Shared);

        if(!isValid)
        {
            return CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid);
        }

        return CredentialVerificationResult.Success();
    }


    /// <summary>
    /// Canonicalizes a JSON-LD document using RDFC-1.0 with static context resolution.
    /// </summary>
    private static string CanonicalizeRdfc(string jsonLdDocument)
    {
        var store = new TripleStore();
        var parserOptions = new JsonLdProcessorOptions
        {
            ProcessingMode = JsonLdProcessingMode.JsonLd11,
            DocumentLoader = CreateContextResolver()
        };
        var parser = new JsonLdParser(parserOptions);

        using var reader = new StringReader(jsonLdDocument);
        parser.Load(store, reader);

        var canonicalizer = new RdfCanonicalizer();
        var canonicalizedResult = canonicalizer.Canonicalize(store);

        return canonicalizedResult.SerializedNQuads;
    }


    /// <summary>
    /// Canonicalizes a JSON document using JSON Canonicalization Scheme (RFC 8785).
    /// </summary>
    private static string CanonicalizeJcs(string json)
    {
        var jsonNode = JsonNode.Parse(json);

        return CanonicalizeJsonNode(jsonNode);
    }


    /// <summary>
    /// Recursively canonicalizes a JSON node per RFC 8785.
    /// </summary>
    private static string CanonicalizeJsonNode(JsonNode? node)
    {
        if(node == null)
        {
            return "null";
        }

        if(node is JsonValue value)
        {
            return CanonicalizeJsonValue(value);
        }

        if(node is JsonArray array)
        {
            var elements = array.Select(CanonicalizeJsonNode);

            return $"[{string.Join(",", elements)}]";
        }

        if(node is JsonObject obj)
        {
            //RFC 8785: Sort object members by their UTF-16 code unit values.
            var sortedMembers = obj
                .OrderBy(kvp => kvp.Key, StringComparer.Ordinal)
                .Select(kvp => $"\"{EscapeJsonString(kvp.Key)}\":{CanonicalizeJsonNode(kvp.Value)}");

            return $"{{{string.Join(",", sortedMembers)}}}";
        }

        return node.ToJsonString();
    }


    /// <summary>
    /// Canonicalizes a JSON value per RFC 8785.
    /// </summary>
    private static string CanonicalizeJsonValue(JsonValue value)
    {
        var element = value.GetValue<JsonElement>();

        return element.ValueKind switch
        {
            JsonValueKind.String => $"\"{EscapeJsonString(element.GetString()!)}\"",
            JsonValueKind.Number => CanonicalizeNumber(element),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => element.GetRawText()
        };
    }


    /// <summary>
    /// Canonicalizes a number per RFC 8785 (ES6 Number.toString semantics).
    /// </summary>
    private static string CanonicalizeNumber(JsonElement element)
    {
        if(element.TryGetInt64(out var longValue))
        {
            return longValue.ToString();
        }

        var doubleValue = element.GetDouble();

        //RFC 8785: Use ES6 serialization for floating-point numbers.
        if(double.IsInfinity(doubleValue) || double.IsNaN(doubleValue))
        {
            return "null";
        }

        //Use round-trip format to preserve precision.
        return doubleValue.ToString("G17", System.Globalization.CultureInfo.InvariantCulture);
    }


    /// <summary>
    /// Escapes a string for JSON output per RFC 8259.
    /// </summary>
    private static string EscapeJsonString(string input)
    {
        var sb = new StringBuilder();
        foreach(var c in input)
        {
            switch(c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if(c < 0x20)
                    {
                        sb.Append($"\\u{(int)c:X4}");
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }

        return sb.ToString();
    }
}


/// <summary>
/// Result of a credential verification operation.
/// </summary>
public readonly struct CredentialVerificationResult: IEquatable<CredentialVerificationResult>
{
    public bool IsValid { get; }

    public VerificationFailureReason? FailureReason { get; }

    private CredentialVerificationResult(bool isValid, VerificationFailureReason? failureReason)
    {
        IsValid = isValid;
        FailureReason = failureReason;
    }

    public static CredentialVerificationResult Success() => new(true, null);

    public static CredentialVerificationResult Failed(VerificationFailureReason reason) => new(false, reason);

    public bool Equals(CredentialVerificationResult other)
    {
        return IsValid == other.IsValid && FailureReason == other.FailureReason;
    }

    public override bool Equals(object? obj)
    {
        return obj is CredentialVerificationResult other && Equals(other);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(IsValid, FailureReason);
    }

    public static bool operator ==(CredentialVerificationResult left, CredentialVerificationResult right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(CredentialVerificationResult left, CredentialVerificationResult right)
    {
        return !left.Equals(right);
    }

    public override string ToString()
    {
        return IsValid ? "Success" : $"Failed: {FailureReason}";
    }
}


/// <summary>
/// Reasons why credential verification might fail.
/// </summary>
public enum VerificationFailureReason
{
    NoProof,
    MissingVerificationMethod,
    VerificationMethodNotFound,
    SignatureInvalid,
    CredentialExpired,
    CredentialNotYetValid,
    IssuerDidResolutionFailed
}