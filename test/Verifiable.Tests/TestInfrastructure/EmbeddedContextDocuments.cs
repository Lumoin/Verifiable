namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Some embedded JSON-LD context documents for testing purposes so that
    /// there is no need to fetch from the network during tests, ensuring test determinism and offline operation.
    /// </summary>
    internal class EmbeddedContextDocuments
    {
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

            "image": {"@id": "https://schema.org/image", "@type": "@id"},

            "QuantitativeValue": {
              "@id": "https://schema.org/QuantitativeValue",
              "@context": {
                "@protected": true,

                "unitCode": "https://schema.org/unitCode",
                "value": "https://schema.org/value"
              }
            },

            "PostalAddress": {
              "@id": "https://schema.org/PostalAddress",
              "@context": {
                "@protected": true,

                "addressCountry": "https://schema.org/addressCountry",
                "addressLocality": "https://schema.org/addressLocality",
                "addressRegion": "https://schema.org/addressRegion"
              }
            },

            "Person": {
              "@id": "https://schema.org/Person",

              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "additionalName": "https://schema.org/additionalName",
                "birthCountry": "https://w3id.org/citizenship#birthCountry",
                "birthDate": {"@id": "https://schema.org/birthDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
                "familyName": "https://schema.org/familyName",
                "gender": "https://schema.org/gender",
                "givenName": "https://schema.org/givenName",
                "height": "https://schema.org/height",
                "image": {"@id": "https://schema.org/image", "@type": "@id"},
                "maritalStatus": "https://w3id.org/citizenship#maritalStatus",
                "marriageCertificateNumber": "https://w3id.org/citizenship#marriageCertificateNumber",
                "marriageLocation": {"@id": "https://w3id.org/citizenship#marriageLocation", "@type": "@id"}
              }
            },

            "PermanentResident": {
              "@id": "https://w3id.org/citizenship#PermanentResident",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "commuterClassification": "https://w3id.org/citizenship#commuterClassification",
                "formerNationality": "https://w3id.org/citizenship#formerNationality",
                "permanentResidentCard": {"@id": "https://w3id.org/citizenship#permanentResidentCard", "@type": "@id"},
                "residence": {"@id": "https://w3id.org/citizenship#residence", "@type": "@id"},
                "residentSince": {"@id": "https://w3id.org/citizenship#residentSince", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
              }
            },

            "PermanentResidentCard": {
              "@id": "https://w3id.org/citizenship#PermanentResidentCard",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
                "identifier": "https://schema.org/identifier",
                "lprCategory": "https://w3id.org/citizenship#lprCategory",
                "lprNumber": "https://w3id.org/citizenship#lprNumber",
                "mrzHash": {
                  "@id": "https://w3id.org/citizenship#mrzHash",
                  "@type": "https://w3id.org/security#multibase"
                }
              }
            },

            "PermanentResidentCardCredential": "https://w3id.org/citizenship#PermanentResidentCardCredential",

            "EmployablePerson": {
              "@id": "https://w3id.org/citizenship#EmployablePerson",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "commuterClassification": "https://w3id.org/citizenship#commuterClassification",
                "employmentAuthorizationDocument": {"@id": "https://w3id.org/citizenship#employmentAuthorizationDocument", "@type": "@id"},
                "formerNationality": "https://w3id.org/citizenship#formerNationality",
                "residence": {"@id": "https://w3id.org/citizenship#residence", "@type": "@id"},
                "residentSince": {"@id": "https://w3id.org/citizenship#residentSince", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
              }
            },

            "EmploymentAuthorizationDocument": {
              "@id": "https://w3id.org/citizenship#EmploymentAuthorizationDocument",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
                "identifier": "https://schema.org/identifier",
                "lprCategory": "https://w3id.org/citizenship#lprCategory",
                "lprNumber": "https://w3id.org/citizenship#lprNumber",
                "mrzHash": {
                  "@id": "https://w3id.org/citizenship#mrzHash",
                  "@type": "https://w3id.org/security#multibase"
                }
              }
            },

            "EmploymentAuthorizationDocumentCredential": "https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential",

            "NaturalizedPerson": {
              "@id": "https://w3id.org/citizenship#NaturalizedPerson",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "formerNationality": "https://w3id.org/citizenship#formerNationality",
                "certificateOfNaturalization": {"@id": "https://w3id.org/citizenship#certificateOfNaturalization", "@type": "@id"},
                "residence": {"@id": "https://w3id.org/citizenship#residence", "@type": "@id"},
                "residentSince": {"@id": "https://w3id.org/citizenship#residentSince", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
                "commuterClassification": "https://w3id.org/citizenship#commuterClassification"
              }
            },

            "CertificateOfNaturalization": {
              "@id": "https://w3id.org/citizenship#CertificateOfNaturalization",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "ceremonyDate": {"@id": "https://w3id.org/citizenship#ceremonyDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
                "ceremonyLocation": {"@id": "https://w3id.org/citizenship#ceremonyLocation", "@type": "@id"},
                "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
                "naturalizationLocation": {"@id": "https://w3id.org/citizenship#naturalizationLocation", "@type": "@id"},
                "naturalizedBy": "https://w3id.org/citizenship#naturalizedBy",
                "identifier": "https://schema.org/identifier",
                "insRegistrationNumber": "https://w3id.org/citizenship#insRegistrationNumber"
              }
            },

            "CertificateOfNaturalizationCredential": "https://w3id.org/citizenship#CertificateOfNaturalizationCredential",

            "Citizen": {
              "@id": "https://w3id.org/citizenship#Citizen",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "certificateOfCitizenship": {"@id": "https://w3id.org/citizenship#certificateOfCitizenship", "@type": "@id"}
              }
            },

            "CertificateOfCitizenship": {
              "@id": "https://w3id.org/citizenship#CertificateOfCitizenship",
              "@context": {
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
                "identifier": "https://schema.org/identifier",
                "ceremonyDate": {"@id": "https://w3id.org/citizenship#ceremonyDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
                "ceremonyLocation": {"@id": "https://w3id.org/citizenship#ceremonyLocation", "@type": "@id"},
                "cisRegistrationNumber": "https://w3id.org/citizenship#cisRegistrationNumber"
              }
            },

            "CertificateOfCitizenshipCredential": "https://w3id.org/citizenship#CertificateOfCitizenshipCredential"
          }
        }
        """;


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
    }
}
