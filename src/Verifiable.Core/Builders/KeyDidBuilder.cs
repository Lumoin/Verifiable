using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Cryptography;

namespace Verifiable.Core.Builders
{
    /// <summary>
    /// Builds <c>did:key</c> DID documents using a fold/aggregate pattern with sensible defaults.
    /// This builder follows the <c>did:key</c> specification (https://w3c-ccg.github.io/did-method-key/)
    /// for creating DID documents from cryptographic key material.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The KeyDidBuilder implements a fold/aggregate pattern where transformation functions
    /// are applied sequentially to build up a complete DID document. The builder provides
    /// default transformations that:
    /// </para>
    /// <list type="number">
    /// <item><description>Create a verification method with the appropriate key format</description></item>
    /// <item><description>Set up the DID identifier based on the encoded public key</description></item>
    /// <item><description>Configure all verification relationships (authentication, assertion, etc.)</description></item>
    /// </list>
    /// <para>
    /// The <c>did:key</c> method is designed for use cases where a DID document can be derived
    /// deterministically from a single public key, making it suitable for scenarios that
    /// require no external resolution infrastructure.
    /// </para>
    /// <para>
    /// Verifiable library provides this preconfigured builder with sensible defaults,
    /// but it can be extended with additional transformation functions using the <see cref="Builder{TResult, TState, TBuilder}.With"/> method.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage with default configuration
    /// var builder = new KeyDidBuilder();
    /// var didDocument = builder.Build(publicKey, JsonWebKey2020.DefaultInstance);
    ///
    /// // Extended usage with custom transformations
    /// var customBuilder = new KeyDidBuilder()
    ///     .With((doc, builder, state) => {
    ///         // Add custom service endpoint
    ///         doc.Service = [new Service {
    ///             Id = CreateServiceId(doc.Id, "service-1"),
    ///             Type = "CustomService",
    ///             ServiceEndpoint = "https://example.com/service"
    ///         }];
    ///         return doc;
    ///     });
    /// </code>
    /// </example>
    public sealed class KeyDidBuilder: Builder<DidDocument, KeyDidBuildState, KeyDidBuilder>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDidBuilder"/> class with default transformations.
        /// The default configuration creates a compliant <c>did:key</c> DID document with all standard verification relationships.
        /// </summary>
        /// <remarks>
        /// The default transformations applied during construction are:
        /// <list type="number">
        /// <item><description>Verification method creation with appropriate key format</description></item>
        /// <item><description>DID identifier setup and verification relationship configuration</description></item>
        /// </list>
        /// These transformations follow the <c>did:key</c> specification and create a fully functional DID document.
        /// </remarks>
        public KeyDidBuilder()
        {
            //First transformation: Create the verification method with the appropriate key format.
            _ = With((didDocument, builder, buildState) =>
            {
                string encodedPublicKey = buildState.EncodedKey;
                PublicKeyMemory publicKey = buildState.PublicKey;
                CryptographicSuite cryptoSuiteChosen = buildState.Suite;

                //Determine the appropriate key format based on the DID method and crypto suite.
                var keyFormatSelected = SsiKeyFormatSelector.DefaultKeyFormatSelector(typeof(KeyDidMethod), cryptoSuiteChosen);
                var keyFormat = SsiKeyFormatSelector.DefaultKeyFormatCreator(keyFormatSelected, publicKey);

                //Create the verification method following did:key conventions.
                didDocument.VerificationMethod =
                [
                    new VerificationMethod
                    {
                        Id = CreateVerificationMethodId(encodedPublicKey),
                        Type = cryptoSuiteChosen.VerificationMethodType,
                        Controller = CreateDidId(encodedPublicKey),
                        KeyFormat = keyFormat
                    }
                ];

                return didDocument;
            })
            //Second transformation: Set up DID identifier and all verification relationships.
            .With((didDocument, builder, buildState) =>
            {
                string encodedPublicKey = buildState.EncodedKey;
                var didId = CreateDidId(encodedPublicKey);
                var didVerificationMethodId = CreateVerificationMethodId(encodedPublicKey);

                //Set the main DID identifier.
                didDocument.Id = new KeyDidMethod(didId);

                if(buildState.PublicKey.SupportsSigning())
                {
                    didDocument.WithAuthentication(didVerificationMethodId)
                               .WithAssertionMethod(didVerificationMethodId)
                               .WithCapabilityInvocation(didVerificationMethodId)
                               .WithCapabilityDelegation(didVerificationMethodId);
                }
                else if(buildState.PublicKey.SupportsKeyAgreement())
                {
                    didDocument.WithKeyAgreement(didVerificationMethodId);
                }

                return didDocument;
            });
        }


        /// <summary>
        /// Builds a <c>did:key</c> DID document from the provided public key material and cryptographic suite.
        /// </summary>
        /// <param name="publicKey">
        /// The public key material to use for creating the DID document.
        /// Must contain valid cryptographic material with appropriate algorithm and purpose metadata.
        /// </param>
        /// <param name="cryptoSuite">
        /// The cryptographic suite that determines how the public key is represented in the verification method.
        /// Common options include <see cref="JsonWebKey2020"/> and <see cref="Multikey"/>.
        /// </param>
        /// <param name="includeDefaultContext">
        /// If <c>true</c>, includes the default JSON-LD context in the DID document.
        /// This is useful for scenarios requiring JSON-LD processing.
        /// </param>
        /// <returns>A fully constructed <c>did:key</c> DID document.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="publicKey"/> or <paramref name="cryptoSuite"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when the public key material is invalid or missing required metadata.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This method extracts the algorithm and purpose information from the public key's metadata,
        /// encodes the key according to the <c>did:key</c> specification, and applies all registered
        /// transformation functions to build the complete DID document.
        /// </para>
        /// <para>
        /// The resulting DID document will include:
        /// </para>
        /// <list type="bullet">
        /// <item><description>A properly formatted <c>did:key</c> identifier</description></item>
        /// <item><description>A verification method with the specified key format</description></item>
        /// <item><description>All standard verification relationships</description></item>
        /// <item><description>Optional JSON-LD context if requested</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// var builder = new KeyDidBuilder();
        ///
        /// // Create DID document with JWK format
        /// var didDoc = builder.Build(publicKey, JsonWebKey2020.DefaultInstance);
        ///
        /// // Create DID document with JSON-LD context
        /// var didDocWithContext = builder.Build(publicKey, Multikey.DefaultInstance, includeDefaultContext: true);
        /// </code>
        /// </example>
        public DidDocument Build(PublicKeyMemory publicKey, CryptographicSuite cryptoSuite, bool includeDefaultContext = false)
        {
            ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
            ArgumentNullException.ThrowIfNull(cryptoSuite, nameof(cryptoSuite));

            //Extract algorithm and purpose from the public key metadata.
            var algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
            var purpose = publicKey.Tag.Get<Purpose>();

            //Encode the public key according to did:key specification.
            string encodedPublicKey = VerifiableCryptoFormatConversions.DefaultAlgorithmToBase58Converter(
                algorithm,
                purpose,
                publicKey.AsReadOnlySpan(),
                DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyMultibase));

            //Create the build state for the fold/aggregate operation.
            KeyDidBuildState buildState = new()
            {
                EncodedKey = encodedPublicKey,
                PublicKey = publicKey,
                Suite = cryptoSuite
            };

            if(includeDefaultContext)
            {
                //Build with a pre-configured seed that includes the default JSON-LD context.
                //See https://w3c-ccg.github.io/did-method-key/#document-creation-algorithm for context requirements.
                return Build(
                    seedGenerator: _ => CreateDidDocumentWithDefaultContext(),
                    seedGeneratorParameter: (publicKey, cryptoSuite),
                    preBuildAction: (_, _) => buildState);
            }

            //Build with default-constructed DID document.
            return Build(
                param: (publicKey, cryptoSuite),
                preBuildAction: (_, _) => buildState);
        }


        /// <summary>
        /// Creates a DID identifier following the <c>did:key</c> specification format.
        /// </summary>
        /// <param name="encodedPublicKey">The Base58-encoded public key with multicodec header.</param>
        /// <returns>A properly formatted <c>did:key</c> identifier.</returns>
        /// <remarks>
        /// This method implements the identifier creation algorithm specified in
        /// https://w3c-ccg.github.io/did-method-key/#identifier-creation-algorithm.
        /// </remarks>
        /// <example>
        /// <code>
        /// string didId = CreateDidId("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        /// // Returns: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        /// </code>
        /// </example>
        private static string CreateDidId(string encodedPublicKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(encodedPublicKey, nameof(encodedPublicKey));

            return $"{KeyDidMethod.Prefix}{encodedPublicKey}";
        }


        /// <summary>
        /// Creates a verification method identifier following the <c>did:key</c> specification format.
        /// </summary>
        /// <param name="encodedPublicKey">The Base58-encoded public key with multicodec header.</param>
        /// <returns>A properly formatted verification method identifier with fragment.</returns>
        /// <remarks>
        /// This method implements the verification method creation algorithm specified in
        /// https://w3c-ccg.github.io/did-method-key/#signature-method-creation-algorithm.
        /// The fragment identifier is the same as the encoded public key, following the specification.
        /// </remarks>
        /// <example>
        /// <code>
        /// string vmId = CreateVerificationMethodId("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        /// // Returns: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        /// </code>
        /// </example>
        private static string CreateVerificationMethodId(string encodedPublicKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(encodedPublicKey, nameof(encodedPublicKey));

            return $"{KeyDidMethod.Prefix}{encodedPublicKey}#{encodedPublicKey}";
        }


        /// <summary>
        /// Creates a DID document with the default JSON-LD context required by the <c>did:key</c> specification.
        /// </summary>
        /// <returns>A DID document with the default context applied.</returns>
        /// <remarks>
        /// This method implements the document creation algorithm specified in
        /// https://w3c-ccg.github.io/did-method-key/#document-creation-algorithm and the context
        /// creation algorithm from https://w3c-ccg.github.io/did-method-key/#context-creation-algorithm.
        /// </remarks>
        private static DidDocument CreateDidDocumentWithDefaultContext()
        {
            var document = new DidDocument();
            document.AddDefaultContext();

            return document;
        }
    }
}