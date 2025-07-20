//TODO: Refactor along with MultibaseSerializer and WellKnownKeyFormats. I.e. this should use a delegate to
//use a user supplied Base64Url encoder.
using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Core.Builders;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Cryptography;
using Verifiable.Jwt;

namespace Verifiable.Core.Builders
{
    public static class IdentifierExtensions
    {
        public static string EncodeKey(PublicKeyMemory publicKey, KeyFormat keyFormat)
        {
            if(keyFormat is PublicKeyJwk)
            {
                return Base64Url.Encode(publicKey.AsReadOnlySpan());
            }

            var algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
            var purpose = publicKey.Tag.Get<Purpose>();

            return VerifiableCryptoFormatConversions.DefaultAlgorithmToBase58Converter(
                algorithm,
                purpose,
                publicKey.AsReadOnlySpan(),
                DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyMultibase));
        }
    }


    /// <summary>
    /// Builds <c>did:web</c> DID documents using a fold/aggregate pattern with representation-aware defaults.
    /// This builder follows both the <c>did:web</c> specification (https://w3c-ccg.github.io/did-method-web/)
    /// and the DID Core specification for creating standards-compliant DID documents that can be served
    /// via HTTPS from web domains. Supports both single and multiple keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The WebDidBuilder implements representation-aware document construction following
    /// the DID Core specification's production and consumption rules:
    /// </para>
    /// <list type="bullet">
    /// <item><description>JSON representation (§6.2): No @context property, plain JSON structure</description></item>
    /// <item><description>JSON-LD representation (§6.3): Includes @context with required DID context</description></item>
    /// </list>
    /// <para>
    /// Key features:
    /// </para>
    /// <list type="number">
    /// <item><description>Representation-aware context management following DID Core specification</description></item>
    /// <item><description>Configurable DID Core version selection (1.0, 1.1, etc.)</description></item>
    /// <item><description>Support for additional contexts when extending the DID document</description></item>
    /// <item><description>Compliance with did:web key material and document handling rules</description></item>
    /// <item><description>Multi-key support with automatic verification relationship assignment</description></item>
    /// </list>
    /// <para>
    /// According to the did:web specification, when a document is served as did.json:
    /// </para>
    /// <list type="bullet">
    /// <item><description>If @context is present, process as JSON-LD following §6.3.2</description></item>
    /// <item><description>If no @context is present, process as JSON following §6.2.2</description></item>
    /// <item><description>The context https://www.w3.org/ns/did/v1 MUST be present for JSON-LD processing</description></item>
    /// </list>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Single key usage
    /// var builder = new WebDidBuilder();
    /// var didDocument = builder.Build(publicKey, verificationMethodType, "example.com");
    ///
    /// // Multiple key usage
    /// var keyInputs = new[]
    /// {
    ///     new KeyMaterialInput { PublicKey = signingKey, VerificationMethodType = Ed25519VerificationMethod.Instance },
    ///     new KeyMaterialInput { PublicKey = exchangeKey, VerificationMethodType = X25519KeyAgreementKey2020VerificationMethod.Instance }
    /// };
    /// var didDocument = builder.Build(keyInputs, "example.com");
    /// </code>
    /// </example>
    public sealed class WebDidBuilder: Builder<DidDocument, WebDidBuildState, WebDidBuilder>
    {
        /// <summary>
        /// Gets or sets the fragment generator used to create fragment identifiers for verification methods.
        /// Defaults to generating numbered fragments like "key-1", "key-2", etc.
        /// </summary>
        public FragmentGenerator FragmentGenerator { get; set; } = NumberedFragmentGenerator;


        /// <summary>
        /// Default fragment generator that creates numbered fragments for all keys.
        /// </summary>
        public static FragmentGenerator NumberedFragmentGenerator { get; } = (state) =>
        {
            var webDidState = (WebDidBuildState)state;
            return $"key-{webDidState.CurrentVerificationMethodIndex + 1}";
        };


        /// <summary>
        /// Alternative fragment generator that uses encoded key identifiers.
        /// </summary>
        public static FragmentGenerator EncodedKeyFragmentGenerator { get; } = (state) =>
        {
            if(state is WebDidBuildState webDidState)
            {
                var keyInput = webDidState.KeyInputs[webDidState.CurrentVerificationMethodIndex];
                var keyFormat = keyInput.VerificationMethodType.CreateKeyFormat(keyInput.PublicKey);
                return IdentifierExtensions.EncodeKey(keyInput.PublicKey, keyFormat);
            }

            return "key-1";
        };


        /// <summary>
        /// Initializes a new instance of the <see cref="WebDidBuilder"/> class with representation-aware transformations.
        /// The builder automatically configures context handling based on the target representation type.
        /// </summary>
        /// <remarks>
        /// The default transformations are applied in this order:
        /// <list type="number">
        /// <item><description>Context management: Adds @context for JSON-LD and JsonWithContext representations</description></item>
        /// <item><description>Verification method creation: With web-appropriate key format and identifiers</description></item>
        /// <item><description>DID identifier setup: Based on the provided web domain</description></item>
        /// <item><description>Verification relationship assignment: Based on key capabilities</description></item>
        /// </list>
        /// <para>
        /// Context handling follows DID Core specification requirements:
        /// </para>
        /// <list type="bullet">
        /// <item><description>JsonWithoutContext: No @context property is added</description></item>
        /// <item><description>JsonWithContext/JsonLd: @context array starts with the specified DID Core version</description></item>
        /// <item><description>Additional contexts are appended to the @context array when present</description></item>
        /// </list>
        /// </remarks>
        public WebDidBuilder()
        {
            //First transformation: Handle @context based on representation type.
            _ = With((didDocument, builder, buildState) =>
            {
                switch(buildState.RepresentationType)
                {
                    case DidRepresentationType.JsonLd:
                    case DidRepresentationType.JsonWithContext:
                        //Create new context with the specified DID Core version.
                        var context = new Context
                        {
                            Contexes = new List<object> { buildState.DidCoreVersion }
                        };

                        //Add any additional contexts specified in build state.
                        if(buildState.AdditionalContexts.Length > 0)
                        {
                            context.Contexes.AddRange(buildState.AdditionalContexts);
                        }

                        //Set the context on the DID document.
                        didDocument.Context = context;
                        break;

                    case DidRepresentationType.JsonWithoutContext:
                        //For JSON representation without context, no @context property is added.
                        break;

                    default:
                        throw new ArgumentOutOfRangeException(nameof(buildState.RepresentationType),
                            buildState.RepresentationType,
                            "Unknown representation type");
                }

                return didDocument;
            })
            //Second transformation: Create all verification methods with appropriate key formats.
            .With((didDocument, builder, buildState) =>
            {
                var verificationMethods = new List<VerificationMethod>();
                var fragmentGenerator = builder.FragmentGenerator;

                for(int i = 0; i < buildState.KeyInputs.Count; i++)
                {
                    buildState.CurrentVerificationMethodIndex = i;
                    var keyInput = buildState.KeyInputs[i];

                    string fragment = keyInput.Fragment ?? fragmentGenerator(buildState);
                    string verificationMethodId = CreateVerificationMethodId(buildState.WebDomain, fragment);

                    var keyFormat = keyInput.VerificationMethodType.CreateKeyFormat(keyInput.PublicKey);

                    //Add key identifier to JWK header if using JWK format.
                    if(keyFormat is PublicKeyJwk publicKeyJwk)
                    {
                        var encodedKey = IdentifierExtensions.EncodeKey(keyInput.PublicKey, keyFormat);
                        publicKeyJwk.Header.Add("kid", encodedKey);
                    }

                    var verificationMethod = new VerificationMethod
                    {
                        Id = verificationMethodId,
                        Type = keyInput.VerificationMethodType.TypeName,
                        Controller = CreateDidId(buildState.WebDomain),
                        KeyFormat = keyFormat
                    };

                    verificationMethods.Add(verificationMethod);
                }

                didDocument.VerificationMethod = verificationMethods.ToArray();
                return didDocument;
            })
            //Third transformation: Set up DID identifier and configure verification relationships.
            .With((didDocument, builder, buildState) =>
            {
                //Set the main DID identifier.
                didDocument.Id = new WebDidMethod(CreateDidId(buildState.WebDomain));

                var fragmentGenerator = builder.FragmentGenerator;

                //Configure verification relationships based on key capabilities.
                for(int i = 0; i < buildState.KeyInputs.Count; i++)
                {
                    buildState.CurrentVerificationMethodIndex = i;
                    var keyInput = buildState.KeyInputs[i];

                    string fragment = keyInput.Fragment ?? fragmentGenerator(buildState);
                    string verificationMethodId = CreateVerificationMethodId(buildState.WebDomain, fragment);

                    if(keyInput.PublicKey.SupportsSigning())
                    {
                        didDocument.WithAuthentication(verificationMethodId)
                                   .WithAssertionMethod(verificationMethodId)
                                   .WithCapabilityInvocation(verificationMethodId)
                                   .WithCapabilityDelegation(verificationMethodId);
                    }

                    if(keyInput.PublicKey.SupportsKeyAgreement())
                    {
                        didDocument.WithKeyAgreement(verificationMethodId);
                    }
                }

                return didDocument;
            });
        }


        /// <summary>
        /// Builds a <c>did:web</c> DID document from the provided key material inputs.
        /// </summary>
        /// <param name="keyInputs">
        /// The collection of key material inputs to use for creating the DID document.
        /// </param>
        /// <param name="webDomain">The web domain that forms the basis of the DID identifier.</param>
        /// <param name="representationType">The target representation type controlling @context handling.</param>
        /// <param name="didCoreVersion">The DID Core version to use for the context URI. Defaults to DID Core 1.0 when context is needed.</param>
        /// <param name="additionalContexts">Additional contexts to include when @context is present.</param>
        /// <returns>A fully constructed <c>did:web</c> DID document in the specified representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        /// <exception cref="ArgumentException">Thrown when webDomain is null or whitespace or keyInputs is empty.</exception>
        public DidDocument Build(
            IEnumerable<KeyMaterialInput> keyInputs,
            string webDomain,
            DidRepresentationType representationType = DidRepresentationType.JsonLd,
            string? didCoreVersion = null,
            params string[] additionalContexts)
        {
            ArgumentNullException.ThrowIfNull(keyInputs, nameof(keyInputs));
            ArgumentException.ThrowIfNullOrWhiteSpace(webDomain, nameof(webDomain));

            var keyInputsList = keyInputs.ToList();
            if(keyInputsList.Count == 0)
            {
                throw new ArgumentException("At least one key input is required.", nameof(keyInputs));
            }

            //Determine the effective DID Core version based on representation type.
            string effectiveDidCoreVersion = representationType switch
            {
                DidRepresentationType.JsonWithoutContext => string.Empty, //Not used for this representation type.
                _ => didCoreVersion ?? Context.DidCore10 //Default to DID Core 1.0 when context is needed.
            };

            //Create the build state for the fold/aggregate operation.
            WebDidBuildState buildState = new()
            {
                WebDomain = webDomain,
                KeyInputs = keyInputsList,
                RepresentationType = representationType,
                DidCoreVersion = effectiveDidCoreVersion,
                AdditionalContexts = additionalContexts ?? [],
                CurrentVerificationMethodIndex = 0 //Will be updated during transformations
            };

            //Build with default-constructed DID document.
            return Build(
                param: keyInputsList,
                preBuildAction: (_, _) => buildState);
        }


        /// <summary>
        /// Builds a <c>did:web</c> DID document with explicit representation type control.
        /// This method provides full control over the document representation format and @context handling.
        /// This is a convenience method for single-key scenarios.
        /// </summary>
        /// <param name="publicKey">The public key material to use for creating the DID document.</param>
        /// <param name="verificationMethodType">The cryptographic suite that determines how the public key is represented.</param>
        /// <param name="webDomain">The web domain that forms the basis of the DID identifier.</param>
        /// <param name="representationType">The target representation type controlling @context handling.</param>
        /// <param name="didCoreVersion">The DID Core version to use for the context URI. Defaults to DID Core 1.0 when context is needed.</param>
        /// <param name="additionalContexts">Additional contexts to include when @context is present.</param>
        /// <returns>A fully constructed <c>did:web</c> DID document in the specified representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        /// <exception cref="ArgumentException">Thrown when webDomain is null or whitespace.</exception>
        /// <remarks>
        /// <para>
        /// This method creates a DID document following the production rules specified in DID Core:
        /// </para>
        /// <list type="bullet">
        /// <item>
        /// <description>
        /// <strong>JsonWithoutContext</strong>: Plain JSON structure without @context (minimal)
        /// </description>
        /// </item>
        /// <item>
        /// <description>
        /// <strong>JsonWithContext</strong>: JSON structure with @context included (dual compatibility)
        /// </description>
        /// </item>
        /// <item>
        /// <description>
        /// <strong>JsonLd</strong>: Full JSON-LD with required @context (semantic processing)
        /// </description>
        /// </item>
        /// </list>
        /// <para>
        /// When @context is included (JsonWithContext or JsonLd), it always starts with the specified
        /// DID Core version (defaulting to DID Core 1.0) followed by any additional contexts.
        /// For JsonWithoutContext, the didCoreVersion parameter is ignored since no context is created.
        /// </para>
        /// </remarks>
        public DidDocument Build(
            PublicKeyMemory publicKey,
            VerificationMethodTypeInfo verificationMethodType,
            string webDomain,
            DidRepresentationType representationType = DidRepresentationType.JsonLd,
            string? didCoreVersion = null,
            params string[] additionalContexts)
        {
            var keyInputs = new[]
            {
                new KeyMaterialInput
                {
                    PublicKey = publicKey,
                    VerificationMethodType = verificationMethodType
                }
            };

            return Build(keyInputs, webDomain, representationType, didCoreVersion, additionalContexts);
        }


        /// <summary>
        /// Creates a DID identifier following the <c>did:web</c> specification format.
        /// </summary>
        /// <param name="webDomain">The web domain for the DID.</param>
        /// <returns>A properly formatted <c>did:web</c> identifier.</returns>
        private static string CreateDidId(string webDomain)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(webDomain, nameof(webDomain));
            return $"{WebDidMethod.Prefix}{webDomain}";
        }


        /// <summary>
        /// Creates a verification method identifier following the <c>did:web</c> specification format.
        /// </summary>
        /// <param name="webDomain">The web domain for the DID.</param>
        /// <param name="fragment">The fragment identifier.</param>
        /// <returns>A properly formatted verification method identifier with fragment.</returns>
        private static string CreateVerificationMethodId(string webDomain, string fragment)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(webDomain, nameof(webDomain));
            ArgumentException.ThrowIfNullOrWhiteSpace(fragment, nameof(fragment));

            return $"{WebDidMethod.Prefix}{webDomain}#{fragment}";
        }
    }
}