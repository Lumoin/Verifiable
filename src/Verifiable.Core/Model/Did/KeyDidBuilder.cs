using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents input for creating a verification method within a DID document.
    /// This encapsulates all the necessary information to create a verification method.
    /// </summary>
    public class KeyMaterialInput
    {
        /// <summary>
        /// Gets or sets the public key material for this verification method.
        /// </summary>
        public required PublicKeyMemory PublicKey { get; init; }

        /// <summary>
        /// Gets or sets the verification method type information that determines
        /// how the key will be represented in the DID document.
        /// </summary>
        public required VerificationMethodTypeInfo VerificationMethodType { get; init; }

        /// <summary>
        /// Gets or sets the fragment identifier for this verification method.
        /// If null, the builder should generate an appropriate fragment using the <see cref="FragmentGenerator"/>.
        /// </summary>
        /// <remarks>
        /// The <see cref="FragmentGenerator"/> should typically only be invoked when this property is null.
        /// This allows for explicit fragment specification while providing automatic generation as a fallback.
        /// </remarks>
        public string? Fragment { get; init; }
    }


    /// <summary>
    /// Builds <c>did:key</c> DID documents using a fold/aggregate pattern with sensible defaults.
    /// This builder follows the <c>did:key</c> specification (https://w3c-ccg.github.io/did-method-key/)
    /// for creating DID documents from cryptographic key material. Supports both single and multiple keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The KeyDidBuilder implements a fold/aggregate pattern where transformation functions
    /// are applied sequentially to build up a complete DID document. The builder provides
    /// default transformations that:
    /// </para>
    /// <list type="number">
    /// <item><description>Create verification methods with the appropriate key formats.</description></item>
    /// <item><description>Set up the DID identifier based on the primary encoded public key.</description></item>
    /// <item><description>Configure verification relationships based on key capabilities.</description></item>
    /// </list>
    /// <para>
    /// <strong>Relationship to Delegate-Based Patterns</strong>
    /// </para>
    /// <para>
    /// This builder is a convenience layer over the library's delegate-based primitives. The underlying
    /// key encoding uses <see cref="CryptoFormatConversions"/> and <see cref="DefaultCoderSelector"/>
    /// delegates. For maximum control over key encoding or custom DID document structures, use the
    /// underlying APIs directly.
    /// </para>
    /// <para>
    /// The <c>did:key</c> method is designed for use cases where a DID document can be derived
    /// deterministically from public key material, making it suitable for scenarios that
    /// require no external resolution infrastructure.
    /// </para>
    /// <para>
    /// For multiple keys, the first key in the collection is used to derive the DID identifier,
    /// and verification relationships are assigned based on each key's cryptographic capabilities.
    /// </para>
    /// <para>
    /// All transformations are asynchronous, enabling operations like key derivation or
    /// external lookups to be integrated directly into the build pipeline.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Single key usage.
    /// var builder = new KeyDidBuilder();
    /// var didDocument = await builder.BuildAsync(publicKey, JsonWebKey2020VerificationMethod.Instance, cancellationToken: ct);
    ///
    /// // Multiple key usage.
    /// var keyInputs = new[]
    /// {
    ///     new KeyMaterialInput { PublicKey = signingKey, VerificationMethodType = Ed25519VerificationMethod.Instance },
    ///     new KeyMaterialInput { PublicKey = exchangeKey, VerificationMethodType = X25519KeyAgreementKey2020VerificationMethod.Instance }
    /// };
    /// var didDocument = await builder.BuildAsync(keyInputs, cancellationToken: ct);
    /// </code>
    /// </example>
    public sealed class KeyDidBuilder: Builder<DidDocument, KeyDidBuildState, KeyDidBuilder>
    {
        /// <summary>
        /// Gets or sets the fragment generator used to create fragment identifiers for verification methods.
        /// Defaults to generating did:key compliant fragments.
        /// </summary>
        public FragmentGenerator FragmentGenerator { get; set; } = DidKeyCompliantFragmentGenerator;


        /// <summary>
        /// Default fragment generator that creates did:key compliant fragments.
        /// The first key uses the encoded key as fragment (per did:key spec), additional keys use numbered fragments.
        /// </summary>
        public static FragmentGenerator DidKeyCompliantFragmentGenerator { get; } = (state) =>
        {
            var keyDidState = (KeyDidBuildState)state;
            var index = keyDidState.CurrentVerificationMethodIndex;

            return index == 0 ? keyDidState.EncodedKey : $"key-{index + 1}";
        };


        /// <summary>
        /// Alternative fragment generator that creates numbered fragments for all keys.
        /// </summary>
        public static FragmentGenerator NumberedFragmentGenerator { get; } = (state) =>
        {
            var keyDidState = (KeyDidBuildState)state;

            return $"key-{keyDidState.CurrentVerificationMethodIndex + 1}";
        };


        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDidBuilder"/> class with default transformations.
        /// The default configuration creates a compliant <c>did:key</c> DID document with verification relationships
        /// assigned based on key capabilities.
        /// </summary>
        public KeyDidBuilder()
        {
            //First transformation: Create all verification methods with appropriate key formats.
            _ = With((didDocument, builder, buildState) =>
            {
                var verificationMethods = new List<VerificationMethod>();
                var fragmentGenerator = builder.FragmentGenerator;

                for(int i = 0; i < buildState!.KeyInputs.Count; i++)
                {
                    buildState.CurrentVerificationMethodIndex = i;
                    var keyInput = buildState.KeyInputs[i];

                    string fragment = keyInput.Fragment ?? fragmentGenerator(buildState);
                    string verificationMethodId = $"{buildState.DidId}#{fragment}";

                    var verificationMethod = new VerificationMethod
                    {
                        Id = verificationMethodId,
                        Type = keyInput.VerificationMethodType.TypeName,
                        Controller = buildState.DidId,
                        KeyFormat = keyInput.VerificationMethodType.CreateKeyFormat(keyInput.PublicKey)
                    };

                    verificationMethods.Add(verificationMethod);
                }

                didDocument.VerificationMethod = verificationMethods.ToArray();

                return ValueTask.FromResult(didDocument);
            })
            //Second transformation: Set up DID identifier and configure verification relationships.
            .With((didDocument, builder, buildState) =>
            {
                //Set the main DID identifier.
                didDocument.Id = new KeyDidMethod(buildState!.DidId);

                var fragmentGenerator = builder.FragmentGenerator;

                //Configure verification relationships based on key capabilities.
                for(int i = 0; i < buildState.KeyInputs.Count; i++)
                {
                    buildState.CurrentVerificationMethodIndex = i;
                    var keyInput = buildState.KeyInputs[i];

                    string fragment = keyInput.Fragment ?? fragmentGenerator(buildState);
                    string verificationMethodId = $"{buildState.DidId}#{fragment}";

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

                return ValueTask.FromResult(didDocument);
            });
        }


        /// <summary>
        /// Builds a <c>did:key</c> DID document from the provided key material inputs.
        /// </summary>
        /// <param name="keyInputs">
        /// The collection of key material inputs to use for creating the DID document.
        /// The first key in the collection is used to derive the DID identifier.
        /// </param>
        /// <param name="includeDefaultContext">
        /// If <c>true</c>, includes the default JSON-LD context in the DID document.
        /// This is useful for scenarios requiring JSON-LD processing.
        /// </param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{DidDocument}"/> containing the fully constructed DID document.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="keyInputs"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="keyInputs"/> is empty or contains invalid key material.
        /// </exception>
        /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
        /// <remarks>
        /// <para>
        /// This method processes multiple keys to create a comprehensive DID document.
        /// The first key in the collection determines the DID identifier, following the
        /// <c>did:key</c> specification encoding rules.
        /// </para>
        /// <para>
        /// Verification relationships are automatically assigned based on each key's capabilities:
        /// </para>
        /// <list type="bullet">
        /// <item><description>Keys supporting signing get: authentication, assertionMethod, capabilityInvocation, capabilityDelegation.</description></item>
        /// <item><description>Keys supporting key agreement get: keyAgreement.</description></item>
        /// </list>
        /// </remarks>
        public ValueTask<DidDocument> BuildAsync(
            IEnumerable<KeyMaterialInput> keyInputs,
            bool includeDefaultContext = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(keyInputs, nameof(keyInputs));

            var keyInputsList = keyInputs.ToList();
            if(keyInputsList.Count == 0)
            {
                throw new ArgumentException("At least one key input is required.", nameof(keyInputs));
            }

            //Use the first key to derive the DID identifier.
            var primaryKey = keyInputsList[0].PublicKey;
            var algorithm = primaryKey.Tag.Get<CryptoAlgorithm>();
            var purpose = primaryKey.Tag.Get<Purpose>();

            //Encode the primary key according to did:key specification.
            string encodedPublicKey = CryptoFormatConversions.DefaultAlgorithmToBase58Converter(
                algorithm,
                purpose,
                primaryKey.AsReadOnlySpan(),
                DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyMultibase));

            string didId = CreateDidId(encodedPublicKey);

            //Create the build state for the fold/aggregate operation.
            KeyDidBuildState buildState = new()
            {
                EncodedKey = encodedPublicKey,
                PublicKey = primaryKey,
                VerificationMethodTypeInfo = keyInputsList[0].VerificationMethodType,
                DidId = didId,
                KeyInputs = keyInputsList,
                CurrentVerificationMethodIndex = 0 //Will be updated during transformations.
            };

            if(includeDefaultContext)
            {
                //Build with a pre-configured seed that includes the default JSON-LD context.
                return BuildAsync(
                    seedGeneratorAsync: _ => ValueTask.FromResult(CreateDidDocumentWithDefaultContext()),
                    seedGeneratorParameter: keyInputsList,
                    preBuildActionAsync: (_, _) => ValueTask.FromResult(buildState),
                    cancellationToken: cancellationToken);
            }

            //Build with default-constructed DID document.
            return BuildAsync(
                param: keyInputsList,
                preBuildActionAsync: (_, _) => ValueTask.FromResult(buildState),
                cancellationToken: cancellationToken);
        }


        /// <summary>
        /// Builds a <c>did:key</c> DID document from a single public key and verification method type.
        /// This is a convenience method for single-key scenarios.
        /// </summary>
        /// <param name="publicKey">The public key material to use for creating the DID document.</param>
        /// <param name="verificationMethodType">The verification method type for the key representation.</param>
        /// <param name="includeDefaultContext">Whether to include the default JSON-LD context.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{DidDocument}"/> containing the fully constructed DID document.</returns>
        public ValueTask<DidDocument> BuildAsync(
            PublicKeyMemory publicKey,
            VerificationMethodTypeInfo verificationMethodType,
            bool includeDefaultContext = false,
            CancellationToken cancellationToken = default)
        {
            var keyInputs = new[]
            {
                new KeyMaterialInput
                {
                    PublicKey = publicKey,
                    VerificationMethodType = verificationMethodType
                }
            };

            return BuildAsync(keyInputs, includeDefaultContext, cancellationToken);
        }


        /// <summary>
        /// Creates a DID identifier following the <c>did:key</c> specification format.
        /// </summary>
        /// <param name="encodedPublicKey">The Base58-encoded public key with multicodec header.</param>
        /// <returns>A properly formatted <c>did:key</c> identifier.</returns>
        private static string CreateDidId(string encodedPublicKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(encodedPublicKey, nameof(encodedPublicKey));

            return $"{KeyDidMethod.Prefix}{encodedPublicKey}";
        }


        /// <summary>
        /// Creates a DID document with the default JSON-LD context required by the <c>did:key</c> specification.
        /// </summary>
        /// <returns>A DID document with the default context applied.</returns>
        private static DidDocument CreateDidDocumentWithDefaultContext()
        {
            var document = new DidDocument();
            document.AddDefaultContext();

            return document;
        }
    }
}