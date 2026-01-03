using System;
using System.Buffers;
using Verifiable.Core.Model.Proofs;
using Verifiable.Core.Serialization;
using Verifiable.Core.Serialization.Json;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Extension methods for adding Data Integrity signing capabilities to <see cref="CredentialBuilder"/>.
/// </summary>
/// <remarks>
/// <para>
/// These extensions enable the builder to capture signing configuration so that
/// <see cref="CredentialBuilder.BuildAsync"/> returns signed credentials directly.
/// </para>
/// <para>
/// This follows the builder pattern principle where "non-moving parts" (signing configuration)
/// are captured in the builder, while "varying parts" (issuer, subject, etc.) are provided
/// at build time.
/// </para>
/// </remarks>
public static class CredentialBuilderSigningExtensions
{
    extension(CredentialBuilder builder)
    {
        /// <summary>
        /// Configures the builder to sign credentials using Data Integrity proofs during build.
        /// </summary>
        /// <param name="privateKey">The private key material for signing.</param>
        /// <param name="verificationMethodId">
        /// The DID URL identifying the verification method (e.g., <c>"did:web:example.com#key-1"</c>).
        /// </param>
        /// <param name="cryptosuite">
        /// The cryptosuite to use for signing (e.g., <c>EddsaJcs2022CryptosuiteInfo.Instance</c>).
        /// </param>
        /// <param name="canonicalize">
        /// The canonicalization function for the cryptosuite's algorithm.
        /// </param>
        /// <param name="contextResolver">
        /// Optional delegate for resolving JSON-LD contexts. Required for RDFC-based cryptosuites,
        /// can be null for JCS-based cryptosuites.
        /// </param>
        /// <param name="encodeProofValue">
        /// Delegate for encoding the signature bytes to a proof value string.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <remarks>
        /// <para>
        /// When signing is configured, the builder's transformations will include a final
        /// async transformation that signs the credential. The signing occurs after all
        /// other transformations have been applied.
        /// </para>
        /// <para>
        /// The signing uses the <see cref="CredentialDataIntegrityExtensions.SignAsync"/> method
        /// internally. See that method for details on the proof creation algorithm.
        /// </para>
        /// </remarks>
        public CredentialBuilder WithSigning(
            PrivateKeyMemory privateKey,
            string verificationMethodId,
            CryptosuiteInfo cryptosuite,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueEncoderDelegate encodeProofValue,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
            ArgumentNullException.ThrowIfNull(cryptosuite, nameof(cryptosuite));
            ArgumentNullException.ThrowIfNull(canonicalize, nameof(canonicalize));
            ArgumentNullException.ThrowIfNull(encodeProofValue, nameof(encodeProofValue));
            ArgumentNullException.ThrowIfNull(serialize, nameof(serialize));
            ArgumentNullException.ThrowIfNull(deserialize, nameof(deserialize));
            ArgumentNullException.ThrowIfNull(serializeProofOptions, nameof(serializeProofOptions));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            return builder.With(async (credential, _, _) =>
            {
                return await credential.SignAsync(
                    privateKey,
                    verificationMethodId,
                    cryptosuite,
                    canonicalize,
                    contextResolver,
                    encodeProofValue,
                    serialize,
                    deserialize,
                    serializeProofOptions,
                    memoryPool);
            });
        }
    }
}