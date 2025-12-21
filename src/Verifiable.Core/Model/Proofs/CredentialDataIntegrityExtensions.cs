using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.Proofs;

/// <summary>
/// Delegate for serializing a credential to a string representation.
/// </summary>
/// <param name="credential">The credential to serialize.</param>
/// <returns>The serialized string representation.</returns>
public delegate string CredentialSerializeDelegate(VerifiableCredential credential);


/// <summary>
/// Delegate for deserializing a string representation to a credential.
/// </summary>
/// <param name="serialized">The serialized string representation.</param>
/// <returns>The deserialized credential.</returns>
public delegate VerifiableCredential CredentialDeserializeDelegate(string serialized);


/// <summary>
/// Delegate for building proof options as a serialized string.
/// </summary>
/// <param name="type">The proof type.</param>
/// <param name="cryptosuiteName">The cryptosuite name.</param>
/// <param name="created">The creation timestamp.</param>
/// <param name="verificationMethodId">The verification method identifier.</param>
/// <param name="proofPurpose">The proof purpose.</param>
/// <param name="context">Optional context for RDFC cryptosuites.</param>
/// <returns>The serialized proof options string.</returns>
public delegate string ProofOptionsSerializeDelegate(
    string type,
    string cryptosuiteName,
    string created,
    string verificationMethodId,
    string proofPurpose,
    object? context);


#pragma warning disable RS0030 // Do not use banned APIs
/// <summary>
/// Extension methods for signing and verifying <see cref="VerifiableCredential"/> instances
/// using Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// These extensions implement the Data Integrity proof algorithms as specified in
/// <see href="https://www.w3.org/TR/vc-data-integrity/">VC Data Integrity</see>.
/// </para>
/// <para>
/// Data Integrity is one of two securing mechanisms defined by the VC Data Model 2.0.
/// It uses embedded proofs where the <see cref="VerifiableCredential.Proof"/> property
/// contains the cryptographic proof. The alternative is envelope-based securing using
/// JOSE or COSE as defined in <see href="https://www.w3.org/TR/vc-jose-cose/">VC-JOSE-COSE</see>.
/// </para>
/// <para>
/// <strong>Time Handling</strong>
/// </para>
/// <para>
/// All timestamps are provided explicitly by the caller:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Signing:</strong> The <c>proofCreated</c> timestamp is provided explicitly.
/// The library does not use <see cref="DateTime.UtcNow"/> or <see cref="TimeProvider"/>.
/// </description></item>
/// <item><description>
/// <strong>Verification:</strong> The library only verifies cryptographic correctness.
/// Temporal policy decisions are the caller's responsibility - they can read
/// <c>ValidFrom</c>, <c>ValidUntil</c>, and proof timestamps directly from the credential.
/// </description></item>
/// </list>
/// <para>
/// These extensions are serialization-agnostic. Callers provide serialization delegates,
/// enabling use with JSON (System.Text.Json, Newtonsoft), CBOR, or other formats.
/// </para>
/// <para>
/// Cryptographic operations use the library's registry infrastructure:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="DefaultHashFunctionSelector"/> for hash algorithm resolution.</description></item>
/// <item><description><see cref="PrivateKeyMemory.SignAsync"/> for signing (uses <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> internally).</description></item>
/// <item><description><see cref="VerificationMethod.VerifySignatureAsync"/> for verification.</description></item>
/// </list>
/// </remarks>
public static class CredentialDataIntegrityExtensions
#pragma warning restore RS0030 // Do not use banned APIs
{
    /// <summary>
    /// The type string for Data Integrity proofs.
    /// </summary>
    private const string DataIntegrityProofType = "DataIntegrityProof";


    extension(VerifiableCredential credential)
    {
        /// <summary>
        /// Signs the credential using a Data Integrity proof.
        /// </summary>
        /// <param name="privateKey">The private key material for signing.</param>
        /// <param name="verificationMethodId">
        /// The DID URL identifying the verification method (e.g., <c>"did:web:example.com#key-1"</c>).
        /// </param>
        /// <param name="cryptosuite">
        /// The cryptosuite to use for signing (e.g., <c>EddsaJcs2022CryptosuiteInfo.Instance</c>).
        /// </param>
        /// <param name="proofCreated">
        /// The timestamp for the proof's <c>created</c> field. Must be provided explicitly by the caller.
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
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new credential instance with the proof attached.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when required parameters are null.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This method implements the proof creation algorithm:
        /// </para>
        /// <list type="number">
        /// <item><description>Serialize the credential.</description></item>
        /// <item><description>Build proof options with type, cryptosuite, created, verificationMethod, proofPurpose.</description></item>
        /// <item><description>Canonicalize both credential and proof options using the provided canonicalizer.</description></item>
        /// <item><description>Hash both canonical forms using the cryptosuite's hash algorithm.</description></item>
        /// <item><description>Concatenate: proofOptionsHash || credentialHash.</description></item>
        /// <item><description>Sign the combined hash using the private key.</description></item>
        /// <item><description>Encode the signature using the provided encoder.</description></item>
        /// <item><description>Attach the proof to a copy of the credential.</description></item>
        /// </list>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-integrity/#add-proof">
        /// VC Data Integrity §4.2 Add Proof</see>.
        /// </para>
        /// </remarks>
        public async ValueTask<VerifiableCredential> SignAsync(
            PrivateKeyMemory privateKey,
            string verificationMethodId,
            CryptosuiteInfo cryptosuite,
            DateTime proofCreated,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueEncoderDelegate encodeProofValue,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
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

            var proofCreatedString = DateTimeStampFormat.Format(proofCreated);

            //Serialize credential.
            var credentialSerialized = serialize(credential);

            //Build proof options.
            var requiresContext = cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
            var proofOptionsSerialized = serializeProofOptions(
                DataIntegrityProofType,
                cryptosuite.CryptosuiteName,
                proofCreatedString,
                verificationMethodId,
                AssertionMethod.Purpose,
                requiresContext ? credential.Context : null);

            //Canonicalize credential and proof options.
            var canonicalCredential = await canonicalize(credentialSerialized, contextResolver, cancellationToken);
            var canonicalProofOptions = await canonicalize(proofOptionsSerialized, contextResolver, cancellationToken);

            //Hash using the cryptosuite's hash algorithm.
            var hashAlgorithm = NormalizeHashAlgorithmName(cryptosuite.HashAlgorithm);
            var hashFunction = DefaultHashFunctionSelector.Select(hashAlgorithm);

            var credentialBytes = Encoding.UTF8.GetBytes(canonicalCredential);
            var proofOptionsBytes = Encoding.UTF8.GetBytes(canonicalProofOptions);

            var credentialHash = hashFunction(credentialBytes);
            var proofOptionsHash = hashFunction(proofOptionsBytes);

            //Combine hashes using memory pool: proofOptionsHash || credentialHash.
            var combinedLength = proofOptionsHash.Length + credentialHash.Length;
            using var hashDataOwner = memoryPool.Rent(combinedLength);
            var hashData = hashDataOwner.Memory.Span;
            proofOptionsHash.CopyTo(hashData);
            credentialHash.CopyTo(hashData.Slice(proofOptionsHash.Length));

            //Sign using the private key (uses CryptoFunctionRegistry internally via Tag).
            using var signature = await privateKey.SignAsync(hashDataOwner.Memory, memoryPool);

            //Encode proof value.
            var proofValue = encodeProofValue(signature.AsReadOnlySpan());

            //Create signed credential copy with proof.
            var signedCredential = deserialize(credentialSerialized);
            signedCredential.Proof =
            [
                new DataIntegrityProof
                {
                    Type = DataIntegrityProofType,
                    Cryptosuite = cryptosuite,
                    Created = proofCreatedString,
                    VerificationMethod = new AssertionMethod(verificationMethodId),
                    ProofPurpose = AssertionMethod.Purpose,
                    ProofValue = proofValue
                }
            ];

            return signedCredential;
        }


        /// <summary>
        /// Verifies the credential's Data Integrity proof.
        /// </summary>
        /// <param name="issuerDidDocument">
        /// The issuer's DID document containing the verification method referenced by the proof.
        /// </param>
        /// <param name="canonicalize">
        /// The canonicalization function for the cryptosuite's algorithm.
        /// </param>
        /// <param name="contextResolver">
        /// Optional delegate for resolving JSON-LD contexts. Required for RDFC-based cryptosuites,
        /// can be null for JCS-based cryptosuites.
        /// </param>
        /// <param name="decodeProofValue">
        /// Delegate for decoding the proof value string to signature bytes.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result indicating cryptographic validity.</returns>
        /// <remarks>
        /// <para>
        /// This method implements the proof verification algorithm:
        /// </para>
        /// <list type="number">
        /// <item><description>Extract the proof and resolve the verification method from the issuer's DID document.</description></item>
        /// <item><description>Serialize the credential without the proof.</description></item>
        /// <item><description>Rebuild proof options matching those used during signing.</description></item>
        /// <item><description>Canonicalize both and compute the hash using the cryptosuite's algorithm.</description></item>
        /// <item><description>Decode the proof value and verify the signature.</description></item>
        /// </list>
        /// <para>
        /// This method only verifies cryptographic correctness. Temporal policy decisions
        /// (e.g., "is this credential expired") are the caller's responsibility. The caller
        /// can read <c>ValidFrom</c>, <c>ValidUntil</c>, and <c>Proof.Created</c> directly
        /// from the credential and compare against their own time source.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">
        /// VC Data Integrity §4.3 Verify Proof</see>.
        /// </para>
        /// </remarks>
        public async ValueTask<CredentialVerificationResult> VerifyAsync(
            DidDocument issuerDidDocument,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueDecoderDelegate decodeProofValue,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerDidDocument, nameof(issuerDidDocument));
            ArgumentNullException.ThrowIfNull(canonicalize, nameof(canonicalize));
            ArgumentNullException.ThrowIfNull(decodeProofValue, nameof(decodeProofValue));
            ArgumentNullException.ThrowIfNull(serialize, nameof(serialize));
            ArgumentNullException.ThrowIfNull(deserialize, nameof(deserialize));
            ArgumentNullException.ThrowIfNull(serializeProofOptions, nameof(serializeProofOptions));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            //Extract proof.
            var proof = credential.Proof?.FirstOrDefault();
            if(proof == null)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.NoProof);
            }

            if(proof.Cryptosuite == null)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.MissingCryptosuite);
            }

            var verificationMethodId = proof.VerificationMethod?.Id;
            if(string.IsNullOrEmpty(verificationMethodId))
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod);
            }

            //Resolve verification method from issuer's DID document.
            var verificationMethod = issuerDidDocument.ResolveVerificationMethodReference(verificationMethodId);
            if(verificationMethod == null)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.VerificationMethodNotFound);
            }

            //Create credential copy without proof for hashing.
            var credentialSerialized = serialize(credential);
            var credentialWithoutProof = deserialize(credentialSerialized);
            credentialWithoutProof.Proof = null;

            var credentialWithoutProofSerialized = serialize(credentialWithoutProof);

            //Rebuild proof options matching those used during signing.
            var requiresContext = proof.Cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
            var proofOptionsSerialized = serializeProofOptions(
                proof.Type!,
                proof.Cryptosuite.CryptosuiteName,
                proof.Created ?? string.Empty,
                verificationMethodId,
                proof.ProofPurpose ?? string.Empty,
                requiresContext ? credential.Context : null);

            //Canonicalize and hash using the cryptosuite's algorithm.
            var canonicalCredential = await canonicalize(credentialWithoutProofSerialized, contextResolver, cancellationToken);
            var canonicalProofOptions = await canonicalize(proofOptionsSerialized, contextResolver, cancellationToken);

            var hashAlgorithm = NormalizeHashAlgorithmName(proof.Cryptosuite.HashAlgorithm);
            var hashFunction = DefaultHashFunctionSelector.Select(hashAlgorithm);

            var credentialBytes = Encoding.UTF8.GetBytes(canonicalCredential);
            var proofOptionsBytes = Encoding.UTF8.GetBytes(canonicalProofOptions);

            var credentialHash = hashFunction(credentialBytes);
            var proofOptionsHash = hashFunction(proofOptionsBytes);

            //Combine hashes using memory pool: proofOptionsHash || credentialHash.
            var combinedLength = proofOptionsHash.Length + credentialHash.Length;
            using var hashDataOwner = memoryPool.Rent(combinedLength);
            var hashData = hashDataOwner.Memory.Span;
            proofOptionsHash.CopyTo(hashData);
            credentialHash.CopyTo(hashData[proofOptionsHash.Length..]);

            //Decode proof value.
            using var signatureBytes = decodeProofValue(proof.ProofValue!, memoryPool);

            //Build signature with algorithm from cryptosuite.
            var signatureTag = new Tag(new Dictionary<Type, object>
            {
                [typeof(CryptoAlgorithm)] = proof.Cryptosuite.SignatureAlgorithm,
                [typeof(Purpose)] = Purpose.Verification
            });
            var signature = new Signature(signatureBytes, signatureTag);

            //Verify using the verification method (uses CryptoFunctionRegistry internally).
            var isValid = await verificationMethod.VerifySignatureAsync(hashDataOwner.Memory, signature, memoryPool);

            if(!isValid)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid);
            }

            return CredentialVerificationResult.Success();
        }
    }


    /// <summary>
    /// Normalizes hash algorithm name from specification format to .NET format.
    /// </summary>
    /// <param name="specName">The hash algorithm name from the specification (e.g., "SHA-256").</param>
    /// <returns>The normalized <see cref="HashAlgorithmName"/>.</returns>
    /// <remarks>
    /// Specifications use hyphenated names like "SHA-256", "SHA-384", while .NET uses
    /// non-hyphenated names like "SHA256", "SHA384". This method bridges that gap.
    /// TODO: Refactor to use a proper matcher/registry pattern.
    /// </remarks>
    private static HashAlgorithmName NormalizeHashAlgorithmName(string specName)
    {
        var normalized = specName.Replace("-", string.Empty, StringComparison.Ordinal);
        return new HashAlgorithmName(normalized);
    }
}