using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for serializing a <see cref="VerifiablePresentation"/> to a string representation.
/// </summary>
/// <param name="presentation">The presentation to serialize.</param>
/// <returns>The serialized string representation.</returns>
public delegate string PresentationSerializeDelegate(VerifiablePresentation presentation);


/// <summary>
/// Delegate for deserializing a string representation to a <see cref="VerifiablePresentation"/>.
/// </summary>
/// <param name="serialized">The serialized string representation.</param>
/// <returns>The deserialized presentation.</returns>
public delegate VerifiablePresentation PresentationDeserializeDelegate(string serialized);


/// <summary>
/// Extension methods for signing and verifying <see cref="VerifiablePresentation"/> instances
/// using Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// Presentation proofs use the <c>authentication</c> verification relationship, binding the
/// proof to the holder's DID document. Unlike credential proofs that use <c>assertionMethod</c>,
/// presentation proofs require a <c>challenge</c> and a <c>domain</c> to prevent replay attacks
/// and bind the proof to a specific verifier interaction.
/// </para>
/// <para>
/// The proof creation and verification algorithms are specified in
/// <see href="https://www.w3.org/TR/vc-data-integrity/#add-proof">VC Data Integrity §4.2 Add Proof</see>
/// and <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">§4.3 Verify Proof</see>.
/// The <c>proofPurpose</c> is always <c>authentication</c> for presentations, as specified in
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations">VC Data Model 2.0 §4.13</see>.
/// </para>
/// <para>
/// <strong>Verification method resolution:</strong> Verification resolves the key through
/// <c>authentication</c> in the holder's DID document via
/// <see cref="VerificationMethodResolutionExtensions"/>. A key that exists in
/// <c>verificationMethod</c> but is not referenced from <c>authentication</c> will cause
/// <see cref="VerificationFailureReason.VerificationMethodNotFound"/> to be returned.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
public static class PresentationDataIntegrityExtensions
{
    extension(VerifiablePresentation presentation)
    {
        /// <summary>
        /// Signs the presentation using a Data Integrity proof with <c>authentication</c> proof purpose.
        /// </summary>
        /// <param name="privateKey">The holder's private key material for signing.</param>
        /// <param name="verificationMethodId">
        /// The DID URL identifying the verification method (e.g., <c>"did:web:example.com#key-1"</c>).
        /// The referenced key must appear in the holder's <c>authentication</c> relationship.
        /// </param>
        /// <param name="cryptosuite">The cryptosuite to use for signing.</param>
        /// <param name="proofCreated">The timestamp for the proof's <c>created</c> field.</param>
        /// <param name="challenge">
        /// The challenge issued by the verifier. Included in the signed proof options to bind
        /// this proof to a specific verifier interaction and prevent replay attacks.
        /// </param>
        /// <param name="domain">
        /// The security domain of the verifier. Included in the signed proof options to prevent
        /// cross-domain replay attacks.
        /// </param>
        /// <param name="canonicalize">The canonicalization function for the cryptosuite's algorithm.</param>
        /// <param name="contextResolver">
        /// Optional delegate for resolving JSON-LD contexts. Required for RDFC-based cryptosuites,
        /// can be <see langword="null"/> for JCS-based cryptosuites.
        /// </param>
        /// <param name="encodeProofValue">Delegate for encoding the signature bytes to a proof value string.</param>
        /// <param name="serialize">Delegate for serializing presentations.</param>
        /// <param name="deserialize">Delegate for deserializing presentations.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">The encoding delegate (e.g., Base58 encoder) passed to the proof value encoder.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new presentation instance with the proof attached.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="verificationMethodId"/>, <paramref name="challenge"/>, or <paramref name="domain"/> is null or whitespace.</exception>
        public async ValueTask<VerifiablePresentation> SignAsync(
            PrivateKeyMemory privateKey,
            string verificationMethodId,
            CryptosuiteInfo cryptosuite,
            DateTime proofCreated,
            string challenge,
            string domain,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueEncoderDelegate encodeProofValue,
            PresentationSerializeDelegate serialize,
            PresentationDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(privateKey);
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
            ArgumentNullException.ThrowIfNull(cryptosuite);
            ArgumentException.ThrowIfNullOrWhiteSpace(challenge);
            ArgumentException.ThrowIfNullOrWhiteSpace(domain);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(encodeProofValue);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(deserialize);
            ArgumentNullException.ThrowIfNull(serializeProofOptions);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proofCreatedString = DateTimeStampFormat.Format(proofCreated);
            var presentationSerialized = serialize(presentation);

            var requiresContext = cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
            var proofOptions = ProofOptionsDocument.ForSigning(
                cryptosuite,
                proofCreatedString,
                verificationMethodId,
                AuthenticationMethod.Purpose,
                requiresContext ? presentation.Context : null,
                domain,
                challenge);

            var proofOptionsSerialized = serializeProofOptions(proofOptions);

            var presentationCanonicalization = await canonicalize(presentationSerialized, contextResolver, cancellationToken)
                .ConfigureAwait(false);
            var proofOptionsCanonicalization = await canonicalize(proofOptionsSerialized, contextResolver, cancellationToken)
                .ConfigureAwait(false);

            var hashAlgorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(cryptosuite.HashAlgorithm);
            var hashFunction = DefaultHashFunctionSelector.Select(hashAlgorithm);

            var presentationByteCount = Encoding.UTF8.GetByteCount(presentationCanonicalization.CanonicalForm);
            var proofOptionsByteCount = Encoding.UTF8.GetByteCount(proofOptionsCanonicalization.CanonicalForm);

            using var presentationBytesOwner = memoryPool.Rent(presentationByteCount);
            using var proofOptionsBytesOwner = memoryPool.Rent(proofOptionsByteCount);

            var presentationBytesWritten = Encoding.UTF8.GetBytes(presentationCanonicalization.CanonicalForm, presentationBytesOwner.Memory.Span);
            var proofOptionsBytesWritten = Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm, proofOptionsBytesOwner.Memory.Span);

            System.Diagnostics.Debug.Assert(presentationBytesWritten == presentationByteCount, "Encoded byte count must match the pre-computed count.");
            System.Diagnostics.Debug.Assert(proofOptionsBytesWritten == proofOptionsByteCount, "Encoded byte count must match the pre-computed count.");

            var presentationHash = hashFunction(presentationBytesOwner.Memory.Span[..presentationBytesWritten].ToArray());
            var proofOptionsHash = hashFunction(proofOptionsBytesOwner.Memory.Span[..proofOptionsBytesWritten].ToArray());

            //Combine hashes: proofOptionsHash || presentationHash.
            var combinedLength = proofOptionsHash.Length + presentationHash.Length;
            using var hashDataOwner = memoryPool.Rent(combinedLength);
            var hashData = hashDataOwner.Memory.Span;
            proofOptionsHash.CopyTo(hashData);
            presentationHash.CopyTo(hashData[proofOptionsHash.Length..]);

            using var signature = await privateKey.SignAsync(hashDataOwner.Memory, memoryPool)
                .ConfigureAwait(false);

            var proofValue = encodeProofValue(signature.AsReadOnlySpan(), encoder, memoryPool);

            var signedPresentation = deserialize(presentationSerialized);
            signedPresentation.Proof =
            [
                new DataIntegrityProof
                {
                    Type = DataIntegrityProof.DataIntegrityProofType,
                    Cryptosuite = cryptosuite,
                    Created = proofCreatedString,
                    VerificationMethod = new AuthenticationMethod(verificationMethodId),
                    ProofPurpose = AuthenticationMethod.Purpose,
                    Challenge = challenge,
                    Domain = domain,
                    ProofValue = proofValue
                }
            ];

            return signedPresentation;
        }


        /// <summary>
        /// Verifies the presentation's Data Integrity proof.
        /// </summary>
        /// <param name="holderDidDocument">
        /// The holder's DID document. The verification method referenced by the proof must
        /// appear in the document's <c>authentication</c> relationship.
        /// </param>
        /// <param name="expectedChallenge">
        /// The challenge the verifier issued. Verification fails if the proof's challenge does not
        /// match, preventing replay attacks.
        /// </param>
        /// <param name="expectedDomain">
        /// The verifier's domain. Verification fails if the proof's domain does not match,
        /// preventing cross-domain replay attacks.
        /// </param>
        /// <param name="canonicalize">The canonicalization function for the cryptosuite's algorithm.</param>
        /// <param name="contextResolver">
        /// Optional delegate for resolving JSON-LD contexts. Required for RDFC-based cryptosuites.
        /// </param>
        /// <param name="decodeProofValue">Delegate for decoding the proof value string to signature bytes.</param>
        /// <param name="serialize">Delegate for serializing presentations.</param>
        /// <param name="deserialize">Delegate for deserializing presentations.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="decoder">The decoding delegate (e.g., Base58 decoder).</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result indicating cryptographic validity.</returns>
        /// <remarks>
        /// <para>
        /// In addition to cryptographic verification, this method checks that the proof's
        /// <c>challenge</c> and <c>domain</c> match the expected values provided by the caller.
        /// This enforces the binding of the proof to the specific verifier interaction.
        /// </para>
        /// <para>
        /// Verification resolves the key via <c>authentication</c>, not from the top-level
        /// <c>verificationMethod</c> array directly. A key that exists in <c>verificationMethod</c>
        /// but is not referenced from <c>authentication</c> will cause
        /// <see cref="VerificationFailureReason.VerificationMethodNotFound"/> to be returned.
        /// </para>
        /// </remarks>
        public async ValueTask<CredentialVerificationResult> VerifyAsync(
            DidDocument holderDidDocument,
            string expectedChallenge,
            string expectedDomain,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueDecoderDelegate decodeProofValue,
            PresentationSerializeDelegate serialize,
            PresentationDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(holderDidDocument);
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedChallenge);
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedDomain);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(decodeProofValue);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(deserialize);
            ArgumentNullException.ThrowIfNull(serializeProofOptions);
            ArgumentNullException.ThrowIfNull(decoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = presentation.Proof?.FirstOrDefault();
            if(proof is null)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.NoProof);
            }

            if(proof.Cryptosuite is null)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.MissingCryptosuite);
            }

            var verificationMethodId = proof.VerificationMethod?.Id;
            if(string.IsNullOrEmpty(verificationMethodId))
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod);
            }

            //Validate challenge and domain before performing expensive cryptographic operations.
            if(!string.Equals(proof.Challenge, expectedChallenge, StringComparison.Ordinal))
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.ChallengeMismatch);
            }

            if(!string.Equals(proof.Domain, expectedDomain, StringComparison.Ordinal))
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.DomainMismatch);
            }

            //Resolve through authentication to enforce the correct verification relationship.
            //A key that exists in verificationMethod but is not referenced from authentication fails here.
            var verificationMethod = holderDidDocument.GetLocalAuthenticationMethodById(verificationMethodId);
            if(verificationMethod is null)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.VerificationMethodNotFound);
            }

            var presentationSerialized = serialize(presentation);
            var presentationWithoutProof = deserialize(presentationSerialized);
            presentationWithoutProof.Proof = null;
            var presentationWithoutProofSerialized = serialize(presentationWithoutProof);

            var requiresContext = proof.Cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
            var proofOptions = ProofOptionsDocument.FromProof(proof, requiresContext ? presentation.Context : null);
            var proofOptionsSerialized = serializeProofOptions(proofOptions);

            var presentationCanonicalization = await canonicalize(presentationWithoutProofSerialized, contextResolver, cancellationToken)
                .ConfigureAwait(false);
            var proofOptionsCanonicalization = await canonicalize(proofOptionsSerialized, contextResolver, cancellationToken)
                .ConfigureAwait(false);

            var hashAlgorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(proof.Cryptosuite.HashAlgorithm);
            var hashFunction = DefaultHashFunctionSelector.Select(hashAlgorithm);

            var presentationByteCount = Encoding.UTF8.GetByteCount(presentationCanonicalization.CanonicalForm);
            var proofOptionsByteCount = Encoding.UTF8.GetByteCount(proofOptionsCanonicalization.CanonicalForm);

            using var presentationBytesOwner = memoryPool.Rent(presentationByteCount);
            using var proofOptionsBytesOwner = memoryPool.Rent(proofOptionsByteCount);

            var presentationBytesWritten = Encoding.UTF8.GetBytes(presentationCanonicalization.CanonicalForm, presentationBytesOwner.Memory.Span);
            var proofOptionsBytesWritten = Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm, proofOptionsBytesOwner.Memory.Span);

            System.Diagnostics.Debug.Assert(presentationBytesWritten == presentationByteCount, "Encoded byte count must match the pre-computed count.");
            System.Diagnostics.Debug.Assert(proofOptionsBytesWritten == proofOptionsByteCount, "Encoded byte count must match the pre-computed count.");

            var presentationHash = hashFunction(presentationBytesOwner.Memory.Span[..presentationBytesWritten].ToArray());
            var proofOptionsHash = hashFunction(proofOptionsBytesOwner.Memory.Span[..proofOptionsBytesWritten].ToArray());

            var combinedLength = proofOptionsHash.Length + presentationHash.Length;
            using var hashDataOwner = memoryPool.Rent(combinedLength);
            var hashData = hashDataOwner.Memory.Span;
            proofOptionsHash.CopyTo(hashData);
            presentationHash.CopyTo(hashData[proofOptionsHash.Length..]);

            using var signatureBytes = decodeProofValue(proof.ProofValue!, decoder, memoryPool);

            var signatureTag = new Tag(new Dictionary<Type, object>
            {
                [typeof(CryptoAlgorithm)] = proof.Cryptosuite.SignatureAlgorithm,
                [typeof(Purpose)] = Purpose.Verification
            });
            using var signature = new Signature(signatureBytes, signatureTag);
            var isValid = await verificationMethod.VerifySignatureAsync(hashDataOwner.Memory, signature, memoryPool)
                .ConfigureAwait(false);

            if(!isValid)
            {
                return CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid);
            }

            return CredentialVerificationResult.Success();
        }
    }

}