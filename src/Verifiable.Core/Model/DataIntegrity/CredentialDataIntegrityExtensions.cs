using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity;

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
/// Delegate for serializing a <see cref="ProofOptionsDocument"/> to a string representation
/// suitable for canonicalization.
/// </summary>
/// <remarks>
/// <para>
/// The proof options document is a spec-mandated intermediate artifact that gets
/// canonicalized and hashed during both signing and verification. Implementations
/// serialize the document according to their format (JSON, CBOR, etc.).
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#add-proof">
/// W3C Data Integrity §4.2 Add Proof</see>.
/// </para>
/// </remarks>
/// <param name="proofOptions">The proof options document to serialize.</param>
/// <returns>The serialized proof options string.</returns>
public delegate string ProofOptionsSerializeDelegate(ProofOptionsDocument proofOptions);


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
/// It uses embedded proofs where the <see cref="DataIntegritySecuredCredential.Proof"/> property
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
/// Temporal policy decisions are the caller's responsibility.
/// </description></item>
/// </list>
/// <para>
/// <strong>Delegate-Based Architecture</strong>
/// </para>
/// <para>
/// All serialization, canonicalization, and encoding operations are provided via delegates.
/// This allows the library core to remain independent of specific serialization libraries
/// (e.g., System.Text.Json, Newtonsoft.Json) while allowing users to provide their own implementations.
/// </para>
/// </remarks>
#pragma warning restore RS0030 // Do not use banned APIs
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The two extension blocks differ by receiver type (VerifiableCredential vs DataIntegritySecuredCredential); the analyzer is not up to date with the C# extension-block syntax.")]
public static class CredentialDataIntegrityExtensions
{
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
        /// Use <see cref="ProofValueCodecs.EncodeBase58Btc"/> for standard Data Integrity proofs.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">The encoding delegate (e.g., Base58 encoder) passed to the proof value encoder.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new credential instance with the proof attached.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when any required parameter is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="verificationMethodId"/> is null or whitespace.
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
        public async ValueTask<DataIntegritySecuredCredential> SignAsync(
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
            EncodeDelegate encoder,
            ComputeDigestDelegate computeDigest,
            BaseMemoryPool memoryPool,
            ExchangeContext context,
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
            ArgumentNullException.ThrowIfNull(encoder, nameof(encoder));
            ArgumentNullException.ThrowIfNull(computeDigest, nameof(computeDigest));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            var proofCreatedString = DateTimeStampFormat.Format(proofCreated);

            //Serialize credential.
            var credentialSerialized = serialize(credential);

            //Build the COMPLETE proof skeleton before signing — everything except
            //proofValue, including the proof id and the chain link. The proof options
            //derive from the skeleton, so every member the wire proof will carry is
            //covered by the signature, matching the §4.2 verify-side reconstruction
            //(proof with proofValue removed). An id or previousProof attached after
            //signing would be unsigned — a chain that does not cryptographically chain.
            var existingProofs = (credential as DataIntegritySecuredCredential)?.Proof;
            var newProof = new DataIntegrityProof
            {
                Id = GenerateProofId(),
                Type = CredentialConstants.DataIntegrityProofType,
                Cryptosuite = cryptosuite,
                Created = proofCreatedString,
                VerificationMethod = new AssertionMethod(verificationMethodId),
                ProofPurpose = AssertionMethod.Purpose,
                PreviousProof = existingProofs is { Count: > 0 } ? existingProofs[^1].Id : null
            };

            var requiresContext = cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
            var proofOptions = ProofOptionsDocument.FromProof(
                newProof, requiresContext ? credential.Context : null);
            var proofOptionsSerialized = serializeProofOptions(proofOptions);

            //Canonicalize credential and proof options.
            var credentialCanonicalization = await canonicalize(credentialSerialized, contextResolver, context, cancellationToken)
                .ConfigureAwait(false);
            var proofOptionsCanonicalization = await canonicalize(proofOptionsSerialized, contextResolver, context, cancellationToken)
                .ConfigureAwait(false);

            //Hash using the cryptosuite's hash algorithm.
            var hashAlgorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(cryptosuite.HashAlgorithm);
            int digestByteLength = WellKnownHashAlgorithms.GetSizeBytes(hashAlgorithm);
            var digestTag = Tag.Create(hashAlgorithm).With(Purpose.Digest);

            var credentialByteCount = Encoding.UTF8.GetByteCount(credentialCanonicalization.CanonicalForm);
            var proofOptionsByteCount = Encoding.UTF8.GetByteCount(proofOptionsCanonicalization.CanonicalForm);

            using var credentialBytesOwner = memoryPool.Rent(credentialByteCount);
            using var proofOptionsBytesOwner = memoryPool.Rent(proofOptionsByteCount);

            var credentialBytesWritten = Encoding.UTF8.GetBytes(credentialCanonicalization.CanonicalForm, credentialBytesOwner.Memory.Span);
            var proofOptionsBytesWritten = Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm, proofOptionsBytesOwner.Memory.Span);

            System.Diagnostics.Debug.Assert(credentialBytesWritten == credentialByteCount, "Encoded byte count must match the pre-computed count.");
            System.Diagnostics.Debug.Assert(proofOptionsBytesWritten == proofOptionsByteCount, "Encoded byte count must match the pre-computed count.");

            (DigestValue credentialDigestValue, _) = await computeDigest(
                new ReadOnlySequence<byte>(credentialBytesOwner.Memory[..credentialBytesWritten]),
                digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
            using DigestValue credentialDigest = credentialDigestValue;

            (DigestValue proofOptionsDigestValue, _) = await computeDigest(
                new ReadOnlySequence<byte>(proofOptionsBytesOwner.Memory[..proofOptionsBytesWritten]),
                digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
            using DigestValue proofOptionsDigest = proofOptionsDigestValue;

            //Combine hashes using memory pool: proofOptionsHash || credentialHash.
            var combinedLength = proofOptionsDigest.Length + credentialDigest.Length;
            using var hashDataOwner = memoryPool.Rent(combinedLength);
            var hashData = hashDataOwner.Memory.Span;
            proofOptionsDigest.AsReadOnlySpan().CopyTo(hashData);
            credentialDigest.AsReadOnlySpan().CopyTo(hashData.Slice(proofOptionsDigest.Length));

            //Sign using the private key (uses CryptoFunctionRegistry internally via Tag).
            using var signature = await privateKey.SignAsync(hashDataOwner.Memory, memoryPool)
                .ConfigureAwait(false);

            //Encode proof value and attach it to the pre-signed skeleton — the only
            //member the signature cannot cover is its own value. When the credential
            //being signed is already a DataIntegritySecuredCredential carrying proofs,
            //the new proof is appended (chained onto the last existing proof via the
            //signed PreviousProof) rather than replacing the chain.
            newProof.ProofValue = encodeProofValue(signature.AsReadOnlySpan(), encoder, memoryPool);

            var proofChain = new List<DataIntegrityProof>();
            if(existingProofs is { Count: > 0 })
            {
                proofChain.AddRange(existingProofs);
            }

            proofChain.Add(newProof);

            var signedCredential = CloneWithProofs(deserialize(credentialSerialized), proofChain);

            return signedCredential;
        }
    }


    extension(DataIntegritySecuredCredential credential)
    {
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
        /// Use <see cref="ProofValueCodecs.DecodeBase58Btc"/> for standard Data Integrity proofs.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="decoder">The decoding delegate (e.g., Base58 decoder) passed to the proof value decoder.</param>
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
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyAsync(
            DidDocument issuerDidDocument,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueDecoderDelegate decodeProofValue,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            DecodeDelegate decoder,
            ComputeDigestDelegate computeDigest,
            BaseMemoryPool memoryPool,
            ExchangeContext context,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerDidDocument, nameof(issuerDidDocument));
            ArgumentNullException.ThrowIfNull(canonicalize, nameof(canonicalize));
            ArgumentNullException.ThrowIfNull(decodeProofValue, nameof(decodeProofValue));
            ArgumentNullException.ThrowIfNull(serialize, nameof(serialize));
            ArgumentNullException.ThrowIfNull(serializeProofOptions, nameof(serializeProofOptions));
            ArgumentNullException.ThrowIfNull(decoder, nameof(decoder));
            ArgumentNullException.ThrowIfNull(computeDigest, nameof(computeDigest));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            //Verify the embedded proof chain. A single proof is the fast path; multiple proofs
            //form a chain that is walked in dependency order, each proof verified against the
            //document view carrying exactly the proofs that preceded it (Data Integrity §2.1.2).
            var proofs = credential.Proof;
            if(proofs is null || proofs.Count == 0)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.NoProof);
            }

            //The chain walk computes a plain validity outcome; the public result then mints a
            //Verified<DataIntegritySecuredCredential> from the receiver on success, bound to the
            //chain root's identity (issuer == resolved-controller, controller-RESOLUTION
            //semantics).
            CredentialVerificationResult outcome;
            BoundProvenance? rootProvenance;
            if(proofs.Count == 1)
            {
                ChainLinkVerificationOutcome linkOutcome = await VerifyChainLinkAsync(
                    credential,
                    proofs[0],
                    precedingProofs: null,
                    issuerDidDocument,
                    canonicalize,
                    contextResolver,
                    decodeProofValue,
                    serialize,
                    serializeProofOptions,
                    decoder,
                    computeDigest,
                    memoryPool,
                    context,
                    cancellationToken).ConfigureAwait(false);

                outcome = linkOutcome.Result;
                rootProvenance = linkOutcome.Provenance;
            }
            else
            {
                var orderedChain = OrderProofChain(proofs, out var chainFailureReason);
                if(orderedChain is null)
                {
                    return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(chainFailureReason);
                }

                outcome = CredentialVerificationResult.Success();
                rootProvenance = null;
                for(int i = 0; i < orderedChain.Count; ++i)
                {
                    var precedingProofs = i == 0 ? null : orderedChain.GetRange(0, i);
                    ChainLinkVerificationOutcome linkOutcome = await VerifyChainLinkAsync(
                        credential,
                        orderedChain[i],
                        precedingProofs,
                        issuerDidDocument,
                        canonicalize,
                        contextResolver,
                        decodeProofValue,
                        serialize,
                        serializeProofOptions,
                        decoder,
                        computeDigest,
                        memoryPool,
                        context,
                        cancellationToken).ConfigureAwait(false);

                    if(!linkOutcome.Result.IsValid)
                    {
                        outcome = linkOutcome.Result;
                        rootProvenance = null;
                        break;
                    }

                    if(i == 0)
                    {
                        rootProvenance = linkOutcome.Provenance;
                    }
                }
            }

            if(!outcome.IsValid)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(outcome.FailureReason);
            }

            //rootProvenance witnesses this exact credential instance; TryCreateBound refuses
            //otherwise, which cannot happen here since the gate above bound the same reference.
            if(rootProvenance is null
                || Verified<DataIntegritySecuredCredential>.TryCreateBound(credential, rootProvenance) is not { } verified)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ControllerMismatch);
            }

            return CredentialVerificationResult<DataIntegritySecuredCredential>.Success(verified);
        }
    }


    //Carries a chain link's plain validity outcome alongside the BoundProvenance the link's own
    //identity check produced on success (null on any failure, including a bind refusal).
    private readonly record struct ChainLinkVerificationOutcome(CredentialVerificationResult Result, BoundProvenance? Provenance);


    //Generates a fresh URN:UUID proof identifier so proofs can be linked into a chain
    //via DataIntegrityProof.PreviousProof.
    private static string GenerateProofId() => $"urn:uuid:{Guid.NewGuid()}";


    //Verifies one Data Integrity proof against the document view that carries exactly the
    //proofs preceding it in the chain (none for a single or root proof). This reconstructs the
    //hashing input the signer used when that proof was created.
    private static async ValueTask<ChainLinkVerificationOutcome> VerifyChainLinkAsync(
        VerifiableCredential credential,
        DataIntegrityProof proof,
        List<DataIntegrityProof>? precedingProofs,
        DidDocument issuerDidDocument,
        CanonicalizationDelegate canonicalize,
        ContextResolverDelegate? contextResolver,
        ProofValueDecoderDelegate decodeProofValue,
        CredentialSerializeDelegate serialize,
        ProofOptionsSerializeDelegate serializeProofOptions,
        DecodeDelegate decoder,
        ComputeDigestDelegate computeDigest,
        BaseMemoryPool memoryPool,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(proof.Cryptosuite is null)
        {
            return new(CredentialVerificationResult.Failed(VerificationFailureReason.MissingCryptosuite), null);
        }

        //Data Integrity 1.0 §4.2: when an expected proof purpose is given and does not match
        //proof.proofPurpose, an error MUST be raised. A credential proof's purpose is
        //assertionMethod (VC-DM 2.0); checked BEFORE resolving anything, mirroring the
        //presentation path's ProofPurposeMismatch gate.
        if(!string.Equals(proof.ProofPurpose, AssertionMethod.Purpose, StringComparison.Ordinal))
        {
            return new(CredentialVerificationResult.Failed(VerificationFailureReason.ProofPurposeMismatch), null);
        }

        var verificationMethodId = proof.VerificationMethod?.Id;
        if(string.IsNullOrEmpty(verificationMethodId))
        {
            return new(CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod), null);
        }

        //Resolve through assertionMethod to enforce the correct verification relationship -- a key
        //that exists in the flat verificationMethod array but is not referenced from assertionMethod
        //must not authenticate an issuer claim.
        var verificationMethod = issuerDidDocument.GetLocalAssertionMethodById(verificationMethodId);
        if(verificationMethod is null)
        {
            return new(CredentialVerificationResult.Failed(VerificationFailureReason.VerificationMethodNotFound), null);
        }

        //Build the document view hashed when this proof was created: the credential carrying the
        //preceding proofs (or none), with the proof under verification itself removed.
        var documentView = CloneWithProofs(credential, precedingProofs);
        var credentialWithoutProofSerialized = serialize(documentView);

        //Rebuild proof options document matching those used during signing.
        var requiresContext = proof.Cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
        var proofOptions = ProofOptionsDocument.FromProof(proof, requiresContext ? credential.Context : null);
        var proofOptionsSerialized = serializeProofOptions(proofOptions);

        //Canonicalize and hash using the cryptosuite's algorithm.
        var credentialCanonicalization = await canonicalize(credentialWithoutProofSerialized, contextResolver, context, cancellationToken)
            .ConfigureAwait(false);
        var proofOptionsCanonicalization = await canonicalize(proofOptionsSerialized, contextResolver, context, cancellationToken)
            .ConfigureAwait(false);

        var hashAlgorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(proof.Cryptosuite.HashAlgorithm);
        int digestByteLength = WellKnownHashAlgorithms.GetSizeBytes(hashAlgorithm);
        var digestTag = Tag.Create(hashAlgorithm).With(Purpose.Digest);

        var credentialByteCount = Encoding.UTF8.GetByteCount(credentialCanonicalization.CanonicalForm);
        var proofOptionsByteCount = Encoding.UTF8.GetByteCount(proofOptionsCanonicalization.CanonicalForm);

        using var credentialBytesOwner = memoryPool.Rent(credentialByteCount);
        using var proofOptionsBytesOwner = memoryPool.Rent(proofOptionsByteCount);

        var credentialBytesWritten = Encoding.UTF8.GetBytes(credentialCanonicalization.CanonicalForm, credentialBytesOwner.Memory.Span);
        var proofOptionsBytesWritten = Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm, proofOptionsBytesOwner.Memory.Span);

        System.Diagnostics.Debug.Assert(credentialBytesWritten == credentialByteCount, "Encoded byte count must match the pre-computed count.");
        System.Diagnostics.Debug.Assert(proofOptionsBytesWritten == proofOptionsByteCount, "Encoded byte count must match the pre-computed count.");

        (DigestValue credentialDigestValue, _) = await computeDigest(
            new ReadOnlySequence<byte>(credentialBytesOwner.Memory[..credentialBytesWritten]),
            digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
        using DigestValue credentialDigest = credentialDigestValue;

        (DigestValue proofOptionsDigestValue, _) = await computeDigest(
            new ReadOnlySequence<byte>(proofOptionsBytesOwner.Memory[..proofOptionsBytesWritten]),
            digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
        using DigestValue proofOptionsDigest = proofOptionsDigestValue;

        //Combine hashes using memory pool: proofOptionsHash || credentialHash.
        var combinedLength = proofOptionsDigest.Length + credentialDigest.Length;
        using var hashDataOwner = memoryPool.Rent(combinedLength);
        var hashData = hashDataOwner.Memory.Span;
        proofOptionsDigest.AsReadOnlySpan().CopyTo(hashData);
        credentialDigest.AsReadOnlySpan().CopyTo(hashData[proofOptionsDigest.Length..]);

        //Decode proof value using the provided decoder delegate.
        using var signatureBytes = decodeProofValue(proof.ProofValue!, decoder, memoryPool);

        //Build signature with algorithm from cryptosuite and verify using the verification
        //method (uses CryptoFunctionRegistry internally).
        var signatureTag = Tag.Create(proof.Cryptosuite.SignatureAlgorithm).With(Purpose.Verification);
        using var signature = new Signature(signatureBytes, signatureTag);
        var isValid = await verificationMethod.VerifySignatureAsync(hashDataOwner.Memory, signature, memoryPool).ConfigureAwait(false);
        if(!isValid)
        {
            return new(CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
        }

        //Controller-RESOLUTION semantics: bind issuer == the resolved method's own
        //controller. A resolved method whose controller disagrees with the credential's issuer claim
        //does not authenticate that issuer, even though the signature and relationship scoping both
        //hold -- this is the deliberate did:web-aliasing / controller-indirection rejection.
        var claimedController = credential.Issuer?.Id;
        if(string.IsNullOrEmpty(claimedController)
            || string.IsNullOrEmpty(verificationMethod.Controller)
            || string.IsNullOrEmpty(verificationMethod.Id))
        {
            return new(CredentialVerificationResult.Failed(VerificationFailureReason.ControllerMismatch), null);
        }

        //Passing the proof's own purpose (not the expected literal) makes the gate independently
        //re-check purpose-to-relationship correspondence; the proofPurpose guard above already
        //returned on a null or mismatched value, so it is non-null and equal to AssertionMethod here.
        BoundProvenance? provenance = BoundProvenance.TryBindByControllerArtifact(
            claimedController,
            verificationMethod.Id,
            verificationMethod.Controller,
            proof.ProofPurpose!,
            VerificationRelationship.AssertionMethod,
            credential);

        return provenance is null
            ? new(CredentialVerificationResult.Failed(VerificationFailureReason.ControllerMismatch), null)
            : new(CredentialVerificationResult.Success(), provenance);
    }


    //Establishes the dependency order of a proof chain by following previousProof -> id links
    //from the single root (the proof with no previousProof). Returns null and sets the failure
    //reason on a cycle, a dangling/broken link, or a malformed (branching/disconnected) chain.
    private static List<DataIntegrityProof>? OrderProofChain(List<DataIntegrityProof> proofs, out VerificationFailureReason failureReason)
    {
        failureReason = VerificationFailureReason.None;

        var byId = new Dictionary<string, DataIntegrityProof>(StringComparer.Ordinal);
        foreach(var proof in proofs)
        {
            if(!string.IsNullOrEmpty(proof.Id))
            {
                byId[proof.Id] = proof;
            }
        }

        //Map each previousProof reference to its successor and locate the single root. A second
        //root, a reference to a non-existent id, or a duplicated reference is a broken chain.
        var successorByPreviousId = new Dictionary<string, DataIntegrityProof>(StringComparer.Ordinal);
        DataIntegrityProof? root = null;
        foreach(var proof in proofs)
        {
            if(string.IsNullOrEmpty(proof.PreviousProof))
            {
                if(root is not null)
                {
                    failureReason = VerificationFailureReason.BrokenProofChain;
                    return null;
                }

                root = proof;
                continue;
            }

            if(!byId.ContainsKey(proof.PreviousProof) || successorByPreviousId.ContainsKey(proof.PreviousProof))
            {
                failureReason = VerificationFailureReason.BrokenProofChain;
                return null;
            }

            successorByPreviousId[proof.PreviousProof] = proof;
        }

        //No root means every proof references another: the references form a cycle.
        if(root is null)
        {
            failureReason = VerificationFailureReason.ProofChainCycle;
            return null;
        }

        var ordered = new List<DataIntegrityProof>(proofs.Count);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        DataIntegrityProof? current = root;
        while(current is not null)
        {
            ordered.Add(current);

            //A proof with no id cannot be referenced, so it must terminate the chain.
            if(string.IsNullOrEmpty(current.Id))
            {
                break;
            }

            if(!visited.Add(current.Id))
            {
                failureReason = VerificationFailureReason.ProofChainCycle;
                return null;
            }

            successorByPreviousId.TryGetValue(current.Id, out current);
        }

        //Fewer proofs than input means the chain is disconnected (a dangling segment).
        if(ordered.Count != proofs.Count)
        {
            failureReason = VerificationFailureReason.BrokenProofChain;
            return null;
        }

        return ordered;
    }


    //Copies the base VerifiableCredential members into a DataIntegritySecuredCredential and
    //attaches the supplied proof set (null for a document view that carries no proof). Used both
    //to produce the embedded-secured signing output and to reconstruct per-link hashing input.
    private static DataIntegritySecuredCredential CloneWithProofs(VerifiableCredential source, List<DataIntegrityProof>? proofs)
    {
        return new DataIntegritySecuredCredential
        {
            Context = source.Context,
            Id = source.Id,
            Type = source.Type,
            Name = source.Name,
            Description = source.Description,
            Issuer = source.Issuer,
            CredentialSubject = source.CredentialSubject,
            ValidFrom = source.ValidFrom,
            ValidUntil = source.ValidUntil,
            CredentialStatus = source.CredentialStatus,
            CredentialSchema = source.CredentialSchema,
            RelatedResource = source.RelatedResource,
            RefreshService = source.RefreshService,
            TermsOfUse = source.TermsOfUse,
            Evidence = source.Evidence,
            AdditionalData = source.AdditionalData,
            Proof = proofs
        };
    }
}
