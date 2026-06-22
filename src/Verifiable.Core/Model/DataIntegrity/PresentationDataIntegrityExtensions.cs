using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
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
/// an <em>interactive</em> presentation proof carries a <c>challenge</c> and a <c>domain</c> to
/// prevent replay attacks and bind the proof to a specific verifier interaction — verified with
/// <c>VerifyAsync</c>. A <em>static linked</em> presentation (one published once and resolved by
/// anyone, such as a did:webvh <c>whois.vp</c>) has no interactive verifier and therefore no such
/// binding — verified with <c>VerifyLinkedPresentationAsync</c>, which is fail-closed against
/// being handed a binding-bearing presentation.
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
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The two extension blocks differ by receiver type (VerifiablePresentation vs DataIntegritySecuredPresentation); the analyzer is not up to date with the C# extension-block syntax.")]
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
        /// <returns>The embedded-secured presentation carrying the proof.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="verificationMethodId"/>, <paramref name="challenge"/>, or <paramref name="domain"/> is null or whitespace.</exception>
        public async ValueTask<DataIntegritySecuredPresentation> SignAsync(
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
            ComputeDigestDelegate computeDigest,
            MemoryPool<byte> memoryPool,
            ExchangeContext context,
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
            ArgumentNullException.ThrowIfNull(computeDigest);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proofCreatedString = DateTimeStampFormat.Format(proofCreated);
            var presentationSerialized = serialize(presentation);

            //Build the complete proof skeleton before signing; the options derive from
            //it (§4.2), so challenge and domain are covered by the signature — that
            //coverage is the anti-replay binding, not the mere presence of the fields.
            var newProof = new DataIntegrityProof
            {
                Type = DataIntegrityProof.DataIntegrityProofType,
                Cryptosuite = cryptosuite,
                Created = proofCreatedString,
                VerificationMethod = new AuthenticationMethod(verificationMethodId),
                ProofPurpose = AuthenticationMethod.Purpose,
                Challenge = challenge,
                Domain = [domain]
            };

            var requiresContext = cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
            var proofOptions = ProofOptionsDocument.FromProof(
                newProof, requiresContext ? presentation.Context : null);

            var proofOptionsSerialized = serializeProofOptions(proofOptions);

            var presentationCanonicalization = await canonicalize(presentationSerialized, contextResolver, context, cancellationToken)
                .ConfigureAwait(false);
            var proofOptionsCanonicalization = await canonicalize(proofOptionsSerialized, contextResolver, context, cancellationToken)
                .ConfigureAwait(false);

            var hashAlgorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(cryptosuite.HashAlgorithm);
            int digestByteLength = WellKnownHashAlgorithms.GetSizeBytes(hashAlgorithm);
            var digestTag = new Tag(new Dictionary<Type, object>
            {
                [typeof(HashAlgorithmName)] = hashAlgorithm,
                [typeof(Purpose)] = Purpose.Digest
            });

            var presentationByteCount = Encoding.UTF8.GetByteCount(presentationCanonicalization.CanonicalForm);
            var proofOptionsByteCount = Encoding.UTF8.GetByteCount(proofOptionsCanonicalization.CanonicalForm);

            using var presentationBytesOwner = memoryPool.Rent(presentationByteCount);
            using var proofOptionsBytesOwner = memoryPool.Rent(proofOptionsByteCount);

            var presentationBytesWritten = Encoding.UTF8.GetBytes(presentationCanonicalization.CanonicalForm, presentationBytesOwner.Memory.Span);
            var proofOptionsBytesWritten = Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm, proofOptionsBytesOwner.Memory.Span);

            System.Diagnostics.Debug.Assert(presentationBytesWritten == presentationByteCount, "Encoded byte count must match the pre-computed count.");
            System.Diagnostics.Debug.Assert(proofOptionsBytesWritten == proofOptionsByteCount, "Encoded byte count must match the pre-computed count.");

            (DigestValue presentationDigestValue, _) = await computeDigest(
                new ReadOnlySequence<byte>(presentationBytesOwner.Memory[..presentationBytesWritten]),
                digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
            using DigestValue presentationDigest = presentationDigestValue;

            (DigestValue proofOptionsDigestValue, _) = await computeDigest(
                new ReadOnlySequence<byte>(proofOptionsBytesOwner.Memory[..proofOptionsBytesWritten]),
                digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
            using DigestValue proofOptionsDigest = proofOptionsDigestValue;

            //Combine hashes: proofOptionsHash || presentationHash.
            var combinedLength = proofOptionsDigest.Length + presentationDigest.Length;
            using var hashDataOwner = memoryPool.Rent(combinedLength);
            var hashData = hashDataOwner.Memory.Span;
            proofOptionsDigest.AsReadOnlySpan().CopyTo(hashData);
            presentationDigest.AsReadOnlySpan().CopyTo(hashData[proofOptionsDigest.Length..]);

            using var signature = await privateKey.SignAsync(hashDataOwner.Memory, memoryPool)
                .ConfigureAwait(false);

            //Attach the proof value to the pre-signed skeleton — the only member the
            //signature cannot cover is its own value.
            newProof.ProofValue = encodeProofValue(signature.AsReadOnlySpan(), encoder, memoryPool);

            var signedPresentation = CloneWithProofs(deserialize(presentationSerialized), [newProof]);

            return signedPresentation;
        }
    }


    extension(DataIntegritySecuredPresentation presentation)
    {


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
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredPresentation>> VerifyAsync(
            DidDocument holderDidDocument,
            string expectedChallenge,
            string expectedDomain,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueDecoderDelegate decodeProofValue,
            PresentationSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            DecodeDelegate decoder,
            ComputeDigestDelegate computeDigest,
            MemoryPool<byte> memoryPool,
            ExchangeContext context,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedChallenge);
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedDomain);

            //The challenge and domain are this path's only addition over the shared verification
            //core: the proof's binding fields MUST equal the verifier's expectation. Everything
            //else — proof purpose, verification-method resolution through authentication, and the
            //cryptographic verify — is shared with VerifyLinkedPresentationAsync.
            VerificationFailureReason? ValidateBinding(DataIntegrityProof proof)
            {
                if(!string.Equals(proof.Challenge, expectedChallenge, StringComparison.Ordinal))
                {
                    return VerificationFailureReason.ChallengeMismatch;
                }

                //§4.2: the given domain "does not contain the same strings as proof.domain
                //(treating a single string as a set containing just that string)" is an
                //error — set equality against the verifier's singleton expectation.
                if(!DataIntegrityProof.DomainSetEquals(proof.Domain, [expectedDomain]))
                {
                    return VerificationFailureReason.DomainMismatch;
                }

                return null;
            }

            return await VerifyCoreAsync(
                presentation,
                holderDidDocument,
                ValidateBinding,
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
        }


        /// <summary>
        /// Verifies a <strong>static linked</strong> presentation's Data Integrity proof — a
        /// presentation that is published once and resolved by anyone, such as a did:webvh
        /// <c>whois.vp</c> — where there is no interactive verifier and therefore no
        /// <c>challenge</c>/<c>domain</c> to bind.
        /// </summary>
        /// <param name="holderDidDocument">
        /// The holder's DID document. The verification method referenced by the proof must
        /// appear in the document's <c>authentication</c> relationship.
        /// </param>
        /// <param name="canonicalize">The canonicalization function for the cryptosuite's algorithm.</param>
        /// <param name="contextResolver">
        /// Optional delegate for resolving JSON-LD contexts. Required for RDFC-based cryptosuites.
        /// </param>
        /// <param name="decodeProofValue">Delegate for decoding the proof value string to signature bytes.</param>
        /// <param name="serialize">Delegate for serializing presentations.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="decoder">The decoding delegate (e.g., Base58 decoder).</param>
        /// <param name="computeDigest">The digest function for the cryptosuite's hash algorithm.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="context">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result indicating cryptographic validity.</returns>
        /// <remarks>
        /// <para>
        /// This path performs the SAME cryptographic verification as the challenge/domain-checked
        /// <c>VerifyAsync</c> — the proof purpose must be <c>authentication</c>, the verification method is resolved
        /// through the holder's <c>authentication</c> relationship, and the signature is verified —
        /// but it does NOT bind the proof to a verifier challenge or domain.
        /// </para>
        /// <para>
        /// To keep that absence safe it is <strong>fail-closed against misuse</strong>: if the
        /// proof carries a <c>challenge</c> or a <c>domain</c>, verification fails with
        /// <see cref="VerificationFailureReason.UnexpectedPresentationBinding"/>. A presentation
        /// minted with a replay binding (for example for an OID4VP exchange) therefore cannot be
        /// verified through this path while its binding goes unchecked — use the
        /// challenge/domain-checked <c>VerifyAsync</c> for those. The binding fields are also
        /// covered by the signature, so stripping them from a bound presentation to route it here
        /// breaks the signature and fails with <see cref="VerificationFailureReason.SignatureInvalid"/>.
        /// </para>
        /// </remarks>
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredPresentation>> VerifyLinkedPresentationAsync(
            DidDocument holderDidDocument,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueDecoderDelegate decodeProofValue,
            PresentationSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            DecodeDelegate decoder,
            ComputeDigestDelegate computeDigest,
            MemoryPool<byte> memoryPool,
            ExchangeContext context,
            CancellationToken cancellationToken = default)
        {
            return await VerifyCoreAsync(
                presentation,
                holderDidDocument,
                RejectBoundPresentation,
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
        }
    }


    /// <summary>
    /// Validates a presentation proof's replay-binding fields (<c>challenge</c>/<c>domain</c>)
    /// against a verify path's policy. Returns the <see cref="VerificationFailureReason"/> that
    /// describes a policy violation, or <see langword="null"/> when the binding is acceptable.
    /// This is the single point at which the interactive (challenge/domain-checked) and the static
    /// linked-presentation verify paths differ; the rest of the verification is shared.
    /// </summary>
    /// <param name="proof">The presentation proof whose binding fields are evaluated.</param>
    private delegate VerificationFailureReason? PresentationBindingValidator(DataIntegrityProof proof);


    /// <summary>
    /// The binding policy for a static linked presentation: it carries no replay binding, so a
    /// proof that DOES carry a <c>challenge</c> or <c>domain</c> is refused (fail closed). See
    /// <see cref="VerificationFailureReason.UnexpectedPresentationBinding"/>.
    /// </summary>
    private static VerificationFailureReason? RejectBoundPresentation(DataIntegrityProof proof)
    {
        bool hasChallenge = !string.IsNullOrEmpty(proof.Challenge);
        bool hasDomain = proof.Domain is { Count: > 0 };
        if(hasChallenge || hasDomain)
        {
            return VerificationFailureReason.UnexpectedPresentationBinding;
        }

        return null;
    }


    /// <summary>
    /// The shared presentation verification core. Checks the proof purpose, resolves the
    /// verification method through the holder's <c>authentication</c> relationship, and verifies
    /// the signature over <c>proofOptionsHash || presentationHash</c>. The supplied
    /// <paramref name="validateBinding"/> decides whether the proof's <c>challenge</c>/<c>domain</c>
    /// are acceptable for the calling path — the only behavioural difference between the
    /// interactive and the static linked-presentation verify.
    /// </summary>
    private static async ValueTask<CredentialVerificationResult<DataIntegritySecuredPresentation>> VerifyCoreAsync(
        DataIntegritySecuredPresentation presentation,
        DidDocument holderDidDocument,
        PresentationBindingValidator validateBinding,
        CanonicalizationDelegate canonicalize,
        ContextResolverDelegate? contextResolver,
        ProofValueDecoderDelegate decodeProofValue,
        PresentationSerializeDelegate serialize,
        ProofOptionsSerializeDelegate serializeProofOptions,
        DecodeDelegate decoder,
        ComputeDigestDelegate computeDigest,
        MemoryPool<byte> memoryPool,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(holderDidDocument);
        ArgumentNullException.ThrowIfNull(canonicalize);
        ArgumentNullException.ThrowIfNull(decodeProofValue);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(serializeProofOptions);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(memoryPool);

        var proof = presentation.Proof?.FirstOrDefault();
        if(proof is null)
        {
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(VerificationFailureReason.NoProof);
        }

        if(proof.Cryptosuite is null)
        {
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(VerificationFailureReason.MissingCryptosuite);
        }

        //Data Integrity 1.0 §4.2: when an expected proof purpose is given and does not
        //match proof.proofPurpose, an error MUST be raised. A presentation proof's
        //purpose is authentication (VC-DM 2.0 §4.13); a proof minted for another
        //purpose (e.g. assertionMethod) must not authenticate a presentation even when
        //its key also appears in the holder's authentication relationship.
        if(!string.Equals(proof.ProofPurpose, AuthenticationMethod.Purpose, StringComparison.Ordinal))
        {
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(VerificationFailureReason.ProofPurposeMismatch);
        }

        var verificationMethodId = proof.VerificationMethod?.Id;
        if(string.IsNullOrEmpty(verificationMethodId))
        {
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(VerificationFailureReason.MissingVerificationMethod);
        }

        //The calling path's binding policy is the only behavioural difference between the
        //interactive and static verifies. Evaluated before the expensive cryptographic work.
        if(validateBinding(proof) is { } bindingFailure)
        {
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(bindingFailure);
        }

        //Resolve through authentication to enforce the correct verification relationship.
        //A key that exists in verificationMethod but is not referenced from authentication fails here.
        var verificationMethod = holderDidDocument.GetLocalAuthenticationMethodById(verificationMethodId);
        if(verificationMethod is null)
        {
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(VerificationFailureReason.VerificationMethodNotFound);
        }

        //The signed document is the presentation WITHOUT its proof member — a
        //proofless view over this secured instance's members.
        var presentationWithoutProofSerialized = serialize(CloneWithProofs(presentation, proofs: null));

        var requiresContext = proof.Cryptosuite.Canonicalization.Equals(CanonicalizationAlgorithm.Rdfc10);
        var proofOptions = ProofOptionsDocument.FromProof(proof, requiresContext ? presentation.Context : null);
        var proofOptionsSerialized = serializeProofOptions(proofOptions);

        var presentationCanonicalization = await canonicalize(presentationWithoutProofSerialized, contextResolver, context, cancellationToken)
            .ConfigureAwait(false);
        var proofOptionsCanonicalization = await canonicalize(proofOptionsSerialized, contextResolver, context, cancellationToken)
            .ConfigureAwait(false);

        var hashAlgorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(proof.Cryptosuite.HashAlgorithm);
        int digestByteLength = WellKnownHashAlgorithms.GetSizeBytes(hashAlgorithm);
        var digestTag = new Tag(new Dictionary<Type, object>
        {
            [typeof(HashAlgorithmName)] = hashAlgorithm,
            [typeof(Purpose)] = Purpose.Digest
        });

        var presentationByteCount = Encoding.UTF8.GetByteCount(presentationCanonicalization.CanonicalForm);
        var proofOptionsByteCount = Encoding.UTF8.GetByteCount(proofOptionsCanonicalization.CanonicalForm);

        using var presentationBytesOwner = memoryPool.Rent(presentationByteCount);
        using var proofOptionsBytesOwner = memoryPool.Rent(proofOptionsByteCount);

        var presentationBytesWritten = Encoding.UTF8.GetBytes(presentationCanonicalization.CanonicalForm, presentationBytesOwner.Memory.Span);
        var proofOptionsBytesWritten = Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm, proofOptionsBytesOwner.Memory.Span);

        System.Diagnostics.Debug.Assert(presentationBytesWritten == presentationByteCount, "Encoded byte count must match the pre-computed count.");
        System.Diagnostics.Debug.Assert(proofOptionsBytesWritten == proofOptionsByteCount, "Encoded byte count must match the pre-computed count.");

        (DigestValue presentationDigestValue, _) = await computeDigest(
            new ReadOnlySequence<byte>(presentationBytesOwner.Memory[..presentationBytesWritten]),
            digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
        using DigestValue presentationDigest = presentationDigestValue;

        (DigestValue proofOptionsDigestValue, _) = await computeDigest(
            new ReadOnlySequence<byte>(proofOptionsBytesOwner.Memory[..proofOptionsBytesWritten]),
            digestByteLength, digestTag, memoryPool, null, cancellationToken).ConfigureAwait(false);
        using DigestValue proofOptionsDigest = proofOptionsDigestValue;

        var combinedLength = proofOptionsDigest.Length + presentationDigest.Length;
        using var hashDataOwner = memoryPool.Rent(combinedLength);
        var hashData = hashDataOwner.Memory.Span;
        proofOptionsDigest.AsReadOnlySpan().CopyTo(hashData);
        presentationDigest.AsReadOnlySpan().CopyTo(hashData[proofOptionsDigest.Length..]);

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
            return CredentialVerificationResult<DataIntegritySecuredPresentation>.Failed(VerificationFailureReason.SignatureInvalid);
        }

        return CredentialVerificationResult<DataIntegritySecuredPresentation>.Success(
            new Verified<DataIntegritySecuredPresentation>(presentation, VerificationContextTag.Create(verificationMethodId)));
    }


    /// <summary>
    /// Copies the presentation's members into an embedded-secured instance carrying
    /// <paramref name="proofs"/>. Passing <see langword="null"/> produces the proofless
    /// document view used for canonicalization.
    /// </summary>
    private static DataIntegritySecuredPresentation CloneWithProofs(
        VerifiablePresentation source, List<DataIntegrityProof>? proofs)
    {
        return new DataIntegritySecuredPresentation
        {
            Context = source.Context,
            Id = source.Id,
            Type = source.Type,
            Holder = source.Holder,
            VerifiableCredential = source.VerifiableCredential,
            EnvelopedVerifiableCredential = source.EnvelopedVerifiableCredential,
            TermsOfUse = source.TermsOfUse,
            AdditionalData = source.AdditionalData,
            Proof = proofs
        };
    }
}
