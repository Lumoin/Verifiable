using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Extension methods for bbs-2023 selective disclosure Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// The bbs-2023 cryptosuite enables unlinkable selective disclosure. The issuer creates a base
/// proof containing a single BBS signature over the credential; the holder can later derive
/// unlinkable proofs that reveal only selected claims without issuer involvement.
/// </para>
/// <para><strong>Three-Party Flow:</strong></para>
/// <list type="number">
/// <item><description>
/// <strong>Issuer:</strong> Creates the base proof using <see cref="CreateBaseProofAsync"/>.
/// </description></item>
/// <item><description>
/// <strong>Holder:</strong> Verifies the base proof using
/// <see cref="CredentialBbs2023Extensions.extension(DataIntegritySecuredCredential).VerifyBaseProofAsync(DidDocument, BbsVerifySignatureFactoryDelegate, ParseBbsBaseProofDelegate, PartitionStatementsDelegate, CanonicalizationDelegate, ContextResolverDelegate?, Context, CredentialSerializeDelegate, ProofOptionsSerializeDelegate, EncodeDelegate, DecodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/>,
/// stores the credential, and later derives a presentation using <see cref="DeriveProofAsync"/>.
/// </description></item>
/// <item><description>
/// <strong>Verifier:</strong> Verifies the derived proof using
/// <see cref="CredentialBbs2023Extensions.extension(DataIntegritySecuredCredential).VerifyDerivedProofAsync(DidDocument, BbsProofVerifyFactoryDelegate, ParseBbsDerivedProofDelegate, CanonicalizationDelegate, ContextResolverDelegate?, Context, CredentialSerializeDelegate, ProofOptionsSerializeDelegate, EncodeDelegate, DecodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/>.
/// </description></item>
/// </list>
/// <para>
/// Each operation has a production variant and a "Verbose" variant that returns intermediate
/// values for W3C test vector validation.
/// </para>
/// <para>
/// All four operations share the same statement-preparation substrate
/// (<see cref="NQuadStatementPreparation.PrepareWithLabelMap"/>) as ecdsa-sd-2023: a label map is
/// applied to the canonical statements, the relabeled statements are sorted Ordinal, and the
/// mandatory/non-mandatory index sets are computed over the sorted list. The only bbs-specific
/// piece is the label-map source: the shuffled-id map (<c>c14nN → bM</c>) from
/// <see cref="BbsShuffledRelabeling.ComputeShuffledLabelMapAsync"/> rather than the ecdsa-sd HMAC map.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/">VC Data Integrity BBS Cryptosuites v1.0</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The two extension blocks differ by receiver type (VerifiableCredential vs DataIntegritySecuredCredential); the analyzer is not up to date with the C# extension-block syntax.")]
public static class CredentialBbs2023Extensions
{
    extension(VerifiableCredential credential)
    {
        /// <summary>
        /// Creates a bbs-2023 base proof for the credential.
        /// </summary>
        /// <param name="issuerPublicKey">The issuer's BLS12-381 G2 public key in its raw 96-byte CFRG encoding.</param>
        /// <param name="verificationMethodId">The DID URL identifying the verification method.</param>
        /// <param name="proofCreated">The timestamp for the proof's created field.</param>
        /// <param name="mandatoryPaths">Paths to claims that must always be disclosed.</param>
        /// <param name="generateHmacKey">Delegate for generating the 32-byte HMAC key for blank node relabeling.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements into mandatory and non-mandatory sets.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="serializeBaseProof">Delegate to serialize the base proof value.</param>
        /// <param name="bbsSign">Delegate that signs the non-mandatory messages with the issuer's BBS key.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new credential instance with the base proof attached.</returns>
        public async ValueTask<DataIntegritySecuredCredential> CreateBaseProofAsync(
            ReadOnlyMemory<byte> issuerPublicKey,
            string verificationMethodId,
            DateTime proofCreated,
            IReadOnlyList<CredentialPath> mandatoryPaths,
            HmacKeyGeneratorDelegate generateHmacKey,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            SerializeBbsBaseProofDelegate serializeBaseProof,
            BbsSignDelegate bbsSign,
            EncodeDelegate encoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(deserialize);

            var result = await credential.CreateBaseProofVerboseAsync(
                issuerPublicKey,
                verificationMethodId,
                proofCreated,
                mandatoryPaths,
                generateHmacKey,
                partitionStatements,
                canonicalize,
                contextResolver,
                serialize,
                deserialize,
                serializeProofOptions,
                serializeBaseProof,
                bbsSign,
                encoder,
                memoryPool,
                exchangeContext,
                cancellationToken).ConfigureAwait(false);

            //The wire proof carries exactly the members the base signature covered. bbs-2023 proofs
            //do not chain, so no id is attached after signing.
            var baseProof = new DataIntegrityProof
            {
                Type = CredentialConstants.DataIntegrityProofType,
                Cryptosuite = Bbs2023CryptosuiteInfo.Instance,
                Created = DateTimeStampFormat.Format(proofCreated),
                VerificationMethod = new AssertionMethod(verificationMethodId),
                ProofPurpose = AssertionMethod.Purpose,
                ProofValue = result.ProofValue
            };

            var signedCredential = CloneToSecured(deserialize(serialize(credential)), [baseProof]);

            return signedCredential;
        }


        /// <summary>
        /// Creates a bbs-2023 base proof for the credential, returning complete intermediate state.
        /// </summary>
        /// <param name="issuerPublicKey">The issuer's BLS12-381 G2 public key in its raw 96-byte CFRG encoding.</param>
        /// <param name="verificationMethodId">The DID URL identifying the verification method.</param>
        /// <param name="proofCreated">The timestamp for the proof's created field.</param>
        /// <param name="mandatoryPaths">Paths to claims that must always be disclosed.</param>
        /// <param name="generateHmacKey">Delegate for generating the 32-byte HMAC key for blank node relabeling.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements into mandatory and non-mandatory sets.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="serializeBaseProof">Delegate to serialize the base proof value.</param>
        /// <param name="bbsSign">Delegate that signs the non-mandatory messages with the issuer's BBS key.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Complete intermediate state including all values for W3C test vector validation.</returns>
        public async ValueTask<BbsBaseProofResult> CreateBaseProofVerboseAsync(
            ReadOnlyMemory<byte> issuerPublicKey,
            string verificationMethodId,
            DateTime proofCreated,
            IReadOnlyList<CredentialPath> mandatoryPaths,
            HmacKeyGeneratorDelegate generateHmacKey,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            SerializeBbsBaseProofDelegate serializeBaseProof,
            BbsSignDelegate bbsSign,
            EncodeDelegate encoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
            ArgumentNullException.ThrowIfNull(mandatoryPaths);
            ArgumentNullException.ThrowIfNull(generateHmacKey);
            ArgumentNullException.ThrowIfNull(partitionStatements);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(deserialize);
            ArgumentNullException.ThrowIfNull(serializeProofOptions);
            ArgumentNullException.ThrowIfNull(serializeBaseProof);
            ArgumentNullException.ThrowIfNull(bbsSign);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            cancellationToken.ThrowIfCancellationRequested();

            var proofCreatedString = DateTimeStampFormat.Format(proofCreated);
            var credentialJson = serialize(credential);

            //The proof options derive from the complete proof skeleton: every member the wire proof
            //will carry is covered by the proof hash, matching the verify-side reconstruction.
            var proofSkeleton = new DataIntegrityProof
            {
                Type = CredentialConstants.DataIntegrityProofType,
                Cryptosuite = Bbs2023CryptosuiteInfo.Instance,
                Created = proofCreatedString,
                VerificationMethod = new AssertionMethod(verificationMethodId),
                ProofPurpose = AssertionMethod.Purpose
            };
            var proofOptions = ProofOptionsDocument.FromProof(proofSkeleton, credential.Context);
            var proofOptionsJson = serializeProofOptions(proofOptions);

            var mandatoryPointers = mandatoryPaths
                .Where(p => p.IsJsonPath)
                .Select(p => p.JsonPointer)
                .ToList();

            var partition = await partitionStatements(credentialJson, mandatoryPointers, canonicalize, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            var canonicalStatements = partition.AllStatements.ToList();

            //A credential that canonicalizes to no statements (for example one with no resolvable
            //@context) would sign a header whose mandatory hash is the SHA-256 of the empty string and
            //a BBS message vector with nothing in it; the resulting base proof would later verify
            //trivially over content the credential does not display. Refuse to mint one rather than
            //sign something that proves nothing.
            if(canonicalStatements.Count == 0)
            {
                throw new InvalidOperationException("The credential canonicalizes to no statements; a base proof would cover nothing.");
            }

            var hmacKey = generateHmacKey();

            ComputeHmacDelegate hmacCompute = ResolveHmacDelegate();

            //bbs-2023 uses the shuffled-id label map (c14n -> b<int>); the shared preparation applies it,
            //relabels statements to _:b<int>, sorts Ordinal, and computes the sorted mandatory and
            //non-mandatory index sets.
            var labelMap = await BbsShuffledRelabeling.ComputeShuffledLabelMapAsync(
                partition.AllStatements,
                hmacKey,
                hmacCompute,
                encoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            var prepared = NQuadStatementPreparation.PrepareWithLabelMap(
                partition.AllStatements,
                partition.MandatoryIndexes,
                labelMap);

            var sortedStatements = prepared.SortedStatements.ToList();

            var sortedMandatoryIndexes = prepared.MandatoryIndexes.OrderBy(i => i).ToList();
            var sortedNonMandatoryIndexes = prepared.NonMandatoryIndexes.OrderBy(i => i).ToList();

            var mandatoryStatements = sortedMandatoryIndexes.Select(i => sortedStatements[i]).ToList();
            var nonMandatoryStatements = sortedNonMandatoryIndexes.Select(i => sortedStatements[i]).ToList();

            //mandatoryHash = SHA-256 over the joined sorted mandatory statements.
            using DigestValue mandatoryHash = await CryptographicKeyEvents.ComputeDigestAsync(
                Encoding.UTF8.GetBytes(string.Join("", mandatoryStatements)),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            //proofHash = SHA-256 over the canonicalized proof options.
            var proofOptionsCanonicalization = await canonicalize(proofOptionsJson, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            using DigestValue proofHash = await CryptographicKeyEvents.ComputeDigestAsync(
                Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            //bbsHeader = proofHash || mandatoryHash.
            var bbsHeaderBytes = new byte[proofHash.Length + mandatoryHash.Length];
            proofHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes);
            mandatoryHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes.AsSpan(proofHash.Length));

            //bbsMessages = the non-mandatory statements, UTF-8 encoded, in sorted order.
            var bbsMessages = nonMandatoryStatements
                .Select(s => Encoding.UTF8.GetBytes(s))
                .ToList();

            cancellationToken.ThrowIfCancellationRequested();

            var bbsSignature = bbsSign(bbsHeaderBytes, bbsMessages, memoryPool);

            var mandatoryPointerStrings = mandatoryPaths
                .Where(p => p.IsJsonPath)
                .Select(p => p.ToJsonPointerString())
                .ToList();

            var proofValue = serializeBaseProof(
                bbsSignature,
                bbsHeaderBytes,
                issuerPublicKey.Span,
                hmacKey,
                mandatoryPointerStrings,
                encoder);

            return new BbsBaseProofResult(
                proofOptionsCanonicalization.CanonicalForm,
                proofValue,
                canonicalStatements,
                sortedStatements,
                prepared.LabelMap,
                sortedMandatoryIndexes,
                sortedNonMandatoryIndexes,
                mandatoryHash.AsReadOnlySpan().ToArray(),
                proofHash.AsReadOnlySpan().ToArray(),
                hmacKey,
                bbsHeaderBytes,
                bbsSignature,
                nonMandatoryStatements);
        }
    }


    extension(DataIntegritySecuredCredential credential)
    {
        /// <summary>
        /// Verifies the base proof on a credential.
        /// </summary>
        /// <param name="bbsVerify">Delegate that verifies the BBS signature over the non-mandatory messages.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="knownContext">
        /// The application's known <c>@context</c>: the exact ordered set of entries a document
        /// must carry for this deployment. Checked after the proof verifies, per
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data
        /// Integrity 1.0 §2.4.1 Validating Contexts</see> and
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
        /// Validation</see>.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result.</returns>
        /// <remarks>
        /// This is a bring-your-own-key primitive: <paramref name="bbsVerify"/> is a plain delegate
        /// already closed over whatever key its caller chose, never resolved or cross-checked against
        /// the credential's <c>issuer</c> claim by this method, so the result mints an
        /// <see cref="AssertedProvenance"/>, never a principal authentication. It exists for callers
        /// whose key trust is established out of band. The resolving overload below — taking a
        /// <see cref="DidDocument"/> and a <see cref="BbsVerifySignatureFactoryDelegate"/> instead of
        /// a pre-bound delegate — is the recommended default.
        /// </remarks>
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyBaseProofAsync(
            BbsVerifySignatureDelegate bbsVerify,
            ParseBbsBaseProofDelegate parseBaseProof,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            Context knownContext,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(knownContext);

            var (result, context) = await credential.VerifyBaseProofVerboseAsync(
                bbsVerify,
                parseBaseProof,
                partitionStatements,
                canonicalize,
                contextResolver,
                serialize,
                serializeProofOptions,
                encoder,
                decoder,
                memoryPool,
                exchangeContext,
                cancellationToken).ConfigureAwait(false);

            context?.Dispose();

            if(!result.IsValid)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(result.FailureReason);
            }

            if(!await ContextDeepValidation.ValidateAfterProofVerifiedAsync(credential, knownContext, cancellationToken).ConfigureAwait(false))
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ContextValidationFailed);
            }

            return CredentialVerificationResult<DataIntegritySecuredCredential>.Success(
                Verified<DataIntegritySecuredCredential>.CreateAsserted(credential, AssertedProvenance.OfLabel(credential.Proof?.FirstOrDefault()?.VerificationMethod?.Id)));
        }


        /// <summary>
        /// Verifies the base proof by RESOLVING the issuer's verification method through
        /// <paramref name="issuerDidDocument"/> — the recommended default shape. Reuses the SAME
        /// controller-binding gate the embedded-proof Data Integrity credential path uses
        /// (<see cref="BoundProvenance.TryBindByControllerArtifact"/> via
        /// <see cref="SelectiveDisclosureIdentityBinding"/>): bbs-2023 folds into that gate rather
        /// than special-casing selective disclosure.
        /// </summary>
        /// <param name="issuerDidDocument">The issuer's DID document, resolved by the caller through its own DID-resolution seam.</param>
        /// <param name="bbsVerifyFactory">
        /// Builds the BBS verify delegate closed over the RESOLVED issuer public key —
        /// <see cref="BbsVerifySignatureDelegate"/> itself carries no key parameter, so this method
        /// cannot hand the resolved key to a pre-bound delegate the way the ecdsa-sd-2023 resolving
        /// overload hands it to <c>CryptoFunctionRegistry</c>.
        /// </param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="knownContext">
        /// The application's known <c>@context</c>: the exact ordered set of entries a document
        /// must carry for this deployment. Checked after the proof verifies, per
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data
        /// Integrity 1.0 §2.4.1 Validating Contexts</see> and
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
        /// Validation</see>.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The verification result. On success the <see cref="Verified{T}"/> carried by the result is
        /// identity-bound (<see cref="Verified{T}.IsIdentityBound"/> is <see langword="true"/>).
        /// </returns>
        /// <remarks>
        /// Every gate below is a fail-closed short-circuit BEFORE the cryptographic check runs:
        /// <list type="number">
        /// <item><description>The proof's declared <c>proofPurpose</c> must be <c>assertionMethod</c>.</description></item>
        /// <item><description>The proof's <c>verificationMethod</c> must resolve under <paramref name="issuerDidDocument"/>'s <c>assertionMethod</c> relationship, not merely the flat verification-method array.</description></item>
        /// <item><description>The BBS signature must verify under the resolved method's own key material.</description></item>
        /// <item><description>The resolved method's own <c>controller</c> must equal <see cref="VerifiableCredential.Issuer"/> (controller-RESOLUTION semantics).</description></item>
        /// <item><description>The credential's own <c>@context</c> must deeply equal <paramref name="knownContext"/> (VC Data Integrity §2.4.1/§4.6).</description></item>
        /// </list>
        /// Only past every gate does <see cref="BoundProvenance.TryBindByControllerArtifact"/> mint a
        /// <see cref="Verified{T}"/> whose <see cref="Verified{T}.IsIdentityBound"/> is <see langword="true"/>.
        /// </remarks>
        /// <exception cref="ArgumentNullException">A required argument is <see langword="null"/>.</exception>
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyBaseProofAsync(
            DidDocument issuerDidDocument,
            BbsVerifySignatureFactoryDelegate bbsVerifyFactory,
            ParseBbsBaseProofDelegate parseBaseProof,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            Context knownContext,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerDidDocument);
            ArgumentNullException.ThrowIfNull(bbsVerifyFactory);
            ArgumentNullException.ThrowIfNull(knownContext);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = credential.Proof?.FirstOrDefault();
            if(proof is null || string.IsNullOrEmpty(proof.ProofValue))
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.NoProof);
            }

            (VerificationMethod? verificationMethod, VerificationFailureReason resolveFailure) =
                SelectiveDisclosureIdentityBinding.TryResolveIssuerAssertionMethod(proof, issuerDidDocument);
            if(verificationMethod is null)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(resolveFailure);
            }

            using PublicKeyMemory issuerPublicKey = verificationMethod.ToPublicKeyMemory(memoryPool);
            BbsVerifySignatureDelegate bbsVerify = bbsVerifyFactory(issuerPublicKey.AsReadOnlyMemory());

            var (result, context) = await credential.VerifyBaseProofVerboseAsync(
                bbsVerify,
                parseBaseProof,
                partitionStatements,
                canonicalize,
                contextResolver,
                serialize,
                serializeProofOptions,
                encoder,
                decoder,
                memoryPool,
                exchangeContext,
                cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            if(!result.IsValid)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(result.FailureReason);
            }

            if(!await ContextDeepValidation.ValidateAfterProofVerifiedAsync(credential, knownContext, cancellationToken).ConfigureAwait(false))
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ContextValidationFailed);
            }

            BoundProvenance? provenance = SelectiveDisclosureIdentityBinding.TryBindIssuer(
                credential, verificationMethod, proof.ProofPurpose!, credential);

            return provenance is null
                || Verified<DataIntegritySecuredCredential>.TryCreateBound(credential, provenance) is not { } verified
                    ? CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ControllerMismatch)
                    : CredentialVerificationResult<DataIntegritySecuredCredential>.Success(verified);
        }


        /// <summary>
        /// Verifies the base proof on a credential, returning complete intermediate state.
        /// </summary>
        /// <param name="bbsVerify">Delegate that verifies the BBS signature over the non-mandatory messages.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A tuple of the verification result and, if successful, the holder context.</returns>
        public async ValueTask<(CredentialVerificationResult Result, BbsHolderProofContext? Context)> VerifyBaseProofVerboseAsync(
            BbsVerifySignatureDelegate bbsVerify,
            ParseBbsBaseProofDelegate parseBaseProof,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(bbsVerify);
            ArgumentNullException.ThrowIfNull(parseBaseProof);
            ArgumentNullException.ThrowIfNull(partitionStatements);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(serializeProofOptions);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(decoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = credential.Proof?.FirstOrDefault();
            if(proof == null)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.NoProof), null);
            }

            //Data Integrity §4.4 requires type, verificationMethod and proofPurpose; any of the three
            //missing groups under the same MissingVerificationMethod reason.
            if(string.IsNullOrEmpty(proof.Type) || string.IsNullOrEmpty(proof.VerificationMethod?.Id) || string.IsNullOrEmpty(proof.ProofPurpose))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod), null);
            }

            //Data Integrity §4.4: "If expectedProofPurpose was given, and it does not match proof.proofPurpose, an error
            //MUST be raised." A credential proof's expected purpose is assertionMethod, compared ordinally as the resolving
            //entry points compare it, so a proof declaring any other purpose never verifies whichever verifier the caller
            //supplies.
            if(!string.Equals(proof.ProofPurpose, AssertionMethod.Purpose, StringComparison.Ordinal))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.ProofPurposeMismatch), null);
            }

            if(proof.Cryptosuite?.CryptosuiteName != CredentialConstants.Cryptosuites.Bbs2023)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.MissingCryptosuite), null);
            }

            if(string.IsNullOrEmpty(proof.ProofValue))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.NoProof), null);
            }

            cancellationToken.ThrowIfCancellationRequested();

            using var parsedProof = parseBaseProof(proof.ProofValue, decoder, memoryPool);

            var credentialWithoutProof = CloneCredentialWithoutProof(credential);
            var credentialJson = serialize(credentialWithoutProof);

            //The credential's own @context is untrusted caller input; a context the canonicalizer
            //cannot load (an unresolvable remote URI, for RDFC-based cryptosuites) is a FAILED
            //verification, per Data Integrity 1.0 §2.4.1, never an escaping exception.
            StatementPartitionResult partition;
            try
            {
                partition = await partitionStatements(credentialJson, parsedProof.MandatoryPointers.ToList(), canonicalize, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch(Exception exception)
            {
                //A canonicalizer or context loader that wraps the cancellation of its own fetch reports that cancellation.
                WrappedCancellation.ThrowIfCarried(exception);

                return (CredentialVerificationResult.Failed(VerificationFailureReason.ContextValidationFailed), null);
            }

            var canonicalStatements = partition.AllStatements.ToList();

            //A credential that canonicalizes to no statements cannot be verified: the mandatory hash
            //and the BBS message vector would both be computed over nothing, and a proof over nothing
            //verifies as valid regardless of what the credential displays. Refusing here closes that
            //bypass before any cryptographic call.
            if(canonicalStatements.Count == 0)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            ComputeHmacDelegate hmacCompute = ResolveHmacDelegate();

            var labelMap = await BbsShuffledRelabeling.ComputeShuffledLabelMapAsync(
                partition.AllStatements,
                parsedProof.HmacKey,
                hmacCompute,
                encoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            var prepared = NQuadStatementPreparation.PrepareWithLabelMap(
                partition.AllStatements,
                partition.MandatoryIndexes,
                labelMap);

            var sortedStatements = prepared.SortedStatements.ToList();

            var sortedMandatoryIndexes = prepared.MandatoryIndexes.OrderBy(i => i).ToList();
            var sortedNonMandatoryIndexes = prepared.NonMandatoryIndexes.OrderBy(i => i).ToList();

            var mandatoryStatements = sortedMandatoryIndexes.Select(i => sortedStatements[i]).ToList();
            var nonMandatoryStatements = sortedNonMandatoryIndexes.Select(i => sortedStatements[i]).ToList();

            using DigestValue mandatoryHash = await CryptographicKeyEvents.ComputeDigestAsync(
                Encoding.UTF8.GetBytes(string.Join("", mandatoryStatements)),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var proofOptions = ProofOptionsDocument.FromProof(proof, credential.Context);
            var proofOptionsJson = serializeProofOptions(proofOptions);

            CanonicalizationResult proofOptionsCanonicalization;
            try
            {
                proofOptionsCanonicalization = await canonicalize(proofOptionsJson, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch(Exception exception)
            {
                //A canonicalizer or context loader that wraps the cancellation of its own fetch reports that cancellation.
                WrappedCancellation.ThrowIfCarried(exception);

                return (CredentialVerificationResult.Failed(VerificationFailureReason.ContextValidationFailed), null);
            }

            using DigestValue proofHash = await CryptographicKeyEvents.ComputeDigestAsync(
                Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var bbsHeaderBytes = new byte[proofHash.Length + mandatoryHash.Length];
            proofHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes);
            mandatoryHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes.AsSpan(proofHash.Length));

            //The parsed bbsHeader must match the reconstructed proofHash || mandatoryHash. A mismatch
            //means the proof options or mandatory statements were tampered with; fail closed.
            if(!parsedProof.BbsHeader.AsSpan().SequenceEqual(bbsHeaderBytes))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            var bbsMessages = nonMandatoryStatements
                .Select(s => Encoding.UTF8.GetBytes(s))
                .ToList();

            cancellationToken.ThrowIfCancellationRequested();

            var isValid = bbsVerify(
                parsedProof.BbsSignature,
                bbsHeaderBytes,
                bbsMessages,
                memoryPool);

            if(!isValid)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            var context = new BbsHolderProofContext(
                canonicalStatements,
                sortedStatements,
                prepared.LabelMap,
                sortedMandatoryIndexes,
                sortedNonMandatoryIndexes,
                nonMandatoryStatements,
                parsedProof.HmacKey,
                proofHash.AsReadOnlySpan().ToArray(),
                mandatoryHash.AsReadOnlySpan().ToArray(),
                bbsHeaderBytes);

            return (CredentialVerificationResult.Success(), context);
        }


        /// <summary>
        /// Creates a bbs-2023 derived proof from a credential with a base proof.
        /// </summary>
        /// <param name="verifierRequestedPaths">Paths to claims the verifier has requested.</param>
        /// <param name="userExclusions">Paths to claims the user wants to exclude, or null.</param>
        /// <param name="presentationHeader">The BBS presentation header bytes.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="selectFragments">Delegate for selecting JSON-LD fragments to create the reduced credential.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="serializeDerivedProof">Delegate to serialize the derived proof value.</param>
        /// <param name="bbsProofGen">Delegate that generates the BBS proof.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new credential instance with only disclosed claims and the derived proof attached.</returns>
        public async ValueTask<DataIntegritySecuredCredential> DeriveProofAsync(
            IReadOnlySet<CredentialPath> verifierRequestedPaths,
            IReadOnlySet<CredentialPath>? userExclusions,
            ReadOnlyMemory<byte> presentationHeader,
            PartitionStatementsDelegate partitionStatements,
            SelectJsonLdFragmentsDelegate selectFragments,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ParseBbsBaseProofDelegate parseBaseProof,
            SerializeBbsDerivedProofDelegate serializeDerivedProof,
            BbsProofGenDelegate bbsProofGen,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            var (derivedCredential, _) = await credential.DeriveProofVerboseAsync(
                verifierRequestedPaths,
                userExclusions,
                presentationHeader,
                partitionStatements,
                selectFragments,
                canonicalize,
                contextResolver,
                serialize,
                deserialize,
                parseBaseProof,
                serializeDerivedProof,
                bbsProofGen,
                encoder,
                decoder,
                memoryPool,
                exchangeContext,
                cancellationToken).ConfigureAwait(false);

            return derivedCredential;
        }


        /// <summary>
        /// Creates a bbs-2023 derived proof from a credential with a base proof, returning intermediate state.
        /// </summary>
        /// <param name="verifierRequestedPaths">Paths to claims the verifier has requested.</param>
        /// <param name="userExclusions">Paths to claims the user wants to exclude, or null.</param>
        /// <param name="presentationHeader">The BBS presentation header bytes.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="selectFragments">Delegate for selecting JSON-LD fragments to create the reduced credential.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="serializeDerivedProof">Delegate to serialize the derived proof value.</param>
        /// <param name="bbsProofGen">Delegate that generates the BBS proof.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A tuple of the derived credential and the parsed derived proof for vector validation.</returns>
        public async ValueTask<(DataIntegritySecuredCredential DerivedCredential, BbsDerivedProof DerivedProof)> DeriveProofVerboseAsync(
            IReadOnlySet<CredentialPath> verifierRequestedPaths,
            IReadOnlySet<CredentialPath>? userExclusions,
            ReadOnlyMemory<byte> presentationHeader,
            PartitionStatementsDelegate partitionStatements,
            SelectJsonLdFragmentsDelegate selectFragments,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ParseBbsBaseProofDelegate parseBaseProof,
            SerializeBbsDerivedProofDelegate serializeDerivedProof,
            BbsProofGenDelegate bbsProofGen,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(verifierRequestedPaths);
            ArgumentNullException.ThrowIfNull(partitionStatements);
            ArgumentNullException.ThrowIfNull(selectFragments);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(deserialize);
            ArgumentNullException.ThrowIfNull(parseBaseProof);
            ArgumentNullException.ThrowIfNull(serializeDerivedProof);
            ArgumentNullException.ThrowIfNull(bbsProofGen);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(decoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = credential.Proof?.FirstOrDefault() ?? throw new InvalidOperationException("Credential must have a proof to derive from.");

            if(proof.Cryptosuite?.CryptosuiteName != CredentialConstants.Cryptosuites.Bbs2023)
            {
                throw new InvalidOperationException($"Expected cryptosuite '{CredentialConstants.Cryptosuites.Bbs2023}' but found '{proof.Cryptosuite?.CryptosuiteName}'.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            using var parsedProof = parseBaseProof(proof.ProofValue!, decoder, memoryPool);

            var credentialWithoutProof = CloneCredentialWithoutProof(credential);
            var fullCredentialJson = serialize(credentialWithoutProof);

            var mandatoryPointers = parsedProof.MandatoryPointers.ToList();

            //Selective pointers map to JSON pointers from the verifier request.
            var selectivePointers = verifierRequestedPaths
                .Where(p => p.IsJsonPath)
                .Select(p => p.JsonPointer)
                .ToList();

            ComputeHmacDelegate hmacCompute = ResolveHmacDelegate();

            //Prepare the FULL document over the base proof's hmacKey, with mandatoryPointers as mandatory.
            //fullPrepared.SortedStatements is the BBS message ordering: the BBS signature covers the
            //non-mandatory messages in ascending non-mandatory sorted-index order.
            var fullPartition = await partitionStatements(fullCredentialJson, mandatoryPointers, canonicalize, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);

            var fullLabelMap = await BbsShuffledRelabeling.ComputeShuffledLabelMapAsync(
                fullPartition.AllStatements,
                parsedProof.HmacKey,
                hmacCompute,
                encoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            var fullPrepared = NQuadStatementPreparation.PrepareWithLabelMap(
                fullPartition.AllStatements,
                fullPartition.MandatoryIndexes,
                fullLabelMap);

            var fullSortedNonMandatoryIndexes = fullPrepared.NonMandatoryIndexes.OrderBy(i => i).ToList();

            //bbsMessages = the full non-mandatory statements, UTF-8 encoded, in ascending sorted order.
            //Each non-mandatory message maps to its 0-based position in this vector, used to express
            //which of them are selectively disclosed.
            var nonMandatoryMessageToVectorIndex = new Dictionary<string, int>(fullSortedNonMandatoryIndexes.Count, StringComparer.Ordinal);
            var bbsMessages = new List<byte[]>(fullSortedNonMandatoryIndexes.Count);
            for(int vectorIndex = 0; vectorIndex < fullSortedNonMandatoryIndexes.Count; vectorIndex++)
            {
                var statement = fullPrepared.SortedStatements[fullSortedNonMandatoryIndexes[vectorIndex]];
                nonMandatoryMessageToVectorIndex[statement] = vectorIndex;
                bbsMessages.Add(Encoding.UTF8.GetBytes(statement));
            }

            //Per §3.3.3 createDisclosureData, disclosedPointers = mandatoryPointers ++ selectivePointers.
            var disclosedPointers = new List<Lumoin.Veritas.JsonPointer.JsonPointer>(mandatoryPointers);
            disclosedPointers.AddRange(selectivePointers);

            //Create the reveal document from the disclosed pointers.
            var reducedCredentialJson = selectFragments(fullCredentialJson, disclosedPointers);

            //Canonicalize the reveal document. Its blank nodes get fresh canonical ids, so the shuffle
            //label map is rebuilt by joining through the shared original bnode identifiers:
            //reduced_c14n -> original_bnode -> full_c14n -> shuffle b-label.
            var reducedPartition = await partitionStatements(reducedCredentialJson, [], canonicalize, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);

            //A reveal document that canonicalizes to no statements would carry a derived proof whose
            //mandatory hash and BBS message vector are both computed over nothing, which verifies
            //trivially. Refuse to mint such a proof rather than hand the holder a credential that
            //verifies without proving anything about any claim it displays.
            if(reducedPartition.AllStatements.Count == 0)
            {
                throw new InvalidOperationException("The disclosed reveal document canonicalizes to no statements; a derived proof would cover nothing.");
            }

            var reducedLabelMap = ComputeReducedLabelMap(
                reducedPartition.LabelMap,
                fullPartition.LabelMap,
                fullLabelMap);

            var reducedPrepared = NQuadStatementPreparation.PrepareWithLabelMap(
                reducedPartition.AllStatements,
                [],
                reducedLabelMap);

            //Walk the reveal document's relabeled+sorted statements in order. A statement that is one of
            //the full non-mandatory messages is a disclosed non-mandatory message; collect its full-vector
            //index into selectiveIndexes (ascending). Otherwise it is mandatory in the reveal document;
            //collect its position within the reveal sorted list into the derived mandatoryIndexes.
            var selectiveIndexes = new List<int>();
            var derivedMandatoryIndexes = new List<int>();
            for(int revealIndex = 0; revealIndex < reducedPrepared.SortedStatements.Count; revealIndex++)
            {
                var statement = reducedPrepared.SortedStatements[revealIndex];
                if(nonMandatoryMessageToVectorIndex.TryGetValue(statement, out int vectorIndex))
                {
                    selectiveIndexes.Add(vectorIndex);
                }
                else
                {
                    derivedMandatoryIndexes.Add(revealIndex);
                }
            }

            selectiveIndexes.Sort();

            cancellationToken.ThrowIfCancellationRequested();

            var bbsProofBytes = bbsProofGen(
                parsedProof.BbsSignature,
                parsedProof.BbsHeader,
                presentationHeader,
                bbsMessages,
                selectiveIndexes,
                memoryPool);

            var derivedProofValue = serializeDerivedProof(
                bbsProofBytes,
                reducedLabelMap,
                derivedMandatoryIndexes,
                selectiveIndexes,
                presentationHeader.Span,
                encoder);

            var derivedProof = new DataIntegrityProof
            {
                Id = proof.Id,
                Type = proof.Type,
                Cryptosuite = proof.Cryptosuite,
                Created = proof.Created,
                VerificationMethod = proof.VerificationMethod,
                ProofPurpose = proof.ProofPurpose,
                ProofValue = derivedProofValue
            };

            var derivedCredential = CloneToSecured(deserialize(reducedCredentialJson), [derivedProof]);

            var derivedProofRecord = new BbsDerivedProof
            {
                BbsProof = bbsProofBytes,
                LabelMap = reducedLabelMap,
                MandatoryIndexes = derivedMandatoryIndexes,
                SelectiveIndexes = selectiveIndexes,
                PresentationHeader = presentationHeader.ToArray()
            };

            return (derivedCredential, derivedProofRecord);
        }


        /// <summary>
        /// Verifies a bbs-2023 derived proof on the credential.
        /// </summary>
        /// <param name="bbsProofVerify">Delegate that verifies the BBS proof against the disclosed messages.</param>
        /// <param name="parseDerivedProof">Delegate to parse the derived proof value.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="knownContext">
        /// The application's known <c>@context</c>: the exact ordered set of entries a document
        /// must carry for this deployment. Checked after the proof verifies, per
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data
        /// Integrity 1.0 §2.4.1 Validating Contexts</see> and
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
        /// Validation</see>. The derived (reveal) document carries the same <c>@context</c> the
        /// base proof's document carried, copied verbatim by selective disclosure.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result.</returns>
        /// <remarks>
        /// This is a bring-your-own-key primitive: <paramref name="bbsProofVerify"/> is a plain
        /// delegate already closed over whatever key its caller chose, never resolved or cross-checked
        /// against the credential's <c>issuer</c> claim by this method, so the result mints an
        /// <see cref="AssertedProvenance"/>, never a principal authentication. The resolving overload
        /// below — taking a <see cref="DidDocument"/> and a <see cref="BbsProofVerifyFactoryDelegate"/>
        /// instead of a pre-bound delegate — is the recommended default.
        /// </remarks>
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyDerivedProofAsync(
            BbsProofVerifyDelegate bbsProofVerify,
            ParseBbsDerivedProofDelegate parseDerivedProof,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            Context knownContext,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(knownContext);

            var (result, context) = await credential.VerifyDerivedProofVerboseAsync(
                bbsProofVerify,
                parseDerivedProof,
                canonicalize,
                contextResolver,
                serialize,
                serializeProofOptions,
                encoder,
                decoder,
                memoryPool,
                exchangeContext,
                cancellationToken).ConfigureAwait(false);

            context?.Dispose();

            if(!result.IsValid)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(result.FailureReason);
            }

            if(!await ContextDeepValidation.ValidateAfterProofVerifiedAsync(credential, knownContext, cancellationToken).ConfigureAwait(false))
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ContextValidationFailed);
            }

            return CredentialVerificationResult<DataIntegritySecuredCredential>.Success(
                Verified<DataIntegritySecuredCredential>.CreateAsserted(credential, AssertedProvenance.OfLabel(credential.Proof?.FirstOrDefault()?.VerificationMethod?.Id)));
        }


        /// <summary>
        /// Verifies a derived proof by RESOLVING the issuer's verification method through
        /// <paramref name="issuerDidDocument"/> — the recommended default shape. See
        /// <see cref="CredentialBbs2023Extensions.extension(DataIntegritySecuredCredential).VerifyBaseProofAsync(DidDocument, BbsVerifySignatureFactoryDelegate, ParseBbsBaseProofDelegate, PartitionStatementsDelegate, CanonicalizationDelegate, ContextResolverDelegate?, Context, CredentialSerializeDelegate, ProofOptionsSerializeDelegate, EncodeDelegate, DecodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/>
        /// for the gate sequence; a derived proof's <c>verificationMethod</c> is the same issuer
        /// method the base proof carried (<see cref="DeriveProofVerboseAsync"/> copies it through
        /// unchanged), so the same resolve-and-bind recipe applies.
        /// </summary>
        /// <param name="issuerDidDocument">The issuer's DID document, resolved by the caller through its own DID-resolution seam.</param>
        /// <param name="bbsProofVerifyFactory">Builds the BBS proof-verify delegate closed over the RESOLVED issuer public key.</param>
        /// <param name="parseDerivedProof">Delegate to parse the derived proof value.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="knownContext">
        /// The application's known <c>@context</c>: the exact ordered set of entries a document
        /// must carry for this deployment. Checked after the proof verifies, per
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data
        /// Integrity 1.0 §2.4.1 Validating Contexts</see> and
        /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
        /// Validation</see>. The derived (reveal) document carries the same <c>@context</c> the
        /// base proof's document carried, copied verbatim by selective disclosure.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The verification result. On success the <see cref="Verified{T}"/> carried by the result is
        /// identity-bound (<see cref="Verified{T}.IsIdentityBound"/> is <see langword="true"/>).
        /// </returns>
        /// <exception cref="ArgumentNullException">A required argument is <see langword="null"/>.</exception>
        public async ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyDerivedProofAsync(
            DidDocument issuerDidDocument,
            BbsProofVerifyFactoryDelegate bbsProofVerifyFactory,
            ParseBbsDerivedProofDelegate parseDerivedProof,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            Context knownContext,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerDidDocument);
            ArgumentNullException.ThrowIfNull(bbsProofVerifyFactory);
            ArgumentNullException.ThrowIfNull(knownContext);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = credential.Proof?.FirstOrDefault();
            if(proof is null || string.IsNullOrEmpty(proof.ProofValue))
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.NoProof);
            }

            (VerificationMethod? verificationMethod, VerificationFailureReason resolveFailure) =
                SelectiveDisclosureIdentityBinding.TryResolveIssuerAssertionMethod(proof, issuerDidDocument);
            if(verificationMethod is null)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(resolveFailure);
            }

            using PublicKeyMemory issuerPublicKey = verificationMethod.ToPublicKeyMemory(memoryPool);
            BbsProofVerifyDelegate bbsProofVerify = bbsProofVerifyFactory(issuerPublicKey.AsReadOnlyMemory());

            var (result, context) = await credential.VerifyDerivedProofVerboseAsync(
                bbsProofVerify,
                parseDerivedProof,
                canonicalize,
                contextResolver,
                serialize,
                serializeProofOptions,
                encoder,
                decoder,
                memoryPool,
                exchangeContext,
                cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            if(!result.IsValid)
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(result.FailureReason);
            }

            if(!await ContextDeepValidation.ValidateAfterProofVerifiedAsync(credential, knownContext, cancellationToken).ConfigureAwait(false))
            {
                return CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ContextValidationFailed);
            }

            BoundProvenance? provenance = SelectiveDisclosureIdentityBinding.TryBindIssuer(
                credential, verificationMethod, proof.ProofPurpose!, credential);

            return provenance is null
                || Verified<DataIntegritySecuredCredential>.TryCreateBound(credential, provenance) is not { } verified
                    ? CredentialVerificationResult<DataIntegritySecuredCredential>.Failed(VerificationFailureReason.ControllerMismatch)
                    : CredentialVerificationResult<DataIntegritySecuredCredential>.Success(verified);
        }


        /// <summary>
        /// Verifies a bbs-2023 derived proof on the credential, returning complete intermediate state.
        /// </summary>
        /// <param name="bbsProofVerify">Delegate that verifies the BBS proof against the disclosed messages.</param>
        /// <param name="parseDerivedProof">Delegate to parse the derived proof value.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="exchangeContext">The per-operation exchange context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A tuple of the verification result and, if successful, the verifier context.</returns>
        public async ValueTask<(CredentialVerificationResult Result, BbsVerifierProofContext? Context)> VerifyDerivedProofVerboseAsync(
            BbsProofVerifyDelegate bbsProofVerify,
            ParseBbsDerivedProofDelegate parseDerivedProof,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            BaseMemoryPool memoryPool,
            ExchangeContext exchangeContext,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(bbsProofVerify);
            ArgumentNullException.ThrowIfNull(parseDerivedProof);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(serializeProofOptions);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(decoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = credential.Proof?.FirstOrDefault();
            if(proof == null)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.NoProof), null);
            }

            //Data Integrity §4.4 requires type, verificationMethod and proofPurpose; any of the three
            //missing groups under the same MissingVerificationMethod reason.
            if(string.IsNullOrEmpty(proof.Type) || string.IsNullOrEmpty(proof.VerificationMethod?.Id) || string.IsNullOrEmpty(proof.ProofPurpose))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.MissingVerificationMethod), null);
            }

            //Data Integrity §4.4: "If expectedProofPurpose was given, and it does not match proof.proofPurpose, an error
            //MUST be raised." A derived proof carries the base proof's assertionMethod purpose, compared ordinally as the
            //resolving entry points compare it, so a proof declaring any other purpose never verifies whichever verifier the
            //caller supplies.
            if(!string.Equals(proof.ProofPurpose, AssertionMethod.Purpose, StringComparison.Ordinal))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.ProofPurposeMismatch), null);
            }

            if(proof.Cryptosuite?.CryptosuiteName != CredentialConstants.Cryptosuites.Bbs2023)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.MissingCryptosuite), null);
            }

            if(string.IsNullOrEmpty(proof.ProofValue))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.NoProof), null);
            }

            cancellationToken.ThrowIfCancellationRequested();

            using var parsedProof = parseDerivedProof(proof.ProofValue, decoder, memoryPool);

            var credentialWithoutProof = CloneCredentialWithoutProof(credential);
            var credentialJson = serialize(credentialWithoutProof);

            //createVerifyData: canonicalize the reveal document, then apply the parsed label map, sort, and
            //split into mandatory (by parsed mandatoryIndexes) and disclosed non-mandatory through the
            //shared preparation substrate. The reveal document's own @context is untrusted caller
            //input; a context the canonicalizer cannot load (an unresolvable remote URI, for
            //RDFC-based cryptosuites) is a FAILED verification, per Data Integrity 1.0 §2.4.1, never
            //an escaping exception.
            CanonicalizationResult credentialCanonicalization;
            try
            {
                credentialCanonicalization = await canonicalize(credentialJson, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch(Exception exception)
            {
                //A canonicalizer or context loader that wraps the cancellation of its own fetch reports that cancellation.
                WrappedCancellation.ThrowIfCarried(exception);

                return (CredentialVerificationResult.Failed(VerificationFailureReason.ContextValidationFailed), null);
            }

            var canonicalStatements = SplitIntoStatements(credentialCanonicalization.CanonicalForm);

            //A reveal document that canonicalizes to no statements at all (for example one whose
            //@context was lost, so no property key resolves to an absolute IRI) cannot be verified:
            //the mandatory hash and the disclosed (non-mandatory) BBS message vector would both be
            //computed over nothing -- neither path carries any content -- and a BBS proof of knowledge
            //over an empty message list verifies as valid regardless of what the credential displays.
            //Refusing here closes that bypass before any cryptographic call. A derived proof whose
            //disclosed set is empty but whose mandatory set is not is a different, legitimate case: the
            //mandatory statements still bind real content into the header, so it is not refused here.
            if(canonicalStatements.Length == 0)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            //A canonical (_:c14nN) blank node in the reveal document with no entry in the parsed
            //derived proof's label map means the map was not built from this same canonicalization
            //-- for example a different conformant RDFC-1.0 implementation assigned different
            //labels to the same graph -- so the statements that would reach the BBS message vector
            //would not be the ones the base proof's shuffled label map actually bound. Refuse
            //rather than verify content that was not what was signed.
            if(BlankNodeRelabelingExtensions.HasUnmappedCanonicalBlankNode(canonicalStatements, parsedProof.LabelMap))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            var reducedPrepared = NQuadStatementPreparation.PrepareWithLabelMap(
                canonicalStatements,
                [],
                parsedProof.LabelMap);

            var sortedStatements = reducedPrepared.SortedStatements;

            var mandatorySet = new HashSet<int>(parsedProof.MandatoryIndexes);
            var mandatoryStatements = new List<string>();
            var nonMandatoryStatements = new List<string>();
            for(int i = 0; i < sortedStatements.Count; i++)
            {
                if(mandatorySet.Contains(i))
                {
                    mandatoryStatements.Add(sortedStatements[i]);
                }
                else
                {
                    nonMandatoryStatements.Add(sortedStatements[i]);
                }
            }

            using DigestValue mandatoryHash = await CryptographicKeyEvents.ComputeDigestAsync(
                Encoding.UTF8.GetBytes(string.Join("", mandatoryStatements)),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var proofOptions = ProofOptionsDocument.FromProof(proof, credential.Context);
            var proofOptionsJson = serializeProofOptions(proofOptions);

            CanonicalizationResult proofOptionsCanonicalization;
            try
            {
                proofOptionsCanonicalization = await canonicalize(proofOptionsJson, contextResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch(Exception exception)
            {
                //A canonicalizer or context loader that wraps the cancellation of its own fetch reports that cancellation.
                WrappedCancellation.ThrowIfCarried(exception);

                return (CredentialVerificationResult.Failed(VerificationFailureReason.ContextValidationFailed), null);
            }

            using DigestValue proofHash = await CryptographicKeyEvents.ComputeDigestAsync(
                Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm),
                outputByteLength: 32,
                tag: CryptoTags.Sha256Digest,
                pool: memoryPool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var bbsHeaderBytes = new byte[proofHash.Length + mandatoryHash.Length];
            proofHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes);
            mandatoryHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes.AsSpan(proofHash.Length));

            var disclosedMessages = nonMandatoryStatements
                .Select(s => Encoding.UTF8.GetBytes(s))
                .ToList();

            cancellationToken.ThrowIfCancellationRequested();

            var isValid = bbsProofVerify(
                parsedProof.BbsProof,
                bbsHeaderBytes,
                parsedProof.PresentationHeader,
                disclosedMessages,
                parsedProof.SelectiveIndexes,
                memoryPool);

            if(!isValid)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            var context = new BbsVerifierProofContext(
                nonMandatoryStatements,
                mandatoryStatements,
                parsedProof.LabelMap.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                parsedProof.MandatoryIndexes.ToList(),
                parsedProof.SelectiveIndexes.ToList(),
                proofHash.AsReadOnlySpan().ToArray(),
                mandatoryHash.AsReadOnlySpan().ToArray(),
                bbsHeaderBytes,
                parsedProof.PresentationHeader.ToArray());

            return (CredentialVerificationResult.Success(), context);
        }
    }


    /// <summary>Splits canonical N-Quads into its statements, each keeping its terminating newline.</summary>
    /// <param name="nquads">The canonical N-Quads document.</param>
    private static string[] SplitIntoStatements(string nquads)
    {
        var lines = nquads.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        return lines.Select(line => line + "\n").ToArray();
    }


    /// <summary>Copies the base <see cref="VerifiableCredential"/> members of <paramref name="credential"/> without any proof.</summary>
    /// <param name="credential">The credential whose members are copied.</param>
    private static VerifiableCredential CloneCredentialWithoutProof(VerifiableCredential credential)
    {
        return new VerifiableCredential
        {
            Context = credential.Context,
            Id = credential.Id,
            Type = credential.Type,
            Name = credential.Name,
            Description = credential.Description,
            Issuer = credential.Issuer,
            CredentialSubject = credential.CredentialSubject,
            ValidFrom = credential.ValidFrom,
            ValidUntil = credential.ValidUntil,
            CredentialStatus = credential.CredentialStatus,
            CredentialSchema = credential.CredentialSchema,
            RelatedResource = credential.RelatedResource,
            RefreshService = credential.RefreshService,
            TermsOfUse = credential.TermsOfUse,
            Evidence = credential.Evidence,
            AdditionalData = credential.AdditionalData
        };
    }


    /// <summary>
    /// Copies the base <see cref="VerifiableCredential"/> members into a <see cref="DataIntegritySecuredCredential"/>
    /// carrying <paramref name="proof"/>.
    /// </summary>
    /// <param name="source">The credential whose members are copied.</param>
    /// <param name="proof">The proofs attached.</param>
    private static DataIntegritySecuredCredential CloneToSecured(VerifiableCredential source, List<DataIntegrityProof> proof)
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
            Proof = proof
        };
    }


    /// <summary>
    /// Computes the reduced credential's shuffle label map (verifier canonical id -> shuffle b-label) by
    /// joining the reduced and full RDFC label maps through their shared original blank node identifiers.
    /// </summary>
    /// <remarks>
    /// Chain: reduced_c14n_id -> original_bnode_id -> full_c14n_id -> shuffle b-label. This mirrors the
    /// ecdsa-sd reduced label-map join, differing only in the final value (a shuffle b-label rather than an
    /// HMAC label).
    /// </remarks>
    private static Dictionary<string, string> ComputeReducedLabelMap(
        IReadOnlyDictionary<string, string>? reducedRdfcLabelMap,
        IReadOnlyDictionary<string, string>? fullRdfcLabelMap,
        IReadOnlyDictionary<string, string> fullShuffledLabelMap)
    {
        var reducedLabelMap = new Dictionary<string, string>(StringComparer.Ordinal);

        if(reducedRdfcLabelMap is null || fullRdfcLabelMap is null)
        {
            return reducedLabelMap;
        }

        var originalToFullCanonical = new Dictionary<string, string>(fullRdfcLabelMap.Count, StringComparer.Ordinal);
        foreach(var (fullCanonical, original) in fullRdfcLabelMap)
        {
            originalToFullCanonical[StripBlankNodePrefix(original)] = StripBlankNodePrefix(fullCanonical);
        }

        foreach(var (reducedCanonical, original) in reducedRdfcLabelMap)
        {
            var bareOriginal = StripBlankNodePrefix(original);
            if(originalToFullCanonical.TryGetValue(bareOriginal, out var fullCanonical)
                && fullShuffledLabelMap.TryGetValue(fullCanonical, out var shuffledLabel))
            {
                reducedLabelMap[StripBlankNodePrefix(reducedCanonical)] = shuffledLabel;
            }
        }

        return reducedLabelMap;
    }


    /// <summary>Removes the <c>_:</c> blank node prefix from <paramref name="identifier"/> when it carries one.</summary>
    /// <param name="identifier">A blank node identifier, prefixed or bare.</param>
    private static string StripBlankNodePrefix(string identifier) =>
        identifier.StartsWith("_:", StringComparison.Ordinal)
            ? identifier[2..]
            : identifier;


    /// <summary>
    /// The <see cref="ComputeHmacDelegate"/> registered with <see cref="CryptographicKeyFactory"/>; the application
    /// registers it at startup, and its absence is a configuration error.
    /// </summary>
    private static ComputeHmacDelegate ResolveHmacDelegate() =>
        CryptographicKeyFactory.GetFunction<ComputeHmacDelegate>(typeof(ComputeHmacDelegate))
        ?? throw new InvalidOperationException(
            $"No {nameof(ComputeHmacDelegate)} has been registered. " +
            "Call CryptographicKeyFactory.RegisterFunction during application startup.");
}
