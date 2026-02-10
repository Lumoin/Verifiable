using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

public delegate byte[] HmacKeyGeneratorDelegate();

/// <summary>
/// Extension methods for ecdsa-sd-2023 selective disclosure Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// The ecdsa-sd-2023 cryptosuite enables selective disclosure where the issuer creates a base proof
/// containing all claims, and the holder can later derive proofs that reveal only selected claims.
/// </para>
/// <para><strong>Three-Party Flow:</strong></para>
/// <list type="number">
/// <item><description>
/// <strong>Issuer:</strong> Creates base proof using <see cref="CreateBaseProofAsync"/>.
/// The issuer has the unsigned credential and signing keys. Produces a signed credential
/// with embedded base proof that is sent to the holder.
/// </description></item>
/// <item><description>
/// <strong>Holder:</strong> Receives signed credential, verifies it using
/// <see cref="VerifyBaseProofAsync"/> with the issuer's public key.
/// Stores the credential. Later, when presenting to a verifier, holder uses
/// <see cref="DeriveProofAsync"/> to create a derived credential with selective disclosure.
/// </description></item>
/// <item><description>
/// <strong>Verifier:</strong> Receives derived credential, verifies it using
/// <see cref="VerifyDerivedProofAsync"/> with the issuer's public key.
/// </description></item>
/// </list>
/// <para><strong>Method Variants:</strong></para>
/// <para>
/// Each operation has two variants: a production API that returns only what is needed for the next step,
/// and a "Verbose" variant that returns additional intermediate values for testing and debugging.
/// The Verbose variants are useful for W3C test vector validation where each intermediate computation
/// must be verified against specification examples.
/// </para>
/// <list type="bullet">
/// <item><description><see cref="CreateBaseProofAsync"/> / <see cref="CreateBaseProofVerboseAsync"/> - Issuer creates base proof.</description></item>
/// <item><description><see cref="VerifyBaseProofAsync"/> / <see cref="VerifyBaseProofVerboseAsync"/> - Holder verifies base proof.</description></item>
/// <item><description><see cref="DeriveProofAsync"/> / <see cref="DeriveProofVerboseAsync"/> - Holder creates derived proof with reduced credential.</description></item>
/// <item><description><see cref="VerifyDerivedProofAsync"/> / <see cref="VerifyDerivedProofVerboseAsync"/> - Verifier verifies derived proof.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/">VC Data Integrity ECDSA Cryptosuites v1.0</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
public static class CredentialEcdsaSd2023Extensions
{
    extension(VerifiableCredential credential)
    {
        /// <summary>
        /// Creates an ecdsa-sd-2023 base proof for the credential.
        /// </summary>
        /// <param name="issuerPrivateKey">The issuer's private key for the base signature.</param>
        /// <param name="ephemeralKeyPair">The ephemeral key pair for statement signatures.</param>
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
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new credential instance with the base proof attached.</returns>
        /// <remarks>
        /// <para>
        /// This is the production API for issuers. For testing with W3C test vectors,
        /// use <see cref="CreateBaseProofVerboseAsync"/> which returns intermediate values.
        /// </para>
        /// <para>
        /// For production use, pass <c>() => RandomNumberGenerator.GetBytes(32)</c> as
        /// the <paramref name="generateHmacKey"/> delegate.
        /// </para>
        /// </remarks>
        public async ValueTask<VerifiableCredential> CreateBaseProofAsync(
            PrivateKeyMemory issuerPrivateKey,
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKeyPair,
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
            SerializeBaseProofDelegate serializeBaseProof,
            EncodeDelegate encoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            using var result = await credential.CreateBaseProofVerboseAsync(
                issuerPrivateKey,
                ephemeralKeyPair,
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
                encoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            var signedCredential = deserialize(serialize(credential));
            signedCredential.Proof =
            [
                new DataIntegrityProof
                {
                    Type = CredentialConstants.DataIntegrityProofType,
                    Cryptosuite = EcdsaSd2023CryptosuiteInfo.Instance,
                    Created = DateTimeStampFormat.Format(proofCreated),
                    VerificationMethod = new AssertionMethod(verificationMethodId),
                    ProofPurpose = AssertionMethod.Purpose,
                    ProofValue = result.ProofValue
                }
            ];

            return signedCredential;
        }


        /// <summary>
        /// Creates an ecdsa-sd-2023 base proof for the credential, returning complete intermediate state.
        /// </summary>
        /// <param name="issuerPrivateKey">The issuer's private key for the base signature.</param>
        /// <param name="ephemeralKeyPair">The ephemeral key pair for statement signatures.</param>
        /// <param name="verificationMethodId">The DID URL identifying the verification method.</param>
        /// <param name="proofCreated">The timestamp for the proof's created field.</param>
        /// <param name="mandatoryPaths">Paths to claims that must always be disclosed.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements into mandatory and non-mandatory sets.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="serializeBaseProof">Delegate to serialize the base proof value.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Complete intermediate state including all values for W3C test vector validation.</returns>
        /// <remarks>
        /// <para>
        /// This method exposes all intermediate values for W3C test vector validation and debugging.
        /// For production usage, prefer <see cref="CreateBaseProofAsync"/> which discards intermediates.
        /// </para>
        /// </remarks>
        /// <summary>
        /// Creates an ecdsa-sd-2023 base proof for the credential, returning complete intermediate state.
        /// </summary>
        /// <param name="issuerPrivateKey">The issuer's private key for the base signature.</param>
        /// <param name="ephemeralKeyPair">The ephemeral key pair for statement signatures.</param>
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
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Complete intermediate state including all values for W3C test vector validation.</returns>
        /// <remarks>
        /// <para>
        /// This method exposes all intermediate values for W3C test vector validation and debugging.
        /// For production usage, prefer <see cref="CreateBaseProofAsync"/> which discards intermediates.
        /// </para>
        /// <para>
        /// The <paramref name="generateHmacKey"/> delegate allows callers to provide deterministic
        /// keys for test vector validation or cryptographically random keys for production use.
        /// For production, use <c>() => RandomNumberGenerator.GetBytes(32)</c>.
        /// </para>
        /// </remarks>
        public async ValueTask<BaseProofResult> CreateBaseProofVerboseAsync(
            PrivateKeyMemory issuerPrivateKey,
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKeyPair,
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
            SerializeBaseProofDelegate serializeBaseProof,
            EncodeDelegate encoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerPrivateKey);
            ArgumentNullException.ThrowIfNull(ephemeralKeyPair);
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
            ArgumentNullException.ThrowIfNull(mandatoryPaths);
            ArgumentNullException.ThrowIfNull(generateHmacKey);
            ArgumentNullException.ThrowIfNull(partitionStatements);
            ArgumentNullException.ThrowIfNull(canonicalize);
            ArgumentNullException.ThrowIfNull(serialize);
            ArgumentNullException.ThrowIfNull(deserialize);
            ArgumentNullException.ThrowIfNull(serializeProofOptions);
            ArgumentNullException.ThrowIfNull(serializeBaseProof);
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            cancellationToken.ThrowIfCancellationRequested();

            var proofCreatedString = DateTimeStampFormat.Format(proofCreated);
            var credentialJson = serialize(credential);

            var proofOptionsJson = serializeProofOptions(
                CredentialConstants.DataIntegrityProofType,
                CredentialConstants.Cryptosuites.EcdsaSd2023,
                proofCreatedString,
                verificationMethodId,
                AssertionMethod.Purpose,
                credential.Context);

            //Convert CredentialPath to JsonPointer for partitioning.
            var mandatoryPointers = mandatoryPaths
                .Where(p => p.IsJsonPath)
                .Select(p => p.JsonPointer)
                .ToList();

            var partition = await partitionStatements(credentialJson, mandatoryPointers, canonicalize, contextResolver, cancellationToken).ConfigureAwait(false);
            var canonicalStatements = partition.AllStatements.ToList();

            //Generate HMAC key using the provided delegate.
            var hmacKey = generateHmacKey();

            var prepared = NQuadStatementPreparation.Prepare(
                partition.AllStatements,
                partition.MandatoryIndexes,
                hmacKey,
                HMACSHA256.HashData,
                encoder);

            var sortedMandatoryStatements = prepared.MandatoryIndexes
                .OrderBy(i => i)
                .Select(idx => prepared.SortedStatements[idx])
                .ToList();

            var mandatoryHash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("", sortedMandatoryStatements)));

            var ephemeralPublicKeyWithHeader = MultibaseSerializer.PrependHeader(
                ephemeralKeyPair.PublicKey,
                memoryPool);

            var canonicalProofOptions = await canonicalize(proofOptionsJson, contextResolver, cancellationToken).ConfigureAwait(false);
            var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));

            int signatureDataLength = proofOptionsHash.Length + ephemeralPublicKeyWithHeader.Memory.Length + mandatoryHash.Length;
            var baseSignatureData = memoryPool.Rent(signatureDataLength);
            var signatureDataSpan = baseSignatureData.Memory.Span;
            proofOptionsHash.CopyTo(signatureDataSpan);
            ephemeralPublicKeyWithHeader.Memory.Span.CopyTo(signatureDataSpan[proofOptionsHash.Length..]);
            mandatoryHash.CopyTo(signatureDataSpan[(proofOptionsHash.Length + ephemeralPublicKeyWithHeader.Memory.Length)..]);

            cancellationToken.ThrowIfCancellationRequested();

            var baseSignature = await issuerPrivateKey.SignAsync(
                baseSignatureData.Memory[..signatureDataLength],
                memoryPool).ConfigureAwait(false);

            //Sign non-mandatory statements.
            var sortedNonMandatoryIndexes = prepared.NonMandatoryIndexes.OrderBy(i => i).ToList();
            var sortedNonMandatoryStatements = sortedNonMandatoryIndexes
                .Select(idx => prepared.SortedStatements[idx])
                .ToList();

            var signedStatements = await SignStatementsAsync(
                sortedNonMandatoryStatements,
                sortedNonMandatoryIndexes,
                ephemeralKeyPair.PrivateKey,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            var signatureBytes = baseSignature.AsReadOnlySpan().ToArray();
            var statementSignatures = signedStatements
                .Select(s => s.Signature.AsReadOnlySpan().ToArray())
                .ToList();
            var mandatoryPointerStrings = mandatoryPaths
                .Where(p => p.IsJsonPath)
                .Select(p => p.ToJsonPointerString())
                .ToList();

            var proofValue = serializeBaseProof(
                signatureBytes,
                ephemeralPublicKeyWithHeader.Memory.Span,
                hmacKey,
                statementSignatures,
                mandatoryPointerStrings,
                encoder);

            return new BaseProofResult(
                canonicalProofOptions,
                proofValue,
                canonicalStatements,
                prepared.SortedStatements.ToList(),
                prepared.LabelMap,
                prepared.MandatoryIndexes.OrderBy(i => i).ToList(),
                prepared.NonMandatoryIndexes.OrderBy(i => i).ToList(),
                mandatoryHash,
                proofOptionsHash,
                hmacKey,
                ephemeralPublicKeyWithHeader,
                baseSignature,
                signedStatements,
                baseSignatureData,
                signatureDataLength);
        }


        /// <summary>
        /// Verifies the base proof on a credential.
        /// </summary>
        /// <param name="issuerPublicKey">The issuer's public key for verifying the base signature.</param>
        /// <param name="verificationDelegate">The verification delegate for the issuer's key.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements into mandatory and non-mandatory sets.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result.</returns>
        /// <remarks>
        /// <para>
        /// This method verifies the issuer's signature on the base proof. After successful verification,
        /// the holder can store the credential and later use <see cref="DeriveProofAsync"/> to create
        /// derived proofs for presentation.
        /// </para>
        /// </remarks>
        public async ValueTask<CredentialVerificationResult> VerifyBaseProofAsync(
            PublicKeyMemory issuerPublicKey,
            VerificationDelegate verificationDelegate,
            ParseBaseProofDelegate parseBaseProof,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            var (result, context) = await credential.VerifyBaseProofVerboseAsync(
                issuerPublicKey,
                verificationDelegate,
                parseBaseProof,
                partitionStatements,
                canonicalize,
                contextResolver,
                serialize,
                serializeProofOptions,
                encoder,
                decoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }


        /// <summary>
        /// Verifies the base proof on a credential, returning complete intermediate state.
        /// </summary>
        /// <param name="issuerPublicKey">The issuer's public key for verifying the base signature.</param>
        /// <param name="verificationDelegate">The verification delegate for the issuer's key.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements into mandatory and non-mandatory sets.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A tuple containing the verification result and, if successful, the holder context
        /// with all intermediate values for W3C test vector validation.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method exposes all intermediate values for W3C test vector validation and debugging.
        /// For production usage, prefer <see cref="VerifyBaseProofAsync"/> which discards intermediates.
        /// </para>
        /// </remarks>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the signatures.")]
        public async ValueTask<(CredentialVerificationResult Result, HolderProofContext? Context)> VerifyBaseProofVerboseAsync(
            PublicKeyMemory issuerPublicKey,
            VerificationDelegate verificationDelegate,
            ParseBaseProofDelegate parseBaseProof,
            PartitionStatementsDelegate partitionStatements,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerPublicKey);
            ArgumentNullException.ThrowIfNull(verificationDelegate);
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

            if(proof.Cryptosuite?.CryptosuiteName != CredentialConstants.Cryptosuites.EcdsaSd2023)
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

            var partition = await partitionStatements(credentialJson, parsedProof.MandatoryPointers.ToList(), canonicalize, contextResolver, cancellationToken).ConfigureAwait(false);
            var canonicalStatements = partition.AllStatements.ToList();

            var prepared = NQuadStatementPreparation.Prepare(
                partition.AllStatements,
                partition.MandatoryIndexes,
                parsedProof.HmacKey,
                HMACSHA256.HashData,
                encoder);

            var sortedMandatoryStatements = prepared.MandatoryIndexes
                .OrderBy(i => i)
                .Select(idx => prepared.SortedStatements[idx])
                .ToList();

            var mandatoryHash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("", sortedMandatoryStatements)));

            var proofOptionsJson = serializeProofOptions(
                proof.Type ?? CredentialConstants.DataIntegrityProofType,
                CredentialConstants.Cryptosuites.EcdsaSd2023,
                proof.Created ?? "",
                proof.VerificationMethod?.Id ?? "",
                proof.ProofPurpose ?? AssertionMethod.Purpose,
                credential.Context);

            var canonicalProofOptions = await canonicalize(proofOptionsJson, contextResolver, cancellationToken).ConfigureAwait(false);
            var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));

            using var ephemeralKeyWithHeader = MultibaseSerializer.PrependHeader(
                parsedProof.EphemeralPublicKey,
                memoryPool);

            int signatureDataLength = proofOptionsHash.Length + ephemeralKeyWithHeader.Memory.Length + mandatoryHash.Length;
            var baseSignatureData = memoryPool.Rent(signatureDataLength);
            var signatureDataSpan = baseSignatureData.Memory.Span;
            proofOptionsHash.CopyTo(signatureDataSpan);
            ephemeralKeyWithHeader.Memory.Span.CopyTo(signatureDataSpan[proofOptionsHash.Length..]);
            mandatoryHash.CopyTo(signatureDataSpan[(proofOptionsHash.Length + ephemeralKeyWithHeader.Memory.Length)..]);

            cancellationToken.ThrowIfCancellationRequested();

            var isValid = await issuerPublicKey.VerifyAsync(
                baseSignatureData.Memory[..signatureDataLength],
                parsedProof.BaseSignature,
                verificationDelegate).ConfigureAwait(false);

            if(!isValid)
            {
                baseSignatureData.Dispose();
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            //Build signed statements from parsed proof.
            var sortedNonMandatoryIndexes = prepared.NonMandatoryIndexes.OrderBy(i => i).ToList();
            var signedStatements = new List<NQuadSignedStatement>();

            for(int i = 0; i < parsedProof.Signatures.Count && i < sortedNonMandatoryIndexes.Count; i++)
            {
                var statementIndex = sortedNonMandatoryIndexes[i];
                var statement = prepared.SortedStatements[statementIndex];
                var signature = parsedProof.Signatures[i];

                var sigBytes = signature.AsReadOnlySpan().ToArray();
                var sigMemory = memoryPool.Rent(sigBytes.Length);
                sigBytes.CopyTo(sigMemory.Memory.Span);
                var ownedSignature = new Signature(sigMemory, signature.Tag);

                signedStatements.Add(new NQuadSignedStatement(statement, ownedSignature, statementIndex));
            }

            //Store key with header for HolderProofContext.
            var ephemeralKeyMemory = memoryPool.Rent(ephemeralKeyWithHeader.Memory.Length);
            ephemeralKeyWithHeader.Memory.Span.CopyTo(ephemeralKeyMemory.Memory.Span);

            var baseSignatureBytes = parsedProof.BaseSignature.AsReadOnlySpan().ToArray();
            var baseSignatureMemory = memoryPool.Rent(baseSignatureBytes.Length);
            baseSignatureBytes.CopyTo(baseSignatureMemory.Memory.Span);
            var baseSignature = new Signature(baseSignatureMemory, parsedProof.BaseSignature.Tag);

            var context = new HolderProofContext(
                canonicalStatements,
                prepared.SortedStatements.ToList(),
                prepared.LabelMap.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                prepared.MandatoryIndexes.OrderBy(i => i).ToList(),
                signedStatements,
                baseSignature,
                baseSignatureData,
                signatureDataLength,
                ephemeralKeyMemory,
                parsedProof.HmacKey,
                proofOptionsHash,
                mandatoryHash);

            return (CredentialVerificationResult.Success(), context);
        }


        /// <summary>
        /// Creates an ecdsa-sd-2023 derived proof from a credential with a base proof.
        /// </summary>
        /// <param name="verifierRequestedPaths">Paths to claims the verifier has requested.</param>
        /// <param name="userExclusions">Paths to claims the user wants to exclude, or null.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="selectFragments">Delegate for selecting JSON-LD fragments to create reduced credential.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="serializeDerivedProof">Delegate to serialize the derived proof value.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A new credential instance with only disclosed claims and the derived proof attached.</returns>
        /// <remarks>
        /// <para>
        /// This method parses the base proof from the stored credential, applies disclosure selection
        /// based on verifier request and user preferences, creates a reduced credential containing
        /// only the disclosed claims, and attaches a derived proof.
        /// </para>
        /// <para>
        /// The disclosure selection uses lattice operations to compute the optimal disclosure:
        /// the minimum set that satisfies verifier requirements while respecting user exclusions.
        /// Mandatory claims (specified at issuance) are always included.
        /// </para>
        /// </remarks>
        public async ValueTask<VerifiableCredential> DeriveProofAsync(
            IReadOnlySet<CredentialPath> verifierRequestedPaths,
            IReadOnlySet<CredentialPath>? userExclusions,
            PartitionStatementsDelegate partitionStatements,
            SelectJsonLdFragmentsDelegate selectFragments,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ParseBaseProofDelegate parseBaseProof,
            SerializeDerivedProofDelegate serializeDerivedProof,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            var (derivedCredential, _) = await credential.DeriveProofVerboseAsync(
                verifierRequestedPaths,
                userExclusions,
                partitionStatements,
                selectFragments,
                canonicalize,
                contextResolver,
                serialize,
                deserialize,
                parseBaseProof,
                serializeDerivedProof,
                encoder,
                decoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            return derivedCredential;
        }


        /// <summary>
        /// Creates an ecdsa-sd-2023 derived proof from a credential with a base proof,
        /// returning complete intermediate state.
        /// </summary>
        /// <param name="verifierRequestedPaths">Paths to claims the verifier has requested.</param>
        /// <param name="userExclusions">Paths to claims the user wants to exclude, or null.</param>
        /// <param name="partitionStatements">Delegate for partitioning statements.</param>
        /// <param name="selectFragments">Delegate for selecting JSON-LD fragments to create reduced credential.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="parseBaseProof">Delegate to parse the base proof value.</param>
        /// <param name="serializeDerivedProof">Delegate to serialize the derived proof value.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A tuple containing the derived credential and the disclosure selection result
        /// for W3C test vector validation.
        /// </returns>
        public async ValueTask<(VerifiableCredential DerivedCredential, DisclosureSelectionResult<int> SelectionResult)> DeriveProofVerboseAsync(
            IReadOnlySet<CredentialPath> verifierRequestedPaths,
            IReadOnlySet<CredentialPath>? userExclusions,
            PartitionStatementsDelegate partitionStatements,
            SelectJsonLdFragmentsDelegate selectFragments,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ParseBaseProofDelegate parseBaseProof,
            SerializeDerivedProofDelegate serializeDerivedProof,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
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
            ArgumentNullException.ThrowIfNull(encoder);
            ArgumentNullException.ThrowIfNull(decoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            var proof = credential.Proof?.FirstOrDefault() ?? throw new InvalidOperationException("Credential must have a proof to derive from.");

            if(proof.Cryptosuite?.CryptosuiteName != CredentialConstants.Cryptosuites.EcdsaSd2023)
            {
                throw new InvalidOperationException($"Expected cryptosuite '{CredentialConstants.Cryptosuites.EcdsaSd2023}' but found '{proof.Cryptosuite?.CryptosuiteName}'.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            using var parsedProof = parseBaseProof(proof.ProofValue!, decoder, memoryPool);

            var credentialWithoutProof = CloneCredentialWithoutProof(credential);
            var fullCredentialJson = serialize(credentialWithoutProof);

            //Prepare full credential statements to determine which signatures to include.
            var fullPartition = await partitionStatements(fullCredentialJson, parsedProof.MandatoryPointers.ToList(), canonicalize, contextResolver, cancellationToken).ConfigureAwait(false);

            var fullPrepared = NQuadStatementPreparation.Prepare(
                fullPartition.AllStatements,
                fullPartition.MandatoryIndexes,
                parsedProof.HmacKey,
                HMACSHA256.HashData,
                encoder);

            //Map verifier requested paths to JSON pointers.
            var requestedPointers = verifierRequestedPaths
                .Where(p => p.IsJsonPath)
                .Select(p => p.JsonPointer)
                .ToList();

            //Map verifier requested paths to statement indexes in the full credential.
            var requestedPartition = await partitionStatements(fullCredentialJson, requestedPointers, canonicalize, contextResolver, cancellationToken).ConfigureAwait(false);
            var requestedPrepared = NQuadStatementPreparation.Prepare(
                requestedPartition.AllStatements,
                requestedPartition.MandatoryIndexes,
                parsedProof.HmacKey,
                HMACSHA256.HashData,
                encoder);
            var requestedIndexes = requestedPrepared.MandatoryIndexes;

            //Map user exclusions to statement indexes if provided.
            IReadOnlySet<int>? excludedIndexes = null;
            if(userExclusions is { Count: > 0 })
            {
                var excludedPointers = userExclusions
                    .Where(p => p.IsJsonPath)
                    .Select(p => p.JsonPointer)
                    .ToList();

                var excludedPartition = await partitionStatements(fullCredentialJson, excludedPointers, canonicalize, contextResolver, cancellationToken).ConfigureAwait(false);
                var excludedPrepared = NQuadStatementPreparation.Prepare(
                    excludedPartition.AllStatements,
                    excludedPartition.MandatoryIndexes,
                    parsedProof.HmacKey,
                    HMACSHA256.HashData,
                    encoder);

                excludedIndexes = excludedPrepared.MandatoryIndexes;
            }

            //Apply lattice-based disclosure selection.
            //The lattice operates on non-mandatory statement indexes only.
            //SelectiveDisclosure.ComputeOptimalDisclosure normalizes the request internally,
            //so if requestedIndexes contains mandatory indexes, they're handled correctly.
            var lattice = new SetDisclosureLattice<int>(
                allClaims: fullPrepared.NonMandatoryIndexes,
                mandatoryClaims: []);

            var selectionResult = SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(
                lattice,
                verifierRequested: requestedIndexes,
                userExclusions: excludedIndexes);

            //Combine mandatory pointers with requested paths for reduced credential.
            var disclosedPointers = parsedProof.MandatoryPointers.ToList();
            disclosedPointers.AddRange(requestedPointers);

            //Create reduced credential JSON containing only disclosed claims.
            var reducedCredentialJson = selectFragments(fullCredentialJson, disclosedPointers);

            //Canonicalize reduced credential to get statements verifier will see.
            var reducedPartition = await partitionStatements(reducedCredentialJson, [], canonicalize, contextResolver, cancellationToken).ConfigureAwait(false);

            //Compute the correct label map for the reduced credential.
            //The reduced credential has different canonical blank node assignments than the full credential
            //(RDFC canonicalization assigns c14n IDs based on graph structure, which changes when statements are removed).
            var reducedLabelMap = ComputeReducedLabelMap(
                reducedPartition.AllStatements,
                fullPrepared.SortedStatements,
                fullPrepared.LabelMap);

            //Prepare the reduced credential statements with the computed label map.
            var reducedPrepared = NQuadStatementPreparation.PrepareWithLabelMap(
                reducedPartition.AllStatements,
                [],
                reducedLabelMap);

            //Build a map from statement content to signature for the full credential's
            //NON-MANDATORY statements only. Mandatory statements have no signatures.
            var fullSortedNonMandatoryIndexes = fullPrepared.NonMandatoryIndexes.OrderBy(i => i).ToList();
            var statementToSignature = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            for(int i = 0; i < fullSortedNonMandatoryIndexes.Count && i < parsedProof.Signatures.Count; i++)
            {
                var statementIdx = fullSortedNonMandatoryIndexes[i];
                var statement = fullPrepared.SortedStatements[statementIdx];
                statementToSignature[statement] = parsedProof.Signatures[i].AsReadOnlySpan().ToArray();
            }

            //Determine mandatory indexes and collect signatures for the reduced credential.
            //A statement is mandatory in the derived proof if it was mandatory in the full
            //credential (i.e., it has no signature in statementToSignature).
            //Per W3C spec Section 3.5.4 createDisclosureData, the mandatoryIndexes in the
            //derived proof are the relative indexes (within the revealed sorted statements)
            //of statements that were mandatory in the full credential.
            var derivedMandatoryIndexes = new List<int>();
            var selectedSignatures = new List<byte[]>();

            for(int reducedIdx = 0; reducedIdx < reducedPrepared.SortedStatements.Count; reducedIdx++)
            {
                var statement = reducedPrepared.SortedStatements[reducedIdx];

                if(statementToSignature.TryGetValue(statement, out var signature))
                {
                    //This statement was non-mandatory in the full credential and has a signature.
                    selectedSignatures.Add(signature);
                }
                else
                {
                    //This statement was mandatory in the full credential (no signature exists).
                    //It must remain mandatory in the derived proof.
                    derivedMandatoryIndexes.Add(reducedIdx);
                }
            }

            using var ephemeralKeyWithHeader = MultibaseSerializer.PrependHeader(
                parsedProof.EphemeralPublicKey,
                memoryPool);

            //Serialize the derived proof with the correctly computed mandatory indexes.
            var derivedProofValue = serializeDerivedProof(
                parsedProof.BaseSignature.AsReadOnlySpan().ToArray(),
                ephemeralKeyWithHeader.Memory.Span,
                selectedSignatures,
                reducedLabelMap,
                derivedMandatoryIndexes,
                encoder,
                decoder,
                memoryPool);

            //Parse reduced credential JSON back to object.
            var derivedCredential = deserialize(reducedCredentialJson);
            derivedCredential.Proof =
            [
                new DataIntegrityProof
                {
                    Type = proof.Type,
                    Cryptosuite = proof.Cryptosuite,
                    Created = proof.Created,
                    VerificationMethod = proof.VerificationMethod,
                    ProofPurpose = proof.ProofPurpose,
                    ProofValue = derivedProofValue
                }
            ];

            return (derivedCredential, selectionResult);
        }


        /// <summary>
        /// Verifies an ecdsa-sd-2023 derived proof on the credential.
        /// </summary>
        /// <param name="issuerPublicKey">The issuer's public key for verifying the base signature.</param>
        /// <param name="verificationDelegate">The verification delegate for the issuer's key.</param>
        /// <param name="parseDerivedProof">Delegate to parse the derived proof value.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result.</returns>
        public async ValueTask<CredentialVerificationResult> VerifyDerivedProofAsync(
            PublicKeyMemory issuerPublicKey,
            VerificationDelegate verificationDelegate,
            ParseDerivedProofDelegate parseDerivedProof,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            var (result, context) = await credential.VerifyDerivedProofVerboseAsync(
                issuerPublicKey,
                verificationDelegate,
                parseDerivedProof,
                canonicalize,
                contextResolver,
                serialize,
                serializeProofOptions,
                encoder,
                decoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }


        /// <summary>
        /// Verifies an ecdsa-sd-2023 derived proof on the credential, returning complete intermediate state.
        /// </summary>
        /// <param name="issuerPublicKey">The issuer's public key for verifying the base signature.</param>
        /// <param name="verificationDelegate">The verification delegate for the issuer's key.</param>
        /// <param name="parseDerivedProof">Delegate to parse the derived proof value.</param>
        /// <param name="canonicalize">Canonicalization function for JSON-LD to N-Quads.</param>
        /// <param name="contextResolver">Delegate for resolving JSON-LD contexts.</param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">Base64URL encoder.</param>
        /// <param name="decoder">Base64URL decoder.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A tuple containing the verification result and, if successful, the verifier context
        /// with all intermediate values for W3C test vector validation.
        /// </returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>")]
        public async ValueTask<(CredentialVerificationResult Result, VerifierProofContext? Context)> VerifyDerivedProofVerboseAsync(
            PublicKeyMemory issuerPublicKey,
            VerificationDelegate verificationDelegate,
            ParseDerivedProofDelegate parseDerivedProof,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            CredentialSerializeDelegate serialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            DecodeDelegate decoder,
            MemoryPool<byte> memoryPool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerPublicKey);
            ArgumentNullException.ThrowIfNull(verificationDelegate);
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

            if(proof.Cryptosuite?.CryptosuiteName != CredentialConstants.Cryptosuites.EcdsaSd2023)
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.MissingCryptosuite), null);
            }

            if(string.IsNullOrEmpty(proof.ProofValue))
            {
                return (CredentialVerificationResult.Failed(VerificationFailureReason.NoProof), null);
            }

            cancellationToken.ThrowIfCancellationRequested();

            using var parsedProof = parseDerivedProof(proof.ProofValue, decoder, encoder, memoryPool);

            var credentialWithoutProof = CloneCredentialWithoutProof(credential);
            var credentialJson = serialize(credentialWithoutProof);

            var canonicalNQuads = await canonicalize(credentialJson, contextResolver, cancellationToken).ConfigureAwait(false);
            var canonicalStatements = SplitIntoStatements(canonicalNQuads);

            var relabeledStatements = BlankNodeRelabelingExtensions.ApplyLabelMap(
                canonicalStatements,
                parsedProof.LabelMap);

            var sortedStatements = relabeledStatements
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();

            var mandatoryStatements = parsedProof.MandatoryIndexes
                .Select(idx => sortedStatements[idx])
                .ToList();

            var mandatoryHash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("", mandatoryStatements)));

            var proofOptionsJson = serializeProofOptions(
                proof.Type ?? CredentialConstants.DataIntegrityProofType,
                CredentialConstants.Cryptosuites.EcdsaSd2023,
                proof.Created ?? "",
                proof.VerificationMethod?.Id ?? "",
                proof.ProofPurpose ?? AssertionMethod.Purpose,
                credential.Context);

            var canonicalProofOptions = await canonicalize(proofOptionsJson, contextResolver, cancellationToken).ConfigureAwait(false);
            var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));

            using var ephemeralKeyWithHeader = MultibaseSerializer.PrependHeader(
                parsedProof.EphemeralPublicKey,
                memoryPool);

            int signatureDataLength = proofOptionsHash.Length + ephemeralKeyWithHeader.Memory.Length + mandatoryHash.Length;
            var baseSignatureData = memoryPool.Rent(signatureDataLength);
            var signatureDataSpan = baseSignatureData.Memory.Span;
            proofOptionsHash.CopyTo(signatureDataSpan);
            ephemeralKeyWithHeader.Memory.Span.CopyTo(signatureDataSpan[proofOptionsHash.Length..]);
            mandatoryHash.CopyTo(signatureDataSpan[(proofOptionsHash.Length + ephemeralKeyWithHeader.Memory.Length)..]);

            cancellationToken.ThrowIfCancellationRequested();

            var baseSignatureValid = await issuerPublicKey.VerifyAsync(
                baseSignatureData.Memory[..signatureDataLength],
                parsedProof.BaseSignature,
                verificationDelegate).ConfigureAwait(false);

            if(!baseSignatureValid)
            {
                baseSignatureData.Dispose();
                return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
            }

            //Verify disclosed statement signatures.
            var rawKeyBytes = parsedProof.EphemeralPublicKey.AsReadOnlySpan();
            var ephemeralKeyMemory = memoryPool.Rent(rawKeyBytes.Length);
            rawKeyBytes.CopyTo(ephemeralKeyMemory.Memory.Span);
            var ephemeralPublicKey = new PublicKeyMemory(ephemeralKeyMemory, CryptoTags.P256PublicKey);

            var nonMandatoryIndexes = Enumerable.Range(0, sortedStatements.Count)
                .Where(i => !parsedProof.MandatoryIndexes.Contains(i))
                .ToList();

            var disclosedStatements = new List<NQuadSignedStatement>();
            for(int i = 0; i < parsedProof.Signatures.Count && i < nonMandatoryIndexes.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var statementIndex = nonMandatoryIndexes[i];
                var statement = sortedStatements[statementIndex];
                var signature = parsedProof.Signatures[i];

                var statementBytes = Encoding.UTF8.GetBytes(statement);
                var sigValid = await ephemeralPublicKey.VerifyAsync(
                    statementBytes,
                    signature,
                    verificationDelegate).ConfigureAwait(false);

                if(!sigValid)
                {
                    baseSignatureData.Dispose();
                    ephemeralPublicKey.Dispose();
                    return (CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), null);
                }

                var sigBytes = signature.AsReadOnlySpan().ToArray();
                var sigMemory = memoryPool.Rent(sigBytes.Length);
                sigBytes.CopyTo(sigMemory.Memory.Span);
                var ownedSignature = new Signature(sigMemory, signature.Tag);

                disclosedStatements.Add(new NQuadSignedStatement(statement, ownedSignature, statementIndex));
            }

            var baseSignatureBytes = parsedProof.BaseSignature.AsReadOnlySpan().ToArray();
            var baseSignatureMemory = memoryPool.Rent(baseSignatureBytes.Length);
            baseSignatureBytes.CopyTo(baseSignatureMemory.Memory.Span);
            var baseSignature = new Signature(baseSignatureMemory, parsedProof.BaseSignature.Tag);

            var context = new VerifierProofContext(
                baseSignature,
                baseSignatureData,
                signatureDataLength,
                ephemeralPublicKey,
                disclosedStatements,
                parsedProof.LabelMap.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                parsedProof.MandatoryIndexes.ToList());

            return (CredentialVerificationResult.Success(), context);
        }
    }


    private static async ValueTask<List<NQuadSignedStatement>> SignStatementsAsync(
        IReadOnlyList<string> statements,
        IReadOnlyList<int> statementIndexes,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        var signedStatements = new List<NQuadSignedStatement>(statements.Count);

        for(int i = 0; i < statements.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var statement = statements[i];
            var signature = await privateKey.SignAsync(
                Encoding.UTF8.GetBytes(statement),
                pool).ConfigureAwait(false);

            signedStatements.Add(new NQuadSignedStatement(statement, signature, statementIndexes[i]));
        }

        return signedStatements;
    }


    private static string[] SplitIntoStatements(string nquads)
    {
        var lines = nquads.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return lines.Select(line => line + "\n").ToArray();
    }


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
            AdditionalData = credential.AdditionalData,
            Proof = null
        };
    }


    /// <summary>
    /// Computes the correct label map for a reduced credential by matching statement content.
    /// </summary>
    /// <param name="reducedCanonicalStatements">Canonical statements from the reduced credential.</param>
    /// <param name="fullHmacSortedStatements">HMAC-relabeled and sorted statements from the full credential.</param>
    /// <param name="fullLabelMap">Label map from the full credential (canonical ID to HMAC label).</param>
    /// <returns>
    /// A label map that correctly maps the reduced credential's canonical IDs to HMAC labels.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The reduced credential, when canonicalized, may assign different canonical IDs (c14n0, c14n1, etc.)
    /// to blank nodes than the full credential did. This is because RDFC-1.0 canonicalization assigns
    /// identifiers based on the graph structure, which changes when statements are removed.
    /// </para>
    /// <para>
    /// This method determines the correct mapping by finding statements in the reduced credential
    /// that have non-blank-node content matching statements in the full credential, then extracting
    /// the HMAC label from the matched full statement.
    /// </para>
    /// </remarks>
    private static Dictionary<string, string> ComputeReducedLabelMap(
        IReadOnlyList<string> reducedCanonicalStatements,
        IReadOnlyList<string> fullHmacSortedStatements,
        IReadOnlyDictionary<string, string> fullLabelMap)
    {
        var reducedLabelMap = new Dictionary<string, string>(StringComparer.Ordinal);

        //Extract all HMAC labels from the full label map for quick lookup.
        var hmacLabels = new HashSet<string>(fullLabelMap.Values, StringComparer.Ordinal);

        //For each reduced canonical statement containing a blank node, find the matching
        //statement in the full HMAC-relabeled statements and extract the HMAC label.
        var blankNodePattern = new System.Text.RegularExpressions.Regex(
            @"_:(c14n\d+)",
            System.Text.RegularExpressions.RegexOptions.Compiled);

        foreach(var reducedStatement in reducedCanonicalStatements)
        {
            var matches = blankNodePattern.Matches(reducedStatement);
            if(matches.Count == 0)
            {
                continue;
            }

            //For each blank node in this statement, try to find its HMAC label.
            foreach(System.Text.RegularExpressions.Match match in matches)
            {
                var canonicalId = match.Groups[1].Value;
                if(reducedLabelMap.ContainsKey(canonicalId))
                {
                    continue;
                }

                //Try each possible HMAC label and see if replacing the canonical ID produces
                //a statement that exists in the full HMAC-relabeled statements.
                foreach(var hmacLabel in hmacLabels)
                {
                    if(reducedLabelMap.ContainsValue(hmacLabel))
                    {
                        //Already assigned to another canonical ID.
                        continue;
                    }

                    //Create test statement with this HMAC label.
                    var testStatement = reducedStatement.Replace(
                        $"_:{canonicalId}",
                        $"_:{hmacLabel}",
                        StringComparison.Ordinal);

                    //Also replace any already-mapped canonical IDs.
                    foreach(var (mappedCanonical, mappedHmac) in reducedLabelMap)
                    {
                        testStatement = testStatement.Replace(
                            $"_:{mappedCanonical}",
                            $"_:{mappedHmac}",
                            StringComparison.Ordinal);
                    }

                    //Check if this statement exists in the full HMAC statements.
                    if(fullHmacSortedStatements.Contains(testStatement))
                    {
                        reducedLabelMap[canonicalId] = hmacLabel;
                        break;
                    }
                }
            }
        }

        return reducedLabelMap;
    }
}