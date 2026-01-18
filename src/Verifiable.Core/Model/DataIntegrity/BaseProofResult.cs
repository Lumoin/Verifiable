using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Result of creating an ecdsa-sd-2023 base proof, including all intermediate values.
/// </summary>
/// <remarks>
/// <para>
/// This type contains all intermediate values from the proof creation process,
/// enabling W3C test vector validation and debugging. For production use where
/// only the final credential is needed, use <c>CreateBaseProofAsync</c> instead
/// of <c>CreateBaseProofWithResultAsync</c>.
/// </para>
/// <para>
/// <strong>Lifecycle:</strong>
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Issuer:</strong> Creates the base proof and embeds <see cref="ProofValue"/> in the credential.
/// </description></item>
/// <item><description>
/// <strong>Holder:</strong> Parses the proof to extract components, selects disclosures,
/// creates derived proof.
/// </description></item>
/// <item><description>
/// <strong>Verifier:</strong> Parses the derived proof and verifies signatures.
/// </description></item>
/// </list>
/// <para>
/// The intermediate values correspond to W3C VC DI ECDSA specification examples:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="CanonicalStatements"/> - Example 75: Canonical N-Quads before relabeling.</description></item>
/// <item><description><see cref="RelabeledStatements"/> - Example 76: HMAC-relabeled N-Quads.</description></item>
/// <item><description><see cref="LabelMap"/> - Example 77: Blank node label map.</description></item>
/// <item><description><see cref="MandatoryIndexes"/> - Indexes of mandatory statements.</description></item>
/// <item><description><see cref="NonMandatoryIndexes"/> - Indexes of non-mandatory statements.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("BaseProof: {ProofValue.Substring(0, Math.Min(20, ProofValue.Length))}..., Statements: {SignedStatements.Count}")]
public sealed class BaseProofResult: IDisposable
{
    /// <summary>
    /// The canonical N-Quad statements of the proof options.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 79. These statements are hashed to produce
    /// <see cref="ProofOptionsHash"/>.
    /// </remarks>
    public string CanonicalProofOptions { get; }

    /// <summary>
    /// The multibase-encoded base proof value to embed in the credential.
    /// </summary>
    public string ProofValue { get; }

    /// <summary>
    /// The canonical N-Quad statements before HMAC relabeling.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 75. These are the statements produced by
    /// RDFC-1.0 canonicalization with <c>_:c14nN</c> blank node identifiers.
    /// </remarks>
    public IReadOnlyList<string> CanonicalStatements { get; }

    /// <summary>
    /// The N-Quad statements after HMAC-based blank node relabeling.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 76. Blank node identifiers are replaced
    /// with HMAC-derived pseudorandom identifiers (<c>_:uXXX</c>).
    /// </remarks>
    public IReadOnlyList<string> RelabeledStatements { get; }

    /// <summary>
    /// The label map from canonical to HMAC-derived blank node identifiers.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 77. Maps <c>c14nN</c> to <c>uXXX</c> identifiers.
    /// </remarks>
    public IReadOnlyDictionary<string, string> LabelMap { get; }

    /// <summary>
    /// The indexes of mandatory statements within the relabeled statements.
    /// </summary>
    public IReadOnlyList<int> MandatoryIndexes { get; }

    /// <summary>
    /// The indexes of non-mandatory statements within the relabeled statements.
    /// </summary>
    public IReadOnlyList<int> NonMandatoryIndexes { get; }

    /// <summary>
    /// The SHA-256 hash of the concatenated mandatory statements.
    /// </summary>
    public byte[] MandatoryHash { get; }

    /// <summary>
    /// The SHA-256 hash of the canonicalized proof options.
    /// </summary>
    public byte[] ProofOptionsHash { get; }

    /// <summary>
    /// The HMAC key used for blank node relabeling.
    /// </summary>
    /// <remarks>
    /// This is needed when creating derived proofs to compute the label map.
    /// </remarks>
    public byte[] HmacKey { get; }

    /// <summary>
    /// The ephemeral public key with multicodec header.
    /// </summary>
    public IMemoryOwner<byte> EphemeralPublicKeyWithHeader { get; }

    /// <summary>
    /// The issuer's base signature.
    /// </summary>
    public Signature BaseSignature { get; }

    /// <summary>
    /// The signed non-mandatory N-Quad statements.
    /// </summary>
    public IReadOnlyList<NQuadSignedStatement> SignedStatements { get; }

    /// <summary>
    /// The data that was signed to create the base signature.
    /// </summary>
    /// <remarks>
    /// This is <c>proofOptionsHash || ephemeralPublicKeyWithHeader || mandatoryHash</c>.
    /// Needed for verification.
    /// </remarks>
    public IMemoryOwner<byte> BaseSignatureData { get; }

    /// <summary>
    /// The length of valid data in <see cref="BaseSignatureData"/>.
    /// </summary>
    /// <remarks>
    /// The memory owner may have allocated more bytes than needed.
    /// Use this length when accessing the signature data.
    /// </remarks>
    public int BaseSignatureDataLength { get; }


    /// <summary>
    /// Creates a new base proof result with all intermediate values.
    /// </summary>
    /// <param name="proofValue">The multibase-encoded proof value.</param>
    /// <param name="canonicalStatements">Canonical N-Quads before relabeling.</param>
    /// <param name="relabeledStatements">N-Quads after HMAC relabeling.</param>
    /// <param name="labelMap">Blank node label map.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements.</param>
    /// <param name="nonMandatoryIndexes">Indexes of non-mandatory statements.</param>
    /// <param name="mandatoryHash">SHA-256 hash of mandatory statements.</param>
    /// <param name="proofOptionsHash">SHA-256 hash of proof options.</param>
    /// <param name="hmacKey">HMAC key for relabeling.</param>
    /// <param name="ephemeralPublicKeyWithHeader">Ephemeral public key with multicodec header.</param>
    /// <param name="baseSignature">The issuer's base signature.</param>
    /// <param name="signedStatements">Signed non-mandatory statements.</param>
    /// <param name="baseSignatureData">Data that was signed.</param>
    /// <param name="baseSignatureDataLength">Length of valid signature data.</param>
    public BaseProofResult(
        string canonicalProofOptions,
        string proofValue,
        IReadOnlyList<string> canonicalStatements,
        IReadOnlyList<string> relabeledStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> nonMandatoryIndexes,
        byte[] mandatoryHash,
        byte[] proofOptionsHash,
        byte[] hmacKey,
        IMemoryOwner<byte> ephemeralPublicKeyWithHeader,
        Signature baseSignature,
        IReadOnlyList<NQuadSignedStatement> signedStatements,
        IMemoryOwner<byte> baseSignatureData,
        int baseSignatureDataLength)
    {
        ArgumentNullException.ThrowIfNull(canonicalProofOptions);
        ArgumentNullException.ThrowIfNull(proofValue);
        ArgumentNullException.ThrowIfNull(canonicalStatements);
        ArgumentNullException.ThrowIfNull(relabeledStatements);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(nonMandatoryIndexes);
        ArgumentNullException.ThrowIfNull(mandatoryHash);
        ArgumentNullException.ThrowIfNull(proofOptionsHash);
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKeyWithHeader);
        ArgumentNullException.ThrowIfNull(baseSignature);
        ArgumentNullException.ThrowIfNull(signedStatements);
        ArgumentNullException.ThrowIfNull(baseSignatureData);

        CanonicalProofOptions = canonicalProofOptions;
        ProofValue = proofValue;        
        CanonicalStatements = canonicalStatements;
        RelabeledStatements = relabeledStatements;
        LabelMap = labelMap;
        MandatoryIndexes = mandatoryIndexes;
        NonMandatoryIndexes = nonMandatoryIndexes;
        MandatoryHash = mandatoryHash;
        ProofOptionsHash = proofOptionsHash;
        HmacKey = hmacKey;
        EphemeralPublicKeyWithHeader = ephemeralPublicKeyWithHeader;
        BaseSignature = baseSignature;
        SignedStatements = signedStatements;
        BaseSignatureData = baseSignatureData;
        BaseSignatureDataLength = baseSignatureDataLength;
    }


    /// <summary>
    /// Disposes the owned memory resources.
    /// </summary>
    public void Dispose()
    {
        EphemeralPublicKeyWithHeader.Dispose();
        BaseSignatureData.Dispose();
        BaseSignature.Dispose();

        foreach(var statement in SignedStatements)
        {
            statement.Signature.Dispose();
        }
    }
}