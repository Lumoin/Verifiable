using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Result of creating a bbs-2023 base proof, including all intermediate values.
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
/// <strong>Verifier:</strong> Parses the derived proof and verifies the BBS proof.
/// </description></item>
/// </list>
/// <para>
/// The intermediate values correspond to W3C VC DI BBS specification examples:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="CanonicalStatements"/> - Canonical N-Quads before relabeling.</description></item>
/// <item><description><see cref="RelabeledStatements"/> - HMAC-relabeled N-Quads.</description></item>
/// <item><description><see cref="LabelMap"/> - Blank node label map.</description></item>
/// <item><description><see cref="MandatoryIndexes"/> - Indexes of mandatory statements.</description></item>
/// <item><description><see cref="NonMandatoryIndexes"/> - Indexes of non-mandatory statements.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("BbsBaseProof: {ProofValue.Substring(0, Math.Min(20, ProofValue.Length))}..., Statements: {NonMandatoryStatements.Count}")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class BbsBaseProofResult: IDisposable
{
    /// <summary>
    /// The canonical N-Quad statements of the proof options.
    /// </summary>
    /// <remarks>
    /// These statements are hashed to produce <see cref="ProofHash"/>.
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
    /// These are the statements produced by RDFC-1.0 canonicalization with
    /// <c>_:c14nN</c> blank node identifiers.
    /// </remarks>
    public IReadOnlyList<string> CanonicalStatements { get; }

    /// <summary>
    /// The N-Quad statements after HMAC-based blank node relabeling, sorted.
    /// </summary>
    /// <remarks>
    /// Blank node identifiers are replaced with HMAC-derived identifiers
    /// (<c>_:b&lt;int&gt;</c>), then sorted.
    /// </remarks>
    public IReadOnlyList<string> RelabeledStatements { get; }

    /// <summary>
    /// The label map from canonical to HMAC-derived blank node identifiers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Maps <c>"c14n0"</c> to <c>"b&lt;int&gt;"</c> identifiers using bare format
    /// without the <c>"_:"</c> prefix.
    /// </para>
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
    public byte[] ProofHash { get; }

    /// <summary>
    /// The HMAC key used for blank node relabeling.
    /// </summary>
    /// <remarks>
    /// This is needed when creating derived proofs to compute the label map.
    /// </remarks>
    public byte[] HmacKey { get; }

    /// <summary>
    /// The BBS header bound into the signature.
    /// </summary>
    /// <remarks>
    /// This is 64 bytes formed as <c>ProofHash || MandatoryHash</c>.
    /// </remarks>
    public byte[] BbsHeader { get; }

    /// <summary>
    /// The issuer's BBS signature.
    /// </summary>
    /// <remarks>
    /// This is an 80-byte BBS signature.
    /// </remarks>
    public byte[] BbsSignature { get; }

    /// <summary>
    /// The sorted non-mandatory statements that became BBS messages.
    /// </summary>
    public IReadOnlyList<string> NonMandatoryStatements { get; }


    /// <summary>
    /// Creates a new base proof result with all intermediate values.
    /// </summary>
    /// <param name="canonicalProofOptions">Canonical N-Quads of the proof options.</param>
    /// <param name="proofValue">The multibase-encoded proof value.</param>
    /// <param name="canonicalStatements">Canonical N-Quads before relabeling.</param>
    /// <param name="relabeledStatements">N-Quads after HMAC relabeling.</param>
    /// <param name="labelMap">Blank node label map.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements.</param>
    /// <param name="nonMandatoryIndexes">Indexes of non-mandatory statements.</param>
    /// <param name="mandatoryHash">SHA-256 hash of mandatory statements.</param>
    /// <param name="proofHash">SHA-256 hash of proof options.</param>
    /// <param name="hmacKey">HMAC key for relabeling.</param>
    /// <param name="bbsHeader">BBS header formed as proof hash concatenated with mandatory hash.</param>
    /// <param name="bbsSignature">The issuer's BBS signature.</param>
    /// <param name="nonMandatoryStatements">Sorted non-mandatory statements that became BBS messages.</param>
    public BbsBaseProofResult(
        string canonicalProofOptions,
        string proofValue,
        IReadOnlyList<string> canonicalStatements,
        IReadOnlyList<string> relabeledStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> nonMandatoryIndexes,
        byte[] mandatoryHash,
        byte[] proofHash,
        byte[] hmacKey,
        byte[] bbsHeader,
        byte[] bbsSignature,
        IReadOnlyList<string> nonMandatoryStatements)
    {
        ArgumentNullException.ThrowIfNull(canonicalProofOptions);
        ArgumentNullException.ThrowIfNull(proofValue);
        ArgumentNullException.ThrowIfNull(canonicalStatements);
        ArgumentNullException.ThrowIfNull(relabeledStatements);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(nonMandatoryIndexes);
        ArgumentNullException.ThrowIfNull(mandatoryHash);
        ArgumentNullException.ThrowIfNull(proofHash);
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentNullException.ThrowIfNull(bbsHeader);
        ArgumentNullException.ThrowIfNull(bbsSignature);
        ArgumentNullException.ThrowIfNull(nonMandatoryStatements);

        CanonicalProofOptions = canonicalProofOptions;
        ProofValue = proofValue;
        CanonicalStatements = canonicalStatements;
        RelabeledStatements = relabeledStatements;
        LabelMap = labelMap;
        MandatoryIndexes = mandatoryIndexes;
        NonMandatoryIndexes = nonMandatoryIndexes;
        MandatoryHash = mandatoryHash;
        ProofHash = proofHash;
        HmacKey = hmacKey;
        BbsHeader = bbsHeader;
        BbsSignature = bbsSignature;
        NonMandatoryStatements = nonMandatoryStatements;
    }


    /// <summary>
    /// Disposes the owned resources.
    /// </summary>
    public void Dispose()
    {
    }
}
