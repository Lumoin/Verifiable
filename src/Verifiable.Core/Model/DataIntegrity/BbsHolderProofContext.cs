using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Context containing parsed base proof components needed by the holder for selective disclosure.
/// </summary>
/// <remarks>
/// <para>
/// This type contains all the information the holder needs to:
/// </para>
/// <list type="bullet">
/// <item><description>Verify the base proof (if not already verified).</description></item>
/// <item><description>Select which claims to disclose.</description></item>
/// <item><description>Create derived proofs.</description></item>
/// </list>
/// <para>
/// The holder receives a signed credential from the issuer and must parse the embedded proof
/// to extract these components. The holder does not have access to the issuer's intermediate
/// computation state; everything must be reconstructed from the credential and proof value.
/// </para>
/// <para>
/// For W3C test vector validation, this type also exposes intermediate values like
/// <see cref="CanonicalStatements"/> and <see cref="RelabeledStatements"/> that correspond
/// to specification examples.
/// </para>
/// </remarks>
[DebuggerDisplay("BbsHolderContext: {NonMandatoryStatements.Count} statements, {LabelMap.Count} labels")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class BbsHolderProofContext: IDisposable
{
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
    /// Maps <c>c14nN</c> to <c>b&lt;int&gt;</c> identifiers.
    /// Needed for creating derived proofs.
    /// </remarks>
    public IReadOnlyDictionary<string, string> LabelMap { get; }

    /// <summary>
    /// The indexes of mandatory statements within the sorted relabeled statements.
    /// </summary>
    public IReadOnlyList<int> MandatoryIndexes { get; }

    /// <summary>
    /// The indexes of non-mandatory statements within the sorted relabeled statements.
    /// </summary>
    public IReadOnlyList<int> NonMandatoryIndexes { get; }

    /// <summary>
    /// The sorted non-mandatory statements the holder can selectively disclose.
    /// </summary>
    /// <remarks>
    /// These statements correspond to the BBS messages over which the issuer signed.
    /// </remarks>
    public IReadOnlyList<string> NonMandatoryStatements { get; }

    /// <summary>
    /// The HMAC key used for blank node relabeling.
    /// </summary>
    /// <remarks>
    /// Extracted from the parsed base proof. Used to relabel statements
    /// consistently when creating derived proofs.
    /// </remarks>
    public byte[] HmacKey { get; }

    /// <summary>
    /// The SHA-256 hash of the canonicalized proof options.
    /// </summary>
    public byte[] ProofHash { get; }

    /// <summary>
    /// The SHA-256 hash of the concatenated mandatory statements.
    /// </summary>
    public byte[] MandatoryHash { get; }

    /// <summary>
    /// The BBS header bound into the signature.
    /// </summary>
    /// <remarks>
    /// This is 64 bytes formed as <c>ProofHash || MandatoryHash</c>.
    /// </remarks>
    public byte[] BbsHeader { get; }


    /// <summary>
    /// Creates a new holder proof context.
    /// </summary>
    public BbsHolderProofContext(
        IReadOnlyList<string> canonicalStatements,
        IReadOnlyList<string> relabeledStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> nonMandatoryIndexes,
        IReadOnlyList<string> nonMandatoryStatements,
        byte[] hmacKey,
        byte[] proofHash,
        byte[] mandatoryHash,
        byte[] bbsHeader)
    {
        ArgumentNullException.ThrowIfNull(canonicalStatements);
        ArgumentNullException.ThrowIfNull(relabeledStatements);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(nonMandatoryIndexes);
        ArgumentNullException.ThrowIfNull(nonMandatoryStatements);
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentNullException.ThrowIfNull(proofHash);
        ArgumentNullException.ThrowIfNull(mandatoryHash);
        ArgumentNullException.ThrowIfNull(bbsHeader);

        CanonicalStatements = canonicalStatements;
        RelabeledStatements = relabeledStatements;
        LabelMap = labelMap;
        MandatoryIndexes = mandatoryIndexes;
        NonMandatoryIndexes = nonMandatoryIndexes;
        NonMandatoryStatements = nonMandatoryStatements;
        HmacKey = hmacKey;
        ProofHash = proofHash;
        MandatoryHash = mandatoryHash;
        BbsHeader = bbsHeader;
    }


    /// <summary>
    /// Disposes the owned resources.
    /// </summary>
    public void Dispose()
    {
    }
}
