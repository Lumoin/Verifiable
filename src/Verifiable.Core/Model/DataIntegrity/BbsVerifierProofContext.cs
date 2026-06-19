using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Context containing parsed derived proof components needed by the verifier.
/// </summary>
/// <remarks>
/// <para>
/// This type contains all the information the verifier needs to verify a derived proof:
/// </para>
/// <list type="bullet">
/// <item><description>The disclosed non-mandatory statements.</description></item>
/// <item><description>The mandatory statements.</description></item>
/// <item><description>The label map and statement indexes.</description></item>
/// <item><description>The BBS header and presentation header bound into the proof.</description></item>
/// </list>
/// <para>
/// The verifier receives a derived credential from the holder and must parse the embedded
/// proof to extract these components. The verifier does not have access to the holder's
/// context; everything must be reconstructed from the credential and proof value.
/// </para>
/// </remarks>
[DebuggerDisplay("BbsVerifierContext: {DisclosedNonMandatoryStatements.Count} disclosed, {MandatoryStatements.Count} mandatory")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class BbsVerifierProofContext: IDisposable
{
    /// <summary>
    /// The disclosed non-mandatory statements.
    /// </summary>
    /// <remarks>
    /// These are the non-mandatory statements the holder chose to disclose.
    /// </remarks>
    public IReadOnlyList<string> DisclosedNonMandatoryStatements { get; }

    /// <summary>
    /// The mandatory statements.
    /// </summary>
    /// <remarks>
    /// These statements are always disclosed and bound into the mandatory hash.
    /// </remarks>
    public IReadOnlyList<string> MandatoryStatements { get; }

    /// <summary>
    /// The label map from canonical to HMAC-derived blank node identifiers.
    /// </summary>
    public IReadOnlyDictionary<string, string> LabelMap { get; }

    /// <summary>
    /// The indexes of mandatory statements.
    /// </summary>
    public IReadOnlyList<int> MandatoryIndexes { get; }

    /// <summary>
    /// The indexes of selectively disclosed statements.
    /// </summary>
    public IReadOnlyList<int> SelectiveIndexes { get; }

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
    /// The presentation header bound into the BBS proof.
    /// </summary>
    public byte[] PresentationHeader { get; }


    /// <summary>
    /// Creates a new verifier proof context.
    /// </summary>
    public BbsVerifierProofContext(
        IReadOnlyList<string> disclosedNonMandatoryStatements,
        IReadOnlyList<string> mandatoryStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> selectiveIndexes,
        byte[] proofHash,
        byte[] mandatoryHash,
        byte[] bbsHeader,
        byte[] presentationHeader)
    {
        ArgumentNullException.ThrowIfNull(disclosedNonMandatoryStatements);
        ArgumentNullException.ThrowIfNull(mandatoryStatements);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(selectiveIndexes);
        ArgumentNullException.ThrowIfNull(proofHash);
        ArgumentNullException.ThrowIfNull(mandatoryHash);
        ArgumentNullException.ThrowIfNull(bbsHeader);
        ArgumentNullException.ThrowIfNull(presentationHeader);

        DisclosedNonMandatoryStatements = disclosedNonMandatoryStatements;
        MandatoryStatements = mandatoryStatements;
        LabelMap = labelMap;
        MandatoryIndexes = mandatoryIndexes;
        SelectiveIndexes = selectiveIndexes;
        ProofHash = proofHash;
        MandatoryHash = mandatoryHash;
        BbsHeader = bbsHeader;
        PresentationHeader = presentationHeader;
    }


    /// <summary>
    /// Disposes the owned resources.
    /// </summary>
    public void Dispose()
    {
    }
}
