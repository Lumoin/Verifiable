using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Context containing parsed base proof components needed by the holder for selective disclosure.
/// </summary>
/// <remarks>
/// <para>
/// This type is returned by <see cref="CredentialEcdsaSd2023Extensions.ParseBaseProofAsync"/> and
/// <see cref="CredentialEcdsaSd2023Extensions.VerifyBaseProofAndPrepareAsync"/>. It contains all
/// the information the holder needs to:
/// </para>
/// <list type="bullet">
/// <item><description>Verify the base proof signature (if not already verified).</description></item>
/// <item><description>Select which claims to disclose.</description></item>
/// <item><description>Create derived proofs using <see cref="CredentialEcdsaSd2023Extensions.DeriveProofAsync"/>.</description></item>
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
[DebuggerDisplay("HolderContext: {SignedStatements.Count} statements, {LabelMap.Count} labels")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class HolderProofContext: IDisposable
{
    /// <summary>
    /// The canonical N-Quad statements before HMAC relabeling.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 75. These are the statements produced by
    /// RDFC-1.0 canonicalization with <c>_:c14nN</c> blank node identifiers.
    /// </remarks>
    public IReadOnlyList<string> CanonicalStatements { get; }

    /// <summary>
    /// The N-Quad statements after HMAC-based blank node relabeling, sorted.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 76. Blank node identifiers are replaced
    /// with HMAC-derived pseudorandom identifiers (<c>_:uXXX</c>), then sorted.
    /// </remarks>
    public IReadOnlyList<string> RelabeledStatements { get; }

    /// <summary>
    /// The label map from canonical to HMAC-derived blank node identifiers.
    /// </summary>
    /// <remarks>
    /// Corresponds to W3C Example 77. Maps <c>c14nN</c> to <c>uXXX</c> identifiers.
    /// Needed for creating derived proofs.
    /// </remarks>
    public IReadOnlyDictionary<string, string> LabelMap { get; }

    /// <summary>
    /// The indexes of mandatory statements within the sorted relabeled statements.
    /// </summary>
    public IReadOnlyList<int> MandatoryIndexes { get; }

    /// <summary>
    /// The signed non-mandatory N-Quad statements with their signatures.
    /// </summary>
    /// <remarks>
    /// These are the statements the holder can selectively disclose.
    /// Each statement includes its signature from the ephemeral key.
    /// </remarks>
    public IReadOnlyList<NQuadSignedStatement> SignedStatements { get; }

    /// <summary>
    /// The issuer's base signature.
    /// </summary>
    public Signature BaseSignature { get; }

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
    public int BaseSignatureDataLength { get; }

    /// <summary>
    /// The ephemeral public key with multicodec header.
    /// </summary>
    /// <remarks>
    /// This key was used by the issuer to sign each non-mandatory statement.
    /// The holder needs it for creating derived proofs.
    /// </remarks>
    public IMemoryOwner<byte> EphemeralPublicKeyWithHeader { get; }

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
    public byte[] ProofOptionsHash { get; }

    /// <summary>
    /// The SHA-256 hash of the concatenated mandatory statements.
    /// </summary>
    public byte[] MandatoryHash { get; }


    /// <summary>
    /// Creates a new holder proof context.
    /// </summary>
    public HolderProofContext(
        IReadOnlyList<string> canonicalStatements,
        IReadOnlyList<string> relabeledStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<NQuadSignedStatement> signedStatements,
        Signature baseSignature,
        IMemoryOwner<byte> baseSignatureData,
        int baseSignatureDataLength,
        IMemoryOwner<byte> ephemeralPublicKeyWithHeader,
        byte[] hmacKey,
        byte[] proofOptionsHash,
        byte[] mandatoryHash)
    {
        ArgumentNullException.ThrowIfNull(canonicalStatements);
        ArgumentNullException.ThrowIfNull(relabeledStatements);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(signedStatements);
        ArgumentNullException.ThrowIfNull(baseSignature);
        ArgumentNullException.ThrowIfNull(baseSignatureData);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKeyWithHeader);
        ArgumentNullException.ThrowIfNull(hmacKey);
        ArgumentNullException.ThrowIfNull(proofOptionsHash);
        ArgumentNullException.ThrowIfNull(mandatoryHash);

        CanonicalStatements = canonicalStatements;
        RelabeledStatements = relabeledStatements;
        LabelMap = labelMap;
        MandatoryIndexes = mandatoryIndexes;
        SignedStatements = signedStatements;
        BaseSignature = baseSignature;
        BaseSignatureData = baseSignatureData;
        BaseSignatureDataLength = baseSignatureDataLength;
        EphemeralPublicKeyWithHeader = ephemeralPublicKeyWithHeader;
        HmacKey = hmacKey;
        ProofOptionsHash = proofOptionsHash;
        MandatoryHash = mandatoryHash;
    }


    /// <summary>
    /// Disposes the owned memory resources.
    /// </summary>
    public void Dispose()
    {
        BaseSignatureData.Dispose();
        EphemeralPublicKeyWithHeader.Dispose();
        BaseSignature.Dispose();

        foreach(var statement in SignedStatements)
        {
            statement.Signature.Dispose();
        }
    }
}