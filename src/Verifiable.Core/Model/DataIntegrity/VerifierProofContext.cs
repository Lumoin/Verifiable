using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Context containing parsed derived proof components needed by the verifier.
/// </summary>
/// <remarks>
/// <para>
/// This type is returned by <see cref="CredentialEcdsaSd2023Extensions.ParseDerivedProofAsync"/>.
/// It contains all the information the verifier needs to verify a derived proof:
/// </para>
/// <list type="bullet">
/// <item><description>The base signature from the issuer.</description></item>
/// <item><description>The ephemeral public key for verifying statement signatures.</description></item>
/// <item><description>The disclosed statements with their signatures.</description></item>
/// <item><description>The reconstructed base signature data.</description></item>
/// </list>
/// <para>
/// The verifier receives a derived credential from the holder and must parse the embedded
/// proof to extract these components. The verifier does not have access to the holder's
/// context; everything must be reconstructed from the credential and proof value.
/// </para>
/// </remarks>
[DebuggerDisplay("VerifierContext: {DisclosedStatements.Count} disclosed statements")]
public sealed class VerifierProofContext: IDisposable
{
    /// <summary>
    /// The issuer's base signature.
    /// </summary>
    public Signature BaseSignature { get; }

    /// <summary>
    /// The data that was signed to create the base signature.
    /// </summary>
    /// <remarks>
    /// Reconstructed as <c>proofOptionsHash || ephemeralPublicKeyWithHeader || mandatoryHash</c>.
    /// </remarks>
    public IMemoryOwner<byte> BaseSignatureData { get; }

    /// <summary>
    /// The length of valid data in <see cref="BaseSignatureData"/>.
    /// </summary>
    public int BaseSignatureDataLength { get; }

    /// <summary>
    /// The ephemeral public key extracted from the derived proof.
    /// </summary>
    /// <remarks>
    /// Used to verify the signatures on disclosed statements.
    /// </remarks>
    public PublicKeyMemory EphemeralPublicKey { get; }

    /// <summary>
    /// The disclosed statements with their signatures.
    /// </summary>
    /// <remarks>
    /// Each statement's signature must verify against the ephemeral public key.
    /// </remarks>
    public IReadOnlyList<NQuadSignedStatement> DisclosedStatements { get; }

    /// <summary>
    /// The label map from canonical to HMAC-derived blank node identifiers.
    /// </summary>
    public IReadOnlyDictionary<string, string> LabelMap { get; }

    /// <summary>
    /// The indexes of mandatory statements.
    /// </summary>
    public IReadOnlyList<int> MandatoryIndexes { get; }


    /// <summary>
    /// Creates a new verifier proof context.
    /// </summary>
    public VerifierProofContext(
        Signature baseSignature,
        IMemoryOwner<byte> baseSignatureData,
        int baseSignatureDataLength,
        PublicKeyMemory ephemeralPublicKey,
        IReadOnlyList<NQuadSignedStatement> disclosedStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes)
    {
        ArgumentNullException.ThrowIfNull(baseSignature);
        ArgumentNullException.ThrowIfNull(baseSignatureData);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
        ArgumentNullException.ThrowIfNull(disclosedStatements);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);

        BaseSignature = baseSignature;
        BaseSignatureData = baseSignatureData;
        BaseSignatureDataLength = baseSignatureDataLength;
        EphemeralPublicKey = ephemeralPublicKey;
        DisclosedStatements = disclosedStatements;
        LabelMap = labelMap;
        MandatoryIndexes = mandatoryIndexes;
    }


    /// <summary>
    /// Disposes the owned memory resources.
    /// </summary>
    public void Dispose()
    {
        BaseSignature.Dispose();
        BaseSignatureData.Dispose();
        EphemeralPublicKey.Dispose();

        foreach(var statement in DisclosedStatements)
        {
            statement.Signature.Dispose();
        }
    }
}