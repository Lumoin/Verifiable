using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;


/// <summary>
/// Complete intermediate state from ecdsa-sd-2023 base proof creation.
/// </summary>
/// <remarks>
/// <para>
/// This class exposes all intermediate values computed during base proof creation.
/// Production code typically only needs <see cref="Credential"/>, but test code
/// validating against W3C specification test vectors needs access to each step.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#add-base-proof-ecdsa-sd-2023">
/// VC Data Integrity ECDSA Cryptosuites: Add Base Proof (ecdsa-sd-2023)</see>.
/// </para>
/// </remarks>
public sealed class BaseProofCreationState: IDisposable
{
    /// <summary>
    /// Gets the credential with the base proof attached.
    /// </summary>
    public VerifiableCredential Credential { get; }

    /// <summary>
    /// Gets the final multibase-encoded proof value.
    /// </summary>
    public string ProofValue { get; }

    /// <summary>
    /// Gets the HMAC key used for blank node relabeling.
    /// </summary>
    public byte[] HmacKey { get; }

    /// <summary>
    /// Gets the ephemeral public key with multicodec header.
    /// </summary>
    public IMemoryOwner<byte> EphemeralPublicKeyWithHeader { get; }

    /// <summary>
    /// Gets the base signature over (proofOptionsHash || ephemeralPublicKey || mandatoryHash).
    /// </summary>
    public Signature BaseSignature { get; }

    /// <summary>
    /// Gets the signed non-mandatory statements.
    /// </summary>
    public IReadOnlyList<NQuadSignedStatement> SignedStatements { get; }

    /// <summary>
    /// Gets the HMAC label map for blank node relabeling.
    /// </summary>
    public IReadOnlyDictionary<string, string> LabelMap { get; }

    /// <summary>
    /// Gets the data that was signed to create <see cref="BaseSignature"/>.
    /// </summary>
    public IMemoryOwner<byte> BaseSignatureData { get; }

    /// <summary>
    /// Gets the length of valid data in <see cref="BaseSignatureData"/>.
    /// </summary>
    public int BaseSignatureDataLength { get; }

    /// <summary>
    /// Gets the indexes of mandatory statements.
    /// </summary>
    public IReadOnlyList<int> MandatoryIndexes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="BaseProofCreationState"/> class.
    /// </summary>
    public BaseProofCreationState(
        VerifiableCredential credential,
        string proofValue,
        byte[] hmacKey,
        IMemoryOwner<byte> ephemeralPublicKeyWithHeader,
        Signature baseSignature,
        IReadOnlyList<NQuadSignedStatement> signedStatements,
        IReadOnlyDictionary<string, string> labelMap,
        IMemoryOwner<byte> baseSignatureData,
        int baseSignatureDataLength,
        IReadOnlyList<int> mandatoryIndexes)
    {
        Credential = credential;
        ProofValue = proofValue;
        HmacKey = hmacKey;
        EphemeralPublicKeyWithHeader = ephemeralPublicKeyWithHeader;
        BaseSignature = baseSignature;
        SignedStatements = signedStatements;
        LabelMap = labelMap;
        BaseSignatureData = baseSignatureData;
        BaseSignatureDataLength = baseSignatureDataLength;
        MandatoryIndexes = mandatoryIndexes;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        EphemeralPublicKeyWithHeader.Dispose();
        BaseSignature.Dispose();
        BaseSignatureData.Dispose();

        foreach(var signedStatement in SignedStatements)
        {
            signedStatement.Signature.Dispose();
        }
    }
}