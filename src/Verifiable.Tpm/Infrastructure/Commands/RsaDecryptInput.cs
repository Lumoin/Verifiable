using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_RSA_Decrypt command (TPM 2.0 Library Part 3, clause 14.3, Table 46): RSA-decrypts
/// <c>cipherText</c> with the private portion of an RSA key under a padding scheme selected between the key's
/// own scheme and <c>inScheme</c> (Table 42). "This command uses the private key of keyHandle for this
/// operation and authorization is required" (clause 14.3.1).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT) - the RSA key to decrypt with. Auth Index: 1, Auth Role: USER.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>cipherText (TPM2B_PUBLIC_KEY_RSA) - the cipher text to be decrypted.</description></item>
///   <item><description>inScheme (TPMT_RSA_DECRYPT+) - the padding scheme to use if the scheme associated with keyHandle is TPM_ALG_NULL.</description></item>
///   <item><description>label (TPM2B_DATA) - the label whose association with the message is to be verified.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 14.3 (Tables 46 and 47).
/// </para>
/// </remarks>
/// <param name="KeyHandle">The RSA key to decrypt with.</param>
/// <param name="CipherText">
/// The ciphertext to decrypt. BORROWS the caller's carrier: this type neither owns nor disposes it — the caller
/// retains ownership across the call, the non-owning contract <see cref="RsaEncryptInput"/> keeps for its own
/// sized parameter.
/// </param>
/// <param name="InScheme">The padding scheme to apply if the key's own scheme is <c>TPM_ALG_NULL</c>.</param>
/// <param name="Label">The label whose association with the message is to be verified. BORROWS the caller's carrier, exactly as <see cref="CipherText"/> does.</param>
public readonly record struct RsaDecryptInput(TpmiDhObject KeyHandle, Tpm2bPublicKeyRsa CipherText, TpmtRsaDecrypt InScheme, Tpm2bData Label): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_RSA_Decrypt;

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// <c>cipherText</c> is a sized buffer and is the command's first parameter, so it is eligible for
    /// session-based parameter encryption (TPM 2.0 Library Part 1, clause 18.1) — the RSA ciphertext block,
    /// worth protecting in flight from an observer collecting ciphertexts for later cryptanalysis.
    /// </para>
    /// <para>
    /// <c>TPM2_RSA_Decrypt()</c> is also the primitive TPM 2.0 Library Part 1, clause 16.6.14 names as the
    /// caution's own risk: "If an unrestricted tpmKey is used for salted session generation, then the
    /// encapsulated salt may be recoverable by a user or attacker that can call a decryption primitive (e.g.,
    /// TPM2_RSA_Decrypt() or TPM2_ECDH_ZGen()). Users are urged to only use restricted keys for salted
    /// sessions. The ability to use an unrestricted key for salted sessions is deprecated. See Part 0." —
    /// "TPM2_StartAuthSession() with an unrestricted tpmKey was deprecated in TPM 2.0 version 185" (Part 0,
    /// clause 3.1.4.3). This command recovers, in the clear, anything OAEP/RSAES/RSAEP-wrapped to a loaded unrestricted
    /// decrypt key — an encapsulated salt included, when that key was a session's <c>tpmKey</c> — and only the
    /// key's own <c>restricted</c> CLEAR/<c>decrypt</c> SET attribute pair
    /// (<c>TPM_RC_ATTRIBUTES</c> at <see cref="Verifiable.Tpm.Automata.TpmLifecycleTransitions.TryBuildRsaDecryptAction"/>)
    /// stands between a loaded key and that recovery.
    /// </para>
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + CipherText.SerializedSize + InScheme.SerializedSize + Label.SerializedSize;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        CipherText.WriteTo(ref writer);
        InScheme.WriteTo(ref writer);
        Label.WriteTo(ref writer);
    }
}
