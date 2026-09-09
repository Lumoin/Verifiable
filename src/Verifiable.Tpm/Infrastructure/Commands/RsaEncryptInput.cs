using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_RSA_Encrypt command (TPM 2.0 Library Part 3, clause 14.2, Table 44): RSA-encrypts
/// <c>message</c> to the public portion of an RSA key under a padding scheme selected between the key's own
/// scheme and <c>inScheme</c> (Table 42). Only the public area of <c>keyHandle</c> needs to be loaded — "Because
/// only the public portion of the key needs to be loaded for this command, the caller can manipulate the
/// attributes of the key in any way desired" (clause 14.2.1's Note).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT) - the RSA key to encrypt under. Auth Index: None - no authorization is required or accepted.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>message (TPM2B_PUBLIC_KEY_RSA) - the message to encrypt.</description></item>
///   <item><description>inScheme (TPMT_RSA_DECRYPT+) - the padding scheme to use if the scheme associated with keyHandle is TPM_ALG_NULL.</description></item>
///   <item><description>label (TPM2B_DATA) - the optional label to associate with the message.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 14.2 (Tables 44 and 45).
/// </para>
/// </remarks>
/// <param name="KeyHandle">The RSA key to encrypt under.</param>
/// <param name="Message">
/// The message to encrypt. BORROWS the caller's carrier: this type neither owns nor disposes it — the caller
/// retains ownership across the call, the non-owning contract <see cref="ObjectChangeAuthInput"/> keeps for its
/// own sized parameter.
/// </param>
/// <param name="InScheme">The padding scheme to apply if the key's own scheme is <c>TPM_ALG_NULL</c>.</param>
/// <param name="Label">The optional label associated with the message. BORROWS the caller's carrier, exactly as <see cref="Message"/> does.</param>
public readonly record struct RsaEncryptInput(TpmiDhObject KeyHandle, Tpm2bPublicKeyRsa Message, TpmtRsaDecrypt InScheme, Tpm2bData Label): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_RSA_Encrypt;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>message</c> is a sized buffer and is the command's first parameter, so it is eligible for
    /// session-based parameter encryption (TPM 2.0 Library Part 1, clause 18.1) — the plaintext being encrypted,
    /// worth protecting in flight from an observer who cannot otherwise learn it from the public modulus alone.
    /// <c>TPM2_RSA_Encrypt()</c> is clause 18.1's own example of a command needing this protection from a bind
    /// or salt session: "As observed in Clause 16.6.15, if the session is unbound and unsalted, the
    /// sessionValue entropy is entirely based on the authValue. For commands with no authValue, such as
    /// TPM2_LoadExternal() or TPM2_RSA_Encrypt(), a bind or salt session must be used to secure the parameter
    /// encryption." This type does not enforce that requirement — the caller is the only party who can, since
    /// <c>keyHandle</c> carries no authValue for the simulator itself to bind or salt against.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>keyHandle</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 14.2, Table 44) — the first
    /// session in an authorization area over this command is a companion, never an authorizer, so a decrypt or
    /// encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0 Library Part 1,
    /// clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + Message.SerializedSize + InScheme.SerializedSize + Label.SerializedSize;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        Message.WriteTo(ref writer);
        InScheme.WriteTo(ref writer);
        Label.WriteTo(ref writer);
    }
}
