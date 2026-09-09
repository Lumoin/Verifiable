using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Encapsulate command (CC = 0x000001A7).
/// </summary>
/// <remarks>
/// <para>
/// Runs the general-purpose KEM primitive TPM 2.0 Library v185 adds (Part 1, clause 8.4.5.1, Table 4: "any
/// KEM") over the public portion of the key referenced by <see cref="KeyHandle"/> — architecturally
/// disjoint from the older Labeled KEM (clause 8.4.5.2) that salting, credential protection, and
/// duplication use. For an ECC key whose <c>kdf</c> is non-NULL, the KEM is DHKEM(curveID, kdf) per
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see> (TPM 2.0 Library Part 1, clause 44.4).
/// This is a public-key operation: <see cref="KeyHandle"/> requires no authorization at all (Auth Index
/// None — "The TPM does not verify the objectAttributes of the key", TPM 2.0 Library Part 3, clause 14.10),
/// so the host verb composes no session for it and the executor is free to frame either
/// <c>TPM_ST_SESSIONS</c> or <c>TPM_ST_NO_SESSIONS</c> depending on whether the caller attaches an audit or
/// encrypt session — a decision this input takes no part in.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 14.10, Table 60):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT, Auth Index None): reference to the public portion of the KEM key. Requires no authorization.</description></item>
/// </list>
/// <para>
/// Table 60 carries no parameters at all — the command's entire input is the handle area — so there is no
/// first command parameter to size an encrypt session against.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EncapsulateInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Encapsulate;

    /// <inheritdoc/>
    /// <remarks>
    /// Always <see langword="false"/>: TPM2_Encapsulate() has no command parameters at all (Table 60), so
    /// there is no first parameter for a session's <c>decrypt</c> attribute to target (TPM 2.0 Library Part
    /// 1, clause 18.1's eligibility rule presupposes a sized parameter that exists).
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => false;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>keyHandle</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 14.10, Table 60) — the first
    /// session in an authorization area over this command is a companion, never an authorizer, so a decrypt or
    /// encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0 Library Part 1,
    /// clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <summary>
    /// Gets the handle of the KEM key whose public portion performs the encapsulation.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Creates a TPM2_Encapsulate input for the given KEM key handle.
    /// </summary>
    /// <param name="keyHandle">The handle of the KEM key.</param>
    /// <returns>A new <see cref="EncapsulateInput"/>.</returns>
    public static EncapsulateInput ForHandle(TpmiDhObject keyHandle)
    {
        return new EncapsulateInput(keyHandle);
    }

    private EncapsulateInput(TpmiDhObject keyHandle)
    {
        KeyHandle = keyHandle;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint); //keyHandle (TPMI_DH_OBJECT).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_Encapsulate has no parameters beyond the handle (Table 60).
    }

    /// <summary>The debugger's one-line rendering: the key handle.</summary>
    private string DebuggerDisplay => $"EncapsulateInput({KeyHandle})";
}
