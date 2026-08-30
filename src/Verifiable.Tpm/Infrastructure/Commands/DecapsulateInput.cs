using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Decapsulate command (CC = 0x000001A8).
/// </summary>
/// <remarks>
/// <para>
/// Recovers the shared secret <see cref="Ciphertext"/> encodes, using the private portion of the KEM key
/// referenced by <see cref="KeyHandle"/> — the decapsulation counterpart of TPM2_Encapsulate() (TPM 2.0
/// Library Part 3, clause 14.11). Unlike TPM2_Encapsulate(), this is a private-key operation:
/// <see cref="KeyHandle"/> requires authorization (Auth Index 1, Auth Role USER), so the command always
/// carries an authorization area and its tag is pinned to <c>TPM_ST_SESSIONS</c> (Table 62) — the executor
/// selects this tag automatically once the caller supplies the session <see cref="KeyHandle"/>'s
/// authorization requires; this type takes no part in that selection (contrast
/// <see cref="EncapsulateInput"/>, whose <c>keyHandle</c> needs no authorization and whose tag is therefore
/// conditional).
/// </para>
/// <para>
/// The key referenced by <see cref="KeyHandle"/> "shall be a KEM key (TPM_RC_KEY) with restricted CLEAR and
/// decrypt SET (TPM_RC_ATTRIBUTES)" — the anti-oracle gate, byte-parallel to TPM2_ECC_Decrypt, that keeps
/// this command from decapsulating traffic protected by a restricted (Labeled-KEM) key such as a storage
/// parent. This input carries no attribute or key-shape check of its own: it frames the wire-exact request
/// Table 62 defines, and the gate is enforced where the key is resolved.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 14.11, Table 62):
/// </para>
/// <list type="bullet">
///   <item><description>@keyHandle (TPMI_DH_OBJECT, Auth Index 1, Auth Role USER): Handle of the KEM key. Requires authorization.</description></item>
///   <item><description>ciphertext (TPM2B_KEM_CIPHERTEXT): The value TPM2_Encapsulate() produced. First (and only) parameter, so it is the encryptable one.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class DecapsulateInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Decapsulate;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>ciphertext</c> (<c>TPM2B_KEM_CIPHERTEXT</c>) is the first (and only) entry of the parameter area
    /// and carries an explicit size field (TPM 2.0 Library Part 3, clause 14.11, Table 62), which is what
    /// TPM 2.0 Library Part 1, clause 18.1 requires of an encryptable parameter and what clause 15.4
    /// restates. The ciphertext is public data (an ephemeral point or a public KEM ciphertext), so
    /// encrypting it protects nothing about <see cref="Ciphertext"/> itself — but the eligibility this flag
    /// reports is structural (first sized parameter), not a statement about confidentiality need, exactly as
    /// <see cref="SignDigestInput.FirstCommandParameterIsEncryptable"/> documents for its own first
    /// parameter. A session without the <c>decrypt</c> attribute is unaffected.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// Gets the handle of the KEM key whose private portion performs the decapsulation.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the KEM ciphertext to decapsulate.
    /// </summary>
    public Tpm2bKemCiphertext Ciphertext { get; }

    /// <summary>
    /// Creates a TPM2_Decapsulate input for the given KEM key handle and ciphertext.
    /// </summary>
    /// <param name="keyHandle">The handle of the KEM key.</param>
    /// <param name="ciphertext">The ciphertext octets TPM2_Encapsulate() produced.</param>
    /// <param name="pool">The memory pool for ciphertext buffer allocation.</param>
    /// <returns>A new <see cref="DecapsulateInput"/>.</returns>
    public static DecapsulateInput Create(TpmiDhObject keyHandle, ReadOnlySpan<byte> ciphertext, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new DecapsulateInput(keyHandle, Tpm2bKemCiphertext.Create(ciphertext, pool));
    }

    private DecapsulateInput(TpmiDhObject keyHandle, Tpm2bKemCiphertext ciphertext)
    {
        KeyHandle = keyHandle;
        Ciphertext = ciphertext;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +          //keyHandle (TPMI_DH_OBJECT).
               Ciphertext.SerializedSize; //ciphertext (TPM2B_KEM_CIPHERTEXT): size prefix + bytes.
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Ciphertext.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Ciphertext.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the key handle and the ciphertext's octet count, never the ciphertext octets.</summary>
    private string DebuggerDisplay => $"DecapsulateInput(Key={KeyHandle}, Ciphertext={Ciphertext.Size} bytes)";
}
