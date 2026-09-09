using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Import command (CC = 0x00000156).
/// </summary>
/// <remarks>
/// <para>
/// Brings a duplicated object in under a new Storage Parent: the outer-wrapper seed is recovered from
/// <c>inSymSeed</c> with the parent's own key, the duplication blob's integrity and encryption are undone, and
/// the sensitive area is re-wrapped under the parent so a subsequent <c>TPM2_Load</c> can use the object here —
/// the destination half of the <c>TPM2_Duplicate</c> migration path (TPM 2.0 Part 1, Clause 20; Part 3,
/// clause 13.3).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 13.3):
/// </para>
/// <list type="bullet">
///   <item><description>parentHandle (TPMI_DH_OBJECT): the Storage Parent for the imported object. Requires USER-role authorization.</description></item>
///   <item><description>encryptionKey (TPM2B_DATA): the inner-wrapper key; the Empty Buffer when the duplicate carries no inner wrapper.</description></item>
///   <item><description>objectPublic (TPM2B_PUBLIC): the duplicated object's public area; its <c>fixedTPM</c> and <c>fixedParent</c> shall be CLEAR.</description></item>
///   <item><description>duplicate (TPM2B_PRIVATE): the duplication blob from <c>TPM2_Duplicate</c>.</description></item>
///   <item><description>inSymSeed (TPM2B_ENCRYPTED_SECRET): the outer-wrapper seed protected to this parent, or the Empty Buffer for a blob duplicated to <c>TPM_RH_NULL</c>.</description></item>
///   <item><description>symmetricAlg (TPMT_SYM_DEF_OBJECT+): the inner-wrapper algorithm, or <c>TPM_ALG_NULL</c> for none.</description></item>
/// </list>
/// <para>
/// This input frames the no-inner-wrapper form — an empty <c>encryptionKey</c> and
/// <c>symmetricAlg = TPM_ALG_NULL</c>. The executor is given one authorization session in handle order: the
/// parent's USER-role session.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ImportInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private Tpm2bPublic ObjectPublic { get; }

    private Tpm2bPrivate Duplicate { get; }

    private Tpm2bEncryptedSecret InSymSeed { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Import;

    /// <summary>
    /// Gets the handle of the Storage Parent the object is imported under.
    /// </summary>
    public TpmiDhObject ParentHandle { get; }

    private ImportInput(TpmiDhObject parentHandle, Tpm2bPublic objectPublic, Tpm2bPrivate duplicate, Tpm2bEncryptedSecret inSymSeed)
    {
        ParentHandle = parentHandle;
        ObjectPublic = objectPublic;
        Duplicate = duplicate;
        InSymSeed = inSymSeed;
    }

    /// <summary>
    /// Creates a TPM2_Import input from the outputs of TPM2_Duplicate, framing the no-inner-wrapper form.
    /// </summary>
    /// <param name="parentHandle">The Storage Parent for the imported object.</param>
    /// <param name="marshaledObjectPublic">The duplicated object's marshaled <c>TPM2B_PUBLIC</c> octets.</param>
    /// <param name="duplicate">The duplication blob from TPM2_Duplicate.</param>
    /// <param name="inSymSeed">The protected outer-wrapper seed, or empty for a blob duplicated to <c>TPM_RH_NULL</c>.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>A new <see cref="ImportInput"/>.</returns>
    public static ImportInput Create(
        uint parentHandle,
        ReadOnlySpan<byte> marshaledObjectPublic,
        ReadOnlySpan<byte> duplicate,
        ReadOnlySpan<byte> inSymSeed,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var publicReader = new TpmReader(marshaledObjectPublic);
        Tpm2bPublic objectPublic = Tpm2bPublic.Parse(ref publicReader, pool);
        Tpm2bPrivate duplicateBuffer = Tpm2bPrivate.Empty;
        try
        {
            duplicateBuffer = Tpm2bPrivate.Create(duplicate, pool);
            Tpm2bEncryptedSecret seedBuffer = Tpm2bEncryptedSecret.Create(inSymSeed, pool);

            return new ImportInput(TpmiDhObject.FromValue(parentHandle), objectPublic, duplicateBuffer, seedBuffer);
        }
        catch
        {
            //These carriers' only owner is this frame until the constructed input adopts them, so a failing
            //later rent must release them or the pooled rentals are orphaned.
            duplicateBuffer.Dispose();
            objectPublic.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                       //parentHandle.
               sizeof(ushort) +                     //encryptionKey (empty TPM2B_DATA).
               ObjectPublic.GetSerializedSize() +   //objectPublic (TPM2B_PUBLIC).
               Duplicate.SerializedSize +           //duplicate (TPM2B_PRIVATE).
               InSymSeed.SerializedSize +           //inSymSeed (TPM2B_ENCRYPTED_SECRET).
               sizeof(ushort);                      //symmetricAlg (TPM_ALG_NULL selector alone).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ParentHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        //encryptionKey: the Empty Buffer the no-inner-wrapper form requires; symmetricAlg: the bare NULL
        //selector, which a TPMT_SYM_DEF_OBJECT carries with no keyBits or mode fields after it.
        writer.WriteUInt16(0);
        ObjectPublic.WriteTo(ref writer);
        Duplicate.WriteTo(ref writer);
        InSymSeed.WriteTo(ref writer);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            ObjectPublic.Dispose();
            Duplicate.Dispose();
            InSymSeed.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"ImportInput(Parent={ParentHandle}, Duplicate={Duplicate.Length} bytes, Seed={InSymSeed.Length} bytes)";
}
