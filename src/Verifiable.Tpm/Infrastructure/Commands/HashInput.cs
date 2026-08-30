using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Hash command (CC = TPM_CC_Hash, 0x0000017D).
/// </summary>
/// <remarks>
/// <para>
/// Hashes a single data buffer on the TPM and returns the digest with a <c>TPMT_TK_HASHCHECK</c> ticket (TPM
/// 2.0 Library Part 3, clause 15.4.1). The ticket, minted under the proof of <see cref="Hierarchy"/>, attests
/// that the hashed octets did not begin with <c>TPM_GENERATED_VALUE</c>, so the digest may be signed with a
/// restricted signing key (<c>TPM2_SignDigest()</c>, clause 20.7); it is the NULL Ticket when
/// <see cref="Hierarchy"/> is <c>TPM_RH_NULL</c> or when the data is not safe to sign. Data larger than the
/// TPM's input buffer goes through a hash sequence instead (<c>TPM2_HashSequenceStart()</c>,
/// <c>TPM2_SequenceUpdate()</c>, <c>TPM2_SequenceComplete()</c>).
/// </para>
/// <para>
/// Wire layout (Table 69): no handles; parameters <c>data</c> (TPM2B_MAX_BUFFER, encryptable as the first
/// parameter), <c>hashAlg</c> (TPMI_ALG_HASH — shall not be <c>TPM_ALG_NULL</c>), then <c>hierarchy</c>
/// (TPMI_RH_HIERARCHY+). The command has no authorization area of its own, so it is framed
/// <c>TPM_ST_NO_SESSIONS</c> unless an audit, encrypt, or decrypt session is present.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 15.4, Table 69 - TPM2_Hash.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HashInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Hash;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The data to hash (<c>data</c>, TPM2B_MAX_BUFFER; may be empty); owned by this input and released by
    /// <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bMaxBuffer Data { get; }

    /// <summary>The hash algorithm to compute (<c>hashAlg</c>, TPMI_ALG_HASH; never <c>TPM_ALG_NULL</c>).</summary>
    public TpmiAlgHash HashAlg { get; }

    /// <summary>
    /// The hierarchy whose proof integrity-protects the returned ticket (<c>hierarchy</c>,
    /// TPMI_RH_HIERARCHY+); <c>TPM_RH_NULL</c> requests no ticket.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Creates an input that hashes <paramref name="data"/> under <paramref name="hashAlg"/>, requesting a
    /// ticket under <paramref name="hierarchy"/>.
    /// </summary>
    /// <param name="data">The data to hash (at most <see cref="Tpm2bMaxBuffer.MaxSize"/> octets).</param>
    /// <param name="hashAlg">The hash algorithm; must not be <c>TPM_ALG_NULL</c>.</param>
    /// <param name="hierarchy">The ticket hierarchy, or <c>TPM_RH_NULL</c> for no ticket.</param>
    /// <param name="pool">The memory pool the data carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static HashInput Create(ReadOnlySpan<byte> data, TpmiAlgHash hashAlg, TpmiRhHierarchy hierarchy, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bMaxBuffer buffer = Tpm2bMaxBuffer.Create(data, pool);

        return new HashInput(buffer, hashAlg, hierarchy);
    }

    /// <summary>
    /// Initializes the input over an already-rented data carrier, adopting its ownership.
    /// </summary>
    /// <param name="data">The owned data carrier.</param>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="hierarchy">The ticket hierarchy.</param>
    private HashInput(Tpm2bMaxBuffer data, TpmiAlgHash hashAlg, TpmiRhHierarchy hierarchy)
    {
        Data = data;
        HashAlg = hashAlg;
        Hierarchy = hierarchy;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return Data.SerializedSize + //data (TPM2B_MAX_BUFFER).
               sizeof(ushort) +      //hashAlg (TPMI_ALG_HASH).
               sizeof(uint);         //hierarchy (TPMI_RH_HIERARCHY+).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //Table 69 has no handle area.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Data.WriteTo(ref writer);
        writer.WriteUInt16((ushort)HashAlg.Value);
        Hierarchy.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Data.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"HashInput(Data={Data.Length} bytes, HashAlg={HashAlg.Value}, Hierarchy=0x{Hierarchy.Value:X8})";
}
