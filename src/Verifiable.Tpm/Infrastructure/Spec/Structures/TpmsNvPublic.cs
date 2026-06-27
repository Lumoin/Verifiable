using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPMS_NV_PUBLIC - the public area of an NV Index.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>nvIndex (UINT32) - the handle of the NV Index.</description></item>
///   <item><description>nameAlg (TPM_ALG_ID, UINT16) - hash algorithm for the Index Name.</description></item>
///   <item><description>attributes (TPMA_NV, UINT32) - the Index attributes.</description></item>
///   <item><description>authPolicy (TPM2B_DIGEST) - optional access policy (Empty Policy when absent).</description></item>
///   <item><description>dataSize (UINT16) - the size of the data area.</description></item>
/// </list>
/// <para>
/// On the command interface this structure is carried inside a <c>TPM2B_NV_PUBLIC</c> (a UINT16
/// size prefix around these octets). See TPM 2.0 Library Part 2, Section 13.6 (Table 235).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsNvPublic: IDisposable
{
    private bool disposed;

    /// <summary>Gets the handle of the NV Index.</summary>
    public uint NvIndex { get; }

    /// <summary>Gets the hash algorithm used to compute the Index Name and process the policy.</summary>
    public TpmAlgIdConstants NameAlg { get; }

    /// <summary>Gets the Index attributes.</summary>
    public TpmaNv Attributes { get; }

    /// <summary>Gets the optional access policy digest; <see cref="Tpm2bDigest.Empty"/> when no policy is present.</summary>
    public Tpm2bDigest AuthPolicy { get; }

    /// <summary>Gets the size in octets of the Index data area.</summary>
    public ushort DataSize { get; }

    /// <summary>
    /// Initializes a new NV public area.
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="authPolicy">The access policy digest; ownership transfers to this instance.</param>
    /// <param name="dataSize">The data area size in octets.</param>
    public TpmsNvPublic(uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, Tpm2bDigest authPolicy, ushort dataSize)
    {
        ArgumentNullException.ThrowIfNull(authPolicy);

        NvIndex = nvIndex;
        NameAlg = nameAlg;
        Attributes = attributes;
        AuthPolicy = authPolicy;
        DataSize = dataSize;
    }

    /// <summary>
    /// Gets the serialized size in octets of this structure (excluding the outer <c>TPM2B_NV_PUBLIC</c> size prefix).
    /// </summary>
    public int SerializedSize =>
        sizeof(uint) + sizeof(ushort) + sizeof(uint) + AuthPolicy.SerializedSize + sizeof(ushort);

    /// <summary>
    /// Writes this structure to a TPM writer (the inner octets, without the outer size prefix).
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt32(NvIndex);
        writer.WriteUInt16((ushort)NameAlg);
        writer.WriteUInt32((uint)Attributes);
        AuthPolicy.WriteTo(ref writer);
        writer.WriteUInt16(DataSize);
    }

    /// <summary>
    /// Parses an NV public area from a TPM reader (the inner octets, without the outer size prefix).
    /// </summary>
    /// <param name="reader">The reader positioned at the structure.</param>
    /// <param name="pool">The memory pool for the policy digest.</param>
    /// <returns>The parsed structure.</returns>
    public static TpmsNvPublic Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        uint nvIndex = reader.ReadUInt32();
        var nameAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        var attributes = (TpmaNv)reader.ReadUInt32();
        Tpm2bDigest authPolicy = Tpm2bDigest.Parse(ref reader, pool);
        ushort dataSize = reader.ReadUInt16();

        return new TpmsNvPublic(nvIndex, nameAlg, attributes, authPolicy, dataSize);
    }

    /// <summary>
    /// Releases the policy digest.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            AuthPolicy.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_NV_PUBLIC(0x{NvIndex:X8}, {Attributes}, {DataSize} bytes)";
}
