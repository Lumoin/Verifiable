using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_NV_ReadPublic command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 31.6, Table 235):
/// </para>
/// <list type="bullet">
///   <item><description>nvPublic (TPM2B_NV_PUBLIC) - the public area of the NV Index: a UINT16
///   size prefix wrapping a <see cref="TpmsNvPublic"/> (TPM 2.0 Part 2, Section 13.6, Table
///   235). There is no dedicated wrapper type for TPM2B_NV_PUBLIC; the size prefix is read here
///   and <see cref="TpmsNvPublic"/> is parsed directly, the same shape
///   <c>NvDefineSpaceInput</c> writes it with.</description></item>
///   <item><description>nvName (TPM2B_NAME) - the Name of the Index: <c>nameAlg ‖
///   H_nameAlg(TPMS_NV_PUBLIC)</c> (TPM 2.0 Part 1, Section 14, Table 6). The digest covers the
///   whole marshaled public area, whose own first field is the Index handle - the handle is
///   hashed once as part of it, never prepended a second time. The recipe
///   hashes the whole public area including <c>TPMA_NV_WRITTEN</c>, so the Name changes the
///   moment the Index is first written; callers deriving a cpHash Name for this Index use this
///   field verbatim rather than recomputing it from <see cref="NvPublic"/>.</description></item>
/// </list>
/// <para>
/// Auth Index: None on the request - no authorization session is ever checked, so this response
/// is reachable for any Index that currently exists, written or unwritten, locked or unlocked
/// (TPM 2.0 Part 3, Section 5.4's read/write-lock gates apply only to commands that access the
/// data area, which this command never does).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class NvReadPublicResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the parsed public area of the NV Index.
    /// </summary>
    public TpmsNvPublic NvPublic { get; }

    /// <summary>
    /// Gets the Name of the NV Index.
    /// </summary>
    public Tpm2bName NvName { get; }

    private NvReadPublicResponse(TpmsNvPublic nvPublic, Tpm2bName nvName)
    {
        NvPublic = nvPublic;
        NvName = nvName;
    }

    /// <summary>
    /// Parses a TPM2_NV_ReadPublic response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static NvReadPublicResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ushort nvPublicSize = reader.ReadUInt16();
        if(nvPublicSize == 0)
        {
            throw new InvalidOperationException("TPM2B_NV_PUBLIC size cannot be zero.");
        }

        TpmsNvPublic nvPublic;
        IMemoryOwner<byte> rawNvPublic = pool.Rent(nvPublicSize);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(nvPublicSize);
            source.CopyTo(rawNvPublic.Memory.Span[..nvPublicSize]);

            var innerReader = new TpmReader(rawNvPublic.Memory.Span[..nvPublicSize]);
            nvPublic = TpmsNvPublic.Parse(ref innerReader, pool);
        }
        finally
        {
            //TpmsNvPublic.Parse copies the authPolicy digest into its own pooled storage, so this
            //bounding rental is scratch only and is never retained by the parsed result.
            rawNvPublic.Dispose();
        }

        try
        {
            Tpm2bName nvName = Tpm2bName.Parse(ref reader, pool);

            return new NvReadPublicResponse(nvPublic, nvName);
        }
        catch
        {
            //A short buffer after the public area must not leak the already-parsed nvPublic.
            nvPublic.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            NvPublic.Dispose();
            NvName.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"NvReadPublicResponse(0x{NvPublic.NvIndex:X8}, {NvName.Size} bytes)";
}
