using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Duplicate command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 13.1):
/// </para>
/// <list type="bullet">
///   <item><description>encryptionKeyOut (TPM2B_DATA): the inner-wrapper key the TPM generated, or the Empty Buffer when <c>symmetricAlg</c> was <c>TPM_ALG_NULL</c>.</description></item>
///   <item><description>duplicate (TPM2B_PRIVATE): the duplicated object's sensitive area under the duplication protections.</description></item>
///   <item><description>outSymSeed (TPM2B_ENCRYPTED_SECRET): the outer-wrapper seed protected to the new parent, or the Empty Buffer for a <c>TPM_RH_NULL</c> new parent.</description></item>
/// </list>
/// <para>
/// All three outputs are opaque to the host and are passed unchanged into <c>TPM2_Import</c> at the
/// destination.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class DuplicateResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the inner-wrapper key, or the empty buffer for the no-inner-wrapper form.
    /// </summary>
    public Tpm2bData EncryptionKeyOut { get; }

    /// <summary>
    /// Gets the duplicated object's protected sensitive area.
    /// </summary>
    public Tpm2bPrivate Duplicate { get; }

    /// <summary>
    /// Gets the outer-wrapper seed protected to the new parent, or the empty buffer for a <c>TPM_RH_NULL</c> new parent.
    /// </summary>
    public Tpm2bEncryptedSecret OutSymSeed { get; }

    private DuplicateResponse(Tpm2bData encryptionKeyOut, Tpm2bPrivate duplicate, Tpm2bEncryptedSecret outSymSeed)
    {
        EncryptionKeyOut = encryptionKeyOut;
        Duplicate = duplicate;
        OutSymSeed = outSymSeed;
    }

    /// <summary>
    /// Parses a TPM2_Duplicate response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static DuplicateResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bData encryptionKeyOut = Tpm2bData.Parse(ref reader, pool);
        Tpm2bPrivate duplicate = Tpm2bPrivate.Empty;
        try
        {
            duplicate = Tpm2bPrivate.Parse(ref reader, pool);
            Tpm2bEncryptedSecret outSymSeed = Tpm2bEncryptedSecret.Parse(ref reader, pool);

            return new DuplicateResponse(encryptionKeyOut, duplicate, outSymSeed);
        }
        catch
        {
            //These carriers' only owner is this frame until the constructed response adopts them, so a failing
            //later read must release them or the pooled rentals are orphaned.
            duplicate.Dispose();
            encryptionKeyOut.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            EncryptionKeyOut.Dispose();
            Duplicate.Dispose();
            OutSymSeed.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"DuplicateResponse(KeyOut={EncryptionKeyOut.Length} bytes, Duplicate={Duplicate.Length} bytes, Seed={OutSymSeed.Length} bytes)";
}
