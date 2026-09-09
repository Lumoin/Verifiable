using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Encapsulate command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 14.10, Table 61), parsed in this order:
/// </para>
/// <list type="bullet">
///   <item><description>sharedSecret (TPM2B_SHARED_SECRET): the KEM output the caller feeds to its own key derivation.</description></item>
///   <item><description>ciphertext (TPM2B_KEM_CIPHERTEXT): the public artifact the holder of the KEM private key decapsulates to recover the same shared secret.</description></item>
/// </list>
/// <para>
/// <see cref="SharedSecret"/> is the first response parameter and carries an explicit size field, so it is
/// the one eligible for session-based parameter encryption on a real TPM (TPM 2.0 Library Part 1, clause
/// 18.1). Absent an encrypt session it rides in the clear — the generic encrypt-session mechanism is the
/// only protection clause 14.10 offers it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EncapsulateResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the shared secret the KEM produced.
    /// </summary>
    public Tpm2bSharedSecret SharedSecret { get; }

    /// <summary>
    /// Gets the ciphertext the holder of the KEM private key feeds into TPM2_Decapsulate() to recover the
    /// same shared secret.
    /// </summary>
    public Tpm2bKemCiphertext Ciphertext { get; }

    private EncapsulateResponse(Tpm2bSharedSecret sharedSecret, Tpm2bKemCiphertext ciphertext)
    {
        SharedSecret = sharedSecret;
        Ciphertext = ciphertext;
    }

    /// <summary>
    /// Parses a TPM2_Encapsulate response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static EncapsulateResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bSharedSecret sharedSecret = Tpm2bSharedSecret.Parse(ref reader, pool);
        try
        {
            Tpm2bKemCiphertext ciphertext = Tpm2bKemCiphertext.Parse(ref reader, pool);

            return new EncapsulateResponse(sharedSecret, ciphertext);
        }
        catch
        {
            //sharedSecret's only owner is this frame until the constructed response adopts it, so a failing
            //ciphertext read must release its pooled (sensitive) rental rather than orphan it.
            sharedSecret.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            SharedSecret.Dispose();
            Ciphertext.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: both octet counts, never the shared-secret or ciphertext octets.</summary>
    private string DebuggerDisplay => $"EncapsulateResponse(SharedSecret={SharedSecret.Size} bytes, Ciphertext={Ciphertext.Size} bytes)";
}
