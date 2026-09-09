using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_HMAC command: the HMAC of the supplied data (TPM 2.0 Library Part 3, clause 15.5,
/// Table 72).
/// </summary>
/// <remarks>
/// <see cref="OutHmac"/> is owned by this response and released by <see cref="Dispose"/>.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HmacResponse: IDisposable, ITpmWireType
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>The HMAC of the data (<c>outHMAC</c>, TPM2B_DIGEST).</summary>
    public Tpm2bDigest OutHmac { get; }

    /// <summary>Initializes the response over its owned carrier.</summary>
    /// <param name="outHmac">The owned digest carrier.</param>
    private HmacResponse(Tpm2bDigest outHmac)
    {
        OutHmac = outHmac;
    }

    /// <summary>
    /// Parses the Table 72 response parameters: <c>outHMAC</c> (TPM2B_DIGEST).
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameter area.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The parsed response; the caller owns it.</returns>
    public static HmacResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bDigest outHmac = Tpm2bDigest.Parse(ref reader, pool);

        return new HmacResponse(outHmac);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            OutHmac.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"HmacResponse(OutHmac={OutHmac.Size} bytes)";
}
